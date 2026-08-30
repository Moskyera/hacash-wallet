//! A cooperative-close freeze that is persisted and then never signed must be
//! released, not latched.
//!
//! `close_channel` writes `FreezeIntentPersisted` and then
//! `FrozenBeforeSigning` before it goes back to the fullnode, so any five
//! minutes in which the Hub cannot finish signing leaves a durable, never-signed
//! freeze. Before this test existed, the next call turned that freeze into
//! `RecoveryRequired`, which `persisted_state_requires_recovery` counts, which
//! makes `settlement_ready()` false, which refuses every payment, every open and
//! every close for every user of the Hub. Nothing could take it back down: the
//! recovery gate demands `signed_transaction_hex`, and this operation never had
//! one, so it could never satisfy its own way out.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::l1_channel::transaction_commitment;
use l2_fast_pay_hub::l1_channel_close::{
    L1_CHANNEL_CLOSE_SCHEMA, L1ChannelCloseRequest, close_request_commitment,
};
use mint::action::{ChannelClose, ChannelOpen};
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType2;
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;

const JOURNAL_KEY: &str = "9393939393939393939393939393939393939393939393939393939393939393";

#[derive(Debug, Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionQuery {
    hash: Option<String>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn close_request(
    user: &Account,
    hub: &Account,
    channel_id: &str,
    lifetime_seconds: u64,
) -> L1ChannelCloseRequest {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let mut action = ChannelClose::new();
    action.channel_id =
        ChannelId::from(<[u8; 16]>::try_from(hex::decode(channel_id).unwrap()).unwrap());
    let now = now_unix();
    let mut tx = TransactionType2::new_by(
        Address::from_readable(user.readable()).unwrap(),
        Amount::from("0.0001").unwrap(),
        now,
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(support::PILOT_CHAIN_ID)]).unwrap();
    tx.push_action(Box::new(guard)).unwrap();
    tx.push_action(Box::new(action)).unwrap();
    tx.fill_sign(user).unwrap();
    let partial_transaction_hex = hex::encode(tx.serialize());
    let mut request = L1ChannelCloseRequest {
        schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
        network: support::PILOT_NETWORK_KIND.into(),
        chain_id: support::PILOT_CHAIN_ID,
        mainnet: false,
        block_1_hash: support::PILOT_BLOCK_ONE.into(),
        node_profile_id: support::PILOT_PROFILE_ID.into(),
        network_instance_id: support::PILOT_INSTANCE.into(),
        transaction_format_version: 2,
        operation_id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        created_unix: now,
        expires_unix: now + lifetime_seconds,
        hub_address: hub.readable().into(),
        user_address: user.readable().into(),
        channel_id: channel_id.into(),
        reuse_version: 1,
        open_height: 900_000,
        partial_transaction_commitment: transaction_commitment(&partial_transaction_hex).unwrap(),
        partial_transaction_hex,
        authorization_public_key_hex: hex::encode(user.public_key().serialize_compressed()),
        authorization_signature_hex: String::new(),
    };
    let commitment: [u8; 32] = hex::decode(close_request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
    request
}

struct MockNode {
    url: String,
    channel: Arc<RwLock<Value>>,
    balance_down: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

/// A fullnode that mines everything it is given, and whose balance query can be
/// taken away and put back.
///
/// The balance query is the last thing `require_close_liquidity` does before
/// the Hub signs, so taking it away is the smallest possible way to reproduce
/// the real failure: the freeze is already durable, the signature is not.
async fn spawn_node(channel: Value) -> MockNode {
    let channel = Arc::new(RwLock::new(channel));
    let balance_down = Arc::new(AtomicBool::new(false));
    let transactions = Arc::new(RwLock::new(HashMap::<String, Value>::new()));
    let app = Router::new()
        .route(
            "/query/channel",
            get({
                let channel = channel.clone();
                move |Query(query): Query<ChannelQuery>| {
                    let channel = channel.clone();
                    async move {
                        let body = channel.read().await.clone();
                        if query.id.as_deref() == body.get("id").and_then(Value::as_str) {
                            Json(body)
                        } else {
                            Json(json!({"ret": 1, "err": "channel not found"}))
                        }
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let transactions = transactions.clone();
                move |Query(query): Query<TransactionQuery>| {
                    let transactions = transactions.clone();
                    async move {
                        let value = {
                            let guard = transactions.read().await;
                            query
                                .hash
                                .as_deref()
                                .and_then(|hash| guard.get(hash).cloned())
                        };
                        Json(
                            value.unwrap_or_else(
                                || json!({"ret": 1, "err": "transaction not found"}),
                            ),
                        )
                    }
                }
            }),
        )
        .route(
            "/query/balance",
            get({
                let balance_down = balance_down.clone();
                move || {
                    let balance_down = balance_down.clone();
                    async move {
                        if balance_down.load(Ordering::Acquire) {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(json!({"ret": 1, "err": "simulated balance outage"})),
                            )
                                .into_response();
                        }
                        Json(json!({"ret": 0, "list": [{"hacash": "1:250"}]})).into_response()
                    }
                }
            }),
        )
        .route(
            "/query/capabilities",
            get(|| async {
                let now = now_unix();
                Json(json!({
                    "ret": 0,
                    "api_version": 1,
                    "api": { "transaction_submit_bound": true },
                    "chain": {"id": support::PILOT_CHAIN_ID, "height": 900000, "next_height": 900001, "mainnet": false},
                    "network": {
                        "kind": support::PILOT_NETWORK_KIND,
                        "node_profile_id": support::PILOT_PROFILE_ID,
                        "block_1_hash": support::PILOT_BLOCK_ONE,
                        "instance_id": support::PILOT_INSTANCE,
                        "transaction_format_version": 2
                    },
                    "sync": {"tip_timestamp_unix": now, "max_tip_age_seconds": 3600, "fresh": true},
                    "transactions": {"registered": [2], "enabled": [2]},
                    "actions": {"registered": [1, 2, 3, 1041], "enabled": [1, 2, 3, 1041]}
                }))
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let channel = channel.clone();
                let transactions = transactions.clone();
                move |body: String| {
                    let channel = channel.clone();
                    let transactions = transactions.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (tx, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        tx.verify_signature().unwrap();
                        let hash = hex::encode(tx.hash().as_bytes());
                        let (kind, height) = if tx.actions()[1].kind() == 2 {
                            let action = ChannelOpen::downcast(&tx.actions()[1]).unwrap();
                            let mut current = channel.write().await;
                            current["id"] = json!(hex::encode(action.channel_id.as_bytes()));
                            current["status"] = json!(0);
                            current["open_height"] = json!(900_000);
                            current["close_height"] = json!(0);
                            current["reuse_version"] = json!(1);
                            current["left"] = json!({
                                "address": action.left_bill.address.to_readable(),
                                "hacash": action.left_bill.amount.to_fin_string(),
                                "satoshi": 0
                            });
                            current["right"] = json!({
                                "address": action.right_bill.address.to_readable(),
                                "hacash": action.right_bill.amount.to_fin_string(),
                                "satoshi": 0
                            });
                            (2, 900_000)
                        } else {
                            let mut current = channel.write().await;
                            current["status"] = json!(1);
                            current["close_height"] = json!(900_001);
                            (3, 900_001)
                        };
                        transactions.write().await.insert(
                            hash.clone(),
                            json!({
                                "ret": 0,
                                "hash": hash.clone(),
                                "hash_with_fee": hex::encode(tx.hash_with_fee().as_bytes()),
                                "tx_type": 2,
                                "body": body,
                                "actions": [{"kind": 1041}, {"kind": kind}],
                                "signatures": [{"complete": true}, {"complete": true}],
                                "block": {"height": height, "timestamp": now_unix()},
                                "confirm": 6
                            }),
                        );
                        Json(json!({"ret": 0, "hash": hash})).into_response()
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockNode {
        url: format!("http://{address}"),
        channel,
        balance_down,
        handle,
    }
}

#[tokio::test]
async fn an_unsigned_close_freeze_that_outlives_its_authorization_is_released_not_latched() {
    let user = Account::create_by("expired-freeze-user").unwrap();
    let hub_account = Account::create_by("expired-freeze-hub").unwrap();
    let open_request = support::channel_open_request(&user, &hub_account);
    let channel_id = open_request.channel_id.clone();
    let node = spawn_node(json!({
        "ret": 0,
        "id": "not-open-yet",
        "status": 0,
        "open_height": 900000,
        "close_height": 0,
        "reuse_version": 1,
        "left": {"address": user.readable(), "hacash": "0.01", "satoshi": 0},
        "right": {"address": hub_account.readable(), "hacash": "0", "satoshi": 0}
    }))
    .await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");
    let open = || {
        HubState::new_secure_with_policy(
            "expired freeze hub",
            hub_account.readable(),
            &node.url,
            None,
            state_path.clone(),
            hex::encode(hub_account.secret_key().serialize()),
            JOURNAL_KEY,
            &"a5".repeat(32),
            "testnet",
            100_000_000,
            100_000_000,
        )
        .unwrap()
    };

    let hub = open();
    hub.open_channel(&open_request).await.unwrap();
    node.channel.write().await["id"] = json!(channel_id);

    // The freeze is persisted, then the node goes away before the Hub can
    // sign. Two seconds of authorization, so it lapses while nothing is signed.
    let stuck = close_request(&user, &hub_account, &channel_id, 2);
    node.balance_down.store(true, Ordering::Release);
    let refusal = hub.close_channel(&stuck).await.unwrap_err().to_string();
    assert!(refusal.contains("balance"), "{refusal}");
    assert_eq!(
        hub.channel_close_status(&stuck.operation_id)
            .unwrap()
            .status,
        "frozen_before_signing"
    );
    assert!(hub.health().settlement_ready);

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    node.balance_down.store(false, Ordering::Release);

    // Replaying the dead request answers with the release and the reason for
    // it, rather than latching the Hub behind a bare `recovery_required`.
    let released = hub.close_channel(&stuck).await.unwrap();
    assert_eq!(released.status, "cancelled_before_signing");
    let reason = released.reason.clone().expect("the person is told why");
    assert!(
        reason.contains("expired before the Hub ever signed it"),
        "{reason}"
    );
    assert!(reason.contains("nothing can land"), "{reason}");

    // The Hub is still open for business - for this user and for everyone else.
    assert!(hub.health().settlement_ready);
    let readiness = hub.mainnet_readiness().await;
    assert!(readiness.cooperative_close_admission_available);
    assert!(readiness.close_liquidity_reserved_by.is_none());

    // And the channel is unfrozen, so a fresh close goes all the way through.
    let second = close_request(&user, &hub_account, &channel_id, 120);
    let closed = hub.close_channel(&second).await.unwrap();
    assert_eq!(closed.status, "retired", "{closed:?}");

    // The release survives a restart, and stays terminal.
    drop(hub);
    let reopened = open();
    assert!(reopened.health().settlement_ready);
    assert_eq!(
        reopened
            .channel_close_status(&stuck.operation_id)
            .unwrap()
            .status,
        "cancelled_before_signing"
    );

    node.handle.abort();
}
