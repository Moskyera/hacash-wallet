mod support;

use std::collections::HashMap;
use std::sync::Arc;

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

fn account(seed: &str) -> Account {
    Account::create_by(seed).unwrap()
}

fn close_request(user: &Account, hub: &Account, channel_id: &str) -> L1ChannelCloseRequest {
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
        expires_unix: now + 60,
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

async fn spawn_recovery_node(
    channel: Value,
) -> (
    String,
    Arc<RwLock<Value>>,
    Arc<RwLock<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let channel = Arc::new(RwLock::new(channel));
    let submitted = Arc::new(RwLock::new(Vec::new()));
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
                        Json(value.unwrap_or_else(|| {
                            json!({"ret": 1, "err": "transaction not found"})
                        }))
                    }
                }
            }),
        )
        .route(
            "/query/balance",
            get(|| async {
                Json(json!({"ret": 0, "list": [{"hacash": "1:250"}]}))
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
                let submitted = submitted.clone();
                let transactions = transactions.clone();
                move |body: String| {
                    let channel = channel.clone();
                    let submitted = submitted.clone();
                    let transactions = transactions.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        assert_eq!(tx.actions().len(), 2);
                        assert_eq!(tx.actions()[0].kind(), 0x0411);
                        assert_eq!(tx.signs().len(), 2);
                        tx.verify_signature().unwrap();
                        let hash = hex::encode(tx.hash().as_bytes());
                        if tx.actions()[1].kind() == 2 {
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
                            transactions.write().await.insert(
                                hash.clone(),
                                json!({
                                    "ret": 0,
                                    "hash": hash.clone(),
                                    "hash_with_fee": hex::encode(tx.hash_with_fee().as_bytes()),
                                    "tx_type": 2,
                                    "body": body.clone(),
                                    "actions": [{"kind": 1041}, {"kind": 2}],
                                    "signatures": [{"complete": true}, {"complete": true}],
                                    "block": {"height": 900_000, "timestamp": now_unix()},
                                    "confirm": 6
                                }),
                            );
                            return Json(json!({"ret": 0, "hash": hash})).into_response();
                        }
                        assert_eq!(tx.actions()[1].kind(), 3);
                        let submission_number = {
                            let mut bodies = submitted.write().await;
                            bodies.push(body.clone());
                            bodies.len()
                        };
                        if submission_number == 1 {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(json!({"ret": 1, "err": "simulated timeout"})),
                            )
                                .into_response();
                        }
                        let mut current = channel.write().await;
                        current["status"] = json!(1);
                        current["close_height"] = json!(900_001);
                        transactions.write().await.insert(
                            hash.clone(),
                            json!({
                                "ret": 0,
                                "hash": hash,
                                "hash_with_fee": hex::encode(tx.hash_with_fee().as_bytes()),
                                "tx_type": 2,
                                "body": body,
                                "actions": [{"kind": 1041}, {"kind": 3}],
                                "signatures": [{"complete": true}, {"complete": true}],
                                "block": {"height": 900_001, "timestamp": now_unix()},
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
    (format!("http://{address}"), channel, submitted, handle)
}

#[tokio::test]
async fn ambiguous_submit_recovers_after_restart_with_exact_same_signed_bytes() {
    let user = account("recovery-close-user");
    let hub_account = account("recovery-close-hub");
    let open_request = support::channel_open_request(&user, &hub_account);
    let channel_id = open_request.channel_id.as_str();
    let channel = json!({
        "ret": 0,
        "id": "not-open-yet",
        "status": 0,
        "open_height": 900000,
        "close_height": 0,
        "reuse_version": 1,
        "left": {"address": user.readable(), "hacash": "0.01", "satoshi": 0},
        "right": {"address": hub_account.readable(), "hacash": "0", "satoshi": 0}
    });
    let request = close_request(&user, &hub_account, channel_id);
    let (node_url, node_channel, submitted, node_handle) = spawn_recovery_node(channel).await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");

    {
        let hub = HubState::new_secure_with_policy(
            "recovery close hub",
            hub_account.readable(),
            &node_url,
            None,
            state_path.clone(),
            hex::encode(hub_account.secret_key().serialize()),
            JOURNAL_KEY,
            &"a5".repeat(32),
            "testnet",
            100_000_000,
            100_000_000,
        )
        .unwrap();
        hub.open_channel(&open_request).await.unwrap();
        node_channel.write().await["id"] = json!(channel_id);
        let response = hub.close_channel(&request).await.unwrap();
        assert_eq!(response.status, "recovery_required");
    }

    let reopened = HubState::new_secure_with_policy(
        "recovery close hub",
        hub_account.readable(),
        &node_url,
        None,
        state_path,
        hex::encode(hub_account.secret_key().serialize()),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "testnet",
        100_000_000,
        100_000_000,
    )
    .unwrap();
    let recovered = reopened.close_channel(&request).await.unwrap();
    assert_eq!(recovered.status, "retired");
    let bodies = submitted.read().await;
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
    node_handle.abort();
}
