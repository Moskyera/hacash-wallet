mod support;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{AddrOrPtr, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::api::FastPayRequest;
use l2_fast_pay_hub::l1_channel::transaction_commitment;
use l2_fast_pay_hub::l1_channel_close::{
    L1_CHANNEL_CLOSE_SCHEMA, L1ChannelCloseRequest, close_request_commitment,
};
use mint::action::{ChannelClose, ChannelOpen};
use protocol::action::{ChainAllow, ChainIDList, HacFromToTrs};
use protocol::transaction::TransactionType2;
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;

const JOURNAL_KEY: &str = "8383838383838383838383838383838383838383838383838383838383838383";

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

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

fn close_request(user: &Account, hub: &Account, channel_id: &str) -> L1ChannelCloseRequest {
    close_request_with_transfer(user, hub, channel_id, None)
}

fn close_request_with_transfer(
    user: &Account,
    hub: &Account,
    channel_id: &str,
    transfer_hac: Option<&str>,
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
    if let Some(amount) = transfer_hac {
        let mut transfer = HacFromToTrs::new();
        transfer.from = AddrOrPtr::from_addr(Address::from_readable(user.readable()).unwrap());
        transfer.to = AddrOrPtr::from_addr(Address::from_readable(hub.readable()).unwrap());
        transfer.hacash = Amount::from(amount).unwrap();
        tx.push_action(Box::new(transfer)).unwrap();
    }
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

async fn spawn_close_node(
    channel: Value,
    close_confirmations: u64,
) -> (
    String,
    Arc<RwLock<Value>>,
    Arc<RwLock<HashMap<String, Value>>>,
    tokio::task::JoinHandle<()>,
) {
    let channel = Arc::new(RwLock::new(channel));
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
                    "actions": {"registered": [1, 2, 3, 14, 1041], "enabled": [1, 2, 3, 14, 1041]}
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
                        let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        assert!(matches!(tx.actions().len(), 2 | 3));
                        assert_eq!(tx.actions()[0].kind(), 0x0411);
                        if tx.actions().len() == 3 {
                            assert_eq!(tx.actions()[1].kind(), 3);
                            assert_eq!(tx.actions()[2].kind(), 14);
                        }
                        assert_eq!(tx.signs().len(), 2);
                        tx.verify_signature().unwrap();
                        let hash = hex::encode(tx.hash().as_bytes());
                        let mut current = channel.write().await;
                        match tx.actions()[1].kind() {
                            2 => {
                                let action = ChannelOpen::downcast(&tx.actions()[1]).unwrap();
                                let channel_id = hex::encode(action.channel_id.as_bytes());
                                let next_reuse = if current["id"].as_str() == Some(&channel_id)
                                    && current["status"].as_u64() == Some(2)
                                {
                                    current["reuse_version"].as_u64().unwrap_or(0) + 1
                                } else {
                                    1
                                };
                                current["id"] = json!(channel_id);
                                current["status"] = json!(0);
                                current["open_height"] = json!(900_000 + next_reuse - 1);
                                current["close_height"] = json!(0);
                                current["reuse_version"] = json!(next_reuse);
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
                                        "block": {
                                            "height": current["open_height"].as_u64().unwrap(),
                                            "timestamp": now_unix()
                                        },
                                        "confirm": 6
                                    }),
                                );
                            }
                            3 => {
                                current["status"] = json!(2);
                                current["close_height"] = json!(900_001);
                                let actions = tx
                                    .actions()
                                    .iter()
                                    .map(|action| json!({"kind": action.kind()}))
                                    .collect::<Vec<_>>();
                                let signatures = tx
                                    .signs()
                                    .iter()
                                    .map(|_| json!({"complete": true}))
                                    .collect::<Vec<_>>();
                                transactions.write().await.insert(
                                    hash.clone(),
                                    json!({
                                        "ret": 0,
                                        "hash": hash,
                                        "hash_with_fee": hex::encode(tx.hash_with_fee().as_bytes()),
                                        "tx_type": 2,
                                        "body": body,
                                        "actions": actions,
                                        "signatures": signatures,
                                        "block": {"height": 900_001, "timestamp": now_unix()},
                                        "confirm": close_confirmations
                                    }),
                                );
                            }
                            kind => panic!("unexpected action {kind}"),
                        }
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), channel, transactions, handle)
}

#[tokio::test]
async fn close_freezes_signs_broadcasts_confirms_and_is_restart_idempotent() {
    let user = account("durable-close-user");
    let hub_account = account("durable-close-hub");
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
    let reopen_request = support::channel_open_request_for_reuse(&user, &hub_account, 2);
    let (node_url, node_channel, _transactions, node_handle) = spawn_close_node(channel, 6).await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");

    let first = {
        let hub = HubState::new_secure_with_policy(
            "durable close hub",
            hub_account.readable(),
            &node_url,
            None,
            state_path.clone(),
            secret_hex(&hub_account),
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
        assert_eq!(response.status, "retired");
        assert!(response.transaction_hash.is_some());
        let public_json = serde_json::to_string(&response).unwrap();
        assert!(!public_json.contains("signed_transaction"));

        let reopen_error = hub.open_channel(&reopen_request).await.unwrap_err();
        assert!(reopen_error.to_string().contains("fresh one-use channel"));
        let current = node_channel.read().await.clone();
        assert_eq!(current["status"], json!(2));
        assert_eq!(current["reuse_version"], json!(1));
        response
    };

    let reopened = HubState::new_secure_with_policy(
        "durable close hub",
        hub_account.readable(),
        &node_url,
        None,
        state_path.clone(),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "testnet",
        100_000_000,
        100_000_000,
    )
    .unwrap();
    let sealed = std::fs::read_to_string(&state_path).unwrap();
    assert!(sealed.contains("hpay-hub-state-aead/1"));
    assert!(!sealed.contains(&request.operation_id));
    assert!(!sealed.contains(&request.partial_transaction_hex));
    let mut tampered_authorization = request.clone();
    tampered_authorization.authorization_signature_hex = "00".repeat(64);
    assert!(
        reopened
            .close_channel(&tampered_authorization)
            .await
            .is_err()
    );
    let replay = reopened.close_channel(&request).await.unwrap();
    assert_eq!(first, replay);
    let reopen_error = reopened.open_channel(&reopen_request).await.unwrap_err();
    assert!(reopen_error.to_string().contains("fresh one-use channel"));
    assert_eq!(node_channel.read().await["reuse_version"], json!(1));
    node_handle.abort();
}

#[tokio::test]
async fn changed_l2_balance_closes_atomically_with_exact_principal_transfer() {
    let user = account("composite-close-user");
    let hub_account = account("composite-close-hub");
    let open_request = support::channel_open_request(&user, &hub_account);
    let channel_id = open_request.channel_id.clone();
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
    let (node_url, node_channel, _transactions, node_handle) = spawn_close_node(channel, 6).await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("composite-close-state.json");
    let close_request =
        close_request_with_transfer(&user, &hub_account, &channel_id, Some("0.001"));

    let first = {
        let hub = HubState::new_secure_with_policy(
            "composite close hub",
            hub_account.readable(),
            &node_url,
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            JOURNAL_KEY,
            &"b5".repeat(32),
            "testnet",
            100_000_000,
            100_000_000,
        )
        .unwrap();
        hub.open_channel(&open_request).await.unwrap();
        node_channel.write().await["id"] = json!(channel_id);

        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let pending = hub
            .settle_fast_pay(&FastPayRequest {
                operation_id: uuid::Uuid::new_v4().to_string(),
                idempotency_key: idempotency_key.clone(),
                payer: user.readable().into(),
                payee: hub_account.readable().into(),
                amount: "0.001".into(),
                channel_id: channel_id.clone(),
                fee_payer: None,
            })
            .await
            .unwrap();
        let mut bill = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(
            pending.bill_hex.as_deref().unwrap(),
        )
        .unwrap();
        bill.chain_payment.fill_sign_by_account(&user).unwrap();
        let confirmed = hub
            .confirm_fast_pay(&pending.payment_id, &idempotency_key, &bill.to_bill_hex())
            .unwrap();
        assert_eq!(confirmed.status, "settled");

        let response = hub.close_channel(&close_request).await.unwrap();
        assert_eq!(response.status, "retired");
        assert_eq!(node_channel.read().await["status"], json!(2));
        response
    };

    let reopened = HubState::new_secure_with_policy(
        "composite close hub",
        hub_account.readable(),
        &node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"b5".repeat(32),
        "testnet",
        100_000_000,
        100_000_000,
    )
    .unwrap();
    assert_eq!(reopened.close_channel(&close_request).await.unwrap(), first);
    node_handle.abort();
}

#[tokio::test]
async fn close_waits_for_depth_then_retires_on_exact_inclusion() {
    let user = account("confirmation-depth-user");
    let hub_account = account("confirmation-depth-hub");
    let open_request = support::channel_open_request(&user, &hub_account);
    let channel_id = open_request.channel_id.clone();
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
    let request = close_request(&user, &hub_account, &channel_id);
    let (node_url, node_channel, transactions, node_handle) = spawn_close_node(channel, 0).await;
    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "confirmation depth hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("state.json"),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"c5".repeat(32),
        "testnet",
        1_000_000,
        1_000_000,
    )
    .unwrap();
    hub.open_channel(&open_request).await.unwrap();
    node_channel.write().await["id"] = json!(channel_id);
    let waiting = hub.close_channel(&request).await.unwrap();
    assert_eq!(waiting.status, "submitted");

    let hash = waiting.transaction_hash.as_deref().unwrap();
    transactions.write().await.get_mut(hash).unwrap()["confirm"] = json!(6);
    let retired = hub.close_channel(&request).await.unwrap();
    assert_eq!(retired.status, "retired");
    node_handle.abort();
}

#[tokio::test]
async fn pre_finality_reorg_moves_close_to_recovery_required() {
    let user = account("pre-finality-reorg-user");
    let hub_account = account("pre-finality-reorg-hub");
    let open_request = support::channel_open_request(&user, &hub_account);
    let channel_id = open_request.channel_id.clone();
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
    let request = close_request(&user, &hub_account, &channel_id);
    let (node_url, node_channel, transactions, node_handle) = spawn_close_node(channel, 0).await;
    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "pre-finality reorg hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("state.json"),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"d5".repeat(32),
        "testnet",
        1_000_000,
        1_000_000,
    )
    .unwrap();
    hub.open_channel(&open_request).await.unwrap();
    node_channel.write().await["id"] = json!(channel_id);
    let waiting = hub.close_channel(&request).await.unwrap();
    assert_eq!(waiting.status, "submitted");

    transactions.write().await.clear();
    let mut channel = node_channel.write().await;
    channel["status"] = json!(0);
    channel["close_height"] = json!(0);
    drop(channel);
    let recovered = hub.close_channel(&request).await.unwrap();
    assert_eq!(recovered.status, "recovery_required");
    node_handle.abort();
}
