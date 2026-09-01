use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{AddrHac, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, request_commitment, transaction_commitment,
};
use mint::action::ChannelOpen;
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType2;
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;

const JOURNAL_KEY: &str = "7373737373737373737373737373737373737373737373737373737373737373";
const PILOT_CHAIN_ID: u32 = 7;
const PILOT_BLOCK_ONE: &str = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const PILOT_INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

#[derive(Deserialize)]
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

async fn spawn_fresh_mainnet_node(
    open_confirmations: u64,
) -> (
    String,
    Arc<RwLock<Option<Value>>>,
    Arc<RwLock<HashMap<String, Value>>>,
    Arc<RwLock<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let channel = Arc::new(RwLock::new(None::<Value>));
    let transactions = Arc::new(RwLock::new(HashMap::<String, Value>::new()));
    let submitted = Arc::new(RwLock::new(Vec::<String>::new()));
    let app = Router::new()
        .route(
            "/query/channel",
            get({
                let channel = channel.clone();
                move |Query(query): Query<ChannelQuery>| {
                    let channel = channel.clone();
                    async move {
                        match channel.read().await.clone() {
                            Some(value)
                                if query.id.as_deref()
                                    == value.get("id").and_then(Value::as_str) =>
                            {
                                Json(value)
                            }
                            _ => Json(json!({"ret": 1, "err": "channel not found"})),
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
                    "chain": { "id": PILOT_CHAIN_ID, "height": 900000, "next_height": 900001, "mainnet": false },
                    "network": {
                        "kind": "local_pilot_v1",
                        "node_profile_id": "hpay-local-pilot-chain-v1",
                        "block_1_hash": PILOT_BLOCK_ONE,
                        "instance_id": PILOT_INSTANCE,
                        "transaction_format_version": 2
                    },
                    "sync": {
                        "tip_timestamp_unix": now,
                        "max_tip_age_seconds": 3600,
                        "fresh": true
                    },
                    "transactions": { "registered": [2], "enabled": [2] },
                    "actions": { "registered": [1, 2, 3, 1041], "enabled": [1, 2, 3, 1041] }
                }))
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let channel = channel.clone();
                let transactions = transactions.clone();
                let submitted = submitted.clone();
                move |body: String| {
                    let channel = channel.clone();
                    let transactions = transactions.clone();
                    let submitted = submitted.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (tx, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        assert_eq!(tx.actions().len(), 2);
                        assert_eq!(tx.actions()[0].kind(), 0x0411);
                        assert_eq!(tx.actions()[1].kind(), 2);
                        assert_eq!(tx.signs().len(), 2);
                        tx.verify_signature().unwrap();
                        let hash = hex::encode(tx.hash().as_bytes());
                        let action = ChannelOpen::downcast(&tx.actions()[1]).unwrap();
                        let channel_id = hex::encode(action.channel_id.as_bytes());
                        *channel.write().await = Some(json!({
                            "ret": 0,
                            "id": channel_id,
                            "status": 0,
                            "open_height": 900001,
                            "close_height": 0,
                            "reuse_version": 1,
                            "left": {
                                "address": action.left_bill.address.to_readable(),
                                "hacash": action.left_bill.amount.to_fin_string(),
                                "satoshi": 0
                            },
                            "right": {
                                "address": action.right_bill.address.to_readable(),
                                "hacash": action.right_bill.amount.to_fin_string(),
                                "satoshi": 0
                            }
                        }));
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
                                "hash": hash.clone(),
                                "hash_with_fee": hex::encode(tx.hash_with_fee().as_bytes()),
                                "tx_type": 2,
                                "body": body.clone(),
                                "actions": actions,
                                "signatures": signatures,
                                "block": {"height": 900_001, "timestamp": now_unix()},
                                "confirm": open_confirmations
                            }),
                        );
                        submitted.write().await.push(body);
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
    (
        format!("http://{address}"),
        channel,
        transactions,
        submitted,
        handle,
    )
}

fn channel_open_request(user: &Account, hub: &Account) -> L1ChannelOpenRequest {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let channel_id = derive_channel_id(user.readable(), hub.readable(), 1);
    let mut action = ChannelOpen::new();
    action.channel_id =
        ChannelId::from(<[u8; 16]>::try_from(hex::decode(&channel_id).unwrap()).unwrap());
    action.left_bill = AddrHac {
        address: Address::from_readable(user.readable()).unwrap(),
        amount: Amount::from("0.01").unwrap(),
    };
    action.right_bill = AddrHac {
        address: Address::from_readable(hub.readable()).unwrap(),
        amount: Amount::from("0").unwrap(),
    };
    let now = now_unix();
    let mut tx = TransactionType2::new_by(
        Address::from_readable(user.readable()).unwrap(),
        Amount::from("0.0001").unwrap(),
        now,
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(PILOT_CHAIN_ID)]).unwrap();
    tx.push_action(Box::new(guard)).unwrap();
    tx.push_action(Box::new(action)).unwrap();
    tx.fill_sign(user).unwrap();
    let partial_transaction_hex = hex::encode(tx.serialize());
    let mut request = L1ChannelOpenRequest {
        schema: L1_CHANNEL_OPEN_SCHEMA.into(),
        network: "local_pilot_v1".into(),
        chain_id: PILOT_CHAIN_ID,
        mainnet: false,
        block_1_hash: PILOT_BLOCK_ONE.into(),
        node_profile_id: "hpay-local-pilot-chain-v1".into(),
        network_instance_id: PILOT_INSTANCE.into(),
        transaction_format_version: 2,
        operation_id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        created_unix: now,
        expires_unix: now + 60,
        hub_address: hub.readable().into(),
        channel_id,
        expected_reuse_version: 1,
        partial_transaction_commitment: transaction_commitment(&partial_transaction_hex).unwrap(),
        partial_transaction_hex,
        authorization_public_key_hex: String::new(),
        authorization_signature_hex: String::new(),
    };
    let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_public_key_hex = hex::encode(user.public_key().serialize_compressed());
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
    request
}

fn refresh_request_authorization(request: &mut L1ChannelOpenRequest, user: &Account) {
    let commitment: [u8; 32] = hex::decode(request_commitment(request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_public_key_hex = hex::encode(user.public_key().serialize_compressed());
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
}

#[tokio::test]
async fn channel_open_is_broadcast_confirmed_idempotent_and_restart_durable() {
    let user = account("durable-channel-user");
    let hub_account = account("durable-channel-hub");
    let request = channel_open_request(&user, &hub_account);
    let (node_url, _channel, _transactions, submitted, node_handle) =
        spawn_fresh_mainnet_node(6).await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");

    let first = {
        let hub = HubState::new_secure_with_policy(
            "durable channel hub",
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
        let first = hub.open_channel(&request).await.unwrap();
        assert_eq!(first.status, "confirmed");
        assert!(first.transaction_hash.is_some());
        assert_eq!(submitted.read().await.len(), 1);
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("signed_transaction")
        );

        let mut reused_operation_id = request.clone();
        reused_operation_id.idempotency_key = uuid::Uuid::new_v4().to_string();
        refresh_request_authorization(&mut reused_operation_id, &user);
        assert!(hub.open_channel(&reused_operation_id).await.is_err());

        let mut reused_transaction = request.clone();
        reused_transaction.operation_id = uuid::Uuid::new_v4().to_string();
        reused_transaction.idempotency_key = uuid::Uuid::new_v4().to_string();
        refresh_request_authorization(&mut reused_transaction, &user);
        assert!(hub.open_channel(&reused_transaction).await.is_err());

        let replay = hub.open_channel(&request).await.unwrap();
        assert_eq!(first, replay);
        assert_eq!(submitted.read().await.len(), 1);
        first
    };

    let sealed = std::fs::read_to_string(&state_path).unwrap();
    assert!(sealed.contains("hpay-hub-state-aead/1"));
    assert!(!sealed.contains(&request.operation_id));
    assert!(!sealed.contains(&request.partial_transaction_hex));

    let reopened = HubState::new_secure_with_policy(
        "durable channel hub",
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
    let mut tampered_authorization = request.clone();
    tampered_authorization.authorization_signature_hex = "00".repeat(64);
    assert!(
        reopened
            .open_channel(&tampered_authorization)
            .await
            .is_err()
    );
    let after_restart = reopened.open_channel(&request).await.unwrap();
    assert_eq!(first, after_restart);
    assert_eq!(submitted.read().await.len(), 1);
    node_handle.abort();
}

#[tokio::test]
async fn invalid_request_authorization_is_rejected_before_hub_signing() {
    let user = account("invalid-auth-user");
    let hub_account = account("invalid-auth-hub");
    let mut request = channel_open_request(&user, &hub_account);
    request.authorization_signature_hex = "00".repeat(64);
    let (node_url, _channel, _transactions, submitted, node_handle) =
        spawn_fresh_mainnet_node(6).await;
    let directory = tempdir().unwrap();
    let hub = Arc::new(
        HubState::new_secure_with_policy(
            "invalid auth hub",
            hub_account.readable(),
            node_url,
            None,
            directory.path().join("hub-state.json"),
            secret_hex(&hub_account),
            JOURNAL_KEY,
            &"a5".repeat(32),
            "testnet",
            100_000_000,
            100_000_000,
        )
        .unwrap(),
    );
    assert!(hub.open_channel(&request).await.is_err());
    assert!(submitted.read().await.is_empty());
    node_handle.abort();
}

#[tokio::test]
async fn channel_open_waits_for_six_confirmations_without_rebroadcast() {
    let user = account("open-finality-user");
    let hub_account = account("open-finality-hub");
    let request = channel_open_request(&user, &hub_account);
    let (node_url, _channel, transactions, submitted, node_handle) =
        spawn_fresh_mainnet_node(0).await;
    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "open finality hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "testnet",
        100_000_000,
        100_000_000,
    )
    .unwrap();

    let pending = hub.open_channel(&request).await.unwrap();
    assert_eq!(pending.status, "submitted");
    assert_eq!(submitted.read().await.len(), 1);
    let hash = pending.transaction_hash.as_deref().unwrap();
    transactions.write().await.get_mut(hash).unwrap()["confirm"] = json!(6);

    let confirmed = hub.open_channel(&request).await.unwrap();
    assert_eq!(confirmed.status, "confirmed");
    assert_eq!(submitted.read().await.len(), 1);
    node_handle.abort();
}

#[tokio::test]
async fn channel_open_enters_recovery_when_pre_finality_evidence_disappears() {
    let user = account("open-reorg-user");
    let hub_account = account("open-reorg-hub");
    let request = channel_open_request(&user, &hub_account);
    let (node_url, channel, transactions, submitted, node_handle) =
        spawn_fresh_mainnet_node(0).await;
    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "open reorg hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "testnet",
        100_000_000,
        100_000_000,
    )
    .unwrap();

    let pending = hub.open_channel(&request).await.unwrap();
    assert_eq!(pending.status, "submitted");
    assert_eq!(submitted.read().await.len(), 1);
    transactions.write().await.clear();
    *channel.write().await = None;

    let recovery = hub.open_channel(&request).await.unwrap();
    assert_eq!(recovery.status, "recovery_required");
    assert_eq!(submitted.read().await.len(), 1);
    node_handle.abort();
}
