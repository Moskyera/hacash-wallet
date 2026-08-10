use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::get;
use axum::{Json, Router};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::api::FastPayRequest;
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::journal::{AuthenticatedJournal, JournalBinding, JournalPhase};
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const JOURNAL_KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

fn account(seed: &str) -> Account {
    Account::create_by(seed).unwrap()
}

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

async fn mock_node(channels: HashMap<String, Value>) -> (String, JoinHandle<()>) {
    let channels = Arc::new(RwLock::new(channels));
    let app = Router::new().route(
        "/query/channel",
        get({
            let channels = channels.clone();
            move |Query(query): Query<ChannelQuery>| {
                let channels = channels.clone();
                async move {
                    let id = query.id.unwrap_or_default();
                    let channels = channels.read().await;
                    Json(
                        channels
                            .get(&id)
                            .cloned()
                            .unwrap_or_else(|| json!({ "ret": 1, "err": "channel not found" })),
                    )
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), handle)
}

async fn fixture(
    seed: &str,
) -> (
    Account,
    Account,
    String,
    String,
    String,
    String,
    JoinHandle<()>,
) {
    let payer = account(&format!("{seed}-payer"));
    let hub = account(&format!("{seed}-hub"));
    let payer_address = payer.readable().to_owned();
    let hub_address = hub.readable().to_owned();
    let channel_id = derive_channel_id(&payer_address, &hub_address, 1);
    let mut channels = HashMap::new();
    channels.insert(
        channel_id.clone(),
        json!({
            "ret": 0,
            "id": channel_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": payer_address, "hacash": "10", "satoshi": 0 },
            "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, handle) = mock_node(channels).await;
    (
        payer,
        hub,
        payer_address,
        hub_address,
        channel_id,
        node_url,
        handle,
    )
}

fn request(
    payer: &str,
    payee: &str,
    channel_id: &str,
    operation_id: String,
    idempotency_key: String,
    amount: &str,
) -> FastPayRequest {
    FastPayRequest {
        operation_id,
        idempotency_key,
        payer: payer.to_owned(),
        payee: payee.to_owned(),
        amount: amount.to_owned(),
        channel_id: channel_id.to_owned(),
        fee_payer: None,
    }
}

fn payer_signed_bill(pending_bill: &str, payer: &Account) -> String {
    let mut bill = ChannelPayCompleteDocuments::from_bill_hex(pending_bill).unwrap();
    bill.chain_payment.fill_sign_by_account(payer).unwrap();
    bill.to_bill_hex()
}

#[tokio::test]
async fn signer_without_authenticated_storage_never_advertises_ready_or_signs() {
    let hub = account("memory-only-hub");
    let hub_address = hub.readable().to_owned();
    let state = HubState::new(
        "memory only",
        hub_address.clone(),
        "http://127.0.0.1:1",
        None,
        0,
        Some(secret_hex(&hub)),
    )
    .unwrap();
    assert!(!state.health().settlement_ready);
    let req = request(
        account("memory-only-payer").readable(),
        &hub_address,
        "channel",
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        "1",
    );
    assert!(
        state
            .settle_fast_pay(&req)
            .await
            .unwrap_err()
            .to_string()
            .contains("durable authenticated L2 storage")
    );
}

#[tokio::test]
async fn readiness_downgrade_after_persist_produces_no_hub_signature() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let payer = account("downgrade-payer");
    let hub_account = account("downgrade-hub");
    let payer_address = payer.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let channel_id = derive_channel_id(&payer_address, &hub_address, 1);
    let channel = json!({
        "ret": 0,
        "id": channel_id,
        "status": 0,
        "reuse_version": 1,
        "left": { "address": payer_address, "hacash": "10", "satoshi": 0 },
        "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/query/channel",
            get({
                let channel = channel.clone();
                move || {
                    let channel = channel.clone();
                    async move { Json(channel) }
                }
            }),
        )
        .route(
            "/query/capabilities",
            get({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        let fresh = calls.fetch_add(1, Ordering::SeqCst) == 0;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        Json(json!({
                            "ret": 0,
                            "api_version": 1,
                            "chain": {
                                "id": 0,
                                "height": 900000,
                                "next_height": 900001,
                                "mainnet": true
                            },
                            "network": {
                                "kind": "mainnet",
                                "block_1_hash": "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
                                "instance_id": "22".repeat(32)
                            },
                            "sync": {
                                "tip_timestamp_unix": now,
                                "max_tip_age_seconds": 3600,
                                "fresh": fresh
                            },
                            "actions": {
                                "registered": [1, 2, 3],
                                "enabled": [1, 2, 3]
                            }
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_address = listener.local_addr().unwrap();
    let node_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "downgrade hub",
        hub_address.clone(),
        format!("http://{node_address}"),
        None,
        directory.path().join("state.json"),
        secret_hex(&hub_account),
        JOURNAL_KEY,
        "mainnet-pilot",
        100_000_000,
        100_000_000,
    )
    .unwrap();
    let operation_id = uuid::Uuid::new_v4().to_string();
    let request = request(
        &payer_address,
        &hub_address,
        &channel_id,
        operation_id.clone(),
        uuid::Uuid::new_v4().to_string(),
        "1",
    );
    let error = hub.settle_fast_pay(&request).await.unwrap_err();
    assert!(error.to_string().contains("stale"), "{error}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let persisted = hub.payment_status(&operation_id).unwrap();
    assert_eq!(persisted.status, "persisted_before_signing");
    let documents =
        ChannelPayCompleteDocuments::from_bill_hex(persisted.bill_hex.as_deref().unwrap()).unwrap();
    assert!(
        !documents
            .chain_payment
            .signature_verified_for_readable(&hub_address)
    );

    node_handle.abort();
}

#[tokio::test]
async fn retries_are_idempotent_and_channel_reservations_are_exclusive() {
    let (payer, hub, payer_address, hub_address, channel_id, node_url, node_handle) =
        fixture("idempotency").await;
    let dir = tempdir().unwrap();
    let state = Arc::new(
        HubState::new_secure(
            "safe hub",
            hub_address.clone(),
            node_url,
            dir.path().join("state-2.json"),
            0,
            Some(secret_hex(&hub)),
            JOURNAL_KEY,
        )
        .unwrap(),
    );
    let operation_id = uuid::Uuid::new_v4().to_string();
    let idempotency_key = uuid::Uuid::new_v4().to_string();
    let first = request(
        &payer_address,
        &hub_address,
        &channel_id,
        operation_id,
        idempotency_key.clone(),
        "1",
    );
    let prepared = state.settle_fast_pay(&first).await.unwrap();
    let repeated = state.settle_fast_pay(&first).await.unwrap();
    assert_eq!(prepared.payment_id, repeated.payment_id);
    assert_eq!(prepared.bill_hex, repeated.bill_hex);

    let changed = request(
        &payer_address,
        &hub_address,
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        idempotency_key.clone(),
        "2",
    );
    assert!(
        state
            .settle_fast_pay(&changed)
            .await
            .unwrap_err()
            .to_string()
            .contains("idempotency conflict")
    );

    let changed_recipient = request(
        &payer_address,
        account("different-recipient").readable(),
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        idempotency_key,
        "1",
    );
    assert!(
        state
            .settle_fast_pay(&changed_recipient)
            .await
            .unwrap_err()
            .to_string()
            .contains("idempotency conflict")
    );

    let other = request(
        &payer_address,
        &hub_address,
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        "0.5",
    );
    assert!(
        state
            .settle_fast_pay(&other)
            .await
            .unwrap_err()
            .to_string()
            .contains("active Fast Pay reservation")
    );
    drop(payer);
    node_handle.abort();
}

#[tokio::test]
async fn durable_state_failure_prevents_signature_production() {
    let (_payer, hub, payer_address, hub_address, channel_id, node_url, node_handle) =
        fixture("persist-before-sign-failure").await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("state.json");
    let state = HubState::new_secure(
        "safe hub",
        hub_address.clone(),
        node_url,
        state_path.clone(),
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    )
    .unwrap();

    std::fs::remove_file(&state_path).unwrap();
    std::fs::create_dir(&state_path).unwrap();
    let req = request(
        &payer_address,
        &hub_address,
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        "1",
    );
    assert!(state.settle_fast_pay(&req).await.is_err());
    assert!(!state.health().settlement_ready);
    let readiness = state.mainnet_readiness().await;
    assert!(!readiness.payments_enabled);
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker.contains("authenticated_storage_or_recovery"))
    );
    drop(state);

    let journal = AuthenticatedJournal::open(
        state_path.with_extension("journal.jsonl"),
        &[0x42; 32],
        JournalBinding {
            wallet_scope: format!("hub:{hub_address}"),
            hub_or_provider_identity: hub_address,
            channel_id: None,
        },
    )
    .unwrap();
    let records = journal.verify().unwrap();
    assert_eq!(
        records.last().map(|record| &record.operation_phase),
        Some(&JournalPhase::StatePersistedBeforeSigning)
    );
    assert!(
        records
            .iter()
            .all(|record| record.operation_phase != JournalPhase::SignatureProduced)
    );
    node_handle.abort();
}

#[tokio::test]
async fn concurrent_operations_cannot_reserve_the_same_channel() {
    let (_payer, hub, payer_address, hub_address, channel_id, node_url, node_handle) =
        fixture("concurrent").await;
    let dir = tempdir().unwrap();
    let state = Arc::new(
        HubState::new_secure(
            "safe hub",
            hub_address.clone(),
            node_url,
            dir.path().join("state.json"),
            0,
            Some(secret_hex(&hub)),
            JOURNAL_KEY,
        )
        .unwrap(),
    );
    let first = request(
        &payer_address,
        &hub_address,
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        "1",
    );
    let second = request(
        &payer_address,
        &hub_address,
        &channel_id,
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        "2",
    );
    let (first_result, second_result) = tokio::join!(
        state.settle_fast_pay(&first),
        state.settle_fast_pay(&second)
    );
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let error = first_result.err().or_else(|| second_result.err()).unwrap();
    assert!(error.to_string().contains("active Fast Pay reservation"));
    node_handle.abort();
}

#[tokio::test]
async fn signed_and_completed_operations_survive_restart_without_duplicate_effects() {
    let (payer, hub, payer_address, hub_address, channel_id, node_url, node_handle) =
        fixture("restart").await;
    let dir = tempdir().unwrap();
    let state_path = dir.path().join("state.json");
    let operation_id = uuid::Uuid::new_v4().to_string();
    let idempotency_key = uuid::Uuid::new_v4().to_string();
    let req = request(
        &payer_address,
        &hub_address,
        &channel_id,
        operation_id.clone(),
        idempotency_key.clone(),
        "1",
    );

    let state = HubState::new_secure(
        "safe hub",
        hub_address.clone(),
        node_url.clone(),
        state_path.clone(),
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    )
    .unwrap();
    let pending = state.settle_fast_pay(&req).await.unwrap();
    let signed = payer_signed_bill(pending.bill_hex.as_deref().unwrap(), &payer);
    drop(state);

    let restarted = HubState::new_secure(
        "safe hub",
        hub_address.clone(),
        node_url.clone(),
        state_path.clone(),
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    )
    .unwrap();
    let repeated = restarted.settle_fast_pay(&req).await.unwrap();
    assert_eq!(pending.bill_hex, repeated.bill_hex);
    let completed = restarted
        .confirm_fast_pay(&operation_id, &idempotency_key, &signed)
        .unwrap();
    assert_eq!(completed.status, "settled");
    drop(restarted);

    let restarted = HubState::new_secure(
        "safe hub",
        hub_address,
        node_url,
        state_path,
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    )
    .unwrap();
    let duplicate = restarted
        .confirm_fast_pay(&operation_id, &idempotency_key, &signed)
        .unwrap();
    assert_eq!(completed.bill_hex, duplicate.bill_hex);
    assert!(
        restarted
            .confirm_fast_pay(&operation_id, &uuid::Uuid::new_v4().to_string(), &signed)
            .unwrap_err()
            .to_string()
            .contains("idempotency conflict")
    );
    node_handle.abort();
}

#[tokio::test]
async fn state_file_has_a_single_process_owner() {
    let (_payer, hub, _payer_address, hub_address, _channel_id, _node_url, node_handle) =
        fixture("exclusive-lock").await;
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let first = HubState::new_secure(
        "safe hub",
        hub_address.clone(),
        "http://127.0.0.1:1",
        path.clone(),
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    )
    .unwrap();
    let second = match HubState::new_secure(
        "safe hub",
        hub_address,
        "http://127.0.0.1:1",
        path,
        0,
        Some(secret_hex(&hub)),
        JOURNAL_KEY,
    ) {
        Ok(_) => panic!("a second hub process must not acquire the same state"),
        Err(error) => error,
    };
    assert!(second.to_string().contains("already owns this state"));
    drop(first);
    node_handle.abort();
}

#[tokio::test]
async fn deleting_the_hub_journal_is_detected() {
    let (_payer, hub_account, _payer_address, hub_address, _channel_id, node_url, node_handle) =
        fixture("deleted-hub-journal").await;
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("state.json");
    let state = HubState::new_secure(
        "safe hub",
        hub_address.clone(),
        node_url.clone(),
        state_path.clone(),
        0,
        Some(secret_hex(&hub_account)),
        JOURNAL_KEY,
    )
    .unwrap();
    drop(state);
    std::fs::remove_file(state_path.with_extension("journal.jsonl")).unwrap();
    let error = match HubState::new_secure(
        "safe hub",
        hub_address,
        node_url,
        state_path,
        0,
        Some(secret_hex(&hub_account)),
        JOURNAL_KEY,
    ) {
        Ok(_) => panic!("deleted authenticated journal must not create a new baseline"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("JournalSequenceRollback"));
    node_handle.abort();
}
