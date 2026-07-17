use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::get;
use axum::{Json, Router};
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::{HubState, build_router};
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

fn test_account(seed: &str) -> Account {
    Account::create_by(seed).unwrap()
}

fn account_secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

async fn prepare_and_confirm(
    client: &reqwest::Client,
    base: &str,
    request: Value,
    payer: &Account,
) -> Value {
    let pending: Value = client
        .post(format!("{base}/v1/fast-pay"))
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending["status"], "pending", "prepare response: {pending}");
    let payment_id = pending["payment_id"].as_str().unwrap();
    let mut bill = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(
        pending["bill_hex"].as_str().unwrap(),
    )
    .unwrap();
    bill.chain_payment.fill_sign_by_account(payer).unwrap();
    client
        .post(format!("{base}/v1/fast-pay/{payment_id}/confirm"))
        .json(&json!({ "bill_hex": bill.to_bill_hex() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[test]
fn hub_rejects_any_fast_pay_fee() {
    let err = match HubState::new(
        "fee hub",
        "1Hub",
        "http://127.0.0.1:8080",
        None,
        0.001,
        None,
    ) {
        Ok(_) => panic!("fee-charging hub must be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("fee-free"));
}

async fn spawn_mock_node(channels: HashMap<String, Value>) -> (String, JoinHandle<()>) {
    let store = Arc::new(RwLock::new(channels));
    let app = Router::new().route(
        "/query/channel",
        get({
            let store = store.clone();
            move |Query(q): Query<ChannelQuery>| {
                let store = store.clone();
                async move {
                    let id = q.id.unwrap_or_default();
                    let map = store.read().await;
                    if let Some(body) = map.get(&id) {
                        Json(body.clone())
                    } else {
                        Json(json!({ "ret": 1, "err": "channel not found" }))
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn hub_health_and_same_channel_fast_pay() {
    let alice = test_account("alice-same-channel");
    let hub_account = test_account("hub-same-channel");
    let alice_address = alice.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let ch_id = derive_channel_id(&alice_address, &hub_address, 1);
    let channel = json!({
        "ret": 0,
        "id": ch_id,
        "status": 0,
        "reuse_version": 1,
        "left": { "address": alice_address, "hacash": "10", "satoshi": 0 },
        "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
    });
    let mut channels = HashMap::new();
    channels.insert(ch_id.clone(), channel);
    let (node_url, node_handle) = spawn_mock_node(channels).await;

    let dir = tempdir().unwrap();
    let state_path = dir.path().join("hub-state.json");
    let hub = Arc::new(
        HubState::new(
            "test hub",
            hub_address.clone(),
            node_url,
            Some(state_path),
            0.0,
            Some(account_secret_hex(&hub_account)),
        )
        .unwrap(),
    );
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{hub_addr}");

    let health: Value = client
        .get(format!("{base}/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);
    assert_eq!(health["hub_address"], hub_address);
    assert_eq!(health["version"], 4);
    assert_eq!(health["hub_fee_mei"], 0.0);
    assert_eq!(health["settlement_ready"], true);
    assert_eq!(health["cross_channel_ready"], true);

    // Pay hub (other party on same channel)
    let pay = prepare_and_confirm(
        &client,
        &base,
        json!({
            "payer": alice_address,
            "payee": hub_address,
            "amount": "1",
            "channel_id": ch_id
        }),
        &alice,
    )
    .await;
    assert_eq!(pay["status"], "settled", "pay response: {pay}");
    assert!(pay["summary"].as_str().unwrap().contains("on-channel"));

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_routes_cross_channel_after_recipient_confirmation() {
    let alice = test_account("alice-cross-channel");
    let bob = test_account("bob-cross-channel");
    let hub_account = test_account("hub-cross-channel");
    let alice_address = alice.readable().to_owned();
    let bob_address = bob.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let alice_ch_id = derive_channel_id(&alice_address, &hub_address, 1);
    let bob_ch_id = derive_channel_id(&bob_address, &hub_address, 1);

    let mut channels = HashMap::new();
    channels.insert(
        alice_ch_id.clone(),
        json!({
            "ret": 0,
            "id": alice_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": alice_address, "hacash": "10", "satoshi": 0 },
            "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
        }),
    );
    channels.insert(
        bob_ch_id.clone(),
        json!({
            "ret": 0,
            "id": bob_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": bob_address, "hacash": "2", "satoshi": 0 },
            "right": { "address": hub_address, "hacash": "5", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;

    let hub = Arc::new(
        HubState::new(
            "test hub",
            hub_address.clone(),
            node_url,
            None,
            0.0,
            Some(account_secret_hex(&hub_account)),
        )
        .unwrap(),
    );
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{hub_addr}");

    let pending: Value = client
        .post(format!("{base}/v1/fast-pay"))
        .json(&json!({
            "payer": alice_address.clone(),
            "payee": bob_address.clone(),
            "amount": "1.5",
            "channel_id": alice_ch_id.clone()
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending["status"], "pending", "prepare response: {pending}");
    let payment_id = pending["payment_id"].as_str().unwrap().to_owned();

    let mut payer_bill = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(
        pending["bill_hex"].as_str().unwrap(),
    )
    .unwrap();
    payer_bill
        .chain_payment
        .fill_sign_by_account(&alice)
        .unwrap();
    let awaiting: Value = client
        .post(format!("{base}/v1/fast-pay/{payment_id}/confirm"))
        .json(&json!({ "bill_hex": payer_bill.to_bill_hex() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(awaiting["status"], "awaiting_recipient");

    let inbox: Value = client
        .get(format!("{base}/v1/fast-pay/inbox/{bob_address}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let item = inbox.as_array().unwrap().first().unwrap();
    assert_eq!(item["payment_id"], payment_id);
    assert_eq!(item["channel_id"], alice_ch_id);
    assert_eq!(item["payee_channel_id"], bob_ch_id);

    let mut recipient_bill = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(
        item["bill_hex"].as_str().unwrap(),
    )
    .unwrap();
    recipient_bill
        .chain_payment
        .fill_sign_by_account(&bob)
        .unwrap();
    let settled: Value = client
        .post(format!("{base}/v1/fast-pay/{payment_id}/confirm"))
        .json(&json!({ "bill_hex": recipient_bill.to_bill_hex() }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settled["status"], "settled", "settle response: {settled}");
    let final_bill = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(
        settled["bill_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert!(final_bill.prove_bindings_valid());
    assert!(final_bill.chain_payment.all_signatures_verified());

    let status: Value = client
        .get(format!("{base}/v1/fast-pay/{payment_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "settled");
    let empty_inbox: Value = client
        .get(format!("{base}/v1/fast-pay/inbox/{bob_address}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(empty_inbox.as_array().unwrap().is_empty());

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_rejects_insufficient_balance() {
    let alice = test_account("alice-insufficient");
    let hub_account = test_account("hub-insufficient");
    let alice_address = alice.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let ch_id = derive_channel_id(&alice_address, &hub_address, 1);
    let mut channels = HashMap::new();
    channels.insert(
        ch_id.clone(),
        json!({
            "ret": 0,
            "id": ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": alice_address, "hacash": "0.5", "satoshi": 0 },
            "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;
    let hub = Arc::new(
        HubState::new(
            "t",
            hub_address.clone(),
            node_url,
            None,
            0.0,
            Some(account_secret_hex(&hub_account)),
        )
        .unwrap(),
    );
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{hub_addr}/v1/fast-pay"))
        .json(&json!({
            "payer": alice_address,
            "payee": hub_address,
            "amount": "1",
            "channel_id": ch_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_rejects_payee_without_hub_channel() {
    let alice = test_account("alice-no-payee-channel");
    let bob = test_account("bob-no-payee-channel");
    let hub_account = test_account("hub-no-payee-channel");
    let alice_address = alice.readable().to_owned();
    let bob_address = bob.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let alice_ch_id = derive_channel_id(&alice_address, &hub_address, 1);
    let mut channels = HashMap::new();
    channels.insert(
        alice_ch_id.clone(),
        json!({
            "ret": 0,
            "id": alice_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": alice_address, "hacash": "10", "satoshi": 0 },
            "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;
    let hub = Arc::new(
        HubState::new(
            "t",
            hub_address.clone(),
            node_url,
            None,
            0.0,
            Some(account_secret_hex(&hub_account)),
        )
        .unwrap(),
    );
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{hub_addr}/v1/fast-pay"))
        .json(&json!({
            "payer": alice_address,
            "payee": bob_address,
            "amount": "1",
            "channel_id": alice_ch_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("has no open Fast Pay channel")
    );

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_ignores_legacy_fee_payer_and_remains_fee_free() {
    let alice = test_account("alice-legacy-fee");
    let hub_account = test_account("hub-legacy-fee");
    let alice_address = alice.readable().to_owned();
    let hub_address = hub_account.readable().to_owned();
    let ch_id = derive_channel_id(&alice_address, &hub_address, 1);
    let channel = json!({
        "ret": 0,
        "id": ch_id,
        "status": 0,
        "reuse_version": 1,
        "left": { "address": alice_address, "hacash": "10", "satoshi": 0 },
        "right": { "address": hub_address, "hacash": "0", "satoshi": 0 }
    });
    let mut channels = HashMap::new();
    channels.insert(ch_id.clone(), channel);
    let (node_url, node_handle) = spawn_mock_node(channels).await;

    let dir = tempdir().unwrap();
    let state_path = dir.path().join("hub-state-recipient-fee.json");
    let hub = Arc::new(
        HubState::new(
            "test hub",
            hub_address.clone(),
            node_url,
            Some(state_path),
            0.0,
            Some(account_secret_hex(&hub_account)),
        )
        .unwrap(),
    );
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{hub_addr}");

    let pay = prepare_and_confirm(
        &client,
        &base,
        json!({
            "payer": alice_address,
            "payee": hub_address,
            "amount": "2",
            "channel_id": ch_id,
            "fee_payer": "recipient"
        }),
        &alice,
    )
    .await;
    assert_eq!(pay["status"], "settled");
    assert!(pay["summary"].as_str().unwrap().contains("with no fee"));

    hub_handle.abort();
    node_handle.abort();
}
