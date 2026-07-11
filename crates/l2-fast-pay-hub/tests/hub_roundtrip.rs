use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::get;
use axum::{Json, Router};
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::{build_router, HubState};
use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
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
    let ch_id = derive_channel_id("1Alice", "1Hub", 1);
    let channel = json!({
        "ret": 0,
        "id": ch_id,
        "status": 0,
        "reuse_version": 1,
        "left": { "address": "1Alice", "hacash": "10", "satoshi": 0 },
        "right": { "address": "1Hub", "hacash": "0", "satoshi": 0 }
    });
    let mut channels = HashMap::new();
    channels.insert(ch_id.clone(), channel);
    let (node_url, node_handle) = spawn_mock_node(channels).await;

    let dir = tempdir().unwrap();
    let state_path = dir.path().join("hub-state.json");
    let hub = Arc::new(
        HubState::new("test hub", "1Hub", node_url, Some(state_path), 0.001, None).unwrap(),
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
    assert_eq!(health["hub_address"], "1Hub");

    // Pay hub (other party on same channel)
    let pay: Value = client
        .post(format!("{base}/v1/fast-pay"))
        .json(&json!({
            "payer": "1Alice",
            "payee": "1Hub",
            "amount": "1",
            "channel_id": ch_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pay["status"], "settled", "pay response: {pay}");
    assert!(pay["summary"]
        .as_str()
        .unwrap()
        .contains("on-channel"));

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_routes_cross_channel_payment() {
    let alice_ch_id = derive_channel_id("1Alice", "1Hub", 1);
    let bob_ch_id = derive_channel_id("1Bob", "1Hub", 1);

    let mut channels = HashMap::new();
    channels.insert(
        alice_ch_id.clone(),
        json!({
            "ret": 0,
            "id": alice_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": "1Alice", "hacash": "10", "satoshi": 0 },
            "right": { "address": "1Hub", "hacash": "0", "satoshi": 0 }
        }),
    );
    channels.insert(
        bob_ch_id.clone(),
        json!({
            "ret": 0,
            "id": bob_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": "1Bob", "hacash": "2", "satoshi": 0 },
            "right": { "address": "1Hub", "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;

    let hub = Arc::new(HubState::new("test hub", "1Hub", node_url, None, 0.001, None).unwrap());
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{hub_addr}");

    let pay: Value = client
        .post(format!("{base}/v1/fast-pay"))
        .json(&json!({
            "payer": "1Alice",
            "payee": "1Bob",
            "amount": "1.5",
            "channel_id": alice_ch_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pay["status"], "settled");
    let summary = pay["summary"].as_str().unwrap();
    assert!(summary.contains("routed"));
    assert!(summary.contains(&bob_ch_id));

    let bill_hex = pay["bill_hex"].as_str().unwrap();
    let bill_bytes = hex::decode(bill_hex).unwrap();
    assert!(!bill_bytes.is_empty());
    assert_ne!(bill_bytes[0], b'{', "bill must be binary wire, not JSON");
    let doc = l2_fast_pay_hub::wire::ChannelPayCompleteDocuments::from_bill_hex(bill_hex).unwrap();
    assert_eq!(doc.prove_bodies.len(), 2);
    assert_eq!(doc.chain_payment.prove_hash_checkers.len(), 2);

    hub_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn hub_rejects_insufficient_balance() {
    let ch_id = derive_channel_id("1Alice", "1Hub", 1);
    let mut channels = HashMap::new();
    channels.insert(
        ch_id.clone(),
        json!({
            "ret": 0,
            "id": ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": "1Alice", "hacash": "0.5", "satoshi": 0 },
            "right": { "address": "1Hub", "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;
    let hub = Arc::new(HubState::new("t", "1Hub", node_url, None, 0.001, None).unwrap());
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{hub_addr}/v1/fast-pay"))
        .json(&json!({
            "payer": "1Alice",
            "payee": "1Hub",
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
    let alice_ch_id = derive_channel_id("1Alice", "1Hub", 1);
    let mut channels = HashMap::new();
    channels.insert(
        alice_ch_id.clone(),
        json!({
            "ret": 0,
            "id": alice_ch_id,
            "status": 0,
            "reuse_version": 1,
            "left": { "address": "1Alice", "hacash": "10", "satoshi": 0 },
            "right": { "address": "1Hub", "hacash": "0", "satoshi": 0 }
        }),
    );
    let (node_url, node_handle) = spawn_mock_node(channels).await;
    let hub = Arc::new(HubState::new("t", "1Hub", node_url, None, 0.001, None).unwrap());
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    let hub_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{hub_addr}/v1/fast-pay"))
        .json(&json!({
            "payer": "1Alice",
            "payee": "1Bob",
            "amount": "1",
            "channel_id": alice_ch_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("no open Fast Pay channel"));

    hub_handle.abort();
    node_handle.abort();
}