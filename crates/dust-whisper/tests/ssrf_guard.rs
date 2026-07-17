//! Relay must not forward to client-supplied URLs (SSRF guard).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::post;
use axum::{Json, Router};
use dust_whisper::crypto::{decrypt_payload, encrypt_payload, generate_relay_keypair};
use dust_whisper::protocol::WhisperInnerPayload;
use dust_whisper::relay::{build_router, relay_state_from_secret};
use reqwest::Client;
use serde_json::json;
use tokio::task::JoinHandle;

async fn spawn_hit_counter() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in_handler = hits.clone();
    let app = Router::new().route(
        "/submit/transaction",
        post(move || async move {
            hits_in_handler.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "ret": 0, "hash": "ok" }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, hits, handle)
}

#[tokio::test]
async fn relay_only_hits_configured_node_not_attacker_host() {
    let (good_addr, good_hits, good_handle) = spawn_hit_counter().await;
    let (evil_addr, evil_hits, evil_handle) = spawn_hit_counter().await;

    let good_node = format!("http://{good_addr}");
    let evil_node = format!("http://{evil_addr}");

    let (sk, pk) = generate_relay_keypair();
    let relay_state = relay_state_from_secret(sk, good_node.clone());
    let relay_app = build_router(relay_state);
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let relay_handle = tokio::spawn(async move {
        axum::serve(relay_listener, relay_app).await.unwrap();
    });

    // Craft a legacy-style inner JSON that tries to point at evil_node.
    let legacy_inner = json!({
        "tx_hex": "cafe",
        "target_node": evil_node
    });
    let inner: WhisperInnerPayload = serde_json::from_value(legacy_inner).unwrap();
    let envelope = encrypt_payload(&pk, &inner).unwrap();

    let client = Client::new();
    let resp = client
        .post(format!("http://{relay_addr}/whisper/v1/submit"))
        .json(&envelope)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    assert_eq!(resp["ret"], 0);
    assert_eq!(good_hits.load(Ordering::SeqCst), 1);
    assert_eq!(evil_hits.load(Ordering::SeqCst), 0);

    let decrypted = decrypt_payload(&sk, &envelope).unwrap();
    assert_eq!(decrypted.tx_hex, "cafe");

    relay_handle.abort();
    good_handle.abort();
    evil_handle.abort();
}
