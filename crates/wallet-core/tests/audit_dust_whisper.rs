//! DUST Whisper wallet routing tests.

use std::net::SocketAddr;

use axum::routing::post;
use axum::{Json, Router};
use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::protocol::{INFO_PATH, WhisperInfo};
use dust_whisper::relay::{build_router, relay_state_from_secret};
use hacash_wallet_core::dust_whisper::{DustWhisperSettings, submit_tx_hex};
use hacash_wallet_core::node::NodeClient;
use reqwest::Client;
use serde_json::json;
use tokio::task::JoinHandle;

async fn spawn_mock_node(expected_hex: &'static str) -> (SocketAddr, JoinHandle<()>) {
    let app = Router::new().route(
        "/submit/transaction",
        post(move |body: String| async move {
            assert_eq!(body, expected_hex);
            Json(json!({ "ret": 0, "hash": "nodehash" }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_relay(node_url: String) -> (SocketAddr, JoinHandle<()>) {
    let (sk, _) = generate_relay_keypair();
    let state = relay_state_from_secret(sk, node_url);
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn whisper_enabled_routes_through_relay() {
    let (node_addr, node_handle) = spawn_mock_node("abc123").await;
    let node_url = format!("http://{node_addr}");
    let (relay_addr, relay_handle) = spawn_relay(node_url.clone()).await;

    let node = NodeClient::new(&node_url);
    let settings = DustWhisperSettings {
        enabled: true,
        relay_urls: vec![format!("http://{relay_addr}")],
        fallback_direct: false,
        auto_start_relay: false,
    };

    let resp = submit_tx_hex(&node, &settings, "abc123")
        .await
        .expect("whisper submit");
    assert_eq!(resp.hash.as_deref(), Some("nodehash"));

    relay_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn whisper_without_fallback_returns_error() {
    let node = NodeClient::new("http://127.0.0.1:1");
    let settings = DustWhisperSettings {
        enabled: true,
        relay_urls: vec!["http://127.0.0.1:1".into()],
        fallback_direct: false,
        auto_start_relay: false,
    };

    let err = submit_tx_hex(&node, &settings, "deadbeef")
        .await
        .unwrap_err();
    assert!(matches!(err, hacash_wallet_core::WalletError::Node(_)));
}

#[tokio::test]
async fn relay_info_is_informational() {
    let (node_addr, node_handle) = spawn_mock_node("ff").await;
    let node_url = format!("http://{node_addr}");
    let (relay_addr, relay_handle) = spawn_relay(node_url.clone()).await;

    let client = Client::new();
    let info: WhisperInfo = client
        .get(format!("http://{relay_addr}{INFO_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.node_url.as_deref(), Some(node_url.as_str()));

    relay_handle.abort();
    node_handle.abort();
}
