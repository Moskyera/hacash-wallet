use std::net::SocketAddr;

use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::protocol::WhisperSettings;
use dust_whisper::relay::{build_router, relay_state_from_secret};
use dust_whisper::submit_tx;
use reqwest::Client;
use tokio::task::JoinHandle;

async fn spawn_mock_node() -> (SocketAddr, JoinHandle<()>) {
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;

    let app = Router::new().route(
        "/submit/transaction",
        post(|| async {
            Json(json!({
                "ret": 0,
                "hash": "mockhash123"
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn whisper_relay_forwards_encrypted_submit() {
    let (node_addr, node_handle) = spawn_mock_node().await;
    let node_url = format!("http://{node_addr}");

    let (sk, _pk) = generate_relay_keypair();
    let relay_state = relay_state_from_secret(sk, node_url.clone());
    let relay_app = build_router(relay_state);
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let relay_handle = tokio::spawn(async move {
        axum::serve(relay_listener, relay_app).await.unwrap();
    });

    let client = Client::new();
    let settings = WhisperSettings {
        enabled: true,
        relay_urls: vec![format!("http://{relay_addr}")],
        fallback_direct: false,
    };

    let result = submit_tx(&client, &settings, &node_url, "cafebabe")
        .await
        .expect("whisper submit");

    assert_eq!(result.ret, 0);
    assert_eq!(result.hash.as_deref(), Some("mockhash123"));

    relay_handle.abort();
    node_handle.abort();
}