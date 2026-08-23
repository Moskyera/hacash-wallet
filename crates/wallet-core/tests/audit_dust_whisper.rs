//! DUST Whisper wallet routing tests.

use std::net::SocketAddr;

use axum::routing::post;
use axum::{Json, Router};
use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::protocol::{INFO_PATH, WhisperInfo};
use dust_whisper::relay::{build_router, relay_state_from_secret, serve_router};
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
        serve_router(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_relay(node_url: String) -> (SocketAddr, JoinHandle<()>) {
    let (sk, _) = generate_relay_keypair();
    spawn_relay_with_secret(node_url, sk).await
}

async fn spawn_relay_with_secret(node_url: String, sk: [u8; 32]) -> (SocketAddr, JoinHandle<()>) {
    let state = relay_state_from_secret(sk, node_url);
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        serve_router(listener, app).await.unwrap();
    });
    (addr, handle)
}

/// A relay of this machine's own, the way the desktop wallet starts one: its
/// secret key in `relay.key` under the wallet data root, which is the file the
/// submit token is derived from at both ends.
async fn spawn_own_relay(node_url: String) -> (SocketAddr, JoinHandle<()>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("wallet data root");
    unsafe { std::env::set_var("HACASH_WALLET_DATA", dir.path()) };
    let key_file = dir.path().join("relay.key");
    let sk = dust_whisper::relay::load_or_create_secret_key(&key_file).expect("relay key");
    let (addr, handle) = spawn_relay_with_secret(node_url, sk).await;
    (addr, handle, dir)
}

/// WHICH LOOPBACK RELAY THIS WALLET MAY PUSH A TRANSACTION THROUGH.
///
/// Both halves in one test, because `HACASH_WALLET_DATA` is process global and
/// what it points at IS the credential: the transaction door wants a token
/// derived from the relay's own key file as well as a connection from this
/// machine, so "which relay is mine" is decided by which key file this wallet
/// can read (`SubmitAccess::ThisMachineOnly`, `crates/dust-whisper/src/relay.rs`).
///
/// The second half is the shape a reverse proxy creates: a caller arriving on
/// 127.0.0.1 that is not this machine's own wallet. Loopback alone used to be
/// the whole check, and behind either proxy configuration in section 4 of
/// docs/RUNNING-A-RELAY.md every submitter on earth arrives that way.
#[tokio::test]
async fn a_transaction_goes_through_this_wallets_own_relay_and_no_other() {
    let (node_addr, node_handle) = spawn_mock_node("abc123").await;
    let node_url = format!("http://{node_addr}");
    let node = NodeClient::new(&node_url).expect("mock node client");

    // 1. THE WALLET'S OWN RELAY: its key file is under this wallet's data root.
    let (relay_addr, relay_handle, _root) = spawn_own_relay(node_url.clone()).await;
    let settings = DustWhisperSettings {
        enabled: true,
        relay_urls: vec![format!("http://{relay_addr}")],
        fallback_direct: false,
        auto_start_relay: false,
        // Nothing here hosts a relay. The bind is whatever a fresh wallet has.
        ..DustWhisperSettings::default()
    };
    let resp = submit_tx_hex(&node, &settings, "abc123")
        .await
        .expect("whisper submit");
    println!("through this wallet's own relay: hash={:?}", resp.hash);
    assert_eq!(resp.hash.as_deref(), Some("nodehash"));
    relay_handle.abort();

    // 2. A LOOPBACK RELAY THIS WALLET HOLDS NO KEY FOR. Same machine, same
    //    payload, no credential.
    let empty = tempfile::tempdir().expect("wallet data root");
    unsafe { std::env::set_var("HACASH_WALLET_DATA", empty.path()) };
    let (other_addr, other_handle) = spawn_relay(node_url.clone()).await;
    let settings = DustWhisperSettings {
        enabled: true,
        relay_urls: vec![format!("http://{other_addr}")],
        fallback_direct: false,
        auto_start_relay: false,
        ..DustWhisperSettings::default()
    };
    let err = submit_tx_hex(&node, &settings, "abc123")
        .await
        .expect_err("a relay whose key this wallet does not hold accepted a transaction");
    println!("through a loopback relay whose key it does not hold: {err}");
    assert!(
        err.to_string()
            .contains("does not accept transactions from other machines"),
        "refused for the wrong reason: {err}"
    );

    other_handle.abort();
    node_handle.abort();
}

#[tokio::test]
async fn whisper_without_fallback_returns_error() {
    let node = NodeClient::new("http://127.0.0.1:1").expect("offline node client");
    let settings = DustWhisperSettings {
        enabled: true,
        relay_urls: vec!["http://127.0.0.1:1".into()],
        fallback_direct: false,
        auto_start_relay: false,
        // Nothing here hosts a relay. The bind is whatever a fresh wallet has.
        ..DustWhisperSettings::default()
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
