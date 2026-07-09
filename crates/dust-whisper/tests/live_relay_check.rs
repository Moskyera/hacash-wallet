//! Manual live check: `cargo test -p dust-whisper --test live_relay_check --features relay -- --ignored`

use dust_whisper::crypto::{encrypt_payload, public_key_from_secret};
use dust_whisper::protocol::WhisperInnerPayload;
use dust_whisper::relay::parse_secret_hex;
use reqwest::Client;
use std::fs;

#[tokio::test]
#[ignore = "requires local relay at 127.0.0.1:8787"]
async fn live_relay_accepts_encrypted_submit() {
    let key_path = std::env::var("APPDATA").unwrap() + "\\HacashWallet\\relay.key";
    let sk = parse_secret_hex(fs::read_to_string(&key_path).unwrap().trim()).unwrap();
    let pk = public_key_from_secret(&sk);
    let inner = WhisperInnerPayload {
        tx_hex: "deadbeef".into(),
    };
    let req = encrypt_payload(&pk, &inner).unwrap();
    let client = Client::new();
    let resp = client
        .post("http://127.0.0.1:8787/whisper/v1/submit")
        .json(&req)
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("decrypt: aead::Error"),
        "relay crypto broken: {body}"
    );
}