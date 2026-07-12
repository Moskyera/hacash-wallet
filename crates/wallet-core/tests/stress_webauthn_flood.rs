//! STRESS: WebAuthn ceremony flood (challenge uniqueness)

mod common;

use common::stress_gate;
use hacash_wallet_core::webauthn::WebAuthnGate;
use std::collections::HashSet;

#[test]
fn stress_webauthn_500_unique_challenges() {
    stress_gate("webauthn_500_challenges", || {
        let gate = WebAuthnGate::new().unwrap();
        let mut seen = HashSet::new();
        for i in 0..500 {
            let opts = gate.begin_register(&format!("1User{i}"), None).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&opts).unwrap();
            let ch = parsed["publicKey"]["challenge"].as_str().unwrap().to_string();
            assert!(seen.insert(ch), "duplicate challenge at iteration {i}");
        }
    });
}

#[test]
fn stress_webauthn_register_finish_100_roundtrips() {
    stress_gate("webauthn_100_roundtrips", || {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use serde_json::json;

        const ORIGIN: &str = "http://localhost:1420";
        let gate = WebAuthnGate::new().unwrap();
        for i in 0..100 {
            let opts = gate.begin_register(&format!("1Stress{i}"), None).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&opts).unwrap();
            let challenge = parsed["publicKey"]["challenge"].as_str().unwrap();
            let client_data = json!({
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": ORIGIN
            });
            let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());
            let cred = json!({
                "rawId": URL_SAFE_NO_PAD.encode(format!("id{i}").as_bytes()),
                "response": { "clientDataJSON": client_data_b64, "publicKey": null }
            });
            assert!(gate.finish_register(&cred.to_string()).is_ok());
        }
    });
}