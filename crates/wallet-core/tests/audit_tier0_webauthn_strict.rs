//! TIER-0: WebAuthn strict mode — pubkey-bound credentials require cryptographic proof.

mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::tier0_gate;
use hacash_wallet_core::webauthn::{StoredCredential, WebAuthnGate};
use sha2::{Digest, Sha256};
use serde_json::json;

const RP_ORIGIN: &str = "http://localhost:1420";

fn client_data_b64(challenge: &str, typ: &str) -> String {
    let cd = json!({ "type": typ, "challenge": challenge, "origin": RP_ORIGIN });
    URL_SAFE_NO_PAD.encode(cd.to_string().as_bytes())
}

fn fake_stored_with_pubkey() -> String {
    let stored = StoredCredential {
        credential_id_b64: "dGVzdA".into(),
        public_key_b64: Some(URL_SAFE_NO_PAD.encode([0xAB; 32])),
        registered_at: "2026-01-01T00:00:00Z".into(),
    };
    URL_SAFE_NO_PAD.encode(serde_json::to_string(&stored).unwrap().as_bytes())
}

#[test]
fn tier0_webauthn_pubkey_credential_rejects_assertion_without_signature() {
    tier0_gate("webauthn_strict_no_sig", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_auth("dGVzdA").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()
            ["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.get")
            }
        });
        let stored = fake_stored_with_pubkey();
        assert!(gate.finish_auth(&cred.to_string(), Some(&stored)).is_err());
    });
}

#[test]
fn tier0_webauthn_pubkey_credential_rejects_bad_signature() {
    tier0_gate("webauthn_strict_bad_sig", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_auth("dGVzdA").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()
            ["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let rp_hash = Sha256::digest(b"localhost");
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&rp_hash);
        auth_data[32] = 0x01;
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.get"),
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "signature": URL_SAFE_NO_PAD.encode([0xFF; 64])
            }
        });
        let stored = fake_stored_with_pubkey();
        assert!(gate.finish_auth(&cred.to_string(), Some(&stored)).is_err());
    });
}

#[test]
fn tier0_webauthn_register_challenge_single_use() {
    tier0_gate("webauthn_register_single_use", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_register("1User").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()
            ["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let cred = json!({
            "rawId": "dGVzdA",
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.create"),
                "publicKey": null
            }
        });
        assert!(gate.finish_register(&cred.to_string()).is_ok());
        assert!(gate.finish_register(&cred.to_string()).is_err());
    });
}

#[test]
fn tier0_webauthn_auth_challenge_single_use() {
    tier0_gate("webauthn_auth_single_use", || {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_auth("dGVzdA").unwrap();
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64("stale", "webauthn.get")
            }
        });
        assert!(gate.finish_auth(&cred.to_string(), None).is_err());
        assert!(gate.finish_auth(&cred.to_string(), None).is_err());
    });
}

#[test]
fn tier0_webauthn_user_not_present_flag_rejected() {
    tier0_gate("webauthn_up_flag", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_auth("dGVzdA").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()
            ["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let rp_hash = Sha256::digest(b"localhost");
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&rp_hash);
        auth_data[32] = 0x00; // UP bit clear
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.get"),
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "signature": URL_SAFE_NO_PAD.encode([1u8; 64])
            }
        });
        assert!(gate.finish_auth(&cred.to_string(), None).is_err());
    });
}