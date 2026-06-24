//! AUDIT-GATE: WebAuthn ceremony adversarial tests (replay, tamper, mismatch)

mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::audit_gate;
use hacash_wallet_core::webauthn::WebAuthnGate;
use serde_json::json;

const RP_ORIGIN: &str = "http://localhost:1420";

fn client_data_b64(challenge: &str, typ: &str, origin: &str) -> String {
    let cd = json!({ "type": typ, "challenge": challenge, "origin": origin });
    URL_SAFE_NO_PAD.encode(cd.to_string().as_bytes())
}

#[test]
fn audit_webauthn_finish_without_begin_fails() {
    audit_gate("webauthn_no_begin", || {
        let gate = WebAuthnGate::new().unwrap();
        let cred = json!({
            "rawId": "dGVzdA",
            "response": { "clientDataJSON": "e30", "publicKey": null }
        });
        assert!(gate.finish_register(&cred.to_string()).is_err());
    });
}

#[test]
fn audit_webauthn_wrong_ceremony_purpose_fails() {
    audit_gate("webauthn_purpose_mismatch", || {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_register("1User").unwrap();
        let challenge = "stale";
        let cred = json!({
            "rawId": "dGVzdA",
            "response": {
                "clientDataJSON": client_data_b64(challenge, "webauthn.create", RP_ORIGIN),
                "publicKey": null
            }
        });
        // begin_auth after register begin should fail on purpose
        gate.begin_auth("dGVzdA").unwrap();
        assert!(gate.finish_register(&cred.to_string()).is_err());
    });
}

#[test]
fn audit_webauthn_wrong_origin_rejected() {
    audit_gate("webauthn_wrong_origin", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_register("1User").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let cred = json!({
            "rawId": "dGVzdA",
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.create", "https://evil.example"),
                "publicKey": null
            }
        });
        assert!(gate.finish_register(&cred.to_string()).is_err());
    });
}

#[test]
fn audit_webauthn_stale_challenge_rejected() {
    audit_gate("webauthn_stale_challenge", || {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_auth("dGVzdA").unwrap();
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64("not-the-active-challenge", "webauthn.get", RP_ORIGIN)
            }
        });
        assert!(gate.finish_auth(&cred.to_string(), None).is_err());
    });
}

#[test]
fn audit_webauthn_auth_data_rp_id_hash_mismatch() {
    audit_gate("webauthn_rpid_hash", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_auth("dGVzdA").unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let bad_auth_data = URL_SAFE_NO_PAD.encode([0u8; 37]);
        let cred = json!({
            "response": {
                "clientDataJSON": client_data_b64(&challenge, "webauthn.get", RP_ORIGIN),
                "authenticatorData": bad_auth_data,
                "signature": URL_SAFE_NO_PAD.encode([1u8; 64])
            }
        });
        assert!(gate.finish_auth(&cred.to_string(), None).is_err());
    });
}

#[test]
fn audit_webauthn_challenge_entropy() {
    audit_gate("webauthn_challenge_entropy", || {
        let gate = WebAuthnGate::new().unwrap();
        let a = gate.begin_register("1A").unwrap();
        let b = gate.begin_register("1B").unwrap();
        let parsed_a: serde_json::Value = serde_json::from_str(&a).unwrap();
        let parsed_b: serde_json::Value = serde_json::from_str(&b).unwrap();
        let ca = parsed_a["publicKey"]["challenge"].as_str().unwrap();
        let cb = parsed_b["publicKey"]["challenge"].as_str().unwrap();
        assert_ne!(ca, cb);
        assert_eq!(ca.len(), 43);
    });
}