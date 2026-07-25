//! AUDIT-GATE: WebAuthn ceremony adversarial tests (replay, tamper, mismatch).

mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::audit_gate;
use coset::{CborSerializable, CoseKeyBuilder, iana};
use hacash_wallet_core::webauthn::{StoredCredential, WebAuthnGate};
use p256::ecdsa::SigningKey;
use serde_json::json;

const RP_ORIGIN: &str = "http://localhost:1420";
const CREDENTIAL_ID: &[u8] = b"test";

fn client_data_b64(challenge: &str, typ: &str, origin: &str) -> String {
    let data = json!({ "type": typ, "challenge": challenge, "origin": origin });
    URL_SAFE_NO_PAD.encode(data.to_string().as_bytes())
}

fn valid_stored_credential() -> String {
    let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let cose = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().unwrap().to_vec(),
        point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .add_key_op(iana::KeyOperation::Verify)
    .build()
    .to_vec()
    .unwrap();
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&StoredCredential {
            version: 2,
            credential_id_b64: URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            public_key_cose_b64: URL_SAFE_NO_PAD.encode(cose),
            rp_id: "localhost".into(),
            origin: RP_ORIGIN.into(),
            sign_count: 0,
            registered_at: "2026-01-01T00:00:00Z".into(),
        })
        .unwrap(),
    )
}

fn assertion(challenge: &str, auth_data: impl AsRef<[u8]>) -> String {
    let credential_id = URL_SAFE_NO_PAD.encode(CREDENTIAL_ID);
    json!({
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_b64(challenge, "webauthn.get", RP_ORIGIN),
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
            "signature": URL_SAFE_NO_PAD.encode([1u8; 64]),
        }
    })
    .to_string()
}

#[test]
fn audit_webauthn_finish_without_begin_fails() {
    audit_gate("webauthn_no_begin", || {
        let gate = WebAuthnGate::new().unwrap();
        assert!(gate.finish_register("{}").is_err());
    });
}

#[test]
fn audit_webauthn_wrong_ceremony_purpose_fails() {
    audit_gate("webauthn_purpose_mismatch", || {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_register("1User", None).unwrap();
        gate.begin_auth(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID), None)
            .unwrap();
        assert!(gate.finish_register("{}").is_err());
    });
}

#[test]
fn audit_webauthn_wrong_origin_rejected() {
    audit_gate("webauthn_wrong_origin", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate.begin_register("1User", None).unwrap();
        let challenge =
            serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
                .as_str()
                .unwrap()
                .to_string();
        let credential_id = URL_SAFE_NO_PAD.encode(CREDENTIAL_ID);
        let credential = json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_b64(
                    &challenge,
                    "webauthn.create",
                    "https://evil.example",
                ),
                "attestationObject": "AA",
            }
        });
        assert!(gate.finish_register(&credential.to_string()).is_err());
    });
}

#[test]
fn audit_webauthn_stale_challenge_rejected() {
    audit_gate("webauthn_stale_challenge", || {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_auth(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID), None)
            .unwrap();
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x05;
        assert!(
            gate.finish_auth(
                &assertion("not-the-active-challenge", auth_data),
                Some(&valid_stored_credential()),
            )
            .is_err()
        );
    });
}

#[test]
fn audit_webauthn_auth_data_rp_id_hash_mismatch() {
    audit_gate("webauthn_rpid_hash", || {
        let gate = WebAuthnGate::new().unwrap();
        let options = gate
            .begin_auth(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID), None)
            .unwrap();
        let challenge =
            serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
                .as_str()
                .unwrap()
                .to_string();
        let mut bad_auth_data = vec![0u8; 37];
        bad_auth_data[32] = 0x05;
        assert!(
            gate.finish_auth(
                &assertion(&challenge, bad_auth_data),
                Some(&valid_stored_credential()),
            )
            .is_err()
        );
    });
}

#[test]
fn audit_webauthn_challenge_entropy() {
    audit_gate("webauthn_challenge_entropy", || {
        let gate = WebAuthnGate::new().unwrap();
        let first = gate.begin_register("1A", None).unwrap();
        let second = gate.begin_register("1B", None).unwrap();
        let first: serde_json::Value = serde_json::from_str(&first).unwrap();
        let second: serde_json::Value = serde_json::from_str(&second).unwrap();
        let first = first["publicKey"]["challenge"].as_str().unwrap();
        let second = second["publicKey"]["challenge"].as_str().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
    });
}
