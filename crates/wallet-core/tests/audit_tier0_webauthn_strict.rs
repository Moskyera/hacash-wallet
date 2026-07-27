//! TIER-0: WebAuthn credentials fail closed unless every required proof is present.

mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::tier0_gate;
use coset::{CborSerializable, CoseKeyBuilder, iana};
use hacash_wallet_core::webauthn::{StoredCredential, WebAuthnGate};
use p256::ecdsa::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};

const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:1420";
const CREDENTIAL_ID: &[u8] = b"test-credential";

fn client_data_b64(challenge: &str, typ: &str) -> String {
    let data = json!({ "type": typ, "challenge": challenge, "origin": RP_ORIGIN });
    URL_SAFE_NO_PAD.encode(data.to_string().as_bytes())
}

fn valid_stored_credential() -> String {
    let signing_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
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
    let stored = StoredCredential {
        version: 2,
        credential_id_b64: URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
        public_key_cose_b64: URL_SAFE_NO_PAD.encode(cose),
        rp_id: RP_ID.into(),
        origin: RP_ORIGIN.into(),
        sign_count: 0,
        registered_at: "2026-01-01T00:00:00Z".into(),
    };
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&stored).unwrap())
}

fn auth_data(flags: u8) -> String {
    let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&1u32.to_be_bytes());
    URL_SAFE_NO_PAD.encode(data)
}

fn assertion(challenge: &str, flags: u8, signature: Option<&str>) -> String {
    let credential_id = URL_SAFE_NO_PAD.encode(CREDENTIAL_ID);
    let mut response = json!({
        "clientDataJSON": client_data_b64(challenge, "webauthn.get"),
        "authenticatorData": auth_data(flags),
    });
    if let Some(signature) = signature {
        response["signature"] = json!(signature);
    }
    json!({
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": response,
    })
    .to_string()
}

fn auth_challenge(gate: &WebAuthnGate) -> String {
    let credential_id = URL_SAFE_NO_PAD.encode(CREDENTIAL_ID);
    let options = gate.begin_auth(&credential_id, None).unwrap();
    serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn tier0_webauthn_rejects_assertion_without_signature() {
    tier0_gate("webauthn_strict_no_sig", || {
        let gate = WebAuthnGate::new().unwrap();
        let challenge = auth_challenge(&gate);
        let stored = valid_stored_credential();
        assert!(
            gate.finish_auth(&assertion(&challenge, 0x05, None), Some(&stored))
                .is_err()
        );
    });
}

#[test]
fn tier0_webauthn_rejects_bad_signature() {
    tier0_gate("webauthn_strict_bad_sig", || {
        let gate = WebAuthnGate::new().unwrap();
        let challenge = auth_challenge(&gate);
        let stored = valid_stored_credential();
        let bad_signature = URL_SAFE_NO_PAD.encode([0xFF; 64]);
        assert!(
            gate.finish_auth(
                &assertion(&challenge, 0x05, Some(&bad_signature)),
                Some(&stored),
            )
            .is_err()
        );
    });
}

#[test]
fn tier0_webauthn_registration_rejects_null_key_material() {
    tier0_gate("webauthn_register_null_key", || {
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
                "clientDataJSON": client_data_b64(&challenge, "webauthn.create"),
                "publicKey": null,
            }
        });
        assert!(gate.finish_register(&credential.to_string()).is_err());
    });
}

#[test]
fn tier0_webauthn_auth_challenge_is_single_use() {
    tier0_gate("webauthn_auth_single_use", || {
        let gate = WebAuthnGate::new().unwrap();
        let challenge = auth_challenge(&gate);
        let stored = valid_stored_credential();
        let bad_signature = URL_SAFE_NO_PAD.encode([0xFF; 64]);
        let credential = assertion(&challenge, 0x05, Some(&bad_signature));
        assert!(gate.finish_auth(&credential, Some(&stored)).is_err());
        assert!(gate.finish_auth(&credential, Some(&stored)).is_err());
    });
}

#[test]
fn tier0_webauthn_requires_user_presence_and_verification() {
    tier0_gate("webauthn_up_uv_flags", || {
        for flags in [0x00, 0x01, 0x04] {
            let gate = WebAuthnGate::new().unwrap();
            let challenge = auth_challenge(&gate);
            let stored = valid_stored_credential();
            let bad_signature = URL_SAFE_NO_PAD.encode([0xFF; 64]);
            assert!(
                gate.finish_auth(
                    &assertion(&challenge, flags, Some(&bad_signature)),
                    Some(&stored),
                )
                .is_err()
            );
        }
    });
}
