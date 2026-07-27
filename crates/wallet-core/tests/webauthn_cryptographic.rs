//! End-to-end WebAuthn ES256 registration and assertion verification.

mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::tier0_gate;
use coset::{CborSerializable, CoseKeyBuilder, cbor::value::Value, iana};
use hacash_wallet_core::webauthn::{StoredCredential, WebAuthnGate, credential_id_from_store};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:1420";
const CREDENTIAL_ID: &[u8] = b"crypto-test-credential";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn client_data(challenge: &str, typ: &str) -> String {
    URL_SAFE_NO_PAD.encode(
        json!({ "type": typ, "challenge": challenge, "origin": RP_ORIGIN })
            .to_string()
            .as_bytes(),
    )
}

fn cose_public_key(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().unwrap().to_vec(),
        point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .add_key_op(iana::KeyOperation::Verify)
    .build()
    .to_vec()
    .unwrap()
}

fn register(gate: &WebAuthnGate, key: &SigningKey) -> String {
    let options = gate.begin_register("1TestAddr", None).unwrap();
    let challenge =
        serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
    let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x45); // UP + UV + AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&(CREDENTIAL_ID.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(CREDENTIAL_ID);
    auth_data.extend_from_slice(&cose_public_key(key));
    let attestation = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut attestation_bytes = Vec::new();
    coset::cbor::ser::into_writer(&attestation, &mut attestation_bytes).unwrap();
    let credential_id = URL_SAFE_NO_PAD.encode(CREDENTIAL_ID);
    gate.finish_register(
        &json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data(&challenge, "webauthn.create"),
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation_bytes),
            }
        })
        .to_string(),
    )
    .unwrap()
}

struct AssertionInput<'a> {
    allowed_id: &'a str,
    asserted_id: &'a [u8],
    key: &'a SigningKey,
    rp_id: &'a str,
    flags: u8,
    sign_count: u32,
    tamper_signature: bool,
}

impl<'a> AssertionInput<'a> {
    fn valid(allowed_id: &'a str, key: &'a SigningKey) -> Self {
        Self {
            allowed_id,
            asserted_id: CREDENTIAL_ID,
            key,
            rp_id: RP_ID,
            flags: 0x05,
            sign_count: 1,
            tamper_signature: false,
        }
    }
}

fn assertion(gate: &WebAuthnGate, input: AssertionInput<'_>) -> String {
    let options = gate.begin_auth(input.allowed_id, None).unwrap();
    let challenge =
        serde_json::from_str::<serde_json::Value>(&options).unwrap()["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
    let client_data = client_data(&challenge, "webauthn.get");
    let mut auth_data = Sha256::digest(input.rp_id.as_bytes()).to_vec();
    auth_data.push(input.flags);
    auth_data.extend_from_slice(&input.sign_count.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(
        URL_SAFE_NO_PAD.decode(&client_data).unwrap(),
    ));
    let signature: Signature = input.key.sign(&signed);
    let mut signature = signature.to_der().as_bytes().to_vec();
    if input.tamper_signature {
        *signature.last_mut().unwrap() ^= 1;
    }
    let asserted_id = URL_SAFE_NO_PAD.encode(input.asserted_id);
    json!({
        "id": asserted_id,
        "rawId": asserted_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data,
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
            "signature": URL_SAFE_NO_PAD.encode(signature),
        }
    })
    .to_string()
}

fn decode_stored(encoded: &str) -> StoredCredential {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
}

#[test]
fn crypto_roundtrip_updates_signature_counter() {
    tier0_gate("webauthn_crypto_roundtrip", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let assertion = assertion(&gate, AssertionInput::valid(&id, &key));
        let updated = gate.finish_auth(&assertion, Some(&stored)).unwrap();
        assert_eq!(decode_stored(&updated).sign_count, 1);
    });
}

#[test]
fn crypto_rejects_wrong_credential_id() {
    tier0_gate("webauthn_wrong_credential_id", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let assertion = assertion(
            &gate,
            AssertionInput {
                asserted_id: b"attacker",
                ..AssertionInput::valid(&id, &key)
            },
        );
        assert!(gate.finish_auth(&assertion, Some(&stored)).is_err());
    });
}

#[test]
fn crypto_rejects_missing_user_verification() {
    tier0_gate("webauthn_missing_uv", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let assertion = assertion(
            &gate,
            AssertionInput {
                flags: 0x01,
                ..AssertionInput::valid(&id, &key)
            },
        );
        assert!(gate.finish_auth(&assertion, Some(&stored)).is_err());
    });
}

#[test]
fn crypto_rejects_wrong_rp_hash() {
    tier0_gate("webauthn_wrong_rp", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let assertion = assertion(
            &gate,
            AssertionInput {
                rp_id: "evil.example",
                ..AssertionInput::valid(&id, &key)
            },
        );
        assert!(gate.finish_auth(&assertion, Some(&stored)).is_err());
    });
}

#[test]
fn crypto_rejects_tampered_signature() {
    tier0_gate("webauthn_bad_signature", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let assertion = assertion(
            &gate,
            AssertionInput {
                tamper_signature: true,
                ..AssertionInput::valid(&id, &key)
            },
        );
        assert!(gate.finish_auth(&assertion, Some(&stored)).is_err());
    });
}

#[test]
fn crypto_rejects_non_increasing_counter() {
    tier0_gate("webauthn_counter_replay", || {
        let gate = WebAuthnGate::new().unwrap();
        let key = signing_key();
        let stored = register(&gate, &key);
        let id = credential_id_from_store(&stored).unwrap();
        let first = assertion(&gate, AssertionInput::valid(&id, &key));
        let updated = gate.finish_auth(&first, Some(&stored)).unwrap();
        let replay = assertion(&gate, AssertionInput::valid(&id, &key));
        assert!(gate.finish_auth(&replay, Some(&updated)).is_err());
    });
}
