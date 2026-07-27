//! Replacing a registered authenticator must be approved by the authenticator
//! being replaced. Otherwise a stolen passphrase is enough to swap the second
//! factor for one the attacker holds, and the "WebAuthn gate" protects nobody.

mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{tier0_gate, with_isolated_wallet_dir};
use coset::{CborSerializable, CoseKeyBuilder, cbor::value::Value, iana};
use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::{WalletError, WalletService};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:1420";
const PASSPHRASE: &str = "webauthn-replacement-pass-01";

/// Distinct authenticators: `1` is the owner's, `2` the replacement, `3` an
/// attacker's key that was never registered.
fn authenticator(seed: u8) -> (SigningKey, Vec<u8>) {
    (
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap(),
        format!("credential-{seed}").into_bytes(),
    )
}

fn client_data(challenge: &str, typ: &str) -> String {
    URL_SAFE_NO_PAD.encode(
        json!({ "type": typ, "challenge": challenge, "origin": RP_ORIGIN })
            .to_string()
            .as_bytes(),
    )
}

fn challenge_of(options: &str) -> String {
    serde_json::from_str::<serde_json::Value>(options).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_string()
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

fn attestation_response(options: &str, key: &SigningKey, credential_id: &[u8]) -> String {
    let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x45); // UP + UV + AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose_public_key(key));
    let attestation = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut attestation_bytes = Vec::new();
    coset::cbor::ser::into_writer(&attestation, &mut attestation_bytes).unwrap();
    let encoded_id = URL_SAFE_NO_PAD.encode(credential_id);
    json!({
        "id": encoded_id,
        "rawId": encoded_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data(&challenge_of(options), "webauthn.create"),
            "attestationObject": URL_SAFE_NO_PAD.encode(attestation_bytes),
        }
    })
    .to_string()
}

fn assertion_response(
    options: &str,
    key: &SigningKey,
    credential_id: &[u8],
    sign_count: u32,
) -> String {
    let client_data = client_data(&challenge_of(options), "webauthn.get");
    let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x05); // UP + UV
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(
        URL_SAFE_NO_PAD.decode(&client_data).unwrap(),
    ));
    let signature: Signature = key.sign(&signed);
    let encoded_id = URL_SAFE_NO_PAD.encode(credential_id);
    json!({
        "id": encoded_id,
        "rawId": encoded_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data,
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    })
    .to_string()
}

fn register(wallet: &mut WalletService, key: &SigningKey, id: &[u8]) -> Result<(), WalletError> {
    let options = wallet.webauthn_register_begin(None)?;
    let response = attestation_response(&options, key, id);
    wallet.webauthn_register_finish(&response, PASSPHRASE)
}

fn approve_replacement(
    wallet: &mut WalletService,
    key: &SigningKey,
    id: &[u8],
    sign_count: u32,
) -> Result<(), WalletError> {
    let options = wallet.webauthn_replacement_auth_begin(None)?;
    let response = assertion_response(&options, key, id, sign_count);
    wallet.webauthn_replacement_auth_finish(&response)
}

fn wallet_with_first_authenticator() -> (WalletService, SigningKey, Vec<u8>) {
    let mut wallet = WalletService::new(None, None).unwrap();
    wallet.create_wallet(PASSPHRASE).unwrap();
    let (owner_key, owner_id) = authenticator(1);
    register(&mut wallet, &owner_key, &owner_id).unwrap();
    assert!(wallet.status().webauthn_enabled);
    (wallet, owner_key, owner_id)
}

#[test]
fn the_first_registration_needs_no_prior_approval() {
    tier0_gate("webauthn_first_registration", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, _, _) = wallet_with_first_authenticator();
            assert!(wallet.status().webauthn_enabled);
        });
    });
}

#[test]
fn the_passphrase_alone_cannot_swap_the_authenticator() {
    tier0_gate("webauthn_replacement_requires_old_key", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, _, _) = wallet_with_first_authenticator();
            let (attacker_key, attacker_id) = authenticator(3);

            let error = register(&mut wallet, &attacker_key, &attacker_id).unwrap_err();
            let message = format!("{error}");
            assert!(message.contains("current authenticator"), "{message}");

            // The registered credential is untouched: a later assertion from the
            // owner's key still verifies, which the attacker's cannot fake.
            let (owner_key, owner_id) = authenticator(1);
            approve_replacement(&mut wallet, &owner_key, &owner_id, 1).unwrap();
        });
    });
}

#[test]
fn an_unregistered_authenticator_cannot_approve_its_own_promotion() {
    tier0_gate("webauthn_replacement_rejects_foreign_key", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, _, owner_id) = wallet_with_first_authenticator();
            let (attacker_key, attacker_id) = authenticator(3);

            // Attacker signs with their own key, and separately tries to sign the
            // owner's credential id with the wrong key.
            assert!(approve_replacement(&mut wallet, &attacker_key, &attacker_id, 1).is_err());
            assert!(approve_replacement(&mut wallet, &attacker_key, &owner_id, 1).is_err());
            assert!(register(&mut wallet, &attacker_key, &attacker_id).is_err());
        });
    });
}

#[test]
fn an_approved_replacement_works_once_and_is_then_consumed() {
    tier0_gate("webauthn_replacement_single_use", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, owner_key, owner_id) = wallet_with_first_authenticator();
            let (second_key, second_id) = authenticator(2);
            let (third_key, third_id) = authenticator(3);

            approve_replacement(&mut wallet, &owner_key, &owner_id, 1).unwrap();
            register(&mut wallet, &second_key, &second_id).unwrap();

            // The approval does not linger for a second swap.
            let error = register(&mut wallet, &third_key, &third_id).unwrap_err();
            assert!(format!("{error}").contains("current authenticator"));

            // The new authenticator is now the one that must approve, and the
            // retired one no longer can.
            assert!(approve_replacement(&mut wallet, &owner_key, &owner_id, 2).is_err());
            approve_replacement(&mut wallet, &second_key, &second_id, 1).unwrap();
            register(&mut wallet, &third_key, &third_id).unwrap();
        });
    });
}

#[test]
fn approving_a_rotation_is_not_consent_to_sign() {
    tier0_gate("webauthn_replacement_is_not_a_send_factor", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, owner_key, owner_id) = wallet_with_first_authenticator();
            wallet
                .change_hardware_signing_mode(PASSPHRASE, HardwareSigningMode::WebAuthnGate)
                .unwrap();
            wallet.lock();
            wallet.unlock(PASSPHRASE).unwrap();

            approve_replacement(&mut wallet, &owner_key, &owner_id, 1).unwrap();
            let factors = wallet.audit_second_factor_snapshot().unwrap();
            assert!(
                !factors.yubikey_ok,
                "a rotation approval must not count as a send second factor"
            );
            assert!(!factors.biometric_ok);
        });
    });
}

#[test]
fn locking_the_wallet_discards_a_pending_rotation_approval() {
    tier0_gate("webauthn_replacement_cleared_on_lock", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, owner_key, owner_id) = wallet_with_first_authenticator();
            let (second_key, second_id) = authenticator(2);

            approve_replacement(&mut wallet, &owner_key, &owner_id, 1).unwrap();
            wallet.lock();
            wallet.unlock(PASSPHRASE).unwrap();
            let error = register(&mut wallet, &second_key, &second_id).unwrap_err();
            assert!(format!("{error}").contains("current authenticator"));
        });
    });
}
