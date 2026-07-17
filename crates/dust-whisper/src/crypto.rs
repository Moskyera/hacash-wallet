use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::{WhisperError, WhisperResult};
use crate::protocol::{HKDF_INFO, PROTOCOL_VERSION, WhisperInnerPayload, WhisperSubmitRequest};

const NONCE_LEN: usize = 12;

pub fn generate_relay_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*secret);
    PublicKey::from(&sk).to_bytes()
}

fn derive_aes_key(shared_secret: &[u8], salt: &[u8]) -> WhisperResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| WhisperError::Crypto(format!("hkdf expand: {e}")))?;
    Ok(key)
}

fn envelope_aad(ephemeral_pk: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(33);
    aad.push(PROTOCOL_VERSION);
    aad.extend_from_slice(ephemeral_pk);
    aad
}

pub fn encrypt_payload(
    relay_pubkey_bytes: &[u8; 32],
    inner: &WhisperInnerPayload,
) -> WhisperResult<WhisperSubmitRequest> {
    let relay_pk = PublicKey::from(*relay_pubkey_bytes);
    let ephemeral = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&relay_pk);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pk.as_bytes());
    salt.extend_from_slice(relay_pk.as_bytes());
    let key = derive_aes_key(shared.as_bytes(), &salt)?;

    let plaintext = serde_json::to_vec(inner)
        .map_err(|e| WhisperError::Crypto(format!("serialize inner payload: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| WhisperError::Crypto(format!("aes key: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = envelope_aad(ephemeral_pk.as_bytes());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| WhisperError::Crypto(format!("encrypt: {e}")))?;

    Ok(WhisperSubmitRequest {
        v: PROTOCOL_VERSION,
        ephemeral_pubkey: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ephemeral_pk.as_bytes(),
        ),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
    })
}

pub fn decrypt_payload(
    relay_secret: &[u8; 32],
    request: &WhisperSubmitRequest,
) -> WhisperResult<WhisperInnerPayload> {
    if request.v != PROTOCOL_VERSION {
        return Err(WhisperError::Protocol(format!(
            "unsupported version {}",
            request.v
        )));
    }

    let ephemeral_pk_bytes = decode_32(&request.ephemeral_pubkey, "ephemeral_pubkey")?;
    let nonce_bytes = decode_nonce(&request.nonce)?;
    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.ciphertext,
    )
    .map_err(|e| WhisperError::Crypto(format!("ciphertext base64: {e}")))?;

    let relay_sk = StaticSecret::from(*relay_secret);
    let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);
    let shared = relay_sk.diffie_hellman(&ephemeral_pk);

    let relay_pk = PublicKey::from(&relay_sk);
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pk.as_bytes());
    salt.extend_from_slice(relay_pk.as_bytes());
    let key = derive_aes_key(shared.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| WhisperError::Crypto(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = envelope_aad(&ephemeral_pk_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| WhisperError::Crypto(format!("decrypt: {e}")))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| WhisperError::Crypto(format!("parse inner payload: {e}")))
}

fn decode_32(b64: &str, field: &str) -> WhisperResult<[u8; 32]> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| WhisperError::Crypto(format!("{field} base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WhisperError::Crypto(format!("{field} must be 32 bytes")))
}

fn decode_nonce(b64: &str) -> WhisperResult<[u8; NONCE_LEN]> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| WhisperError::Crypto(format!("nonce base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WhisperError::Crypto(format!("nonce must be {NONCE_LEN} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let (sk, pk) = generate_relay_keypair();
        let inner = WhisperInnerPayload {
            tx_hex: "deadbeef".into(),
        };
        let req = encrypt_payload(&pk, &inner).unwrap();
        let out = decrypt_payload(&sk, &req).unwrap();
        assert_eq!(out.tx_hex, "deadbeef");
    }
}
