//! Inbox fetch/ack authentication verified on the relay.

use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};

const INBOX_AUTH_DOMAIN: &[u8] = b"hacash-messenger-inbox-v1";

pub fn inbox_auth_digest(to: &str, nonce: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INBOX_AUTH_DOMAIN);
    h.update(to.as_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

pub fn verify_inbox_auth(
    to: &str,
    nonce: &str,
    claimant_pubkey_hex: &str,
    signature_hex: &str,
) -> bool {
    let Ok(pk_bytes) = hex::decode(claimant_pubkey_hex.trim()) else {
        return false;
    };
    let Ok(pk): Result<[u8; 33], _> = pk_bytes.try_into() else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let Ok(pubkey) = PublicKey::from_slice(&pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_compact(&sig_arr) else {
        return false;
    };
    let digest = inbox_auth_digest(to, nonce);
    Secp256k1::verification_only()
        .verify_ecdsa(Message::from_digest(digest), &sig, &pubkey)
        .is_ok()
}
