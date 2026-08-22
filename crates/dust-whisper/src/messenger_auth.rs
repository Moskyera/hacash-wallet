//! Inbox fetch/ack authentication and envelope sender authentication.

use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};
use sys::Account;

use crate::protocol::MessengerEnvelope;

const INBOX_AUTH_DOMAIN: &[u8] = b"hacash-messenger-inbox-v1";
const ENVELOPE_AUTH_DOMAIN: &[u8] = b"hacash-messenger-envelope-v1";

pub fn inbox_auth_digest(to: &str, nonce: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INBOX_AUTH_DOMAIN);
    h.update(to.as_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

/// True when `pubkey` is the key that address `expected_addr` was derived from.
///
/// Without this the signature check below only proves that the caller holds *some*
/// key, never that the key owns the inbox being claimed, so any key could read and
/// delete any inbox. Same derivation the wallet uses in
/// `wallet-core/src/messenger_crypto.rs::verify_pubkey_address`.
pub fn pubkey_matches_address(pubkey: &[u8; 33], expected_addr: &str) -> bool {
    let derived = Account::get_address_by_public_key(*pubkey);
    Account::to_readable(&derived) == expected_addr
}

/// Everything on an envelope that decides where it goes and what it says.
///
/// `to` is inside the digest, so a signed envelope cannot be replayed into a
/// different person's inbox. `from_pubkey` is inside it too, so the key the
/// signature is checked against cannot be swapped after the fact. `from_sig`
/// is the one field left out: it is the signature over this.
pub fn envelope_auth_digest(env: &MessengerEnvelope) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ENVELOPE_AUTH_DOMAIN);
    h.update([env.v]);
    for part in [
        env.id.as_str(),
        env.to.as_str(),
        env.from.as_str(),
        env.from_pubkey.as_deref().unwrap_or(""),
        env.nonce.as_str(),
        env.ciphertext.as_str(),
        env.sent_at.as_str(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

/// True when the envelope really was written by the holder of `from`'s key.
///
/// The send endpoint had no authentication of any kind: `from` was a free
/// string, so anybody who knew two public addresses could post a message that
/// the recipient's wallet filed as an incoming message from a trusted contact.
/// Three things have to line up here: the envelope carries a sender pubkey,
/// that pubkey derives to the address in `from`, and it signed this envelope.
pub fn verify_envelope_sender(env: &MessengerEnvelope) -> bool {
    let (Some(pubkey_hex), Some(sig_hex)) = (env.from_pubkey.as_deref(), env.from_sig.as_deref())
    else {
        return false;
    };
    let Ok(pk_bytes) = hex::decode(pubkey_hex.trim()) else {
        return false;
    };
    let Ok(pk): Result<[u8; 33], _> = pk_bytes.try_into() else {
        return false;
    };
    if !pubkey_matches_address(&pk, env.from.trim()) {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
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
    Secp256k1::verification_only()
        .verify_ecdsa(
            Message::from_digest(envelope_auth_digest(env)),
            &sig,
            &pubkey,
        )
        .is_ok()
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
    if !pubkey_matches_address(&pk, to) {
        return false;
    }
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
