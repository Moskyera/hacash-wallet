//! secp256k1 ECDH + HKDF message encryption and inbox auth signatures.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use libsecp256k1::{PublicKey, SecretKey, SharedSecret};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sys::Account;

use crate::error::{WalletError, WalletResult};

pub const MESSENGER_CRYPTO_V1: u8 = 1;
pub const MESSENGER_CRYPTO_V2: u8 = 2;
const MESSENGER_HKDF_INFO: &[u8] = b"hacash-messenger-v2";
const MESSENGER_V1_INFO: &[u8] = b"hacash-messenger-v1";
const STORE_INFO: &[u8] = b"hacash-messenger-store-v1";
const INBOX_AUTH_DOMAIN: &[u8] = b"hacash-messenger-inbox-v1";
const NONCE_LEN: usize = 12;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PlainBody {
    pub body: String,
    pub sent_at: String,
}

pub fn storage_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STORE_INFO);
    h.update(secret);
    h.finalize().into()
}

pub fn pubkey_hex(account: &Account) -> String {
    hex::encode(account.public_key().serialize_compressed())
}

pub fn parse_pubkey_hex(hex_str: &str) -> WalletResult<[u8; 33]> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| WalletError::Other(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::Other("pubkey must be 33 bytes".into()))
}

pub fn verify_pubkey_address(pubkey: &[u8; 33], expected_addr: &str) -> bool {
    let derived = Account::get_address_by_public_key(*pubkey);
    Account::to_readable(&derived) == expected_addr
}

fn pair_key_v1(addr_a: &str, addr_b: &str) -> [u8; 32] {
    let (lo, hi) = if addr_a < addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };
    let mut h = Sha256::new();
    h.update(MESSENGER_V1_INFO);
    h.update(lo.as_bytes());
    h.update(hi.as_bytes());
    h.finalize().into()
}

fn ecdh_shared(my_sk: &SecretKey, peer_pk: &[u8; 33]) -> WalletResult<[u8; 32]> {
    let peer = PublicKey::parse_compressed(peer_pk).map_err(|e| WalletError::Other(e.to_string()))?;
    let shared = SharedSecret::<sha2_v09::Sha256>::new(&peer, my_sk)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_ref());
    Ok(out)
}

fn derive_message_key(shared: &[u8; 32], addr_a: &str, addr_b: &str) -> [u8; 32] {
    let (lo, hi) = if addr_a < addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };
    let mut salt = Vec::with_capacity(lo.len() + hi.len());
    salt.extend_from_slice(lo.as_bytes());
    salt.extend_from_slice(hi.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(MESSENGER_HKDF_INFO, &mut key)
        .expect("hkdf expand");
    key
}

fn encrypt_with_key(key: &[u8; 32], body: &str, sent_at: &str, aad: &[u8]) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("aes key");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let plaintext = serde_json::to_vec(&PlainBody {
        body: body.into(),
        sent_at: sent_at.into(),
    })
    .expect("serialize");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .expect("encrypt");
    (hex::encode(nonce_bytes), hex::encode(ciphertext))
}

fn decrypt_with_key(
    key: &[u8; 32],
    nonce_hex: &str,
    ciphertext_hex: &str,
    aad: &[u8],
) -> WalletResult<PlainBody> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(WalletError::Other("invalid messenger nonce".into()));
    }
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| WalletError::Other("messenger decrypt failed".into()))?;
    serde_json::from_slice(&plaintext).map_err(|e| WalletError::Other(e.to_string()))
}

pub fn encrypt_body_v2(
    my: &Account,
    my_addr: &str,
    peer_addr: &str,
    peer_pubkey: &[u8; 33],
    body: &str,
    sent_at: &str,
) -> WalletResult<(String, String)> {
    if !verify_pubkey_address(peer_pubkey, peer_addr) {
        return Err(WalletError::Other("peer pubkey does not match address".into()));
    }
    let shared = ecdh_shared(my.secret_key(), peer_pubkey)?;
    let key = derive_message_key(&shared, my_addr, peer_addr);
    Ok(encrypt_with_key(&key, body, sent_at, MESSENGER_HKDF_INFO))
}

pub fn encrypt_body_v1(my_addr: &str, peer_addr: &str, body: &str, sent_at: &str) -> (String, String) {
    let key = pair_key_v1(my_addr, peer_addr);
    encrypt_with_key(&key, body, sent_at, MESSENGER_V1_INFO)
}

pub fn decrypt_body(
    my: &Account,
    my_addr: &str,
    peer_addr: &str,
    peer_pubkey: Option<&[u8; 33]>,
    crypto_v: u8,
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> WalletResult<PlainBody> {
    match crypto_v {
        MESSENGER_CRYPTO_V2 => {
            let peer_pk = peer_pubkey.ok_or_else(|| {
                WalletError::Other("v2 envelope missing peer pubkey".into())
            })?;
            if !verify_pubkey_address(peer_pk, peer_addr) {
                return Err(WalletError::Other("peer pubkey mismatch".into()));
            }
            let shared = ecdh_shared(my.secret_key(), peer_pk)?;
            let key = derive_message_key(&shared, my_addr, peer_addr);
            decrypt_with_key(&key, nonce_hex, ciphertext_hex, MESSENGER_HKDF_INFO)
        }
        MESSENGER_CRYPTO_V1 => {
            let key = pair_key_v1(my_addr, peer_addr);
            decrypt_with_key(&key, nonce_hex, ciphertext_hex, MESSENGER_V1_INFO)
        }
        _ => Err(WalletError::Other(format!("unsupported messenger crypto v{crypto_v}"))),
    }
}

pub fn inbox_auth_digest(to: &str, nonce: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INBOX_AUTH_DOMAIN);
    h.update(to.as_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

pub fn sign_inbox_auth(account: &Account, to: &str, nonce: &str) -> String {
    let digest = inbox_auth_digest(to, nonce);
    hex::encode(account.do_sign(&digest))
}

pub fn verify_inbox_auth(
    to: &str,
    nonce: &str,
    claimant_pubkey: &[u8; 33],
    signature_hex: &str,
) -> WalletResult<()> {
    if !verify_pubkey_address(claimant_pubkey, to) {
        return Err(WalletError::Other("claimant pubkey does not match address".into()));
    }
    let sig_bytes = hex::decode(signature_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| WalletError::Other("signature must be 64 bytes".into()))?;
    let digest = inbox_auth_digest(to, nonce);
    if Account::verify_signature(&digest, claimant_pubkey, &sig) {
        Ok(())
    } else {
        Err(WalletError::Other("invalid inbox auth signature".into()))
    }
}

pub fn encrypt_store(plaintext: &[u8], key: &[u8; 32]) -> WalletResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: STORE_INFO,
            },
        )
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let out = serde_json::json!({
        "v": 1,
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(ciphertext),
    });
    serde_json::to_vec(&out).map_err(|e| WalletError::Other(e.to_string()))
}

pub fn decrypt_store(blob: &[u8], key: &[u8; 32]) -> WalletResult<Vec<u8>> {
    let wrapper: serde_json::Value =
        serde_json::from_slice(blob).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_hex = wrapper["nonce"]
        .as_str()
        .ok_or_else(|| WalletError::Other("missing store nonce".into()))?;
    let ciphertext_hex = wrapper["ciphertext"]
        .as_str()
        .ok_or_else(|| WalletError::Other("missing store ciphertext".into()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: STORE_INFO,
            },
        )
        .map_err(|_| WalletError::Other("messenger store decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_roundtrip() {
        let a = Account::create_by("test-a").unwrap();
        let b = Account::create_by("test-b").unwrap();
        let a_addr = a.readable().to_string();
        let b_addr = b.readable().to_string();
        let b_pk = b.public_key().serialize_compressed();
        let (n, c) = encrypt_body_v2(&a, &a_addr, &b_addr, &b_pk, "hello", "2026-01-01T00:00:00Z").unwrap();
        let p = decrypt_body(&b, &b_addr, &a_addr, Some(&a.public_key().serialize_compressed()), MESSENGER_CRYPTO_V2, &n, &c).unwrap();
        assert_eq!(p.body, "hello");
    }

    #[test]
    fn inbox_auth_roundtrip() {
        let a = Account::create_by("inbox-test").unwrap();
        let addr = a.readable().to_string();
        let nonce = "abc123";
        let sig = sign_inbox_auth(&a, &addr, nonce);
        verify_inbox_auth(&addr, nonce, &a.public_key().serialize_compressed(), &sig).unwrap();
    }
}