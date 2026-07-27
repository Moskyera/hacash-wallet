//! Encrypted at-rest storage for the quantum keystore blob (separate from settings.json).

use std::io::Read;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{WalletError, WalletResult};
use crate::paths::{quantum_keystore_path, secure_write};

const NONCE_LEN: usize = 12;
const INFO: &[u8] = b"hacash-wallet-quantum-keystore-v1";
const AEAD_TAG_BYTES: usize = 16;
const MAX_QUANTUM_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUANTUM_FILE_BYTES: usize = MAX_QUANTUM_PLAINTEXT_BYTES * 2 + 4096;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QuantumFileKey([u8; 32]);

impl QuantumFileKey {
    pub fn derive(passphrase: &str, vault_salt: &[u8; 16]) -> WalletResult<Self> {
        let params = Params::new(32 * 1024, 2, 1, Some(32))
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(vault_salt);
        salt[0] ^= INFO[0];
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
struct QuantumVaultBlob {
    nonce: String,
    ciphertext: String,
}

pub(crate) fn encode_encrypted(key: &QuantumFileKey, json: &str) -> WalletResult<Vec<u8>> {
    if json.len() > MAX_QUANTUM_PLAINTEXT_BYTES {
        return Err(WalletError::Vault(
            "quantum keystore exceeds the safe size limit".into(),
        ));
    }

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| WalletError::Vault(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: json.as_bytes(),
                aad: INFO,
            },
        )
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    let blob = QuantumVaultBlob {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    };
    let raw = serde_json::to_vec(&blob).map_err(|e| WalletError::Vault(e.to_string()))?;
    if raw.len() > MAX_QUANTUM_FILE_BYTES {
        return Err(WalletError::Vault(
            "encrypted quantum keystore exceeds the safe size limit".into(),
        ));
    }
    Ok(raw)
}

pub(crate) fn decode_encrypted(key: &QuantumFileKey, raw: &[u8]) -> WalletResult<String> {
    if raw.len() > MAX_QUANTUM_FILE_BYTES {
        return Err(WalletError::Vault(
            "encrypted quantum keystore exceeds the safe size limit".into(),
        ));
    }
    let blob: QuantumVaultBlob =
        serde_json::from_slice(raw).map_err(|e| WalletError::Vault(e.to_string()))?;
    if blob.nonce.len() != NONCE_LEN * 2 {
        return Err(WalletError::Vault("quantum keystore nonce invalid".into()));
    }
    if blob.ciphertext.is_empty()
        || !blob.ciphertext.len().is_multiple_of(2)
        || blob.ciphertext.len() > (MAX_QUANTUM_PLAINTEXT_BYTES + AEAD_TAG_BYTES) * 2
    {
        return Err(WalletError::Vault(
            "quantum keystore ciphertext size outside safe limits".into(),
        ));
    }

    let nonce = hex::decode(&blob.nonce).map_err(|e| WalletError::Vault(e.to_string()))?;
    let ciphertext =
        hex::decode(&blob.ciphertext).map_err(|e| WalletError::Vault(e.to_string()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| WalletError::Vault(e.to_string()))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: INFO,
            },
        )
        .map_err(|_| WalletError::Vault("quantum keystore decrypt failed".into()))?;
    if plain.len() > MAX_QUANTUM_PLAINTEXT_BYTES {
        return Err(WalletError::Vault(
            "quantum keystore plaintext exceeds the safe size limit".into(),
        ));
    }
    String::from_utf8(plain).map_err(|e| WalletError::Vault(e.to_string()))
}

pub fn save_encrypted(key: &QuantumFileKey, json: &str) -> WalletResult<()> {
    let raw = encode_encrypted(key, json)?;
    secure_write(&quantum_keystore_path(), &raw).map_err(|e| WalletError::Vault(e.to_string()))
}

pub fn load_encrypted(key: &QuantumFileKey) -> WalletResult<Option<String>> {
    let path = quantum_keystore_path();
    if !path.exists() {
        return Ok(None);
    }
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WalletError::Vault(
            "quantum keystore path is not a regular file".into(),
        ));
    }
    if metadata.len() > MAX_QUANTUM_FILE_BYTES as u64 {
        return Err(WalletError::Vault(
            "encrypted quantum keystore exceeds the safe size limit".into(),
        ));
    }

    let file = std::fs::File::open(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_QUANTUM_FILE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    decode_encrypted(key, &raw).map(Some)
}

pub fn remove_encrypted_file() -> WalletResult<()> {
    let path = quantum_keystore_path();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_outer_encryption_roundtrip_and_wrong_key_rejection() {
        let salt_a = [7u8; 16];
        let salt_b = [8u8; 16];
        let key = QuantumFileKey::derive("wallet-passphrase", &salt_a).unwrap();
        let wrong_key = QuantumFileKey::derive("wallet-passphrase", &salt_b).unwrap();
        let raw = encode_encrypted(&key, r#"{"kind":"opaque","secret":"protected"}"#).unwrap();
        assert_eq!(
            decode_encrypted(&key, &raw).unwrap(),
            r#"{"kind":"opaque","secret":"protected"}"#
        );
        assert!(decode_encrypted(&wrong_key, &raw).is_err());
    }

    #[test]
    fn quantum_outer_file_size_is_bounded_before_json_or_crypto() {
        let key = QuantumFileKey::derive("wallet-passphrase", &[7u8; 16]).unwrap();
        let oversized = vec![0u8; MAX_QUANTUM_FILE_BYTES + 1];
        assert!(decode_encrypted(&key, &oversized).is_err());
    }
}
