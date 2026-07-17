//! Encrypted at-rest storage for the quantum keystore blob (separate from settings.json).

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

pub fn save_encrypted(key: &QuantumFileKey, json: &str) -> WalletResult<()> {
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
    let raw = serde_json::to_string(&blob).map_err(|e| WalletError::Vault(e.to_string()))?;
    secure_write(&quantum_keystore_path(), raw.as_bytes())
        .map_err(|e| WalletError::Vault(e.to_string()))
}

pub fn load_encrypted(key: &QuantumFileKey) -> WalletResult<Option<String>> {
    let path = quantum_keystore_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    let blob: QuantumVaultBlob =
        serde_json::from_str(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
    let nonce = hex::decode(&blob.nonce).map_err(|e| WalletError::Vault(e.to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(WalletError::Vault("quantum keystore nonce invalid".into()));
    }
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
    String::from_utf8(plain)
        .map_err(|e| WalletError::Vault(e.to_string()))
        .map(Some)
}

pub fn remove_encrypted_file() -> WalletResult<()> {
    let path = quantum_keystore_path();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    Ok(())
}
