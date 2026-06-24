use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{WalletError, WalletResult};

const VAULT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub version: u8,
    pub address: String,
    pub created_at: String,
    pub kdf: String,
    pub security_profile: String,
    #[serde(default)]
    pub webauthn_credential_b64: Option<String>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

pub struct EncryptedVault {
    pub metadata: VaultMetadata,
    ciphertext: Vec<u8>,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl EncryptedVault {
    pub fn encrypt(
        secret_hex: &str,
        address: &str,
        passphrase: &str,
        security_profile: &str,
    ) -> WalletResult<Self> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), secret_hex.as_bytes())
            .map_err(|e| WalletError::Vault(e.to_string()))?;

        Ok(Self {
            metadata: VaultMetadata {
                version: VAULT_VERSION,
                address: address.to_owned(),
                created_at: chrono::Utc::now().to_rfc3339(),
                kdf: "argon2id-m=65536,t=3,p=4".into(),
                security_profile: security_profile.into(),
                webauthn_credential_b64: None,
            },
            ciphertext,
            salt,
            nonce,
        })
    }

    pub fn decrypt(&self, passphrase: &str) -> WalletResult<String> {
        let key = derive_key(passphrase, &self.salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        let plain = cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| WalletError::InvalidPassphrase)?;
        String::from_utf8(plain).map_err(|e| WalletError::Vault(e.to_string()))
    }

    pub fn save(&self, path: &PathBuf) -> WalletResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::Vault(e.to_string()))?;
        }
        let blob = VaultBlob {
            metadata: self.metadata.clone(),
            salt: hex::encode(self.salt),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        };
        let json = serde_json::to_string_pretty(&blob).map_err(|e| WalletError::Vault(e.to_string()))?;
        fs::write(path, json).map_err(|e| WalletError::Vault(e.to_string()))
    }

    pub fn load(path: &PathBuf) -> WalletResult<Self> {
        let raw = fs::read_to_string(path).map_err(|e| WalletError::Vault(e.to_string()))?;
        let blob: VaultBlob = serde_json::from_str(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
        Ok(Self {
            metadata: blob.metadata,
            salt: parse_fixed_array::<SALT_LEN>(&blob.salt)?,
            nonce: parse_fixed_array::<NONCE_LEN>(&blob.nonce)?,
            ciphertext: hex::decode(blob.ciphertext).map_err(|e| WalletError::Vault(e.to_string()))?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    metadata: VaultMetadata,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> WalletResult<DerivedKey> {
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| WalletError::Vault(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    Ok(DerivedKey(out))
}

fn parse_fixed_array<const N: usize>(hex_str: &str) -> WalletResult<[u8; N]> {
    let bytes = hex::decode(hex_str).map_err(|e| WalletError::Vault(e.to_string()))?;
    if bytes.len() != N {
        return Err(WalletError::Vault("invalid vault field length".into()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn default_vault_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("HacashWallet")
        .join("vault.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip() {
        let vault = EncryptedVault::encrypt("abc123", "1Test", "passphrase", "balanced").unwrap();
        let plain = vault.decrypt("passphrase").unwrap();
        assert_eq!(plain, "abc123");
        assert!(vault.decrypt("wrong").is_err());
    }
}