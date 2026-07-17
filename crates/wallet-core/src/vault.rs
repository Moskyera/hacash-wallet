use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{WalletError, WalletResult};
use crate::kdf::KdfParams;
use crate::paths::secure_write;
use crate::secure_mem::with_locked_passphrase;

pub const VAULT_VERSION_LATEST: u8 = 2;
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

#[derive(Clone)]
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
        let kdf = KdfParams::from_profile(security_profile);
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        let metadata = VaultMetadata {
            version: VAULT_VERSION_LATEST,
            address: address.to_owned(),
            created_at: chrono::Utc::now().to_rfc3339(),
            kdf: kdf.label(),
            security_profile: security_profile.into(),
            webauthn_credential_b64: None,
        };

        let aad = vault_aad(&metadata);
        let key = with_locked_passphrase(passphrase, |p| derive_key(p, &salt, &kdf))?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret_hex.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| WalletError::Vault(e.to_string()))?;

        Ok(Self {
            metadata,
            ciphertext,
            salt,
            nonce,
        })
    }

    pub fn decrypt(&self, passphrase: &str) -> WalletResult<String> {
        let kdf = KdfParams::from_metadata_kdf(&self.metadata.kdf)?;
        let key = with_locked_passphrase(passphrase, |p| derive_key(p, &self.salt, &kdf))?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|e| WalletError::Vault(e.to_string()))?;
        let payload = if self.metadata.version >= 2 {
            let aad = vault_aad(&self.metadata);
            cipher
                .decrypt(
                    Nonce::from_slice(&self.nonce),
                    Payload {
                        msg: self.ciphertext.as_ref(),
                        aad: &aad,
                    },
                )
                .map_err(|_| WalletError::InvalidPassphrase)?
        } else {
            cipher
                .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
                .map_err(|_| WalletError::InvalidPassphrase)?
        };
        String::from_utf8(payload).map_err(|e| WalletError::Vault(e.to_string()))
    }

    pub fn save(&self, path: &PathBuf) -> WalletResult<()> {
        let blob = VaultBlob {
            metadata: self.metadata.clone(),
            salt: hex::encode(self.salt),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        };
        let json = serde_json::to_string(&blob).map_err(|e| WalletError::Vault(e.to_string()))?;
        secure_write(path, json.as_bytes()).map_err(|e| WalletError::Vault(e.to_string()))
    }

    pub fn reencrypt(&mut self, old_passphrase: &str, new_passphrase: &str) -> WalletResult<()> {
        let mut secret = self.decrypt(old_passphrase)?;
        let address = self.metadata.address.clone();
        let profile = self.metadata.security_profile.clone();
        let webauthn = self.metadata.webauthn_credential_b64.clone();
        let mut replacement = Self::encrypt(&secret, &address, new_passphrase, &profile)?;
        secret.zeroize();
        replacement.metadata.webauthn_credential_b64 = webauthn;
        *self = replacement;
        Ok(())
    }

    pub fn export_json(&self) -> WalletResult<String> {
        let blob = VaultBlob {
            metadata: self.metadata.clone(),
            salt: hex::encode(self.salt),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        };
        serde_json::to_string_pretty(&blob).map_err(|e| WalletError::Vault(e.to_string()))
    }

    /// Parse an exported backup JSON blob (same format as [`Self::export_json`]).
    pub fn from_export_json(raw: &str) -> WalletResult<Self> {
        let blob: VaultBlob = serde_json::from_str(raw)
            .map_err(|e| WalletError::Vault(format!("invalid backup JSON: {e}")))?;
        Self::from_vault_blob(blob)
    }

    /// Read wallet address from backup metadata without decrypting (for UI preview).
    pub fn backup_address_from_json(raw: &str) -> WalletResult<String> {
        let blob: VaultBlob = serde_json::from_str(raw)
            .map_err(|e| WalletError::Vault(format!("invalid backup JSON: {e}")))?;
        if blob.metadata.address.trim().is_empty() {
            return Err(WalletError::Vault("backup missing address metadata".into()));
        }
        Ok(blob.metadata.address)
    }

    pub fn load(path: &PathBuf) -> WalletResult<Self> {
        let raw = fs::read_to_string(path).map_err(|e| WalletError::Vault(e.to_string()))?;
        let blob: VaultBlob =
            serde_json::from_str(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
        Self::from_vault_blob(blob)
    }

    fn from_vault_blob(blob: VaultBlob) -> WalletResult<Self> {
        if blob.metadata.version == 0 || blob.metadata.version > VAULT_VERSION_LATEST {
            return Err(WalletError::Vault(format!(
                "unsupported vault version {} (supported 1..={VAULT_VERSION_LATEST})",
                blob.metadata.version
            )));
        }
        let ciphertext =
            hex::decode(&blob.ciphertext).map_err(|e| WalletError::Vault(e.to_string()))?;
        if ciphertext.is_empty() {
            return Err(WalletError::Vault("empty vault ciphertext".into()));
        }
        Ok(Self {
            metadata: blob.metadata,
            salt: parse_fixed_array::<SALT_LEN>(&blob.salt)?,
            nonce: parse_fixed_array::<NONCE_LEN>(&blob.nonce)?,
            ciphertext,
        })
    }

    pub fn meta_snapshot(&self) -> VaultMetaSnapshot {
        VaultMetaSnapshot {
            address: self.metadata.address.clone(),
            security_profile: self.metadata.security_profile.clone(),
            webauthn_credential_b64: self.metadata.webauthn_credential_b64.clone(),
        }
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

#[derive(Debug, Clone)]
pub struct VaultMetaSnapshot {
    pub address: String,
    pub security_profile: String,
    pub webauthn_credential_b64: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    metadata: VaultMetadata,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn vault_aad(metadata: &VaultMetadata) -> Vec<u8> {
    format!(
        "hacash-vault|v{}|{}|{}|{}",
        metadata.version, metadata.address, metadata.security_profile, metadata.kdf
    )
    .into_bytes()
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> WalletResult<DerivedKey> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
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
    crate::paths::vault_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip_v2_aad() {
        let vault = EncryptedVault::encrypt("abc123", "1Test", "passphrase", "balanced").unwrap();
        assert_eq!(vault.metadata.version, 2);
        let plain = vault.decrypt("passphrase").unwrap();
        assert_eq!(plain, "abc123");
        assert!(vault.decrypt("wrong").is_err());
    }

    #[test]
    fn vault_aad_binds_metadata() {
        let mut vault =
            EncryptedVault::encrypt("abc123", "1Test", "passphrase", "balanced").unwrap();
        vault.metadata.address = "1Evil".into();
        assert!(vault.decrypt("passphrase").is_err());
    }

    #[test]
    fn paranoid_kdf_stronger_than_balanced() {
        let b = KdfParams::balanced();
        let p = KdfParams::paranoid();
        assert!(p.m_cost > b.m_cost);
        assert!(p.t_cost >= b.t_cost);
    }
}
