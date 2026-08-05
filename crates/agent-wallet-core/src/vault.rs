use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::kdf::KdfParams;
use hacash_wallet_core::paths::secure_write;
use hacash_wallet_core::secure_mem::LockedBytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

const VAULT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const STATE_MASTER_LEN: usize = 32;
const DESKTOP_IDENTITY_SECRET_LEN: usize = 32;
const MAX_VAULT_BYTES: u64 = 256 * 1024;
const MIN_PASSPHRASE_CHARS: usize = 15;
const MAX_PASSPHRASE_CHARS: usize = 1024;
const AAD_DOMAIN: &[u8] = b"HPAY/agent-wallet/vault/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentEncryptedVault {
    version: u8,
    wallet_id: AgentWalletId,
    address: String,
    network_mode: String,
    primary_signing_device_id: String,
    signer_epoch: u64,
    store_uuid: String,
    created_at: u64,
    kdf: String,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct VaultPayload {
    wallet_id: String,
    address: String,
    network_mode: String,
    blockchain_secret_hex: String,
    state_master_hex: String,
    desktop_identity_secret_hex: String,
    store_uuid: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct AgentVaultSecrets {
    blockchain_secret_hex: String,
    state_master: [u8; STATE_MASTER_LEN],
    desktop_identity_secret: [u8; DESKTOP_IDENTITY_SECRET_LEN],
}

impl AgentVaultSecrets {
    pub(crate) fn blockchain_secret_hex(&self) -> &str {
        &self.blockchain_secret_hex
    }

    pub(crate) fn state_master(&self) -> &[u8; STATE_MASTER_LEN] {
        &self.state_master
    }

    pub(crate) fn desktop_identity_secret(&self) -> &[u8; DESKTOP_IDENTITY_SECRET_LEN] {
        &self.desktop_identity_secret
    }
}

impl AgentEncryptedVault {
    pub(crate) fn create(
        wallet_id: AgentWalletId,
        passphrase: &str,
        network_mode: &str,
        created_at: u64,
    ) -> AgentWalletResult<(Self, String)> {
        validate_passphrase(passphrase)?;
        validate_network(network_mode)?;

        let primary_signing_device_id = format!("desktop_{}", uuid::Uuid::new_v4().simple());
        let desktop_identity_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let desktop_identity_secret_hex = hex::encode(desktop_identity_secret.to_bytes());
        let account = WalletAccount::create_random().map_err(|_| AgentWalletError::Crypto)?;
        let address = account.address();
        let blockchain_secret_hex = account.secret_hex();
        let mut state_master = [0_u8; STATE_MASTER_LEN];
        rand::thread_rng().fill_bytes(&mut state_master);
        let store_uuid = uuid::Uuid::new_v4().simple().to_string();

        let payload = VaultPayload {
            wallet_id: wallet_id.to_string(),
            address: address.clone(),
            network_mode: network_mode.to_owned(),
            blockchain_secret_hex: blockchain_secret_hex.to_string(),
            state_master_hex: hex::encode(state_master),
            desktop_identity_secret_hex,
            store_uuid: store_uuid.clone(),
        };
        state_master.zeroize();

        let kdf = KdfParams::paranoid();
        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut vault = Self {
            version: VAULT_VERSION,
            wallet_id,
            address: address.clone(),
            network_mode: network_mode.to_owned(),
            primary_signing_device_id,
            signer_epoch: 1,
            store_uuid,
            created_at,
            kdf: kdf.label(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: String::new(),
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| AgentWalletError::Crypto)?);
        let ciphertext = encrypt(
            passphrase,
            &salt,
            &nonce,
            &kdf,
            &vault.aad(),
            plaintext.as_slice(),
        )?;
        vault.ciphertext_hex = hex::encode(ciphertext);
        Ok((vault, address))
    }

    pub(crate) fn load(path: &Path) -> AgentWalletResult<Self> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| AgentWalletError::AgentWalletNotFound)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_BYTES {
            return Err(AgentWalletError::Vault);
        }
        let bytes = fs::read(path).map_err(|_| AgentWalletError::Vault)?;
        let vault: Self = serde_json::from_slice(&bytes).map_err(|_| AgentWalletError::Vault)?;
        vault.validate_metadata()?;
        Ok(vault)
    }

    /// Parses a `vault.json` document that is not on disk here yet.
    ///
    /// Used by backup and restore, which must read a vault's authenticated
    /// metadata - and decrypt it with the owner's passphrase - before anything
    /// is written. It applies `validate_metadata` exactly as [`Self::load`]
    /// does; the only difference is where the bytes came from.
    pub(crate) fn from_bytes(bytes: &[u8]) -> AgentWalletResult<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(AgentWalletError::Vault);
        }
        let vault: Self = serde_json::from_slice(bytes).map_err(|_| AgentWalletError::Vault)?;
        vault.validate_metadata()?;
        Ok(vault)
    }

    pub(crate) fn to_bytes(&self) -> AgentWalletResult<Vec<u8>> {
        self.validate_metadata()?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| AgentWalletError::Vault)?;
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(AgentWalletError::Vault);
        }
        Ok(bytes)
    }

    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    pub(crate) fn save(&self, path: &Path) -> AgentWalletResult<()> {
        self.validate_metadata()?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| AgentWalletError::Vault)?;
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(AgentWalletError::Vault);
        }
        secure_write(path, &bytes).map_err(|_| AgentWalletError::PersistenceFailed)
    }

    pub(crate) fn unlock(&self, passphrase: &str) -> AgentWalletResult<AgentVaultSecrets> {
        self.validate_metadata()?;
        let kdf = KdfParams::from_metadata_kdf(&self.kdf).map_err(|_| AgentWalletError::Vault)?;
        let salt = decode_array::<SALT_LEN>(&self.salt_hex)?;
        let nonce = decode_array::<NONCE_LEN>(&self.nonce_hex)?;
        let ciphertext = hex::decode(&self.ciphertext_hex).map_err(|_| AgentWalletError::Vault)?;
        let plaintext = Zeroizing::new(decrypt(
            passphrase,
            &salt,
            &nonce,
            &kdf,
            &self.aad(),
            &ciphertext,
        )?);
        let payload: VaultPayload =
            serde_json::from_slice(plaintext.as_slice()).map_err(|_| AgentWalletError::Vault)?;

        if payload.wallet_id != self.wallet_id.as_str()
            || payload.address != self.address
            || payload.network_mode != self.network_mode
            || payload.store_uuid != self.store_uuid
        {
            return Err(AgentWalletError::Vault);
        }
        let account = WalletAccount::from_secret_hex(&payload.blockchain_secret_hex)
            .map_err(|_| AgentWalletError::Vault)?;
        if account.address() != self.address {
            return Err(AgentWalletError::Vault);
        }
        let state_master = decode_array::<STATE_MASTER_LEN>(&payload.state_master_hex)?;
        let desktop_identity_secret =
            decode_array::<DESKTOP_IDENTITY_SECRET_LEN>(&payload.desktop_identity_secret_hex)?;
        hpay_agent_connector::ServerIdentityKey::from_secret_bytes(&desktop_identity_secret)
            .map_err(|_| AgentWalletError::Vault)?;
        Ok(AgentVaultSecrets {
            blockchain_secret_hex: payload.blockchain_secret_hex.clone(),
            state_master,
            desktop_identity_secret,
        })
    }

    pub(crate) fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }

    pub(crate) fn address(&self) -> &str {
        &self.address
    }

    pub(crate) fn network_mode(&self) -> &str {
        &self.network_mode
    }

    pub(crate) fn primary_signing_device_id(&self) -> &str {
        &self.primary_signing_device_id
    }

    pub(crate) fn signer_epoch(&self) -> u64 {
        self.signer_epoch
    }

    pub(crate) fn store_uuid(&self) -> &str {
        &self.store_uuid
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(256);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.push(self.version);
        push_field(&mut aad, self.wallet_id.as_str().as_bytes());
        push_field(&mut aad, self.address.as_bytes());
        push_field(&mut aad, self.network_mode.as_bytes());
        push_field(&mut aad, self.primary_signing_device_id.as_bytes());
        aad.extend_from_slice(&self.signer_epoch.to_be_bytes());
        push_field(&mut aad, self.store_uuid.as_bytes());
        aad.extend_from_slice(&self.created_at.to_be_bytes());
        push_field(&mut aad, self.kdf.as_bytes());
        aad
    }

    fn validate_metadata(&self) -> AgentWalletResult<()> {
        if self.version != VAULT_VERSION
            || self.signer_epoch == 0
            || self.store_uuid.len() != 32
            || !self.store_uuid.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.address.is_empty()
        {
            return Err(AgentWalletError::Vault);
        }
        AgentWalletId::parse(self.wallet_id.to_string())?;
        validate_network(&self.network_mode)?;
        validate_device_id(&self.primary_signing_device_id)?;
        KdfParams::from_metadata_kdf(&self.kdf).map_err(|_| AgentWalletError::Vault)?;
        let _ = decode_array::<SALT_LEN>(&self.salt_hex)?;
        let _ = decode_array::<NONCE_LEN>(&self.nonce_hex)?;
        let ciphertext = hex::decode(&self.ciphertext_hex).map_err(|_| AgentWalletError::Vault)?;
        if ciphertext.len() < 16 || ciphertext.len() > MAX_VAULT_BYTES as usize {
            return Err(AgentWalletError::Vault);
        }
        Ok(())
    }
}

/// Seals a state-backup payload with the same primitives this vault uses.
///
/// Argon2id at the paranoid profile over the owner's passphrase, AES-256-GCM,
/// caller-supplied additional authenticated data. It is the vault's own
/// `encrypt`, exported so that backup does not grow a second, subtly different
/// copy of the wallet's encryption - which is exactly how one of two copies ends
/// up weaker than the other.
pub(crate) fn seal_backup_payload(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> AgentWalletResult<Vec<u8>> {
    encrypt(
        passphrase,
        salt,
        nonce,
        &KdfParams::paranoid(),
        aad,
        plaintext,
    )
}

/// Opens what [`seal_backup_payload`] sealed. A wrong passphrase and a tampered
/// envelope are the same opaque `Vault` error, and neither reveals anything about
/// the passphrase.
pub(crate) fn open_backup_payload(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> AgentWalletResult<Vec<u8>> {
    decrypt(
        passphrase,
        salt,
        nonce,
        &KdfParams::paranoid(),
        aad,
        ciphertext,
    )
}

fn encrypt(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    kdf: &KdfParams,
    aad: &[u8],
    plaintext: &[u8],
) -> AgentWalletResult<Vec<u8>> {
    let key = derive_key(passphrase, salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| AgentWalletError::Crypto)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AgentWalletError::Crypto)
}

fn decrypt(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    kdf: &KdfParams,
    aad: &[u8],
    ciphertext: &[u8],
) -> AgentWalletResult<Vec<u8>> {
    let key = derive_key(passphrase, salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| AgentWalletError::Crypto)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AgentWalletError::Vault)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> AgentWalletResult<Zeroizing<[u8; 32]>> {
    validate_passphrase(passphrase)?;
    kdf.validate_bounds().map_err(|_| AgentWalletError::Vault)?;
    let locked =
        LockedBytes::from_slice(passphrase.as_bytes()).map_err(|_| AgentWalletError::Crypto)?;
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|_| AgentWalletError::Vault)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(locked.as_slice(), salt, output.as_mut())
        .map_err(|_| AgentWalletError::Crypto)?;
    Ok(output)
}

fn validate_passphrase(passphrase: &str) -> AgentWalletResult<()> {
    let chars = passphrase.chars().count();
    if !(MIN_PASSPHRASE_CHARS..=MAX_PASSPHRASE_CHARS).contains(&chars) {
        return Err(AgentWalletError::Vault);
    }
    Ok(())
}

fn validate_network(network: &str) -> AgentWalletResult<()> {
    if matches!(network, "mainnet" | "testnet") {
        Ok(())
    } else {
        Err(AgentWalletError::Vault)
    }
}

fn validate_device_id(device_id: &str) -> AgentWalletResult<()> {
    let suffix = device_id
        .strip_prefix("desktop_")
        .ok_or(AgentWalletError::Vault)?;
    if suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AgentWalletError::Vault)
    }
}

fn decode_array<const N: usize>(value: &str) -> AgentWalletResult<[u8; N]> {
    let bytes = Zeroizing::new(hex::decode(value).map_err(|_| AgentWalletError::Vault)?);
    if bytes.len() != N {
        return Err(AgentWalletError::Vault);
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes.as_slice());
    Ok(output)
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("vault metadata fields are bounded");
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
}

pub(crate) fn derive_domain_key(
    master: &[u8; STATE_MASTER_LEN],
    wallet_id: &AgentWalletId,
    store_uuid: &str,
    label: &[u8],
) -> AgentWalletResult<[u8; 32]> {
    use hkdf::Hkdf;

    let salt = Sha256::digest(
        [
            b"HPAY/agent-wallet/domain-key/v1".as_slice(),
            wallet_id.as_str().as_bytes(),
            store_uuid.as_bytes(),
        ]
        .concat(),
    );
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master);
    let mut output = [0_u8; 32];
    hkdf.expand(label, &mut output)
        .map_err(|_| AgentWalletError::Crypto)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip_binds_wallet_address_and_independent_master() {
        let wallet_id = AgentWalletId::new();
        let (vault, address) = AgentEncryptedVault::create(
            wallet_id.clone(),
            "correct horse battery agent",
            "testnet",
            1_700_000_000,
        )
        .unwrap();
        let secrets = vault.unlock("correct horse battery agent").unwrap();
        assert_eq!(
            WalletAccount::from_secret_hex(secrets.blockchain_secret_hex())
                .unwrap()
                .address(),
            address
        );
        assert_ne!(secrets.state_master(), &[0_u8; 32]);
        assert_ne!(secrets.desktop_identity_secret(), &[0_u8; 32]);
        assert_ne!(secrets.state_master(), secrets.desktop_identity_secret());
        assert!(vault.primary_signing_device_id().starts_with("desktop_"));
        assert_eq!(vault.primary_signing_device_id().len(), 40);
        assert_eq!(vault.wallet_id(), &wallet_id);
        assert!(vault.unlock("wrong passphrase value").is_err());
    }

    #[test]
    fn authenticated_metadata_cannot_be_swapped() {
        let (mut vault, _) = AgentEncryptedVault::create(
            AgentWalletId::new(),
            "correct horse battery agent",
            "testnet",
            1_700_000_000,
        )
        .unwrap();
        vault.network_mode = "mainnet".into();
        assert!(vault.unlock("correct horse battery agent").is_err());
    }

    #[test]
    fn save_load_uses_explicit_agent_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-vault.json");
        let (vault, _) = AgentEncryptedVault::create(
            AgentWalletId::new(),
            "correct horse battery agent",
            "testnet",
            1_700_000_000,
        )
        .unwrap();
        vault.save(&path).unwrap();
        let loaded = AgentEncryptedVault::load(&path).unwrap();
        assert_eq!(loaded.address(), vault.address());
    }
}
