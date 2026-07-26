use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::kdf::KdfParams;
use crate::paths::secure_write;
use crate::secure_mem::with_locked_passphrase;

pub const VAULT_VERSION_LATEST: u8 = 3;
const SALT_LEN: usize = 16;
pub const MAX_VAULT_FILE_BYTES: u64 = 128 * 1024;
const MAX_VAULT_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_METADATA_TEXT_BYTES: usize = 16 * 1024;
const MAX_SETTINGS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_QUANTUM_FILE_BYTES: u64 = 8 * 1024 * 1024 + 4096;
const MAX_MIGRATION_JOURNAL_BYTES: u64 = 4096;
const MIGRATION_VERSION: u8 = 1;

const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub version: u8,
    pub address: String,
    pub created_at: String,
    pub kdf: String,
    pub security_profile: String,
    #[serde(default)]
    pub hardware_signing_mode: String,
    #[serde(default)]
    pub webauthn_credential_b64: Option<String>,
    #[serde(default)]
    pub webauthn_credential_binding_sha256: Option<String>,
    /// Set only when the private key was derived from a human-chosen phrase
    /// instead of a random secret. Such a key is reproducible by anyone who
    /// guesses the phrase, so the fact must survive every migration, passphrase
    /// change and backup round-trip. Absent for every normal vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_key_derivation: Option<String>,
}

/// The only accepted value of [`VaultMetadata::legacy_key_derivation`]: the
/// upstream `Account::create_by_password` derivation, a single unsalted SHA-256.
pub const LEGACY_DERIVATION_BRAINWALLET_SHA256: &str = "brainwallet_sha256";

const SAFE_LEGACY_HARDWARE_MODE: &str = "webauthn_gate";

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
        Self::encrypt_with_policy(
            secret_hex,
            address,
            passphrase,
            security_profile,
            "software",
            None,
            None,
        )
    }

    /// Encrypt a key that was derived from a human-chosen phrase. The weakness is
    /// recorded in authenticated metadata so it can never be quietly lost.
    pub fn encrypt_legacy_derived(
        secret_hex: &str,
        address: &str,
        passphrase: &str,
        security_profile: &str,
        derivation: &str,
    ) -> WalletResult<Self> {
        Self::encrypt_with_policy(
            secret_hex,
            address,
            passphrase,
            security_profile,
            "software",
            None,
            Some(derivation),
        )
    }

    pub(crate) fn encrypt_with_policy(
        secret_hex: &str,
        address: &str,
        passphrase: &str,
        security_profile: &str,
        hardware_signing_mode: &str,
        webauthn_credential_b64: Option<&str>,
        legacy_key_derivation: Option<&str>,
    ) -> WalletResult<Self> {
        if let Some(derivation) = legacy_key_derivation
            && derivation != LEGACY_DERIVATION_BRAINWALLET_SHA256
        {
            return Err(WalletError::Vault(
                "unknown legacy key derivation marker".into(),
            ));
        }
        let kdf = KdfParams::try_from_profile(security_profile)?;
        validate_signing_policy(security_profile, hardware_signing_mode)?;
        let webauthn_credential_binding_sha256 = webauthn_credential_b64
            .map(crate::webauthn::credential_binding_sha256)
            .transpose()?;
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
            hardware_signing_mode: hardware_signing_mode.into(),
            webauthn_credential_b64: webauthn_credential_b64.map(str::to_owned),
            webauthn_credential_binding_sha256,
            legacy_key_derivation: legacy_key_derivation.map(str::to_owned),
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

    pub fn decrypt_verified_secret(&self, passphrase: &str) -> WalletResult<String> {
        let mut secret = self.decrypt(passphrase)?;
        let account = match WalletAccount::from_secret_hex(&secret) {
            Ok(account) => account,
            Err(_) => {
                secret.zeroize();
                return Err(WalletError::Vault(
                    "decrypted vault secret is invalid".into(),
                ));
            }
        };
        if account.address() != self.metadata.address {
            secret.zeroize();
            return Err(WalletError::Vault(
                "vault address metadata does not match its private key".into(),
            ));
        }
        Ok(secret)
    }

    pub fn save(&self, path: &Path) -> WalletResult<()> {
        let json = self.to_json_bytes(false)?;
        secure_write(path, &json).map_err(|e| WalletError::Vault(e.to_string()))
    }

    pub fn reencrypted_for_profile(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        security_profile: &str,
    ) -> WalletResult<Self> {
        let (hardware_signing_mode, webauthn_credential_b64) = self.policy_for_migration()?;
        self.reencrypted_with_policy(
            old_passphrase,
            new_passphrase,
            security_profile,
            &hardware_signing_mode,
            webauthn_credential_b64.as_deref(),
        )
    }

    pub(crate) fn reencrypted_with_policy(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        security_profile: &str,
        hardware_signing_mode: &str,
        webauthn_credential_b64: Option<&str>,
    ) -> WalletResult<Self> {
        let mut secret = self.decrypt_verified_secret(old_passphrase)?;
        let replacement = Self::encrypt_with_policy(
            &secret,
            &self.metadata.address,
            new_passphrase,
            security_profile,
            hardware_signing_mode,
            webauthn_credential_b64,
            // A weak derivation is a permanent property of the key, not of this
            // vault file. No migration may launder it away.
            self.metadata.legacy_key_derivation.as_deref(),
        );
        secret.zeroize();
        let mut replacement = replacement?;
        replacement.metadata.created_at = self.metadata.created_at.clone();
        Ok(replacement)
    }

    /// Return the policy that may safely survive an authenticated migration.
    ///
    /// Version 1 had no metadata authentication and version 2 did not authenticate
    /// either the signing mode or WebAuthn credential. Legacy vaults therefore
    /// migrate to a fail-closed WebAuthn gate with no credential; the owner must
    /// explicitly re-register WebAuthn or authenticate a switch back to software.
    pub(crate) fn policy_for_migration(&self) -> WalletResult<(String, Option<String>)> {
        if self.metadata.version >= 3 {
            self.validate_authenticated_policy()?;
            return Ok((
                self.metadata.hardware_signing_mode.clone(),
                self.metadata.webauthn_credential_b64.clone(),
            ));
        }
        Ok((SAFE_LEGACY_HARDWARE_MODE.into(), None))
    }

    pub(crate) fn security_profile_for_migration(&self) -> String {
        if self.metadata.version >= 2 {
            self.metadata.security_profile.clone()
        } else {
            // V1 metadata was not AAD-bound, so never inherit its potentially
            // tampered policy. Paranoid is the only fail-closed migration target.
            "paranoid".into()
        }
    }

    pub(crate) fn update_webauthn_counter_credential(
        &mut self,
        updated_credential_b64: &str,
    ) -> WalletResult<()> {
        self.validate_authenticated_policy()?;
        let expected = self
            .metadata
            .webauthn_credential_binding_sha256
            .as_deref()
            .ok_or_else(|| WalletError::Policy("WebAuthn credential is not registered".into()))?;
        let actual = crate::webauthn::credential_binding_sha256(updated_credential_b64)?;
        if actual != expected {
            return Err(WalletError::Policy(
                "WebAuthn credential binding changed during authentication".into(),
            ));
        }
        self.metadata.webauthn_credential_b64 = Some(updated_credential_b64.into());
        Ok(())
    }

    pub fn reencrypt(&mut self, old_passphrase: &str, new_passphrase: &str) -> WalletResult<()> {
        *self = self.reencrypted_for_profile(
            old_passphrase,
            new_passphrase,
            &self.metadata.security_profile,
        )?;
        Ok(())
    }

    pub fn export_json(&self) -> WalletResult<String> {
        let json = self.to_json_bytes(true)?;
        String::from_utf8(json).map_err(|e| WalletError::Vault(e.to_string()))
    }

    fn to_blob(&self) -> VaultBlob {
        VaultBlob {
            metadata: self.metadata.clone(),
            salt: hex::encode(self.salt),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        }
    }

    fn to_json_bytes(&self, pretty: bool) -> WalletResult<Vec<u8>> {
        if pretty {
            serde_json::to_vec_pretty(&self.to_blob())
        } else {
            serde_json::to_vec(&self.to_blob())
        }
        .map_err(|e| WalletError::Vault(e.to_string()))
    }

    /// Parse an exported backup JSON blob (same format as [`Self::export_json`]).
    pub fn from_export_json(raw: &str) -> WalletResult<Self> {
        ensure_input_size(raw.len(), MAX_VAULT_FILE_BYTES, "backup")?;
        let blob: VaultBlob = serde_json::from_str(raw)
            .map_err(|e| WalletError::Vault(format!("invalid backup JSON: {e}")))?;
        Self::from_vault_blob(blob)
    }

    /// Read wallet address from backup metadata without decrypting (for UI preview).
    pub fn backup_address_from_json(raw: &str) -> WalletResult<String> {
        ensure_input_size(raw.len(), MAX_VAULT_FILE_BYTES, "backup")?;
        let blob: VaultBlob = serde_json::from_str(raw)
            .map_err(|e| WalletError::Vault(format!("invalid backup JSON: {e}")))?;
        validate_vault_blob(&blob)?;
        Ok(blob.metadata.address)
    }

    pub fn load(path: &Path) -> WalletResult<Self> {
        let raw = read_bounded(path, MAX_VAULT_FILE_BYTES, "vault")?;
        let blob: VaultBlob =
            serde_json::from_slice(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
        Self::from_vault_blob(blob)
    }

    fn from_vault_blob(blob: VaultBlob) -> WalletResult<Self> {
        validate_vault_blob(&blob)?;
        let ciphertext =
            hex::decode(&blob.ciphertext).map_err(|e| WalletError::Vault(e.to_string()))?;
        Ok(Self {
            metadata: blob.metadata,
            salt: parse_fixed_array::<SALT_LEN>(&blob.salt)?,
            nonce: parse_fixed_array::<NONCE_LEN>(&blob.nonce)?,
            ciphertext,
        })
    }

    pub fn meta_snapshot(&self) -> VaultMetaSnapshot {
        VaultMetaSnapshot {
            version: self.metadata.version,
            address: self.metadata.address.clone(),
            security_profile: self.metadata.security_profile.clone(),
            hardware_signing_mode: self.metadata.hardware_signing_mode.clone(),
            webauthn_credential_b64: self.metadata.webauthn_credential_b64.clone(),
            webauthn_credential_binding_sha256: self
                .metadata
                .webauthn_credential_binding_sha256
                .clone(),
            legacy_key_derivation: self.metadata.legacy_key_derivation.clone(),
        }
    }

    pub fn legacy_key_derivation(&self) -> Option<&str> {
        self.metadata.legacy_key_derivation.as_deref()
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub(crate) fn validate_authenticated_policy(&self) -> WalletResult<()> {
        if self.metadata.version < 3 {
            return Err(WalletError::Policy(
                "legacy vault policy must be migrated after passphrase authentication".into(),
            ));
        }
        validate_signing_policy(
            &self.metadata.security_profile,
            &self.metadata.hardware_signing_mode,
        )?;
        validate_webauthn_binding_metadata(&self.metadata)
    }
}

#[derive(Debug, Clone)]
pub struct VaultMetaSnapshot {
    pub version: u8,
    pub address: String,
    pub security_profile: String,
    pub hardware_signing_mode: String,
    pub webauthn_credential_b64: Option<String>,
    pub webauthn_credential_binding_sha256: Option<String>,
    pub legacy_key_derivation: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    metadata: VaultMetadata,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn validate_vault_blob(blob: &VaultBlob) -> WalletResult<()> {
    let metadata = &blob.metadata;
    if metadata.version == 0 || metadata.version > VAULT_VERSION_LATEST {
        return Err(WalletError::Vault(format!(
            "unsupported vault version {} (supported 1..={VAULT_VERSION_LATEST})",
            metadata.version
        )));
    }
    if metadata.address.trim().is_empty() || metadata.address.len() > 128 {
        return Err(WalletError::Vault("invalid vault address metadata".into()));
    }
    let metadata_bytes = metadata.address.len()
        + metadata.created_at.len()
        + metadata.kdf.len()
        + metadata.security_profile.len()
        + metadata.hardware_signing_mode.len()
        + metadata
            .webauthn_credential_b64
            .as_ref()
            .map_or(0, String::len)
        + metadata
            .webauthn_credential_binding_sha256
            .as_ref()
            .map_or(0, String::len)
        + metadata.legacy_key_derivation.as_ref().map_or(0, String::len);
    if metadata_bytes > MAX_METADATA_TEXT_BYTES {
        return Err(WalletError::Vault(
            "vault metadata exceeds safe limit".into(),
        ));
    }

    let stored_kdf = KdfParams::from_metadata_kdf(&metadata.kdf)?;
    if metadata.version >= 2 {
        let expected_kdf = KdfParams::try_from_profile(&metadata.security_profile)?;
        if stored_kdf != expected_kdf {
            return Err(WalletError::Vault(
                "vault profile and kdf metadata are inconsistent".into(),
            ));
        }
        if metadata.version >= 3 {
            validate_signing_policy(&metadata.security_profile, &metadata.hardware_signing_mode)?;
            validate_webauthn_binding_metadata(metadata)?;
        }
    }
    if let Some(derivation) = metadata.legacy_key_derivation.as_deref() {
        if metadata.version < 3 {
            return Err(WalletError::Vault(
                "legacy derivation marker requires an authenticated vault version".into(),
            ));
        }
        if derivation != LEGACY_DERIVATION_BRAINWALLET_SHA256 {
            return Err(WalletError::Vault(
                "unknown legacy key derivation marker".into(),
            ));
        }
    }

    if blob.salt.len() != SALT_LEN * 2 || blob.nonce.len() != NONCE_LEN * 2 {
        return Err(WalletError::Vault("invalid vault field length".into()));
    }
    if blob.ciphertext.is_empty()
        || !blob.ciphertext.len().is_multiple_of(2)
        || blob.ciphertext.len() > MAX_VAULT_CIPHERTEXT_BYTES * 2
    {
        return Err(WalletError::Vault(
            "vault ciphertext size outside safe limits".into(),
        ));
    }
    Ok(())
}

fn validate_signing_hardware_mode(mode: &str) -> WalletResult<()> {
    if matches!(mode, "software" | "webauthn_gate" | "airgap_only") {
        return Ok(());
    }
    Err(WalletError::Policy(
        "signing vault has an invalid authenticated hardware mode".into(),
    ))
}

fn validate_signing_policy(profile: &str, mode: &str) -> WalletResult<()> {
    validate_signing_hardware_mode(mode)?;
    if mode == "airgap_only" && profile != "paranoid" {
        return Err(WalletError::Policy(
            "cold vault requires the paranoid security profile".into(),
        ));
    }
    Ok(())
}

fn validate_webauthn_binding_metadata(metadata: &VaultMetadata) -> WalletResult<()> {
    match (
        metadata.webauthn_credential_b64.as_deref(),
        metadata.webauthn_credential_binding_sha256.as_deref(),
    ) {
        (None, None) => Ok(()),
        (Some(credential), Some(expected)) => {
            if expected.len() != 64
                || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
                || expected.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(WalletError::Policy(
                    "invalid WebAuthn credential binding metadata".into(),
                ));
            }
            if crate::webauthn::credential_binding_sha256(credential)? != expected {
                return Err(WalletError::Policy(
                    "stored WebAuthn credential does not match its binding".into(),
                ));
            }
            Ok(())
        }
        _ => Err(WalletError::Policy(
            "WebAuthn credential and binding must both be present".into(),
        )),
    }
}

fn vault_aad(metadata: &VaultMetadata) -> Vec<u8> {
    if metadata.version == 2 {
        return format!(
            "hacash-vault|v{}|{}|{}|{}",
            metadata.version, metadata.address, metadata.security_profile, metadata.kdf
        )
        .into_bytes();
    }
    if metadata.version >= 3 {
        let mut aad = b"hacash-vault-aad-v3".to_vec();
        push_aad_field(&mut aad, &[metadata.version]);
        push_aad_field(&mut aad, metadata.address.as_bytes());
        push_aad_field(&mut aad, metadata.security_profile.as_bytes());
        push_aad_field(&mut aad, metadata.kdf.as_bytes());
        push_aad_field(&mut aad, metadata.hardware_signing_mode.as_bytes());
        push_aad_field(
            &mut aad,
            metadata
                .webauthn_credential_binding_sha256
                .as_deref()
                .unwrap_or("none")
                .as_bytes(),
        );
        // Appended only when present, so the AAD of every vault written before
        // this field existed stays byte-identical and keeps decrypting. Adding,
        // removing or editing the marker on an existing vault breaks GCM.
        if let Some(derivation) = metadata.legacy_key_derivation.as_deref() {
            push_aad_field(&mut aad, b"legacy-key-derivation");
            push_aad_field(&mut aad, derivation.as_bytes());
        }
        return aad;
    }
    Vec::new()
}

fn push_aad_field(aad: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    aad.extend_from_slice(&len.to_be_bytes());
    aad.extend_from_slice(value);
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

fn ensure_input_size(actual: usize, maximum: u64, label: &str) -> WalletResult<()> {
    if actual as u64 > maximum {
        return Err(WalletError::Vault(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> WalletResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| WalletError::Vault(e.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WalletError::Vault(format!(
            "{label} path is not a regular file"
        )));
    }
    if metadata.len() > maximum {
        return Err(WalletError::Vault(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    let file = fs::File::open(path).map_err(|e| WalletError::Vault(e.to_string()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    ensure_input_size(bytes.len(), maximum, label)?;
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MigrationPhase {
    Commit,
    Rollback,
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationJournal {
    version: u8,
    phase: MigrationPhase,
    quantum_included: bool,
    quantum_existed: bool,
    settings_included: bool,
    settings_existed: bool,
}

struct MigrationPaths<'a> {
    vault: &'a Path,
    quantum: &'a Path,
    settings: &'a Path,
}

fn migration_journal_path(vault_path: &Path) -> WalletResult<PathBuf> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| WalletError::Vault("vault path has no parent".into()))?;
    Ok(parent.join(".wallet-vault-migration-v1.json"))
}

fn migration_artifact_path(target: &Path, suffix: &str) -> WalletResult<PathBuf> {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| WalletError::Vault("wallet data path is invalid".into()))?;
    Ok(target.with_file_name(format!("{name}.migration-{suffix}")))
}

fn sync_parent(path: &Path) -> WalletResult<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| WalletError::Vault("wallet data path has no parent".into()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> WalletResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WalletError::Vault(error.to_string())),
    }
}

fn remove_target_artifacts(target: &Path) -> WalletResult<()> {
    remove_if_exists(&migration_artifact_path(target, "new")?)?;
    remove_if_exists(&migration_artifact_path(target, "old")?)
}

fn cleanup_migration_artifacts(paths: &MigrationPaths<'_>) {
    let _ = remove_target_artifacts(paths.vault);
    let _ = remove_target_artifacts(paths.quantum);
    let _ = remove_target_artifacts(paths.settings);
}

/// Permanently abandon any pending migration before a user-authorized wallet reset. Removing the
/// journal first prevents a later startup from restoring files the reset deliberately deleted.
pub(crate) fn discard_wallet_migration(
    vault_path: &Path,
    quantum_path: &Path,
    settings_path: &Path,
) -> WalletResult<()> {
    let paths = MigrationPaths {
        vault: vault_path,
        quantum: quantum_path,
        settings: settings_path,
    };
    let journal_path = migration_journal_path(vault_path)?;
    remove_if_exists(&journal_path)?;
    sync_parent(&journal_path)?;
    remove_target_artifacts(paths.vault)?;
    remove_target_artifacts(paths.quantum)?;
    remove_target_artifacts(paths.settings)?;
    Ok(())
}

fn prepare_target(target: &Path, new_bytes: &[u8], maximum: u64) -> WalletResult<bool> {
    ensure_input_size(new_bytes.len(), maximum, "migration payload")?;
    let new_path = migration_artifact_path(target, "new")?;
    let old_path = migration_artifact_path(target, "old")?;
    remove_if_exists(&new_path)?;
    remove_if_exists(&old_path)?;

    let existed = target.exists();
    if existed {
        let old_bytes = read_bounded(target, maximum, "wallet data")?;
        secure_write(&old_path, &old_bytes).map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    secure_write(&new_path, new_bytes).map_err(|e| WalletError::Vault(e.to_string()))?;
    sync_parent(target)?;
    Ok(existed)
}

fn apply_target(
    target: &Path,
    phase: MigrationPhase,
    existed_before: bool,
    maximum: u64,
) -> WalletResult<()> {
    let source = match phase {
        MigrationPhase::Commit => migration_artifact_path(target, "new")?,
        MigrationPhase::Rollback => migration_artifact_path(target, "old")?,
    };

    if phase == MigrationPhase::Rollback && !existed_before {
        remove_if_exists(target)?;
        sync_parent(target)?;
        return Ok(());
    }

    let expected = read_bounded(&source, maximum, "migration artifact")?;
    secure_write(target, &expected).map_err(|e| WalletError::Vault(e.to_string()))?;
    let actual = read_bounded(target, maximum, "migrated wallet data")?;
    if actual != expected {
        return Err(WalletError::Vault(
            "wallet migration verification failed".into(),
        ));
    }
    sync_parent(target)
}

fn write_migration_journal(path: &Path, journal: &MigrationJournal) -> WalletResult<()> {
    let bytes = serde_json::to_vec(journal).map_err(|e| WalletError::Vault(e.to_string()))?;
    ensure_input_size(
        bytes.len(),
        MAX_MIGRATION_JOURNAL_BYTES,
        "migration journal",
    )?;
    secure_write(path, &bytes).map_err(|e| WalletError::Vault(e.to_string()))?;
    sync_parent(path)
}

pub(crate) fn recover_wallet_migration(
    vault_path: &Path,
    quantum_path: &Path,
    settings_path: &Path,
) -> WalletResult<()> {
    let paths = MigrationPaths {
        vault: vault_path,
        quantum: quantum_path,
        settings: settings_path,
    };
    let journal_path = migration_journal_path(vault_path)?;
    if !journal_path.exists() {
        cleanup_migration_artifacts(&paths);
        return Ok(());
    }

    let raw = read_bounded(
        &journal_path,
        MAX_MIGRATION_JOURNAL_BYTES,
        "migration journal",
    )?;
    let journal: MigrationJournal =
        serde_json::from_slice(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
    if journal.version != MIGRATION_VERSION {
        return Err(WalletError::Vault(
            "unsupported wallet migration journal".into(),
        ));
    }

    apply_target(paths.vault, journal.phase, true, MAX_VAULT_FILE_BYTES)?;
    if journal.quantum_included {
        apply_target(
            paths.quantum,
            journal.phase,
            journal.quantum_existed,
            MAX_QUANTUM_FILE_BYTES,
        )?;
    }
    if journal.settings_included {
        apply_target(
            paths.settings,
            journal.phase,
            journal.settings_existed,
            MAX_SETTINGS_FILE_BYTES,
        )?;
    }

    remove_if_exists(&journal_path)?;
    sync_parent(&journal_path)?;
    cleanup_migration_artifacts(&paths);
    Ok(())
}

pub(crate) fn commit_wallet_migration(
    vault_path: &Path,
    replacement_vault: &EncryptedVault,
    quantum_path: &Path,
    replacement_quantum: Option<&[u8]>,
    settings_path: &Path,
    replacement_settings: Option<&[u8]>,
) -> WalletResult<()> {
    let paths = MigrationPaths {
        vault: vault_path,
        quantum: quantum_path,
        settings: settings_path,
    };
    recover_wallet_migration(paths.vault, paths.quantum, paths.settings)?;
    cleanup_migration_artifacts(&paths);
    let journal_path = migration_journal_path(paths.vault)?;
    let vault_bytes = replacement_vault.to_json_bytes(false)?;

    let prepared: WalletResult<(Option<bool>, Option<bool>)> = (|| {
        if !prepare_target(paths.vault, &vault_bytes, MAX_VAULT_FILE_BYTES)? {
            return Err(WalletError::NoWallet);
        }
        let quantum_existed = replacement_quantum
            .map(|bytes| prepare_target(paths.quantum, bytes, MAX_QUANTUM_FILE_BYTES))
            .transpose()?;
        let settings_existed = replacement_settings
            .map(|bytes| prepare_target(paths.settings, bytes, MAX_SETTINGS_FILE_BYTES))
            .transpose()?;
        Ok((quantum_existed, settings_existed))
    })();
    let (quantum_existed, settings_existed) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            cleanup_migration_artifacts(&paths);
            return Err(error);
        }
    };

    let mut journal = MigrationJournal {
        version: MIGRATION_VERSION,
        phase: MigrationPhase::Commit,
        quantum_included: quantum_existed.is_some(),
        quantum_existed: quantum_existed.unwrap_or(false),
        settings_included: settings_existed.is_some(),
        settings_existed: settings_existed.unwrap_or(false),
    };
    if let Err(error) = write_migration_journal(&journal_path, &journal) {
        let journal_removed =
            remove_if_exists(&journal_path).and_then(|()| sync_parent(&journal_path));
        if journal_removed.is_ok() {
            cleanup_migration_artifacts(&paths);
            return Err(error);
        }
        return Err(WalletError::Vault(format!(
            "wallet migration journal cleanup failed; restart required: {error}"
        )));
    }

    match recover_wallet_migration(paths.vault, paths.quantum, paths.settings) {
        Ok(()) => Ok(()),
        Err(commit_error) => {
            journal.phase = MigrationPhase::Rollback;
            if let Err(journal_error) = write_migration_journal(&journal_path, &journal) {
                return Err(WalletError::Vault(format!(
                    "wallet migration interrupted; restart required: {commit_error}; rollback journal: {journal_error}"
                )));
            }
            match recover_wallet_migration(paths.vault, paths.quantum, paths.settings) {
                Ok(()) => Err(commit_error),
                Err(rollback_error) => Err(WalletError::Vault(format!(
                    "wallet migration recovery required: {commit_error}; rollback: {rollback_error}"
                ))),
            }
        }
    }
}

pub fn default_vault_path() -> PathBuf {
    crate::paths::vault_path()
}

#[cfg(test)]
impl EncryptedVault {
    pub(crate) fn encrypt_legacy_v2_for_test(
        secret_hex: &str,
        address: &str,
        passphrase: &str,
        security_profile: &str,
        webauthn_credential_b64: Option<&str>,
    ) -> WalletResult<Self> {
        let kdf = KdfParams::try_from_profile(security_profile)?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata = VaultMetadata {
            version: 2,
            address: address.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            kdf: kdf.label(),
            security_profile: security_profile.into(),
            hardware_signing_mode: String::new(),
            webauthn_credential_b64: webauthn_credential_b64.map(str::to_owned),
            webauthn_credential_binding_sha256: None,
            legacy_key_derivation: None,
        };
        let key = with_locked_passphrase(passphrase, |p| derive_key(p, &salt, &kdf))?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|error| WalletError::Vault(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret_hex.as_bytes(),
                    aad: &vault_aad(&metadata),
                },
            )
            .map_err(|error| WalletError::Vault(error.to_string()))?;
        Ok(Self {
            metadata,
            ciphertext,
            salt,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use coset::{CborSerializable, CoseKeyBuilder, iana};
    use p256::ecdsa::SigningKey;

    fn stored_credential(key_byte: u8, sign_count: u32) -> String {
        let signing_key = SigningKey::from_bytes((&[key_byte; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let cose = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .algorithm(iana::Algorithm::ES256)
        .add_key_op(iana::KeyOperation::Verify)
        .build()
        .to_vec()
        .unwrap();
        let stored = crate::webauthn::StoredCredential {
            version: 2,
            credential_id_b64: URL_SAFE_NO_PAD.encode([key_byte; 16]),
            public_key_cose_b64: URL_SAFE_NO_PAD.encode(cose),
            rp_id: "localhost".into(),
            origin: "http://localhost:1420".into(),
            sign_count,
            registered_at: "2026-01-01T00:00:00Z".into(),
        };
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&stored).unwrap())
    }

    #[test]
    fn vault_roundtrip_v3_aad() {
        let vault = EncryptedVault::encrypt("abc123", "1Test", "passphrase", "balanced").unwrap();
        assert_eq!(vault.metadata.version, 3);
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

    #[test]
    fn hostile_vault_metadata_is_bounded_before_argon2() {
        let vault = EncryptedVault::encrypt("abc123", "1Test", "passphrase", "balanced").unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&vault.export_json().unwrap()).unwrap();
        value["metadata"]["kdf"] =
            serde_json::Value::String("argon2id-m=4294967295,t=2,p=1".into());
        let raw = serde_json::to_string(&value).unwrap();
        assert!(EncryptedVault::from_export_json(&raw).is_err());
        let oversized = "x".repeat(MAX_VAULT_FILE_BYTES as usize + 1);
        assert!(EncryptedVault::from_export_json(&oversized).is_err());
    }

    #[test]
    fn v3_aad_binds_hardware_mode_and_webauthn_identity() {
        let credential = stored_credential(7, 0);
        let vault = EncryptedVault::encrypt_with_policy(
            "abc123",
            "1Test",
            "passphrase",
            "balanced",
            "software",
            Some(&credential),
            None,
        )
        .unwrap();

        let mut hardware_tamper = vault.clone();
        hardware_tamper.metadata.hardware_signing_mode = "webauthn_gate".into();
        assert!(hardware_tamper.decrypt("passphrase").is_err());

        let attacker = stored_credential(9, 0);
        let mut credential_tamper: serde_json::Value =
            serde_json::from_str(&vault.export_json().unwrap()).unwrap();
        credential_tamper["metadata"]["webauthn_credential_b64"] = attacker.clone().into();
        assert!(
            EncryptedVault::from_export_json(&credential_tamper.to_string()).is_err(),
            "credential replacement must disagree with its authenticated binding"
        );

        credential_tamper["metadata"]["webauthn_credential_binding_sha256"] =
            crate::webauthn::credential_binding_sha256(&attacker)
                .unwrap()
                .into();
        let tampered = EncryptedVault::from_export_json(&credential_tamper.to_string()).unwrap();
        assert!(
            tampered.decrypt("passphrase").is_err(),
            "replacing both public metadata fields must still fail AAD authentication"
        );
    }

    #[test]
    fn counter_update_requires_same_immutable_webauthn_binding() {
        let credential = stored_credential(7, 0);
        let mut vault = EncryptedVault::encrypt_with_policy(
            "abc123",
            "1Test",
            "passphrase",
            "balanced",
            "software",
            Some(&credential),
            None,
        )
        .unwrap();
        let binding = vault.metadata.webauthn_credential_binding_sha256.clone();
        let advanced = stored_credential(7, 1);
        vault.update_webauthn_counter_credential(&advanced).unwrap();
        assert_eq!(vault.metadata.webauthn_credential_binding_sha256, binding);
        assert_eq!(vault.decrypt("passphrase").unwrap(), "abc123");

        let attacker = stored_credential(9, 2);
        assert!(vault.update_webauthn_counter_credential(&attacker).is_err());
        assert_eq!(
            vault.metadata.webauthn_credential_b64.as_deref(),
            Some(advanced.as_str())
        );
    }

    #[test]
    fn legacy_v2_vault_still_decrypts_before_authenticated_migration() {
        let vault = EncryptedVault::encrypt_legacy_v2_for_test(
            "abc123",
            "1Test",
            "passphrase",
            "balanced",
            Some("legacy-untrusted-credential"),
        )
        .unwrap();
        let loaded = EncryptedVault::from_export_json(&vault.export_json().unwrap()).unwrap();
        assert_eq!(loaded.metadata.version, 2);
        assert_eq!(loaded.decrypt("passphrase").unwrap(), "abc123");
        assert_eq!(
            loaded.policy_for_migration().unwrap(),
            ("webauthn_gate".into(), None)
        );
    }

    #[test]
    fn interrupted_multi_file_commit_rolls_forward_before_wallet_load() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.json");
        let quantum_path = directory.path().join("quantum.keystore.enc");
        let settings_path = directory.path().join("settings.json");

        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let address = account.address();
        let old_vault =
            EncryptedVault::encrypt(&secret, &address, "old-passphrase", "balanced").unwrap();
        let new_vault =
            EncryptedVault::encrypt(&secret, &address, "new-passphrase", "balanced").unwrap();
        old_vault.save(&vault_path).unwrap();
        secure_write(&quantum_path, b"old-quantum").unwrap();
        secure_write(&settings_path, b"old-settings").unwrap();

        let new_vault_bytes = new_vault.to_json_bytes(false).unwrap();
        assert!(prepare_target(&vault_path, &new_vault_bytes, MAX_VAULT_FILE_BYTES).unwrap());
        assert!(prepare_target(&quantum_path, b"new-quantum", MAX_QUANTUM_FILE_BYTES).unwrap());
        assert!(prepare_target(&settings_path, b"new-settings", MAX_SETTINGS_FILE_BYTES).unwrap());

        let journal_path = migration_journal_path(&vault_path).unwrap();
        write_migration_journal(
            &journal_path,
            &MigrationJournal {
                version: MIGRATION_VERSION,
                phase: MigrationPhase::Commit,
                quantum_included: true,
                quantum_existed: true,
                settings_included: true,
                settings_existed: true,
            },
        )
        .unwrap();

        // Model a crash after only the first write. Startup must finish the same commit.
        apply_target(
            &vault_path,
            MigrationPhase::Commit,
            true,
            MAX_VAULT_FILE_BYTES,
        )
        .unwrap();
        assert_eq!(fs::read(&quantum_path).unwrap(), b"old-quantum");

        recover_wallet_migration(&vault_path, &quantum_path, &settings_path).unwrap();
        let loaded = EncryptedVault::load(&vault_path).unwrap();
        assert_eq!(
            loaded.decrypt_verified_secret("new-passphrase").unwrap(),
            secret.as_str()
        );
        assert!(loaded.decrypt("old-passphrase").is_err());
        assert_eq!(fs::read(&quantum_path).unwrap(), b"new-quantum");
        assert_eq!(fs::read(&settings_path).unwrap(), b"new-settings");
        assert!(!journal_path.exists());
    }
}
