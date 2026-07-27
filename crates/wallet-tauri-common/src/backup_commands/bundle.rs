use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hacash_wallet_core::WalletService;
use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::messenger_crypto::{decrypt_store, storage_key_from_secret};
use hacash_wallet_core::paths::{self, secure_write};
use hacash_wallet_core::settings::WalletSettings;
use hacash_wallet_core::vault::{EncryptedVault, VAULT_VERSION_LATEST};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const BACKUP_MAGIC: &str = "HACASH_WALLET_BACKUP";
const BACKUP_VERSION: u16 = 1;
const PAYLOAD_SCHEMA: &str = "hacash-full-wallet-state-v1";
const CIPHER_NAME: &str = "AES-256-GCM";
const KDF_NAME: &str = "Argon2id";
const KDF_VERSION: u32 = 19;
#[cfg(not(test))]
const KDF_MEMORY_KIB: u32 = 128 * 1024;
#[cfg(test)]
const KDF_MEMORY_KIB: u32 = 19 * 1024;
#[cfg(not(test))]
const KDF_ITERATIONS: u32 = 4;
#[cfg(test)]
const KDF_ITERATIONS: u32 = 1;
const KDF_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const MAX_PASSPHRASE_CHARS: usize = 1024;
const MIN_LEGACY_PASSPHRASE_CHARS: usize = 8;
pub(crate) const MAX_BACKUP_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BACKUP_PAYLOAD_BYTES: usize = 48 * 1024 * 1024;
const MAX_RESTORE_JOURNAL_BYTES: usize = 64 * 1024;
const RESTORE_JOURNAL_NAME: &str = ".wallet-restore.json";
const RESTORE_JOURNAL_MAGIC: &str = "HACASH_WALLET_RESTORE";
const RESTORE_JOURNAL_VERSION: u8 = 1;

const ROLE_REQUIRED_SECRET: &str = "required_secret";
const ROLE_REQUIRED_RECOVERY: &str = "required_recovery_state";
const ROLE_PRIVATE_USER_STATE: &str = "private_user_state";

type BackupResult<T> = Result<T, BackupError>;

#[derive(Debug, Clone)]
pub(crate) struct BackupError(String);

impl BackupError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn io(context: &str, error: io::Error) -> Self {
        Self(format!("{context}: {error}"))
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BackupError {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BackupPreview {
    pub address: String,
    pub format: String,
    pub version: u16,
    pub encrypted: bool,
    pub address_verified: bool,
    pub requires_legacy_confirmation: bool,
    pub included: Vec<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEnvelope {
    header: BackupHeader,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupHeader {
    magic: String,
    version: u16,
    payload_schema: String,
    wallet_address: String,
    created_at_unix: u64,
    kdf: BackupKdf,
    cipher: String,
    nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupKdf {
    name: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    schema: String,
    manifest: BackupManifest,
    files: BackupFiles,
}

impl Drop for BackupPayload {
    fn drop(&mut self) {
        self.files.classic_vault_b64.zeroize();
        self.files.settings_b64.zeroize();
        if let Some(value) = self.files.quantum_keystore_b64.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.files.l2_bills_b64.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.files.messenger_b64.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    wallet_address: String,
    created_at_unix: u64,
    files: BackupFileManifest,
    exclusions: Vec<BackupExclusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFileManifest {
    classic_vault: BackupFileDescriptor,
    settings: BackupFileDescriptor,
    quantum_keystore: Option<BackupFileDescriptor>,
    l2_bills: Option<BackupFileDescriptor>,
    messenger: Option<BackupFileDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFileDescriptor {
    role: String,
    byte_len: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupExclusion {
    id: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFiles {
    classic_vault_b64: String,
    settings_b64: String,
    quantum_keystore_b64: Option<String>,
    l2_bills_b64: Option<String>,
    messenger_b64: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StateFile {
    Vault,
    Settings,
    Quantum,
    Bills,
    History,
    Messenger,
    LegacyBiometric,
}

impl StateFile {
    const ALL: [Self; 7] = [
        Self::Vault,
        Self::Settings,
        Self::Quantum,
        Self::Bills,
        Self::History,
        Self::Messenger,
        Self::LegacyBiometric,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::Vault => "classic_vault",
            Self::Settings => "settings",
            Self::Quantum => "quantum_keystore",
            Self::Bills => "l2_bills",
            Self::History => "transaction_history",
            Self::Messenger => "messenger",
            Self::LegacyBiometric => "legacy_biometric_unlock",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Vault => "vault.json",
            Self::Settings => "settings.json",
            Self::Quantum => "quantum.keystore.enc",
            Self::Bills => "l2_bills.json",
            Self::History => "tx_history.json",
            Self::Messenger => "messenger.json",
            Self::LegacyBiometric => "biometric_unlock.enc",
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::Vault => 128 * 1024,
            Self::Settings => 1024 * 1024,
            Self::Quantum => 9 * 1024 * 1024,
            Self::Bills => 8 * 1024 * 1024,
            Self::History => 4 * 1024 * 1024,
            Self::Messenger => 8 * 1024 * 1024,
            Self::LegacyBiometric => 1024 * 1024,
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|entry| entry.id() == id)
    }
}

struct RestorePlan {
    desired: BTreeMap<StateFile, Option<Vec<u8>>>,
    address: String,
}

impl Drop for RestorePlan {
    fn drop(&mut self) {
        for bytes in self.desired.values_mut().flatten() {
            bytes.zeroize();
        }
    }
}

struct OriginalState(BTreeMap<StateFile, Option<Vec<u8>>>);

impl Drop for OriginalState {
    fn drop(&mut self) {
        for bytes in self.0.values_mut().flatten() {
            bytes.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    magic: String,
    version: u8,
    transaction_id: String,
    phase: RestorePhase,
    originals: Vec<JournalOriginal>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    Preparing,
    Prepared,
    Applying,
    RollingBack,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalOriginal {
    id: String,
    present: bool,
    byte_len: u64,
    sha256: Option<String>,
}

trait RestoreHooks {
    fn before_apply(&mut self, _index: usize, _file: StateFile) -> BackupResult<()> {
        Ok(())
    }

    fn before_rollback(&mut self, _index: usize, _file: StateFile) -> BackupResult<()> {
        Ok(())
    }
}

struct NoopRestoreHooks;
impl RestoreHooks for NoopRestoreHooks {}

pub(crate) fn export_bundle(service: &mut WalletService, passphrase: &str) -> BackupResult<String> {
    validate_passphrase_shape(passphrase)?;
    service
        .verify_wallet_passphrase(passphrase)
        .map_err(|error| BackupError::new(error.to_string()))?;

    let root = paths::wallet_data_root();
    validate_wallet_root(&root)?;
    recover_at_root(&root, &mut NoopRestoreHooks)?;

    let vault_bytes = read_required_state(&root, StateFile::Vault)?;
    let vault_json = std::str::from_utf8(&vault_bytes)
        .map_err(|_| BackupError::new("active vault is not valid UTF-8 JSON"))?;
    let vault = EncryptedVault::from_export_json(vault_json)
        .map_err(|error| BackupError::new(error.to_string()))?;
    if vault.metadata.version != VAULT_VERSION_LATEST {
        return Err(BackupError::new(
            "unlock the wallet once to migrate its legacy vault before creating a full backup",
        ));
    }
    let mut verified_secret = Zeroizing::new(
        vault
            .decrypt_verified_secret(passphrase)
            .map_err(|error| BackupError::new(error.to_string()))?,
    );
    let snapshot = vault.meta_snapshot();

    let mut settings = service.get_settings();
    if settings.quantum_keystore_json.is_some() {
        return Err(BackupError::new(
            "legacy plaintext Quantum state must be migrated by unlocking the wallet before backup",
        ));
    }
    canonicalize_restored_settings(&mut settings, &snapshot)?;
    let settings_bytes = serde_json::to_vec(&settings)
        .map_err(|error| BackupError::new(format!("serialize backup settings: {error}")))?;

    let quantum = read_optional_state(&root, StateFile::Quantum)?;
    if quantum.is_none() && (settings.quantum_mode || settings.quantum_meta.is_some()) {
        return Err(BackupError::new(
            "Quantum metadata exists but the encrypted Quantum keystore is missing",
        ));
    }
    if let Some(bytes) = quantum.as_deref() {
        validate_quantum_wrapper(bytes)?;
        let key =
            hacash_wallet_core::quantum_vault::QuantumFileKey::derive(passphrase, vault.salt())
                .map_err(|error| BackupError::new(error.to_string()))?;
        let decrypted = hacash_wallet_core::quantum_vault::load_encrypted(&key)
            .map_err(|error| BackupError::new(error.to_string()))?;
        if decrypted.is_none() {
            return Err(BackupError::new(
                "Quantum keystore disappeared during backup",
            ));
        }
        drop(decrypted.map(Zeroizing::new));
    }

    let bills = read_optional_state(&root, StateFile::Bills)?;
    if let Some(bytes) = bills.as_deref() {
        validate_bills(bytes)?;
    }
    let status = service.status();
    let persisted_bill_count = bills
        .as_deref()
        .map(parse_bill_count)
        .transpose()?
        .unwrap_or(0);
    if persisted_bill_count != status.l2_bill_count {
        return Err(BackupError::new(
            "L2 bill state changed during backup; retry after wallet activity stops",
        ));
    }

    let messenger = read_optional_state(&root, StateFile::Messenger)?;
    if let Some(bytes) = messenger.as_deref() {
        validate_messenger(bytes, &verified_secret)?;
    }
    verified_secret.zeroize();

    let created_at_unix = unix_now()?;
    let files = BackupFiles {
        classic_vault_b64: encode_file(&vault_bytes),
        settings_b64: encode_file(&settings_bytes),
        quantum_keystore_b64: quantum.as_deref().map(encode_file),
        l2_bills_b64: bills.as_deref().map(encode_file),
        messenger_b64: messenger.as_deref().map(encode_file),
    };
    let manifest = BackupManifest {
        wallet_address: snapshot.address.clone(),
        created_at_unix,
        files: BackupFileManifest {
            classic_vault: describe_file(&vault_bytes, ROLE_REQUIRED_SECRET),
            settings: describe_file(&settings_bytes, ROLE_REQUIRED_RECOVERY),
            quantum_keystore: quantum
                .as_deref()
                .map(|bytes| describe_file(bytes, ROLE_REQUIRED_SECRET)),
            l2_bills: bills
                .as_deref()
                .map(|bytes| describe_file(bytes, ROLE_REQUIRED_RECOVERY)),
            messenger: messenger
                .as_deref()
                .map(|bytes| describe_file(bytes, ROLE_PRIVATE_USER_STATE)),
        },
        exclusions: expected_exclusions(),
    };
    let payload = BackupPayload {
        schema: PAYLOAD_SCHEMA.into(),
        manifest,
        files,
    };
    encrypt_payload(&payload, passphrase, &snapshot.address, created_at_unix)
}

pub(crate) fn preview(raw: &str) -> BackupResult<BackupPreview> {
    let trimmed = raw.trim();
    ensure_envelope_size(trimmed.len())?;
    if looks_like_full_bundle(trimmed) {
        let envelope: BackupEnvelope = serde_json::from_str(trimmed)
            .map_err(|error| BackupError::new(format!("invalid full backup JSON: {error}")))?;
        validate_header(&envelope.header)?;
        validate_b64_size(
            &envelope.ciphertext_b64,
            MAX_BACKUP_PAYLOAD_BYTES + TAG_BYTES,
            "backup ciphertext",
        )?;
        return Ok(BackupPreview {
            address: envelope.header.wallet_address,
            format: "full_authenticated".into(),
            version: envelope.header.version,
            encrypted: true,
            address_verified: false,
            requires_legacy_confirmation: false,
            included: vec![
                "Classic signing vault".into(),
                "Security and network settings".into(),
                "Quantum keystore when configured".into(),
                "L2 dispute bills when present".into(),
                "Encrypted messenger history when present".into(),
            ],
            warning: Some(
                "The displayed address is verified only after the backup passphrase authenticates the bundle. Device-bound biometric unlock, external WebAuthn authenticator private keys, and local transaction display history are not transferred. \
                 Restoring also rolls security policy back to whatever it was when the backup was taken: if Cold Vault was activated or a WebAuthn authenticator was replaced afterwards, this restore undoes that and re-enables the older state, including the older signature counter. Restore an old backup only if you intend that."
                    .into(),
            ),
        });
    }

    let address = EncryptedVault::backup_address_from_json(trimmed)
        .map_err(|error| BackupError::new(error.to_string()))?;
    Ok(BackupPreview {
        address,
        format: "legacy_classic_only".into(),
        version: 0,
        encrypted: true,
        address_verified: false,
        requires_legacy_confirmation: true,
        included: vec!["Classic signing vault only".into()],
        warning: Some(
            "Legacy backup: restores only the classic signing key. It does not contain the Quantum keystore, L2 dispute bills, settings, biometric configuration, messenger data, or transaction history. It also carries no security policy, so the restored wallet is an ordinary online software wallet even if this key was later moved into Cold Vault or put behind a WebAuthn gate. Continue only if you accept those losses."
                .into(),
        ),
    })
}

pub(crate) fn restore(
    service: &mut WalletService,
    raw: &str,
    passphrase: &str,
    allow_legacy: bool,
) -> BackupResult<String> {
    validate_passphrase_shape(passphrase)?;
    if service.status().has_wallet {
        return Err(BackupError::new(
            "a wallet already exists; restore is allowed only into an empty wallet profile",
        ));
    }
    let trimmed = raw.trim();
    ensure_envelope_size(trimmed.len())?;

    let plan = if looks_like_full_bundle(trimmed) {
        let payload = decrypt_payload(trimmed, passphrase)?;
        plan_from_full_payload(&payload, passphrase)?
    } else {
        if !allow_legacy {
            return Err(BackupError::new(
                "legacy classic-key-only backup requires explicit loss acknowledgement",
            ));
        }
        plan_from_legacy(trimmed, passphrase)?
    };
    let address = plan.address.clone();
    let root = paths::wallet_data_root();
    validate_wallet_root(&root)?;
    recover_at_root(&root, &mut NoopRestoreHooks)?;

    let node_override = std::env::var("HACASH_WALLET_NODE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut hooks = NoopRestoreHooks;
    let candidate = transactional_apply_at(&root, &plan, &mut hooks, || {
        let mut candidate = WalletService::new(node_override.clone(), None)
            .map_err(|error| BackupError::new(format!("restored wallet reload failed: {error}")))?;
        let restored_address = candidate
            .unlock(passphrase)
            .map_err(|error| BackupError::new(format!("restored wallet unlock failed: {error}")))?;
        if restored_address != address {
            return Err(BackupError::new(
                "restored wallet address does not match the authenticated backup",
            ));
        }
        Ok(candidate)
    })?;
    *service = candidate;
    Ok(address)
}

pub(crate) fn recover_interrupted_restore() -> BackupResult<()> {
    let root = paths::wallet_data_root();
    if !root.exists() {
        return Ok(());
    }
    validate_wallet_root(&root)?;
    recover_at_root(&root, &mut NoopRestoreHooks)
}

fn plan_from_full_payload(payload: &BackupPayload, passphrase: &str) -> BackupResult<RestorePlan> {
    validate_payload_manifest(payload)?;
    let vault_bytes = decode_manifest_file(
        &payload.files.classic_vault_b64,
        &payload.manifest.files.classic_vault,
        StateFile::Vault,
        ROLE_REQUIRED_SECRET,
    )?;
    let settings_bytes = decode_manifest_file(
        &payload.files.settings_b64,
        &payload.manifest.files.settings,
        StateFile::Settings,
        ROLE_REQUIRED_RECOVERY,
    )?;
    let quantum = decode_optional_manifest_file(
        payload.files.quantum_keystore_b64.as_deref(),
        payload.manifest.files.quantum_keystore.as_ref(),
        StateFile::Quantum,
        ROLE_REQUIRED_SECRET,
    )?;
    let bills = decode_optional_manifest_file(
        payload.files.l2_bills_b64.as_deref(),
        payload.manifest.files.l2_bills.as_ref(),
        StateFile::Bills,
        ROLE_REQUIRED_RECOVERY,
    )?;
    let messenger = decode_optional_manifest_file(
        payload.files.messenger_b64.as_deref(),
        payload.manifest.files.messenger.as_ref(),
        StateFile::Messenger,
        ROLE_PRIVATE_USER_STATE,
    )?;

    let vault_json = std::str::from_utf8(&vault_bytes)
        .map_err(|_| BackupError::new("backup vault is not valid UTF-8 JSON"))?;
    let vault = EncryptedVault::from_export_json(vault_json)
        .map_err(|error| BackupError::new(error.to_string()))?;
    if vault.metadata.version != VAULT_VERSION_LATEST {
        return Err(BackupError::new(
            "full backup contains a legacy vault; import it through the quarantined legacy flow",
        ));
    }
    let secret = Zeroizing::new(
        vault
            .decrypt_verified_secret(passphrase)
            .map_err(|_| BackupError::new("backup authentication failed"))?,
    );
    let snapshot = vault.meta_snapshot();
    if snapshot.address != payload.manifest.wallet_address {
        return Err(BackupError::new(
            "backup manifest address does not match the signing vault",
        ));
    }

    let mut settings: WalletSettings = serde_json::from_slice(&settings_bytes)
        .map_err(|error| BackupError::new(format!("invalid backup settings: {error}")))?;
    if settings.quantum_keystore_json.is_some() {
        return Err(BackupError::new(
            "full backup contains forbidden plaintext Quantum state",
        ));
    }
    canonicalize_restored_settings(&mut settings, &snapshot)?;
    if quantum.is_none() && (settings.quantum_mode || settings.quantum_meta.is_some()) {
        return Err(BackupError::new(
            "backup Quantum metadata has no encrypted Quantum keystore",
        ));
    }
    if let Some(bytes) = quantum.as_deref() {
        validate_quantum_wrapper(bytes)?;
    }
    if let Some(bytes) = bills.as_deref() {
        validate_bills(bytes)?;
    }
    if let Some(bytes) = messenger.as_deref() {
        validate_messenger(bytes, &secret)?;
    }

    let canonical_settings = serde_json::to_vec(&settings)
        .map_err(|error| BackupError::new(format!("serialize restored settings: {error}")))?;
    let mut desired = BTreeMap::new();
    desired.insert(StateFile::Vault, Some(vault_bytes));
    desired.insert(StateFile::Settings, Some(canonical_settings));
    desired.insert(StateFile::Quantum, quantum);
    desired.insert(StateFile::Bills, bills);
    desired.insert(StateFile::History, None);
    desired.insert(StateFile::Messenger, messenger);
    desired.insert(StateFile::LegacyBiometric, None);
    Ok(RestorePlan {
        desired,
        address: snapshot.address,
    })
}

fn plan_from_legacy(raw: &str, passphrase: &str) -> BackupResult<RestorePlan> {
    if raw.len() > StateFile::Vault.max_bytes() {
        return Err(BackupError::new(
            "legacy backup exceeds the safe size limit",
        ));
    }
    let vault = EncryptedVault::from_export_json(raw)
        .map_err(|error| BackupError::new(error.to_string()))?;
    let secret = vault
        .decrypt_verified_secret(passphrase)
        .map_err(|_| BackupError::new("legacy backup passphrase is incorrect"))?;
    drop(Zeroizing::new(secret));
    let address = vault.meta_snapshot().address;
    let settings = serde_json::to_vec(&WalletSettings::default())
        .map_err(|error| BackupError::new(format!("serialize legacy restore settings: {error}")))?;
    let mut desired = BTreeMap::new();
    desired.insert(StateFile::Vault, Some(raw.as_bytes().to_vec()));
    desired.insert(StateFile::Settings, Some(settings));
    desired.insert(StateFile::Quantum, None);
    desired.insert(StateFile::Bills, None);
    desired.insert(StateFile::History, None);
    desired.insert(StateFile::Messenger, None);
    desired.insert(StateFile::LegacyBiometric, None);
    Ok(RestorePlan { desired, address })
}

fn canonicalize_restored_settings(
    settings: &mut WalletSettings,
    snapshot: &hacash_wallet_core::vault::VaultMetaSnapshot,
) -> BackupResult<()> {
    settings.security_profile = snapshot.security_profile.clone();
    settings.hardware_signing_mode = snapshot.hardware_signing_mode.clone();
    settings.webauthn_enabled = snapshot.webauthn_credential_b64.is_some();
    settings.watch_only_address = None;
    settings.biometric_unlock_enabled = false;
    settings.quantum_keystore_json = None;
    settings
        .validate_and_normalize()
        .map_err(|error| BackupError::new(format!("invalid backup settings: {error}")))
}

fn encrypt_payload(
    payload: &BackupPayload,
    passphrase: &str,
    address: &str,
    created_at_unix: u64,
) -> BackupResult<String> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload)
            .map_err(|error| BackupError::new(format!("serialize backup payload: {error}")))?,
    );
    if plaintext.len() > MAX_BACKUP_PAYLOAD_BYTES {
        return Err(BackupError::new(
            "backup payload exceeds the safe size limit",
        ));
    }
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let header = BackupHeader {
        magic: BACKUP_MAGIC.into(),
        version: BACKUP_VERSION,
        payload_schema: PAYLOAD_SCHEMA.into(),
        wallet_address: address.into(),
        created_at_unix,
        kdf: BackupKdf {
            name: KDF_NAME.into(),
            version: KDF_VERSION,
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt_b64: BASE64.encode(salt),
        },
        cipher: CIPHER_NAME.into(),
        nonce_b64: BASE64.encode(nonce),
    };
    let aad = header_aad(&header)?;
    let key = derive_backup_key(passphrase, &salt, &header.kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| BackupError::new("backup cipher initialization failed"))?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BackupError::new("backup encryption failed"))?,
    );
    let envelope = BackupEnvelope {
        header,
        ciphertext_b64: BASE64.encode(&*ciphertext),
    };
    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|error| BackupError::new(format!("serialize backup envelope: {error}")))?;
    ensure_envelope_size(json.len())?;
    Ok(json)
}

fn decrypt_payload(raw: &str, passphrase: &str) -> BackupResult<BackupPayload> {
    ensure_envelope_size(raw.len())?;
    let envelope: BackupEnvelope = serde_json::from_str(raw)
        .map_err(|error| BackupError::new(format!("invalid full backup JSON: {error}")))?;
    validate_header(&envelope.header)?;
    let salt = decode_fixed::<SALT_BYTES>(&envelope.header.kdf.salt_b64, "backup salt")?;
    let nonce = decode_fixed::<NONCE_BYTES>(&envelope.header.nonce_b64, "backup nonce")?;
    let ciphertext = Zeroizing::new(decode_b64_limited(
        &envelope.ciphertext_b64,
        MAX_BACKUP_PAYLOAD_BYTES + TAG_BYTES,
        "backup ciphertext",
    )?);
    if ciphertext.len() < TAG_BYTES {
        return Err(BackupError::new("backup ciphertext is truncated"));
    }
    let aad = header_aad(&envelope.header)?;
    let key = derive_backup_key(passphrase, &salt, &envelope.header.kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| BackupError::new("backup cipher initialization failed"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                BackupError::new("backup authentication failed (wrong passphrase or modified file)")
            })?,
    );
    if plaintext.len() > MAX_BACKUP_PAYLOAD_BYTES {
        return Err(BackupError::new(
            "backup payload exceeds the safe size limit",
        ));
    }
    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|error| BackupError::new(format!("invalid authenticated payload: {error}")))?;
    validate_payload_manifest_against_header(&payload, &envelope.header)?;
    Ok(payload)
}

fn validate_header(header: &BackupHeader) -> BackupResult<()> {
    if header.magic != BACKUP_MAGIC
        || header.version != BACKUP_VERSION
        || header.payload_schema != PAYLOAD_SCHEMA
        || header.cipher != CIPHER_NAME
    {
        return Err(BackupError::new("unsupported backup format or cipher"));
    }
    validate_address_text(&header.wallet_address)?;
    if header.created_at_unix == 0 {
        return Err(BackupError::new("backup creation timestamp is invalid"));
    }
    if header.kdf.name != KDF_NAME
        || header.kdf.version != KDF_VERSION
        || header.kdf.memory_kib != KDF_MEMORY_KIB
        || header.kdf.iterations != KDF_ITERATIONS
        || header.kdf.parallelism != KDF_PARALLELISM
    {
        return Err(BackupError::new(
            "unsupported or unsafe backup KDF parameters",
        ));
    }
    decode_fixed::<SALT_BYTES>(&header.kdf.salt_b64, "backup salt")?;
    decode_fixed::<NONCE_BYTES>(&header.nonce_b64, "backup nonce")?;
    Ok(())
}

fn validate_payload_manifest_against_header(
    payload: &BackupPayload,
    header: &BackupHeader,
) -> BackupResult<()> {
    if payload.schema != PAYLOAD_SCHEMA
        || payload.manifest.wallet_address != header.wallet_address
        || payload.manifest.created_at_unix != header.created_at_unix
    {
        return Err(BackupError::new(
            "authenticated backup header and manifest do not match",
        ));
    }
    validate_payload_manifest(payload)
}

fn validate_payload_manifest(payload: &BackupPayload) -> BackupResult<()> {
    if payload.schema != PAYLOAD_SCHEMA {
        return Err(BackupError::new("unsupported backup payload schema"));
    }
    validate_address_text(&payload.manifest.wallet_address)?;
    let exclusions: BTreeSet<String> = payload
        .manifest
        .exclusions
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    let expected: BTreeSet<String> = expected_exclusions()
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    if exclusions != expected || exclusions.len() != payload.manifest.exclusions.len() {
        return Err(BackupError::new(
            "backup manifest does not declare the required exclusions",
        ));
    }
    for exclusion in &payload.manifest.exclusions {
        if exclusion.reason.trim().is_empty() || exclusion.reason.len() > 512 {
            return Err(BackupError::new("backup exclusion reason is invalid"));
        }
    }
    Ok(())
}

fn expected_exclusions() -> Vec<BackupExclusion> {
    vec![
        BackupExclusion {
            id: "device_bound_biometric_unlock".into(),
            reason: "OS-keystore biometric unlock material is device-bound and must be enrolled again on the restored device.".into(),
        },
        BackupExclusion {
            id: "webauthn_authenticator_private_key".into(),
            reason: "The wallet stores only public WebAuthn credential data; the authenticator private key remains external and must still be available after restore.".into(),
        },
        BackupExclusion {
            id: "transaction_display_history".into(),
            reason: "Non-authoritative local display history is not required to recover keys, assets, or L2 dispute proofs.".into(),
        },
        BackupExclusion {
            id: "runtime_and_network_caches".into(),
            reason: "Balances, metadata, discovery results, and runtime sessions are reconstructed from authenticated wallet state and the network.".into(),
        },
    ]
}

fn describe_file(bytes: &[u8], role: &str) -> BackupFileDescriptor {
    BackupFileDescriptor {
        role: role.into(),
        byte_len: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn decode_manifest_file(
    encoded: &str,
    descriptor: &BackupFileDescriptor,
    file: StateFile,
    expected_role: &str,
) -> BackupResult<Vec<u8>> {
    validate_descriptor(descriptor, file, expected_role)?;
    let bytes = decode_b64_limited(encoded, file.max_bytes(), file.id())?;
    verify_descriptor(&bytes, descriptor, file.id())?;
    Ok(bytes)
}

fn decode_optional_manifest_file(
    encoded: Option<&str>,
    descriptor: Option<&BackupFileDescriptor>,
    file: StateFile,
    expected_role: &str,
) -> BackupResult<Option<Vec<u8>>> {
    match (encoded, descriptor) {
        (None, None) => Ok(None),
        (Some(encoded), Some(descriptor)) => {
            decode_manifest_file(encoded, descriptor, file, expected_role).map(Some)
        }
        _ => Err(BackupError::new(format!(
            "backup {} data and manifest presence do not match",
            file.id()
        ))),
    }
}

fn validate_descriptor(
    descriptor: &BackupFileDescriptor,
    file: StateFile,
    expected_role: &str,
) -> BackupResult<()> {
    if descriptor.role != expected_role {
        return Err(BackupError::new(format!(
            "backup {} has an invalid recovery role",
            file.id()
        )));
    }
    if descriptor.byte_len == 0 || descriptor.byte_len > file.max_bytes() as u64 {
        return Err(BackupError::new(format!(
            "backup {} size is outside safe limits",
            file.id()
        )));
    }
    validate_sha256_text(&descriptor.sha256)
}

fn verify_descriptor(
    bytes: &[u8],
    descriptor: &BackupFileDescriptor,
    label: &str,
) -> BackupResult<()> {
    if descriptor.byte_len != bytes.len() as u64 || descriptor.sha256 != sha256_hex(bytes) {
        return Err(BackupError::new(format!(
            "backup {label} failed its authenticated manifest digest"
        )));
    }
    Ok(())
}

fn validate_bills(bytes: &[u8]) -> BackupResult<()> {
    parse_bill_count(bytes).map(|_| ())
}

fn parse_bill_count(bytes: &[u8]) -> BackupResult<usize> {
    let store: BillStore = serde_json::from_slice(bytes)
        .map_err(|error| BackupError::new(format!("invalid L2 dispute bill state: {error}")))?;
    Ok(store.count())
}

fn validate_quantum_wrapper(bytes: &[u8]) -> BackupResult<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct QuantumWrapper {
        nonce: String,
        ciphertext: String,
    }
    let wrapper: QuantumWrapper = serde_json::from_slice(bytes)
        .map_err(|error| BackupError::new(format!("invalid Quantum keystore wrapper: {error}")))?;
    if wrapper.nonce.len() != NONCE_BYTES * 2
        || !wrapper.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        || wrapper.ciphertext.len() < TAG_BYTES * 2
        || !wrapper.ciphertext.len().is_multiple_of(2)
        || !wrapper
            .ciphertext
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(BackupError::new("Quantum keystore wrapper is malformed"));
    }
    Ok(())
}

fn validate_messenger(bytes: &[u8], secret_hex: &str) -> BackupResult<()> {
    let secret = Zeroizing::new(
        hex::decode(secret_hex)
            .map_err(|_| BackupError::new("wallet secret cannot validate messenger state"))?,
    );
    let secret_array: &[u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::new("wallet secret length is invalid"))?;
    let storage_key = Zeroizing::new(storage_key_from_secret(secret_array));
    let plaintext = Zeroizing::new(
        decrypt_store(bytes, &storage_key)
            .map_err(|_| BackupError::new("encrypted messenger state failed authentication"))?,
    );
    let value: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|error| BackupError::new(format!("invalid messenger state: {error}")))?;
    if !value
        .as_object()
        .and_then(|object| object.get("messages"))
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(BackupError::new(
            "messenger state is missing its message list",
        ));
    }
    Ok(())
}

fn derive_backup_key(
    passphrase: &str,
    salt: &[u8; SALT_BYTES],
    kdf: &BackupKdf,
) -> BackupResult<Zeroizing<[u8; KEY_BYTES]>> {
    validate_passphrase_shape(passphrase)?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|_| BackupError::new("backup KDF parameters are invalid"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| BackupError::new("backup key derivation failed"))?;
    Ok(key)
}

fn header_aad(header: &BackupHeader) -> BackupResult<Vec<u8>> {
    serde_json::to_vec(header)
        .map_err(|error| BackupError::new(format!("serialize backup header: {error}")))
}

fn looks_like_full_bundle(raw: &str) -> bool {
    #[derive(Deserialize)]
    struct EnvelopeProbe {
        header: Option<HeaderProbe>,
    }
    #[derive(Deserialize)]
    struct HeaderProbe {
        magic: Option<String>,
    }
    serde_json::from_str::<EnvelopeProbe>(raw)
        .ok()
        .and_then(|probe| probe.header)
        .and_then(|header| header.magic)
        .is_some_and(|magic| magic == BACKUP_MAGIC)
}

fn validate_passphrase_shape(passphrase: &str) -> BackupResult<()> {
    let count = passphrase.chars().count();
    if !(MIN_LEGACY_PASSPHRASE_CHARS..=MAX_PASSPHRASE_CHARS).contains(&count) {
        return Err(BackupError::new(format!(
            "backup passphrase must contain {MIN_LEGACY_PASSPHRASE_CHARS} to {MAX_PASSPHRASE_CHARS} characters"
        )));
    }
    Ok(())
}

fn validate_address_text(address: &str) -> BackupResult<()> {
    if address.trim() != address || address.len() > 64 {
        return Err(BackupError::new("backup wallet address is malformed"));
    }
    let parsed = hacash_wallet_core::parse_address(address, "testnet")
        .map_err(|_| BackupError::new("backup wallet address is malformed"))?;
    if parsed.address != address {
        return Err(BackupError::new(
            "backup wallet address is not in canonical form",
        ));
    }
    Ok(())
}

fn encode_file(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

fn decode_fixed<const N: usize>(encoded: &str, label: &str) -> BackupResult<[u8; N]> {
    let bytes = decode_b64_limited(encoded, N, label)?;
    bytes
        .try_into()
        .map_err(|_| BackupError::new(format!("{label} length is invalid")))
}

fn decode_b64_limited(encoded: &str, max_decoded: usize, label: &str) -> BackupResult<Vec<u8>> {
    validate_b64_size(encoded, max_decoded, label)?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| BackupError::new(format!("{label} is not valid base64")))?;
    if bytes.len() > max_decoded {
        return Err(BackupError::new(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    Ok(bytes)
}

fn validate_b64_size(encoded: &str, max_decoded: usize, label: &str) -> BackupResult<()> {
    let max_encoded = max_decoded.div_ceil(3).saturating_mul(4).saturating_add(4);
    if encoded.is_empty() || encoded.len() > max_encoded {
        return Err(BackupError::new(format!(
            "{label} size is outside safe limits"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_sha256_text(value: &str) -> BackupResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackupError::new("backup SHA-256 digest is malformed"));
    }
    Ok(())
}

fn ensure_envelope_size(size: usize) -> BackupResult<()> {
    if size == 0 || size > MAX_BACKUP_ENVELOPE_BYTES {
        return Err(BackupError::new("backup file size is outside safe limits"));
    }
    Ok(())
}

fn unix_now() -> BackupResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| BackupError::new("system clock is before the Unix epoch"))
}

fn validate_wallet_root(root: &Path) -> BackupResult<()> {
    if !root.exists() {
        fs::create_dir_all(root).map_err(|error| BackupError::io("create wallet data", error))?;
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| BackupError::io("inspect wallet data directory", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::new(
            "wallet data path must be a real directory, not a symlink",
        ));
    }
    Ok(())
}

fn state_path(root: &Path, file: StateFile) -> PathBuf {
    root.join(file.file_name())
}

fn read_required_state(root: &Path, file: StateFile) -> BackupResult<Vec<u8>> {
    read_optional_state(root, file)?
        .ok_or_else(|| BackupError::new(format!("required wallet state {} is missing", file.id())))
}

fn read_optional_state(root: &Path, file: StateFile) -> BackupResult<Option<Vec<u8>>> {
    read_optional_file(&state_path(root, file), file.max_bytes(), file.id())
}

fn read_optional_file(path: &Path, max_bytes: usize, label: &str) -> BackupResult<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(BackupError::io(&format!("inspect {label}"), error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::new(format!(
            "{label} must be a regular file, not a symlink"
        )));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(BackupError::new(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    let file_handle =
        fs::File::open(path).map_err(|error| BackupError::io(&format!("open {label}"), error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file_handle
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BackupError::io(&format!("read {label}"), error))?;
    if bytes.len() > max_bytes {
        return Err(BackupError::new(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    Ok(Some(bytes))
}

fn transactional_apply_at<T, F, H>(
    root: &Path,
    plan: &RestorePlan,
    hooks: &mut H,
    validator: F,
) -> BackupResult<T>
where
    F: FnOnce() -> BackupResult<T>,
    H: RestoreHooks,
{
    validate_restore_plan(plan)?;
    recover_at_root(root, hooks)?;
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let tx_dir_name = format!(".restore-{transaction_id}");
    let tx_dir = root.join(&tx_dir_name);
    let journal_path = root.join(RESTORE_JOURNAL_NAME);

    let mut originals = OriginalState(BTreeMap::new());
    let mut journal_originals = Vec::new();
    for file in StateFile::ALL {
        let original = read_optional_state(root, file)?;
        journal_originals.push(JournalOriginal {
            id: file.id().into(),
            present: original.is_some(),
            byte_len: original.as_ref().map_or(0, |bytes| bytes.len() as u64),
            sha256: original.as_deref().map(sha256_hex),
        });
        originals.0.insert(file, original);
    }
    let mut journal = RestoreJournal {
        magic: RESTORE_JOURNAL_MAGIC.into(),
        version: RESTORE_JOURNAL_VERSION,
        transaction_id,
        phase: RestorePhase::Preparing,
        originals: journal_originals,
    };
    write_journal(&journal_path, &journal)?;
    if let Err(error) = fs::create_dir(&tx_dir) {
        let _ = remove_regular_file(&journal_path, "restore journal");
        return Err(BackupError::io(
            "create restore transaction directory",
            error,
        ));
    }
    for file in StateFile::ALL {
        if let Some(bytes) = originals.0.get(&file).and_then(Option::as_deref)
            && let Err(error) = secure_write(&tx_dir.join(old_file_name(file)), bytes)
        {
            let primary = BackupError::io("stage restore rollback copy", error);
            let cleanup = cleanup_transaction(root, &journal);
            return match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup_error) => Err(BackupError::new(format!(
                    "{primary}; staging cleanup also failed: {cleanup_error}"
                ))),
            };
        }
    }
    journal.phase = RestorePhase::Prepared;
    write_journal(&journal_path, &journal)?;
    journal.phase = RestorePhase::Applying;
    write_journal(&journal_path, &journal)?;

    let apply_result = (|| {
        for (index, file) in StateFile::ALL.into_iter().enumerate() {
            hooks.before_apply(index, file)?;
            match plan.desired.get(&file).and_then(Option::as_deref) {
                Some(bytes) => secure_write(&state_path(root, file), bytes)
                    .map_err(|error| BackupError::io(&format!("restore {}", file.id()), error))?,
                None => remove_regular_file(&state_path(root, file), file.id())?,
            }
        }
        validator()
    })();

    match apply_result {
        Ok(value) => {
            journal.phase = RestorePhase::Committed;
            if let Err(error) = write_journal(&journal_path, &journal) {
                let primary = BackupError::new(format!(
                    "restored state validated but its commit journal failed: {error}"
                ));
                return Err(fail_with_rollback(root, &mut journal, hooks, primary));
            }
            if let Err(error) = cleanup_transaction(root, &journal) {
                tracing::warn!("committed backup restore cleanup deferred: {error}");
            }
            Ok(value)
        }
        Err(primary) => Err(fail_with_rollback(root, &mut journal, hooks, primary)),
    }
}

fn fail_with_rollback<H: RestoreHooks>(
    root: &Path,
    journal: &mut RestoreJournal,
    hooks: &mut H,
    primary: BackupError,
) -> BackupError {
    journal.phase = RestorePhase::RollingBack;
    let journal_error = write_journal(&root.join(RESTORE_JOURNAL_NAME), journal).err();
    match rollback_from_journal(root, journal, hooks) {
        Ok(()) => match cleanup_transaction(root, journal) {
            Ok(()) => match journal_error {
                Some(error) => BackupError::new(format!(
                    "{primary}; rollback completed but its journal update failed: {error}"
                )),
                None => primary,
            },
            Err(cleanup) => BackupError::new(format!(
                "{primary}; rollback completed but cleanup failed: {cleanup}"
            )),
        },
        Err(rollback) => BackupError::new(format!(
            "{primary}; rollback failed and will be retried at startup: {rollback}"
        )),
    }
}

fn validate_restore_plan(plan: &RestorePlan) -> BackupResult<()> {
    let keys: BTreeSet<_> = plan.desired.keys().copied().collect();
    let expected: BTreeSet<_> = StateFile::ALL.into_iter().collect();
    if keys != expected {
        return Err(BackupError::new(
            "restore plan does not cover every wallet state file",
        ));
    }
    for (file, bytes) in &plan.desired {
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() > file.max_bytes())
        {
            return Err(BackupError::new(format!(
                "restore {} exceeds the safe size limit",
                file.id()
            )));
        }
    }
    validate_address_text(&plan.address)
}

fn recover_at_root<H: RestoreHooks>(root: &Path, hooks: &mut H) -> BackupResult<()> {
    let journal_path = root.join(RESTORE_JOURNAL_NAME);
    let Some(raw) =
        read_optional_file(&journal_path, MAX_RESTORE_JOURNAL_BYTES, "restore journal")?
    else {
        return Ok(());
    };
    let mut journal: RestoreJournal = serde_json::from_slice(&raw)
        .map_err(|error| BackupError::new(format!("invalid restore journal: {error}")))?;
    validate_journal(&journal)?;
    match journal.phase {
        RestorePhase::Preparing | RestorePhase::Committed => cleanup_transaction(root, &journal),
        RestorePhase::Prepared | RestorePhase::Applying | RestorePhase::RollingBack => {
            if journal.phase != RestorePhase::RollingBack {
                journal.phase = RestorePhase::RollingBack;
                write_journal(&journal_path, &journal)?;
            }
            rollback_from_journal(root, &journal, hooks)?;
            cleanup_transaction(root, &journal)
        }
    }
}

fn validate_journal(journal: &RestoreJournal) -> BackupResult<()> {
    if journal.magic != RESTORE_JOURNAL_MAGIC || journal.version != RESTORE_JOURNAL_VERSION {
        return Err(BackupError::new("unsupported restore journal"));
    }
    if journal.transaction_id.len() != 32
        || !journal
            .transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(BackupError::new(
            "restore journal transaction ID is malformed",
        ));
    }
    if journal.originals.len() != StateFile::ALL.len() {
        return Err(BackupError::new(
            "restore journal file inventory is incomplete",
        ));
    }
    let mut ids = BTreeSet::new();
    for original in &journal.originals {
        let file = StateFile::from_id(&original.id)
            .ok_or_else(|| BackupError::new("restore journal contains an unknown file ID"))?;
        if !ids.insert(original.id.as_str()) {
            return Err(BackupError::new(
                "restore journal contains duplicate file IDs",
            ));
        }
        if original.present {
            if original.byte_len == 0 || original.byte_len > file.max_bytes() as u64 {
                return Err(BackupError::new("restore journal original size is invalid"));
            }
            validate_sha256_text(
                original
                    .sha256
                    .as_deref()
                    .ok_or_else(|| BackupError::new("restore journal digest is missing"))?,
            )?;
        } else if original.byte_len != 0 || original.sha256.is_some() {
            return Err(BackupError::new(
                "restore journal absent-file metadata is invalid",
            ));
        }
    }
    Ok(())
}

fn rollback_from_journal<H: RestoreHooks>(
    root: &Path,
    journal: &RestoreJournal,
    hooks: &mut H,
) -> BackupResult<()> {
    let tx_dir = transaction_dir(root, journal)?;
    for (index, original) in journal.originals.iter().rev().enumerate() {
        let file = StateFile::from_id(&original.id)
            .ok_or_else(|| BackupError::new("restore journal contains an unknown file ID"))?;
        hooks.before_rollback(index, file)?;
        let target = state_path(root, file);
        if original.present {
            let staged = Zeroizing::new(
                read_optional_file(
                    &tx_dir.join(old_file_name(file)),
                    file.max_bytes(),
                    "staged restore original",
                )?
                .ok_or_else(|| BackupError::new("staged restore original is missing"))?,
            );
            if staged.len() as u64 != original.byte_len
                || sha256_hex(&staged) != original.sha256.as_deref().unwrap_or_default()
            {
                return Err(BackupError::new(
                    "staged restore original failed its rollback digest",
                ));
            }
            secure_write(&target, &staged)
                .map_err(|error| BackupError::io("restore original wallet state", error))?;
        } else {
            remove_regular_file(&target, file.id())?;
        }
    }
    Ok(())
}

fn transaction_dir(root: &Path, journal: &RestoreJournal) -> BackupResult<PathBuf> {
    validate_journal(journal)?;
    let directory = root.join(format!(".restore-{}", journal.transaction_id));
    if directory.parent() != Some(root) {
        return Err(BackupError::new(
            "restore transaction escaped the wallet directory",
        ));
    }
    Ok(directory)
}

fn write_journal(path: &Path, journal: &RestoreJournal) -> BackupResult<()> {
    validate_journal(journal)?;
    let json = serde_json::to_vec(journal)
        .map_err(|error| BackupError::new(format!("serialize restore journal: {error}")))?;
    if json.len() > MAX_RESTORE_JOURNAL_BYTES {
        return Err(BackupError::new(
            "restore journal exceeds the safe size limit",
        ));
    }
    secure_write(path, &json).map_err(|error| BackupError::io("write restore journal", error))
}

fn cleanup_transaction(root: &Path, journal: &RestoreJournal) -> BackupResult<()> {
    let tx_dir = transaction_dir(root, journal)?;
    match fs::symlink_metadata(&tx_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(BackupError::new(
                    "restore transaction path is not a real directory",
                ));
            }
            for entry in fs::read_dir(&tx_dir)
                .map_err(|error| BackupError::io("list restore transaction", error))?
            {
                let entry = entry
                    .map_err(|error| BackupError::io("read restore transaction entry", error))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|error| BackupError::io("inspect restore transaction entry", error))?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || !is_allowed_tx_artifact(&name)
                {
                    return Err(BackupError::new(
                        "restore transaction contains an unexpected entry",
                    ));
                }
                fs::remove_file(entry.path())
                    .map_err(|error| BackupError::io("remove restore transaction file", error))?;
            }
            fs::remove_dir(&tx_dir)
                .map_err(|error| BackupError::io("remove restore transaction directory", error))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(BackupError::io("inspect restore transaction", error)),
    }
    remove_regular_file(&root.join(RESTORE_JOURNAL_NAME), "restore journal")
}

fn old_file_name(file: StateFile) -> String {
    format!("old-{}", file.id())
}

fn is_allowed_tx_artifact(name: &str) -> bool {
    if StateFile::ALL
        .into_iter()
        .any(|file| name == old_file_name(file))
    {
        return true;
    }
    if !name.starts_with('.') || !name.ends_with(".tmp") {
        return false;
    }
    StateFile::ALL.into_iter().any(|file| {
        let prefix = format!(".{}.", old_file_name(file));
        let Some(random) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            return false;
        };
        random.len() == 32 && random.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn remove_regular_file(path: &Path, label: &str) -> BackupResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BackupError::new(format!(
                    "refusing to remove non-regular {label}"
                )));
            }
            fs::remove_file(path)
                .map_err(|error| BackupError::io(&format!("remove {label}"), error))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BackupError::io(&format!("inspect {label}"), error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASS: &str = "correct horse battery staple";

    fn fixture_payload() -> BackupPayload {
        let vault = b"fixture-vault";
        let settings = b"fixture-settings";
        BackupPayload {
            schema: PAYLOAD_SCHEMA.into(),
            manifest: BackupManifest {
                wallet_address: "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa".into(),
                created_at_unix: 1_700_000_000,
                files: BackupFileManifest {
                    classic_vault: describe_file(vault, ROLE_REQUIRED_SECRET),
                    settings: describe_file(settings, ROLE_REQUIRED_RECOVERY),
                    quantum_keystore: None,
                    l2_bills: None,
                    messenger: None,
                },
                exclusions: expected_exclusions(),
            },
            files: BackupFiles {
                classic_vault_b64: encode_file(vault),
                settings_b64: encode_file(settings),
                quantum_keystore_b64: None,
                l2_bills_b64: None,
                messenger_b64: None,
            },
        }
    }

    #[test]
    fn authenticated_bundle_roundtrips_and_rejects_wrong_passphrase() {
        let payload = fixture_payload();
        let json = encrypt_payload(
            &payload,
            TEST_PASS,
            &payload.manifest.wallet_address,
            payload.manifest.created_at_unix,
        )
        .unwrap();
        let decoded = decrypt_payload(&json, TEST_PASS).unwrap();
        assert_eq!(
            decoded.manifest.wallet_address,
            payload.manifest.wallet_address
        );
        let error = decrypt_payload(&json, "wrong-passphrase-value").unwrap_err();
        assert!(error.to_string().contains("authentication failed"));
    }

    #[test]
    fn authenticated_bundle_rejects_tampering_and_truncation() {
        let payload = fixture_payload();
        let json = encrypt_payload(
            &payload,
            TEST_PASS,
            &payload.manifest.wallet_address,
            payload.manifest.created_at_unix,
        )
        .unwrap();
        let mut envelope: BackupEnvelope = serde_json::from_str(&json).unwrap();
        let replacement = if envelope.ciphertext_b64.starts_with('A') {
            "B"
        } else {
            "A"
        };
        envelope.ciphertext_b64.replace_range(0..1, replacement);
        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(decrypt_payload(&tampered, TEST_PASS).is_err());
        assert!(decrypt_payload(&json[..json.len() / 2], TEST_PASS).is_err());
    }

    #[test]
    fn authenticated_full_payload_builds_a_complete_restore_plan() {
        let secret = "11".repeat(32);
        let account = hacash_wallet_core::account::WalletAccount::from_secret_hex(&secret).unwrap();
        let address = account.address();
        let vault = EncryptedVault::encrypt(&secret, &address, TEST_PASS, "balanced").unwrap();
        let vault_bytes = vault.export_json().unwrap().into_bytes();
        let settings_bytes = serde_json::to_vec(&WalletSettings::default()).unwrap();
        let payload = BackupPayload {
            schema: PAYLOAD_SCHEMA.into(),
            manifest: BackupManifest {
                wallet_address: address.clone(),
                created_at_unix: 1_700_000_000,
                files: BackupFileManifest {
                    classic_vault: describe_file(&vault_bytes, ROLE_REQUIRED_SECRET),
                    settings: describe_file(&settings_bytes, ROLE_REQUIRED_RECOVERY),
                    quantum_keystore: None,
                    l2_bills: None,
                    messenger: None,
                },
                exclusions: expected_exclusions(),
            },
            files: BackupFiles {
                classic_vault_b64: encode_file(&vault_bytes),
                settings_b64: encode_file(&settings_bytes),
                quantum_keystore_b64: None,
                l2_bills_b64: None,
                messenger_b64: None,
            },
        };
        let json = encrypt_payload(
            &payload,
            TEST_PASS,
            &address,
            payload.manifest.created_at_unix,
        )
        .unwrap();
        let decoded = decrypt_payload(&json, TEST_PASS).unwrap();
        let plan = plan_from_full_payload(&decoded, TEST_PASS).unwrap();
        assert_eq!(plan.address, address);
        assert!(plan.desired[&StateFile::Vault].is_some());
        assert!(plan.desired[&StateFile::Settings].is_some());
        assert!(plan.desired[&StateFile::History].is_none());
        assert!(plan.desired[&StateFile::LegacyBiometric].is_none());
    }

    #[test]
    fn preview_quarantines_legacy_classic_only_backups() {
        let secret = "22".repeat(32);
        let account = hacash_wallet_core::account::WalletAccount::from_secret_hex(&secret).unwrap();
        let vault =
            EncryptedVault::encrypt(&secret, &account.address(), TEST_PASS, "balanced").unwrap();
        let preview = preview(&vault.export_json().unwrap()).unwrap();
        assert!(preview.requires_legacy_confirmation);
        assert_eq!(preview.format, "legacy_classic_only");
    }

    struct FailHooks {
        fail_apply: Option<usize>,
        fail_rollback: Option<usize>,
    }

    impl RestoreHooks for FailHooks {
        fn before_apply(&mut self, index: usize, _file: StateFile) -> BackupResult<()> {
            if self.fail_apply == Some(index) {
                return Err(BackupError::new("injected apply failure"));
            }
            Ok(())
        }

        fn before_rollback(&mut self, index: usize, _file: StateFile) -> BackupResult<()> {
            if self.fail_rollback == Some(index) {
                return Err(BackupError::new("injected rollback failure"));
            }
            Ok(())
        }
    }

    fn transaction_plan() -> RestorePlan {
        let mut desired = BTreeMap::new();
        for file in StateFile::ALL {
            desired.insert(file, None);
        }
        desired.insert(StateFile::Vault, Some(b"new-vault".to_vec()));
        desired.insert(StateFile::Settings, Some(b"new-settings".to_vec()));
        RestorePlan {
            desired,
            address: "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa".into(),
        }
    }

    #[test]
    fn restore_rolls_back_every_changed_file_when_apply_or_validation_fails() {
        let temp = tempfile::tempdir().unwrap();
        secure_write(&temp.path().join("vault.json"), b"old-vault").unwrap();
        secure_write(&temp.path().join("settings.json"), b"old-settings").unwrap();
        let plan = transaction_plan();
        let mut hooks = FailHooks {
            fail_apply: Some(2),
            fail_rollback: None,
        };
        assert!(transactional_apply_at(temp.path(), &plan, &mut hooks, || Ok(())).is_err());
        assert_eq!(
            fs::read(temp.path().join("vault.json")).unwrap(),
            b"old-vault"
        );
        assert_eq!(
            fs::read(temp.path().join("settings.json")).unwrap(),
            b"old-settings"
        );
        assert!(!temp.path().join(RESTORE_JOURNAL_NAME).exists());

        let mut hooks = FailHooks {
            fail_apply: None,
            fail_rollback: None,
        };
        let error = transactional_apply_at(temp.path(), &plan, &mut hooks, || {
            Err::<(), _>(BackupError::new("post-restore validation failed"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("post-restore validation failed"));
        assert_eq!(
            fs::read(temp.path().join("vault.json")).unwrap(),
            b"old-vault"
        );
    }

    #[test]
    fn rollback_failure_is_durable_and_startup_recovery_finishes_it() {
        let temp = tempfile::tempdir().unwrap();
        secure_write(&temp.path().join("vault.json"), b"old-vault").unwrap();
        secure_write(&temp.path().join("settings.json"), b"old-settings").unwrap();
        let plan = transaction_plan();
        let mut failing = FailHooks {
            fail_apply: Some(2),
            fail_rollback: Some(0),
        };
        let error =
            transactional_apply_at(temp.path(), &plan, &mut failing, || Ok(())).unwrap_err();
        assert!(error.to_string().contains("rollback failed"));
        assert!(temp.path().join(RESTORE_JOURNAL_NAME).exists());

        recover_at_root(temp.path(), &mut NoopRestoreHooks).unwrap();
        assert_eq!(
            fs::read(temp.path().join("vault.json")).unwrap(),
            b"old-vault"
        );
        assert_eq!(
            fs::read(temp.path().join("settings.json")).unwrap(),
            b"old-settings"
        );
        assert!(!temp.path().join(RESTORE_JOURNAL_NAME).exists());
    }

    #[test]
    fn unsafe_kdf_metadata_and_oversized_base64_are_rejected_before_crypto() {
        let payload = fixture_payload();
        let json = encrypt_payload(
            &payload,
            TEST_PASS,
            &payload.manifest.wallet_address,
            payload.manifest.created_at_unix,
        )
        .unwrap();
        let mut envelope: BackupEnvelope = serde_json::from_str(&json).unwrap();
        envelope.header.kdf.memory_kib = u32::MAX;
        assert!(
            decrypt_payload(&serde_json::to_string(&envelope).unwrap(), TEST_PASS)
                .unwrap_err()
                .to_string()
                .contains("KDF")
        );
        assert!(decode_b64_limited(&"A".repeat(100), 2, "fixture").is_err());
    }

    /// `HACASH_WALLET_DATA` is process-global, so the tests that redirect the
    /// wallet root must not run concurrently with each other.
    static WALLET_ROOT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_isolated_wallet_root<T>(f: impl FnOnce() -> T) -> T {
        let _guard = WALLET_ROOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("wallet-data");
        fs::create_dir_all(&root).expect("wallet root");
        // SAFETY: test-only redirection of the wallet data root.
        unsafe { std::env::set_var("HACASH_WALLET_DATA", &root) };
        let result = f();
        unsafe { std::env::remove_var("HACASH_WALLET_DATA") };
        drop(dir);
        result
    }

    fn wipe_wallet_root() {
        let root = paths::wallet_data_root();
        for entry in fs::read_dir(&root).expect("read wallet root") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                fs::remove_dir_all(&path).expect("remove dir");
            } else {
                fs::remove_file(&path).expect("remove file");
            }
        }
    }

    /// The whole point of a backup: the two functions the IPC layer actually
    /// calls must survive a full export, wipe and restore, and the restored
    /// wallet must open with the same key. Everything below these two is covered
    /// by the tests above; this covers the seam.
    #[test]
    fn export_and_restore_round_trip_recovers_the_same_wallet() {
        with_isolated_wallet_root(|| {
            let mut service = WalletService::new(None, None).expect("service");
            let address = service.create_wallet(TEST_PASS).expect("create wallet");

            let bundle = export_bundle(&mut service, TEST_PASS).expect("export");
            let preview = preview(&bundle).expect("preview");
            assert_eq!(preview.format, "full_authenticated");
            assert_eq!(preview.address, address);
            assert!(!preview.requires_legacy_confirmation);

            // Restoring over a live wallet is refused; rollback must go through
            // an explicit reset first.
            let error = restore(&mut service, &bundle, TEST_PASS, false).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("only into an empty wallet profile")
            );

            service.lock();
            drop(service);
            wipe_wallet_root();

            let mut restored_into = WalletService::new(None, None).expect("service");
            assert!(!restored_into.status().has_wallet);
            let restored = restore(&mut restored_into, &bundle, TEST_PASS, false).expect("restore");
            assert_eq!(restored, address);

            // The restored vault really opens with the same passphrase and key.
            let mut reopened = WalletService::new(None, None).expect("service");
            assert!(reopened.status().has_wallet);
            assert_eq!(reopened.unlock(TEST_PASS).expect("unlock"), address);
            assert!(reopened.status().signing_available);
        });
    }

    #[test]
    fn a_wrong_passphrase_or_tampered_bundle_never_replaces_a_wallet() {
        with_isolated_wallet_root(|| {
            let mut service = WalletService::new(None, None).expect("service");
            let address = service.create_wallet(TEST_PASS).expect("create wallet");
            let bundle = export_bundle(&mut service, TEST_PASS).expect("export");
            service.lock();
            drop(service);
            wipe_wallet_root();

            let mut target = WalletService::new(None, None).expect("service");
            assert!(
                restore(&mut target, &bundle, "wrong-passphrase-value", false)
                    .unwrap_err()
                    .to_string()
                    .contains("authentication failed")
            );
            // A failed restore must leave the profile untouched, not half-written.
            assert!(!target.status().has_wallet);

            let mut envelope: BackupEnvelope = serde_json::from_str(&bundle).unwrap();
            let mut raw = BASE64.decode(envelope.ciphertext_b64.as_bytes()).unwrap();
            let last = raw.len() - 1;
            raw[last] ^= 1;
            envelope.ciphertext_b64 = BASE64.encode(&raw);
            let tampered = serde_json::to_string(&envelope).unwrap();
            assert!(restore(&mut target, &tampered, TEST_PASS, false).is_err());
            assert!(!target.status().has_wallet);

            // Only the untouched bundle works, proving the wipe really happened.
            assert_eq!(
                restore(&mut target, &bundle, TEST_PASS, false).expect("restore"),
                address
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn restore_refuses_symlink_targets() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, temp.path().join("vault.json")).unwrap();
        let plan = transaction_plan();
        let error = transactional_apply_at(temp.path(), &plan, &mut NoopRestoreHooks, || Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("regular file"));
        assert_eq!(fs::read(outside).unwrap(), b"outside");
    }
}
