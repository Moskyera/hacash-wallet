use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use fs2::FileExt;
use hkdf::Hkdf;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const ENCRYPTED_STATE_VERSION: u32 = 1;
const ROOT_MARKER_VERSION: &[u8] = b"HPAY_AGENT_WALLET_STORAGE_V1\n";
const ENCRYPTION_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/ENCRYPTED-STATE/V1";
const REGISTRY_FILE: &str = "registry.json";
const LOCK_FILE: &str = ".agent-wallet.lock";
const ROOT_MARKER_FILE: &str = ".storage-version";
const WALLETS_DIRECTORY: &str = "wallets";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_ENCRYPTED_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Public, non-secret metadata used to discover independent Agent Wallets.
///
/// The registry intentionally contains no private key, passphrase, storage key,
/// policy, session, authorization token, or L2 state. Sensitive state belongs in
/// a per-wallet authenticated encrypted file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletRegistry {
    pub schema_version: u32,
    pub store_id: String,
    pub wallets: BTreeMap<String, AgentWalletRegistryEntry>,
}

impl AgentWalletRegistry {
    fn empty(store_id: String) -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            store_id,
            wallets: BTreeMap::new(),
        }
    }

    pub fn wallet(&self, wallet_id: &AgentWalletId) -> Option<&AgentWalletRegistryEntry> {
        self.wallets.get(wallet_id.as_str())
    }

    pub fn insert(&mut self, entry: AgentWalletRegistryEntry) -> AgentWalletResult<()> {
        validate_wallet_id(&entry.wallet_id)?;
        if self.wallets.contains_key(entry.wallet_id.as_str()) {
            return Err(AgentWalletError::AgentWalletAlreadyExists);
        }
        self.wallets
            .insert(entry.wallet_id.as_str().to_owned(), entry);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletRegistryEntry {
    pub wallet_id: AgentWalletId,
    pub address: String,
    pub created_at_unix: u64,
}

impl AgentWalletRegistryEntry {
    pub fn new(
        wallet_id: AgentWalletId,
        address: impl Into<String>,
        created_at_unix: u64,
    ) -> AgentWalletResult<Self> {
        validate_wallet_id(&wallet_id)?;
        let address = address.into();
        validate_registry_address(&address)?;
        Ok(Self {
            wallet_id,
            address,
            created_at_unix,
        })
    }
}

/// Every path for one Agent Wallet is derived from a caller-supplied root.
///
/// This type deliberately has no dependency on `HACASH_WALLET_DATA`,
/// `wallet_core::paths`, or any Personal Wallet path. The caller chooses the
/// Agent Wallet root once and passes it explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWalletPaths {
    base_root: PathBuf,
    wallet_root: PathBuf,
}

impl AgentWalletPaths {
    pub fn new(base_root: impl AsRef<Path>, wallet_id: &AgentWalletId) -> AgentWalletResult<Self> {
        validate_wallet_id(wallet_id)?;
        let base_root = base_root.as_ref().to_path_buf();
        if base_root.as_os_str().is_empty() {
            return Err(AgentWalletError::PersistenceFailed);
        }
        let wallet_root = base_root.join(WALLETS_DIRECTORY).join(wallet_id.as_str());
        Ok(Self {
            base_root,
            wallet_root,
        })
    }

    pub fn wallet_root(&self) -> &Path {
        &self.wallet_root
    }

    pub fn vault_path(&self) -> PathBuf {
        self.wallet_root.join("vault.json")
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.wallet_root.join("sessions")
    }

    pub fn l2_dir(&self) -> PathBuf {
        self.wallet_root.join("l2")
    }

    pub fn encrypted_state_path(&self, state_name: &str) -> AgentWalletResult<PathBuf> {
        validate_state_name(state_name)?;
        Ok(self.wallet_root.join(format!("{state_name}.enc.json")))
    }
}

/// Process-exclusive access to an Agent Wallet storage root.
///
/// One lock covers the registry and every wallet below this root. This is
/// intentionally separate from the Personal Wallet lock and paths.
#[derive(Debug)]
pub struct AgentStorage {
    root: PathBuf,
    store_id: String,
    lock_file: File,
}

impl AgentStorage {
    pub fn open(base_root: impl AsRef<Path>) -> AgentWalletResult<Self> {
        let requested_root = base_root.as_ref();
        if requested_root.as_os_str().is_empty() {
            return Err(AgentWalletError::PersistenceFailed);
        }
        reject_symlink(requested_root)?;
        fs::create_dir_all(requested_root).map_err(|_| AgentWalletError::PersistenceFailed)?;
        reject_symlink(requested_root)?;

        // `secure_write` applies the same private directory policy as the
        // Personal Wallet without selecting or touching any Personal path.
        let marker_path = requested_root.join(ROOT_MARKER_FILE);
        reject_symlink(&marker_path)?;
        hacash_wallet_core::paths::secure_write(&marker_path, ROOT_MARKER_VERSION)
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        reject_symlink(&marker_path)?;

        let root = requested_root
            .canonicalize()
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        let lock_path = root.join(LOCK_FILE);
        reject_symlink(&lock_path)?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        reject_symlink(&lock_path)?;
        ensure_path_is_within(&root, &lock_path)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        restrict_lock_file_permissions(&lock_file)?;

        let registry_path = root.join(REGISTRY_FILE);
        let (store_id, create_registry) = if registry_path.exists() {
            let registry: AgentWalletRegistry =
                read_json_bounded(&registry_path, MAX_REGISTRY_BYTES)?;
            validate_registry(&registry)?;
            (registry.store_id, false)
        } else {
            (uuid::Uuid::new_v4().to_string(), true)
        };

        let storage = Self {
            root,
            store_id,
            lock_file,
        };
        if create_registry {
            storage.save_registry(&AgentWalletRegistry::empty(storage.store_id.clone()))?;
        }
        Ok(storage)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn registry_path(&self) -> PathBuf {
        self.root.join(REGISTRY_FILE)
    }

    pub fn paths(&self, wallet_id: &AgentWalletId) -> AgentWalletResult<AgentWalletPaths> {
        AgentWalletPaths::new(&self.root, wallet_id)
    }

    pub fn load_registry(&self) -> AgentWalletResult<AgentWalletRegistry> {
        let registry: AgentWalletRegistry =
            read_json_bounded(&self.registry_path(), MAX_REGISTRY_BYTES)?;
        validate_registry(&registry)?;
        if registry.store_id != self.store_id {
            return Err(AgentWalletError::PersistenceFailed);
        }
        Ok(registry)
    }

    pub fn save_registry(&self, registry: &AgentWalletRegistry) -> AgentWalletResult<()> {
        validate_registry(registry)?;
        if registry.store_id != self.store_id {
            return Err(AgentWalletError::PersistenceFailed);
        }
        let bytes =
            serde_json::to_vec(registry).map_err(|_| AgentWalletError::PersistenceFailed)?;
        if bytes.len() as u64 > MAX_REGISTRY_BYTES {
            return Err(AgentWalletError::PersistenceFailed);
        }
        hacash_wallet_core::paths::secure_write(&self.registry_path(), &bytes)
            .map_err(|_| AgentWalletError::PersistenceFailed)
    }

    pub fn ensure_wallet_layout(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<AgentWalletPaths> {
        let paths = self.paths(wallet_id)?;
        let directories = [
            paths.wallet_root().to_path_buf(),
            paths.sessions_dir(),
            paths.l2_dir(),
        ];
        for directory in &directories {
            reject_symlink(directory)?;
            fs::create_dir_all(directory).map_err(|_| AgentWalletError::PersistenceFailed)?;
            reject_symlink(directory)?;
            let marker = directory.join(ROOT_MARKER_FILE);
            reject_symlink(&marker)?;
            hacash_wallet_core::paths::secure_write(&marker, ROOT_MARKER_VERSION)
                .map_err(|_| AgentWalletError::PersistenceFailed)?;
            reject_symlink(&marker)?;
        }
        Ok(paths)
    }

    /// Encrypt and atomically replace one named state document.
    ///
    /// The master key is supplied by the service and must be derived separately
    /// from the blockchain signing key. This storage layer never derives it from
    /// a Personal Wallet secret or from process-global state.
    pub fn write_encrypted<T: Serialize>(
        &self,
        wallet_id: &AgentWalletId,
        state_name: &str,
        schema_version: u32,
        master_key: &[u8; KEY_LEN],
        value: &T,
    ) -> AgentWalletResult<()> {
        validate_schema_version(schema_version)?;
        let paths = self.ensure_wallet_layout(wallet_id)?;
        let path = paths.encrypted_state_path(state_name)?;

        let mut plaintext =
            serde_json::to_vec(value).map_err(|_| AgentWalletError::PersistenceFailed)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            plaintext.zeroize();
            return Err(AgentWalletError::PersistenceFailed);
        }

        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = state_aad(&self.store_id, wallet_id, state_name, schema_version)?;
        let mut key = derive_state_key(
            master_key,
            &salt,
            &self.store_id,
            wallet_id,
            state_name,
            schema_version,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AgentWalletError::Crypto)?;
        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        );
        key.zeroize();
        plaintext.zeroize();
        let ciphertext = encrypted.map_err(|_| AgentWalletError::Crypto)?;

        let envelope = EncryptedStateEnvelope {
            envelope_version: ENCRYPTED_STATE_VERSION,
            store_id: self.store_id.clone(),
            wallet_id: wallet_id.as_str().to_owned(),
            state_name: state_name.to_owned(),
            schema_version,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|_| AgentWalletError::PersistenceFailed)?;
        if bytes.len() as u64 > MAX_ENCRYPTED_STATE_BYTES {
            return Err(AgentWalletError::PersistenceFailed);
        }
        hacash_wallet_core::paths::secure_write(&path, &bytes)
            .map_err(|_| AgentWalletError::PersistenceFailed)
    }

    pub fn read_encrypted<T: DeserializeOwned>(
        &self,
        wallet_id: &AgentWalletId,
        state_name: &str,
        schema_version: u32,
        master_key: &[u8; KEY_LEN],
    ) -> AgentWalletResult<T> {
        self.read_encrypted_if_exists(wallet_id, state_name, schema_version, master_key)?
            .ok_or(AgentWalletError::PersistenceFailed)
    }

    pub fn read_encrypted_if_exists<T: DeserializeOwned>(
        &self,
        wallet_id: &AgentWalletId,
        state_name: &str,
        schema_version: u32,
        master_key: &[u8; KEY_LEN],
    ) -> AgentWalletResult<Option<T>> {
        validate_schema_version(schema_version)?;
        let paths = self.paths(wallet_id)?;
        let path = paths.encrypted_state_path(state_name)?;
        if !path.exists() {
            return Ok(None);
        }
        let envelope: EncryptedStateEnvelope = read_json_bounded(&path, MAX_ENCRYPTED_STATE_BYTES)?;
        validate_envelope(
            &envelope,
            &self.store_id,
            wallet_id,
            state_name,
            schema_version,
        )?;

        let salt = decode_fixed::<SALT_LEN>(&envelope.salt_hex)?;
        let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce_hex)?;
        let ciphertext = decode_bounded_hex(
            &envelope.ciphertext_hex,
            MAX_PLAINTEXT_BYTES
                .checked_add(16)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        )?;
        let aad = state_aad(&self.store_id, wallet_id, state_name, schema_version)?;
        let mut key = derive_state_key(
            master_key,
            &salt,
            &self.store_id,
            wallet_id,
            state_name,
            schema_version,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AgentWalletError::Crypto)?;
        let decrypted = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        );
        key.zeroize();
        let mut plaintext = decrypted.map_err(|_| AgentWalletError::JournalAuthenticationFailed)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            plaintext.zeroize();
            return Err(AgentWalletError::PersistenceFailed);
        }
        let value =
            serde_json::from_slice(&plaintext).map_err(|_| AgentWalletError::PersistenceFailed);
        plaintext.zeroize();
        value.map(Some)
    }
}

impl Drop for AgentStorage {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock_file);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedStateEnvelope {
    envelope_version: u32,
    store_id: String,
    wallet_id: String,
    state_name: String,
    schema_version: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

fn validate_registry(registry: &AgentWalletRegistry) -> AgentWalletResult<()> {
    if registry.schema_version != REGISTRY_SCHEMA_VERSION
        || uuid::Uuid::parse_str(&registry.store_id).is_err()
    {
        return Err(AgentWalletError::PersistenceFailed);
    }
    for (key, entry) in &registry.wallets {
        validate_wallet_id(&entry.wallet_id)?;
        if key != entry.wallet_id.as_str() {
            return Err(AgentWalletError::PersistenceFailed);
        }
        validate_registry_address(&entry.address)?;
    }
    Ok(())
}

fn validate_registry_address(address: &str) -> AgentWalletResult<()> {
    if address.is_empty()
        || address.len() > 128
        || !address.is_ascii()
        || address
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AgentWalletError::PersistenceFailed);
    }
    Ok(())
}

fn validate_wallet_id(wallet_id: &AgentWalletId) -> AgentWalletResult<()> {
    let reparsed = AgentWalletId::parse(wallet_id.as_str())?;
    if reparsed != *wallet_id {
        return Err(AgentWalletError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_state_name(state_name: &str) -> AgentWalletResult<()> {
    let mut bytes = state_name.bytes();
    let Some(first) = bytes.next() else {
        return Err(AgentWalletError::InvalidIdentifier);
    };
    if !first.is_ascii_lowercase()
        || state_name.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AgentWalletError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_schema_version(schema_version: u32) -> AgentWalletResult<()> {
    if schema_version == 0 {
        return Err(AgentWalletError::PersistenceFailed);
    }
    Ok(())
}

fn validate_envelope(
    envelope: &EncryptedStateEnvelope,
    store_id: &str,
    wallet_id: &AgentWalletId,
    state_name: &str,
    schema_version: u32,
) -> AgentWalletResult<()> {
    if envelope.envelope_version != ENCRYPTED_STATE_VERSION
        || envelope.store_id != store_id
        || envelope.wallet_id != wallet_id.as_str()
        || envelope.state_name != state_name
        || envelope.schema_version != schema_version
    {
        return Err(AgentWalletError::JournalAuthenticationFailed);
    }
    validate_wallet_id(&AgentWalletId::parse(&envelope.wallet_id)?)?;
    validate_state_name(&envelope.state_name)?;
    validate_schema_version(envelope.schema_version)
}

fn derive_state_key(
    master_key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    store_id: &str,
    wallet_id: &AgentWalletId,
    state_name: &str,
    schema_version: u32,
) -> AgentWalletResult<[u8; KEY_LEN]> {
    let info = state_aad(store_id, wallet_id, state_name, schema_version)?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut key = [0_u8; KEY_LEN];
    hkdf.expand(&info, &mut key)
        .map_err(|_| AgentWalletError::Crypto)?;
    Ok(key)
}

fn state_aad(
    store_id: &str,
    wallet_id: &AgentWalletId,
    state_name: &str,
    schema_version: u32,
) -> AgentWalletResult<Vec<u8>> {
    validate_wallet_id(wallet_id)?;
    validate_state_name(state_name)?;
    validate_schema_version(schema_version)?;
    if uuid::Uuid::parse_str(store_id).is_err() {
        return Err(AgentWalletError::PersistenceFailed);
    }
    let mut aad = Vec::with_capacity(192);
    append_aad_field(&mut aad, ENCRYPTION_DOMAIN)?;
    append_aad_field(&mut aad, store_id.as_bytes())?;
    append_aad_field(&mut aad, wallet_id.as_str().as_bytes())?;
    append_aad_field(&mut aad, state_name.as_bytes())?;
    append_aad_field(&mut aad, &schema_version.to_be_bytes())?;
    Ok(aad)
}

fn append_aad_field(buffer: &mut Vec<u8>, field: &[u8]) -> AgentWalletResult<()> {
    let length = u32::try_from(field.len()).map_err(|_| AgentWalletError::IntegerOverflow)?;
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(field);
    Ok(())
}

fn read_json_bounded<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> AgentWalletResult<T> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(AgentWalletError::PersistenceFailed);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| AgentWalletError::PersistenceFailed)?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(|_| AgentWalletError::PersistenceFailed)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AgentWalletError::PersistenceFailed)?;
    if bytes.len() as u64 > max_bytes {
        return Err(AgentWalletError::PersistenceFailed);
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentWalletError::PersistenceFailed)
}

fn decode_fixed<const N: usize>(encoded: &str) -> AgentWalletResult<[u8; N]> {
    let decoded = decode_bounded_hex(encoded, N)?;
    decoded
        .try_into()
        .map_err(|_| AgentWalletError::PersistenceFailed)
}

fn decode_bounded_hex(encoded: &str, max_decoded_bytes: usize) -> AgentWalletResult<Vec<u8>> {
    let max_encoded = max_decoded_bytes
        .checked_mul(2)
        .ok_or(AgentWalletError::IntegerOverflow)?;
    if encoded.len() > max_encoded || !encoded.len().is_multiple_of(2) {
        return Err(AgentWalletError::PersistenceFailed);
    }
    hex::decode(encoded).map_err(|_| AgentWalletError::PersistenceFailed)
}

fn reject_symlink(path: &Path) -> AgentWalletResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(AgentWalletError::PersistenceFailed)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AgentWalletError::PersistenceFailed),
    }
}

fn ensure_path_is_within(root: &Path, path: &Path) -> AgentWalletResult<()> {
    let canonical = path
        .canonicalize()
        .map_err(|_| AgentWalletError::PersistenceFailed)?;
    if canonical.parent() != Some(root) {
        return Err(AgentWalletError::PersistenceFailed);
    }
    Ok(())
}

fn restrict_lock_file_permissions(file: &File) -> AgentWalletResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::HacUnits;
    use crate::policy::AgentPolicy;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct TestState {
        available: HacUnits,
        policy: AgentPolicy,
    }

    fn registry_entry(wallet_id: AgentWalletId) -> AgentWalletRegistryEntry {
        AgentWalletRegistryEntry::new(wallet_id, "1AgentWalletAddress", 1_700_000_000).unwrap()
    }

    #[test]
    fn paths_are_explicit_and_traversal_resistant() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = AgentWalletPaths::new(temp.path(), &wallet_id).unwrap();
        assert!(paths.wallet_root().starts_with(temp.path()));
        assert!(paths.vault_path().starts_with(paths.wallet_root()));
        assert!(paths.l2_dir().starts_with(paths.wallet_root()));

        // The current opaque-ID serde representation cannot itself validate.
        // Storage revalidates it before the value can become a path component.
        let malicious: AgentWalletId = serde_json::from_str("\"../../personal\"").unwrap();
        assert_eq!(
            AgentWalletPaths::new(temp.path(), &malicious),
            Err(AgentWalletError::InvalidIdentifier)
        );
        assert!(paths.encrypted_state_path("../personal").is_err());
        assert!(paths.encrypted_state_path("state.json").is_err());
    }

    #[test]
    fn process_lock_is_exclusive_and_released_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let first = AgentStorage::open(temp.path()).unwrap();
        assert!(AgentStorage::open(temp.path()).is_err());
        drop(first);
        AgentStorage::open(temp.path()).unwrap();
    }

    #[test]
    fn registry_roundtrip_is_atomic_and_validated() {
        let temp = tempfile::tempdir().unwrap();
        let storage = AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let mut registry = storage.load_registry().unwrap();
        registry.insert(registry_entry(wallet_id.clone())).unwrap();
        storage.save_registry(&registry).unwrap();
        assert_eq!(
            storage
                .load_registry()
                .unwrap()
                .wallet(&wallet_id)
                .unwrap()
                .wallet_id,
            wallet_id
        );
        assert!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp"))
        );
    }

    #[test]
    fn encrypted_state_roundtrips_and_is_bound_to_wallet_schema_and_key() {
        let temp = tempfile::tempdir().unwrap();
        let storage = AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let other_wallet_id = AgentWalletId::new();
        let state = TestState {
            available: HacUnits::new(42),
            policy: AgentPolicy::default(),
        };
        let key = [7_u8; KEY_LEN];
        storage
            .write_encrypted(&wallet_id, "state", 1, &key, &state)
            .unwrap();
        let loaded: TestState = storage
            .read_encrypted(&wallet_id, "state", 1, &key)
            .unwrap();
        assert_eq!(loaded, state);
        assert!(
            storage
                .read_encrypted::<TestState>(&wallet_id, "state", 2, &key)
                .is_err()
        );
        assert!(
            storage
                .read_encrypted::<TestState>(&other_wallet_id, "state", 1, &key)
                .is_err()
        );
        assert!(
            storage
                .read_encrypted::<TestState>(&wallet_id, "state", 1, &[8_u8; KEY_LEN])
                .is_err()
        );
    }

    #[test]
    fn ciphertext_or_envelope_tampering_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let storage = AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let key = [9_u8; KEY_LEN];
        let state = TestState {
            available: HacUnits::new(5),
            policy: AgentPolicy::default(),
        };
        storage
            .write_encrypted(&wallet_id, "state", 1, &key, &state)
            .unwrap();
        let path = storage
            .paths(&wallet_id)
            .unwrap()
            .encrypted_state_path("state")
            .unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let ciphertext = envelope["ciphertext_hex"].as_str().unwrap();
        let replacement = if ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        envelope["ciphertext_hex"] =
            serde_json::Value::String(format!("{replacement}{}", &ciphertext[1..]));
        let bytes = serde_json::to_vec(&envelope).unwrap();
        hacash_wallet_core::paths::secure_write(&path, &bytes).unwrap();
        assert_eq!(
            storage.read_encrypted::<TestState>(&wallet_id, "state", 1, &key),
            Err(AgentWalletError::JournalAuthenticationFailed)
        );
    }

    #[test]
    fn registry_store_id_cannot_be_rebound() {
        let temp = tempfile::tempdir().unwrap();
        let storage = AgentStorage::open(temp.path()).unwrap();
        let mut registry = storage.load_registry().unwrap();
        registry.store_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            storage.save_registry(&registry),
            Err(AgentWalletError::PersistenceFailed)
        );
    }
}
