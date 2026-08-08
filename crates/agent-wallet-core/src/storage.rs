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
const RESTORE_JOURNAL_FILE: &str = ".agent-restore-journal";
const RESTORE_JOURNAL_MAGIC: &str = "hpay_agent_wallet_restore_journal";
const RESTORE_JOURNAL_VERSION: u32 = 1;
const MAX_RESTORE_JOURNAL_BYTES: u64 = 4 * 1024;
/// Every file name this crate ever writes directly inside one wallet directory.
///
/// Rolling back an interrupted restore removes exactly these and nothing else,
/// so a recovery can never delete a file the owner or another program put there.
/// `an_uncommitted_restore_leaves_no_trace_of_the_wallet` walks a real wallet
/// built by the real code and fails if any entry is missing from this list, so
/// the list cannot drift away from the writers.
const WALLET_DIRECTORY_FILES: [&str; 5] = [
    "vault.json",
    "journal.json",
    "wallet_state.enc.json",
    "wallet_state_pending.enc.json",
    ".emergency-stop-v1",
];
const WALLET_DIRECTORY_SUBDIRECTORIES: [&str; 2] = ["sessions", "l2"];
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

    // ---- THE INTERRUPTED-RESTORE WRITE-AHEAD RECORD ----------------------
    //
    // Restoring an Agent Wallet is five durable writes that only mean anything
    // together, and the registry entry is the last of them. Before this record
    // existed, a crash inside that sequence left the keys on disk under a wallet
    // the registry did not list: invisible to `list_wallets`, answered with
    // `AgentWalletNotFound` by `unlock_session`, and then refused FOR EVER by
    // the restore's own pre-check, which could not tell its own debris from a
    // live wallet. That is a half-restore, it was executed, and it was terminal.
    //
    // The rule here is the Personal Wallet's rule from `transactional_apply_at`:
    // write down what is about to be attempted BEFORE attempting it, and let the
    // next open finish the story. Because the registry entry is what makes a
    // wallet exist at all, the commit point needs no separate phase and recovery
    // needs no heuristic:
    //
    //   * record present, wallet registered     -> the restore committed and
    //     only its own record outlived it. Retire the record.
    //   * record present, wallet NOT registered -> nothing committed. Remove
    //     everything the interrupted restore had written, then the record.
    //
    // Every deletion needs BOTH authorisations - a record naming this wallet and
    // the absence of a registry entry for it - and is confined to the file names
    // in `WALLET_DIRECTORY_FILES`. Anything else is left exactly where it is.

    fn restore_journal_path(&self) -> PathBuf {
        self.root.join(RESTORE_JOURNAL_FILE)
    }

    /// Records, durably, which wallet a restore is about to build.
    ///
    /// Not one byte of that wallet may be written before this returns; that
    /// ordering is the whole guarantee.
    pub(crate) fn begin_wallet_restore(&self, wallet_id: &AgentWalletId) -> AgentWalletResult<()> {
        validate_wallet_id(wallet_id)?;

        let record = AgentRestoreJournal {
            magic: RESTORE_JOURNAL_MAGIC.to_owned(),
            version: RESTORE_JOURNAL_VERSION,
            store_id: self.store_id.clone(),
            wallet_id: wallet_id.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| AgentWalletError::PersistenceFailed)?;
        if bytes.len() as u64 > MAX_RESTORE_JOURNAL_BYTES {
            return Err(AgentWalletError::PersistenceFailed);
        }
        let path = self.restore_journal_path();
        reject_symlink(&path)?;
        hacash_wallet_core::paths::secure_write(&path, &bytes)
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        reject_symlink(&path)
    }

    /// Retires the record once the registry entry - the commit point - is down.
    ///
    /// A failure here is not a failure of the restore. The wallet exists; the
    /// next open sees a committed wallet and retires the record there.
    pub(crate) fn finish_wallet_restore(&self) -> AgentWalletResult<()> {
        self.remove_restore_journal()
    }

    /// Finishes the story of a restore that was interrupted, whichever way it
    /// actually ended. A no-op when no restore was in flight.
    pub(crate) fn recover_interrupted_wallet_restore(&self) -> AgentWalletResult<()> {
        let path = self.restore_journal_path();
        reject_symlink(&path)?;
        if !path.exists() {
            return Ok(());
        }
        let record =
            match read_json_bounded::<AgentRestoreJournal>(&path, MAX_RESTORE_JOURNAL_BYTES) {
                Ok(record)
                    if record.magic == RESTORE_JOURNAL_MAGIC
                        && record.version == RESTORE_JOURNAL_VERSION
                        && record.store_id == self.store_id
                        && validate_wallet_id(&record.wallet_id).is_ok() =>
                {
                    record
                }
                // A record that will not parse, or that belongs to another store,
                // authorises nothing. The only act it could ever authorise is a
                // deletion, so it is retired and no wallet file is touched.
                _ => return self.remove_restore_journal(),
            };
        if self.load_registry()?.wallet(&record.wallet_id).is_some() {
            return self.remove_restore_journal();
        }
        self.discard_uncommitted_wallet_directory(&record.wallet_id)?;
        self.remove_restore_journal()
    }

    fn remove_restore_journal(&self) -> AgentWalletResult<()> {
        let path = self.restore_journal_path();
        reject_symlink(&path)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AgentWalletError::PersistenceFailed),
        }
    }

    /// Removes a wallet directory that the registry does not list, restricted to
    /// the file names this crate writes into one.
    ///
    /// Fails if any of the four documents that make a wallet a wallet is still
    /// there afterwards, because that is the state a restore cannot retry
    /// through - and a failure leaves the write-ahead record in place, so the
    /// next open tries again rather than giving up.
    fn discard_uncommitted_wallet_directory(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<()> {
        // Re-asked here rather than trusted from the caller: this is the only
        // function in the crate that deletes a vault.
        if self.load_registry()?.wallet(wallet_id).is_some() {
            return Err(AgentWalletError::PersistenceFailed);
        }
        let paths = self.paths(wallet_id)?;
        let wallet_root = paths.wallet_root().to_path_buf();
        reject_symlink(&wallet_root)?;
        if !wallet_root.exists() {
            return Ok(());
        }
        let wallets_directory = self.root.join(WALLETS_DIRECTORY);
        reject_symlink(&wallets_directory)?;
        let canonical_wallets = wallets_directory
            .canonicalize()
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        ensure_path_is_within(&canonical_wallets, &wallet_root)?;
        if prune_wallet_directory(&wallet_root, true)? {
            let _ = fs::remove_dir(&wallet_root);
            // And the shared parent, if this was the only thing in it. Both
            // removals only ever succeed on an empty directory, and the store
            // lock makes this the only process that could be in here.
            let _ = fs::remove_dir(&canonical_wallets);
        }
        for path in [
            paths.vault_path(),
            wallet_root.join("journal.json"),
            paths.encrypted_state_path("wallet_state")?,
            paths.encrypted_state_path("wallet_state_pending")?,
        ] {
            if path.exists() {
                return Err(AgentWalletError::PersistenceFailed);
            }
        }
        Ok(())
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

/// Decrypts one state envelope whose `store_id` is the one recorded IN the
/// envelope rather than the one of the store now holding it.
///
/// WHY THIS IS NOT A LOOSENING OF [`AgentStorage::read_encrypted`], which keeps
/// binding to its own `store_id` and is untouched. A state file's authenticity
/// rests on the AEAD key derived from the wallet's own `state_master`, on the
/// journal's MAC chain, and on the state commitment in the journal head - not on
/// `store_id`. What `store_id` buys is that a state file cannot be moved between
/// two stores on this machine WITHOUT SOMEONE SAYING SO, which is exactly the
/// invariant a restore has to break, once, deliberately, with the owner's
/// passphrase in hand.
///
/// It is used only by restore, which immediately re-encrypts the plaintext for
/// the receiving store and then re-reads it through `read_encrypted` before it
/// will call the restore a success, so nothing this returns is ever left on disk
/// bound to a foreign store.
pub fn decrypt_foreign_state_envelope(
    envelope_bytes: &[u8],
    wallet_id: &AgentWalletId,
    state_name: &str,
    schema_version: u32,
    master_key: &[u8; KEY_LEN],
) -> AgentWalletResult<Vec<u8>> {
    validate_schema_version(schema_version)?;
    if envelope_bytes.len() as u64 > MAX_ENCRYPTED_STATE_BYTES {
        return Err(AgentWalletError::PersistenceFailed);
    }
    let envelope: EncryptedStateEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|_| AgentWalletError::PersistenceFailed)?;
    // Everything except `store_id` is checked exactly as `read_encrypted`
    // checks it, and `store_id` is still authenticated - as AAD - against the
    // value the envelope itself carries, so a tampered `store_id` fails the
    // AEAD rather than being ignored.
    validate_envelope(
        &envelope,
        &envelope.store_id,
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
    let aad = state_aad(&envelope.store_id, wallet_id, state_name, schema_version)?;
    let mut key = derive_state_key(
        master_key,
        &salt,
        &envelope.store_id,
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
    Ok(plaintext)
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

/// The write-ahead record of a restore in flight.
///
/// It carries only what a recovery needs in order to be allowed to act: which
/// store it belongs to, and which wallet was being built. Nothing secret, and
/// nothing a recovery has to interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRestoreJournal {
    magic: String,
    version: u32,
    store_id: String,
    wallet_id: AgentWalletId,
}

/// Removes the entries this crate writes inside one wallet directory, and only
/// those. Returns true when the directory is now empty and may itself go.
///
/// A symlink, a foreign file or a foreign subdirectory is never followed and
/// never deleted: it is simply left behind, and its presence is reported by the
/// `false` return so the wallet directory itself survives.
fn prune_wallet_directory(directory: &Path, is_wallet_root: bool) -> AgentWalletResult<bool> {
    reject_symlink(directory)?;
    let entries = fs::read_dir(directory).map_err(|_| AgentWalletError::PersistenceFailed)?;
    let mut emptied = true;
    for entry in entries {
        let entry = entry.map_err(|_| AgentWalletError::PersistenceFailed)?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| AgentWalletError::PersistenceFailed)?;
        let raw_name = entry.file_name();
        let Some(name) = raw_name
            .to_str()
            .filter(|_| !metadata.file_type().is_symlink())
        else {
            emptied = false;
            continue;
        };
        if metadata.is_dir() {
            if is_wallet_root
                && WALLET_DIRECTORY_SUBDIRECTORIES.contains(&name)
                && prune_wallet_directory(&path, false)?
                && fs::remove_dir(&path).is_ok()
            {
                continue;
            }
            emptied = false;
            continue;
        }
        if !is_wallet_directory_file(name, is_wallet_root) || fs::remove_file(&path).is_err() {
            emptied = false;
        }
    }
    Ok(emptied)
}

/// True when this crate is the only thing that could have written this name.
fn is_wallet_directory_file(name: &str, is_wallet_root: bool) -> bool {
    let is_target = |candidate: &str| {
        candidate == ROOT_MARKER_FILE
            || (is_wallet_root && WALLET_DIRECTORY_FILES.contains(&candidate))
    };
    is_target(name) || is_secure_write_temporary(name, is_target)
}

/// True for `secure_write`'s own half-written temporary of one of those names.
///
/// `secure_write` writes `.<target>.<uuid simple>.tmp` next to its target and
/// unlinks it on failure, so one can only be left behind by a process that died
/// mid-write - which is precisely the case this rollback exists for.
fn is_secure_write_temporary(name: &str, is_target: impl Fn(&str) -> bool) -> bool {
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((target, random)) = body.rsplit_once('.') else {
        return false;
    };
    random.len() == 32 && random.bytes().all(|byte| byte.is_ascii_hexdigit()) && is_target(target)
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
