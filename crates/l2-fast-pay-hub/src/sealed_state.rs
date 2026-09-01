use crate::error::{HubError, HubResult};
use crate::storage::{
    HubPersistedState, acquire_state_lock, ensure_not_symlink, initialize_authenticated_state,
    load_state_file, save_bytes_atomic, save_state_file,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};
const FORMAT: &str = "hpay-hub-state-aead/1";
const KEY_DOMAIN: &[u8] = b"HPAY/FAST-PAY-HUB/STATE-AEAD/V1";
const NONCE_BYTES: usize = 12;
const MAX_PLAINTEXT_STATE_BYTES: usize = 64 * 1024 * 1024;
// Hex doubles the ciphertext and the authenticated JSON envelope adds bounded metadata.
const MAX_SEALED_STATE_BYTES: u64 = (MAX_PLAINTEXT_STATE_BYTES as u64 * 2) + 4096;
pub(crate) enum StateStore {
    Plaintext { path: PathBuf },
    Sealed(EncryptedStateStore),
}
impl StateStore {
    pub(crate) fn plaintext(path: PathBuf) -> Self {
        Self::Plaintext { path }
    }
    pub(crate) fn sealed(path: PathBuf, key_hex: &str, hub_address: &str) -> HubResult<Self> {
        Ok(Self::Sealed(EncryptedStateStore::new(
            path,
            key_hex,
            hub_address,
        )?))
    }
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::Plaintext { path } => path,
            Self::Sealed(store) => &store.path,
        }
    }
    pub(crate) fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }
    pub(crate) fn load(&self) -> HubResult<HubPersistedState> {
        match self {
            Self::Plaintext { path } => load_state_file(path),
            Self::Sealed(store) => store.load(),
        }
    }
    pub(crate) fn save(&self, state: &HubPersistedState) -> HubResult<()> {
        match self {
            Self::Plaintext { path } => save_state_file(path, state),
            Self::Sealed(store) => store.save(state),
        }
    }
}
pub(crate) struct EncryptedStateStore {
    path: PathBuf,
    hub_address: String,
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedStateFileV1 {
    format: String,
    key_id: String,
    nonce_hex: String,
    ciphertext_hex: String,
}
impl EncryptedStateStore {
    fn new(path: PathBuf, key_hex: &str, hub_address: &str) -> HubResult<Self> {
        let mut master = hex::decode(key_hex.trim())
            .map_err(|_| HubError::State("state encryption key must be hex".into()))?;
        if master.len() != 32 || hub_address.trim().is_empty() {
            master.zeroize();
            return Err(HubError::State(
                "state encryption key must decode to exactly 32 bytes".into(),
            ));
        }
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), &master);
        let mut key = [0u8; 32];
        hkdf.expand(hub_address.trim().as_bytes(), &mut key)
            .map_err(|_| HubError::State("state encryption key derivation failed".into()))?;
        master.zeroize();
        let key_id = hex::encode(&Sha256::digest(key)[..8]);
        Ok(Self {
            path,
            hub_address: hub_address.trim().to_owned(),
            key_id,
            key: Zeroizing::new(key),
        })
    }
    fn load(&self) -> HubResult<HubPersistedState> {
        if let Some(parent) = self.path.parent() {
            ensure_not_symlink(parent, "hub state directory")?;
        }
        ensure_not_symlink(&self.path, "sealed Hub state file")?;
        if !self.path.exists() {
            return Ok(HubPersistedState::default());
        }
        let metadata =
            fs::metadata(&self.path).map_err(|error| HubError::State(error.to_string()))?;
        if metadata.len() > MAX_SEALED_STATE_BYTES {
            return Err(HubError::State(
                "sealed Hub state exceeds the size limit".into(),
            ));
        }
        let raw = fs::read(&self.path).map_err(|error| HubError::State(error.to_string()))?;
        let envelope: SealedStateFileV1 = serde_json::from_slice(&raw).map_err(|_| {
            HubError::State(
                "mainnet Hub state is plaintext, malformed, or requires explicit migration".into(),
            )
        })?;
        self.validate_envelope(&envelope)?;
        let nonce = decode_fixed::<NONCE_BYTES>(&envelope.nonce_hex, "state nonce")?;
        let mut ciphertext = hex::decode(&envelope.ciphertext_hex)
            .map_err(|_| HubError::State("sealed state ciphertext is not hex".into()))?;
        if ciphertext.len() > MAX_PLAINTEXT_STATE_BYTES + 16 {
            ciphertext.zeroize();
            return Err(HubError::State(
                "sealed state ciphertext exceeds the size limit".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|_| HubError::State("state cipher initialization failed".into()))?;
        let decrypted = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &self.aad(),
            },
        );
        ciphertext.zeroize();
        let mut plaintext = decrypted
            .map_err(|_| HubError::State("sealed Hub state authentication failed".into()))?;
        if plaintext.len() > MAX_PLAINTEXT_STATE_BYTES {
            plaintext.zeroize();
            return Err(HubError::State(
                "Hub state plaintext exceeds the size limit".into(),
            ));
        }
        let state = serde_json::from_slice(&plaintext)
            .map_err(|_| HubError::State("decrypted Hub state is malformed".into()));
        plaintext.zeroize();
        state
    }
    fn save(&self, state: &HubPersistedState) -> HubResult<()> {
        let mut plaintext =
            serde_json::to_vec(state).map_err(|error| HubError::State(error.to_string()))?;
        if plaintext.len() > MAX_PLAINTEXT_STATE_BYTES {
            plaintext.zeroize();
            return Err(HubError::State(
                "Hub state plaintext exceeds the size limit".into(),
            ));
        }
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|_| HubError::State("state cipher initialization failed".into()))?;
        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &self.aad(),
            },
        );
        plaintext.zeroize();
        let mut ciphertext =
            encrypted.map_err(|_| HubError::State("Hub state encryption failed".into()))?;
        let ciphertext_hex = hex::encode(&ciphertext);
        ciphertext.zeroize();
        let envelope = SealedStateFileV1 {
            format: FORMAT.into(),
            key_id: self.key_id.clone(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex,
        };
        let bytes = serde_json::to_vec_pretty(&envelope)
            .map_err(|error| HubError::State(error.to_string()))?;
        if bytes.len() as u64 > MAX_SEALED_STATE_BYTES {
            return Err(HubError::State(
                "sealed Hub state exceeds the size limit".into(),
            ));
        }
        save_bytes_atomic(&self.path, &bytes)
    }
    fn validate_envelope(&self, envelope: &SealedStateFileV1) -> HubResult<()> {
        if envelope.format != FORMAT || envelope.key_id != self.key_id {
            return Err(HubError::State(
                "sealed Hub state format or key identifier mismatch".into(),
            ));
        }
        Ok(())
    }
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        for field in [
            FORMAT.as_bytes(),
            self.key_id.as_bytes(),
            self.hub_address.as_bytes(),
            &0u32.to_be_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u64).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }
}
/// Offline, lock-protected and restart-safe plaintext-to-sealed state migration.
///
/// The authenticated journal/checkpoint is verified before replacement. The
/// exact plaintext file is retained as a private backup, the sealed candidate
/// is decrypted and commitment-checked, and only then atomically replaces it.
pub fn migrate_plaintext_state_to_sealed(
    path: &Path,
    hub_address: &str,
    journal_key_hex: &str,
    state_key_hex: &str,
) -> HubResult<PathBuf> {
    if journal_key_hex
        .trim()
        .eq_ignore_ascii_case(state_key_hex.trim())
    {
        return Err(HubError::State(
            "journal and state encryption keys must be independent".into(),
        ));
    }
    if !path.exists() {
        return Err(HubError::State(
            "plaintext Hub state file does not exist".into(),
        ));
    }
    let _lock = acquire_state_lock(path)?;
    ensure_not_symlink(path, "plaintext Hub state file")?;
    let original = fs::read(path).map_err(|error| HubError::State(error.to_string()))?;
    let backup_path = path.with_extension("plaintext-pre-seal.backup");
    ensure_not_symlink(&backup_path, "plaintext migration backup")?;
    if backup_path.exists() {
        let existing =
            fs::read(&backup_path).map_err(|error| HubError::State(error.to_string()))?;
        if existing != original {
            return Err(HubError::State(
                "plaintext migration backup exists with different contents".into(),
            ));
        }
    } else {
        save_bytes_atomic(&backup_path, &original)?;
    }

    let plaintext_store = StateStore::plaintext(path.to_path_buf());
    let mut state = plaintext_store.load()?;
    let mut journal_key = hex::decode(journal_key_hex.trim())
        .map_err(|_| HubError::State("journal storage key must be hex".into()))?;
    if journal_key.len() != 32 {
        journal_key.zeroize();
        return Err(HubError::State(
            "journal storage key must decode to exactly 32 bytes".into(),
        ));
    }
    let journal = crate::journal::AuthenticatedJournal::open(
        path.with_extension("journal.jsonl"),
        &journal_key,
        crate::journal::JournalBinding {
            wallet_scope: format!("hub:{}", hub_address.trim()),
            hub_or_provider_identity: hub_address.trim().to_owned(),
            channel_id: None,
        },
    );
    journal_key.zeroize();
    let journal = journal?;
    initialize_authenticated_state(&plaintext_store, &mut state, &journal, hub_address)?;

    let expected_commitment = crate::storage::state_commitment(&state)?;
    let candidate_path = path.with_extension("sealed-migration-v1.tmp");
    ensure_not_symlink(&candidate_path, "sealed migration candidate")?;
    let candidate = EncryptedStateStore::new(candidate_path.clone(), state_key_hex, hub_address)?;
    candidate.save(&state)?;
    let verified = candidate.load()?;
    if crate::storage::state_commitment(&verified)? != expected_commitment {
        return Err(HubError::State(
            "sealed migration verification commitment mismatch".into(),
        ));
    }
    let sealed_bytes =
        fs::read(&candidate_path).map_err(|error| HubError::State(error.to_string()))?;
    save_bytes_atomic(path, &sealed_bytes)?;
    let final_store = EncryptedStateStore::new(path.to_path_buf(), state_key_hex, hub_address)?;
    if crate::storage::state_commitment(&final_store.load()?)? != expected_commitment {
        return Err(HubError::State(
            "sealed migration final verification failed".into(),
        ));
    }
    fs::remove_file(&candidate_path).map_err(|error| HubError::State(error.to_string()))?;
    Ok(backup_path)
}
fn decode_fixed<const N: usize>(value: &str, label: &str) -> HubResult<[u8; N]> {
    let decoded = hex::decode(value).map_err(|_| HubError::State(format!("{label} is not hex")))?;
    decoded
        .try_into()
        .map_err(|_| HubError::State(format!("{label} has the wrong length")))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_state_roundtrips_without_plaintext_and_uses_fresh_nonces() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub-state.json");
        let store = StateStore::sealed(path.clone(), &"11".repeat(32), "hub-address").unwrap();
        let mut state = HubPersistedState::default();
        state.completed_request_commitments.insert(
            "known-plaintext-marker".into(),
            "secret-signed-state-marker".into(),
        );
        store.save(&state).unwrap();
        let first = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&first).contains("secret-signed-state-marker"));
        assert_eq!(
            store.load().unwrap().completed_request_commitments,
            state.completed_request_commitments
        );
        store.save(&state).unwrap();
        let second = fs::read(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            store.load().unwrap().completed_request_commitments,
            state.completed_request_commitments
        );
    }
    #[test]
    fn authenticated_plaintext_migration_keeps_backup_and_verifies_sealed_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub-state.json");
        let hub = "migration-hub";
        let journal_key = "22".repeat(32);
        let state_key = "33".repeat(32);
        let plaintext_store = StateStore::plaintext(path.clone());
        let mut state = HubPersistedState::default();
        state.completed_request_commitments.insert(
            "migration-marker".into(),
            "authenticated-plaintext-value".into(),
        );
        plaintext_store.save(&state).unwrap();
        let journal = crate::journal::AuthenticatedJournal::open(
            path.with_extension("journal.jsonl"),
            &hex::decode(&journal_key).unwrap(),
            crate::journal::JournalBinding {
                wallet_scope: format!("hub:{hub}"),
                hub_or_provider_identity: hub.into(),
                channel_id: None,
            },
        )
        .unwrap();
        initialize_authenticated_state(&plaintext_store, &mut state, &journal, hub).unwrap();

        let backup =
            migrate_plaintext_state_to_sealed(&path, hub, &journal_key, &state_key).unwrap();
        let backup_raw = fs::read_to_string(&backup).unwrap();
        assert!(backup_raw.contains("authenticated-plaintext-value"));
        let final_raw = fs::read_to_string(&path).unwrap();
        assert!(!final_raw.contains("authenticated-plaintext-value"));
        let sealed = StateStore::sealed(path, &state_key, hub).unwrap();
        assert_eq!(
            sealed
                .load()
                .unwrap()
                .completed_request_commitments
                .get("migration-marker")
                .map(String::as_str),
            Some("authenticated-plaintext-value")
        );
    }

    #[test]
    fn wrong_key_hub_tampering_and_plaintext_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub-state.json");
        let store = StateStore::sealed(path.clone(), &"11".repeat(32), "hub-a").unwrap();
        store.save(&HubPersistedState::default()).unwrap();
        assert!(
            StateStore::sealed(path.clone(), &"22".repeat(32), "hub-a")
                .unwrap()
                .load()
                .is_err()
        );
        assert!(
            StateStore::sealed(path.clone(), &"11".repeat(32), "hub-b")
                .unwrap()
                .load()
                .is_err()
        );
        let mut raw = fs::read(&path).unwrap();
        let last = raw
            .iter_mut()
            .rfind(|byte| **byte == b'0' || **byte == b'1')
            .unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        fs::write(&path, raw).unwrap();
        assert!(store.load().is_err());
        fs::write(&path, b"{\"channels\":{},\"payments\":{}}" as &[u8]).unwrap();
        assert!(store.load().is_err());
    }
}
