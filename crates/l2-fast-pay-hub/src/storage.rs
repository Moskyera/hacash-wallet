//! Durable materialized state for the HPAY Wallet Hub API v4.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::amount::HacAmount;
use crate::api::FastPayResponse;
use crate::error::{HubError, HubResult};
use crate::journal::{
    AuthenticatedJournal, JournalEvent, JournalHead, JournalOperationType, JournalPhase,
};
use crate::operation::{IdempotencyRecord, ReservationStatus};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub(crate) struct ChannelLedger {
    pub left_balance_mei: HacAmount,
    pub right_balance_mei: HacAmount,
    pub bill_auto_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingSettlement {
    pub created_at: u64,
    #[serde(default)]
    pub operation_id: String,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub request_commitment: String,
    #[serde(default = "legacy_recovery_status")]
    pub status: ReservationStatus,
    #[serde(default)]
    pub unsigned_state_commitment: String,
    #[serde(default)]
    pub payer: String,
    #[serde(default)]
    pub payee: String,
    #[serde(default)]
    pub amount: String,
    pub channel_id: String,
    #[serde(default)]
    pub channel_reuse_version: u64,
    pub base_ledger: ChannelLedger,
    pub next_ledger: ChannelLedger,
    #[serde(default)]
    pub payee_channel_id: Option<String>,
    #[serde(default)]
    pub payee_base_ledger: Option<ChannelLedger>,
    #[serde(default)]
    pub payee_next_ledger: Option<ChannelLedger>,
    pub response: FastPayResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct HubPersistedState {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub journal_sequence: u64,
    #[serde(default)]
    pub journal_head: String,
    #[serde(default)]
    pub state_commitment: String,
    pub channels: HashMap<String, ChannelLedger>,
    pub payments: HashMap<String, FastPayResponse>,
    #[serde(default)]
    pub pending: HashMap<String, PendingSettlement>,
    #[serde(default)]
    pub idempotency: HashMap<String, IdempotencyRecord>,
    #[serde(default)]
    pub completed_request_commitments: HashMap<String, String>,
}

pub(crate) fn state_commitment(state: &HubPersistedState) -> HubResult<String> {
    let mut value =
        serde_json::to_value(state).map_err(|error| HubError::State(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| HubError::State("materialized state is not an object".into()))?;
    object.remove("journal_sequence");
    object.remove("journal_head");
    object.remove("state_commitment");
    let canonical =
        serde_json::to_vec(&value).map_err(|error| HubError::State(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

pub(crate) fn acquire_state_lock(path: &Path) -> HubResult<fs::File> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| HubError::State("hub state path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| HubError::State(error.to_string()))?;
    ensure_not_symlink(parent, "hub state directory")?;
    let lock_path = path.with_extension("lock");
    ensure_not_symlink(&lock_path, "hub state lock")?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| HubError::State(error.to_string()))?;
    file.try_lock_exclusive().map_err(|error| {
        HubError::State(format!(
            "another Fast Pay hub process already owns this state: {error}"
        ))
    })?;
    Ok(file)
}

pub(crate) fn initialize_authenticated_state(
    state_path: &Path,
    state: &mut HubPersistedState,
    journal: &AuthenticatedJournal,
    hub_address: &str,
) -> HubResult<()> {
    let had_authenticated_state = state.schema_version != 0
        || state.journal_sequence != 0
        || !state.journal_head.is_empty()
        || !state.state_commitment.is_empty();
    let records = journal.verify()?;
    let checkpoint = journal.read_checkpoint()?;
    if records.is_empty() {
        if had_authenticated_state || checkpoint.is_some() {
            return Err(HubError::State("JournalSequenceRollback".into()));
        }
        state.schema_version = 1;
        let current_commitment = state_commitment(state)?;
        backup_legacy_state(state_path)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", hub_address.trim()),
            hub_or_provider_identity: hub_address.trim().to_owned(),
            channel_id: "__migration__".into(),
            channel_reuse_version: 0,
            operation_id: "legacy-state-migration-v1".into(),
            operation_type: JournalOperationType::Migration,
            operation_phase: JournalPhase::ReconciliationCompleted,
            amount_units: 0,
            sender: String::new(),
            recipient: String::new(),
            previous_state_commitment: current_commitment.clone(),
            new_state_commitment: current_commitment.clone(),
            idempotency_key: "legacy-state-migration-v1".into(),
            request_commitment: current_commitment.clone(),
            expected_bill_number: None,
            unsigned_state_commitment: None,
            created_at: unix_timestamp(),
        })?;
        state.journal_sequence = record.entry_sequence;
        state.journal_head = record.entry_hash.clone();
        state.state_commitment = current_commitment.clone();
        save_state_file(state_path, state)?;
        journal.write_checkpoint(&JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: current_commitment,
        })?;
        return Ok(());
    }
    if state.schema_version != 1 {
        return Err(HubError::State(
            "authenticated L2 state schema is invalid".into(),
        ));
    }
    let current_commitment = state_commitment(state)?;
    let last = records
        .last()
        .ok_or_else(|| HubError::State("journal head missing".into()))?;
    if let Some(checkpoint) = &checkpoint {
        if checkpoint.sequence > last.entry_sequence {
            return Err(HubError::State("JournalSequenceRollback".into()));
        }
        if checkpoint.sequence == last.entry_sequence && checkpoint.entry_hash != last.entry_hash {
            return Err(HubError::State("JournalChainBroken".into()));
        }
    }

    if state.journal_sequence != last.entry_sequence || state.journal_head != last.entry_hash {
        if last.new_state_commitment == current_commitment {
            state.journal_sequence = last.entry_sequence;
            state.journal_head = last.entry_hash.clone();
            state.state_commitment = current_commitment.clone();
            save_state_file(state_path, state)?;
        } else {
            return Err(HubError::State("StateCommitmentMismatch".into()));
        }
    }
    if state.state_commitment != current_commitment
        || last.new_state_commitment != current_commitment
    {
        return Err(HubError::State("StateCommitmentMismatch".into()));
    }
    let head = JournalHead {
        sequence: last.entry_sequence,
        entry_hash: last.entry_hash.clone(),
        state_commitment: current_commitment,
    };
    if checkpoint.as_ref() != Some(&head) {
        journal.write_checkpoint(&head)?;
    }
    Ok(())
}

fn backup_legacy_state(path: &Path) -> HubResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let backup = path.with_extension("legacy-v0.backup");
    let original = fs::read(path).map_err(|error| HubError::State(error.to_string()))?;
    if backup.exists() {
        let existing = fs::read(&backup).map_err(|error| HubError::State(error.to_string()))?;
        if existing != original {
            return Err(HubError::State(
                "legacy migration backup exists with different contents".into(),
            ));
        }
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&backup)
        .map_err(|error| HubError::State(error.to_string()))?;
    file.write_all(&original)
        .and_then(|_| file.sync_all())
        .map_err(|error| HubError::State(error.to_string()))
}

fn legacy_recovery_status() -> ReservationStatus {
    ReservationStatus::RecoveryRequired
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn load_state_file(path: &Path) -> HubResult<HubPersistedState> {
    if !path.exists() {
        return Ok(HubPersistedState::default());
    }
    let raw = fs::read_to_string(path).map_err(|error| HubError::State(error.to_string()))?;
    serde_json::from_str(&raw).map_err(|error| HubError::State(error.to_string()))
}

pub(crate) fn save_state_file(path: &Path, state: &HubPersistedState) -> HubResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| HubError::State("hub state path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| HubError::State(error.to_string()))?;
    ensure_not_symlink(parent, "hub state directory")?;
    ensure_not_symlink(path, "hub state file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| HubError::State(error.to_string()))?;
    }

    let json =
        serde_json::to_vec_pretty(state).map_err(|error| HubError::State(error.to_string()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| HubError::State("hub state path has no filename".into()))?
        .to_string_lossy();
    let temp_path = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }

        let mut file = options
            .open(&temp_path)
            .map_err(|error| HubError::State(error.to_string()))?;
        file.write_all(&json)
            .and_then(|_| file.sync_all())
            .map_err(|error| HubError::State(error.to_string()))?;
        drop(file);
        ensure_not_symlink(path, "hub state file")?;
        atomic_replace(&temp_path, path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|error| HubError::State(error.to_string()))?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| HubError::State(error.to_string()))?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn ensure_not_symlink(path: &Path, label: &str) -> HubResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(HubError::State(format!("{label} must not be a symlink")))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HubError::State(error.to_string())),
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> HubResult<()> {
    fs::rename(source, destination).map_err(|error| HubError::State(error.to_string()))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> HubResult<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(HubError::State(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_float_state_migrates_without_reset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub-state.json");
        fs::write(
            &path,
            r#"{
              "channels": {
                "channel": {
                  "left_balance_mei": 7.498,
                  "right_balance_mei": 2.002,
                  "bill_auto_number": 9
                }
              },
              "payments": {},
              "pending": {}
            }"#,
        )
        .unwrap();

        let state = load_state_file(&path).unwrap();
        let ledger = state.channels.get("channel").unwrap();
        assert_eq!(ledger.left_balance_mei.as_millimeis(), 7_498);
        assert_eq!(ledger.right_balance_mei.as_millimeis(), 2_002);
        save_state_file(&path, &state).unwrap();
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(migrated.contains(r#""left_balance_mei": "7.498""#));
        assert!(migrated.contains(r#""right_balance_mei": "2.002""#));
    }

    #[test]
    fn state_replacement_is_atomic_and_leaves_no_temp_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub-state.json");
        save_state_file(&path, &HubPersistedState::default()).unwrap();
        save_state_file(&path, &HubPersistedState::default()).unwrap();
        let leftovers = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }
}
