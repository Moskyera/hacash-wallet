//! Durable, authenticated append journal for Fast Pay state transitions.
//!
//! Records are hash chained and HMAC authenticated. The authentication key is
//! domain-separated from its caller-provided storage master key. A separately
//! authenticated checkpoint detects an older journal when the checkpoint is
//! still current. Complete rollback of every local file still requires an
//! external monotonic anchor and is therefore reported as a deployment
//! requirement rather than hidden behind a false local-only guarantee.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{HubError, HubResult};

const AUTH_DOMAIN: &[u8] = b"HPAY/L2/JOURNAL/AUTH/V1";
const CHECKPOINT_DOMAIN: &[u8] = b"HPAY/L2/JOURNAL/CHECKPOINT/V1";
const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalBinding {
    pub wallet_scope: String,
    pub hub_or_provider_identity: String,
    pub channel_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationType {
    Migration,
    FastPay,
    RecipientConfirmation,
    Recovery,
    Reconciliation,
    L1ChannelOpen,
    L1ChannelClose,
    HvmChannelActivation,
    HvmPayment,
    HvmWatchtower,
    HvmLeaseRenewal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    PaymentIntentCreated,
    FundsReserved,
    RecipientConfirmed,
    UnsignedStatePrepared,
    StatePersistedBeforeSigning,
    SignatureProduced,
    PaymentSubmitted,
    PaymentAcknowledged,
    PaymentCommitted,
    PaymentRejected,
    PaymentExpired,
    ReservationReleased,
    RecoveryStarted,
    RecoveryCompleted,
    ReconciliationCompleted,
    L1IntentValidated,
    L1OpenAbandonedUnsigned,
    L1OpenSignatureMayExist,
    L1SignatureProduced,
    L1OpenSubmissionStarted,
    L1OpenSubmitted,
    L1OpenConfirmed,
    L1OpenRecoveryRequired,
    L1CloseFreezeIntentPersisted,
    L1CloseFrozenBeforeSigning,
    L1CloseSignatureMayExist,
    L1CloseSubmissionStarted,
    L1CloseSubmitted,
    L1CloseConfirmed,
    L1CloseRetired,
    L1CloseRecoveryRequired,
    /// A channel-close voucher was reserved for one channel and made durable
    /// before the Hub signer was called. The entry alone bars this channel from
    /// ever being issued a second voucher, whether or not the signature that
    /// followed survived.
    L1CloseVoucherSignatureMayExist,
    /// The exact countersigned delta-zero close bytes were made durable and
    /// handed to the owner. Nothing was broadcast, and the channel stays open.
    L1CloseVoucherIssued,
    HvmChannelActivated,
    HvmPaymentProposalPersisted,
    HvmPaymentSignatureMayExist,
    HvmPaymentFullySigned,
    HvmChainIntentPersisted,
    HvmChainSignatureMayExist,
    HvmChainSigned,
    HvmChainSubmissionStarted,
    HvmChainSubmitted,
    HvmChainConfirmed,
    HvmChainRecoveryRequired,
    /// A signed chain transaction was proven inadmissible by a consensus rule
    /// that block verification itself applies, read from the chain one last
    /// time and found absent, and retired to a terminal state so a correct
    /// replacement can be signed.
    HvmChainAbandonedInadmissible,
    /// The exact external rollback anchor request was made durable before it
    /// went on the wire. A receipt that matches no such record matches
    /// nothing.
    RollbackAnchorRequestPersisted,
    /// The witness's signed receipt was verified and made durable together
    /// with the advanced counter, before the signing key was used.
    RollbackAnchorReceiptPersisted,
    /// The witness refused. The channel is latched and will not sign again
    /// without `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`.
    RollbackAnchorRefused,
}

#[derive(Debug, Clone)]
pub struct JournalEvent {
    pub wallet_scope: String,
    pub hub_or_provider_identity: String,
    pub channel_id: String,
    pub channel_reuse_version: u64,
    pub operation_id: String,
    pub operation_type: JournalOperationType,
    pub operation_phase: JournalPhase,
    pub amount_units: u64,
    pub sender: String,
    pub recipient: String,
    pub previous_state_commitment: String,
    pub new_state_commitment: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub expected_bill_number: Option<u64>,
    pub unsigned_state_commitment: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalRecord {
    pub journal_version: u32,
    pub entry_sequence: u64,
    pub previous_entry_hash: String,
    pub entry_hash: String,
    pub wallet_scope: String,
    pub hub_or_provider_identity: String,
    pub channel_id: String,
    pub channel_reuse_version: u64,
    pub operation_id: String,
    pub operation_type: JournalOperationType,
    pub operation_phase: JournalPhase,
    pub amount_units: u64,
    pub sender: String,
    pub recipient: String,
    pub previous_state_commitment: String,
    pub new_state_commitment: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub expected_bill_number: Option<u64>,
    pub unsigned_state_commitment: Option<String>,
    pub created_at: u64,
    pub authentication_tag: String,
}

#[derive(Debug, Clone, Serialize)]
struct RecordBody<'a> {
    journal_version: u32,
    entry_sequence: u64,
    previous_entry_hash: &'a str,
    wallet_scope: &'a str,
    hub_or_provider_identity: &'a str,
    channel_id: &'a str,
    channel_reuse_version: u64,
    operation_id: &'a str,
    operation_type: JournalOperationType,
    operation_phase: JournalPhase,
    amount_units: u64,
    sender: &'a str,
    recipient: &'a str,
    previous_state_commitment: &'a str,
    new_state_commitment: &'a str,
    idempotency_key: &'a str,
    request_commitment: &'a str,
    expected_bill_number: Option<u64>,
    unsigned_state_commitment: Option<&'a str>,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalHead {
    pub sequence: u64,
    pub entry_hash: String,
    pub state_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthenticatedCheckpoint {
    version: u32,
    wallet_scope: String,
    hub_or_provider_identity: String,
    sequence: u64,
    entry_hash: String,
    state_commitment: String,
    authentication_tag: String,
}

pub struct AuthenticatedJournal {
    path: PathBuf,
    checkpoint_path: PathBuf,
    binding: JournalBinding,
    auth_key: Zeroizing<[u8; 32]>,
}

impl AuthenticatedJournal {
    pub fn open(
        path: impl Into<PathBuf>,
        storage_master_key: &[u8],
        binding: JournalBinding,
    ) -> HubResult<Self> {
        if storage_master_key.len() < 32 {
            return Err(HubError::State(
                "journal storage master key must contain at least 32 bytes".into(),
            ));
        }
        if binding.wallet_scope.trim().is_empty()
            || binding.hub_or_provider_identity.trim().is_empty()
        {
            return Err(HubError::State(
                "journal wallet scope and provider identity are required".into(),
            ));
        }
        let path = path.into();
        let checkpoint_path = path.with_extension("checkpoint.json");
        let auth_key = derive_auth_key(storage_master_key, &binding)?;
        let journal = Self {
            path,
            checkpoint_path,
            binding,
            auth_key,
        };
        journal.ensure_parent()?;
        journal.verify()?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify(&self) -> HubResult<Vec<JournalRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        reject_symlink(&self.path, "L2 journal")?;
        let metadata =
            fs::metadata(&self.path).map_err(|error| HubError::State(error.to_string()))?;
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(HubError::State("L2 journal exceeds the size limit".into()));
        }
        let raw = fs::read(&self.path).map_err(|error| HubError::State(error.to_string()))?;
        if !raw.is_empty() && !raw.ends_with(b"\n") {
            return Err(HubError::State(
                "JournalTruncated: final record is incomplete".into(),
            ));
        }

        let mut records = Vec::new();
        let mut expected_sequence = 1_u64;
        let mut previous_hash = String::new();
        let mut previous_state_commitment: Option<String> = None;
        for line in raw
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if line.len() > MAX_RECORD_BYTES {
                return Err(HubError::State("L2 journal record is oversized".into()));
            }
            let record: JournalRecord = serde_json::from_slice(line)
                .map_err(|_| HubError::State("JournalAuthenticationFailed".into()))?;
            if record.journal_version != JOURNAL_VERSION {
                return Err(HubError::State("unsupported L2 journal version".into()));
            }
            if record.entry_sequence != expected_sequence {
                return Err(HubError::State("JournalSequenceRollback".into()));
            }
            if record.previous_entry_hash != previous_hash {
                return Err(HubError::State("JournalChainBroken".into()));
            }
            if previous_state_commitment
                .as_ref()
                .is_some_and(|expected| expected != &record.previous_state_commitment)
            {
                return Err(HubError::State("StateCommitmentMismatch".into()));
            }
            self.verify_binding(&record)?;
            let expected_hash = record_hash(&record)?;
            if record.entry_hash != expected_hash {
                return Err(HubError::State("JournalAuthenticationFailed".into()));
            }
            verify_tag(
                &self.auth_key[..],
                &record.entry_hash,
                &record.authentication_tag,
            )?;
            previous_hash = record.entry_hash.clone();
            previous_state_commitment = Some(record.new_state_commitment.clone());
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| HubError::State("journal sequence overflow".into()))?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn append(&self, event: JournalEvent) -> HubResult<JournalRecord> {
        self.verify_event_binding(&event)?;
        let records = self.verify()?;
        let entry_sequence = records.last().map_or(Ok(1_u64), |record| {
            record
                .entry_sequence
                .checked_add(1)
                .ok_or_else(|| HubError::State("journal sequence overflow".into()))
        })?;
        let previous_entry_hash = records
            .last()
            .map(|record| record.entry_hash.clone())
            .unwrap_or_default();
        if records
            .last()
            .is_some_and(|record| record.new_state_commitment != event.previous_state_commitment)
        {
            return Err(HubError::State("StateCommitmentMismatch".into()));
        }
        let mut record = JournalRecord {
            journal_version: JOURNAL_VERSION,
            entry_sequence,
            previous_entry_hash,
            entry_hash: String::new(),
            wallet_scope: event.wallet_scope,
            hub_or_provider_identity: event.hub_or_provider_identity,
            channel_id: event.channel_id,
            channel_reuse_version: event.channel_reuse_version,
            operation_id: event.operation_id,
            operation_type: event.operation_type,
            operation_phase: event.operation_phase,
            amount_units: event.amount_units,
            sender: event.sender,
            recipient: event.recipient,
            previous_state_commitment: event.previous_state_commitment,
            new_state_commitment: event.new_state_commitment,
            idempotency_key: event.idempotency_key,
            request_commitment: event.request_commitment,
            expected_bill_number: event.expected_bill_number,
            unsigned_state_commitment: event.unsigned_state_commitment,
            created_at: event.created_at,
            authentication_tag: String::new(),
        };
        record.entry_hash = record_hash(&record)?;
        record.authentication_tag = compute_tag(&self.auth_key[..], &record.entry_hash)?;
        let mut encoded =
            serde_json::to_vec(&record).map_err(|error| HubError::State(error.to_string()))?;
        encoded.push(b'\n');
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(HubError::State("L2 journal record is oversized".into()));
        }
        reject_symlink(&self.path, "L2 journal")?;
        let current_len = if self.path.exists() {
            fs::metadata(&self.path)
                .map_err(|error| HubError::State(error.to_string()))?
                .len()
        } else {
            0
        };
        let projected_len = current_len
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| HubError::State("L2 journal size overflow".into()))?;
        if projected_len > MAX_JOURNAL_BYTES {
            return Err(HubError::State(
                "L2 journal append would exceed the size limit".into(),
            ));
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|error| HubError::State(error.to_string()))?;
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|error| HubError::State(error.to_string()))?;
        restrict_file_permissions(&self.path)?;
        sync_parent(
            self.path
                .parent()
                .ok_or_else(|| HubError::State("journal path has no parent".into()))?,
        )?;
        Ok(record)
    }

    pub fn write_checkpoint(&self, head: &JournalHead) -> HubResult<()> {
        let mut checkpoint = AuthenticatedCheckpoint {
            version: JOURNAL_VERSION,
            wallet_scope: self.binding.wallet_scope.clone(),
            hub_or_provider_identity: self.binding.hub_or_provider_identity.clone(),
            sequence: head.sequence,
            entry_hash: head.entry_hash.clone(),
            state_commitment: head.state_commitment.clone(),
            authentication_tag: String::new(),
        };
        let payload = checkpoint_payload(&checkpoint)?;
        checkpoint.authentication_tag =
            compute_domain_tag(&self.auth_key[..], CHECKPOINT_DOMAIN, &payload)?;
        let bytes =
            serde_json::to_vec(&checkpoint).map_err(|error| HubError::State(error.to_string()))?;
        durable_replace(&self.checkpoint_path, &bytes)
    }

    pub fn read_checkpoint(&self) -> HubResult<Option<JournalHead>> {
        if !self.checkpoint_path.exists() {
            return Ok(None);
        }
        reject_symlink(&self.checkpoint_path, "L2 journal checkpoint")?;
        let raw =
            fs::read(&self.checkpoint_path).map_err(|error| HubError::State(error.to_string()))?;
        if raw.len() > MAX_RECORD_BYTES {
            return Err(HubError::State("L2 checkpoint is oversized".into()));
        }
        let checkpoint: AuthenticatedCheckpoint = serde_json::from_slice(&raw)
            .map_err(|_| HubError::State("JournalAuthenticationFailed".into()))?;
        if checkpoint.version != JOURNAL_VERSION
            || checkpoint.wallet_scope != self.binding.wallet_scope
            || checkpoint.hub_or_provider_identity != self.binding.hub_or_provider_identity
        {
            return Err(HubError::State("ForeignWalletStateDetected".into()));
        }
        let payload = checkpoint_payload(&checkpoint)?;
        verify_domain_tag(
            &self.auth_key[..],
            CHECKPOINT_DOMAIN,
            &payload,
            &checkpoint.authentication_tag,
        )?;
        Ok(Some(JournalHead {
            sequence: checkpoint.sequence,
            entry_hash: checkpoint.entry_hash,
            state_commitment: checkpoint.state_commitment,
        }))
    }

    fn ensure_parent(&self) -> HubResult<()> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| HubError::State("journal path has no parent".into()))?;
        fs::create_dir_all(parent).map_err(|error| HubError::State(error.to_string()))?;
        reject_symlink(parent, "L2 journal directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| HubError::State(error.to_string()))?;
        }
        Ok(())
    }

    fn verify_binding(&self, record: &JournalRecord) -> HubResult<()> {
        if record.wallet_scope != self.binding.wallet_scope
            || record.hub_or_provider_identity != self.binding.hub_or_provider_identity
            || self
                .binding
                .channel_id
                .as_ref()
                .is_some_and(|channel| channel != &record.channel_id)
        {
            return Err(HubError::State("ForeignWalletStateDetected".into()));
        }
        Ok(())
    }

    fn verify_event_binding(&self, event: &JournalEvent) -> HubResult<()> {
        if event.wallet_scope != self.binding.wallet_scope
            || event.hub_or_provider_identity != self.binding.hub_or_provider_identity
            || self
                .binding
                .channel_id
                .as_ref()
                .is_some_and(|channel| channel != &event.channel_id)
        {
            return Err(HubError::State("ForeignWalletStateDetected".into()));
        }
        Ok(())
    }
}

fn derive_auth_key(
    storage_master_key: &[u8],
    binding: &JournalBinding,
) -> HubResult<Zeroizing<[u8; 32]>> {
    let mut salt = Sha256::new();
    salt.update(AUTH_DOMAIN);
    hash_field(&mut salt, binding.wallet_scope.as_bytes());
    hash_field(&mut salt, binding.hub_or_provider_identity.as_bytes());
    if let Some(channel) = &binding.channel_id {
        hash_field(&mut salt, channel.as_bytes());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), storage_master_key);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(AUTH_DOMAIN, output.as_mut())
        .map_err(|_| HubError::State("journal key derivation failed".into()))?;
    Ok(output)
}

fn record_hash(record: &JournalRecord) -> HubResult<String> {
    let body = RecordBody {
        journal_version: record.journal_version,
        entry_sequence: record.entry_sequence,
        previous_entry_hash: &record.previous_entry_hash,
        wallet_scope: &record.wallet_scope,
        hub_or_provider_identity: &record.hub_or_provider_identity,
        channel_id: &record.channel_id,
        channel_reuse_version: record.channel_reuse_version,
        operation_id: &record.operation_id,
        operation_type: record.operation_type,
        operation_phase: record.operation_phase,
        amount_units: record.amount_units,
        sender: &record.sender,
        recipient: &record.recipient,
        previous_state_commitment: &record.previous_state_commitment,
        new_state_commitment: &record.new_state_commitment,
        idempotency_key: &record.idempotency_key,
        request_commitment: &record.request_commitment,
        expected_bill_number: record.expected_bill_number,
        unsigned_state_commitment: record.unsigned_state_commitment.as_deref(),
        created_at: record.created_at,
    };
    let encoded = serde_json::to_vec(&body).map_err(|error| HubError::State(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn checkpoint_payload(checkpoint: &AuthenticatedCheckpoint) -> HubResult<Vec<u8>> {
    serde_json::to_vec(&(
        checkpoint.version,
        &checkpoint.wallet_scope,
        &checkpoint.hub_or_provider_identity,
        checkpoint.sequence,
        &checkpoint.entry_hash,
        &checkpoint.state_commitment,
    ))
    .map_err(|error| HubError::State(error.to_string()))
}

fn compute_tag(key: &[u8], entry_hash: &str) -> HubResult<String> {
    compute_domain_tag(key, AUTH_DOMAIN, entry_hash.as_bytes())
}

fn compute_domain_tag(key: &[u8], domain: &[u8], payload: &[u8]) -> HubResult<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| HubError::State("journal authentication key rejected".into()))?;
    mac.update(domain);
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_tag(key: &[u8], entry_hash: &str, tag: &str) -> HubResult<()> {
    verify_domain_tag(key, AUTH_DOMAIN, entry_hash.as_bytes(), tag)
}

fn verify_domain_tag(key: &[u8], domain: &[u8], payload: &[u8], tag: &str) -> HubResult<()> {
    let decoded =
        hex::decode(tag).map_err(|_| HubError::State("JournalAuthenticationFailed".into()))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| HubError::State("journal authentication key rejected".into()))?;
    mac.update(domain);
    mac.update(payload);
    mac.verify_slice(&decoded)
        .map_err(|_| HubError::State("JournalAuthenticationFailed".into()))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn durable_replace(path: &Path, bytes: &[u8]) -> HubResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| HubError::State("checkpoint path has no parent".into()))?;
    let name = path
        .file_name()
        .ok_or_else(|| HubError::State("checkpoint path has no filename".into()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| HubError::State(error.to_string()))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| HubError::State(error.to_string()))?;
        drop(file);
        atomic_replace(&temporary, path)?;
        restrict_file_permissions(path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reject_symlink(path: &Path, label: &str) -> HubResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(HubError::State(format!("{label} must not be a symlink")))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HubError::State(error.to_string())),
    }
}

fn restrict_file_permissions(path: &Path) -> HubResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| HubError::State(error.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> HubResult<()> {
    #[cfg(unix)]
    {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| HubError::State(error.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
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
    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(HubError::State(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

impl Drop for AuthenticatedJournal {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(channel: Option<&str>) -> JournalBinding {
        JournalBinding {
            wallet_scope: "wallet-a".into(),
            hub_or_provider_identity: "hub-a".into(),
            channel_id: channel.map(str::to_owned),
        }
    }

    fn event(sequence: u64) -> JournalEvent {
        JournalEvent {
            wallet_scope: "wallet-a".into(),
            hub_or_provider_identity: "hub-a".into(),
            channel_id: "channel-a".into(),
            channel_reuse_version: 1,
            operation_id: format!("operation-{sequence}"),
            operation_type: JournalOperationType::FastPay,
            operation_phase: JournalPhase::FundsReserved,
            amount_units: sequence,
            sender: "payer".into(),
            recipient: "payee".into(),
            previous_state_commitment: format!("state-{}", sequence - 1),
            new_state_commitment: format!("state-{sequence}"),
            idempotency_key: format!("key-{sequence}"),
            request_commitment: format!("request-{sequence}"),
            expected_bill_number: Some(sequence),
            unsigned_state_commitment: Some(format!("unsigned-{sequence}")),
            created_at: sequence,
        }
    }

    fn journal(directory: &Path) -> AuthenticatedJournal {
        AuthenticatedJournal::open(
            directory.join("journal.jsonl"),
            &[7_u8; 32],
            binding(Some("channel-a")),
        )
        .unwrap()
    }

    #[test]
    fn valid_authenticated_chain_and_checkpoint_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let first = journal.append(event(1)).unwrap();
        let second = journal.append(event(2)).unwrap();
        assert_eq!(journal.verify().unwrap().len(), 2);
        let head = JournalHead {
            sequence: second.entry_sequence,
            entry_hash: second.entry_hash,
            state_commitment: "state-2".into(),
        };
        journal.write_checkpoint(&head).unwrap();
        assert_eq!(journal.read_checkpoint().unwrap(), Some(head));
        assert_eq!(first.entry_sequence, 1);
    }

    #[test]
    fn modified_checkpoint_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        let record = journal.append(event(1)).unwrap();
        journal
            .write_checkpoint(&JournalHead {
                sequence: record.entry_sequence,
                entry_hash: record.entry_hash,
                state_commitment: "state-1".into(),
            })
            .unwrap();

        let checkpoint_path = directory.path().join("journal.checkpoint.json");
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
        checkpoint["state_commitment"] = serde_json::json!("attacker-state");
        fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();

        assert!(
            journal
                .read_checkpoint()
                .unwrap_err()
                .to_string()
                .contains("Authentication")
        );
    }

    #[test]
    fn modified_entry_and_invalid_tag_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        journal.append(event(1)).unwrap();
        let mut line: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(journal.path()).unwrap()).unwrap();
        line["amount_units"] = serde_json::json!(999);
        fs::write(journal.path(), format!("{}\n", line)).unwrap();
        assert!(
            journal
                .verify()
                .unwrap_err()
                .to_string()
                .contains("Authentication")
        );
    }

    #[test]
    fn deleted_reordered_and_duplicated_entries_are_rejected() {
        for mode in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let journal = journal(directory.path());
            journal.append(event(1)).unwrap();
            journal.append(event(2)).unwrap();
            journal.append(event(3)).unwrap();
            let lines: Vec<_> = fs::read_to_string(journal.path())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect();
            let changed = match mode {
                0 => vec![lines[0].clone(), lines[2].clone()],
                1 => vec![lines[1].clone(), lines[0].clone(), lines[2].clone()],
                _ => vec![
                    lines[0].clone(),
                    lines[1].clone(),
                    lines[1].clone(),
                    lines[2].clone(),
                ],
            };
            fs::write(journal.path(), format!("{}\n", changed.join("\n"))).unwrap();
            assert!(journal.verify().is_err());
        }
    }

    #[test]
    fn truncated_final_entry_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        journal.append(event(1)).unwrap();
        let mut raw = fs::read(journal.path()).unwrap();
        raw.pop();
        fs::write(journal.path(), raw).unwrap();
        assert!(
            journal
                .verify()
                .unwrap_err()
                .to_string()
                .contains("Truncated")
        );
    }

    #[test]
    fn wrong_wallet_channel_or_key_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        journal.append(event(1)).unwrap();
        assert!(
            AuthenticatedJournal::open(
                journal.path(),
                &[7_u8; 32],
                JournalBinding {
                    wallet_scope: "wallet-b".into(),
                    ..binding(Some("channel-a"))
                }
            )
            .is_err()
        );
        assert!(
            AuthenticatedJournal::open(journal.path(), &[7_u8; 32], binding(Some("channel-b")))
                .is_err()
        );
        assert!(
            AuthenticatedJournal::open(journal.path(), &[8_u8; 32], binding(Some("channel-a")))
                .is_err()
        );
    }

    #[test]
    fn older_valid_journal_is_rejected_by_newer_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let journal = journal(directory.path());
        journal.append(event(1)).unwrap();
        let old = fs::read(journal.path()).unwrap();
        let second = journal.append(event(2)).unwrap();
        journal
            .write_checkpoint(&JournalHead {
                sequence: second.entry_sequence,
                entry_hash: second.entry_hash,
                state_commitment: "state-2".into(),
            })
            .unwrap();
        fs::write(journal.path(), old).unwrap();
        let records = journal.verify().unwrap();
        let checkpoint = journal.read_checkpoint().unwrap().unwrap();
        assert!(records.last().unwrap().entry_sequence < checkpoint.sequence);
    }
}
