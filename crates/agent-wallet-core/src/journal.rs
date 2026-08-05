//! Authenticated, tamper-evident journal for one Agent Wallet.
//!
//! This is deliberately separate from the Fast Pay/L2 journal. Records contain
//! only event categories and 32-byte commitments. Amounts, recipients, private
//! keys, approval tokens, raw transactions, and other sensitive payloads must
//! remain in their dedicated encrypted stores.
//!
//! Mutating methods require `&mut self`, but that cannot coordinate independent
//! processes. The owning Agent Wallet store must hold its per-wallet exclusive
//! lock for the complete read/verify/write operation. [`secure_write`] prevents
//! torn replacement of the journal file; it does not replace that store lock.
//!
//! The returned head hash can be anchored by the owning encrypted store. Without
//! such an external anchor, an authenticated hash chain detects modification,
//! truncation within a supplied file, and reordering, but cannot distinguish a
//! valid older snapshot from the latest snapshot.

use std::fs;
use std::path::{Path, PathBuf};

use hacash_wallet_core::paths::secure_write;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::WalletScope;

const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 65_536;
const MAX_RECORD_BYTES: usize = 2 * 1024;
const MAX_SCOPE_BYTES: usize = 96;
const ZERO_HASH: JournalCommitment = JournalCommitment([0_u8; 32]);

const KEY_DOMAIN: &[u8] = b"HPAY/AGENT/JOURNAL/KEY/V1";
const RECORD_HASH_DOMAIN: &[u8] = b"HPAY/AGENT/JOURNAL/RECORD-HASH/V1";
const RECORD_MAC_DOMAIN: &[u8] = b"HPAY/AGENT/JOURNAL/RECORD-MAC/V1";
const COMMITMENT_DOMAIN: &[u8] = b"HPAY/AGENT/JOURNAL/COMMITMENT/V1";

type HmacSha256 = Hmac<Sha256>;

/// A redacted reference to data that is stored elsewhere.
///
/// Callers should commit to an already-canonical representation and use a
/// stable, purpose-specific domain. This value is safe to persist in the
/// journal; the committed plaintext is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct JournalCommitment([u8; 32]);

impl JournalCommitment {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn commit(domain: &[u8], canonical_value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(COMMITMENT_DOMAIN);
        put_len_prefixed(&mut hasher, domain);
        put_len_prefixed(&mut hasher, canonical_value);
        Self(hasher.finalize().into())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for JournalCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for JournalCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "commitment must be exactly 32 lowercase hexadecimal bytes",
            ));
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut bytes).map_err(D::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// Fixed event vocabulary. It intentionally carries no free-form metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentJournalEventKind {
    WalletCreated,
    WalletLocked,
    WalletUnlocked,
    AgentPaired,
    AgentRevoked,
    AgentAuthenticationChallengeIssued,
    AgentAuthenticationSucceeded,
    AgentDisconnected,
    CompanionDevicePaired,
    CompanionDeviceRevoked,
    CompanionSessionChallengeReserved,
    CompanionSessionEstablished,
    CompanionTransportFrameConsumed,
    PolicyChanged,
    PaymentRequested,
    FundsReserved,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalRejected,
    TransactionPrepared,
    TransactionSigned,
    RollbackWitnessAccepted,
    RollbackWitnessInitialized,
    RollbackWitnessProposed,
    /// A pending anchor that expired before its receipt arrived was replaced by
    /// a fresh one for the same operation, at the same chain position.
    RollbackWitnessAnchorReissued,
    /// The owner abandoned a signed payment that was never broadcast and that no
    /// phone can still witness. It releases the reservation; it moves no money.
    RollbackWitnessAbandoned,
    /// A pending anchor that expired unwitnessed was dropped out of the single
    /// pending slot. The operation it named is untouched - same status, same
    /// `tx_hash`, same reservation - and still needs a real phone signature.
    RollbackWitnessAnchorReleased,
    RollbackWitnessArchived,
    PostSubmitWitnessProposed,
    PostSubmitWitnessAccepted,
    FinalWitnessProposed,
    FinalWitnessAccepted,
    TransactionSubmissionAcknowledged,
    TransactionReconciled,
    WitnessRotationPrepared,
    WitnessRotationAuthorized,
    WitnessRotationBaselineAccepted,
    WitnessRotationCompletionProposed,
    WitnessRotationCompleted,
    WitnessRecoveryRotationPrepared,
    WitnessRotationTicketIssued,
    WitnessRotationCandidateAccepted,
    WitnessRotationOldDeviceRevoked,
    WitnessRotationCancelled,
    WitnessRotationRetargeted,
    TransactionBroadcast,
    PaymentCommitted,
    PaymentFailed,
    EmergencyStopEnabled,
    EmergencyStopDisabled,
    OperationsExpired,
    OperationsCompacted,
    RecoveryRequired,
}

impl AgentJournalEventKind {
    fn code(self) -> u16 {
        match self {
            Self::WalletCreated => 1,
            Self::WalletLocked => 2,
            Self::WalletUnlocked => 3,
            Self::AgentPaired => 10,
            Self::AgentRevoked => 11,
            Self::AgentAuthenticationChallengeIssued => 12,
            Self::AgentAuthenticationSucceeded => 13,
            Self::AgentDisconnected => 14,
            Self::CompanionDevicePaired => 15,
            Self::CompanionDeviceRevoked => 16,
            Self::CompanionSessionChallengeReserved => 17,
            Self::CompanionSessionEstablished => 18,
            Self::CompanionTransportFrameConsumed => 19,
            Self::PolicyChanged => 20,
            Self::PaymentRequested => 30,
            Self::FundsReserved => 31,
            Self::ApprovalRequested => 32,
            Self::ApprovalGranted => 33,
            Self::ApprovalRejected => 34,
            Self::TransactionPrepared => 35,
            Self::TransactionSigned => 36,
            Self::RollbackWitnessAccepted => 44,
            Self::RollbackWitnessInitialized => 45,
            Self::RollbackWitnessProposed => 46,
            Self::RollbackWitnessArchived => 47,
            Self::PostSubmitWitnessProposed => 48,
            Self::PostSubmitWitnessAccepted => 49,
            Self::FinalWitnessProposed => 51,
            Self::FinalWitnessAccepted => 52,
            Self::TransactionSubmissionAcknowledged => 53,
            Self::TransactionReconciled => 54,
            Self::WitnessRotationPrepared => 60,
            Self::WitnessRotationAuthorized => 61,
            Self::WitnessRotationBaselineAccepted => 62,
            Self::WitnessRotationCompletionProposed => 63,
            Self::WitnessRotationCompleted => 64,
            Self::WitnessRecoveryRotationPrepared => 65,
            Self::WitnessRotationTicketIssued => 66,
            Self::WitnessRotationCandidateAccepted => 67,
            Self::WitnessRotationOldDeviceRevoked => 68,
            Self::WitnessRotationCancelled => 69,
            Self::WitnessRotationRetargeted => 70,
            Self::RollbackWitnessAnchorReissued => 71,
            Self::RollbackWitnessAbandoned => 72,
            Self::RollbackWitnessAnchorReleased => 73,
            Self::TransactionBroadcast => 37,
            Self::PaymentCommitted => 38,
            Self::PaymentFailed => 39,
            Self::EmergencyStopEnabled => 40,
            Self::EmergencyStopDisabled => 41,
            Self::OperationsExpired => 42,
            Self::OperationsCompacted => 43,
            Self::RecoveryRequired => 50,
        }
    }
}

/// Redacted event accepted by the journal.
///
/// The optional commitments may identify an operation, actor, or encrypted
/// metadata record without placing those values in plaintext in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentJournalEvent {
    pub(crate) kind: AgentJournalEventKind,
    pub(crate) operation_commitment: Option<JournalCommitment>,
    pub(crate) actor_commitment: Option<JournalCommitment>,
    pub(crate) metadata_commitment: Option<JournalCommitment>,
    pub(crate) previous_state_commitment: JournalCommitment,
    pub(crate) new_state_commitment: JournalCommitment,
    pub(crate) occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentJournalRecord {
    journal_version: u32,
    sequence: u64,
    previous_record_hash: JournalCommitment,
    wallet_scope: String,
    event_kind: AgentJournalEventKind,
    operation_commitment: Option<JournalCommitment>,
    actor_commitment: Option<JournalCommitment>,
    metadata_commitment: Option<JournalCommitment>,
    previous_state_commitment: JournalCommitment,
    new_state_commitment: JournalCommitment,
    occurred_at_unix_ms: u64,
    record_hash: JournalCommitment,
    authentication_tag: JournalCommitment,
}

impl AgentJournalRecord {
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    #[cfg(test)]
    pub(crate) fn event_kind(&self) -> AgentJournalEventKind {
        self.event_kind
    }

    pub(crate) fn record_hash(&self) -> JournalCommitment {
        self.record_hash
    }

    pub(crate) fn previous_record_hash(&self) -> JournalCommitment {
        self.previous_record_hash
    }

    pub(crate) fn previous_state_commitment(&self) -> JournalCommitment {
        self.previous_state_commitment
    }

    pub(crate) fn state_commitment(&self) -> JournalCommitment {
        self.new_state_commitment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    journal_version: u32,
    wallet_scope: String,
    records: Vec<AgentJournalRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AgentJournalHead {
    pub(crate) sequence: u64,
    pub(crate) record_hash: JournalCommitment,
    pub(crate) state_commitment: Option<JournalCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentJournalRecovery {
    pub(crate) head: AgentJournalHead,
    pub(crate) records: Vec<AgentJournalRecord>,
}

/// A single-wallet journal handle with an independently supplied 32-byte key.
pub(crate) struct AgentJournal {
    path: PathBuf,
    wallet_scope: WalletScope,
    authentication_key: Zeroizing<[u8; 32]>,
}

impl AgentJournal {
    /// Opens an existing journal or prepares an empty one.
    ///
    /// This method never deletes, truncates, repairs, or silently replaces an
    /// invalid journal. Invalid persisted state is returned for manual recovery.
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        wallet_scope: WalletScope,
        independent_journal_key: &[u8; 32],
    ) -> AgentWalletResult<Self> {
        validate_wallet_scope(wallet_scope.as_str())?;
        let authentication_key =
            derive_authentication_key(independent_journal_key, wallet_scope.as_str())?;
        let journal = Self {
            path: path.into(),
            wallet_scope,
            authentication_key: Zeroizing::new(authentication_key),
        };
        if journal.path.exists() {
            journal.verify()?;
        }
        Ok(journal)
    }

    /// Appends one authenticated logical record using atomic whole-file replace.
    ///
    /// The caller must hold the owning store's exclusive per-wallet lock until
    /// this method returns.
    pub(crate) fn append(
        &mut self,
        event: AgentJournalEvent,
    ) -> AgentWalletResult<AgentJournalRecord> {
        let recovery = self.verify()?;
        if let Some(expected) = recovery.head.state_commitment
            && event.previous_state_commitment != expected
        {
            return Err(AgentWalletError::InvalidOperationState);
        }

        let sequence = recovery
            .head
            .sequence
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        let mut record = AgentJournalRecord {
            journal_version: JOURNAL_VERSION,
            sequence,
            previous_record_hash: recovery.head.record_hash,
            wallet_scope: self.wallet_scope.as_str().to_owned(),
            event_kind: event.kind,
            operation_commitment: event.operation_commitment,
            actor_commitment: event.actor_commitment,
            metadata_commitment: event.metadata_commitment,
            previous_state_commitment: event.previous_state_commitment,
            new_state_commitment: event.new_state_commitment,
            occurred_at_unix_ms: event.occurred_at_unix_ms,
            record_hash: ZERO_HASH,
            authentication_tag: ZERO_HASH,
        };
        record.record_hash = calculate_record_hash(&record)?;
        record.authentication_tag = self.calculate_authentication_tag(record.record_hash)?;

        let mut records = recovery.records;
        if records.len() >= MAX_RECORDS {
            return Err(AgentWalletError::PersistenceFailed);
        }
        records.push(record.clone());
        let journal_file = JournalFile {
            journal_version: JOURNAL_VERSION,
            wallet_scope: self.wallet_scope.as_str().to_owned(),
            records,
        };
        let encoded =
            serde_json::to_vec(&journal_file).map_err(|_| AgentWalletError::PersistenceFailed)?;
        if encoded.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(AgentWalletError::PersistenceFailed);
        }
        secure_write(&self.path, &encoded).map_err(|_| AgentWalletError::PersistenceFailed)?;

        // A successful atomic write must also be readable and authenticated.
        let persisted = self.verify()?;
        if persisted.head.sequence != record.sequence
            || persisted.head.record_hash != record.record_hash
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(record)
    }

    /// Authenticates the complete file and returns its verified recovery view.
    pub(crate) fn verify(&self) -> AgentWalletResult<AgentJournalRecovery> {
        let Some(file) = read_bounded_file(&self.path)? else {
            return Ok(empty_recovery());
        };
        if file.journal_version != JOURNAL_VERSION
            || file.wallet_scope != self.wallet_scope.as_str()
            || file.records.len() > MAX_RECORDS
        {
            return Err(AgentWalletError::JournalAuthenticationFailed);
        }

        let mut expected_sequence = 1_u64;
        let mut expected_previous_hash = ZERO_HASH;
        let mut expected_previous_state: Option<JournalCommitment> = None;
        for record in &file.records {
            if record.journal_version != JOURNAL_VERSION
                || record.wallet_scope != self.wallet_scope.as_str()
                || record.sequence != expected_sequence
                || record.previous_record_hash != expected_previous_hash
            {
                return Err(AgentWalletError::JournalAuthenticationFailed);
            }
            if let Some(expected) = expected_previous_state
                && record.previous_state_commitment != expected
            {
                return Err(AgentWalletError::JournalAuthenticationFailed);
            }
            let encoded_record = serde_json::to_vec(record)
                .map_err(|_| AgentWalletError::JournalAuthenticationFailed)?;
            if encoded_record.len() > MAX_RECORD_BYTES {
                return Err(AgentWalletError::JournalAuthenticationFailed);
            }

            let expected_record_hash = calculate_record_hash(record)?;
            if record.record_hash != expected_record_hash {
                return Err(AgentWalletError::JournalAuthenticationFailed);
            }
            self.verify_authentication_tag(record.record_hash, record.authentication_tag)?;

            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(AgentWalletError::JournalAuthenticationFailed)?;
            expected_previous_hash = record.record_hash;
            expected_previous_state = Some(record.new_state_commitment);
        }

        let head = file
            .records
            .last()
            .map(|record| AgentJournalHead {
                sequence: record.sequence,
                record_hash: record.record_hash,
                state_commitment: Some(record.new_state_commitment),
            })
            .unwrap_or_else(empty_head);
        Ok(AgentJournalRecovery {
            head,
            records: file.records,
        })
    }

    /// Returns verified records without modifying the journal.
    ///
    /// Recovery decisions are intentionally left to the caller. No invalid or
    /// unrecognized file is automatically deleted or reset.
    #[cfg(test)]
    pub(crate) fn recover(&self) -> AgentWalletResult<AgentJournalRecovery> {
        self.verify()
    }

    fn calculate_authentication_tag(
        &self,
        record_hash: JournalCommitment,
    ) -> AgentWalletResult<JournalCommitment> {
        let mut mac = HmacSha256::new_from_slice(self.authentication_key.as_ref())
            .map_err(|_| AgentWalletError::Crypto)?;
        mac.update(RECORD_MAC_DOMAIN);
        mac.update(record_hash.as_bytes());
        Ok(JournalCommitment(mac.finalize().into_bytes().into()))
    }

    fn verify_authentication_tag(
        &self,
        record_hash: JournalCommitment,
        authentication_tag: JournalCommitment,
    ) -> AgentWalletResult<()> {
        let mut mac = HmacSha256::new_from_slice(self.authentication_key.as_ref())
            .map_err(|_| AgentWalletError::Crypto)?;
        mac.update(RECORD_MAC_DOMAIN);
        mac.update(record_hash.as_bytes());
        mac.verify_slice(authentication_tag.as_bytes())
            .map_err(|_| AgentWalletError::JournalAuthenticationFailed)
    }
}

fn derive_authentication_key(
    independent_journal_key: &[u8; 32],
    wallet_scope: &str,
) -> AgentWalletResult<[u8; 32]> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(KEY_DOMAIN);
    put_len_prefixed(&mut salt_hasher, wallet_scope.as_bytes());
    let salt = salt_hasher.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), independent_journal_key);
    let mut output = [0_u8; 32];
    hkdf.expand(KEY_DOMAIN, &mut output)
        .map_err(|_| AgentWalletError::Crypto)?;
    Ok(output)
}

fn calculate_record_hash(record: &AgentJournalRecord) -> AgentWalletResult<JournalCommitment> {
    let canonical = canonical_record_body(record)?;
    if canonical.len() > MAX_RECORD_BYTES {
        return Err(AgentWalletError::JournalAuthenticationFailed);
    }
    let mut hasher = Sha256::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(canonical);
    Ok(JournalCommitment(hasher.finalize().into()))
}

fn canonical_record_body(record: &AgentJournalRecord) -> AgentWalletResult<Vec<u8>> {
    let scope = record.wallet_scope.as_bytes();
    if scope.len() > MAX_SCOPE_BYTES || scope.len() > u16::MAX as usize {
        return Err(AgentWalletError::JournalAuthenticationFailed);
    }
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(&record.journal_version.to_be_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.extend_from_slice(record.previous_record_hash.as_bytes());
    bytes.extend_from_slice(&(scope.len() as u16).to_be_bytes());
    bytes.extend_from_slice(scope);
    bytes.extend_from_slice(&record.event_kind.code().to_be_bytes());
    put_optional_commitment(&mut bytes, record.operation_commitment);
    put_optional_commitment(&mut bytes, record.actor_commitment);
    put_optional_commitment(&mut bytes, record.metadata_commitment);
    bytes.extend_from_slice(record.previous_state_commitment.as_bytes());
    bytes.extend_from_slice(record.new_state_commitment.as_bytes());
    bytes.extend_from_slice(&record.occurred_at_unix_ms.to_be_bytes());
    Ok(bytes)
}

fn put_optional_commitment(bytes: &mut Vec<u8>, value: Option<JournalCommitment>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn put_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_wallet_scope(scope: &str) -> AgentWalletResult<()> {
    let Some(identifier) = scope.strip_prefix("agent_wallet:aw_") else {
        return Err(AgentWalletError::InvalidWalletScope);
    };
    if scope.len() > MAX_SCOPE_BYTES
        || identifier.len() != 32
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AgentWalletError::InvalidWalletScope);
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> AgentWalletResult<Option<JournalFile>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AgentWalletError::PersistenceFailed),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(AgentWalletError::JournalAuthenticationFailed);
    }
    let bytes = fs::read(path).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(AgentWalletError::JournalAuthenticationFailed);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| AgentWalletError::JournalAuthenticationFailed)
}

fn empty_head() -> AgentJournalHead {
    AgentJournalHead {
        sequence: 0,
        record_hash: ZERO_HASH,
        state_commitment: None,
    }
}

fn empty_recovery() -> AgentJournalRecovery {
    AgentJournalRecovery {
        head: empty_head(),
        records: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AgentWalletId;

    fn scope() -> WalletScope {
        WalletScope::for_agent_wallet(
            &AgentWalletId::parse("aw_0123456789abcdef0123456789abcdef").unwrap(),
        )
    }

    fn event(
        kind: AgentJournalEventKind,
        previous_state: JournalCommitment,
        new_state: JournalCommitment,
    ) -> AgentJournalEvent {
        AgentJournalEvent {
            kind,
            operation_commitment: Some(JournalCommitment::commit(b"operation-id", b"op_sensitive")),
            actor_commitment: Some(JournalCommitment::commit(b"agent-id", b"agent_sensitive")),
            metadata_commitment: Some(JournalCommitment::commit(
                b"payment-details",
                b"recipient=1SecretAddress;amount=42.50000000",
            )),
            previous_state_commitment: previous_state,
            new_state_commitment: new_state,
            occurred_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn append_and_recover_authenticates_chain_without_plaintext_payment_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-journal.json");
        let key = [7_u8; 32];
        let mut journal = AgentJournal::open(&path, scope(), &key).unwrap();
        let state_one = JournalCommitment::commit(b"state", b"one");
        let state_two = JournalCommitment::commit(b"state", b"two");

        journal
            .append(event(
                AgentJournalEventKind::WalletCreated,
                ZERO_HASH,
                state_one,
            ))
            .unwrap();
        journal
            .append(event(
                AgentJournalEventKind::PaymentRequested,
                state_one,
                state_two,
            ))
            .unwrap();

        let recovery = journal.recover().unwrap();
        assert_eq!(recovery.records.len(), 2);
        assert_eq!(recovery.head.sequence, 2);
        assert_eq!(recovery.head.state_commitment, Some(state_two));
        assert_eq!(
            recovery.records[1].event_kind(),
            AgentJournalEventKind::PaymentRequested
        );
        assert_eq!(recovery.records[1].sequence(), 2);
        assert_ne!(recovery.records[1].record_hash(), ZERO_HASH);
        assert_eq!(recovery.records[1].state_commitment(), state_two);

        let persisted = String::from_utf8(fs::read(path).unwrap()).unwrap();
        assert!(!persisted.contains("1SecretAddress"));
        assert!(!persisted.contains("42.50000000"));
        assert!(!persisted.contains("op_sensitive"));
        assert!(!persisted.contains("agent_sensitive"));
    }

    #[test]
    fn wrong_key_and_modified_record_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-journal.json");
        let key = [8_u8; 32];
        let mut journal = AgentJournal::open(&path, scope(), &key).unwrap();
        journal
            .append(event(
                AgentJournalEventKind::WalletCreated,
                ZERO_HASH,
                JournalCommitment::commit(b"state", b"one"),
            ))
            .unwrap();

        assert_eq!(
            AgentJournal::open(&path, scope(), &[9_u8; 32]).err(),
            Some(AgentWalletError::JournalAuthenticationFailed)
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["records"][0]["event_kind"] = serde_json::Value::String("wallet_locked".to_owned());
        secure_write(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            journal.verify().unwrap_err(),
            AgentWalletError::JournalAuthenticationFailed
        );
    }

    #[test]
    fn strict_scope_sequence_previous_hash_and_unknown_fields_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-journal.json");
        let key = [10_u8; 32];
        let mut journal = AgentJournal::open(&path, scope(), &key).unwrap();
        journal
            .append(event(
                AgentJournalEventKind::WalletCreated,
                ZERO_HASH,
                JournalCommitment::commit(b"state", b"one"),
            ))
            .unwrap();
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        for (field, replacement) in [
            ("sequence", serde_json::json!(2)),
            (
                "previous_record_hash",
                serde_json::json!(hex::encode([3_u8; 32])),
            ),
            (
                "wallet_scope",
                serde_json::json!("agent_wallet:aw_deadbeef"),
            ),
            ("journal_version", serde_json::json!(2)),
        ] {
            let mut modified = original.clone();
            modified["records"][0][field] = replacement;
            secure_write(&path, &serde_json::to_vec(&modified).unwrap()).unwrap();
            assert_eq!(
                journal.verify().unwrap_err(),
                AgentWalletError::JournalAuthenticationFailed,
                "field {field} must fail closed"
            );
        }

        let mut modified = original;
        modified["records"][0]["unexpected"] = serde_json::json!("ignored?");
        secure_write(&path, &serde_json::to_vec(&modified).unwrap()).unwrap();
        assert_eq!(
            journal.verify().unwrap_err(),
            AgentWalletError::JournalAuthenticationFailed
        );
    }

    #[test]
    fn state_discontinuity_is_rejected_before_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-journal.json");
        let key = [11_u8; 32];
        let mut journal = AgentJournal::open(&path, scope(), &key).unwrap();
        let state_one = JournalCommitment::commit(b"state", b"one");
        journal
            .append(event(
                AgentJournalEventKind::WalletCreated,
                ZERO_HASH,
                state_one,
            ))
            .unwrap();
        let before = fs::read(&path).unwrap();

        let result = journal.append(event(
            AgentJournalEventKind::PolicyChanged,
            JournalCommitment::commit(b"state", b"wrong"),
            JournalCommitment::commit(b"state", b"two"),
        ));
        assert_eq!(result, Err(AgentWalletError::InvalidOperationState));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn recovery_is_read_only_and_oversized_files_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-journal.json");
        let key = [12_u8; 32];
        let mut journal = AgentJournal::open(&path, scope(), &key).unwrap();
        journal
            .append(event(
                AgentJournalEventKind::WalletCreated,
                ZERO_HASH,
                JournalCommitment::commit(b"state", b"one"),
            ))
            .unwrap();
        let before = fs::read(&path).unwrap();
        journal.recover().unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);

        let oversized = vec![b'x'; MAX_JOURNAL_BYTES as usize + 1];
        secure_write(&path, &oversized).unwrap();
        assert_eq!(
            journal.verify().unwrap_err(),
            AgentWalletError::JournalAuthenticationFailed
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), oversized.len() as u64);
    }

    #[test]
    fn commitment_encoding_is_canonical_lowercase_hex() {
        let commitment = JournalCommitment::from_bytes([0xab; 32]);
        let encoded = serde_json::to_string(&commitment).unwrap();
        assert_eq!(encoded, format!("\"{}\"", "ab".repeat(32)));
        assert!(serde_json::from_str::<JournalCommitment>(&encoded).is_ok());
        assert!(
            serde_json::from_str::<JournalCommitment>(&format!("\"{}\"", "AB".repeat(32))).is_err()
        );
        assert!(serde_json::from_str::<JournalCommitment>("\"00\"").is_err());
    }
}
