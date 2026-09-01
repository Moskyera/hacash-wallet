use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hpay_companion_protocol::{
    AgentFastPayApprovalDecision, AgentHvmApprovalDecision, ApprovalDecision, DeviceId,
    DevicePermission, DevicePublicRecord, DeviceRegistry, DeviceRole, EncryptedCompanionFrame,
    FRAME_VERSION, LanEndpoint, MobileApprovalDecision, MobileWitnessState, ReplayGuard,
    ReplayGuardSnapshot, ReplayHighWaterMark, ReplayNonceRecord,
    SignedAgentFastPayApprovalDecision, SignedAgentHvmApprovalDecision,
    SignedRotationCandidateAcceptance, SignedRotationPairingTicket,
    SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
    WitnessReconciliationStatus, WitnessRotationPhase,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::network::agent_fast_pay_network_allowed;
use super::{MAX_STATE_BYTES, STATE_VERSION, unix_now};

const RESET_MARKER: &[u8] = br#"{"stateVersion":"reset"}"#;

pub(super) trait CompanionStateStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String>;
}

#[derive(Debug)]
pub(super) struct FileCompanionStateStore {
    path: PathBuf,
}

impl FileCompanionStateStore {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn reject_symlink(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err("Agent companion state must not be a symlink".to_owned())
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Agent companion state metadata: {error}")),
        }
    }
}

impl CompanionStateStore for FileCompanionStateStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        Self::reject_symlink(&self.path)?;
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read Agent companion state: {error}")),
        };
        if bytes == RESET_MARKER {
            let _ = fs::remove_file(&self.path);
            return Ok(None);
        }
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err("Agent companion state has an invalid size".to_owned());
        }
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String> {
        Self::reject_symlink(&self.path)?;
        match bytes {
            Some(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
                    return Err("Agent companion state has an invalid size".to_owned());
                }
                hacash_wallet_core::paths::secure_write(&self.path, bytes)
                    .map_err(|error| format!("persist Agent companion state: {error}"))
            }
            None => {
                // Atomic logical deletion: first replace the scoped public state with a
                // non-sensitive reset marker. Physical removal is best effort; a crash or
                // removal failure still leaves no wallet/device/replay/endpoint material.
                hacash_wallet_core::paths::secure_write(&self.path, RESET_MARKER)
                    .map_err(|error| format!("reset Agent companion state: {error}"))?;
                let _ = fs::remove_file(&self.path);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobilePendingApproval {
    pub(super) state_version: String,
    pub(super) commitment_hash: String,
    pub(super) decision: MobileApprovalDecision,
}

impl MobilePendingApproval {
    pub(super) fn validate(&self) -> Result<(), String> {
        let binding = self
            .decision
            .network_binding
            .as_ref()
            .ok_or_else(|| "Pending pilot approval has no network binding".to_owned())?;
        self.decision
            .canonical_bytes()
            .map_err(|error| error.to_string())?;
        if self.state_version != "1"
            || self.decision.decision_version != 3
            || self.commitment_hash.len() != 64
            || !self
                .commitment_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || binding.network_id != "testnet"
            || binding.chain_id == 0
            || binding.transaction_format_version != 2
        {
            return Err("Pending pilot approval binding is invalid".to_owned());
        }
        Ok(())
    }
}

/// One exact Agent Fast Pay owner decision retained for crash-safe delivery.
///
/// The unsigned decision is persisted before Android opens the biometric
/// prompt, consuming its monotonic sequence once. The exact signed object is
/// then persisted before transport. A response-loss retry therefore sends the
/// same signature bytes instead of creating a second authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobilePendingAgentFastPayApproval {
    pub(super) state_version: String,
    pub(super) commitment_hash: String,
    pub(super) decision: AgentFastPayApprovalDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) signed_decision: Option<SignedAgentFastPayApprovalDecision>,
}

impl MobilePendingAgentFastPayApproval {
    pub(super) fn validate(&self) -> Result<(), String> {
        let canonical_hash = self
            .decision
            .commitment
            .canonical_sha256_hex()
            .map_err(|error| error.to_string())?;
        self.decision
            .canonical_bytes()
            .map_err(|error| error.to_string())?;
        if self.state_version != "1"
            || self.commitment_hash != canonical_hash
            || self.decision.commitment_sha256 != canonical_hash
            || !agent_fast_pay_network_allowed(&self.decision.commitment.network_binding)
            || self.decision.commitment.network_fee_units != 0
            || self.decision.commitment.wallet_fee_units != 0
            || self.decision.commitment.hub_fee_units != 0
            || self.decision.commitment.total_debit_units != self.decision.commitment.amount_units
            || self.signed_decision.as_ref().is_some_and(|signed| {
                signed.decision != self.decision || !is_signature(&signed.signature_hex)
            })
        {
            return Err("Pending Agent Fast Pay approval is invalid".to_owned());
        }
        Ok(())
    }
}

/// One exact Agent HVM owner decision retained for crash-safe delivery.
///
/// This is a distinct rail from native ChannelPay. The durable record binds
/// the exact deployment, all lease evidence, previous bill, next unsigned bill
/// and zero-fee decision before Android may use its biometric key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobilePendingAgentHvmApproval {
    pub(super) state_version: String,
    pub(super) commitment_hash: String,
    pub(super) decision: AgentHvmApprovalDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) signed_decision: Option<SignedAgentHvmApprovalDecision>,
}

impl MobilePendingAgentHvmApproval {
    pub(super) fn validate(&self) -> Result<(), String> {
        let canonical_hash = self
            .decision
            .commitment
            .canonical_sha256_hex()
            .map_err(|error| error.to_string())?;
        self.decision
            .canonical_bytes()
            .map_err(|error| error.to_string())?;
        if self.state_version != "1"
            || self.commitment_hash != canonical_hash
            || self.decision.commitment_sha256 != canonical_hash
            || !agent_fast_pay_network_allowed(&self.decision.commitment.network_binding)
            || self.decision.commitment.network_fee_zhu != 0
            || self.decision.commitment.wallet_fee_zhu != 0
            || self.decision.commitment.hub_fee_zhu != 0
            || self.decision.commitment.total_debit_zhu != self.decision.commitment.amount_zhu
            || self.signed_decision.as_ref().is_some_and(|signed| {
                signed.decision != self.decision || !is_signature(&signed.signature_hex)
            })
        {
            return Err("Pending Agent HVM approval is invalid".to_owned());
        }
        Ok(())
    }
}

/// The owner's consent, on this handset, to witness one exact operation they
/// did not approve here.
///
/// A payment the owner approved on HPAY Desktop leaves no `MobilePendingApproval`
/// on the phone, so the binding `sign_pilot_witness` used to require simply is
/// not there. Deleting the requirement would turn the witness into an automatic
/// co-signature, which is the one thing the rollback witness must never be. This
/// record replaces it: it is written durably, before anything is fetched or
/// signed, and it names the operation together with the exact amount and
/// recipient the owner was shown when they pressed confirm. An anchor is then
/// bound to this, so a tap carries information rather than an opaque id, and a
/// crash between the tap and the signature resumes the same payment instead of
/// silently witnessing a different one.
///
/// It carries no signature and no network binding, and it is never sent
/// anywhere. The anchor's network fields are checked against the phone's own
/// durable `MobileWitnessState` pins instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobilePendingWitness {
    pub(super) state_version: String,
    pub(super) operation_id: String,
    pub(super) amount_units: String,
    pub(super) recipient: String,
    pub(super) status: String,
    pub(super) confirmed_at: String,
}

impl MobilePendingWitness {
    pub(super) fn validate(&self) -> Result<(), String> {
        let amount_units = parse_decimal_u64(&self.amount_units)?;
        let confirmed_at = parse_decimal_u64(&self.confirmed_at)?;
        if self.state_version != "1"
            || self.operation_id.is_empty()
            || self.operation_id.len() > 128
            || amount_units == 0
            || self.recipient.is_empty()
            || self.recipient.len() > 128
            || confirmed_at == 0
            || !hpay_companion_protocol::WITNESS_PENDING_ACTIVITY_STATUSES
                .contains(&self.status.as_str())
        {
            return Err("Pending witness confirmation is invalid".to_owned());
        }
        Ok(())
    }
}

/// How long a consent record survives after the paired desktop has stopped
/// listing the operation it names as awaiting this phone's rollback witness.
///
/// The desktop's disclosure is a snapshot, and there are short windows inside a
/// healthy flow where an operation legitimately leaves it - between the receipt
/// being accepted and the broadcast landing, for instance. The grace is the
/// anchor lifetime, which is longer than any of those windows, so a record is
/// only ever retired once the desktop has been consistently silent about it.
#[cfg(any(target_os = "android", test))]
const CONSENT_DESKTOP_SILENCE_GRACE_SECS: u64 = 5 * 60;

/// The age past which a consent record is retired with no desktop statement at
/// all.
///
/// A phone that can never reach its desktop again - revoked, or the desktop
/// gone - would otherwise hold its record for ever, and that record blocks the
/// reset, blocks pairing and blocks every other payment. Retiring it ends only
/// this phone's local intent to sign; it cancels nothing, un-signs nothing, and
/// the owner can confirm again the moment the desktop offers the operation.
#[cfg(any(target_os = "android", test))]
const CONSENT_MAX_AGE_SECS: u64 = 24 * 60 * 60;

pub(super) const DISCARDED_WITNESS_CONFIRMATION: &str = "witness_confirmation";
pub(super) const DISCARDED_PILOT_APPROVAL: &str = "pilot_approval";
pub(super) const DISCARDED_AGENT_FAST_PAY_APPROVAL: &str = "agent_fast_pay_approval";
pub(super) const DISCARDED_AGENT_HVM_APPROVAL: &str = "agent_hvm_approval";

#[cfg(any(target_os = "android", test))]
pub(super) const DISCARD_DESKTOP_NO_LONGER_AWAITING: &str = "desktop_no_longer_awaits_this_phone";
#[cfg(any(target_os = "android", test))]
pub(super) const DISCARD_AGED_OUT: &str = "aged_out_on_this_phone";
#[cfg(any(target_os = "android", test))]
pub(super) const DISCARD_OWNER: &str = "owner_discarded";

const DISCARD_REASONS: [&str; 3] = [
    "desktop_no_longer_awaits_this_phone",
    "aged_out_on_this_phone",
    "owner_discarded",
];

/// How many discard receipts this phone keeps.
///
/// The history has to be bounded - an unbounded list on a handset is its own
/// defect, and this one is written by paths the owner does not drive - but it
/// must not be bounded at one, which is what it used to be. A single slot is
/// last-write-wins: discard the confirmation for one payment, hold and discard
/// another, and the first receipt is gone with nothing said. Losing the
/// evidence is the exact thing the record exists to prevent.
///
/// Thirty-two is far beyond any plausible run of discards: a phone holds at
/// most one consent record at a time, and each receipt needs a separate
/// confirm-then-retire cycle to exist at all. At the documented 512-byte field
/// caps the whole history is under 40 KB against a 1 MiB state budget, so a
/// full history can never be the reason a discard fails to persist - which
/// matters, because a discard that cannot persist is refused, and a refused
/// discard is the stranding this whole area exists to end.
pub(super) const MAX_DISCARDED_CONSENTS: usize = 32;

/// The receipt for a consent record this phone stopped holding.
///
/// Clearing a consent record must never be silent. This is not evidence of a
/// signature and it is not a witness: the signed evidence lives in
/// [`MobileWitnessState`], which no discard ever touches. This says only that
/// the phone's local intent to sign one exact operation ended, when, and why -
/// enough for the owner to recognise the payment and go and look at it on the
/// desktop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobileDiscardedConsent {
    pub(super) state_version: String,
    pub(super) kind: String,
    pub(super) operation_id: String,
    pub(super) amount_units: String,
    pub(super) recipient: String,
    pub(super) confirmed_at: String,
    pub(super) discarded_at: String,
    pub(super) reason: String,
}

impl MobileDiscardedConsent {
    pub(super) fn validate(&self) -> Result<(), String> {
        parse_decimal_u64(&self.amount_units)?;
        parse_decimal_u64(&self.confirmed_at)?;
        parse_decimal_u64(&self.discarded_at)?;
        if self.state_version != "1"
            || !matches!(
                self.kind.as_str(),
                DISCARDED_WITNESS_CONFIRMATION
                    | DISCARDED_PILOT_APPROVAL
                    | DISCARDED_AGENT_FAST_PAY_APPROVAL
                    | DISCARDED_AGENT_HVM_APPROVAL
            )
            || self.operation_id.is_empty()
            // Deliberately looser than the 128 a witness confirmation allows.
            // A receipt is built from whichever record was retired, and a
            // pilot approval's own shape check bounds neither field, so a
            // tighter cap here would refuse the discard and wedge the phone on
            // exactly the record it needs to let go of.
            || self.operation_id.len() > 512
            || self.recipient.is_empty()
            || self.recipient.len() > 512
            || !DISCARD_REASONS.contains(&self.reason.as_str())
        {
            return Err("Discarded consent record is invalid".to_owned());
        }
        Ok(())
    }

    #[cfg(any(target_os = "android", test))]
    fn from_witness(pending: &MobilePendingWitness, reason: &str, now: u64) -> Self {
        Self {
            state_version: "1".to_owned(),
            kind: DISCARDED_WITNESS_CONFIRMATION.to_owned(),
            operation_id: pending.operation_id.clone(),
            amount_units: pending.amount_units.clone(),
            recipient: pending.recipient.clone(),
            confirmed_at: pending.confirmed_at.clone(),
            discarded_at: now.to_string(),
            reason: reason.to_owned(),
        }
    }

    #[cfg(any(target_os = "android", test))]
    fn from_approval(pending: &MobilePendingApproval, reason: &str, now: u64) -> Self {
        Self {
            state_version: "1".to_owned(),
            kind: DISCARDED_PILOT_APPROVAL.to_owned(),
            operation_id: pending.decision.operation_id.clone(),
            amount_units: pending.decision.amount_units.to_string(),
            recipient: pending.decision.recipient.clone(),
            confirmed_at: pending.decision.issued_at.to_string(),
            discarded_at: now.to_string(),
            reason: reason.to_owned(),
        }
    }

    #[cfg(any(target_os = "android", test))]
    fn from_agent_fast_pay_approval(
        pending: &MobilePendingAgentFastPayApproval,
        reason: &str,
        now: u64,
    ) -> Self {
        Self {
            state_version: "1".to_owned(),
            kind: DISCARDED_AGENT_FAST_PAY_APPROVAL.to_owned(),
            operation_id: pending.decision.commitment.operation_id.clone(),
            amount_units: pending.decision.commitment.amount_units.to_string(),
            recipient: pending.decision.commitment.payee.clone(),
            confirmed_at: pending.decision.decision_issued_at.to_string(),
            discarded_at: now.to_string(),
            reason: reason.to_owned(),
        }
    }

    #[cfg(any(target_os = "android", test))]
    fn from_agent_hvm_approval(
        pending: &MobilePendingAgentHvmApproval,
        reason: &str,
        now: u64,
    ) -> Self {
        Self {
            state_version: "1".to_owned(),
            kind: DISCARDED_AGENT_HVM_APPROVAL.to_owned(),
            operation_id: pending.decision.commitment.operation_id.clone(),
            amount_units: pending.decision.commitment.amount_zhu.to_string(),
            recipient: pending.decision.commitment.payee.clone(),
            confirmed_at: pending.decision.decision_issued_at.to_string(),
            discarded_at: now.to_string(),
            reason: reason.to_owned(),
        }
    }
}

/// Appends one receipt to the bounded history, counting anything the cap
/// pushes out.
///
/// The oldest receipts go first, and the count of what went is kept and shown.
/// Two directions were rejected. Dropping the oldest silently is the same
/// class of defect as the single slot: evidence disappears and nothing says
/// so. Refusing the discard once the history is full is worse still - the
/// discard is the owner's last exit from a held consent record, so a full log
/// would wedge the phone on exactly the record it needs to let go of, which is
/// the stranding this area exists to end. Keeping the newest and counting the
/// rest loses no exit and hides nothing: the count is durable, and the screen
/// says how many receipts it no longer shows and where to look them up.
#[cfg(any(target_os = "android", test))]
fn push_discard_bounded(
    history: &mut Vec<MobileDiscardedConsent>,
    dropped: &mut u64,
    discard: MobileDiscardedConsent,
) {
    history.push(discard);
    trim_discard_history(history, dropped);
}

fn trim_discard_history(history: &mut Vec<MobileDiscardedConsent>, dropped: &mut u64) {
    if history.len() > MAX_DISCARDED_CONSENTS {
        let excess = history.len() - MAX_DISCARDED_CONSENTS;
        history.drain(..excess);
        *dropped = dropped.saturating_add(excess as u64);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MobileCompanionDurableState {
    pub(super) state_version: u64,
    pub(super) agent_wallet_id: String,
    pub(super) desktop_device_id: DeviceId,
    pub(super) mobile_device_id: DeviceId,
    pub(super) endpoints: Vec<LanEndpoint>,
    pub(super) registry: DeviceRegistry,
    pub(super) replay: ReplayGuardSnapshot,
    pub(super) response_sequence: u64,
    pub(super) approval_sequence: u64,
    pub(super) pending_pairing_ack: Option<EncryptedCompanionFrame>,
    pub(super) pending_approval: Option<MobilePendingApproval>,
    pub(super) pending_agent_fast_pay_approval: Option<MobilePendingAgentFastPayApproval>,
    pub(super) pending_agent_hvm_approval: Option<MobilePendingAgentHvmApproval>,
    pub(super) pending_witness: Option<MobilePendingWitness>,
    /// Every consent record this phone stopped holding, oldest first, capped
    /// at [`MAX_DISCARDED_CONSENTS`].
    ///
    /// Phone-local like everything else here, and kept so that a discard is
    /// never silent. Append-only: a later discard never overwrites an earlier
    /// receipt, which is what a single slot did. It authorizes nothing and is
    /// never consulted by `require_authorized_witness_binding`.
    pub(super) discarded_consents: Vec<MobileDiscardedConsent>,
    /// How many receipts the cap has pushed out of that history.
    ///
    /// Non-zero only once [`MAX_DISCARDED_CONSENTS`] receipts are held, and
    /// surfaced on the phone verbatim, so the owner is told that older
    /// receipts existed rather than left to assume the list is complete.
    pub(super) discarded_consents_dropped: u64,
    pub(super) witness: Option<MobileWitnessState>,
    pub(super) rotation_phase: WitnessRotationPhase,
    pub(super) pending_rotation_authorization: Option<SignedWitnessRotationAuthorization>,
    pub(super) pending_rotation_baseline: Option<SignedWitnessRotationBaselineReceipt>,
    pub(super) rotation_ticket: Option<SignedRotationPairingTicket>,
    pub(super) rotation_candidate_acceptance: Option<SignedRotationCandidateAcceptance>,
}

impl MobileCompanionDurableState {
    pub(super) fn validate_at(&self, now: u64) -> Result<(), String> {
        if self.state_version != STATE_VERSION
            || self.agent_wallet_id.is_empty()
            || self.endpoints.is_empty()
        {
            return Err("Agent companion state scope is invalid".to_owned());
        }
        let unique = self
            .endpoints
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        if unique.len() != self.endpoints.len() {
            return Err("Agent companion state contains duplicate endpoints".to_owned());
        }
        self.registry
            .validate()
            .map_err(|error| error.to_string())?;
        validate_record(
            &self.registry,
            &self.desktop_device_id,
            &self.agent_wallet_id,
            DeviceRole::Desktop,
        )?;
        validate_record(
            &self.registry,
            &self.mobile_device_id,
            &self.agent_wallet_id,
            DeviceRole::Mobile,
        )?;
        ReplayGuard::from_snapshot(self.replay.clone(), now).map_err(|error| error.to_string())?;
        if let Some(ack) = &self.pending_pairing_ack
            && (ack.frame_version != FRAME_VERSION
                || ack.session_id.is_empty()
                || ack.sender_device_id != self.mobile_device_id
                || ack.recipient_device_id != self.desktop_device_id
                || ack.sequence != 1
                || ack.expires_at <= ack.issued_at
                || ack.nonce_hex.len() != 24
                || !ack.nonce_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                || ack.ciphertext_hex.len() < 32
                || !ack.ciphertext_hex.len().is_multiple_of(2)
                || !ack
                    .ciphertext_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err("Pending mobile pairing acknowledgement is invalid".to_owned());
        }
        if let Some(pending) = &self.pending_approval {
            pending.validate()?;
            if pending.decision.agent_wallet_id != self.agent_wallet_id
                || pending.decision.desktop_device_id != self.desktop_device_id
                || pending.decision.mobile_device_id != self.mobile_device_id
                || pending.decision.approval_sequence != self.approval_sequence
            {
                return Err(
                    "Pending pilot approval scope does not match companion state".to_owned(),
                );
            }
        }
        if let Some(pending) = &self.pending_agent_fast_pay_approval {
            pending.validate()?;
            if pending.decision.commitment.agent_wallet_id != self.agent_wallet_id
                || pending.decision.commitment.desktop_device_id != self.desktop_device_id
                || pending.decision.mobile_device_id != self.mobile_device_id
                || pending.decision.approval_sequence != self.approval_sequence
            {
                return Err(
                    "Pending Agent Fast Pay approval scope does not match companion state"
                        .to_owned(),
                );
            }
            let permission = match pending.decision.decision {
                ApprovalDecision::Approve => DevicePermission::ApprovePayment,
                ApprovalDecision::Reject => DevicePermission::RejectPayment,
            };
            let record = self
                .registry
                .require(
                    &self.mobile_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Mobile,
                    permission,
                )
                .map_err(|error| error.to_string())?;
            if record.authorization_epoch != pending.decision.device_authorization_epoch {
                return Err(
                    "Pending Agent Fast Pay approval authorization epoch is stale".to_owned(),
                );
            }
        }
        if let Some(pending) = &self.pending_agent_hvm_approval {
            pending.validate()?;
            if pending.decision.commitment.agent_wallet_id != self.agent_wallet_id
                || pending.decision.commitment.desktop_device_id != self.desktop_device_id
                || pending.decision.mobile_device_id != self.mobile_device_id
                || pending.decision.approval_sequence != self.approval_sequence
            {
                return Err(
                    "Pending Agent HVM approval scope does not match companion state".to_owned(),
                );
            }
            let permission = match pending.decision.decision {
                ApprovalDecision::Approve => DevicePermission::ApprovePayment,
                ApprovalDecision::Reject => DevicePermission::RejectPayment,
            };
            let record = self
                .registry
                .require(
                    &self.mobile_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Mobile,
                    permission,
                )
                .map_err(|error| error.to_string())?;
            if record.authorization_epoch != pending.decision.device_authorization_epoch {
                return Err("Pending Agent HVM approval authorization epoch is stale".to_owned());
            }
        }
        let consent_count = usize::from(self.pending_approval.is_some())
            + usize::from(self.pending_agent_fast_pay_approval.is_some())
            + usize::from(self.pending_agent_hvm_approval.is_some())
            + usize::from(self.pending_witness.is_some());
        if consent_count > 1
            && (self.pending_agent_fast_pay_approval.is_some()
                || self.pending_agent_hvm_approval.is_some())
        {
            return Err("Only one mobile payment consent may be pending".to_owned());
        }
        if let Some(pending) = &self.pending_witness {
            pending.validate()?;
            // At most one operation can ever be waiting on this phone, so a
            // consent record for one operation cannot coexist with a signed
            // approval for another. Fail closed rather than pick.
            if self
                .pending_approval
                .as_ref()
                .is_some_and(|approval| approval.decision.operation_id != pending.operation_id)
            {
                return Err(
                    "Pending witness confirmation and pending approval name different operations"
                        .to_owned(),
                );
            }
        }
        // A history longer than the cap, or a dropped count claiming the cap
        // was reached while the history is not full, is a state no path here
        // can write: `push_discard_bounded` is the only writer and it counts
        // exactly what it drains. Refusing is the same fail-closed direction
        // the receipt's own reason check already takes.
        if self.discarded_consents.len() > MAX_DISCARDED_CONSENTS
            || (self.discarded_consents_dropped > 0
                && self.discarded_consents.len() != MAX_DISCARDED_CONSENTS)
        {
            return Err("Discarded consent history is invalid".to_owned());
        }
        for discarded in &self.discarded_consents {
            discarded.validate()?;
        }
        if let Some(witness) = &self.witness {
            witness.validate().map_err(|error| error.to_string())?;
            if witness.agent_wallet_id != self.agent_wallet_id
                || witness.desktop_device_id != self.desktop_device_id
                || witness.mobile_device_id != self.mobile_device_id
            {
                return Err("Mobile witness scope does not match companion state".to_owned());
            }
        }
        if self.pending_rotation_authorization.is_some() && self.pending_rotation_baseline.is_some()
        {
            return Err("Mobile rotation cannot hold two signing roles".to_owned());
        }
        if let Some(signed) = &self.pending_rotation_authorization {
            signed
                .rotation
                .canonical_bytes()
                .map_err(|error| error.to_string())?;
            if signed.rotation.agent_wallet_id != self.agent_wallet_id
                || signed.rotation.desktop_device_id != self.desktop_device_id
                || signed.rotation.old_mobile_device_id != self.mobile_device_id
                || !is_signature(&signed.signature_hex)
            {
                return Err("Pending rotation authorization scope is invalid".to_owned());
            }
        }
        if let Some(signed) = &self.pending_rotation_baseline {
            signed
                .receipt
                .canonical_bytes()
                .map_err(|error| error.to_string())?;
            if signed.receipt.agent_wallet_id != self.agent_wallet_id
                || signed.receipt.new_mobile_device_id != self.mobile_device_id
                || !is_signature(&signed.signature_hex)
            {
                return Err("Pending rotation baseline scope is invalid".to_owned());
            }
        }
        match (&self.rotation_ticket, &self.rotation_candidate_acceptance) {
            (None, None) => {}
            (Some(ticket), Some(acceptance)) => {
                let desktop = validate_record(
                    &self.registry,
                    &self.desktop_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Desktop,
                )?;
                let candidate = validate_record(
                    &self.registry,
                    &self.mobile_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Mobile,
                )?;
                ticket
                    .verify(&desktop, acceptance.acceptance.accepted_at)
                    .map_err(|error| error.to_string())?;
                acceptance
                    .verify(ticket, &candidate, acceptance.acceptance.accepted_at)
                    .map_err(|error| error.to_string())?;
                if !matches!(
                    self.rotation_phase,
                    WitnessRotationPhase::CandidatePairedRestricted
                        | WitnessRotationPhase::CandidateBaselineVerified
                        | WitnessRotationPhase::AwaitingOldDeviceRevocation
                        | WitnessRotationPhase::AwaitingCompletionAnchor
                        | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                        | WitnessRotationPhase::Completed
                ) {
                    return Err("Restricted rotation candidate phase is invalid".to_owned());
                }
            }
            _ => return Err("Rotation candidate ticket state is incomplete".to_owned()),
        }
        Ok(())
    }

    pub(super) fn requires_controlled_rotation(&self) -> bool {
        !matches!(
            self.rotation_phase,
            WitnessRotationPhase::Stable | WitnessRotationPhase::Completed
        )
    }

    /// The phase `reset_before_witness_rotation` would durably write, and refuse
    /// with, if the reset were attempted right now.
    ///
    /// This is deliberately wider than [`Self::requires_controlled_rotation`]:
    /// it also fires on a pending pilot approval and on any witness record,
    /// while `rotation_phase` is still `Stable`. Until it was surfaced, the
    /// phone offered a reset that could only refuse, and the refusal itself
    /// permanently replaced the reset section. The screen must be able to see
    /// the predicate the storage layer actually enforces.
    pub(super) fn rotation_blocking_phase(&self) -> Option<WitnessRotationPhase> {
        if self.pending_approval.is_some()
            || self.pending_agent_fast_pay_approval.is_some()
            || self.pending_agent_hvm_approval.is_some()
        {
            return Some(WitnessRotationPhase::BlockedByPendingApproval);
        }
        // A confirmed-but-unfinished witness is an unresolved signed operation
        // by construction: the desktop only offers one for an operation that is
        // already signed. Wiping it here would drop the owner's consent record
        // while the payment it names is still live.
        if self.pending_witness.is_some() {
            return Some(WitnessRotationPhase::BlockedByUnresolvedSignedOperation);
        }
        self.witness.as_ref().map(|witness| {
            if witness
                .last_transaction_state
                .as_ref()
                .is_some_and(|transaction| {
                    !matches!(
                        transaction.reconciliation_status,
                        WitnessReconciliationStatus::Confirmed
                            | WitnessReconciliationStatus::Rejected
                    )
                })
            {
                WitnessRotationPhase::BlockedByUnresolvedSignedOperation
            } else {
                WitnessRotationPhase::RotationRequired
            }
        })
    }

    /// Rewinds the marker a refused reset wrote, once its cause is gone.
    ///
    /// `reset_before_witness_rotation` durably writes its refusal phase, and
    /// nothing used to write it back. A cleared approval therefore left the
    /// phone permanently claiming a controlled rotation was required with no
    /// rotation to run, and a cleared witness confirmation left the same lie
    /// behind `BlockedByUnresolvedSignedOperation`. Only those two refusal
    /// markers are ever rewritten, and only to whatever the reset would refuse
    /// with now - `Stable` when it would not refuse at all. Every other phase,
    /// including `Completed`, stands untouched.
    #[cfg(any(target_os = "android", test))]
    fn rewind_reset_refusal_marker(&mut self) {
        if matches!(
            self.rotation_phase,
            WitnessRotationPhase::BlockedByPendingApproval
                | WitnessRotationPhase::BlockedByUnresolvedSignedOperation
        ) {
            self.rotation_phase = self
                .rotation_blocking_phase()
                .unwrap_or(WitnessRotationPhase::Stable);
        }
    }

    /// Forgets the pilot approval naming this exact operation.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn clear_pending_approval_for(&mut self, operation_id: &str) -> Result<(), String> {
        let pending = self
            .pending_approval
            .as_ref()
            .ok_or_else(|| "No pilot approval is pending".to_owned())?;
        if pending.decision.operation_id != operation_id {
            return Err("Pilot approval completion scope mismatch".to_owned());
        }
        self.pending_approval = None;
        self.rewind_reset_refusal_marker();
        Ok(())
    }

    /// Forgets the exact Agent Fast Pay decision only after a matching desktop
    /// acknowledgement or an explicit owner discard.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn clear_pending_agent_fast_pay_approval_for(
        &mut self,
        operation_id: &str,
    ) -> Result<(), String> {
        let pending = self
            .pending_agent_fast_pay_approval
            .as_ref()
            .ok_or_else(|| "No Agent Fast Pay approval is pending".to_owned())?;
        if pending.decision.commitment.operation_id != operation_id {
            return Err("Agent Fast Pay approval completion scope mismatch".to_owned());
        }
        self.pending_agent_fast_pay_approval = None;
        self.rewind_reset_refusal_marker();
        Ok(())
    }

    #[cfg(any(target_os = "android", test))]
    pub(super) fn clear_pending_agent_hvm_approval_for(
        &mut self,
        operation_id: &str,
    ) -> Result<(), String> {
        let pending = self
            .pending_agent_hvm_approval
            .as_ref()
            .ok_or_else(|| "No Agent HVM approval is pending".to_owned())?;
        if pending.decision.commitment.operation_id != operation_id {
            return Err("Agent HVM approval completion scope mismatch".to_owned());
        }
        self.pending_agent_hvm_approval = None;
        self.rewind_reset_refusal_marker();
        Ok(())
    }

    /// Forgets the witness confirmation naming this exact operation.
    ///
    /// This ends the phone's local intent to sign and nothing else. It never
    /// advances, completes or fakes a witness: the signed evidence is
    /// [`MobileWitnessState`], which this does not touch, so an operation with
    /// no receipt stays exactly as unwitnessed as it was.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn clear_pending_witness_for(&mut self, operation_id: &str) -> Result<(), String> {
        let pending = self
            .pending_witness
            .as_ref()
            .ok_or_else(|| "No witness confirmation is pending".to_owned())?;
        if pending.operation_id != operation_id {
            return Err("Pilot witness completion scope mismatch".to_owned());
        }
        self.pending_witness = None;
        self.rewind_reset_refusal_marker();
        Ok(())
    }

    /// The consent record, if any, that is provably obsolete right now.
    ///
    /// Two things can prove it, and nothing else may:
    ///
    /// * `desktop_awaiting` - the operation ids an authenticated status
    ///   snapshot from the paired desktop listed as awaiting this phone's
    ///   rollback witness. A record naming an operation that is not in that
    ///   list, after the grace period, is one the desktop will not accept a
    ///   receipt for. `None` means no statement was available and proves
    ///   nothing.
    /// * age - a record older than [`CONSENT_MAX_AGE_SECS`], which is the only
    ///   exit for a phone whose desktop is gone for good.
    ///
    /// A transport error proves nothing and must never reach here: a flaky or
    /// hostile desktop could otherwise erase the owner's consent for a live
    /// payment by simply refusing to answer.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn obsolete_consent(
        &self,
        desktop_awaiting: Option<&[String]>,
        now: u64,
    ) -> Option<MobileDiscardedConsent> {
        fn retired(
            operation_id: &str,
            recorded_at: u64,
            desktop_awaiting: Option<&[String]>,
            now: u64,
        ) -> Option<&'static str> {
            // A desktop that is still asking for this witness outranks every
            // other signal, and it is checked first. Age used to be checked
            // first, so a reconciliation that legitimately ran past
            // `CONSENT_MAX_AGE_SECS` had the owner's consent retired out from
            // under a witness card that was still on screen - and so did any
            // phone whose clock jumped forward a day. Retaining is always the
            // safe direction: a record the desktop still offers is a record the
            // owner still has a working button for.
            let awaiting = desktop_awaiting;
            if awaiting.is_some_and(|awaiting| awaiting.iter().any(|id| id == operation_id)) {
                return None;
            }
            if now > recorded_at.saturating_add(CONSENT_MAX_AGE_SECS) {
                return Some(DISCARD_AGED_OUT);
            }
            awaiting?;
            (now > recorded_at.saturating_add(CONSENT_DESKTOP_SILENCE_GRACE_SECS))
                .then_some(DISCARD_DESKTOP_NO_LONGER_AWAITING)
        }

        if let Some(pending) = &self.pending_witness {
            let confirmed_at = parse_decimal_u64(&pending.confirmed_at).unwrap_or(0);
            if let Some(reason) =
                retired(&pending.operation_id, confirmed_at, desktop_awaiting, now)
            {
                return Some(MobileDiscardedConsent::from_witness(pending, reason, now));
            }
        }
        if let Some(pending) = &self.pending_approval
            && let Some(reason) = retired(
                &pending.decision.operation_id,
                pending.decision.issued_at,
                desktop_awaiting,
                now,
            )
        {
            return Some(MobileDiscardedConsent::from_approval(pending, reason, now));
        }
        if let Some(pending) = &self.pending_agent_fast_pay_approval
            && let Some(reason) = retired(
                &pending.decision.commitment.operation_id,
                pending.decision.decision_issued_at,
                None,
                now,
            )
        {
            return Some(MobileDiscardedConsent::from_agent_fast_pay_approval(
                pending, reason, now,
            ));
        }
        if let Some(pending) = &self.pending_agent_hvm_approval
            && let Some(reason) = retired(
                &pending.decision.commitment.operation_id,
                pending.decision.decision_issued_at,
                None,
                now,
            )
        {
            return Some(MobileDiscardedConsent::from_agent_hvm_approval(
                pending, reason, now,
            ));
        }
        None
    }

    /// Applies a discard produced by [`Self::obsolete_consent`] or by the
    /// owner, and appends a receipt for it.
    ///
    /// The receipt is validated before the record is cleared, so a receipt that
    /// could not be written refuses the discard rather than clearing silently.
    /// That direction is the recoverable one: a refused discard can be tried
    /// again, a discard with no receipt cannot be undone. Every field of a
    /// receipt is guaranteed by the source record's own validation, so this can
    /// only fire on a state that would already have failed to load.
    ///
    /// The receipt is appended, never substituted. The history used to be one
    /// slot, so a second discard erased the first with nothing said - see
    /// [`MAX_DISCARDED_CONSENTS`] for what bounds it now and what happens when
    /// that bound is reached.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn apply_consent_discard(
        &mut self,
        discard: MobileDiscardedConsent,
    ) -> Result<(), String> {
        discard.validate()?;
        match discard.kind.as_str() {
            DISCARDED_WITNESS_CONFIRMATION => {
                self.clear_pending_witness_for(&discard.operation_id)?;
            }
            DISCARDED_PILOT_APPROVAL => {
                self.clear_pending_approval_for(&discard.operation_id)?;
            }
            DISCARDED_AGENT_FAST_PAY_APPROVAL => {
                self.clear_pending_agent_fast_pay_approval_for(&discard.operation_id)?;
            }
            DISCARDED_AGENT_HVM_APPROVAL => {
                self.clear_pending_agent_hvm_approval_for(&discard.operation_id)?;
            }
            _ => return Err("Discarded consent record is invalid".to_owned()),
        }
        push_discard_bounded(
            &mut self.discarded_consents,
            &mut self.discarded_consents_dropped,
            discard,
        );
        Ok(())
    }

    /// The owner's own discard of one exact operation they named.
    ///
    /// The only exit that cannot be derived from desktop state, so it is
    /// deliberately the owner's act. The operation id has to match what this
    /// phone is holding, so the screen must show the payment before the press
    /// rather than after it.
    #[cfg(any(target_os = "android", test))]
    pub(super) fn owner_discard_consent(
        &mut self,
        operation_id: &str,
        now: u64,
    ) -> Result<MobileDiscardedConsent, String> {
        let discard = if self
            .pending_witness
            .as_ref()
            .is_some_and(|pending| pending.operation_id == operation_id)
        {
            MobileDiscardedConsent::from_witness(
                self.pending_witness.as_ref().expect("checked above"),
                DISCARD_OWNER,
                now,
            )
        } else if self
            .pending_approval
            .as_ref()
            .is_some_and(|pending| pending.decision.operation_id == operation_id)
        {
            MobileDiscardedConsent::from_approval(
                self.pending_approval.as_ref().expect("checked above"),
                DISCARD_OWNER,
                now,
            )
        } else if self
            .pending_agent_fast_pay_approval
            .as_ref()
            .is_some_and(|pending| pending.decision.commitment.operation_id == operation_id)
        {
            MobileDiscardedConsent::from_agent_fast_pay_approval(
                self.pending_agent_fast_pay_approval
                    .as_ref()
                    .expect("checked above"),
                DISCARD_OWNER,
                now,
            )
        } else if self
            .pending_agent_hvm_approval
            .as_ref()
            .is_some_and(|pending| pending.decision.commitment.operation_id == operation_id)
        {
            MobileDiscardedConsent::from_agent_hvm_approval(
                self.pending_agent_hvm_approval
                    .as_ref()
                    .expect("checked above"),
                DISCARD_OWNER,
                now,
            )
        } else {
            return Err("This phone is not holding a confirmation for that payment".to_owned());
        };
        self.apply_consent_discard(discard.clone())?;
        Ok(discard)
    }
}

/// Why the pairing-only reset is refusing, in the words of the actual blocker.
///
/// The single old sentence named a controlled desktop/mobile witness rotation
/// whatever the cause. When the cause was a held consent record that was worse
/// than unhelpful: the owner ran the rotation, the rotation completed, and the
/// reset refused again - because a held record blocks it regardless of any
/// rotation phase. A rotation is only the answer when witness state is the
/// blocker, and only then is it named.
fn reset_refusal_message(state: &MobileCompanionDurableState) -> String {
    if state.pending_witness.is_some() {
        return "Companion reset is blocked because this phone is still holding your confirmation to witness one payment. Finish that payment, or discard the confirmation on this screen, and try again. Running a witness rotation does not clear it."
            .to_owned();
    }
    if state.pending_approval.is_some() {
        return "Companion reset is blocked because this phone is still holding one pilot approval. Finish that payment, or discard the approval on this screen, and try again. Running a witness rotation does not clear it."
            .to_owned();
    }
    if state.pending_agent_fast_pay_approval.is_some() {
        return "Companion reset is blocked because this phone is still holding one Agent Fast Pay approval. Finish that approval, or discard it on this screen, and try again. Running a witness rotation does not clear it."
            .to_owned();
    }
    if state.pending_agent_hvm_approval.is_some() {
        return "Companion reset is blocked because this phone is still holding one Agent HVM Fast Pay approval. Finish that approval, or discard it on this screen, and try again. Running a witness rotation does not clear it."
            .to_owned();
    }
    "Companion reset is blocked after pilot approval or witness initialization; controlled desktop/mobile witness rotation is required"
        .to_owned()
}

fn is_signature(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_record(
    registry: &DeviceRegistry,
    device_id: &DeviceId,
    wallet_id: &str,
    role: DeviceRole,
) -> Result<DevicePublicRecord, String> {
    let record = registry
        .records()
        .find(|record| &record.device_id == device_id)
        .ok_or_else(|| "Agent companion state is missing a paired device".to_owned())?;
    record.validate().map_err(|error| error.to_string())?;
    if record.is_revoked() || record.agent_wallet_id != wallet_id || record.role != role {
        return Err("Agent companion device scope does not match durable state".to_owned());
    }
    Ok(record.clone())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableStateDocument {
    state_version: String,
    agent_wallet_id: String,
    desktop_device_id: DeviceId,
    mobile_device_id: DeviceId,
    endpoints: Vec<LanEndpoint>,
    registry: DeviceRegistry,
    replay: DurableReplayDocument,
    response_sequence: String,
    #[serde(default = "decimal_zero")]
    approval_sequence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_pairing_ack: Option<EncryptedCompanionFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_approval: Option<MobilePendingApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_agent_fast_pay_approval: Option<MobilePendingAgentFastPayApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_agent_hvm_approval: Option<MobilePendingAgentHvmApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_witness: Option<MobilePendingWitness>,
    /// The single receipt the previous build wrote, read and never written.
    ///
    /// The document is `deny_unknown_fields`, and a state file that fails to
    /// decode disables the whole companion - including every consent exit -
    /// so the old key has to stay readable. A phone updating into the bounded
    /// history folds its one receipt in as the oldest entry and writes the
    /// list from then on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discarded_consent: Option<MobileDiscardedConsent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    discarded_consents: Vec<MobileDiscardedConsent>,
    #[serde(default = "decimal_zero", skip_serializing_if = "is_decimal_zero")]
    discarded_consents_dropped: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness: Option<MobileWitnessState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_phase: Option<WitnessRotationPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rotation_authorization: Option<SignedWitnessRotationAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rotation_baseline: Option<SignedWitnessRotationBaselineReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_ticket: Option<SignedRotationPairingTicket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_candidate_acceptance: Option<SignedRotationCandidateAcceptance>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableReplayDocument {
    snapshot_version: String,
    high_water_marks: Vec<DurableHighWaterMark>,
    used_nonces: Vec<DurableNonceRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableHighWaterMark {
    context: String,
    sender_device_id: DeviceId,
    last_sequence: String,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableNonceRecord {
    context: String,
    sender_device_id: DeviceId,
    nonce: String,
    issued_at: String,
    expires_at: String,
}

impl From<&MobileCompanionDurableState> for DurableStateDocument {
    fn from(state: &MobileCompanionDurableState) -> Self {
        Self {
            state_version: state.state_version.to_string(),
            agent_wallet_id: state.agent_wallet_id.clone(),
            desktop_device_id: state.desktop_device_id.clone(),
            mobile_device_id: state.mobile_device_id.clone(),
            endpoints: state.endpoints.clone(),
            registry: state.registry.clone(),
            replay: DurableReplayDocument {
                snapshot_version: state.replay.snapshot_version.to_string(),
                high_water_marks: state
                    .replay
                    .high_water_marks
                    .iter()
                    .map(|mark| DurableHighWaterMark {
                        context: mark.context.clone(),
                        sender_device_id: mark.sender_device_id.clone(),
                        last_sequence: mark.last_sequence.to_string(),
                        expires_at: mark.expires_at.to_string(),
                    })
                    .collect(),
                used_nonces: state
                    .replay
                    .used_nonces
                    .iter()
                    .map(|record| DurableNonceRecord {
                        context: record.context.clone(),
                        sender_device_id: record.sender_device_id.clone(),
                        nonce: record.nonce.clone(),
                        issued_at: record.issued_at.to_string(),
                        expires_at: record.expires_at.to_string(),
                    })
                    .collect(),
            },
            response_sequence: state.response_sequence.to_string(),
            approval_sequence: state.approval_sequence.to_string(),
            pending_pairing_ack: state.pending_pairing_ack.clone(),
            pending_approval: state.pending_approval.clone(),
            pending_agent_fast_pay_approval: state.pending_agent_fast_pay_approval.clone(),
            pending_agent_hvm_approval: state.pending_agent_hvm_approval.clone(),
            pending_witness: state.pending_witness.clone(),
            // Never written again: the history below replaces it.
            discarded_consent: None,
            discarded_consents: state.discarded_consents.clone(),
            discarded_consents_dropped: state.discarded_consents_dropped.to_string(),
            witness: state.witness.clone(),
            rotation_phase: Some(state.rotation_phase),
            pending_rotation_authorization: state.pending_rotation_authorization.clone(),
            pending_rotation_baseline: state.pending_rotation_baseline.clone(),
            rotation_ticket: state.rotation_ticket.clone(),
            rotation_candidate_acceptance: state.rotation_candidate_acceptance.clone(),
        }
    }
}

impl TryFrom<DurableStateDocument> for MobileCompanionDurableState {
    type Error = String;

    fn try_from(document: DurableStateDocument) -> Result<Self, Self::Error> {
        let rotation_phase = document
            .rotation_phase
            .unwrap_or(WitnessRotationPhase::Stable);
        // The one receipt an older build wrote is the oldest thing this phone
        // knows, so it goes first. No build ever writes both keys; if a hand
        // edited file carries both, the pair is still kept in that order
        // rather than one of them being dropped on the floor.
        let mut discarded_consents_dropped =
            parse_decimal_u64(&document.discarded_consents_dropped)?;
        let mut discarded_consents: Vec<MobileDiscardedConsent> = document
            .discarded_consent
            .into_iter()
            .chain(document.discarded_consents)
            .collect();
        trim_discard_history(&mut discarded_consents, &mut discarded_consents_dropped);
        Ok(Self {
            state_version: parse_decimal_u64(&document.state_version)?,
            agent_wallet_id: document.agent_wallet_id,
            desktop_device_id: document.desktop_device_id,
            mobile_device_id: document.mobile_device_id,
            endpoints: document.endpoints,
            registry: document.registry,
            replay: ReplayGuardSnapshot {
                snapshot_version: parse_decimal_u64(&document.replay.snapshot_version)?,
                high_water_marks: document
                    .replay
                    .high_water_marks
                    .into_iter()
                    .map(|mark| {
                        Ok(ReplayHighWaterMark {
                            context: mark.context,
                            sender_device_id: mark.sender_device_id,
                            last_sequence: parse_decimal_u64(&mark.last_sequence)?,
                            expires_at: parse_decimal_u64(&mark.expires_at)?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
                used_nonces: document
                    .replay
                    .used_nonces
                    .into_iter()
                    .map(|record| {
                        Ok(ReplayNonceRecord {
                            context: record.context,
                            sender_device_id: record.sender_device_id,
                            nonce: record.nonce,
                            issued_at: parse_decimal_u64(&record.issued_at)?,
                            expires_at: parse_decimal_u64(&record.expires_at)?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
            },
            response_sequence: parse_decimal_u64(&document.response_sequence)?,
            approval_sequence: parse_decimal_u64(&document.approval_sequence)?,
            pending_pairing_ack: document.pending_pairing_ack,
            pending_approval: document.pending_approval,
            pending_agent_fast_pay_approval: document.pending_agent_fast_pay_approval,
            pending_agent_hvm_approval: document.pending_agent_hvm_approval,
            pending_witness: document.pending_witness,
            discarded_consents,
            discarded_consents_dropped,
            witness: document.witness,
            rotation_phase,
            pending_rotation_authorization: document.pending_rotation_authorization,
            pending_rotation_baseline: document.pending_rotation_baseline,
            rotation_ticket: document.rotation_ticket,
            rotation_candidate_acceptance: document.rotation_candidate_acceptance,
        })
    }
}

fn decimal_zero() -> String {
    "0".to_owned()
}

/// Keeps a zero counter out of the document, so a phone that has discarded
/// nothing writes exactly the bytes it wrote before this history existed.
fn is_decimal_zero(value: &str) -> bool {
    value == "0"
}

fn parse_decimal_u64(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("u64 state values must be strict decimal strings".to_owned());
    }
    value
        .parse::<u64>()
        .map_err(|_| "u64 state value is out of range".to_owned())
}

pub(super) fn encode_state(state: &MobileCompanionDurableState) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&DurableStateDocument::from(state)).map_err(|error| error.to_string())
}

fn decode_state(bytes: &[u8], now: u64) -> Result<MobileCompanionDurableState, String> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err("Agent companion state has an invalid size".to_owned());
    }
    let document: DurableStateDocument =
        serde_json::from_slice(bytes).map_err(|error| format!("decode Agent state: {error}"))?;
    let state = MobileCompanionDurableState::try_from(document)?;
    state.validate_at(now)?;
    Ok(state)
}

pub(super) struct SharedCompanionState {
    store: Arc<dyn CompanionStateStore>,
    pub(super) state: Mutex<Option<MobileCompanionDurableState>>,
    initialization_error: RwLock<Option<String>>,
}

impl std::fmt::Debug for SharedCompanionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedCompanionState")
            .field("state", &"<public-pairing-and-replay-state>")
            .field(
                "initialization_error",
                &self.initialization_error.read().map(|value| value.clone()),
            )
            .finish()
    }
}

impl SharedCompanionState {
    pub(super) fn open(store: Arc<dyn CompanionStateStore>) -> Self {
        let loaded = store.load().and_then(|bytes| {
            bytes
                .map(|bytes| decode_state(&bytes, unix_now()?))
                .transpose()
        });
        match loaded {
            Ok(state) => Self {
                store,
                state: Mutex::new(state),
                initialization_error: RwLock::new(None),
            },
            Err(error) => Self {
                store,
                state: Mutex::new(None),
                initialization_error: RwLock::new(Some(error)),
            },
        }
    }

    pub(super) fn require_available(&self) -> Result<(), String> {
        let error = self
            .initialization_error
            .read()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())?;
        if let Some(error) = error.as_ref() {
            return Err(format!(
                "Agent companion is disabled because durable state is invalid: {error}"
            ));
        }
        Ok(())
    }

    pub(super) async fn current(&self) -> Result<Option<MobileCompanionDurableState>, String> {
        self.require_available()?;
        Ok(self.state.lock().await.clone())
    }

    #[cfg(target_os = "android")]
    pub(super) async fn clear_pending_pairing_ack(&self) -> Result<(), String> {
        self.require_available()?;
        let mut slot = self.state.lock().await;
        let Some(current) = slot.as_ref() else {
            return Ok(());
        };
        if current.pending_pairing_ack.is_none() {
            return Ok(());
        }
        let mut next = current.clone();
        next.pending_pairing_ack = None;
        self.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn install_new(
        &self,
        state: MobileCompanionDurableState,
    ) -> Result<(), String> {
        self.require_available()?;
        state.validate_at(unix_now()?)?;
        let bytes = encode_state(&state)?;
        let mut slot = self.state.lock().await;
        if slot.is_some() {
            return Err("This phone is already paired; explicit reset is required".to_owned());
        }
        self.store.replace(Some(&bytes))?;
        *slot = Some(state);
        Ok(())
    }

    #[cfg(any(target_os = "android", test))]
    pub(super) fn persist_locked(&self, state: &MobileCompanionDurableState) -> Result<(), String> {
        self.require_available()?;
        state.validate_at(unix_now()?)?;
        self.store.replace(Some(&encode_state(state)?))
    }

    /// Retires a consent record the desktop, or time, has proved obsolete.
    ///
    /// Returns the receipt when something was discarded. Callers pass the
    /// desktop's own statement, never a transport error - see
    /// [`MobileCompanionDurableState::obsolete_consent`].
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn sweep_obsolete_consent(
        &self,
        desktop_awaiting: Option<&[String]>,
        now: u64,
    ) -> Result<Option<MobileDiscardedConsent>, String> {
        self.require_available()?;
        let mut slot = self.state.lock().await;
        let Some(current) = slot.as_ref() else {
            return Ok(None);
        };
        let Some(discard) = current.obsolete_consent(desktop_awaiting, now) else {
            return Ok(None);
        };
        let mut next = current.clone();
        next.apply_consent_discard(discard.clone())?;
        self.persist_locked(&next)?;
        *slot = Some(next);
        Ok(Some(discard))
    }

    /// The owner's explicit discard of the exact operation they were shown.
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn discard_consent_by_owner(
        &self,
        operation_id: &str,
        now: u64,
    ) -> Result<MobileDiscardedConsent, String> {
        self.require_available()?;
        let mut slot = self.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "This phone is not paired, so it holds no confirmation".to_owned())?
            .clone();
        let mut next = current;
        let discard = next.owner_discard_consent(operation_id, now)?;
        self.persist_locked(&next)?;
        *slot = Some(next);
        Ok(discard)
    }

    pub(super) async fn reset_before_witness_rotation(&self) -> Result<(), String> {
        let mut slot = self.state.lock().await;
        if let Some(current) = slot.as_ref()
            && let Some(phase) = current.rotation_blocking_phase()
        {
            let message = reset_refusal_message(current);
            // A refusal must not downgrade a terminal phase. Overwriting
            // `Completed` with a blocking marker told an owner who had just
            // finished a controlled rotation to go and run it again, for ever.
            if current.rotation_phase != WitnessRotationPhase::Completed
                && current.rotation_phase != phase
            {
                let mut next = current.clone();
                next.rotation_phase = phase;
                // The marker is a diagnostic, never a reason to write durable
                // state the loader would reject. A restricted rotation
                // candidate constrains its own phase, and this write did not
                // respect that: the refusal wrote a phase `validate_at`
                // forbids, which disabled the whole companion on the next
                // launch and - because every consent exit persists through
                // `persist_locked`, which validates - killed the owner discard
                // and the automatic sweep that this same refusal message tells
                // the owner to use. A marker that will not fit is simply not
                // written; the refusal itself is unchanged.
                if next.validate_at(unix_now()?).is_ok() {
                    let bytes = encode_state(&next)?;
                    self.store.replace(Some(&bytes))?;
                    *slot = Some(next);
                }
            }
            return Err(message);
        }
        self.store.replace(None)?;
        *slot = None;
        *self
            .initialization_error
            .write()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())? = None;
        Ok(())
    }

    /// Clears a pairing whose Android identity this phone no longer holds.
    ///
    /// This is the only reset that runs while a pilot approval or witness record
    /// exists, and it is safe for one reason: the durable witness state is bound
    /// to `mobile_device_id`, which is derived from the companion public key. If
    /// that key is gone - deleted, or invalidated in hardware by a new biometric
    /// enrolment - this phone can never sign a witness receipt as that device
    /// again, so the anti-rollback high-water mark it is holding can never be
    /// presented to anyone and protects nothing. Erasing it destroys no
    /// guarantee.
    ///
    /// The invariant is checked here, against the durable state itself, and the
    /// caller must pass the identity it actually read from the Keystore. A live
    /// identity that still matches is refused: that phone must use the ordinary
    /// pairing-only reset, or the controlled rotation, exactly as before.
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn reset_orphaned_pairing(
        &self,
        live_device_id: Option<&DeviceId>,
    ) -> Result<(), String> {
        let mut slot = self.state.lock().await;
        let Some(current) = slot.as_ref() else {
            return Err("This phone is not paired, so there is nothing to retire".to_owned());
        };
        if live_device_id == Some(&current.mobile_device_id) {
            return Err(
                "This phone still holds the exact secure identity this pairing is bound to, so its witness state still counts"
                    .to_owned(),
            );
        }
        self.store.replace(None)?;
        *slot = None;
        *self
            .initialization_error
            .write()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())? = None;
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn reset(&self) -> Result<(), String> {
        let mut slot = self.state.lock().await;
        self.store.replace(None)?;
        *slot = None;
        *self
            .initialization_error
            .write()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())? = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use hpay_companion_protocol::{
        AGENT_FAST_PAY_APPROVAL_VERSION, AGENT_HVM_APPROVAL_VERSION,
        AgentFastPayApprovalCommitment, AgentFastPayNetworkBinding, AgentHvmApprovalCommitment,
        CompanionError, ReplayMetadata, SoftwareDeviceIdentity,
    };

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        bytes: StdMutex<Option<Vec<u8>>>,
        fail_replace: AtomicBool,
    }

    impl MemoryStore {
        fn with_bytes(bytes: Vec<u8>) -> Self {
            Self {
                bytes: StdMutex::new(Some(bytes)),
                fail_replace: AtomicBool::new(false),
            }
        }
    }

    impl CompanionStateStore for MemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.bytes.lock().unwrap().clone())
        }

        fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String> {
            if self.fail_replace.load(Ordering::SeqCst) {
                return Err("injected persistence failure".to_owned());
            }
            *self.bytes.lock().unwrap() = bytes.map(ToOwned::to_owned);
            Ok(())
        }
    }

    fn state_fixture(now: u64) -> MobileCompanionDurableState {
        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), now - 1)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                mobile
                    .public_record(
                        "wallet_one",
                        BTreeSet::from([
                            DevicePermission::ViewAgentWalletStatus,
                            DevicePermission::ApprovePayment,
                            DevicePermission::RejectPayment,
                        ]),
                        now - 1,
                    )
                    .unwrap(),
            )
            .unwrap();
        MobileCompanionDurableState {
            state_version: STATE_VERSION,
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            mobile_device_id: mobile.device_id().clone(),
            endpoints: vec![LanEndpoint::parse("hpay-lan://192.168.1.8:42492").unwrap()],
            registry,
            replay: ReplayGuard::new().snapshot(now).unwrap(),
            response_sequence: 0,
            approval_sequence: 0,
            pending_pairing_ack: None,
            pending_approval: None,
            pending_agent_fast_pay_approval: None,
            pending_agent_hvm_approval: None,
            pending_witness: None,
            discarded_consents: Vec::new(),
            discarded_consents_dropped: 0,
            witness: None,
            rotation_phase: WitnessRotationPhase::Stable,
            pending_rotation_authorization: None,
            pending_rotation_baseline: None,
            rotation_ticket: None,
            rotation_candidate_acceptance: None,
        }
    }

    fn pending_agent_fast_pay(
        state: &MobileCompanionDurableState,
        now: u64,
    ) -> MobilePendingAgentFastPayApproval {
        let commitment = AgentFastPayApprovalCommitment {
            approval_version: AGENT_FAST_PAY_APPROVAL_VERSION,
            approval_id: "fast_pay_approval_mobile_storage".to_owned(),
            challenge_nonce: "ab".repeat(16),
            operation_id: "operation_fast_pay_mobile_storage".to_owned(),
            hub_operation_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            public_idempotency_key: "agent-mobile-storage-key".to_owned(),
            hub_idempotency_key: "hpay-agent:550e8400-e29b-41d4-a716-446655440001".to_owned(),
            agent_wallet_id: state.agent_wallet_id.clone(),
            wallet_scope: format!("agent_wallet:{}", state.agent_wallet_id),
            agent_id: "agent_mobile_storage".to_owned(),
            desktop_device_id: state.desktop_device_id.clone(),
            request_commitment: "aa".repeat(32),
            binding_commitment: "bb".repeat(32),
            route_commitment: "cc".repeat(32),
            payer: "1Payer".to_owned(),
            payee: "1Payee".to_owned(),
            amount_hac: "0.012".to_owned(),
            amount_units: 12_000,
            amount_millimeis: 12,
            hub_url: "https://hub.example".to_owned(),
            hub_address: "1Hub".to_owned(),
            channel_id: "dd".repeat(16),
            channel_reuse_version: 7,
            channel_open_height: 900_000,
            fee_payer: "sender".to_owned(),
            network_fee_units: 0,
            wallet_fee_units: 0,
            hub_fee_units: 0,
            total_debit_units: 12_000,
            policy_epoch: 3,
            signer_epoch: 4,
            emergency_epoch: 5,
            issued_at: now,
            expires_at: now + 300,
            network_binding: AgentFastPayNetworkBinding {
                network_mode: "testnet".to_owned(),
                chain_id: 7,
                genesis_identifier: "ee".repeat(32),
                node_profile_id: "fa".repeat(32),
                network_instance_id: "testnet:mobile-storage".to_owned(),
                transaction_format_version: 2,
            },
        };
        let authorization_epoch = state
            .registry
            .require(
                &state.mobile_device_id,
                &state.agent_wallet_id,
                DeviceRole::Mobile,
                DevicePermission::ApprovePayment,
            )
            .unwrap()
            .authorization_epoch;
        let decision = AgentFastPayApprovalDecision::from_commitment(
            commitment,
            ApprovalDecision::Approve,
            state.mobile_device_id.clone(),
            authorization_epoch,
            1,
            now + 1,
        )
        .unwrap();
        MobilePendingAgentFastPayApproval {
            state_version: "1".to_owned(),
            commitment_hash: decision.commitment_sha256.clone(),
            decision,
            signed_decision: None,
        }
    }

    fn pending_agent_hvm(
        state: &MobileCompanionDurableState,
        now: u64,
    ) -> MobilePendingAgentHvmApproval {
        let commitment = AgentHvmApprovalCommitment {
            approval_version: AGENT_HVM_APPROVAL_VERSION,
            approval_id: "hvm_approval_mobile_storage".to_owned(),
            challenge_nonce: "11".repeat(16),
            operation_id: "operation_hvm_mobile_storage".to_owned(),
            hub_operation_id: "550e8400-e29b-41d4-a716-446655440010".to_owned(),
            public_idempotency_key: "agent-hvm-mobile-storage-key".to_owned(),
            hub_idempotency_key: "hpay-agent-hvm:550e8400-e29b-41d4-a716-446655440011".to_owned(),
            agent_wallet_id: state.agent_wallet_id.clone(),
            wallet_scope: format!("agent_wallet:{}", state.agent_wallet_id),
            agent_id: "agent_hvm_mobile_storage".to_owned(),
            agent_authorization_epoch: 2,
            desktop_device_id: state.desktop_device_id.clone(),
            hub_url: "https://hub.example".to_owned(),
            hub_address: "1Hub".to_owned(),
            settlement_profile: "hpay-hvm-channel-v1".to_owned(),
            contract_address: "3Contract".to_owned(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 900_000,
            bytecode_sha3: "11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349"
                .to_owned(),
            channel_id: "33".repeat(16),
            channel_reuse_version: 1,
            challenge_blocks: 12,
            binding_commitment: "44".repeat(32),
            lease_snapshot_commitment: "55".repeat(32),
            previous_bill_commitment: "66".repeat(32),
            unsigned_request_commitment: "77".repeat(32),
            payer: "1Payer".to_owned(),
            payee: "provider:compute".to_owned(),
            amount_hac: "0.01".to_owned(),
            amount_zhu: 1_000_000,
            fee_payer: "sender".to_owned(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: 1_000_000,
            policy_epoch: 3,
            signer_epoch: 4,
            emergency_epoch: 5,
            issued_at: now,
            expires_at: now + 300,
            network_binding: AgentFastPayNetworkBinding {
                network_mode: "testnet".to_owned(),
                chain_id: 7,
                genesis_identifier: "88".repeat(32),
                node_profile_id: "hpay-local-pilot-chain-v1".to_owned(),
                network_instance_id: "testnet:hvm-mobile-storage".to_owned(),
                transaction_format_version: 2,
            },
        };
        let authorization_epoch = state
            .registry
            .require(
                &state.mobile_device_id,
                &state.agent_wallet_id,
                DeviceRole::Mobile,
                DevicePermission::ApprovePayment,
            )
            .unwrap()
            .authorization_epoch;
        let decision = AgentHvmApprovalDecision::from_commitment(
            commitment,
            ApprovalDecision::Approve,
            state.mobile_device_id.clone(),
            authorization_epoch,
            1,
            now + 1,
        )
        .unwrap();
        MobilePendingAgentHvmApproval {
            state_version: "1".to_owned(),
            commitment_hash: decision.commitment_sha256.clone(),
            decision,
            signed_decision: None,
        }
    }

    #[test]
    fn agent_fast_pay_consent_roundtrips_blocks_reset_and_has_an_owner_exit() {
        let now = 10_000;
        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_agent_fast_pay_approval = Some(pending_agent_fast_pay(&state, now));
        let encoded = encode_state(&state).unwrap();
        let mut decoded = decode_state(&encoded, now + 2).unwrap();
        assert_eq!(
            decoded.pending_agent_fast_pay_approval,
            state.pending_agent_fast_pay_approval
        );
        assert_eq!(
            decoded.rotation_blocking_phase(),
            Some(WitnessRotationPhase::BlockedByPendingApproval)
        );
        let operation_id = decoded
            .pending_agent_fast_pay_approval
            .as_ref()
            .unwrap()
            .decision
            .commitment
            .operation_id
            .clone();
        let receipt = decoded
            .owner_discard_consent(&operation_id, now + 3)
            .unwrap();
        assert_eq!(receipt.kind, DISCARDED_AGENT_FAST_PAY_APPROVAL);
        assert!(decoded.pending_agent_fast_pay_approval.is_none());
        assert_eq!(decoded.discarded_consents.last(), Some(&receipt));
    }

    #[test]
    fn agent_fast_pay_consent_cannot_coexist_or_use_a_stale_authorization_epoch() {
        let now = 20_000;
        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_agent_fast_pay_approval = Some(pending_agent_fast_pay(&state, now));
        state.pending_witness = Some(MobilePendingWitness {
            state_version: "1".to_owned(),
            operation_id: "operation_other".to_owned(),
            amount_units: "1".to_owned(),
            recipient: "1Other".to_owned(),
            status: hpay_companion_protocol::WITNESS_PENDING_ACTIVITY_STATUSES[0].to_owned(),
            confirmed_at: now.to_string(),
        });
        assert!(state.validate_at(now + 2).is_err());

        state.pending_witness = None;
        state
            .pending_agent_fast_pay_approval
            .as_mut()
            .unwrap()
            .decision
            .device_authorization_epoch += 1;
        assert!(state.validate_at(now + 2).is_err());
    }

    #[test]
    fn agent_hvm_consent_roundtrips_blocks_reset_and_has_an_owner_exit() {
        let now = 30_000;
        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_agent_hvm_approval = Some(pending_agent_hvm(&state, now));
        let encoded = encode_state(&state).unwrap();
        let mut decoded = decode_state(&encoded, now + 2).unwrap();
        assert_eq!(
            decoded.pending_agent_hvm_approval,
            state.pending_agent_hvm_approval
        );
        assert_eq!(
            decoded.rotation_blocking_phase(),
            Some(WitnessRotationPhase::BlockedByPendingApproval)
        );
        let operation_id = decoded
            .pending_agent_hvm_approval
            .as_ref()
            .unwrap()
            .decision
            .commitment
            .operation_id
            .clone();
        let receipt = decoded
            .owner_discard_consent(&operation_id, now + 3)
            .unwrap();
        assert_eq!(receipt.kind, DISCARDED_AGENT_HVM_APPROVAL);
        assert!(decoded.pending_agent_hvm_approval.is_none());
        assert_eq!(decoded.discarded_consents.last(), Some(&receipt));
    }

    #[test]
    fn agent_hvm_consent_rejects_coexistence_fees_and_stale_authorization() {
        let now = 40_000;
        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_agent_hvm_approval = Some(pending_agent_hvm(&state, now));
        state.pending_agent_fast_pay_approval = Some(pending_agent_fast_pay(&state, now));
        assert!(state.validate_at(now + 2).is_err());

        state.pending_agent_fast_pay_approval = None;
        state
            .pending_agent_hvm_approval
            .as_mut()
            .unwrap()
            .decision
            .device_authorization_epoch += 1;
        assert!(state.validate_at(now + 2).is_err());

        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_agent_hvm_approval = Some(pending_agent_hvm(&state, now));
        state
            .pending_agent_hvm_approval
            .as_mut()
            .unwrap()
            .decision
            .commitment
            .wallet_fee_zhu = 1;
        assert!(state.validate_at(now + 2).is_err());
    }

    #[test]
    fn pending_pairing_ack_roundtrips_and_old_state_defaults_to_none() {
        let now = 1_000;
        let mut state = state_fixture(now);
        let ack = EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "pairing_session_one".to_owned(),
            sender_device_id: state.mobile_device_id.clone(),
            recipient_device_id: state.desktop_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: now + 120,
            nonce_hex: "11".repeat(12),
            ciphertext_hex: "22".repeat(32),
        };
        state.pending_pairing_ack = Some(ack.clone());
        let encoded = encode_state(&state).unwrap();
        let decoded = decode_state(&encoded, now).unwrap();
        assert_eq!(decoded.pending_pairing_ack, Some(ack));

        let mut old_document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        old_document
            .as_object_mut()
            .unwrap()
            .remove("pending_pairing_ack");
        let old_encoded = serde_json::to_vec(&old_document).unwrap();
        assert!(
            decode_state(&old_encoded, now)
                .unwrap()
                .pending_pairing_ack
                .is_none()
        );
    }
    #[test]
    fn durable_json_uses_only_decimal_strings_for_u64_values() {
        let state = state_fixture(1_000);
        let encoded = encode_state(&state).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        fn assert_no_numbers(value: &serde_json::Value) {
            match value {
                serde_json::Value::Number(number) => panic!("numeric JSON leaked: {number}"),
                serde_json::Value::Array(values) => values.iter().for_each(assert_no_numbers),
                serde_json::Value::Object(values) => values.values().for_each(assert_no_numbers),
                _ => {}
            }
        }
        assert_no_numbers(&value);
        let mut numeric = value;
        numeric["response_sequence"] = serde_json::json!(0);
        assert!(decode_state(&serde_json::to_vec(&numeric).unwrap(), 1_000).is_err());
        for invalid in ["", "00", "+1", "-1", "1.0", "18446744073709551616"] {
            assert!(parse_decimal_u64(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn corrupt_state_disables_companion_fail_closed() {
        let store = Arc::new(MemoryStore::with_bytes(
            br#"{"state_version":"1"}"#.to_vec(),
        ));
        let shared = SharedCompanionState::open(store);
        assert!(shared.current().await.unwrap_err().contains("disabled"));
    }

    #[tokio::test]
    async fn reset_recovers_from_corrupt_durable_state() {
        let store = Arc::new(MemoryStore::with_bytes(b"corrupt".to_vec()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        assert!(shared.current().await.unwrap_err().contains("disabled"));
        shared.reset().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert!(store.bytes.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn persistence_failure_never_publishes_pairing_or_reset() {
        let store = Arc::new(MemoryStore::default());
        store.fail_replace.store(true, Ordering::SeqCst);
        let shared = SharedCompanionState::open(store);
        assert!(shared.install_new(state_fixture(1_000)).await.is_err());
        assert!(shared.current().await.unwrap().is_none());

        let store = Arc::new(MemoryStore::default());
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        shared.install_new(state_fixture(1_000)).await.unwrap();
        store.fail_replace.store(true, Ordering::SeqCst);
        assert!(shared.reset().await.is_err());
        assert!(shared.current().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn file_reset_removes_only_companion_state_and_preserves_personal_sentinel() {
        let now = unix_now().unwrap();
        let root = std::env::temp_dir().join(format!(
            "hpay-mobile-companion-reset-{}-{now}",
            std::process::id()
        ));
        let personal = root.join("personal").join("vault.json");
        let companion = root.join("agent-companion").join("state.json");
        hacash_wallet_core::paths::secure_write(&personal, b"personal-sentinel").unwrap();
        let shared =
            SharedCompanionState::open(Arc::new(FileCompanionStateStore::new(companion.clone())));
        shared.install_new(state_fixture(now)).await.unwrap();
        assert!(companion.exists());

        shared.reset().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert_eq!(fs::read(&personal).unwrap(), b"personal-sentinel");
        if companion.exists() {
            assert_eq!(fs::read(&companion).unwrap(), RESET_MARKER);
        }

        let _ = fs::remove_file(&companion);
        let _ = fs::remove_file(&personal);
        let _ = fs::remove_dir(root.join("agent-companion"));
        let _ = fs::remove_dir(root.join("personal"));
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn persisted_replay_rejects_duplicate_after_restart() {
        let now = 1_000;
        let mut state = state_fixture(now);
        let replay = ReplayMetadata {
            context: "companion-message:session_one".to_owned(),
            sender_device_id: state.desktop_device_id.clone(),
            sequence: 1,
            nonce: "0123456789abcdef01234567".to_owned(),
            issued_at: now,
            expires_at: now + 60,
        };
        let mut guard = ReplayGuard::from_snapshot(state.replay.clone(), now).unwrap();
        let permit = guard.check(&replay, now).unwrap();
        guard.commit(permit, now).unwrap();
        state.replay = guard.snapshot(now).unwrap();
        let restored = decode_state(&encode_state(&state).unwrap(), now).unwrap();
        let restarted = ReplayGuard::from_snapshot(restored.replay, now).unwrap();
        assert_eq!(
            restarted.check(&replay, now),
            Err(CompanionError::SequenceReplay)
        );
    }

    #[test]
    fn durable_state_rejects_cross_wallet_and_cross_device_records() {
        let now = 1_000;
        let state = state_fixture(now);
        let mut wrong_wallet = state.clone();
        wrong_wallet.agent_wallet_id = "wallet_two".to_owned();
        assert!(wrong_wallet.validate_at(now).is_err());

        let mut wrong_devices = state;
        std::mem::swap(
            &mut wrong_devices.desktop_device_id,
            &mut wrong_devices.mobile_device_id,
        );
        assert!(wrong_devices.validate_at(now).is_err());
    }

    #[tokio::test]
    async fn initialized_zero_sequence_witness_blocks_reset_without_mutation() {
        let now = unix_now().unwrap();
        let mut state = state_fixture(now);
        state.witness = Some(
            MobileWitnessState::new(
                state.agent_wallet_id.clone(),
                state.desktop_device_id.clone(),
                state.mobile_device_id.clone(),
                "testnet".to_owned(),
                "11".repeat(32),
                1,
                1,
                1,
            )
            .unwrap(),
        );
        assert_eq!(state.witness.as_ref().unwrap().last_anchor_sequence, 0);
        assert!(!state.requires_controlled_rotation());
        state.validate_at(now).unwrap();

        let encoded = encode_state(&state).unwrap();
        let store = Arc::new(MemoryStore::with_bytes(encoded.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        let before = shared.current().await.unwrap();

        let error = shared.reset_before_witness_rotation().await.unwrap_err();
        assert!(error.contains("controlled desktop/mobile witness rotation"));
        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(after.rotation_phase, WitnessRotationPhase::RotationRequired);
        assert!(after.requires_controlled_rotation());
        assert_ne!(Some(after), before);
        assert_ne!(
            store.bytes.lock().unwrap().as_deref(),
            Some(encoded.as_slice())
        );
    }

    fn witness_bearing_state(now: u64) -> MobileCompanionDurableState {
        let mut state = state_fixture(now);
        state.witness = Some(
            MobileWitnessState::new(
                state.agent_wallet_id.clone(),
                state.desktop_device_id.clone(),
                state.mobile_device_id.clone(),
                "testnet".to_owned(),
                "11".repeat(32),
                1,
                1,
                1,
            )
            .unwrap(),
        );
        state
    }

    /// Dead end 4: a revoked phone that also holds witness state.
    ///
    /// Its only documented route back is a new companion identity, and that
    /// route needs the stale pairing cleared first. The pairing-only reset
    /// refuses forever once witness state exists, so the handset was stuck with
    /// an instruction the code refused. Once the key the pairing is bound to is
    /// gone, the witness state cannot be presented to anyone, and retiring it
    /// destroys nothing.
    #[tokio::test]
    async fn pairing_bound_to_a_lost_identity_can_be_retired_when_the_pairing_only_reset_refuses() {
        let now = unix_now().unwrap();
        let state = witness_bearing_state(now);
        let paired_device = state.mobile_device_id.clone();
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        // The instruction the recovery guide used to give, and what it does.
        assert!(
            shared
                .reset_before_witness_rotation()
                .await
                .unwrap_err()
                .contains("controlled desktop/mobile witness rotation")
        );
        assert!(shared.current().await.unwrap().is_some());

        // No usable companion key on this phone any more: the pairing is
        // orphaned and can be retired.
        shared.reset_orphaned_pairing(None).await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert!(store.bytes.lock().unwrap().is_none());
        let _ = paired_device;
    }

    /// The same escape, on a phone that replaced its companion key rather than
    /// losing it.
    #[tokio::test]
    async fn pairing_bound_to_a_replaced_identity_can_be_retired() {
        let now = unix_now().unwrap();
        let store = Arc::new(MemoryStore::with_bytes(
            encode_state(&witness_bearing_state(now)).unwrap(),
        ));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        shared
            .reset_orphaned_pairing(Some(replacement.device_id()))
            .await
            .unwrap();
        assert!(shared.current().await.unwrap().is_none());
    }

    /// A phone that still holds the exact key its pairing is bound to keeps
    /// every existing refusal. Its high-water mark is still enforceable, so
    /// erasing it would be a real rollback hole.
    #[tokio::test]
    async fn a_live_matching_identity_is_never_allowed_to_retire_its_own_witness_state() {
        let now = unix_now().unwrap();
        let state = witness_bearing_state(now);
        let live = state.mobile_device_id.clone();
        let encoded = encode_state(&state).unwrap();
        let store = Arc::new(MemoryStore::with_bytes(encoded.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        let error = shared
            .reset_orphaned_pairing(Some(&live))
            .await
            .unwrap_err();
        assert!(error.contains("still holds the exact secure identity"));
        assert_eq!(
            shared.current().await.unwrap().unwrap().mobile_device_id,
            live
        );
        assert_eq!(
            store.bytes.lock().unwrap().as_deref(),
            Some(encoded.as_slice()),
            "a refused retire must not write anything at all"
        );
    }

    /// An owner who changed nothing sees exactly what they saw before.
    ///
    /// A phone with no pilot approval and no witness record still runs the
    /// ordinary pairing-only reset, still reports no blocking phase, and the
    /// new retire path is refused for it because its identity still matches.
    #[tokio::test]
    async fn an_unchanged_phone_keeps_the_ordinary_pairing_only_reset() {
        let now = unix_now().unwrap();
        let state = state_fixture(now);
        let live = state.mobile_device_id.clone();
        assert_eq!(state.rotation_blocking_phase(), None);
        assert!(!state.requires_controlled_rotation());
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        assert!(shared.reset_orphaned_pairing(Some(&live)).await.is_err());
        assert!(shared.current().await.unwrap().is_some());
        shared.reset_before_witness_rotation().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
    }

    // ---------------------------------------------------------------------
    // Consent records that cannot be cleared.
    //
    // A phone holding one of these can neither reset, nor pair, nor approve or
    // witness any other payment. Everything below is executed against the real
    // storage layer, in the exact state each stranding path leaves behind.
    // ---------------------------------------------------------------------

    fn witness_confirmation(operation_id: &str, confirmed_at: u64) -> MobilePendingWitness {
        MobilePendingWitness {
            state_version: "1".to_owned(),
            operation_id: operation_id.to_owned(),
            amount_units: "50000000".to_owned(),
            recipient: "1NewDeveloper".to_owned(),
            status: "signed_awaiting_witness".to_owned(),
            confirmed_at: confirmed_at.to_string(),
        }
    }

    fn pilot_approval(
        state: &MobileCompanionDurableState,
        operation_id: &str,
        issued_at: u64,
    ) -> MobilePendingApproval {
        use hpay_companion_protocol::{
            ApprovalCommitment, ApprovalDecision, ApprovalNetworkBinding,
        };

        let commitment = ApprovalCommitment {
            approval_version: 3,
            approval_id: "approval_one".to_owned(),
            operation_id: operation_id.to_owned(),
            agent_wallet_id: state.agent_wallet_id.clone(),
            agent_id: "agent_one".to_owned(),
            desktop_device_id: state.desktop_device_id.clone(),
            transaction_commitment: "ab".repeat(32),
            amount_units: 50_000_000,
            fee_units: 1_000,
            wallet_fee_units: 0,
            total_debit_units: 50_001_000,
            recipient: "1NewDeveloper".to_owned(),
            policy_epoch: 1,
            challenge_nonce: "cd".repeat(16),
            issued_at,
            expires_at: issued_at + 60,
            network_binding: Some(ApprovalNetworkBinding {
                network_id: "testnet".to_owned(),
                chain_id: 1,
                genesis_identifier: "11".repeat(32),
                node_profile_id: "22".repeat(32),
                transaction_format_version: 2,
            }),
        };
        MobilePendingApproval {
            state_version: "1".to_owned(),
            commitment_hash: commitment.canonical_sha256_hex().unwrap(),
            decision: MobileApprovalDecision::from_commitment(
                &commitment,
                ApprovalDecision::Approve,
                state.mobile_device_id.clone(),
                1,
                state.approval_sequence,
                issued_at,
            ),
        }
    }

    /// The exact state the headline stranding path leaves behind: the owner
    /// confirmed, the receipt was accepted, the desktop stopped offering the
    /// operation, and the refused reset durably marked the phone.
    fn stranded_confirmation_state(now: u64) -> MobileCompanionDurableState {
        let mut state = state_fixture(now);
        state.pending_witness = Some(witness_confirmation("operation_one", now));
        state.rotation_phase = WitnessRotationPhase::BlockedByUnresolvedSignedOperation;
        state
    }

    /// A confirmation the desktop is still offering is never swept, however old
    /// it is. The owner has a live payment and a working button.
    #[test]
    fn a_confirmation_the_desktop_still_offers_is_never_swept() {
        let now = 1_000;
        let state = stranded_confirmation_state(now);
        let awaiting = vec!["operation_one".to_owned()];
        for at in [now, now + 10_000, now + CONSENT_MAX_AGE_SECS] {
            assert_eq!(state.obsolete_consent(Some(&awaiting), at), None);
        }
    }

    /// A desktop that did not answer has said nothing. A hostile or flaky one
    /// must not be able to erase the owner's consent for a live payment by
    /// simply refusing to reply.
    #[test]
    fn a_desktop_that_said_nothing_sweeps_nothing() {
        let now = 1_000;
        let state = stranded_confirmation_state(now);
        assert_eq!(
            state.obsolete_consent(None, now + CONSENT_MAX_AGE_SECS),
            None
        );
        // Nor does a statement that arrived inside the grace window: an
        // operation legitimately leaves the offered set for a moment in the
        // middle of a healthy flow.
        assert_eq!(
            state.obsolete_consent(Some(&[]), now + CONSENT_DESKTOP_SILENCE_GRACE_SECS),
            None
        );
    }

    /// Stranding paths 2, 4, 9, 11 and 12, end to end.
    ///
    /// The phone is holding a confirmation for an operation the desktop no
    /// longer offers - cancelled, expired, committed elsewhere, or accepted
    /// into reconciliation. Before this change nothing could clear it: the
    /// reset refused and re-marked the phone, pairing refused because the phone
    /// was already paired, and the witness card that owned the only clear had
    /// disappeared with the operation. The next authenticated sync now retires
    /// it, the marker the refusal wrote is rewound, and the ordinary
    /// pairing-only reset works again.
    #[tokio::test]
    async fn a_confirmation_the_desktop_stopped_offering_is_swept_and_unblocks_the_phone() {
        let now = unix_now().unwrap();
        let confirmed_at = now - CONSENT_DESKTOP_SILENCE_GRACE_SECS - 1;
        let mut state = stranded_confirmation_state(now);
        state.pending_witness = Some(witness_confirmation("operation_one", confirmed_at));
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        // Every way out is closed while the record is held.
        assert!(
            shared
                .reset_before_witness_rotation()
                .await
                .unwrap_err()
                .contains("holding your confirmation")
        );
        assert!(
            shared
                .reset_orphaned_pairing(Some(&state.mobile_device_id))
                .await
                .unwrap_err()
                .contains("still holds the exact secure identity")
        );

        // The desktop's own authenticated snapshot lists nothing awaiting this
        // phone's witness.
        let discarded = shared
            .sweep_obsolete_consent(Some(&[]), now)
            .await
            .unwrap()
            .expect("a confirmation the desktop no longer offers is retired");
        assert_eq!(discarded.reason, DISCARD_DESKTOP_NO_LONGER_AWAITING);
        assert_eq!(discarded.operation_id, "operation_one");
        // The receipt names the payment in the words the owner was shown.
        assert_eq!(discarded.amount_units, "50000000");
        assert_eq!(discarded.recipient, "1NewDeveloper");
        assert_eq!(discarded.confirmed_at, confirmed_at.to_string());

        let after = shared.current().await.unwrap().unwrap();
        assert!(after.pending_witness.is_none());
        assert_eq!(after.discarded_consents, vec![discarded.clone()]);
        // The marker the refused reset wrote does not outlive its cause.
        assert_eq!(after.rotation_phase, WitnessRotationPhase::Stable);
        assert_eq!(after.rotation_blocking_phase(), None);
        assert!(!after.requires_controlled_rotation());

        // And the reset the phone was being refused now runs.
        shared.reset_before_witness_rotation().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert!(store.bytes.lock().unwrap().is_none());
    }

    /// Stranding path 10: the desktop revoked this phone, or is gone for good.
    ///
    /// No statement will ever arrive, so age is the only proof left. It ends
    /// this phone's intent to sign and nothing else.
    #[tokio::test]
    async fn a_phone_whose_desktop_will_never_answer_again_gets_out_on_age_alone() {
        let now = unix_now().unwrap();
        let mut state = stranded_confirmation_state(now);
        state.pending_witness = Some(witness_confirmation(
            "operation_one",
            now - CONSENT_MAX_AGE_SECS - 1,
        ));
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        let discarded = shared
            .sweep_obsolete_consent(None, now)
            .await
            .unwrap()
            .expect("a record older than its maximum age is retired with no desktop at all");
        assert_eq!(discarded.reason, DISCARD_AGED_OUT);
        let after = shared.current().await.unwrap().unwrap();
        assert!(after.pending_witness.is_none());
        assert_eq!(after.rotation_phase, WitnessRotationPhase::Stable);
        shared.reset_before_witness_rotation().await.unwrap();
    }

    /// Stranding path 3: the owner presses the escape, and it names exactly the
    /// payment they were shown.
    #[tokio::test]
    async fn the_owner_can_discard_only_the_exact_payment_this_phone_is_holding() {
        let now = unix_now().unwrap();
        let state = stranded_confirmation_state(now);
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        assert!(
            shared
                .discard_consent_by_owner("operation_two", now)
                .await
                .unwrap_err()
                .contains("not holding a confirmation for that payment")
        );
        assert!(
            shared
                .current()
                .await
                .unwrap()
                .unwrap()
                .pending_witness
                .is_some()
        );

        let discarded = shared
            .discard_consent_by_owner("operation_one", now)
            .await
            .unwrap();
        assert_eq!(discarded.reason, DISCARD_OWNER);
        assert_eq!(discarded.kind, DISCARDED_WITNESS_CONFIRMATION);
        let after = shared.current().await.unwrap().unwrap();
        assert!(after.pending_witness.is_none());
        assert_eq!(after.discarded_consents, vec![discarded]);
        // A second press has nothing left to discard and says so, rather than
        // silently succeeding.
        assert!(
            shared
                .discard_consent_by_owner("operation_one", now)
                .await
                .is_err()
        );
    }

    /// Holds a witness confirmation on a live shared state, exactly the way
    /// `confirm_pending_witness` does: lock, set the record, persist through
    /// the validating write.
    async fn hold_confirmation(
        shared: &SharedCompanionState,
        operation_id: &str,
        confirmed_at: u64,
    ) {
        let mut slot = shared.state.lock().await;
        let mut next = slot.as_ref().expect("paired").clone();
        next.pending_witness = Some(witness_confirmation(operation_id, confirmed_at));
        shared.persist_locked(&next).unwrap();
        *slot = Some(next);
    }

    /// The defect, executed: a second discard used to erase the first receipt.
    ///
    /// `discarded_consent` was one slot, last-write-wins. Discard the
    /// confirmation for one payment, then hold and discard another, and the
    /// first receipt was simply gone - no counter, no notice, nothing on the
    /// screen. Losing that evidence is precisely what the record exists to
    /// prevent, and the owner had no way to know a payment they had stopped
    /// holding was ever there. Both receipts now survive, in the order they
    /// happened, across a restart, and neither discard touches the signed
    /// witness evidence.
    #[tokio::test]
    async fn a_second_discard_never_erases_the_first_receipt() {
        let now = unix_now().unwrap();
        let state = witness_bearing_state(now);
        let signed_evidence = state.witness.clone().unwrap();
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        hold_confirmation(&shared, "operation_one", now).await;
        let first = shared
            .discard_consent_by_owner("operation_one", now + 1)
            .await
            .unwrap();

        hold_confirmation(&shared, "operation_two", now + 2).await;
        let second = shared
            .discard_consent_by_owner("operation_two", now + 3)
            .await
            .unwrap();

        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(
            after.discarded_consents,
            vec![first.clone(), second.clone()],
            "the receipt for the first discard must survive the second one"
        );
        assert_eq!(after.discarded_consents_dropped, 0);
        // Nothing was traded for the extra receipt: no consent record is left
        // holding, and the signed anti-rollback evidence is byte-identical.
        assert!(after.pending_witness.is_none());
        assert!(after.pending_approval.is_none());
        assert_eq!(after.witness.as_ref(), Some(&signed_evidence));

        // And both are still there after the app is closed and reopened, which
        // is the only way an owner would ever come looking for the older one.
        let reopened = SharedCompanionState::open(store as Arc<dyn CompanionStateStore>);
        let restored = reopened.current().await.unwrap().unwrap();
        assert_eq!(restored.discarded_consents, vec![first, second]);
        assert_eq!(restored.witness, Some(signed_evidence));
    }

    /// The cap is bounded and says what it dropped.
    ///
    /// A history that grows for ever on a handset is its own defect, so it is
    /// capped - but dropping the oldest silently would be the same class of
    /// defect as the single slot, and refusing the discard once the log is
    /// full would wedge the phone on the record it needs to let go of. So the
    /// newest are kept, the overflow is counted durably, and the count is what
    /// the screen reports.
    #[tokio::test]
    async fn the_history_stops_at_its_cap_and_counts_exactly_what_it_dropped() {
        let now = unix_now().unwrap();
        let state = state_fixture(now);
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        let overflow = 3;
        let total = MAX_DISCARDED_CONSENTS + overflow;
        for index in 0..total {
            let operation_id = format!("operation_{index}");
            hold_confirmation(&shared, &operation_id, now).await;
            // Every discard succeeds, including the ones past the cap: the
            // owner's last exit is never refused because the log is full.
            shared
                .discard_consent_by_owner(&operation_id, now + 1)
                .await
                .unwrap();
        }

        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(after.discarded_consents.len(), MAX_DISCARDED_CONSENTS);
        assert_eq!(after.discarded_consents_dropped, overflow as u64);
        // The newest are the ones kept, and the oldest survivor is exactly the
        // one after the last dropped receipt.
        assert_eq!(
            after.discarded_consents.first().unwrap().operation_id,
            format!("operation_{overflow}")
        );
        assert_eq!(
            after.discarded_consents.last().unwrap().operation_id,
            format!("operation_{}", total - 1)
        );
        // Nothing that was dropped is silently missing: the count of it is
        // durable, and survives a restart alongside the receipts themselves.
        let reopened = SharedCompanionState::open(store as Arc<dyn CompanionStateStore>);
        let restored = reopened.current().await.unwrap().unwrap();
        assert_eq!(restored.discarded_consents, after.discarded_consents);
        assert_eq!(restored.discarded_consents_dropped, overflow as u64);

        // A history longer than the cap, or a count claiming an overflow the
        // history does not show, is refused rather than loaded.
        let mut forged = restored.clone();
        forged
            .discarded_consents
            .push(forged.discarded_consents[0].clone());
        assert!(forged.validate_at(now).is_err());
        let mut miscounted = restored;
        miscounted.discarded_consents.pop();
        assert!(miscounted.validate_at(now).is_err());
    }

    /// A phone updating from the single-slot build keeps its one receipt.
    ///
    /// The durable document is `deny_unknown_fields` and a state file that
    /// fails to decode disables the whole companion, consent exits included,
    /// so the old key stays readable. It is folded in as the oldest entry and
    /// never written again.
    #[test]
    fn the_single_receipt_an_older_build_wrote_is_read_and_migrated() {
        let now = 1_000;
        let mut state = stranded_confirmation_state(now);
        state
            .owner_discard_consent("operation_one", now + 5)
            .unwrap();
        let legacy_receipt = state.discarded_consents[0].clone();

        // Exactly what the previous build put on disk: one `discarded_consent`
        // object, and no history key at all.
        let mut document: serde_json::Value =
            serde_json::from_slice(&encode_state(&state).unwrap()).unwrap();
        let object = document.as_object_mut().unwrap();
        object.remove("discarded_consents");
        object.insert(
            "discarded_consent".to_owned(),
            serde_json::to_value(&legacy_receipt).unwrap(),
        );
        let legacy_bytes = serde_json::to_vec(&document).unwrap();

        let restored = decode_state(&legacy_bytes, now).unwrap();
        assert_eq!(restored.discarded_consents, vec![legacy_receipt.clone()]);
        assert_eq!(restored.discarded_consents_dropped, 0);

        // Written back as history, with the old key retired.
        let rewritten: serde_json::Value =
            serde_json::from_slice(&encode_state(&restored).unwrap()).unwrap();
        assert!(rewritten.get("discarded_consent").is_none());
        assert_eq!(
            rewritten.get("discarded_consents").unwrap(),
            &serde_json::json!([legacy_receipt])
        );
    }

    /// Discarding is not witnessing.
    ///
    /// The anti-rollback evidence this phone holds is `MobileWitnessState`. No
    /// discard, automatic or owner-driven, may advance its sequence, change its
    /// hash or invent a transaction state - otherwise "clear the record" would
    /// become a way to make an unwitnessed payment look witnessed.
    #[tokio::test]
    async fn discarding_a_consent_record_never_touches_the_signed_witness_evidence() {
        let now = unix_now().unwrap();
        let mut state = witness_bearing_state(now);
        state.pending_witness = Some(witness_confirmation("operation_one", now));
        let before = state.witness.clone().unwrap();
        assert_eq!(before.last_anchor_sequence, 0);
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        shared
            .discard_consent_by_owner("operation_one", now)
            .await
            .unwrap();
        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(after.witness.as_ref(), Some(&before));
        // And the phone is still exactly as blocked from resetting as any
        // witness-bearing phone: the discard bought no rollback authority.
        assert_eq!(
            after.rotation_blocking_phase(),
            Some(WitnessRotationPhase::RotationRequired)
        );
        assert!(
            shared
                .reset_before_witness_rotation()
                .await
                .unwrap_err()
                .contains("controlled desktop/mobile witness rotation")
        );
    }

    /// Stranding path 6, executed: a held confirmation refuses every other
    /// payment this phone could approve, at the persist step rather than at the
    /// approval itself.
    #[test]
    fn a_held_confirmation_blocks_every_other_payment_until_it_is_discarded() {
        let now = 1_000;
        let mut state = stranded_confirmation_state(now);
        state.approval_sequence = 1;
        state.pending_approval = Some(pilot_approval(&state, "operation_two", now));
        assert!(
            state
                .validate_at(now)
                .unwrap_err()
                .contains("name different operations")
        );

        state.owner_discard_consent("operation_one", now).unwrap();
        state.validate_at(now).unwrap();
    }

    /// The approval and the confirmation are one lifecycle, not two.
    ///
    /// A lost rejection acknowledgement, or an approval whose operation the
    /// desktop finished by another route, used to leave a `pending_approval`
    /// with no clear on any path at all.
    #[tokio::test]
    async fn an_approval_the_desktop_no_longer_offers_is_swept_the_same_way() {
        let now = unix_now().unwrap();
        let issued_at = now - CONSENT_DESKTOP_SILENCE_GRACE_SECS - 1;
        let mut state = state_fixture(now);
        state.approval_sequence = 1;
        state.pending_approval = Some(pilot_approval(&state, "operation_one", issued_at));
        state.rotation_phase = WitnessRotationPhase::BlockedByPendingApproval;
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        let discarded = shared
            .sweep_obsolete_consent(Some(&[]), now)
            .await
            .unwrap()
            .expect("an approval the desktop no longer offers is retired");
        assert_eq!(discarded.kind, DISCARDED_PILOT_APPROVAL);
        assert_eq!(discarded.operation_id, "operation_one");
        assert_eq!(discarded.recipient, "1NewDeveloper");

        let after = shared.current().await.unwrap().unwrap();
        assert!(after.pending_approval.is_none());
        assert_eq!(after.rotation_phase, WitnessRotationPhase::Stable);
        // The monotonic approval sequence is never rewound by a discard.
        assert_eq!(after.approval_sequence, 1);
        shared.reset_before_witness_rotation().await.unwrap();
    }

    /// Dead end 5, executed.
    ///
    /// The refusal used to name a controlled rotation whatever was blocking it,
    /// and then durably write a blocking phase over `Completed`. An owner who
    /// had just finished a rotation was told to run it again, for ever, and the
    /// refusal itself flipped `requires_controlled_rotation` back to true.
    #[tokio::test]
    async fn a_refused_reset_never_downgrades_a_completed_rotation_or_misnames_the_blocker() {
        let now = unix_now().unwrap();
        let mut state = stranded_confirmation_state(now);
        state.rotation_phase = WitnessRotationPhase::Completed;
        assert!(!state.requires_controlled_rotation());
        let encoded = encode_state(&state).unwrap();
        let store = Arc::new(MemoryStore::with_bytes(encoded.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        let error = shared.reset_before_witness_rotation().await.unwrap_err();
        assert!(
            error.contains("holding your confirmation"),
            "the refusal must name the blocker that is actually holding the reset: {error}"
        );
        assert!(
            !error.contains("witness rotation is required"),
            "a held confirmation is not a rotation problem: {error}"
        );
        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(after.rotation_phase, WitnessRotationPhase::Completed);
        assert!(!after.requires_controlled_rotation());
        assert_eq!(
            store.bytes.lock().unwrap().as_deref(),
            Some(encoded.as_slice()),
            "a refusal must never downgrade a terminal rotation phase"
        );
    }

    /// A witness-bearing phone with nothing held keeps the old wording, because
    /// for it a controlled rotation really is the answer.
    #[tokio::test]
    async fn a_witness_bearing_phone_still_gets_the_rotation_refusal_it_always_got() {
        let now = unix_now().unwrap();
        let store = Arc::new(MemoryStore::with_bytes(
            encode_state(&witness_bearing_state(now)).unwrap(),
        ));
        let shared = SharedCompanionState::open(store);
        assert!(
            shared
                .reset_before_witness_rotation()
                .await
                .unwrap_err()
                .contains("controlled desktop/mobile witness rotation is required")
        );
    }

    /// An owner who changes nothing sees nothing new.
    ///
    /// No consent record, no sweep, no discard receipt, and a durable document
    /// that is byte-identical to the one the previous build wrote - so a phone
    /// updating into this change reads its own state unchanged, and a phone
    /// with no consent record never starts writing a new key.
    #[tokio::test]
    async fn an_unchanged_phone_gains_no_new_state_and_is_never_swept() {
        let now = unix_now().unwrap();
        let state = state_fixture(now);
        assert_eq!(
            state.obsolete_consent(Some(&[]), now + CONSENT_MAX_AGE_SECS),
            None
        );
        assert_eq!(
            state.obsolete_consent(None, now + CONSENT_MAX_AGE_SECS),
            None
        );

        let encoded = encode_state(&state).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for key in [
            "discarded_consent",
            "discarded_consents",
            "discarded_consents_dropped",
        ] {
            assert!(
                document.get(key).is_none(),
                "a phone holding nothing must not start writing a new durable key: {key}"
            );
        }
        assert_eq!(decode_state(&encoded, now).unwrap(), state);

        let store = Arc::new(MemoryStore::with_bytes(encoded.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        assert_eq!(
            shared.sweep_obsolete_consent(Some(&[]), now).await.unwrap(),
            None
        );
        assert_eq!(
            store.bytes.lock().unwrap().as_deref(),
            Some(encoded.as_slice()),
            "a sweep that retires nothing must not write anything at all"
        );
        shared.reset_before_witness_rotation().await.unwrap();
    }

    /// The discard receipt survives a restart, so the owner can still find out
    /// what happened after closing the app.
    #[test]
    fn a_discard_receipt_is_durable_and_validated_on_the_way_back_in() {
        let now = 1_000;
        let mut state = stranded_confirmation_state(now);
        state
            .owner_discard_consent("operation_one", now + 5)
            .unwrap();
        let restored = decode_state(&encode_state(&state).unwrap(), now).unwrap();
        assert_eq!(restored.discarded_consents, state.discarded_consents);

        let mut forged = state;
        forged.discarded_consents[0].reason = "witnessed".to_owned();
        assert!(
            forged.validate_at(now).is_err(),
            "a receipt naming a reason this phone never writes is refused"
        );
    }

    /// Dead end 2: the storage layer refuses on a wider predicate than the one
    /// the phone screen could see, and the refusal is not a no-op. The screen
    /// now reads the predicate that is actually enforced.
    #[test]
    fn reset_blocking_phase_is_visible_before_a_pending_approval_moves_the_rotation_phase() {
        let now = unix_now().unwrap();
        let clean = state_fixture(now);
        assert!(!clean.requires_controlled_rotation());
        assert_eq!(clean.rotation_blocking_phase(), None);

        let witnessing = witness_bearing_state(now);
        assert!(
            !witnessing.requires_controlled_rotation(),
            "the phase the screen used to read is still stable here"
        );
        assert_eq!(
            witnessing.rotation_blocking_phase(),
            Some(WitnessRotationPhase::RotationRequired),
            "but the reset would refuse, and durably rewrite the phase"
        );
    }

    /// A desktop that is still asking for this witness outranks age.
    ///
    /// The age exit exists for a phone no desktop will ever answer again. It
    /// used to be evaluated first, so it also fired on a phone whose desktop
    /// had just said, in an authenticated snapshot, that it is still waiting -
    /// retiring live consent under a witness card that was still on screen, and
    /// doing the same to any phone whose clock jumped forward a day.
    #[test]
    fn a_desktop_still_asking_for_this_witness_outranks_age() {
        let now = 1_000_000;
        let state = stranded_confirmation_state(now);
        let awaiting = vec!["operation_one".to_owned()];
        for at in [
            now,
            now + CONSENT_DESKTOP_SILENCE_GRACE_SECS + 1,
            now + CONSENT_MAX_AGE_SECS + 1,
            now + CONSENT_MAX_AGE_SECS * 30,
        ] {
            assert_eq!(
                state.obsolete_consent(Some(&awaiting), at),
                None,
                "a confirmation the desktop is still asking for is never retired"
            );
        }
        // The exit for a phone with no desktop at all is untouched.
        assert!(
            state
                .obsolete_consent(None, now + CONSENT_MAX_AGE_SECS + 1)
                .is_some_and(|discard| discard.reason == DISCARD_AGED_OUT)
        );
        // And so is the exit for a desktop that answered without it.
        assert!(
            state
                .obsolete_consent(Some(&[]), now + CONSENT_MAX_AGE_SECS + 1)
                .is_some()
        );
    }

    /// A restricted rotation candidate: signed ticket plus signed acceptance,
    /// the exact state `finalize_rotation_pairing` installs, holding one
    /// witness confirmation.
    async fn rotation_candidate_state(now: u64) -> MobileCompanionDurableState {
        use hpay_companion_protocol::{
            PlatformDeviceSigner, RotationCandidateAcceptance, RotationPairingTicket,
            SignedRotationCandidateAcceptance, SignedRotationPairingTicket,
        };

        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let old_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        for record in [
            desktop
                .public_record("wallet_one", BTreeSet::new(), now - 1)
                .unwrap(),
            candidate
                .public_record(
                    "wallet_one",
                    BTreeSet::from([DevicePermission::ViewAgentWalletStatus]),
                    now - 1,
                )
                .unwrap(),
        ] {
            registry.register(record).unwrap();
        }
        let ticket = RotationPairingTicket {
            ticket_version: 1,
            ticket_id: "ticket_one".to_owned(),
            pairing_id: "pairing_one".to_owned(),
            rotation_id: "rotation_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            old_mobile_device_id: old_mobile.device_id().clone(),
            expected_candidate_device_id: candidate.device_id().clone(),
            expected_candidate_identity_fingerprint: PlatformDeviceSigner::identity(&candidate)
                .fingerprint()
                .unwrap(),
            network_id: "testnet".to_owned(),
            genesis_identifier: "11".repeat(32),
            current_witness_epoch: 1,
            next_witness_epoch: 2,
            current_mobile_authorization_epoch: 1,
            next_mobile_authorization_epoch: 2,
            latest_anchor_sequence: 0,
            latest_anchor_hash: "0".repeat(64),
            journal_sequence: 1,
            journal_head_hash: "22".repeat(32),
            policy_epoch: 1,
            old_mobile_authorization_commitment: None,
            single_use_nonce: "33".repeat(32),
            issued_at: now - 1,
            expires_at: now + 200,
        };
        let signed_ticket = SignedRotationPairingTicket::sign(ticket.clone(), &desktop)
            .await
            .unwrap();
        let acceptance = RotationCandidateAcceptance::for_ticket(&ticket, now).unwrap();
        let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, &candidate)
            .await
            .unwrap();

        let state = MobileCompanionDurableState {
            state_version: STATE_VERSION,
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            mobile_device_id: candidate.device_id().clone(),
            endpoints: vec![LanEndpoint::parse("hpay-lan://192.168.1.8:42492").unwrap()],
            registry,
            replay: ReplayGuard::new().snapshot(now).unwrap(),
            response_sequence: 0,
            approval_sequence: 0,
            pending_pairing_ack: None,
            pending_approval: None,
            pending_agent_fast_pay_approval: None,
            pending_agent_hvm_approval: None,
            pending_witness: Some(witness_confirmation("operation_one", now)),
            discarded_consents: Vec::new(),
            discarded_consents_dropped: 0,
            witness: None,
            rotation_phase: WitnessRotationPhase::CandidatePairedRestricted,
            pending_rotation_authorization: None,
            pending_rotation_baseline: None,
            rotation_ticket: Some(signed_ticket),
            rotation_candidate_acceptance: Some(signed_acceptance),
        };
        state
            .validate_at(now)
            .expect("a restricted candidate may hold one witness confirmation");
        state
    }

    /// The refused reset must not destroy the exits it points the owner at.
    ///
    /// A restricted rotation candidate constrains its own `rotation_phase`. The
    /// refusal used to write its blocking marker there regardless, producing
    /// durable state the loader rejects: the companion was disabled on the next
    /// launch, and every consent exit - the owner's discard and the automatic
    /// sweep alike - failed on the same validation, because both persist
    /// through `persist_locked`. The refusal message tells the owner to discard
    /// the confirmation on this screen; pressing reset first must not be what
    /// takes that away.
    #[tokio::test]
    async fn a_refused_reset_never_writes_state_the_loader_would_reject() {
        let now = unix_now().unwrap();
        let state = rotation_candidate_state(now).await;
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);

        let refusal = shared.reset_before_witness_rotation().await.unwrap_err();
        assert!(refusal.contains("holding your confirmation"));

        // The phone still loads.
        let bytes = store.bytes.lock().unwrap().clone().unwrap();
        decode_state(&bytes, unix_now().unwrap())
            .expect("a refused reset left durable state the loader rejects");
        assert_eq!(
            shared.current().await.unwrap().unwrap().rotation_phase,
            WitnessRotationPhase::CandidatePairedRestricted,
            "a marker that will not fit is not written at all"
        );

        // And the automatic exit still works, after the reset has been tried.
        assert!(
            shared
                .sweep_obsolete_consent(Some(&[]), now + CONSENT_MAX_AGE_SECS + 1)
                .await
                .unwrap()
                .is_some()
        );
        let restored =
            SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        assert!(restored.current().await.unwrap().is_some());
    }

    /// EXECUTED: THE CRASH AT THE ROTATION CANDIDATE'S DURABLE WRITE.
    ///
    /// `confirm_rotation_candidate_pairing` persists `CandidatePairedRestricted`
    /// with the signed ticket and the signed acceptance, and only then returns
    /// the acceptance for the owner to carry to the desktop by QR. A crash in
    /// that gap leaves the phone durably a restricted candidate with the ticket
    /// consumed while the desktop rotation is still waiting for it, and - unlike
    /// the normal pairing at `pairing.rs:223` - there is no `pending_pairing_ack`
    /// to re-send, so the QR cannot be produced again.
    ///
    /// This is that exact disk, written through the real store to a real file and
    /// read back by a real reopen. What it establishes:
    ///
    ///   * the SIGNED ACCEPTANCE SURVIVES. It is part of the durable record, so
    ///     the half of the delivery that carries rotation authority is not lost,
    ///     and the desktop accepts a re-delivery of it idempotently - executed on
    ///     the desktop side by
    ///     `a_redelivered_candidate_acceptance_is_accepted_rather_than_refused`.
    ///   * the OWNER HAS AN EXIT. The candidate handset is fresh: no pending
    ///     approval, no pending witness, no witness record, so
    ///     `rotation_blocking_phase` is `None` and the pairing reset SUCCEEDS.
    ///     The enumeration recorded this site as blocked on that predicate; it is
    ///     not, and the difference is executed here rather than read.
    ///
    /// The encrypted acknowledgement is deliberately NOT made durable for the
    /// candidate: `pending_pairing_ack` is what drives
    /// `pending_pairing_finalization`, which on the phone gates auto-connect and
    /// replaces the candidate's whole screen with the LAN finalisation step. That
    /// is a behaviour change on a path that only runs on the handset, so it is
    /// named rather than guessed at.
    #[tokio::test]
    async fn a_crash_at_the_rotation_candidate_write_keeps_the_acceptance_and_an_exit() {
        let now = unix_now().unwrap();
        let mut state = rotation_candidate_state(now).await;
        // The state as `confirm_rotation_candidate_pairing` installs it: a fresh
        // handset that has confirmed nothing yet.
        state.pending_witness = None;
        state.validate_at(now).unwrap();
        let acceptance = state.rotation_candidate_acceptance.clone().unwrap();

        let root = std::env::temp_dir().join(format!(
            "hpay-mobile-rotation-candidate-crash-{}-{now}",
            std::process::id()
        ));
        let companion = root.join("agent-companion").join("state.json");
        let store: Arc<dyn CompanionStateStore> =
            Arc::new(FileCompanionStateStore::new(companion.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store));
        // THE DURABLE WRITE. Nothing after it runs: this is the crash.
        shared.install_new(state).await.unwrap();
        assert!(companion.exists());
        drop(shared);

        // THE REBOOT.
        let rebooted = SharedCompanionState::open(Arc::clone(&store));
        let after = rebooted
            .current()
            .await
            .unwrap()
            .expect("the phone must still load after the crash");
        assert_eq!(
            after.rotation_phase,
            WitnessRotationPhase::CandidatePairedRestricted
        );
        assert_eq!(
            after.rotation_candidate_acceptance.as_ref(),
            Some(&acceptance),
            "the signed acceptance must survive the crash, or the rotation \
             authority the phone already granted is unrecoverable"
        );
        assert!(after.rotation_ticket.is_some());
        assert!(
            after.pending_pairing_ack.is_none(),
            "and the encrypted acknowledgement is not durable for a candidate, \
             by decision - see this test's own note"
        );

        // THE OWNER'S EXIT, EXECUTED. This is not blocked.
        assert_eq!(
            after.rotation_blocking_phase(),
            None,
            "a fresh candidate handset blocks nothing"
        );
        rebooted
            .reset_before_witness_rotation()
            .await
            .expect("the candidate handset must be resettable so the owner can start again");
        assert!(rebooted.current().await.unwrap().is_none());
        let fresh = SharedCompanionState::open(Arc::clone(&store));
        assert!(fresh.current().await.unwrap().is_none());

        let _ = fs::remove_file(&companion);
        let _ = fs::remove_dir(root.join("agent-companion"));
        let _ = fs::remove_dir(root);
    }

    /// The owner's discard survives a refused reset on the same phone.
    #[tokio::test]
    async fn the_owner_discard_survives_a_refused_reset_on_a_rotation_candidate() {
        let now = unix_now().unwrap();
        let state = rotation_candidate_state(now).await;
        let store = Arc::new(MemoryStore::with_bytes(encode_state(&state).unwrap()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        let _ = shared.reset_before_witness_rotation().await.unwrap_err();
        let discarded = shared
            .discard_consent_by_owner("operation_one", now)
            .await
            .expect("the exit the refusal names must still exist after the refusal");
        assert_eq!(discarded.reason, DISCARD_OWNER);
        let after = shared.current().await.unwrap().unwrap();
        assert!(after.pending_witness.is_none());
        // The rotation this phone is a candidate for is untouched.
        assert!(after.rotation_ticket.is_some());
        assert_eq!(
            after.rotation_phase,
            WitnessRotationPhase::CandidatePairedRestricted
        );
    }
}
