use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use hacash_wallet_core::settings::validate_signing_node_url;
use hpay_companion_protocol::{
    DesktopChallengeSequence, DeviceId, DevicePublicRecord, SignedRollbackAnchor,
    SignedRotationCandidateAcceptance, SignedRotationPairingTicket, SignedWitnessReceipt,
    SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt, WitnessRotationPhase,
    WitnessRotationRecord,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::amount::HacUnits;
use crate::companion_signer::AgentDesktopCompanionSigner;
use crate::emergency::AgentEmergencyController;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::fast_pay_operation::AgentFastPayOperation;
use crate::hvm_payment_operation::AgentHvmPaymentOperation;
use crate::journal::AgentJournalEventKind;
use crate::node_binding::{
    AgentNodeSnapshot, AgentNodeStatus, anchor_for_new_wallet, probe_agent_node,
};
use crate::operation::{
    AgentOperation, AgentPaymentRequest, OperationStatus, PaymentOperationView,
};
use crate::pairing_outbox::PairingCompletionOutboxEntry;
use crate::policy::{AgentPermission, AgentPolicy, AgentRecord, AgentStatus};
use crate::signer::AgentTransactionSigner;
use crate::storage::{AgentStorage, AgentWalletRegistryEntry};
use crate::types::{AgentId, AgentWalletId, OperationId, WalletScope};
use crate::vault::{AgentEncryptedVault, derive_domain_key};
mod admin;
mod backup;
mod companion;
mod connector;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod diagnostics;
mod hvm;
mod hvm_registry;
mod hvm_registry_open;
mod l2;
mod payment;
mod state;

#[cfg(test)]
use payment::validate_policy_for_request;
use payment::{agent_spending_ready, require_agent_spending_network, validate_authorization};
use state::{
    active_fast_pay_reservations, active_l1_reservations, cancel_pre_signing_operations,
    fast_pay_channel_exposure, mark_explicit_emergency_stop, prune_terminal_pre_signing_for_agent,
    spent_in_window, validate_text,
};
#[cfg(test)]
use state::{active_reservations, journal_path, scoped_idempotency_key};

pub use backup::{
    AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING, AgentWalletBackupAcknowledgement,
    AgentWalletBackupFile, AgentWalletBackupMetadata, AgentWalletBackupPreview,
    AgentWalletBackupWarning, AgentWalletRestoreOutcome,
};
pub use companion::{
    AgentCompanionPairingAttempt, AgentCompletedCompanionPairing, AgentDesktopSessionAttempt,
    AgentPairingAttemptBudget, MAX_PAIRING_REQUEST_ATTEMPTS,
    WITNESS_PENDING_OPERATION_STATUS_NAMES,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use companion::{StrandedWitnessRecovery, WitnessRotationControls};
pub use hvm::AgentHvmChannelBinding;
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use hvm_registry::{
    AGENT_REGISTRY_EXIT_GAS_BUDGET, AGENT_REGISTRY_EXIT_GAS_MAX,
    AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES, AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU,
    AGENT_VM_LOWEST_FEE_PURITY_UNIT238, AgentHvmRegistryExitProgress,
    AgentHvmRegistryExitStepProgress, agent_registry_exit_gas_reserve_zhu,
    agent_registry_exit_transaction_ceiling_zhu,
};
pub use hvm_registry::{AgentHvmRegistryBinding, AgentHvmRegistryExitHead};
pub use hvm_registry_open::{
    AgentHvmRegistryChannelOpen, AgentHvmRegistryCountersignedRefund, AgentHvmRegistryFunding,
};
use l2::{
    AgentChannelCloseOperation, AgentChannelCloseVoucherOperation, AgentChannelSetupOperation,
};
pub use l2::{
    AgentChannelClosePhase, AgentChannelCloseReview, AgentChannelCloseVoucherBroadcast,
    AgentChannelCloseVoucherPhase, AgentChannelCloseVoucherView, AgentChannelSetupPhase,
    AgentChannelSetupReview, AgentL2Binding,
};

const STATE_SCHEMA_VERSION: u32 = 1;
const STATE_NAME: &str = "wallet_state";
const PENDING_STATE_NAME: &str = "wallet_state_pending";
const JOURNAL_FILE: &str = "journal.json";
const MAX_SESSION_SECONDS: u64 = 15 * 60;
const MAX_APPROVAL_SECONDS: u64 = 5 * 60;
const MAX_AGENT_NAME_BYTES: usize = 128;
const MAX_AGENT_VERSION_BYTES: usize = 64;
const MAX_OPERATIONS_PER_WALLET: usize = 4_096;
// Terminal pre-signing outcomes have no blockchain side effect. Their
// idempotency result is retained for the complete request lifetime and is
// pruned only at or after request expiry. No post-expiry grace is safe with
// the 4,096-record cap and the authenticated 30-requests/minute rate limit.
const MAX_REQUESTS_PER_AGENT_PER_MINUTE: usize = 30;
const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The sentence the owner must have ticked, compared byte for byte at
/// `service.rs:666`, so it has to stay identical to the one the screen shows
/// in `apps/desktop/src/agent/access.ts`. If the two drift, consent that was
/// genuinely given stops being recognised.
///
/// It replaces "a trusted bounded pilot and I accept its recovery limits",
/// which was true and told a reader neither the amount at risk nor what
/// trusted costs them. This names both, because a consent that does not name
/// the number is not consent to the number.
///
/// The failure it names was corrected on 2026-08-23. It used to say the
/// provider could put an old receipt on chain while the owner slept and take
/// the difference. That is wrong on both rails this build can run. Native
/// ChannelPay registers only action 3 and `channel_close` in the node checks
/// BOTH signatures, so a provider acting alone cannot move the money; on the
/// HVM registry rail a stale receipt pays the owner MORE, which is why
/// `decide_user_exit_action` finishes what is standing rather than answering
/// it. The real exposure, and the one the 10 HAC cap is for, is that the money
/// comes out only if the provider co-signs.
pub const AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT: &str = "I understand that this provider holds my channel funds. This channel can only be closed if the provider co-signs it: the chain requires both signatures and no unilateral exit exists on this rail, so if it stops answering, refuses to sign, or disappears, what is in this channel stays locked and nobody can release it for me. At most 10 HAC per channel is at risk. I will not put in more than I can afford to lose.";

const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateAgentWallet {
    pub passphrase: String,
    pub network_mode: String,
    pub node_url: String,
    #[serde(default)]
    pub block_one_fingerprint: Option<String>,
    #[serde(default)]
    pub mainnet_pilot_acknowledgement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreatedAgentWallet {
    pub wallet_id: AgentWalletId,
    pub address: String,
    pub network_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnlockedAgentWalletStatus {
    pub wallet_id: AgentWalletId,
    pub address: String,
    pub network_mode: String,
    pub signer_epoch: u64,
    pub payments_suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletOverview {
    pub wallet_id: AgentWalletId,
    pub address: String,
    pub network_mode: String,
    pub node_url: Option<String>,
    pub block_one_fingerprint: Option<String>,
    pub node: Option<AgentNodeSnapshot>,
    pub node_status: AgentNodeStatus,
    pub node_error: Option<String>,
    pub unlocked: bool,
    pub payments_suspended: bool,
    pub mainnet_spending_ready: bool,
    pub trusted_mainnet_fast_pay_pilot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_binding: Option<AgentL2Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_channel_setup: Option<AgentChannelSetupReview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_channel_close: Option<AgentChannelCloseReview>,
    /// The one delta-zero close the owner holds for this channel, if the Hub
    /// countersigned it. Surfaced so a person can see that an exit exists,
    /// what it pays them, and that broadcasting it needs no Hub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_channel_close_voucher: Option<AgentChannelCloseVoucherView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hvm_channel_binding: Option<AgentHvmChannelBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hvm_registry_binding: Option<AgentHvmRegistryBinding>,
    pub confirmed_balance_units: Option<HacUnits>,
    pub reserved_units: HacUnits,
    pub available_units: Option<HacUnits>,
    pub fast_pay_deposit_units: Option<HacUnits>,
    pub fast_pay_reserved_units: HacUnits,
    pub fast_pay_available_units: Option<HacUnits>,
    pub spent_today_units: HacUnits,
    pub spent_this_month_units: HacUnits,
    pub authorized_agents: u32,
    pub pending_approvals: u32,
    pub pilot_enabled: bool,
    pub mobile_witness_ready: bool,
    pub mobile_witness_synchronized: bool,
    pub latest_anchor_sequence: u64,
    pub witness_rotation_phase: Option<WitnessRotationPhase>,
    pub unresolved_signed_operations: u32,
    pub stale: bool,
}

/// Core-only authorization copied from one connector-created verified request.
/// It cannot be constructed by an agent-facing API.
struct AgentAuthorization {
    wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    agent_id: AgentId,
    authorization_epoch: u64,
    identity_key_sha256: String,
    capability: AgentPermission,
}

impl AgentAuthorization {
    fn wallet_scope(&self) -> &WalletScope {
        &self.wallet_scope
    }

    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    fn capability(&self) -> AgentPermission {
        self.capability
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentWalletState {
    schema_version: u32,
    wallet_id: AgentWalletId,
    address: String,
    network_mode: String,
    node_url: String,
    #[serde(default)]
    block_one_fingerprint: String,
    primary_signing_device_id: String,
    signer_epoch: u64,
    policy_epoch: u64,
    emergency_epoch: u64,
    payments_suspended: bool,
    external_rollback_anchor_ready: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    trusted_mainnet_fast_pay_pilot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    l2_binding: Option<AgentL2Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    l2_channel_setup: Option<AgentChannelSetupOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    l2_channel_close: Option<AgentChannelCloseOperation>,
    /// The owner's exit from the Fast Pay channel: one countersigned
    /// delta-zero close, taken once immediately after the open confirms and
    /// never refreshed. Written through the same encrypted `persist_event`
    /// path as everything else here and carried in the encrypted backup, so it
    /// survives a restore. A voucher that does not survive a restore is not an
    /// exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    l2_channel_close_voucher: Option<AgentChannelCloseVoucherOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_channel_binding: Option<AgentHvmChannelBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_registry_binding: Option<AgentHvmRegistryBinding>,
    /// The newest fully-signed registry bill, kept explicitly rather than
    /// recovered by scanning `hvm_payment_operations`. Without it the user's
    /// route out of a channel depends on a payment-operation map staying
    /// intact; see [`AgentHvmRegistryExitHead`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_registry_exit_head: Option<AgentHvmRegistryExitHead>,
    /// The wallet's own half of a registry channel open: the left-signed
    /// serial-1 full refund, and the Hub countersignature once this wallet has
    /// checked it. Written before any funding may be built, and the only thing
    /// [`AgentWalletManager::hvm_registry_funding_authorization`] will accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_registry_open: Option<AgentHvmRegistryChannelOpen>,
    agents: BTreeMap<String, AgentRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pairing_completion_outbox: BTreeMap<String, PairingCompletionOutboxEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    companion_security: Option<companion::CompanionSecurityState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_witness: Option<AuthenticatedRollbackWitnessState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness_rotation: Option<AuthenticatedWitnessRotationState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    witness_rotation_history: Vec<AuthenticatedWitnessRotationState>,
    operations: BTreeMap<String, AgentOperation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fast_pay_operations: BTreeMap<String, AgentFastPayOperation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    hvm_payment_operations: BTreeMap<String, AgentHvmPaymentOperation>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    // Legacy V1 fields remain parseable only for authenticated state compatibility.
    // They are required to stay empty and are never an authorization authority.
    authentication_challenges: BTreeMap<String, serde_json::Value>,
    authenticated_sessions: BTreeMap<String, serde_json::Value>,
    journal_sequence: u64,
    journal_head_hash: String,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedRollbackWitnessState {
    state_version: u64,
    witness_epoch: u64,
    mobile_device_id: DeviceId,
    last_anchor_sequence: u64,
    last_anchor_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<AuthenticatedPendingWitness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_completed: Option<AuthenticatedCompletedWitness>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    history: Vec<AuthenticatedCompletedWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPendingWitness {
    operation_id: String,
    proposal: SignedRollbackAnchor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<SignedWitnessReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedCompletedWitness {
    operation_id: String,
    proposal: SignedRollbackAnchor,
    receipt: SignedWitnessReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedWitnessRotationState {
    phase: WitnessRotationPhase,
    record: WitnessRotationRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old_mobile_authorization: Option<SignedWitnessRotationAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairing_ticket: Option<SignedRotationPairingTicket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_device: Option<DevicePublicRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_acceptance: Option<SignedRotationCandidateAcceptance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ticket_consumed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_mobile_baseline: Option<SignedWitnessRotationBaselineReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_anchor: Option<SignedRollbackAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_receipt: Option<SignedWitnessReceipt>,
}

impl AuthenticatedRollbackWitnessState {
    fn validate(&self, wallet_id: &AgentWalletId) -> AgentWalletResult<()> {
        let zero_hash = ZERO_HASH_HEX;
        let is_hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let base_valid = self.state_version == 1
            && self.witness_epoch > 0
            && is_hash(&self.last_anchor_hash)
            && ((self.last_anchor_sequence == 0 && self.last_anchor_hash == zero_hash)
                || (self.last_anchor_sequence > 0 && self.last_anchor_hash != zero_hash));
        if !base_valid {
            return Err(AgentWalletError::RollbackDetected);
        }
        if let Some(pending) = &self.pending {
            let anchor = &pending.proposal.anchor;
            let expected_sequence = if pending.receipt.is_some() {
                self.last_anchor_sequence
            } else {
                self.last_anchor_sequence
                    .checked_add(1)
                    .ok_or(AgentWalletError::RollbackDetected)?
            };
            let expected_hash = anchor
                .canonical_sha256_hex()
                .map_err(|_| AgentWalletError::RollbackDetected)?;
            if pending.operation_id.is_empty()
                || anchor.agent_wallet_id != wallet_id.as_str()
                || anchor.mobile_device_id != self.mobile_device_id
                || anchor.witness_epoch != self.witness_epoch
                || anchor.anchor_sequence != expected_sequence
                || (pending.receipt.is_none()
                    && anchor.previous_anchor_hash != self.last_anchor_hash)
                || (pending.receipt.is_some()
                    && (expected_hash != self.last_anchor_hash
                        || pending.receipt.as_ref().is_none_or(|receipt| {
                            receipt.receipt.anchor_hash != self.last_anchor_hash
                        })))
            {
                return Err(AgentWalletError::RollbackDetected);
            }
        }
        if let Some(completed) = &self.last_completed {
            let anchor = &completed.proposal.anchor;
            let anchor_hash = anchor
                .canonical_sha256_hex()
                .map_err(|_| AgentWalletError::RollbackDetected)?;
            if completed.operation_id.is_empty()
                || anchor.agent_wallet_id != wallet_id.as_str()
                || anchor.anchor_sequence == 0
                || anchor.anchor_sequence > self.last_anchor_sequence
                || completed.receipt.receipt.anchor_id != anchor.anchor_id
                || completed.receipt.receipt.anchor_hash != anchor_hash
            {
                return Err(AgentWalletError::RollbackDetected);
            }
        }
        if self.history.len() > 4_096 {
            return Err(AgentWalletError::RollbackDetected);
        }
        let mut prior_sequence = 0_u64;
        for completed in &self.history {
            let anchor = &completed.proposal.anchor;
            let anchor_hash = anchor
                .canonical_sha256_hex()
                .map_err(|_| AgentWalletError::RollbackDetected)?;
            if completed.operation_id.is_empty()
                || anchor.agent_wallet_id != wallet_id.as_str()
                || anchor.anchor_sequence <= prior_sequence
                || anchor.anchor_sequence > self.last_anchor_sequence
                || completed.receipt.receipt.anchor_id != anchor.anchor_id
                || completed.receipt.receipt.anchor_hash != anchor_hash
            {
                return Err(AgentWalletError::RollbackDetected);
            }
            prior_sequence = anchor.anchor_sequence;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperationRail {
    #[default]
    L1,
    FastPay,
    HvmFastPay,
}

impl OperationRail {
    const fn is_l1(&self) -> bool {
        matches!(self, Self::L1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdempotencyRecord {
    #[serde(default, skip_serializing_if = "OperationRail::is_l1")]
    rail: OperationRail,
    request_commitment: String,
    operation_id: OperationId,
}

struct UnlockedAgentWallet {
    unlock_expires_at: u64,
    state_master: Zeroizing<[u8; 32]>,
    journal_key: Zeroizing<[u8; 32]>,
    desktop_identity_secret: Zeroizing<[u8; 32]>,
    desktop_companion_signer: AgentDesktopCompanionSigner,
    active_companion_pairings: BTreeMap<String, u64>,
    signer: AgentTransactionSigner,
}

impl Drop for UnlockedAgentWallet {
    fn drop(&mut self) {
        self.desktop_companion_signer.disable();
    }
}

pub struct AgentWalletManager {
    storage: AgentStorage,
    unlocked: BTreeMap<String, UnlockedAgentWallet>,
    emergency_controllers: BTreeMap<String, AgentEmergencyController>,
    /// Per-wallet, process-lifetime source for the desktop `challenge_sequence`.
    ///
    /// The phone consumes that field as a strictly increasing anti-replay
    /// counter, so it cannot be drawn independently per handshake. It is kept
    /// here rather than in `unlocked` so that locking and unlocking the wallet
    /// cannot rewind it, and behind its own lock so that issuing a sequence
    /// needs only `&self` on the unauthenticated challenge phase.
    challenge_sequences: Mutex<BTreeMap<String, DesktopChallengeSequence>>,
    /// Crash injection for the two durable boundaries inside
    /// `apply_mobile_witness_and_broadcast`. Test builds only: the fields, and
    /// every read of them, are compiled out of the shipped library, so an owner
    /// runs exactly the code that shipped before this existed.
    ///
    /// Setting one makes that call return without running anything below the
    /// boundary. Everything above it has already been written to disk by
    /// `persist_event`, so the on-disk state is byte-for-byte what a process
    /// that died at that instant leaves behind, and the test reopens the wallet
    /// from that disk rather than from memory.
    #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) crash_after_witness_accepted: bool,
    /// Same, one step later: the receipt is durable AND the broadcast has
    /// already happened, and the archive that would move the payment on never
    /// runs.
    #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) crash_before_witness_archive: bool,
    /// The sweep's two other multi-write boundaries, injected so the claim that
    /// they are already recoverable is executed rather than read:
    /// `approve_desktop_and_broadcast` journals `ApprovalGranted` and then calls
    /// `resume_payment`, and `accept_witness_rotation_baseline` journals
    /// `WitnessRotationBaselineAccepted` and then revokes the old phone.
    #[cfg(test)]
    pub(crate) crash_after_approval_granted: bool,
    #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) crash_after_rotation_baseline: bool,
    /// The two boundaries the second sweep found still open.
    ///
    /// `resume_payment` persists `BroadcastSubmitted` and only then posts the
    /// signed bytes to the node, on purpose, so that a restart reconciles
    /// rather than rebroadcasts. This injects the crash in that gap - the one
    /// case where the durable status says "submitted" and provably nothing was.
    #[cfg(test)]
    pub(crate) crash_after_broadcast_persisted: bool,
    /// `apply_mobile_approval_and_broadcast` journals the phone's decision AND
    /// the replay-guard snapshot that consumes it, and then calls
    /// `resume_payment` to sign. This injects the crash in that gap.
    #[cfg(test)]
    pub(crate) crash_after_mobile_approval_granted: bool,
    /// The three remaining boundaries the second sweep enumerated, injected so
    /// that the claim they are benign is executed rather than read:
    /// `pending_rollback_anchor` journals `RollbackWitnessInitialized` and then
    /// mints the anchor; `create_payment_intent` journals `FundsReserved` and
    /// then builds the transaction at the node; `resume_payment` journals
    /// `TransactionSigned` and then reloads and broadcasts.
    #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) crash_after_witness_state_initialized: bool,
    #[cfg(test)]
    pub(crate) crash_after_funds_reserved: bool,
    #[cfg(test)]
    pub(crate) crash_after_transaction_signed: bool,
    /// Where inside `restore_agent_wallet_backup` to stop dead.
    ///
    /// The restore is the one place in the crate that performs five durable
    /// writes in a row, so one boolean per window would be five flags that can
    /// disagree. One point, set once, stops the function exactly there and
    /// leaves the write-ahead record behind - which is what dying there does.
    #[cfg(test)]
    pub(crate) crash_restore_at: Option<RestoreCrashPoint>,
}

/// The durable-write windows inside `restore_agent_wallet_backup`, named so a
/// test can crash at each one and then say which one it crashed at.
///
/// The list is compiled into every build so the restore reads the same in a
/// release build as it does in a test one; only the flag that arms it is
/// test-only, so a release build cannot be made to stop at any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum RestoreCrashPoint {
    AfterWriteAheadRecord,
    AfterWalletLayout,
    AfterVault,
    AfterJournal,
    AfterState,
    AfterPendingRemoval,
    AfterVerification,
    AfterRegistry,
}

#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
impl RestoreCrashPoint {
    /// Every window, so a test cannot silently cover only some of them.
    pub(crate) const ALL: [Self; 8] = [
        Self::AfterWriteAheadRecord,
        Self::AfterWalletLayout,
        Self::AfterVault,
        Self::AfterJournal,
        Self::AfterState,
        Self::AfterPendingRemoval,
        Self::AfterVerification,
        Self::AfterRegistry,
    ];
}

impl AgentWalletManager {
    /// Open only the independent Agent Wallet namespace selected by the
    /// caller. This never reads or writes Personal Wallet paths.
    pub fn open(base_root: impl AsRef<Path>) -> AgentWalletResult<Self> {
        let storage = AgentStorage::open(base_root)?;
        // A restore that was interrupted finishes its story here, before
        // anything reads the store: either it had committed and only its own
        // write-ahead record is left, or nothing committed and everything it had
        // written goes. Best effort on purpose - it can only ever touch a wallet
        // the registry does not list, so a store that fails to heal is still
        // safe to open, and the next open and the next restore both try again.
        let _ = storage.recover_interrupted_wallet_restore();
        let registry = storage.load_registry()?;
        let mut emergency_controllers = BTreeMap::new();
        for wallet_id in registry.wallets.values().map(|entry| &entry.wallet_id) {
            let paths = storage.paths(wallet_id)?;
            let controller = AgentEmergencyController::new(&paths, wallet_id)?;
            emergency_controllers.insert(wallet_id.as_str().to_owned(), controller);
        }
        Ok(Self {
            storage,
            unlocked: BTreeMap::new(),
            emergency_controllers,
            challenge_sequences: Mutex::new(BTreeMap::new()),
            #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
            crash_after_witness_accepted: false,
            #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
            crash_before_witness_archive: false,
            #[cfg(test)]
            crash_after_approval_granted: false,
            #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
            crash_after_rotation_baseline: false,
            #[cfg(test)]
            crash_after_broadcast_persisted: false,
            #[cfg(test)]
            crash_after_mobile_approval_granted: false,
            #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
            crash_after_witness_state_initialized: false,
            #[cfg(test)]
            crash_after_funds_reserved: false,
            #[cfg(test)]
            crash_after_transaction_signed: false,
            #[cfg(test)]
            crash_restore_at: None,
        })
    }

    /// Stops the restore dead at one of its durable-write windows.
    ///
    /// It returns the error rather than unwinding through any cleanup on
    /// purpose: nothing after the call runs, the write-ahead record stays on
    /// disk, and that is exactly the disk a killed process leaves.
    #[cfg(test)]
    pub(crate) fn restore_crash(&self, point: RestoreCrashPoint) -> AgentWalletResult<()> {
        if self.crash_restore_at == Some(point) {
            return Err(AgentWalletError::PersistenceFailed);
        }
        Ok(())
    }

    /// Nothing at all in a release build. There is no flag to arm.
    #[cfg(not(test))]
    #[inline]
    pub(crate) fn restore_crash(&self, point: RestoreCrashPoint) -> AgentWalletResult<()> {
        let _ = point;
        Ok(())
    }

    pub fn storage_root(&self) -> &Path {
        self.storage.root()
    }

    /// Return the shared, lock-independent emergency interlock for this exact
    /// Agent Wallet. Supervisors must retain a clone so marker-first stop does
    /// not wait for the manager mutex or a node request.
    pub fn emergency_controller(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<AgentEmergencyController> {
        self.emergency_controllers
            .get(wallet_id.as_str())
            .cloned()
            .ok_or(AgentWalletError::AgentWalletNotFound)
    }

    pub fn list_wallets(&self) -> AgentWalletResult<Vec<AgentWalletRegistryEntry>> {
        Ok(self
            .storage
            .load_registry()?
            .wallets
            .into_values()
            .collect())
    }

    /// Agent Wallet creation is explicit. Merely opening HPAY never invokes
    /// this method.
    pub fn create_wallet(
        &mut self,
        request: CreateAgentWallet,
        now: u64,
    ) -> AgentWalletResult<CreatedAgentWallet> {
        let trusted_mainnet_fast_pay_pilot = request.network_mode == "mainnet"
            && request.mainnet_pilot_acknowledgement.as_deref()
                == Some(AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT);
        if !matches!(request.network_mode.as_str(), "mainnet" | "testnet")
            || (request.network_mode == "testnet"
                && request.mainnet_pilot_acknowledgement.is_some())
            || !agent_spending_ready(&request.network_mode, trusted_mainnet_fast_pay_pilot)
        {
            return Err(AgentWalletError::InvalidPaymentRequest);
        }
        let node_url = validate_signing_node_url(&request.node_url, &request.network_mode)
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let block_one_fingerprint = anchor_for_new_wallet(
            &request.network_mode,
            request.block_one_fingerprint.as_deref(),
        )?;

        let wallet_id = AgentWalletId::new();
        let paths = self.storage.ensure_wallet_layout(&wallet_id)?;
        // New Agent Wallets start with spending disabled, but this default is
        // not an emergency stop. Read-only companion connectivity remains
        // available until the user explicitly presses Pause All Agents.
        let emergency = AgentEmergencyController::new(&paths, &wallet_id)?;
        let (vault, address) = AgentEncryptedVault::create(
            wallet_id.clone(),
            &request.passphrase,
            &request.network_mode,
            now,
        )?;
        vault.save(&paths.vault_path())?;
        let secrets = vault.unlock(&request.passphrase)?;
        let state_master = Zeroizing::new(*secrets.state_master());
        let journal_key = Zeroizing::new(derive_domain_key(
            &state_master,
            &wallet_id,
            vault.store_uuid(),
            b"journal-authentication/v1",
        )?);
        drop(secrets);

        let mut state = AgentWalletState {
            schema_version: STATE_SCHEMA_VERSION,
            wallet_id: wallet_id.clone(),
            address: address.clone(),
            network_mode: request.network_mode.clone(),
            node_url,
            block_one_fingerprint,
            primary_signing_device_id: vault.primary_signing_device_id().to_owned(),
            signer_epoch: vault.signer_epoch(),
            policy_epoch: 1,
            emergency_epoch: 1,
            payments_suspended: true,
            external_rollback_anchor_ready: false,
            trusted_mainnet_fast_pay_pilot,
            l2_binding: None,
            l2_channel_setup: None,
            l2_channel_close: None,
            l2_channel_close_voucher: None,
            hvm_channel_binding: None,
            hvm_registry_binding: None,
            hvm_registry_exit_head: None,
            hvm_registry_open: None,
            agents: BTreeMap::new(),
            pairing_completion_outbox: BTreeMap::new(),
            companion_security: None,
            rollback_witness: None,
            witness_rotation: None,
            witness_rotation_history: Vec::new(),
            operations: BTreeMap::new(),
            fast_pay_operations: BTreeMap::new(),
            hvm_payment_operations: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            authentication_challenges: BTreeMap::new(),
            authenticated_sessions: BTreeMap::new(),
            journal_sequence: 0,
            journal_head_hash: ZERO_HASH_HEX.into(),
            updated_at: now,
        };
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::WalletCreated,
            None,
            None,
            now,
        )?;

        // Publish the public registry entry last. A crash before this point
        // leaves an unregistered private directory, never a half-created wallet.
        let mut registry = self.storage.load_registry()?;
        registry.insert(AgentWalletRegistryEntry::new(
            wallet_id.clone(),
            address.clone(),
            now,
        )?)?;
        self.storage.save_registry(&registry)?;
        self.emergency_controllers
            .insert(wallet_id.as_str().to_owned(), emergency);

        Ok(CreatedAgentWallet {
            wallet_id,
            address,
            network_mode: request.network_mode,
        })
    }

    /// Unlock, and then finish any witness that a crash interrupted between its
    /// two durable writes.
    ///
    /// The recovery reads only what is already on disk and needs no network, so
    /// it belongs here rather than behind a control the owner has to find. It
    /// is a no-op on every wallet that was not interrupted.
    ///
    /// A failure inside it must never cost the owner access to their wallet:
    /// the session is already live at that point, the archive persists as its
    /// last act so a failed one leaves the residue exactly as it was, and the
    /// next unlock tries again.
    pub fn unlock(
        &mut self,
        wallet_id: &AgentWalletId,
        passphrase: &str,
        now: u64,
    ) -> AgentWalletResult<UnlockedAgentWalletStatus> {
        let status = self.unlock_session(wallet_id, passphrase, now)?;
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            let _ = self.resume_interrupted_witness_archive(wallet_id, now);
            let _ = self.resume_interrupted_rotation_baseline(wallet_id, now);
        }
        Ok(status)
    }

    /// The unlock itself, with no recovery attached.
    ///
    /// Split out so the crash-recovery suite can reopen a wallet exactly as it
    /// stood before the recovery existed, and prove that the residue really has
    /// no exit without it.
    #[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn unlock_without_witness_recovery_for_test(
        &mut self,
        wallet_id: &AgentWalletId,
        passphrase: &str,
        now: u64,
    ) -> AgentWalletResult<UnlockedAgentWalletStatus> {
        self.unlock_session(wallet_id, passphrase, now)
    }

    fn unlock_session(
        &mut self,
        wallet_id: &AgentWalletId,
        passphrase: &str,
        now: u64,
    ) -> AgentWalletResult<UnlockedAgentWalletStatus> {
        let registry = self.storage.load_registry()?;
        let entry = registry
            .wallet(wallet_id)
            .ok_or(AgentWalletError::AgentWalletNotFound)?;
        let paths = self.storage.paths(wallet_id)?;
        let vault = AgentEncryptedVault::load(&paths.vault_path())?;
        if vault.wallet_id() != wallet_id || vault.address() != entry.address {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let secrets = vault.unlock(passphrase)?;
        let state_master = Zeroizing::new(*secrets.state_master());
        let journal_key = Zeroizing::new(derive_domain_key(
            &state_master,
            wallet_id,
            vault.store_uuid(),
            b"journal-authentication/v1",
        )?);
        let desktop_identity_secret = Zeroizing::new(*secrets.desktop_identity_secret());
        let desktop_companion_signer = AgentDesktopCompanionSigner::from_unlocked_secret(
            DeviceId::parse(vault.primary_signing_device_id().to_owned())
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            &desktop_identity_secret,
        )?;
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            vault.address().to_owned(),
            vault.network_mode().to_owned(),
            vault.signer_epoch(),
            secrets.blockchain_secret_hex(),
            now,
        )?;
        drop(secrets);
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if state.address != vault.address()
            || state.network_mode != vault.network_mode()
            || state.primary_signing_device_id != vault.primary_signing_device_id()
            || state.signer_epoch != vault.signer_epoch()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let emergency = self.emergency_controller(wallet_id)?;
        let authenticated_emergency_stop = state.payments_suspended && state.emergency_epoch > 1;
        let emergency_status = emergency.reconcile_startup(authenticated_emergency_stop)?;
        if emergency_status.stopped && mark_explicit_emergency_stop(&mut state)? {
            state.updated_at = now;
            self.persist_event(
                &mut state,
                &state_master,
                &journal_key,
                AgentJournalEventKind::EmergencyStopEnabled,
                None,
                None,
                now,
            )?;
        }
        let status = UnlockedAgentWalletStatus {
            wallet_id: wallet_id.clone(),
            address: state.address.clone(),
            network_mode: state.network_mode.clone(),
            signer_epoch: state.signer_epoch,
            payments_suspended: emergency.status(state.payments_suspended).stopped,
        };
        // Persist the security event before publishing the live signer.
        // A failed write must never leave an apparently failed unlock active.
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::WalletUnlocked,
            None,
            None,
            now,
        )?;
        self.unlocked.insert(
            wallet_id.as_str().to_owned(),
            UnlockedAgentWallet {
                unlock_expires_at: now
                    .checked_add(MAX_SESSION_SECONDS)
                    .ok_or(AgentWalletError::IntegerOverflow)?,
                state_master,
                journal_key,
                desktop_identity_secret,
                desktop_companion_signer,
                active_companion_pairings: BTreeMap::new(),
                signer,
            },
        );
        Ok(status)
    }

    /// Return the non-blockchain desktop connector identity only while this
    /// Agent Wallet is unlocked. The private material never enters frontend
    /// state, preferences, logs, or Personal Wallet storage.
    pub fn connector_server_identity(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<(String, hpay_agent_connector::ServerIdentityKey)> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let key = hpay_agent_connector::ServerIdentityKey::from_secret_bytes(
            &session.desktop_identity_secret,
        )
        .map_err(|_| AgentWalletError::Crypto)?;
        key.pinned_identity(state.primary_signing_device_id.clone())
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        Ok((state.primary_signing_device_id, key))
    }

    pub fn lock(&mut self, wallet_id: &AgentWalletId, now: u64) -> AgentWalletResult<()> {
        let Some(session) = self.unlocked.remove(wallet_id.as_str()) else {
            return Ok(());
        };
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WalletLocked,
            None,
            None,
            now,
        )
    }

    pub fn unlocked_status(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<UnlockedAgentWalletStatus> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let payments_suspended = self
            .emergency_controller(wallet_id)?
            .status(state.payments_suspended)
            .stopped;
        Ok(UnlockedAgentWalletStatus {
            wallet_id: state.wallet_id,
            address: state.address,
            network_mode: state.network_mode,
            signer_epoch: state.signer_epoch,
            payments_suspended,
        })
    }

    pub async fn overview(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentWalletOverview> {
        self.expire_session(wallet_id, now);
        let session = match self.unlocked.get(wallet_id.as_str()) {
            Some(session) => session,
            None => {
                let registry = self.storage.load_registry()?;
                let entry = registry
                    .wallet(wallet_id)
                    .ok_or(AgentWalletError::AgentWalletNotFound)?;
                let vault =
                    AgentEncryptedVault::load(&self.storage.paths(wallet_id)?.vault_path())?;
                return Ok(AgentWalletOverview {
                    wallet_id: wallet_id.clone(),
                    address: entry.address.clone(),
                    network_mode: vault.network_mode().to_owned(),
                    node_url: None,
                    block_one_fingerprint: None,
                    node: None,
                    node_status: AgentNodeStatus::Unchecked,
                    node_error: None,
                    unlocked: false,
                    payments_suspended: true,
                    mainnet_spending_ready: agent_spending_ready(vault.network_mode(), false),
                    trusted_mainnet_fast_pay_pilot: false,
                    l2_binding: None,
                    l2_channel_setup: None,
                    l2_channel_close: None,
                    l2_channel_close_voucher: None,
                    hvm_channel_binding: None,
                    hvm_registry_binding: None,
                    confirmed_balance_units: None,
                    reserved_units: HacUnits::ZERO,
                    available_units: None,
                    fast_pay_deposit_units: None,
                    fast_pay_reserved_units: HacUnits::ZERO,
                    fast_pay_available_units: None,
                    spent_today_units: HacUnits::ZERO,
                    spent_this_month_units: HacUnits::ZERO,
                    authorized_agents: 0,
                    pending_approvals: 0,
                    pilot_enabled: cfg!(feature = "agent-wallet-testnet-pilot"),
                    mobile_witness_ready: false,
                    mobile_witness_synchronized: false,
                    latest_anchor_sequence: 0,
                    witness_rotation_phase: None,
                    unresolved_signed_operations: 0,
                    stale: true,
                });
            }
        };
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let node_probe = probe_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await;
        let (confirmed, node_status, node_error) = if node_probe.status == AgentNodeStatus::Verified
        {
            let balance = match hacash_wallet_core::node::NodeClient::new(&state.node_url) {
                Ok(node) => node
                    .query_balance_entry(&state.address, false)
                    .await
                    .map_err(|_| AgentWalletError::NodeRejected)
                    .and_then(|entry| HacUnits::from_decimal(entry.hacash_decimal())),
                Err(_) => Err(AgentWalletError::NodeRejected),
            };
            match balance {
                Ok(balance) => (Some(balance), AgentNodeStatus::Verified, None),
                Err(_) => (
                    None,
                    AgentNodeStatus::BalanceError,
                    Some(
                        "Node anchor verified, but the Agent Wallet balance response was invalid"
                            .into(),
                    ),
                ),
            }
        } else {
            (None, node_probe.status, node_probe.error)
        };
        let reserved = active_l1_reservations(&state)?;
        let fast_pay_reserved = active_fast_pay_reservations(&state)?;
        let fast_pay_deposit = state
            .l2_binding
            .as_ref()
            .filter(|binding| binding.is_active())
            .map(AgentL2Binding::deposit_units);
        let fast_pay_available = fast_pay_deposit
            .map(|deposit| deposit.checked_sub(fast_pay_channel_exposure(&state)?))
            .transpose()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let payments_suspended = self
            .emergency_controller(wallet_id)?
            .status(state.payments_suspended)
            .stopped;
        let available = confirmed.map(|balance| {
            if balance >= reserved {
                HacUnits::new(balance.get() - reserved.get())
            } else {
                HacUnits::ZERO
            }
        });
        Ok(AgentWalletOverview {
            wallet_id: wallet_id.clone(),
            address: state.address.clone(),
            network_mode: state.network_mode.clone(),
            node_url: Some(state.node_url.clone()),
            block_one_fingerprint: Some(state.block_one_fingerprint.clone()),
            node: node_probe.snapshot,
            node_status,
            node_error,
            unlocked: true,
            payments_suspended,
            mainnet_spending_ready: agent_spending_ready(
                &state.network_mode,
                state.trusted_mainnet_fast_pay_pilot,
            ),
            trusted_mainnet_fast_pay_pilot: state.trusted_mainnet_fast_pay_pilot,
            l2_binding: state.l2_binding.clone(),
            l2_channel_setup: state
                .l2_channel_setup
                .as_ref()
                .map(|operation| operation.review.clone()),
            l2_channel_close: state
                .l2_channel_close
                .as_ref()
                .map(|operation| operation.review.clone()),
            l2_channel_close_voucher: state
                .l2_channel_close_voucher
                .as_ref()
                .map(|operation| operation.view.clone()),
            hvm_channel_binding: state.hvm_channel_binding.clone(),
            hvm_registry_binding: state.hvm_registry_binding.clone(),
            confirmed_balance_units: confirmed,
            reserved_units: reserved,
            available_units: available,
            fast_pay_deposit_units: fast_pay_deposit,
            fast_pay_reserved_units: fast_pay_reserved,
            fast_pay_available_units: fast_pay_available,
            spent_today_units: spent_in_window(&state, now, 86_400)?,
            spent_this_month_units: spent_in_window(&state, now, 31 * 86_400)?,
            authorized_agents: state
                .agents
                .values()
                .filter(|agent| agent.status == AgentStatus::Active)
                .count()
                .try_into()
                .map_err(|_| AgentWalletError::IntegerOverflow)?,
            pending_approvals: state
                .operations
                .values()
                .filter(|operation| operation.status() == OperationStatus::ApprovalRequested)
                .count()
                .saturating_add(
                    state
                        .fast_pay_operations
                        .values()
                        .filter(|operation| {
                            operation.status()
                                == crate::fast_pay_operation::AgentFastPayStatus::ApprovalRequested
                        })
                        .count(),
                )
                .try_into()
                .map_err(|_| AgentWalletError::IntegerOverflow)?,
            pilot_enabled: cfg!(feature = "agent-wallet-testnet-pilot"),
            mobile_witness_ready: state.rollback_witness.is_some(),
            mobile_witness_synchronized: state
                .rollback_witness
                .as_ref()
                .is_some_and(|witness| witness.pending.is_none()),
            latest_anchor_sequence: state
                .rollback_witness
                .as_ref()
                .map_or(0, |witness| witness.last_anchor_sequence),
            witness_rotation_phase: state
                .witness_rotation
                .as_ref()
                .map(|rotation| rotation.phase),
            unresolved_signed_operations: state
                .operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.status(),
                        OperationStatus::Signed
                            | OperationStatus::SignedAwaitingWitness
                            | OperationStatus::WitnessedAwaitingBroadcast
                            | OperationStatus::BroadcastSubmitted
                            | OperationStatus::BroadcastUncertain
                            | OperationStatus::SubmittedAwaitingFinalWitness
                            | OperationStatus::ReconciliationRequired
                            | OperationStatus::ReconciledAwaitingFinalWitness
                            | OperationStatus::RecoveryRequired
                    )
                })
                .count()
                .try_into()
                .map_err(|_| AgentWalletError::IntegerOverflow)?,
            stale: confirmed.is_none(),
        })
    }

    pub fn disable_all_agent_payments(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<()> {
        // Durable stop and permit invalidation happen before any manager state
        // read. A supervisor can call the shared controller without this lock.
        self.emergency_controller(wallet_id)?.request_stop()?;
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if !mark_explicit_emergency_stop(&mut state)? {
            return Ok(());
        }
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::EmergencyStopEnabled,
            None,
            None,
            now,
        )
    }

    /// Re-enable is deliberately local-only and requires an unlocked Agent
    /// Wallet. Mobile/agent protocols do not expose this method.
    pub fn enable_agent_payments_locally(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        // Bind this enable attempt to the current emergency generation before
        // changing authenticated state. A newer marker-first stop invalidates
        // the permit and therefore cannot be cleared by this older attempt.
        let emergency = self.emergency_controller(wallet_id)?;
        let enable_permit = emergency.issue_authenticated_enable_permit()?;
        cancel_pre_signing_operations(&mut state, None, "policy_changed")?;
        state.payments_suspended = false;
        state.emergency_epoch = state
            .emergency_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        state.policy_epoch = state
            .policy_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::EmergencyStopDisabled,
            None,
            None,
            now,
        )?;
        // persist_event reload-verifies the authenticated state. Only now may
        // the independent marker and in-memory latch be cleared.
        emergency.clear_after_authenticated_enable(enable_permit, false)
    }

    pub fn revoke_agent(
        &mut self,
        wallet_id: &AgentWalletId,
        agent_id: &AgentId,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let agent = state
            .agents
            .get_mut(agent_id.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?;
        agent.status = AgentStatus::Revoked;
        agent.authorization_epoch = agent
            .authorization_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        state
            .pairing_completion_outbox
            .retain(|_, completion| completion.record().agent_id != *agent_id);
        state.authenticated_sessions.clear();
        state.authentication_challenges.clear();
        cancel_pre_signing_operations(&mut state, Some(agent_id), "agent_revoked")?;
        // Revocation invalidates this agent's authorization epoch, so its
        // newly terminal pre-signing rows cannot be replayed. Remove those
        // rows and their idempotency keys in this same authenticated event.
        prune_terminal_pre_signing_for_agent(&mut state, agent_id);
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::AgentRevoked,
            None,
            Some(agent_id.as_str().as_bytes()),
            now,
        )
    }
}

impl Drop for AgentWalletManager {
    fn drop(&mut self) {
        self.unlocked.clear();
    }
}

#[cfg(test)]
mod tests;
