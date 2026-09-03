//! Durable materialized state for the HPAY Wallet Hub API v7.

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
use crate::hvm_channel::HvmChannelRecoveryBundleV1;
use crate::hvm_ledger::{
    PersistedHvmBillProgression, PersistedHvmChannelLedger, validate_progression,
};
use crate::hvm_registry::{
    HvmRegistryBillV2, HvmRegistryLiveSnapshotV2, HvmRegistryRecoveryBundleV2,
    HvmRegistryRefundCountersignRequestV2,
};
use crate::hvm_registry_ledger::{
    PersistedHvmRegistryLedger, PersistedHvmRegistryProgression, validate_registry_progression,
};
use crate::journal::{
    AuthenticatedJournal, JournalEvent, JournalHead, JournalOperationType, JournalPhase,
};
use crate::node::HvmChannelLiveSnapshot;
use crate::operation::{IdempotencyRecord, ReservationStatus};
use crate::rollback_anchor::{HubAnchorRequestV1, HubWitnessReceiptV1, RollbackAnchorPin};
use crate::sealed_state::StateStore;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmChannelActivation {
    pub binding_commitment: String,
    pub recovery_bundle: HvmChannelRecoveryBundleV1,
    pub activation_snapshot: HvmChannelLiveSnapshot,
    pub minimum_required_live_blocks: u64,
    pub minimum_required_recover_blocks: u64,
    pub activated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmRegistryActivation {
    pub binding_commitment: String,
    pub recovery_bundle: HvmRegistryRecoveryBundleV2,
    pub activation_snapshot: HvmRegistryLiveSnapshotV2,
    pub minimum_required_live_blocks: u64,
    pub minimum_required_recover_blocks: u64,
    pub activated_unix: u64,
}

/// The Hub's durable record of one serial-1 refund it countersigned at channel
/// open, keyed on the binding commitment.
///
/// One binding, one refund signature, forever. Re-asking returns the identical
/// bytes; asking with a different serial-1 bill for the same binding is
/// refused. That is what stops a Hub being walked into signing two different
/// refunds for one channel, and it is why this is durable rather than derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmRegistryOpenCountersignature {
    pub binding_commitment: String,
    pub request: HvmRegistryRefundCountersignRequestV2,
    pub hub_refund_signature_hex: String,
    pub anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
    pub countersigned_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HvmChainOperationKind {
    Challenge,
    Respond,
    Finalize,
    RenewAllLeases,
    /// Move the settled principal out of the contract with an Action 14
    /// `HacFromToTrs` whose `from` is the contract. This is the only door HAC
    /// leaves either HPAY contract through: on the registry rail `settle()`
    /// only rewrites the claimable counters, and on the V1 rail `finalize()`
    /// only writes `status`. Both contracts admit the payout through a
    /// `PermitHAC` hook that pins the payee and the exact amount.
    Claim,
}

impl HvmChainOperationKind {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Respond => "respond",
            Self::Finalize => "finalize",
            Self::RenewAllLeases => "renew_all_leases",
            Self::Claim => "claim",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HvmChainOperationStatus {
    IntentPersisted,
    SignatureMayExist,
    Signed,
    SubmissionStarted,
    Submitted,
    Confirmed,
    RecoveryRequired,
    /// Terminal. The exact signed transaction was proven inadmissible by a
    /// consensus rule that block verification itself applies, so it cannot be
    /// inside any valid block, and it was read from the chain one last time
    /// and found absent. Nothing will ever offer these bytes to a node again.
    ///
    /// Only the shared HVM registry table has this transition; see
    /// [`super::inadmissible`] for the proof it requires.
    Abandoned,
}

impl HvmChainOperationStatus {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::IntentPersisted => "intent_persisted",
            Self::SignatureMayExist => "signature_may_exist",
            Self::Signed => "signed",
            Self::SubmissionStarted => "submission_started",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::RecoveryRequired => "recovery_required",
            Self::Abandoned => "abandoned",
        }
    }

    /// Does this status leave nothing outstanding against the channel?
    ///
    /// A resolved operation no longer blocks a new one. `Confirmed` resolves
    /// because the transaction executed; `Abandoned` resolves because it
    /// provably could not have. Every other status leaves a transaction whose
    /// fate is still open, and those keep the channel occupied.
    pub(crate) const fn is_resolved(&self) -> bool {
        matches!(self, Self::Confirmed | Self::Abandoned)
    }
}

/// Why a registry chain operation was abandoned, kept with the record forever.
///
/// This is the evidence, not a note. `validate_hvm_state` re-checks the
/// arithmetic on every load, so a state file cannot carry an abandonment whose
/// own numbers do not prove it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmChainAbandonment {
    /// Stable name of the consensus rule that proved the bytes inadmissible.
    /// Must be one [`crate::inadmissible::InadmissibilityRule`] still knows.
    pub rule: String,
    /// The exact arithmetic in words, so the record is auditable without the
    /// node that produced it.
    pub detail: String,
    /// Timestamp read out of the signed bytes themselves.
    pub transaction_timestamp: u64,
    /// The chain tip the proof was taken against.
    pub chain_tip_timestamp_unix: u64,
    pub observed_unix: u64,
    pub proof_height: u64,
    /// Height at which the transaction was read one last time and found
    /// absent. The proof says it cannot be there; this says it is not.
    pub absent_at_height: u64,
    pub abandoned_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmChainOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub binding_commitment: String,
    pub kind: HvmChainOperationKind,
    pub bill_serial: Option<u64>,
    pub expected_left_balance_zhu: Option<u64>,
    pub expected_right_balance_zhu: Option<u64>,
    pub lease_keys: Vec<String>,
    pub lease_periods: Option<u64>,
    /// Exact payee of a `Claim`. Absent for every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_payee: Option<String>,
    /// Exact zhu a `Claim` moves. The contract's `PermitHAC` hook demands this
    /// equal `left_balance` to the zhu, so it is never approximated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_amount_zhu: Option<u64>,
    /// Observed height at which the exact payout was found already recorded on
    /// chain by somebody else. Claims are permissionless, so a third party can
    /// pay the payee first; that settles this operation without a second
    /// transaction of our own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_settled_elsewhere_height: Option<u64>,
    pub pre_observed_height: u64,
    pub pre_status: u8,
    pub pre_serial: u64,
    pub pre_minimum_live_blocks: u64,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub transaction_timestamp: u64,
    pub call_source_commitment: String,
    pub call_source: String,
    pub signed_transaction_hex: Option<String>,
    pub transaction_hash: Option<String>,
    pub status: HvmChainOperationStatus,
    pub submitted_unix: Option<u64>,
    pub confirmed_block_height: Option<u64>,
    pub observed_confirmations: u64,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmRegistryChainOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub binding_commitment: String,
    pub kind: HvmChainOperationKind,
    pub bill: Option<HvmRegistryBillV2>,
    pub lease_periods: Option<u64>,
    /// Exact payee of a `Claim`. Absent for every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_payee: Option<String>,
    /// Exact zhu a `Claim` moves. The contract's `PermitHAC` hook demands this
    /// equal `c_left_balance_` to the zhu, so it is never approximated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_amount_zhu: Option<u64>,
    /// Observed height at which the exact payout was found already recorded on
    /// chain by somebody else. Claims are permissionless, so a third party can
    /// pay the payee first; that settles this operation without a second
    /// transaction of our own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_settled_elsewhere_height: Option<u64>,
    pub pre_observed_height: u64,
    pub pre_status: u8,
    pub pre_serial: u64,
    pub pre_left_balance_zhu: u64,
    pub pre_hub_balance_zhu: u64,
    pub pre_deadline: u64,
    pub pre_minimum_live_blocks: u64,
    pub pre_minimum_recover_blocks: u64,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub transaction_timestamp: u64,
    pub call_source_commitment: String,
    pub call_source: String,
    pub signed_transaction_hex: Option<String>,
    pub transaction_hash: Option<String>,
    pub status: HvmChainOperationStatus,
    pub submitted_unix: Option<u64>,
    pub confirmed_block_height: Option<u64>,
    /// Canonical hash of the block the transaction was observed in. Together
    /// with `confirmed_block_height` this is the reorg anchor: an observation
    /// that moves either half is a reorg, not a fresher reading. Records
    /// written before anchoring existed carry `None` and are treated as legacy
    /// unanchored, exactly as the Local Pilot journal treats them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_block_hash: Option<String>,
    pub observed_confirmations: u64,
    /// Present exactly when `status` is `Abandoned`, and never otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<PersistedHvmChainAbandonment>,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub last_error: Option<String>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum L1ChannelOpenStatus {
    ValidatedBeforeSigning,
    AbandonedUnsigned,
    SignatureMayExist,
    Signed,
    SubmissionStarted,
    Submitted,
    Confirmed,
    /// Broadcast, never mined, and the chain says so.
    ///
    /// Before this variant existed the only two statuses that stopped holding
    /// pilot admission budget were `Confirmed` and `AbandonedUnsigned`, and
    /// `AbandonedUnsigned` is reachable only before a signature exists. So an
    /// open that was signed, broadcast and then never included held its whole
    /// deposit against `--mainnet-max-aggregate-tvl-hac-zhu` for the life of
    /// the durable state, and nothing in the tree could ever release it. On a
    /// pilot Hub whose cap is one channel wide that is a permanent brick: the
    /// budget was spent by a transaction that does not exist.
    ///
    /// It is not a tombstone. The bytes are real and carry both signatures, so
    /// `has_durable_signature` stays true and the sweep keeps asking the chain
    /// about it. If the transaction is ever mined after all, the very next
    /// admission re-adopts it and the deposit starts counting again. What the
    /// variant retires is the *reservation*, not the operation.
    AbandonedUnmined,
    RecoveryRequired,
}

impl L1ChannelOpenStatus {
    pub(crate) fn public_name(&self) -> &'static str {
        match self {
            Self::ValidatedBeforeSigning => "validated_before_signing",
            Self::AbandonedUnsigned => "abandoned_unsigned",
            Self::SignatureMayExist => "signature_may_exist",
            Self::Signed => "signed",
            Self::SubmissionStarted => "submission_started",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::AbandonedUnmined => "abandoned_unmined",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    pub(crate) fn reserves_admission(&self) -> bool {
        !matches!(
            self,
            Self::Confirmed | Self::AbandonedUnsigned | Self::AbandonedUnmined
        )
    }

    pub(crate) fn has_durable_signature(&self) -> bool {
        matches!(
            self,
            Self::Signed
                | Self::SubmissionStarted
                | Self::Submitted
                | Self::Confirmed
                | Self::AbandonedUnmined
                | Self::RecoveryRequired
        )
    }

    /// This open's signed bytes must not be put on the wire again by the Hub.
    ///
    /// A retired open was retired precisely because the Hub decided to stop
    /// carrying it. Re-broadcasting it on the next resume would hand the
    /// deposit straight back to the budget it was released from, which is the
    /// opposite of the point.
    pub(crate) fn is_retired_unmined(&self) -> bool {
        matches!(self, Self::AbandonedUnmined)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedL1ChannelOpen {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub chain_id: u32,
    #[serde(default)]
    pub mainnet: bool,
    #[serde(default)]
    pub block_1_hash: String,
    #[serde(default)]
    pub node_profile_id: String,
    #[serde(default)]
    pub network_instance_id: String,
    #[serde(default)]
    pub transaction_format_version: u64,
    pub channel_id: String,
    #[serde(default = "default_channel_reuse_version")]
    pub reuse_version: u64,
    pub user_address: String,
    pub user_deposit_zhu: u64,
    #[serde(default)]
    pub network_fee_zhu: u64,
    pub partial_transaction_hex: String,
    pub partial_transaction_commitment: String,
    pub transaction_hash: String,
    pub signed_transaction_hex: Option<String>,
    pub signed_transaction_commitment: Option<String>,
    #[serde(default)]
    pub confirmed_block_height: Option<u64>,
    /// Chain height the fullnode reported when these bytes went on the wire.
    ///
    /// Recorded so that "this was broadcast and never mined" can be judged in
    /// blocks rather than in seconds. A chain that stalls produces no blocks
    /// and therefore retires nothing, which a wall clock cannot express: it
    /// would call an open dead during an outage that never gave it a chance to
    /// be included in the first place.
    ///
    /// `None` for every record written before this field existed - including
    /// the one this whole change is about. Those fall back to the wall clock;
    /// see `open_is_retirement_candidate`.
    ///
    /// `skip_serializing_if` is not tidiness, it is the difference between the
    /// owner's Hub starting and not starting. `state_commitment` is a SHA over
    /// the serialized state, and `initialize_authenticated_state` refuses to
    /// boot when that hash does not match the one the journal recorded. A new
    /// field that always serializes changes the hash of every durable state
    /// that already contains a channel-open, so upgrading the binary would
    /// bricked the Hub with `StateCommitmentMismatch` on a state that was never
    /// touched. Skipped when absent, an untouched record serializes exactly as
    /// it did before and its commitment is unchanged; the first transition that
    /// records a height recomputes both sides together, which is the normal
    /// path. Pinned by `a_new_field_must_not_move_an_untouched_state_commitment`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broadcast_height: Option<u64>,
    #[serde(default)]
    pub observed_confirmations: u64,
    pub status: L1ChannelOpenStatus,
    pub created_unix: u64,
    pub expires_unix: u64,
    #[serde(default)]
    pub updated_unix: u64,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChannelLifecycleStatus {
    FreezeIntentPersisted,
    FrozenBeforeSigning,
    SignatureMayExist,
    Signed,
    SubmissionStarted,
    Submitted,
    ConfirmedClosed,
    Retired,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedChannelLifecycle {
    pub operation_id: String,
    pub channel_id: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub status: ChannelLifecycleStatus,
    pub state_commitment: String,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum L1ChannelCloseStatus {
    FreezeIntentPersisted,
    FrozenBeforeSigning,
    SignatureMayExist,
    Signed,
    SubmissionStarted,
    Submitted,
    ConfirmedClosed,
    Retired,
    RecoveryRequired,
}

impl L1ChannelCloseStatus {
    pub(crate) fn public_name(&self) -> &'static str {
        match self {
            Self::FreezeIntentPersisted => "freeze_intent_persisted",
            Self::FrozenBeforeSigning => "frozen_before_signing",
            Self::SignatureMayExist => "signature_may_exist",
            Self::Signed => "signed",
            Self::SubmissionStarted => "submission_started",
            Self::Submitted => "submitted",
            Self::ConfirmedClosed => "confirmed_closed",
            Self::Retired => "retired",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct PersistedL1ChannelClose {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub chain_id: u32,
    #[serde(default)]
    pub mainnet: bool,
    #[serde(default)]
    pub block_1_hash: String,
    #[serde(default)]
    pub node_profile_id: String,
    #[serde(default)]
    pub network_instance_id: String,
    #[serde(default)]
    pub transaction_format_version: u64,
    pub channel_id: String,
    pub hub_address: String,
    pub user_address: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub original_ledger: ChannelLedger,
    #[serde(default)]
    pub final_ledger: Option<ChannelLedger>,
    pub partial_transaction_hex: String,
    pub partial_transaction_commitment: String,
    pub authorization_public_key_hex: String,
    pub authorization_signature_hex: String,
    pub transaction_hash: Option<String>,
    pub signed_transaction_hex: Option<String>,
    pub signed_transaction_commitment: Option<String>,
    #[serde(default)]
    pub confirmed_block_height: Option<u64>,
    #[serde(default)]
    pub observed_confirmations: u64,
    pub status: L1ChannelCloseStatus,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub updated_unix: u64,
    pub last_error: Option<String>,
}

/// How far one channel-close voucher got. There are only two states, and no
/// terminal one: a voucher is never retired, because the Hub never learns
/// whether the owner broadcast it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum L1ChannelCloseVoucherStatus {
    /// Made durable **before** the Hub signer was called. A crash here leaves
    /// the entry in place with no bytes, and the entry alone permanently bars
    /// this channel from ever being issued another voucher. That is the point:
    /// the Hub must never be able to produce two conflicting signed closes for
    /// one channel, so an unrecoverable signature is refused rather than
    /// replaced.
    SignatureMayExist,
    /// The exact countersigned bytes are persisted and were returned.
    Issued,
}

/// The one delta-zero close this Hub countersigned for one channel, and handed
/// back instead of broadcasting.
///
/// Kept in its own single-entry-per-channel map rather than in
/// `l1_channel_closes`, because the two are different promises: a cooperative
/// close is a transaction the Hub broadcasts and then tracks to finality, and
/// a voucher is a signature the Hub gives away and never hears about again.
/// One channel may have one or the other, never both.
///
/// Exactly one voucher per channel, ever, at delta zero, never refreshed.
/// Refreshing after payments would leave the owner holding several valid
/// closes naming the same channel, each with a distinct transaction hash, only
/// the first to land winning; the owner would rationally broadcast the oldest,
/// which is pure loss to the Hub for zero owner benefit, since a delta-zero
/// voucher already pays the owner the maximum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct PersistedL1ChannelCloseVoucher {
    pub channel_id: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub network: String,
    pub chain_id: u32,
    pub mainnet: bool,
    pub block_1_hash: String,
    pub node_profile_id: String,
    pub network_instance_id: String,
    pub transaction_format_version: u64,
    pub hub_address: String,
    pub user_address: String,
    pub reuse_version: u64,
    pub open_height: u64,
    /// The distribution recorded on L1 at open, which is what Action 3 refunds
    /// and therefore what this voucher pays out.
    pub original_ledger: ChannelLedger,
    pub partial_transaction_hex: String,
    pub partial_transaction_commitment: String,
    pub transaction_hash: String,
    #[serde(default)]
    pub signed_transaction_hex: Option<String>,
    #[serde(default)]
    pub signed_transaction_commitment: Option<String>,
    pub status: L1ChannelCloseVoucherStatus,
    pub created_unix: u64,
    pub updated_unix: u64,
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_opens: HashMap<String, PersistedL1ChannelOpen>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_open_idempotency: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_open_commitments: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub channel_lifecycle: HashMap<String, PersistedChannelLifecycle>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_closes: HashMap<String, PersistedL1ChannelClose>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_close_idempotency: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_close_commitments: HashMap<String, String>,
    /// Channel-close vouchers, keyed by channel ID so the map itself enforces
    /// one per channel. Absent and skipped on every state file written before
    /// vouchers existed, so the state commitment of a Hub that never issued one
    /// is byte-identical to what it was.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub l1_channel_close_vouchers: HashMap<String, PersistedL1ChannelCloseVoucher>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_channel_activations: HashMap<String, PersistedHvmChannelActivation>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_channel_ledgers: HashMap<String, PersistedHvmChannelLedger>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_bill_progressions: HashMap<String, PersistedHvmBillProgression>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_chain_operations: HashMap<String, PersistedHvmChainOperation>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_registry_activations: HashMap<String, PersistedHvmRegistryActivation>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_registry_ledgers: HashMap<String, PersistedHvmRegistryLedger>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_registry_progressions: HashMap<String, PersistedHvmRegistryProgression>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_registry_chain_operations: HashMap<String, PersistedHvmRegistryChainOperation>,
    /// Serial-1 refunds this Hub has countersigned at channel open, before the
    /// channel exists on chain and before it holds any coin.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hvm_registry_open_countersignatures:
        HashMap<String, PersistedHvmRegistryOpenCountersignature>,
    /// The Hub's half of the external monotonic rollback anchor: the pinned
    /// witness store, the highest counter this Hub has durably recorded, and
    /// the exact reservation for each in-flight signature.
    ///
    /// Absent on every state file written before the anchor existed, and
    /// skipped when absent, so the state commitment of an anchor-free Hub is
    /// byte-identical to what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_anchor: Option<PersistedRollbackAnchorState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedRollbackAnchorState {
    #[serde(default)]
    pub pin: RollbackAnchorPin,
    /// Highest serial this Hub has reserved with the witness, per channel.
    #[serde(default)]
    pub channel_serials: HashMap<String, u64>,
    /// The exact anchor request this Hub put on the wire, per operation, made
    /// durable **before** it was sent. A receipt that does not match one of
    /// these matches nothing.
    #[serde(default)]
    pub reservations: HashMap<String, PersistedRollbackAnchorReservation>,
    /// Channels latched in anchor refusal. A latched channel never signs again
    /// without the operator procedure, and a single latched channel holds
    /// `external_rollback_anchor_ready` false for the whole Hub.
    #[serde(default)]
    pub latched_refusals: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedRollbackAnchorReservation {
    pub request: HubAnchorRequestV1,
    pub request_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<HubWitnessReceiptV1>,
    /// The witness's signature over `receipt`, kept beside it rather than
    /// instead of it so that a state file written before this field existed
    /// still loads under `deny_unknown_fields`.
    ///
    /// It is kept because the receipt does not stop at this Hub: it rides on
    /// with the co-signed bill to the counterparty wallet, which recovers the
    /// witness's signing address from this signature. A retry that replayed a
    /// receipt with the signature stripped would serve a bill the counterparty
    /// cannot check, so [`reserve_rollback_anchor`] re-reserves rather than
    /// replaying when this is absent.
    ///
    /// Absent and skipped on every reservation persisted before this field, so
    /// the state commitment of a Hub that never reserved anything is unchanged.
    ///
    /// [`reserve_rollback_anchor`]: crate::state::HubState
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_signature_hex: Option<String>,
    pub updated_unix: u64,
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
    state_store: &StateStore,
    state: &mut HubPersistedState,
    journal: &AuthenticatedJournal,
    hub_address: &str,
) -> HubResult<()> {
    validate_hvm_state(state)?;
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
        backup_legacy_state(state_store.path())?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", hub_address.trim()),
            hub_or_provider_identity: hub_address.trim().to_owned(),
            channel_id: "__migration__".into(),
            channel_reuse_version: 0,
            operation_id: "legacy-state-migration-v1".into(),
            operation_type: JournalOperationType::Migration,
            operation_phase: JournalPhase::ReconciliationCompleted,
            amount_zhu: 0,
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
        state_store.save(state)?;
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
            state_store.save(state)?;
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

pub(crate) fn validate_hvm_state(state: &HubPersistedState) -> HubResult<()> {
    validate_hvm_channel_activations_v1(state)?;
    validate_hvm_registry_activations_v2(state)?;
    validate_rollback_anchor_state(state)
}

/// The Hub's durable anchor record has to be internally consistent, because
/// the whole point of it is to be the thing a restored Hub is measured
/// against. Each stored reservation must re-derive its own commitment, each
/// stored receipt must restate the exact request it answers, and the pinned
/// counter must not sit below any receipt the Hub already holds.
fn validate_rollback_anchor_state(state: &HubPersistedState) -> HubResult<()> {
    let Some(anchor) = state.rollback_anchor.as_ref() else {
        return Ok(());
    };
    for (operation_id, reservation) in &anchor.reservations {
        if reservation.request.commitment()? != reservation.request_commitment {
            return Err(HubError::State(format!(
                "rollback anchor reservation {operation_id} does not re-derive its commitment"
            )));
        }
        let Some(receipt) = reservation.receipt.as_ref() else {
            continue;
        };
        if receipt.request_id != reservation.request.request_id
            || receipt.request_commitment != reservation.request_commitment
            || receipt.hub_identity != reservation.request.hub_identity
            || receipt.binding_commitment != reservation.request.binding_commitment
            || receipt.serial != reservation.request.serial
            || receipt.proposed_bill_commitment != reservation.request.proposed_bill_commitment
            || receipt.counter_value != reservation.request.counter_value
        {
            return Err(HubError::State(format!(
                "rollback anchor receipt for {operation_id} does not restate its request"
            )));
        }
        // The pinned counter belongs to the pinned witness. A continuity
        // reservation is by construction answered by a *different* store - the
        // ceremony exists only while the pin no longer matches, and it
        // deliberately does not move the pin - so its counter is a position in
        // an unrelated sequence and comparing the two is a category error.
        // Left in, it made the declaration permanently unavailable (a hard 500,
        // on every read) for exactly the honest operator the path exists to
        // rescue, whenever the replacement store happened to be ahead of the
        // incumbent. The invariant that does apply is checked instead, and it
        // is a stronger one: a continuity receipt must not come from the pinned
        // store at all.
        if operation_id.starts_with(crate::rollback_anchor::CONTINUITY_REQUEST_ID_PREFIX) {
            if !anchor.pin.witness_instance_id.is_empty()
                && receipt.witness_instance_id == anchor.pin.witness_instance_id
            {
                return Err(HubError::State(format!(
                    "rollback anchor continuity reservation {operation_id} is receipted by the \
                     witness store this Hub pinned, so it re-anchors nothing"
                )));
            }
        } else if receipt.counter_value > anchor.pin.highest_counter_value {
            return Err(HubError::State(format!(
                "rollback anchor receipt for {operation_id} is ahead of the durable counter"
            )));
        }
        if anchor
            .channel_serials
            .get(&receipt.binding_commitment)
            .is_none_or(|serial| *serial < receipt.serial)
        {
            return Err(HubError::State(format!(
                "rollback anchor receipt for {operation_id} is ahead of the durable channel serial"
            )));
        }
    }
    Ok(())
}

fn validate_hvm_channel_activations_v1(state: &HubPersistedState) -> HubResult<()> {
    let activations = state.hvm_channel_activations.values().collect::<Vec<_>>();
    for (map_key, activation) in &state.hvm_channel_activations {
        activation.recovery_bundle.validate_crypto()?;
        let binding = &activation.recovery_bundle.binding;
        if map_key != &activation.binding_commitment
            || activation.binding_commitment != binding.commitment()?
            || activation.minimum_required_live_blocks == 0
        {
            return Err(HubError::State(
                "persisted HVM activation key or commitment is inconsistent".into(),
            ));
        }
        if activation.minimum_required_recover_blocks == 0 {
            activation
                .activation_snapshot
                .validate_initial_open_binding(binding, activation.minimum_required_live_blocks)?;
        } else {
            activation.activation_snapshot.validate_open_binding(
                binding,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks,
            )?;
        }
    }
    for (index, left) in activations.iter().enumerate() {
        let left = &left.recovery_bundle.binding;
        for right in activations.iter().skip(index + 1) {
            let right = &right.recovery_bundle.binding;
            if left.contract_address == right.contract_address
                || (left.channel_id == right.channel_id
                    && left.reuse_version == right.reuse_version)
            {
                return Err(HubError::State(
                    "persisted HVM activations reuse a contract or channel incarnation".into(),
                ));
            }
        }
    }
    if state.hvm_channel_ledgers.len() != state.hvm_channel_activations.len() {
        return Err(HubError::State(
            "persisted HVM activations and ledgers are not one-to-one".into(),
        ));
    }
    for (commitment, ledger) in &state.hvm_channel_ledgers {
        let activation = state
            .hvm_channel_activations
            .get(commitment)
            .ok_or_else(|| {
                HubError::State("persisted HVM ledger has no exact activation".into())
            })?;
        let binding = &activation.recovery_bundle.binding;
        if ledger.binding_commitment != *commitment
            || ledger.latest_fully_signed_bill.binding_commitment != *commitment
        {
            return Err(HubError::State(
                "persisted HVM ledger commitment is inconsistent".into(),
            ));
        }
        ledger
            .latest_fully_signed_bill
            .validate_fully_signed(binding)?;
    }
    for (operation_id, progression) in &state.hvm_bill_progressions {
        if progression.request.operation_id != *operation_id {
            return Err(HubError::State(
                "persisted HVM progression map key is inconsistent".into(),
            ));
        }
        let activation = state
            .hvm_channel_activations
            .get(&progression.request.binding_commitment)
            .ok_or_else(|| HubError::State("HVM progression activation is missing".into()))?;
        let ledger = state
            .hvm_channel_ledgers
            .get(&progression.request.binding_commitment)
            .ok_or_else(|| HubError::State("HVM progression ledger is missing".into()))?;
        validate_progression(progression, &activation.recovery_bundle.binding, ledger)?;
    }
    for progression in state
        .hvm_bill_progressions
        .values()
        .filter(|progression| progression.status.is_unresolved())
    {
        let count = state
            .hvm_bill_progressions
            .values()
            .filter(|other| {
                other.status.is_unresolved()
                    && other.request.binding_commitment == progression.request.binding_commitment
            })
            .count();
        if count != 1 {
            return Err(HubError::State(
                "HVM channel has more than one unresolved bill progression".into(),
            ));
        }
    }
    for (operation_id, operation) in &state.hvm_chain_operations {
        if operation.operation_id != *operation_id
            || operation.operation_id.trim().is_empty()
            || operation.idempotency_key.trim().is_empty()
            || !state
                .hvm_channel_activations
                .contains_key(&operation.binding_commitment)
            || operation.network_fee_zhu == 0
            || operation.gas_max == 0
            || operation.transaction_timestamp == 0
            || operation.pre_observed_height == 0
            || !matches!(operation.pre_status, 2..=4)
            || operation.call_source_commitment.len() != 64
            || operation.call_source.trim().is_empty()
            || hex::encode(Sha256::digest(operation.call_source.as_bytes()))
                != operation.call_source_commitment
        {
            return Err(HubError::State(
                "persisted HVM chain operation identity is inconsistent".into(),
            ));
        }
        let expected_lease_keys = crate::hvm_watchtower::HVM_STORAGE_KEYS
            .iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>();
        if operation.kind == HvmChainOperationKind::RenewAllLeases {
            if operation.lease_keys != expected_lease_keys
                || operation.lease_periods.is_none_or(|periods| {
                    periods == 0 || periods > crate::hvm_watchtower::HVM_LEASE_RENEWAL_MAX_PERIODS
                })
                || operation.bill_serial.is_some()
            {
                return Err(HubError::State(
                    "persisted HVM lease renewal does not cover exactly all 18 keys".into(),
                ));
            }
        } else if !operation.lease_keys.is_empty() || operation.lease_periods.is_some() {
            return Err(HubError::State(
                "non-renewal HVM operation contains lease state".into(),
            ));
        }
        let bill_state_required = matches!(
            operation.kind,
            HvmChainOperationKind::Challenge | HvmChainOperationKind::Respond
        );
        if bill_state_required
            != (operation.bill_serial.is_some()
                && operation.expected_left_balance_zhu.is_some()
                && operation.expected_right_balance_zhu.is_some())
        {
            return Err(HubError::State(
                "persisted HVM operation bill postcondition is incomplete".into(),
            ));
        }
        if operation.kind == HvmChainOperationKind::Claim {
            let binding = &state
                .hvm_channel_activations
                .get(&operation.binding_commitment)
                .ok_or_else(|| HubError::State("HVM claim activation is missing".into()))?
                .recovery_bundle
                .binding;
            let payee = operation
                .claim_payee
                .as_deref()
                .ok_or_else(|| HubError::State("HVM claim lost its exact payee".into()))?;
            let amount_zhu = operation
                .claim_amount_zhu
                .ok_or_else(|| HubError::State("HVM claim lost its exact payout amount".into()))?;
            // Re-derive the canonical descriptor from the binding rather than
            // trusting the stored text. A payout record that no longer derives
            // is a record this Hub must not sign from again.
            if crate::hvm_watchtower::claim_left_payout_source(binding, payee, amount_zhu)?
                != operation.call_source
            {
                return Err(HubError::State(
                    "persisted HVM claim payout descriptor is not canonical".into(),
                ));
            }
        } else if operation.claim_payee.is_some()
            || operation.claim_amount_zhu.is_some()
            || operation.claim_settled_elsewhere_height.is_some()
        {
            return Err(HubError::State(
                "non-claim HVM operation contains payout state".into(),
            ));
        }
        // A permissionless third party may pay the payee before us. When that
        // is observed the operation resolves with the contract's own
        // `left_claimed` flag as its evidence; it never owns a block of its
        // own, so it must not pretend to.
        let settled_elsewhere = operation.claim_settled_elsewhere_height;
        if let Some(height) = settled_elsewhere
            && (height == 0
                || operation.status != HvmChainOperationStatus::Confirmed
                || operation.confirmed_block_height.is_some()
                || operation.observed_confirmations != 0)
        {
            return Err(HubError::State(
                "HVM claim settled elsewhere carries inconsistent evidence".into(),
            ));
        }
        // The abandonment transition belongs to the shared registry table
        // alone, which is where the proof gate and its durable evidence live.
        // A v1 record carrying it has no proof behind it and is refused.
        if operation.status == HvmChainOperationStatus::Abandoned {
            return Err(HubError::State(
                "the v1 HVM chain operation table has no abandonment transition".into(),
            ));
        }
        // A settled-elsewhere claim keeps its exact signed bytes like every
        // other record past `SignatureMayExist`. There is no carve-out here.
        //
        // There used to be one, for "a claim resolved before it was ever
        // signed". No v1 production path can reach that state: both callers of
        // `settle_hvm_claim_paid_elsewhere` sit downstream of points where the
        // signed bytes and the transaction hash have already been unwrapped.
        // The relaxation therefore bought nothing, and only widened what a
        // hand-edited state file could carry past validation, so it was
        // removed rather than left standing as a dead exemption.
        let signed_required = !matches!(
            operation.status,
            HvmChainOperationStatus::IntentPersisted | HvmChainOperationStatus::SignatureMayExist
        );
        if signed_required
            && (operation
                .signed_transaction_hex
                .as_deref()
                .is_none_or(str::is_empty)
                || operation
                    .transaction_hash
                    .as_deref()
                    .is_none_or(str::is_empty))
        {
            return Err(HubError::State(
                "persisted HVM chain operation lost its exact signed transaction".into(),
            ));
        }
        if operation.status == HvmChainOperationStatus::Confirmed
            && settled_elsewhere.is_none()
            && (operation.confirmed_block_height.is_none() || operation.observed_confirmations < 6)
        {
            return Err(HubError::State(
                "confirmed HVM chain operation lacks finality evidence".into(),
            ));
        }
        let idempotency_count = state
            .hvm_chain_operations
            .values()
            .filter(|other| other.idempotency_key == operation.idempotency_key)
            .count();
        if idempotency_count != 1 {
            return Err(HubError::State(
                "persisted HVM chain operation idempotency key is not unique".into(),
            ));
        }
        if operation.status != HvmChainOperationStatus::Confirmed {
            let unresolved_for_binding = state
                .hvm_chain_operations
                .values()
                .filter(|other| {
                    other.binding_commitment == operation.binding_commitment
                        && other.status != HvmChainOperationStatus::Confirmed
                })
                .count();
            if unresolved_for_binding != 1 {
                return Err(HubError::State(
                    "persisted HVM channel has more than one unresolved chain operation".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_hvm_registry_open_countersignatures_v2(state: &HubPersistedState) -> HubResult<()> {
    for (map_key, record) in &state.hvm_registry_open_countersignatures {
        record.request.validate_shape()?;
        let binding_commitment = record.request.binding.commitment()?;
        if map_key != &record.binding_commitment
            || record.binding_commitment != binding_commitment
            || record.countersigned_unix == 0
        {
            return Err(HubError::State(
                "persisted registry open countersignature commitment is inconsistent".into(),
            ));
        }
        // Re-derive the whole answer from the stored ask. A record that no
        // longer verifies is a record this Hub must not serve again.
        let bundle = record
            .request
            .attach_hub_countersignature(&record.hub_refund_signature_hex)?;
        if bundle.binding != record.request.binding {
            return Err(HubError::State(
                "persisted registry open countersignature drifted from its binding".into(),
            ));
        }
    }
    Ok(())
}

fn validate_hvm_registry_activations_v2(state: &HubPersistedState) -> HubResult<()> {
    validate_hvm_registry_open_countersignatures_v2(state)?;
    let activations = state.hvm_registry_activations.values().collect::<Vec<_>>();
    for (map_key, activation) in &state.hvm_registry_activations {
        activation.recovery_bundle.validate_crypto()?;
        let binding = &activation.recovery_bundle.binding;
        if map_key != &activation.binding_commitment
            || activation.binding_commitment != binding.commitment()?
            || activation.minimum_required_live_blocks == 0
        {
            return Err(HubError::State(
                "persisted HVM registry activation commitment is inconsistent".into(),
            ));
        }
        if activation.minimum_required_recover_blocks == 0 {
            activation
                .activation_snapshot
                .validate_initial_open_binding(binding, activation.minimum_required_live_blocks)?;
        } else {
            activation.activation_snapshot.validate_open_binding(
                binding,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks,
            )?;
        }
    }
    for (index, left) in activations.iter().enumerate() {
        let left = &left.recovery_bundle.binding;
        for right in activations.iter().skip(index + 1) {
            let right = &right.recovery_bundle.binding;
            if (left.contract_address == right.contract_address
                && left.left_address == right.left_address)
                || (left.contract_address == right.contract_address
                    && left.channel_id == right.channel_id
                    && left.reuse_version == right.reuse_version)
            {
                return Err(HubError::State(
                    "shared HVM registry reuses a left slot or channel incarnation".into(),
                ));
            }
        }
    }
    if state.hvm_registry_ledgers.len() != state.hvm_registry_activations.len() {
        return Err(HubError::State(
            "registry activations and ledgers are not one-to-one".into(),
        ));
    }
    for (commitment, ledger) in &state.hvm_registry_ledgers {
        let activation = state
            .hvm_registry_activations
            .get(commitment)
            .ok_or_else(|| HubError::State("registry ledger has no activation".into()))?;
        let binding = &activation.recovery_bundle.binding;
        if ledger.binding_commitment != *commitment
            || ledger.latest_fully_signed_bill.binding_commitment != *commitment
        {
            return Err(HubError::State(
                "registry ledger commitment is inconsistent".into(),
            ));
        }
        ledger
            .latest_fully_signed_bill
            .validate_fully_signed(binding)?;
    }
    for (operation_id, progression) in &state.hvm_registry_progressions {
        if progression.request.operation_id != *operation_id
            || state.hvm_bill_progressions.contains_key(operation_id)
        {
            return Err(HubError::State(
                "registry progression operation identity is inconsistent".into(),
            ));
        }
        let activation = state
            .hvm_registry_activations
            .get(&progression.request.binding_commitment)
            .ok_or_else(|| HubError::State("registry progression activation is missing".into()))?;
        let ledger = state
            .hvm_registry_ledgers
            .get(&progression.request.binding_commitment)
            .ok_or_else(|| HubError::State("registry progression ledger is missing".into()))?;
        validate_registry_progression(progression, &activation.recovery_bundle.binding, ledger)?;
    }
    for progression in state
        .hvm_registry_progressions
        .values()
        .filter(|progression| progression.status.is_unresolved())
    {
        let count = state
            .hvm_registry_progressions
            .values()
            .filter(|other| {
                other.status.is_unresolved()
                    && other.request.binding_commitment == progression.request.binding_commitment
            })
            .count();
        if count != 1 {
            return Err(HubError::State(
                "registry channel has more than one unresolved progression".into(),
            ));
        }
    }
    for progression in state.hvm_registry_progressions.values() {
        let duplicate_idempotency = state
            .hvm_registry_progressions
            .values()
            .filter(|other| {
                other.request.idempotency_key == progression.request.idempotency_key
                    && other.request.operation_id != progression.request.operation_id
            })
            .count();
        let conflicts_with_v1 = state
            .hvm_bill_progressions
            .values()
            .any(|other| other.request.idempotency_key == progression.request.idempotency_key);
        if duplicate_idempotency != 0 || conflicts_with_v1 {
            return Err(HubError::State(
                "HVM payment idempotency key is not globally unique".into(),
            ));
        }
    }
    validate_hvm_registry_chain_operations_v2(state)?;
    Ok(())
}

/// A block anchor is exactly 64 lower-case hex characters. Anything else is
/// not something a later observation could be compared against.
pub(crate) fn is_canonical_block_anchor(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_hvm_registry_chain_operations_v2(state: &HubPersistedState) -> HubResult<()> {
    use crate::hvm_registry_watchtower::{
        registry_challenge_call_source, registry_claim_payout_source,
        registry_finalize_call_source, registry_renew_all_call_source,
        registry_respond_call_source,
    };

    for (operation_id, operation) in &state.hvm_registry_chain_operations {
        let activation = state
            .hvm_registry_activations
            .get(&operation.binding_commitment)
            .ok_or_else(|| HubError::State("registry chain operation has no activation".into()))?;
        let binding = &activation.recovery_bundle.binding;
        if operation.operation_id != *operation_id
            || operation.operation_id.trim().is_empty()
            || operation.idempotency_key.trim().is_empty()
            || operation.request_commitment.len() != 64
            || operation.pre_observed_height == 0
            || !matches!(operation.pre_status, 2..=4)
            || operation.network_fee_zhu == 0
            || operation.gas_max == 0
            || operation.transaction_timestamp == 0
            || operation.call_source_commitment.len() != 64
            || operation.call_source.trim().is_empty()
            || hex::encode(Sha256::digest(operation.call_source.as_bytes()))
                != operation.call_source_commitment
        {
            return Err(HubError::State(
                "persisted registry chain operation identity is inconsistent".into(),
            ));
        }
        let expected_source = match operation.kind {
            HvmChainOperationKind::Challenge => {
                let bill = operation.bill.as_ref().ok_or_else(|| {
                    HubError::State("registry challenge lost its exact bill".into())
                })?;
                bill.validate_fully_signed(binding)?;
                registry_challenge_call_source(binding, bill)?
            }
            HvmChainOperationKind::Respond => {
                let bill = operation.bill.as_ref().ok_or_else(|| {
                    HubError::State("registry response lost its exact bill".into())
                })?;
                bill.validate_fully_signed(binding)?;
                registry_respond_call_source(binding, bill)?
            }
            HvmChainOperationKind::Finalize => {
                if operation.bill.is_some() || operation.lease_periods.is_some() {
                    return Err(HubError::State(
                        "registry finalize contains unrelated bill or lease state".into(),
                    ));
                }
                registry_finalize_call_source(binding)?
            }
            HvmChainOperationKind::RenewAllLeases => {
                if operation.bill.is_some() {
                    return Err(HubError::State(
                        "registry renewal contains unrelated bill state".into(),
                    ));
                }
                let periods = operation.lease_periods.ok_or_else(|| {
                    HubError::State("registry renewal lost its exact period count".into())
                })?;
                registry_renew_all_call_source(binding, periods)?
            }
            HvmChainOperationKind::Claim => {
                if operation.bill.is_some() || operation.lease_periods.is_some() {
                    return Err(HubError::State(
                        "registry claim contains unrelated bill or lease state".into(),
                    ));
                }
                let payee = operation
                    .claim_payee
                    .as_deref()
                    .ok_or_else(|| HubError::State("registry claim lost its exact payee".into()))?;
                let amount_zhu = operation.claim_amount_zhu.ok_or_else(|| {
                    HubError::State("registry claim lost its exact payout amount".into())
                })?;
                registry_claim_payout_source(binding, payee, amount_zhu)?
            }
        };
        if expected_source != operation.call_source {
            return Err(HubError::State(
                "persisted registry chain call source is not canonical".into(),
            ));
        }
        if operation.kind != HvmChainOperationKind::RenewAllLeases
            && operation.lease_periods.is_some()
        {
            return Err(HubError::State(
                "non-renewal registry operation contains lease state".into(),
            ));
        }
        if operation.kind != HvmChainOperationKind::Claim
            && (operation.claim_payee.is_some()
                || operation.claim_amount_zhu.is_some()
                || operation.claim_settled_elsewhere_height.is_some())
        {
            return Err(HubError::State(
                "non-claim registry operation contains payout state".into(),
            ));
        }
        // A permissionless third party may pay the payee before us. When that
        // is observed the operation resolves with the contract's own
        // `c_left_claimed_` flag as its evidence; it never owns a block of its
        // own, so it must not pretend to.
        let settled_elsewhere = operation.claim_settled_elsewhere_height;
        if let Some(height) = settled_elsewhere
            && (operation.kind != HvmChainOperationKind::Claim
                || height == 0
                || operation.status != HvmChainOperationStatus::Confirmed
                || operation.confirmed_block_height.is_some()
                || operation.confirmed_block_hash.is_some()
                || operation.observed_confirmations != 0)
        {
            return Err(HubError::State(
                "registry claim settled elsewhere carries inconsistent evidence".into(),
            ));
        }
        // A claim resolved before it was ever signed genuinely has no bytes.
        // One that was signed first still has to keep them exactly.
        let settled_elsewhere_before_signing = settled_elsewhere.is_some()
            && operation.signed_transaction_hex.is_none()
            && operation.transaction_hash.is_none()
            && operation.submitted_unix.is_none();
        let signed_required = !matches!(
            operation.status,
            HvmChainOperationStatus::IntentPersisted | HvmChainOperationStatus::SignatureMayExist
        ) && !settled_elsewhere_before_signing;
        if signed_required
            && (operation
                .signed_transaction_hex
                .as_deref()
                .is_none_or(str::is_empty)
                || operation
                    .transaction_hash
                    .as_deref()
                    .is_none_or(str::is_empty))
        {
            return Err(HubError::State(
                "persisted registry chain operation lost its exact signed transaction".into(),
            ));
        }
        if operation.status == HvmChainOperationStatus::Confirmed
            && settled_elsewhere.is_none()
            && (operation.confirmed_block_height.is_none() || operation.observed_confirmations < 6)
        {
            return Err(HubError::State(
                "confirmed registry chain operation lacks finality evidence".into(),
            ));
        }
        if let Some(anchor) = operation.confirmed_block_hash.as_deref()
            && (operation.confirmed_block_height.is_none() || !is_canonical_block_anchor(anchor))
        {
            return Err(HubError::State(
                "registry chain operation has a malformed block anchor".into(),
            ));
        }
        validate_registry_chain_abandonment(operation)?;
        let idempotency_count = state
            .hvm_registry_chain_operations
            .values()
            .filter(|other| other.idempotency_key == operation.idempotency_key)
            .count();
        let conflicts_with_v1 = state
            .hvm_chain_operations
            .values()
            .any(|other| other.idempotency_key == operation.idempotency_key);
        if idempotency_count != 1 || conflicts_with_v1 {
            return Err(HubError::State(
                "HVM chain idempotency key is not globally unique".into(),
            ));
        }
        // An operation whose fate is still open keeps the channel to itself.
        // `Abandoned` counts as resolved for exactly the same reason
        // `Confirmed` does: there is no transaction left that could still
        // land, so a replacement is not a second live transaction.
        if !operation.status.is_resolved() {
            let unresolved = state
                .hvm_registry_chain_operations
                .values()
                .filter(|other| {
                    other.binding_commitment == operation.binding_commitment
                        && !other.status.is_resolved()
                })
                .count();
            if unresolved != 1 {
                return Err(HubError::State(
                    "registry channel has more than one unresolved chain operation".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Re-check an abandonment from the record alone, on every load.
///
/// The transition is only ever taken behind
/// [`crate::inadmissible::prove_transaction_inadmissible`] and a final chain
/// read. This is the second line: a state file that arrives with an
/// abandonment whose own numbers do not prove inadmissibility — a hand-edited
/// one, a restored one, one naming a rule that no longer exists — is refused
/// rather than trusted. There is no arm here that accepts an abandonment
/// without arithmetic behind it.
fn validate_registry_chain_abandonment(
    operation: &PersistedHvmRegistryChainOperation,
) -> HubResult<()> {
    let abandoned = match (&operation.abandoned, &operation.status) {
        (Some(abandoned), HvmChainOperationStatus::Abandoned) => abandoned,
        (None, HvmChainOperationStatus::Abandoned) => {
            return Err(HubError::State(
                "abandoned registry chain operation carries no inadmissibility proof".into(),
            ));
        }
        (Some(_), _) => {
            return Err(HubError::State(
                "registry chain operation carries an abandonment it is not in".into(),
            ));
        }
        (None, _) => return Ok(()),
    };
    // An abandoned operation keeps the exact bytes the proof is about — they
    // are the evidence — and owns no block, because it was never in one.
    if operation
        .signed_transaction_hex
        .as_deref()
        .is_none_or(str::is_empty)
        || operation
            .transaction_hash
            .as_deref()
            .is_none_or(str::is_empty)
        || operation.confirmed_block_height.is_some()
        || operation.confirmed_block_hash.is_some()
        || operation.observed_confirmations != 0
        || operation.claim_settled_elsewhere_height.is_some()
    {
        return Err(HubError::State(
            "abandoned registry chain operation carries inconsistent evidence".into(),
        ));
    }
    if abandoned.detail.trim().is_empty()
        || abandoned.chain_tip_timestamp_unix == 0
        || abandoned.observed_unix == 0
        || abandoned.proof_height == 0
        || abandoned.absent_at_height == 0
        || abandoned.abandoned_unix == 0
    {
        return Err(HubError::State(
            "abandoned registry chain operation has an incomplete proof".into(),
        ));
    }
    // The proof is about the transaction this record actually signed.
    if abandoned.transaction_timestamp != operation.transaction_timestamp {
        return Err(HubError::State(
            "abandonment proof is about a different transaction timestamp".into(),
        ));
    }
    let Some(rule) = crate::inadmissible::InadmissibilityRule::from_name(&abandoned.rule) else {
        return Err(HubError::State(
            "abandoned registry chain operation names an unknown consensus rule".into(),
        ));
    };
    match rule {
        crate::inadmissible::InadmissibilityRule::FutureTimestamp => {
            let ceiling = abandoned
                .chain_tip_timestamp_unix
                .max(abandoned.observed_unix)
                .saturating_add(crate::inadmissible::INADMISSIBILITY_CLOCK_MARGIN_SECONDS);
            if abandoned.transaction_timestamp <= ceiling {
                return Err(HubError::State(
                    "abandonment proof does not put the transaction timestamp past the chain clock"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn backup_legacy_state(path: &Path) -> HubResult<()> {
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

fn default_channel_reuse_version() -> u64 {
    1
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
    let json =
        serde_json::to_vec_pretty(state).map_err(|error| HubError::State(error.to_string()))?;
    save_bytes_atomic(path, &json)
}

pub(crate) fn save_bytes_atomic(path: &Path, bytes: &[u8]) -> HubResult<()> {
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
        file.write_all(bytes)
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

pub(crate) fn ensure_not_symlink(path: &Path, label: &str) -> HubResult<()> {
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

    #[test]
    fn additive_registry_maps_preserve_legacy_state_and_commitment() {
        let baseline = HubPersistedState::default();
        let baseline_commitment = state_commitment(&baseline).unwrap();
        let encoded = serde_json::to_value(&baseline).unwrap();
        assert!(encoded.get("hvm_registry_activations").is_none());
        assert!(encoded.get("hvm_registry_ledgers").is_none());
        assert!(encoded.get("hvm_registry_progressions").is_none());
        assert!(encoded.get("hvm_registry_chain_operations").is_none());

        let legacy: HubPersistedState =
            serde_json::from_str(r#"{"channels":{},"payments":{}}"#).unwrap();
        assert!(legacy.hvm_registry_activations.is_empty());
        assert!(legacy.hvm_registry_ledgers.is_empty());
        assert!(legacy.hvm_registry_progressions.is_empty());
        assert!(legacy.hvm_registry_chain_operations.is_empty());
        assert_eq!(state_commitment(&legacy).unwrap(), baseline_commitment);
    }

    /// A registry chain operation carrying nothing but the fields the
    /// abandonment validator reads. Everything else is left at values the
    /// validator does not look at, so each test below fails for exactly the
    /// reason it names.
    fn abandonable() -> PersistedHvmRegistryChainOperation {
        PersistedHvmRegistryChainOperation {
            operation_id: "operation".into(),
            idempotency_key: "idempotency".into(),
            request_commitment: "aa".repeat(32),
            binding_commitment: "bb".repeat(32),
            kind: HvmChainOperationKind::Finalize,
            bill: None,
            lease_periods: None,
            claim_payee: None,
            claim_amount_zhu: None,
            claim_settled_elsewhere_height: None,
            pre_observed_height: 2_886,
            pre_status: 3,
            pre_serial: 2,
            pre_left_balance_zhu: 900_000_000,
            pre_hub_balance_zhu: 100_000_000,
            pre_deadline: 2_878,
            pre_minimum_live_blocks: 20_000,
            pre_minimum_recover_blocks: 30_000,
            network_fee_zhu: 10_000,
            gas_max: u8::MAX,
            transaction_timestamp: 1_791_527_729,
            call_source_commitment: "cc".repeat(32),
            call_source: "source".into(),
            signed_transaction_hex: Some("00".into()),
            transaction_hash: Some("dd".repeat(32)),
            status: HvmChainOperationStatus::Abandoned,
            submitted_unix: None,
            confirmed_block_height: None,
            confirmed_block_hash: None,
            observed_confirmations: 0,
            abandoned: Some(abandonment()),
            created_unix: 1_786_831_000,
            updated_unix: 1_786_831_000,
            last_error: Some("fullnode refused the transaction".into()),
        }
    }

    /// The live case: a finalize stamped 1791527729 against a ~1786831000
    /// chain clock.
    fn abandonment() -> PersistedHvmChainAbandonment {
        PersistedHvmChainAbandonment {
            rule: "future_timestamp".into(),
            detail: "transaction timestamp 1791527729 exceeds the chain clock ceiling".into(),
            transaction_timestamp: 1_791_527_729,
            chain_tip_timestamp_unix: 1_786_831_000,
            observed_unix: 1_786_831_000,
            proof_height: 2_886,
            absent_at_height: 2_886,
            abandoned_unix: 1_786_831_100,
        }
    }

    #[test]
    fn a_well_formed_abandonment_is_accepted() {
        validate_registry_chain_abandonment(&abandonable()).unwrap();
    }

    /// Every operation that is not abandoned must serialise exactly as it did
    /// before this field existed. Otherwise adding the transition would move
    /// the state commitment of every live Hub that never uses it, and an
    /// existing state file would stop matching its own authenticated head.
    #[test]
    fn the_abandonment_field_is_invisible_to_operations_without_one() {
        let mut ordinary = abandonable();
        ordinary.status = HvmChainOperationStatus::RecoveryRequired;
        ordinary.abandoned = None;
        let encoded = serde_json::to_value(&ordinary).unwrap();
        assert!(encoded.get("abandoned").is_none());

        // And a file written before the field existed still loads.
        let mut without_key = encoded.clone();
        without_key.as_object_mut().unwrap().remove("abandoned");
        let decoded: PersistedHvmRegistryChainOperation =
            serde_json::from_value(without_key).unwrap();
        assert_eq!(decoded, ordinary);

        // An abandoned one does carry it.
        let abandoned = serde_json::to_value(abandonable()).unwrap();
        assert!(abandoned.get("abandoned").is_some());
    }

    /// The whole point of re-checking on load: an abandonment is only worth
    /// what its own arithmetic proves. A state file that arrives claiming one
    /// without the numbers behind it is refused, not trusted.
    #[test]
    fn an_abandonment_whose_numbers_do_not_prove_it_is_refused_on_load() {
        // The timestamp is ahead of the tip, but not past the clock ceiling:
        // a node could still accept it, so this is no proof at all.
        let mut inside_margin = abandonable();
        let stamp = 1_786_831_000 + crate::inadmissible::INADMISSIBILITY_CLOCK_MARGIN_SECONDS;
        inside_margin.transaction_timestamp = stamp;
        inside_margin
            .abandoned
            .as_mut()
            .unwrap()
            .transaction_timestamp = stamp;
        assert!(validate_registry_chain_abandonment(&inside_margin).is_err());

        // One second past the ceiling is a proof.
        let mut past_ceiling = inside_margin.clone();
        past_ceiling.transaction_timestamp = stamp + 1;
        past_ceiling
            .abandoned
            .as_mut()
            .unwrap()
            .transaction_timestamp = stamp + 1;
        validate_registry_chain_abandonment(&past_ceiling).unwrap();

        // A proof about some other transaction's timestamp is not a proof
        // about this record's transaction.
        let mut mismatched = abandonable();
        mismatched.abandoned.as_mut().unwrap().transaction_timestamp = 1_791_527_728;
        assert!(validate_registry_chain_abandonment(&mismatched).is_err());
    }

    /// There is no rule named "operator override", and a record inventing one
    /// cannot be read back as a proof.
    #[test]
    fn an_abandonment_naming_an_unknown_rule_is_refused() {
        for rule in ["operator_override", "force", "", "future_timestamp "] {
            let mut operation = abandonable();
            operation.abandoned.as_mut().unwrap().rule = rule.into();
            assert!(
                validate_registry_chain_abandonment(&operation).is_err(),
                "rule {rule:?} must not be readable as a proof"
            );
        }
    }

    #[test]
    fn the_abandoned_status_and_its_proof_must_agree() {
        // Abandoned without a proof.
        let mut bare = abandonable();
        bare.abandoned = None;
        assert!(validate_registry_chain_abandonment(&bare).is_err());

        // A proof attached to a record that is not abandoned.
        for status in [
            HvmChainOperationStatus::RecoveryRequired,
            HvmChainOperationStatus::Confirmed,
            HvmChainOperationStatus::Submitted,
        ] {
            let mut mislabelled = abandonable();
            mislabelled.status = status;
            assert!(validate_registry_chain_abandonment(&mislabelled).is_err());
        }

        // Neither: the ordinary case, untouched.
        let mut ordinary = abandonable();
        ordinary.status = HvmChainOperationStatus::RecoveryRequired;
        ordinary.abandoned = None;
        validate_registry_chain_abandonment(&ordinary).unwrap();
    }

    /// An abandoned operation was never in a block, so it must not carry the
    /// evidence of one, and it must keep the exact bytes its proof is about.
    #[test]
    fn an_abandoned_operation_owns_no_block_and_keeps_its_bytes() {
        let mut anchored = abandonable();
        anchored.confirmed_block_height = Some(2_887);
        assert!(validate_registry_chain_abandonment(&anchored).is_err());

        let mut confirmations = abandonable();
        confirmations.observed_confirmations = 6;
        assert!(validate_registry_chain_abandonment(&confirmations).is_err());

        let mut byteless = abandonable();
        byteless.signed_transaction_hex = None;
        assert!(validate_registry_chain_abandonment(&byteless).is_err());

        let mut hashless = abandonable();
        hashless.transaction_hash = Some(String::new());
        assert!(validate_registry_chain_abandonment(&hashless).is_err());
    }

    /// `Abandoned` and `Confirmed` are the two statuses that free the channel
    /// for a new operation. Everything else leaves a transaction whose fate is
    /// still open.
    #[test]
    fn only_confirmed_and_abandoned_resolve_an_operation() {
        assert!(HvmChainOperationStatus::Confirmed.is_resolved());
        assert!(HvmChainOperationStatus::Abandoned.is_resolved());
        for status in [
            HvmChainOperationStatus::IntentPersisted,
            HvmChainOperationStatus::SignatureMayExist,
            HvmChainOperationStatus::Signed,
            HvmChainOperationStatus::SubmissionStarted,
            HvmChainOperationStatus::Submitted,
            HvmChainOperationStatus::RecoveryRequired,
        ] {
            assert!(
                !status.is_resolved(),
                "{} must not resolve",
                status.as_str()
            );
        }
    }

    /// UPGRADING THE HUB BINARY MUST NOT BRICK A DURABLE STATE IT NEVER TOUCHED.
    ///
    /// `state_commitment` is a SHA over the serialized `HubPersistedState`, and
    /// `initialize_authenticated_state` refuses to start when it does not match
    /// the commitment the authenticated journal recorded. A field added to a
    /// persisted struct that always serializes therefore rewrites the hash of
    /// every state file already on disk, and the next start of the upgraded
    /// binary fails with `StateCommitmentMismatch` on a state nobody edited.
    /// On a Hub holding real channels that is not an inconvenience; it is the
    /// Hub refusing to come back.
    ///
    /// The key set below is what the binary before `broadcast_height` wrote.
    /// It is spelled out rather than derived so that the next field added
    /// without `skip_serializing_if` fails here, in a test that says why,
    /// instead of on an owner's machine after an upgrade.
    #[test]
    fn a_new_field_must_not_move_an_untouched_state_commitment() {
        const KEYS_THE_PREVIOUS_BINARY_WROTE: &[&str] = &[
            "block_1_hash",
            "chain_id",
            "channel_id",
            "confirmed_block_height",
            "created_unix",
            "expires_unix",
            "idempotency_key",
            "last_error",
            "mainnet",
            "network",
            "network_fee_zhu",
            "network_instance_id",
            "node_profile_id",
            "observed_confirmations",
            "operation_id",
            "partial_transaction_commitment",
            "partial_transaction_hex",
            "request_commitment",
            "reuse_version",
            "signed_transaction_commitment",
            "signed_transaction_hex",
            "status",
            "transaction_format_version",
            "transaction_hash",
            "updated_unix",
            "user_address",
            "user_deposit_zhu",
        ];

        // An operation as the owner's Hub holds it: broadcast, never mined, and
        // written before any height was recorded.
        let untouched = PersistedL1ChannelOpen {
            operation_id: "e2d8136b-201f-4a20-ba87-2fd2500cb270".into(),
            idempotency_key: "hpay:channel-open:3e6dfcee".into(),
            request_commitment: "7be664e9".into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: "001e231c".into(),
            node_profile_id: "hacash-mainnet".into(),
            network_instance_id: "5a310ec0".into(),
            transaction_format_version: 2,
            channel_id: "ec74cea2f8fc576fecbbac878cb46a6d".into(),
            reuse_version: 1,
            user_address: "1LCY6uQS3iNGy2mKSmhFVU2dHgBQLf74Fx".into(),
            user_deposit_zhu: 20_000_000,
            network_fee_zhu: 24_100,
            partial_transaction_hex: "00".into(),
            partial_transaction_commitment: "partial".into(),
            transaction_hash: "hash".into(),
            signed_transaction_hex: Some("0011".into()),
            signed_transaction_commitment: Some("signed".into()),
            confirmed_block_height: None,
            broadcast_height: None,
            observed_confirmations: 0,
            status: L1ChannelOpenStatus::Submitted,
            created_unix: 1_787_662_846,
            expires_unix: 1_787_663_146,
            updated_unix: 1_787_662_846,
            last_error: None,
        };

        let serialized = serde_json::to_value(&untouched).unwrap();
        let keys: Vec<String> = serialized.as_object().unwrap().keys().cloned().collect();
        let expected: Vec<String> = KEYS_THE_PREVIOUS_BINARY_WROTE
            .iter()
            .map(|key| (*key).to_owned())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            sorted, expected,
            "the serialized shape of an untouched channel-open changed, which moves its              state commitment and stops an upgraded Hub from starting. A new field must              carry #[serde(default, skip_serializing_if = \"Option::is_none\")]"
        );
        assert!(
            !keys.iter().any(|key| key == "broadcast_height"),
            "broadcast_height must be absent until something records one"
        );

        // And once a height is recorded it does appear, through the normal
        // committed transition that recomputes both sides of the commitment.
        let mut broadcast = untouched.clone();
        broadcast.broadcast_height = Some(777_754);
        let serialized = serde_json::to_value(&broadcast).unwrap();
        assert_eq!(
            serialized.get("broadcast_height"),
            Some(&serde_json::json!(777_754))
        );
    }
}
