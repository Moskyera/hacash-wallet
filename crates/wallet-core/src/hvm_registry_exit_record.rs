//! The durable per-step record of a user-side HVM registry exit.
//!
//! # What was missing
//!
//! [`crate::hvm_registry_exit`] decides and builds; it performs no I/O and it
//! remembers nothing. Nothing else remembered either: before this module,
//! `PersistedHvmRegistryExit`, `exit_operation` and `ExitStep` matched no
//! symbol anywhere under `crates/agent-wallet-core` or
//! `crates/wallet-core/src/l2_safety.rs`. An exit therefore lived entirely in
//! one process's memory.
//!
//! That is not an edge case on this rail. The arbitration window is measured
//! in blocks — `binding.challenge_blocks` plus
//! `HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS` plus
//! [`crate::hvm_registry_exit::HVM_REGISTRY_EXIT_LEASE_SLACK_BLOCKS`], which
//! at the 300s Hacash block target is hours — so a laptop lid closing between
//! `challenge` and `finalize` is the ordinary case. Reopened with no memory,
//! the driver would re-plan the same step, re-sign it at whatever timestamp it
//! now holds, and put a **second** transaction on the wire for a step that may
//! already be mined. `crates/wallet-core/tests/adversarial_user_side_exit.rs`
//! ATTACK 4 measures exactly that: the same plan signed sixty seconds apart is
//! two different transaction hashes.
//!
//! # The shape, and why it is the Hub's shape
//!
//! The Hub already solved this for itself:
//! `PersistedHvmRegistryChainOperation` in
//! `crates/l2-fast-pay-hub/src/storage.rs`, whose stored call source is
//! re-derived by `validate_hvm_registry_chain_operations_v2` on every load,
//! before anything is signed. This is the wallet's peer of that record, held
//! in the wallet's own authenticated store rather than the Hub's.
//!
//! A record is **never trusted for its own contents**. Every read runs
//! [`validate_persisted_exit_step`], which re-derives the call source from the
//! binding and the wallet's own head bill using the very functions that built
//! it — [`registry_challenge_call_source`] and its siblings, imported from the
//! Hub crate, not re-implemented. A record whose stored source does not equal
//! the freshly derived one is refused. A durable record that vouches for
//! itself is evidence of nothing.
//!
//! # What the record carries and why each field is load bearing
//!
//! * `call_source` and `call_source_commitment` — the exact bytes the step
//!   means, and a commitment over them, so tampering is caught even before the
//!   re-derivation.
//! * `signed_transaction_hex` and `transaction_hash` — a step that may already
//!   be mined must never be re-signed at a different timestamp. Resume
//!   re-submits *these bytes*; it does not build new ones.
//! * `transaction_timestamp`, `network_fee_zhu`, `gas_max` — the complete set
//!   of non-deterministic inputs to the builder. `libsecp256k1::sign` is
//!   RFC 6979 deterministic (`sys/src/account.rs:153`), so re-signing with
//!   these stored values reproduces the identical transaction, which is what
//!   makes the [`HvmRegistryExitResumeV1::ResignExact`] arm safe.
//! * `pre_observed_height`, `pre_status`, `pre_serial`, `pre_left_balance_zhu`,
//!   `pre_deadline`, `pre_snapshot_commitment` — the chain as it was read
//!   immediately before signing. Without it a record cannot say what question
//!   it was the answer to.
//! * `phase` — where this step actually stands, and the only thing that
//!   decides whether the key may be used again.

use l2_fast_pay_hub::hvm_registry::{HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS, HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
    registry_challenge_call_source, registry_claim_payout_source, registry_finalize_call_source,
    registry_renew_channel_call_source, registry_renew_registry_call_source,
    registry_respond_call_source,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};
use crate::hvm_registry_exit::{HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep};

/// Schema string on every persisted exit step. Present so a record written by
/// a future shape cannot be read as this one.
pub const HVM_REGISTRY_EXIT_RECORD_SCHEMA: &str = "hpay.registry.exit.step.v1";

/// Stable marker on every refusal that means "this durable record does not
/// re-derive". Callers above wallet-core match on this to route the failure,
/// exactly as they already match on
/// [`crate::l2_safety::ANCHOR_WITNESS_DECISION_REQUIRED`]. It is a
/// classification token and is never shown to a person: the surfaces above
/// translate it into their own words.
pub const REFUSAL_EXIT_RECORD_INVALID: &str = "hvm_registry_exit_record_invalid";

/// Stable marker meaning "this step's own phase forbids what you asked", which
/// includes the one that matters most: a step whose bytes may already be on
/// chain being asked to sign again.
pub const REFUSAL_EXIT_STEP_BLOCKED: &str = "hvm_registry_exit_step_blocked";

/// Where one exit step stands.
///
/// The order is the only order this store permits, and every advance is
/// checked against it in [`crate::l2_safety`]. The split between
/// `SignatureMayExist` and `Signed` is deliberate and is the same split the
/// Fast Pay path already makes between `persist_before_signing` and
/// `persist_signature`: the possibility of a signature is made durable
/// **before** the key is used, so a crash inside the signer is a state this
/// store can name rather than a gap it cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryExitPhase {
    /// The call source and its commitment are durable. Nothing is signed.
    IntentPersisted,
    /// The signer was about to be used. Bytes may or may not exist, and if
    /// they do this store does not hold them yet.
    SignatureMayExist,
    /// The exact bytes and their transaction hash are durable. Not yet handed
    /// to a node by us — though nothing stops a node from having them.
    Signed,
    /// Handed to a node. Whether it will be mined is unknown.
    Submitted,
    /// Observed on chain at a known height.
    Confirmed,
    /// The step's effect was found already done on chain without a
    /// transaction of ours being the cause. `finalize` and the Action 14 claim
    /// are permissionless, so a third party settling first is ordinary and is
    /// not an error.
    SettledElsewhere,
}

impl HvmRegistryExitPhase {
    /// Nothing further will ever be signed for this step under this attempt.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::SettledElsewhere)
    }

    /// Bytes for this step may be on somebody's wire right now.
    pub fn may_have_bytes_in_flight(self) -> bool {
        matches!(
            self,
            Self::SignatureMayExist | Self::Signed | Self::Submitted
        )
    }
}

/// Anchor for [`deterministic_exit_transaction_timestamp`]. A fixed instant in
/// the past, so every derived timestamp is one the chain will accept forever:
/// the only rule a Hacash node applies to a transaction timestamp is
/// `tx.timestamp <= now` (`hacash-fullnodedev/chain/src/check.rs:99` and
/// `chain/src/verify.rs:74`). There is no lower bound and no expiry.
pub const HVM_REGISTRY_EXIT_TIMESTAMP_EPOCH: u64 = 1_700_000_000;

/// Width of the derived-timestamp window, in seconds. Purely cosmetic — it
/// spreads derived timestamps over about twelve days so two channels do not
/// share a suspiciously identical one — and it is bounded so the anchor above
/// stays comfortably in the past.
pub const HVM_REGISTRY_EXIT_TIMESTAMP_SPREAD: u64 = 1 << 20;

/// The transaction timestamp for one attempt at one step of one exit, derived
/// rather than read off a clock.
///
/// # Why an exit does not use the wall clock
///
/// A wallet's own bytes are its worst enemy here. `libsecp256k1::sign` is RFC
/// 6979 deterministic (`sys/src/account.rs:153`), so two runs of the builder
/// with identical inputs produce the identical transaction — and the only
/// input that is not already fixed by the binding, the bill and the chain is
/// the timestamp. Take it from the clock and every re-plan is a *second*
/// transaction for the same step; derive it, and a wallet cannot produce two
/// even if it forgets everything it ever knew.
///
/// The durable record makes the terms sticky once a step is opened, which
/// covers the ordinary crash. This covers the case the record cannot: a store
/// restored from a snapshot taken *before* the step was opened — a VM
/// rollback, a restore point, a folder-sync client winning a race. There the
/// wallet re-plans with no memory at all, and with a derived timestamp it
/// re-plans into the byte-identical transaction it already signed, which the
/// chain deduplicates by hash instead of mining twice.
///
/// `attempt` is a term because the one legitimate second transaction — a lease
/// renewal replacing a stuck one at a higher fee — must be a different
/// transaction on purpose.
pub fn deterministic_exit_transaction_timestamp(
    binding_commitment: &str,
    step: HvmRegistryExitStep,
    attempt: u32,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"hpay-hvm-registry-exit-timestamp/1");
    hasher.update((binding_commitment.len() as u64).to_be_bytes());
    hasher.update(binding_commitment.as_bytes());
    hasher.update((step.slug().len() as u64).to_be_bytes());
    hasher.update(step.slug().as_bytes());
    hasher.update(attempt.to_be_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    HVM_REGISTRY_EXIT_TIMESTAMP_EPOCH
        + (u64::from_be_bytes(head) % HVM_REGISTRY_EXIT_TIMESTAMP_SPREAD)
}

/// The exact step a caller proposes to take, derived from a plan and the
/// snapshot that plan was made from.
///
/// Built only by [`HvmRegistryExitIntentV1::from_plan`], so a caller cannot
/// pair a `Claim` step with a challenge's call source, or record a payout
/// amount the snapshot never showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvmRegistryExitIntentV1 {
    pub binding_commitment: String,
    pub step: HvmRegistryExitStep,
    pub call_source: String,
    pub bill_serial: Option<u64>,
    pub claim_payee: Option<String>,
    pub claim_amount_zhu: Option<u64>,
    pub lease_periods: Option<u64>,
    pub pre_observed_height: u64,
    pub pre_status: u8,
    pub pre_serial: u64,
    pub pre_left_balance_zhu: u64,
    pub pre_deadline: u64,
    pub pre_snapshot_commitment: String,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub transaction_timestamp: u64,
}

impl HvmRegistryExitIntentV1 {
    /// Turn a plan and the snapshot it was decided from into the exact intent
    /// that will be made durable.
    ///
    /// The plan's own call source is **re-derived and compared here too**, not
    /// merely copied. A plan travels from `plan_user_exit_step` to this
    /// function through caller code, and the whole point of the record is that
    /// nothing between the derivation and the signature is taken on trust.
    pub fn from_plan(
        kit: &HvmRegistryExitKitV1,
        plan: &HvmRegistryExitPlanV1,
        snapshot: &HvmRegistryLiveSnapshotV2,
        network_fee_zhu: u64,
        transaction_timestamp: u64,
        gas_max: u8,
    ) -> WalletResult<Self> {
        kit.validate_crypto().map_err(hub_error)?;
        if network_fee_zhu == 0 || gas_max == 0 || transaction_timestamp == 0 {
            return Err(WalletError::L2(
                "a durable exit step needs its exact fee, gas ceiling and timestamp".into(),
            ));
        }
        if snapshot.observed_height == 0 {
            return Err(WalletError::L2(
                "a durable exit step needs the height its snapshot was read at".into(),
            ));
        }
        let binding = &kit.binding;
        let binding_commitment = binding.commitment().map_err(hub_error)?;
        let (step, call_source, bill_serial, claim_payee, claim_amount_zhu, lease_periods) =
            match plan {
                HvmRegistryExitPlanV1::Wait { reason } => {
                    return Err(WalletError::L2(format!(
                        "there is no exit step to record right now: {reason}"
                    )));
                }
                HvmRegistryExitPlanV1::Call { step, call_source } => match step {
                    HvmRegistryExitStep::Challenge | HvmRegistryExitStep::Respond => (
                        *step,
                        call_source.clone(),
                        Some(kit.latest_bill.serial),
                        None,
                        None,
                        None,
                    ),
                    HvmRegistryExitStep::Finalize => {
                        (*step, call_source.clone(), None, None, None, None)
                    }
                    HvmRegistryExitStep::RenewChannelLease => (
                        *step,
                        call_source.clone(),
                        None,
                        None,
                        None,
                        Some(HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS),
                    ),
                    HvmRegistryExitStep::RenewRegistryLease => (
                        *step,
                        call_source.clone(),
                        None,
                        None,
                        None,
                        Some(HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS),
                    ),
                    HvmRegistryExitStep::Claim => {
                        return Err(WalletError::L2(
                            "the registry claim is an Action 14 payout, not a contract call".into(),
                        ));
                    }
                },
                HvmRegistryExitPlanV1::Claim {
                    payee,
                    amount_zhu,
                    call_source,
                } => (
                    HvmRegistryExitStep::Claim,
                    call_source.clone(),
                    None,
                    Some(payee.clone()),
                    Some(*amount_zhu),
                    None,
                ),
            };
        let intent = Self {
            binding_commitment,
            step,
            call_source,
            bill_serial,
            claim_payee,
            claim_amount_zhu,
            lease_periods,
            pre_observed_height: snapshot.observed_height,
            pre_status: snapshot.channel.status.value,
            pre_serial: snapshot.channel.serial.value,
            pre_left_balance_zhu: snapshot.channel.left_balance.value,
            pre_deadline: snapshot.channel.deadline.value,
            pre_snapshot_commitment: snapshot.commitment().map_err(hub_error)?,
            network_fee_zhu,
            gas_max,
            transaction_timestamp,
        };
        // Derive the canonical source for what we just classified and compare.
        // The plan is an input like any other.
        let expected = canonical_call_source(
            binding,
            kit,
            intent.step,
            intent.claim_payee.as_deref(),
            intent.claim_amount_zhu,
            intent.lease_periods,
        )?;
        if expected != intent.call_source {
            return Err(WalletError::L2(
                "exit plan call source is not the canonical call for its step".into(),
            ));
        }
        Ok(intent)
    }

    /// The store key. One record per `(binding_commitment, step)`, exactly as
    /// the Hub keeps one operation per `(binding_commitment, kind)`.
    pub fn record_key(&self) -> String {
        exit_record_key(&self.binding_commitment, self.step)
    }
}

/// One durable exit step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedHvmRegistryExitStepV1 {
    pub schema: String,
    pub binding_commitment: String,
    pub step: HvmRegistryExitStep,
    /// Which attempt at this step this record is. Only the two lease renewals
    /// can ever exceed 1, and only from a terminal previous attempt; see
    /// [`crate::l2_safety::ClientL2Safety::begin_or_resume_exit_step`].
    pub attempt: u32,
    pub call_source: String,
    pub call_source_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bill_serial: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_amount_zhu: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_periods: Option<u64>,
    pub pre_observed_height: u64,
    pub pre_status: u8,
    pub pre_serial: u64,
    pub pre_left_balance_zhu: u64,
    pub pre_deadline: u64,
    pub pre_snapshot_commitment: String,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub transaction_timestamp: u64,
    pub phase: HvmRegistryExitPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_transaction_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_block_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_block_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_elsewhere_height: Option<u64>,
    /// Transaction hashes of earlier terminal attempts at this step. Nothing
    /// is ever erased; a superseded attempt is remembered, because "did we
    /// already put something on the wire for this" must stay answerable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_transaction_hashes: Vec<String>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

impl PersistedHvmRegistryExitStepV1 {
    pub fn record_key(&self) -> String {
        exit_record_key(&self.binding_commitment, self.step)
    }

    /// Build the first attempt at a step from a validated intent.
    pub fn open(intent: &HvmRegistryExitIntentV1, now: u64) -> Self {
        Self {
            schema: HVM_REGISTRY_EXIT_RECORD_SCHEMA.into(),
            binding_commitment: intent.binding_commitment.clone(),
            step: intent.step,
            attempt: 1,
            call_source_commitment: call_source_commitment(&intent.call_source),
            call_source: intent.call_source.clone(),
            bill_serial: intent.bill_serial,
            claim_payee: intent.claim_payee.clone(),
            claim_amount_zhu: intent.claim_amount_zhu,
            lease_periods: intent.lease_periods,
            pre_observed_height: intent.pre_observed_height,
            pre_status: intent.pre_status,
            pre_serial: intent.pre_serial,
            pre_left_balance_zhu: intent.pre_left_balance_zhu,
            pre_deadline: intent.pre_deadline,
            pre_snapshot_commitment: intent.pre_snapshot_commitment.clone(),
            network_fee_zhu: intent.network_fee_zhu,
            gas_max: intent.gas_max,
            transaction_timestamp: intent.transaction_timestamp,
            phase: HvmRegistryExitPhase::IntentPersisted,
            signed_transaction_hex: None,
            transaction_hash: None,
            submitted_unix: None,
            confirmed_block_height: None,
            confirmed_block_hash: None,
            settled_elsewhere_height: None,
            previous_transaction_hashes: Vec::new(),
            created_unix: now,
            updated_unix: now,
        }
    }

    /// Open a further attempt at a step whose previous attempt is terminal,
    /// carrying that attempt's transaction hash forward rather than dropping
    /// it.
    pub fn supersede(&self, intent: &HvmRegistryExitIntentV1, now: u64) -> Self {
        let mut next = Self::open(intent, now);
        next.attempt = self.attempt.saturating_add(1);
        next.created_unix = self.created_unix;
        next.previous_transaction_hashes = self.previous_transaction_hashes.clone();
        if let Some(hash) = self.transaction_hash.as_ref() {
            next.previous_transaction_hashes.push(hash.clone());
        }
        next
    }
}

/// What reopening the wallet should do about a step, decided by the record
/// rather than by the caller.
///
/// This is the half of the problem that matters. A write path that forgets to
/// write costs one lost step; a resume path that guesses wrong signs a second
/// transaction for a step already mined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvmRegistryExitResumeV1 {
    /// Nothing has ever been signed for this step. Announce the signature with
    /// [`crate::l2_safety::ClientL2Safety::mark_exit_step_signature_may_exist`]
    /// and then sign.
    SignFresh {
        record: PersistedHvmRegistryExitStepV1,
    },
    /// The signer was entered and the process died before the bytes were made
    /// durable. Re-sign with the record's own `transaction_timestamp`,
    /// `network_fee_zhu` and `gas_max`: the signature scheme is deterministic,
    /// so the result is the same transaction, not a second one.
    ResignExact {
        record: PersistedHvmRegistryExitStepV1,
    },
    /// Exact bytes exist. **Do not sign.** Look this hash up on chain; submit
    /// these same bytes again only if it is absent.
    AwaitChain {
        record: PersistedHvmRegistryExitStepV1,
        transaction_hash: String,
        signed_transaction_hex: String,
    },
    /// Settled. Nothing to sign and nothing to submit.
    Done {
        record: PersistedHvmRegistryExitStepV1,
    },
}

impl HvmRegistryExitResumeV1 {
    pub fn record(&self) -> &PersistedHvmRegistryExitStepV1 {
        match self {
            Self::SignFresh { record }
            | Self::ResignExact { record }
            | Self::Done { record }
            | Self::AwaitChain { record, .. } => record,
        }
    }

    /// True exactly when the caller is permitted to use the signing key.
    pub fn may_sign(&self) -> bool {
        matches!(self, Self::SignFresh { .. } | Self::ResignExact { .. })
    }
}

/// Decide the resume action for a record that has already been validated.
pub fn resume_action(record: &PersistedHvmRegistryExitStepV1) -> HvmRegistryExitResumeV1 {
    match record.phase {
        HvmRegistryExitPhase::IntentPersisted => HvmRegistryExitResumeV1::SignFresh {
            record: record.clone(),
        },
        HvmRegistryExitPhase::SignatureMayExist => HvmRegistryExitResumeV1::ResignExact {
            record: record.clone(),
        },
        HvmRegistryExitPhase::Signed | HvmRegistryExitPhase::Submitted => {
            // `validate_persisted_exit_step` has already refused any record in
            // these phases without both halves, so the expects below cannot
            // fire on a record that came out of the store.
            match (
                record.transaction_hash.as_ref(),
                record.signed_transaction_hex.as_ref(),
            ) {
                (Some(hash), Some(hex)) => HvmRegistryExitResumeV1::AwaitChain {
                    record: record.clone(),
                    transaction_hash: hash.clone(),
                    signed_transaction_hex: hex.clone(),
                },
                // Unreachable through the store. Falling back to the strictest
                // arm rather than to a signing arm keeps an impossible state
                // from becoming a second transaction.
                _ => HvmRegistryExitResumeV1::Done {
                    record: record.clone(),
                },
            }
        }
        HvmRegistryExitPhase::Confirmed | HvmRegistryExitPhase::SettledElsewhere => {
            HvmRegistryExitResumeV1::Done {
                record: record.clone(),
            }
        }
    }
}

/// Re-derive everything a stored record claims, from the binding and the
/// wallet's own head bill.
///
/// This is the whole reason the record is worth anything. It is the wallet's
/// peer of `validate_hvm_registry_chain_operations_v2`
/// (`crates/l2-fast-pay-hub/src/storage.rs:1187`), and it runs on every read
/// and before every write, never once at load time only.
pub fn validate_persisted_exit_step(
    record: &PersistedHvmRegistryExitStepV1,
    kit: &HvmRegistryExitKitV1,
) -> WalletResult<()> {
    // Every refusal below is tagged with one marker in one place, so the
    // sentences stay readable and the classification above wallet-core stays
    // exact.
    re_derive_exit_step(record, kit).map_err(|error| match error {
        WalletError::L2(message) => {
            WalletError::L2(format!("{REFUSAL_EXIT_RECORD_INVALID}: {message}"))
        }
        other => other,
    })
}

fn re_derive_exit_step(
    record: &PersistedHvmRegistryExitStepV1,
    kit: &HvmRegistryExitKitV1,
) -> WalletResult<()> {
    kit.validate_crypto().map_err(hub_error)?;
    let binding = &kit.binding;
    if record.schema != HVM_REGISTRY_EXIT_RECORD_SCHEMA {
        return Err(WalletError::L2(
            "persisted exit step carries an unknown schema".into(),
        ));
    }
    let binding_commitment = binding.commitment().map_err(hub_error)?;
    if record.binding_commitment != binding_commitment {
        return Err(WalletError::L2(
            "persisted exit step belongs to a different channel binding".into(),
        ));
    }
    if record.attempt == 0
        || record.call_source.trim().is_empty()
        || record.call_source_commitment.len() != 64
        || record.pre_observed_height == 0
        || !matches!(record.pre_status, 2..=4)
        || record.pre_snapshot_commitment.len() != 64
        || record.network_fee_zhu == 0
        || record.gas_max == 0
        || record.transaction_timestamp == 0
        || record.created_unix == 0
        || record.updated_unix < record.created_unix
    {
        return Err(WalletError::L2(
            "persisted exit step identity is inconsistent".into(),
        ));
    }
    if call_source_commitment(&record.call_source) != record.call_source_commitment {
        return Err(WalletError::L2(
            "persisted exit step call source does not match its own commitment".into(),
        ));
    }

    // Per-step shape. Fields that belong to another step must be absent, so a
    // record cannot smuggle a payout amount into a finalize.
    let is_bill_step = matches!(
        record.step,
        HvmRegistryExitStep::Challenge | HvmRegistryExitStep::Respond
    );
    let is_renewal = matches!(
        record.step,
        HvmRegistryExitStep::RenewChannelLease | HvmRegistryExitStep::RenewRegistryLease
    );
    let is_claim = record.step == HvmRegistryExitStep::Claim;
    if is_bill_step {
        let serial = record.bill_serial.ok_or_else(|| {
            WalletError::L2("persisted exit step lost the serial of its own bill".into())
        })?;
        if serial != kit.latest_bill.serial {
            return Err(WalletError::L2(
                "persisted exit step was built from a different bill than this wallet now holds"
                    .into(),
            ));
        }
    } else if record.bill_serial.is_some() {
        return Err(WalletError::L2(
            "persisted exit step carries a bill serial its step has no use for".into(),
        ));
    }
    if is_renewal {
        if record.lease_periods.is_none_or(|periods| periods == 0) {
            return Err(WalletError::L2(
                "persisted lease renewal lost its exact period count".into(),
            ));
        }
    } else if record.lease_periods.is_some() {
        return Err(WalletError::L2(
            "non-renewal exit step carries lease state".into(),
        ));
    }
    if is_claim {
        let payee = record.claim_payee.as_deref().ok_or_else(|| {
            WalletError::L2("persisted registry claim lost its exact payee".into())
        })?;
        // `registry_claim_payout_source` refuses any payee that is not the
        // binding's left address, so the re-derivation below already enforces
        // this. Stated separately so the refusal names the actual problem.
        if payee != binding.left_address {
            return Err(WalletError::L2(
                "persisted registry claim is aimed at somebody other than this wallet".into(),
            ));
        }
        if record.claim_amount_zhu.is_none_or(|amount| amount == 0) {
            return Err(WalletError::L2(
                "persisted registry claim lost its exact payout amount".into(),
            ));
        }
        // The amount is the one field the re-derivation could not previously
        // check, because `canonical_call_source` is handed the record's own
        // number and compares it against a source built from that same number.
        // A record claiming half of u64 against a channel holding a million
        // zhu re-derived cleanly. Nothing could write one — but "nothing can
        // write it" is a property of the write path, and this function exists
        // precisely because the write path is not the only way bytes arrive.
        //
        // So the amount is pinned to a *chain* fact the record already
        // carries: the settled left balance read immediately before signing.
        // That is the same number the contract's `PermitHAC` hook demands, so
        // a record that disagrees with it describes a transaction that could
        // never execute anyway.
        if record.claim_amount_zhu != Some(record.pre_left_balance_zhu) {
            return Err(WalletError::L2(
                "persisted registry claim does not pay the settled balance its own snapshot read"
                    .into(),
            ));
        }
        // A payout exists only after `settle()`. A claim recorded against an
        // open or challenging channel is describing money the contract has not
        // yet credited.
        if record.pre_status != 4 {
            return Err(WalletError::L2(
                "persisted registry claim was recorded before this channel settled".into(),
            ));
        }
    } else if record.claim_payee.is_some() || record.claim_amount_zhu.is_some() {
        return Err(WalletError::L2(
            "non-claim exit step carries payout state".into(),
        ));
    }

    // The re-derivation itself.
    let expected = canonical_call_source(
        binding,
        kit,
        record.step,
        record.claim_payee.as_deref(),
        record.claim_amount_zhu,
        record.lease_periods,
    )?;
    if expected != record.call_source {
        return Err(WalletError::L2(
            "persisted exit step call source is not canonical for this binding".into(),
        ));
    }

    // Phase against evidence. A phase that claims more than the record holds
    // is the one failure that would let a resume sign twice.
    match record.phase {
        HvmRegistryExitPhase::IntentPersisted | HvmRegistryExitPhase::SignatureMayExist => {
            if record.signed_transaction_hex.is_some()
                || record.transaction_hash.is_some()
                || record.submitted_unix.is_some()
                || record.confirmed_block_height.is_some()
                || record.settled_elsewhere_height.is_some()
            {
                return Err(WalletError::L2(
                    "persisted exit step claims an unsigned phase while holding signed evidence"
                        .into(),
                ));
            }
        }
        HvmRegistryExitPhase::Signed | HvmRegistryExitPhase::Submitted => {
            if record
                .signed_transaction_hex
                .as_ref()
                .is_none_or(String::is_empty)
                || record
                    .transaction_hash
                    .as_ref()
                    .is_none_or(|hash| hash.len() != 64)
            {
                return Err(WalletError::L2(
                    "persisted exit step claims a signed phase without its exact bytes".into(),
                ));
            }
            if record.settled_elsewhere_height.is_some()
                || record.confirmed_block_height.is_some()
                || record.confirmed_block_hash.is_some()
            {
                return Err(WalletError::L2(
                    "persisted exit step claims a signed phase while holding chain evidence".into(),
                ));
            }
            if record.phase == HvmRegistryExitPhase::Submitted && record.submitted_unix.is_none() {
                return Err(WalletError::L2(
                    "persisted exit step claims submission without when".into(),
                ));
            }
        }
        HvmRegistryExitPhase::Confirmed => {
            if record
                .signed_transaction_hex
                .as_ref()
                .is_none_or(String::is_empty)
                || record
                    .transaction_hash
                    .as_ref()
                    .is_none_or(|hash| hash.len() != 64)
                || record
                    .confirmed_block_height
                    .is_none_or(|height| height == 0)
                || record
                    .confirmed_block_hash
                    .as_ref()
                    .is_none_or(|hash| hash.len() != 64)
                || record.settled_elsewhere_height.is_some()
            {
                return Err(WalletError::L2(
                    "persisted exit step claims confirmation without its anchor".into(),
                ));
            }
        }
        HvmRegistryExitPhase::SettledElsewhere => {
            // A step somebody else completed never owns a block of ours, so it
            // must not pretend to. Bytes may or may not exist: the step can be
            // observed done before we ever signed, or after we signed and lost
            // the race.
            if record
                .settled_elsewhere_height
                .is_none_or(|height| height == 0)
                || record.confirmed_block_height.is_some()
                || record.confirmed_block_hash.is_some()
            {
                return Err(WalletError::L2(
                    "persisted exit step settled elsewhere carries inconsistent evidence".into(),
                ));
            }
        }
    }
    Ok(())
}

/// The one place a step's canonical call source is derived, used by the write
/// path and the read path alike so the two cannot drift.
fn canonical_call_source(
    binding: &HvmRegistryBindingV2,
    kit: &HvmRegistryExitKitV1,
    step: HvmRegistryExitStep,
    claim_payee: Option<&str>,
    claim_amount_zhu: Option<u64>,
    lease_periods: Option<u64>,
) -> WalletResult<String> {
    match step {
        HvmRegistryExitStep::Challenge => {
            registry_challenge_call_source(binding, &kit.latest_bill).map_err(hub_error)
        }
        HvmRegistryExitStep::Respond => {
            registry_respond_call_source(binding, &kit.latest_bill).map_err(hub_error)
        }
        HvmRegistryExitStep::Finalize => registry_finalize_call_source(binding).map_err(hub_error),
        HvmRegistryExitStep::RenewChannelLease => {
            let periods = lease_periods.ok_or_else(|| {
                WalletError::L2("a channel lease renewal needs its exact period count".into())
            })?;
            registry_renew_channel_call_source(binding, periods).map_err(hub_error)
        }
        HvmRegistryExitStep::RenewRegistryLease => {
            let periods = lease_periods.ok_or_else(|| {
                WalletError::L2("a registry lease renewal needs its exact period count".into())
            })?;
            registry_renew_registry_call_source(binding, periods).map_err(hub_error)
        }
        HvmRegistryExitStep::Claim => {
            let payee = claim_payee
                .ok_or_else(|| WalletError::L2("a registry claim needs its exact payee".into()))?;
            let amount_zhu = claim_amount_zhu.ok_or_else(|| {
                WalletError::L2("a registry claim needs its exact payout amount".into())
            })?;
            registry_claim_payout_source(binding, payee, amount_zhu).map_err(hub_error)
        }
    }
}

/// The store key for one step of one channel incarnation.
pub fn exit_record_key(binding_commitment: &str, step: HvmRegistryExitStep) -> String {
    format!("{binding_commitment}:{}", step.slug())
}

fn call_source_commitment(call_source: &str) -> String {
    hex::encode(Sha256::digest(call_source.as_bytes()))
}

fn hub_error(error: l2_fast_pay_hub::error::HubError) -> WalletError {
    WalletError::L2(error.to_string())
}
