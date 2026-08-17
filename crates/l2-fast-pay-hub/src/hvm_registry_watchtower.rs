//! Pure watchtower decisions and exact Type 3 calls for the shared HVM
//! registry profile. The module contains no persistence or network I/O.

use basis::interface::{Transaction, TransactionRead};
use field::{
    AddrOrList, AddrOrPtr, Address, Amount, Field, Serialize as FieldSerialize, Uint1, Uint4,
};
use protocol::action::{ChainAllow, ChainIDList, HacFromToTrs};
use protocol::transaction::TransactionType3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;
use vm::ContractAddress;
use vm::action::ContractMainCall;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::parse_address;
use crate::hvm_registry::{
    HPAY_REGISTRY_MAX_RENT_STEP, HvmRegistryBillV2, HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2,
};
use crate::hvm_watchtower::HVM_LEASE_RENEWAL_MAX_PERIODS;

pub const HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA: &str = "hpay-hvm-registry-watchtower-request/2";
pub const HVM_REGISTRY_LEASE_REQUEST_SCHEMA: &str = "hpay-hvm-registry-lease-request/2";

/// Blocks of head-room the watchtower demands between the height it has
/// verified and the challenge deadline before it will build, sign and submit
/// a `respond`.
///
/// The contract sets `deadline = height_at_challenge + challenge_blocks`, its
/// `respond` requires `block_height() < deadline` **at execution**, and its
/// `finalize` becomes callable by anybody once `block_height() >= deadline`.
/// The bare rule `observed_height < deadline` therefore permits acting with
/// `deadline - observed_height == 1`: a bet that the transaction is mined in
/// the very next block, with nothing left over if it is not. Losing that bet
/// does not cost a fee, it costs the channel — a stale split gets finalised.
///
/// Three blocks, each one paying for a specific thing that happens between
/// the decision and the response being mined:
///
/// 1. **Tip lag.** `observed_height` is what the registry query chose to
///    return. It is cross-checked against the node's own tip
///    (`require_fresh_registry_evidence`), and that check tolerates
///    [`HVM_REGISTRY_MAX_SNAPSHOT_TIP_DRIFT_BLOCKS`] — so the height being
///    reasoned about may already be one block behind the chain.
/// 2. **The pipeline.** Between the decision and the submission the Hub makes
///    three bounded node round-trips (`NODE_REQUEST_TIMEOUT` is 10s each),
///    writes two durable journal records, and produces one signature. Up to
///    roughly 40s of wall clock, which can straddle a block boundary.
/// 3. **Inclusion.** A transaction handed to a node while a block is already
///    being assembled is first eligible for the block after it.
///
/// So the tower acts with 3, 4, … blocks left and refuses at 2, 1 and 0.
/// Against the reviewed `challenge_blocks = 12` binding that leaves 9 of the
/// 12 blocks usable and spends 3 on head-room. On a 300s Hacash block target
/// that head-room is 900s, which is 15 times the shortest tick interval
/// `HvmLeaseSchedulerConfig::validate` will accept (60s), so a challenge the
/// scheduler sees at all is seen with time to spare.
pub const HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS: u64 = 3;

/// How far the registry snapshot's `observed_height` may trail the node's own
/// reported chain tip before its evidence is refused.
///
/// The capabilities read and the registry read are two separate requests to
/// two separate endpoints, so exactly one block may legitimately land between
/// them. A wider gap means the two answers came from different views of the
/// chain, and the height the deadline is being measured against is not the
/// height the chain is actually at. Only the trailing direction is bounded:
/// a snapshot *ahead* of the tip read shortens the window this tower believes
/// it has, which is the safe direction.
pub const HVM_REGISTRY_MAX_SNAPSHOT_TIP_DRIFT_BLOCKS: u64 = 1;

/// The oldest chain tip the watchtower will act on, in seconds.
///
/// `FULLNODE_MAX_TIP_AGE_SECONDS` lets the generic node gate accept a tip an
/// hour old. That is fine for reading a balance and useless for a challenge
/// window measured in a handful of blocks: in an hour the real chain can be
/// far past the deadline while this node still reports the height it was
/// stuck at. 300s is one Hacash block target and five times the shortest
/// scheduler interval, so a node that is keeping up is never refused and a
/// node that has stopped moving always is.
pub const HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryWatchtowerModeV2 {
    Monitor,
    BeginChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryWatchtowerRequestV2 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub binding_commitment: String,
    pub mode: HvmRegistryWatchtowerModeV2,
    pub network_fee_zhu: u64,
    pub timestamp: u64,
    pub gas_max: u8,
    pub created_unix: u64,
}

impl HvmRegistryWatchtowerRequestV2 {
    pub fn validate(&self) -> HubResult<()> {
        if self.schema != HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.operation_id.len() > 256
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > 256
            || !canonical_commitment(&self.binding_commitment)
            || self.network_fee_zhu == 0
            || self.timestamp == 0
            || self.gas_max == 0
            || self.created_unix == 0
        {
            return Err(HubError::State(
                "HVM registry watchtower request is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("watchtower encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryLeaseRenewalRequestV2 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub binding_commitment: String,
    pub renew_when_blocks_at_or_below: u64,
    pub periods: u64,
    pub network_fee_zhu: u64,
    pub timestamp: u64,
    pub gas_max: u8,
    pub created_unix: u64,
}

impl HvmRegistryLeaseRenewalRequestV2 {
    pub fn validate(&self) -> HubResult<()> {
        if self.schema != HVM_REGISTRY_LEASE_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.operation_id.len() > 256
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > 256
            || !canonical_commitment(&self.binding_commitment)
            || self.renew_when_blocks_at_or_below == 0
            || self.periods == 0
            || self.periods > HVM_LEASE_RENEWAL_MAX_PERIODS
            || self.network_fee_zhu == 0
            || self.timestamp == 0
            || self.gas_max == 0
            || self.created_unix == 0
        {
            return Err(HubError::State(
                "HVM registry lease renewal request is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("lease request encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HvmRegistryChainResponseV2 {
    pub operation_id: String,
    pub status: String,
    pub action: String,
    pub transaction_hash: Option<String>,
    pub confirmed_block_height: Option<u64>,
    pub observed_confirmations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvmRegistryWatchtowerDecisionV2 {
    NoAction,
    /// Start a unilateral settlement from OPEN by putting the latest
    /// fully-signed bill on chain. Only [`decide_user_exit_action`] ever
    /// returns this: the Hub's monitor has no reason to move an OPEN channel,
    /// and the user does.
    OpenChallengeWithLatestBill,
    RespondWithLatestBill,
    Finalize,
    /// The channel is FINAL and the settled principal is still sitting in the
    /// contract. Only an Action 14 payout moves it out.
    ClaimLeftPayout,
    RecoveryRequired,
}

pub fn decide_registry_watchtower_action(
    snapshot: &HvmRegistryLiveSnapshotV2,
    binding: &HvmRegistryBindingV2,
    latest: &HvmRegistryBillV2,
) -> HubResult<HvmRegistryWatchtowerDecisionV2> {
    snapshot.validate_runtime_binding(binding, 1, 1)?;
    latest.validate_fully_signed(binding)?;
    let chain_serial = snapshot.channel.serial.value;
    if chain_serial > latest.serial {
        return Ok(HvmRegistryWatchtowerDecisionV2::RecoveryRequired);
    }
    let chain_matches_latest = chain_serial == latest.serial
        && snapshot.channel.left_balance.value == latest.left_balance_zhu
        && snapshot.channel.hub_balance.value == latest.hub_balance_zhu;
    if chain_serial == latest.serial && !chain_matches_latest {
        return Ok(HvmRegistryWatchtowerDecisionV2::RecoveryRequired);
    }
    match snapshot.channel.status.value {
        2 => Ok(HvmRegistryWatchtowerDecisionV2::NoAction),
        3 if chain_serial < latest.serial
            && snapshot.observed_height < snapshot.channel.deadline.value =>
        {
            Ok(HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill)
        }
        3 if chain_serial < latest.serial => Ok(HvmRegistryWatchtowerDecisionV2::RecoveryRequired),
        3 if chain_matches_latest
            && snapshot.observed_height >= snapshot.channel.deadline.value =>
        {
            Ok(HvmRegistryWatchtowerDecisionV2::Finalize)
        }
        3 => Ok(HvmRegistryWatchtowerDecisionV2::NoAction),
        // FINAL. `settle()` only moved the accounting: it credited
        // `g_left_claimable` and left `c_left_claimed_` false. The coin itself
        // is still inside the contract until an Action 14 payout runs. When
        // `c_left_claimed_` is already true the payout happened — by us or by
        // any third party, since claims are permissionless — and there is
        // nothing left to do. A zero left balance is marked claimed by
        // `settle()` itself and is likewise nothing to claim.
        4 if chain_matches_latest
            && !snapshot.channel.left_claimed.value
            && snapshot.channel.left_balance.value > 0 =>
        {
            Ok(HvmRegistryWatchtowerDecisionV2::ClaimLeftPayout)
        }
        4 if chain_matches_latest => Ok(HvmRegistryWatchtowerDecisionV2::NoAction),
        4 => Ok(HvmRegistryWatchtowerDecisionV2::RecoveryRequired),
        _ => Ok(HvmRegistryWatchtowerDecisionV2::RecoveryRequired),
    }
}

/// The same decision, taken from the *left* party's chair.
///
/// Exactly one situation reads differently, and it is the whole point of a
/// unilateral exit: on status 2 (OPEN) the Hub's monitor answers `NoAction`,
/// because an open channel that nobody has challenged is a channel doing its
/// job. A user whose Hub has gone silent is looking at the same OPEN status
/// and needs the opposite answer — OPEN is where an exit *starts*, by putting
/// the latest fully-signed bill on chain with `challenge`.
///
/// Every other branch is delegated verbatim to
/// [`decide_registry_watchtower_action`] rather than restated, so respond,
/// finalize, claim and the two `RecoveryRequired` rules cannot drift apart
/// between the two callers. In particular `chain_serial > latest.serial` stays
/// `RecoveryRequired` here too: a chain ahead of the wallet's own head means
/// the wallet's evidence is not the newest evidence, and challenging with it
/// would be the user attacking themselves.
/// The second divergence: a party acting **for the left side** never spends a
/// fee to reduce what the left side is paid.
///
/// See [`registry_respond_defends_left_payout`] for why this is not a
/// nicety. On the shipped one-directional rail it means `respond` never fires
/// from this chair at all, and that is the correct answer rather than a
/// disabled feature: every bill after the first pays the user strictly less,
/// so a `respond` carrying a newer serial can only ever hand money back. The
/// day the rail carries refunds or a Hub deposit, the same rule starts firing
/// on its own, in the user's favour, with no edit here.
pub fn decide_user_exit_action(
    snapshot: &HvmRegistryLiveSnapshotV2,
    binding: &HvmRegistryBindingV2,
    latest: &HvmRegistryBillV2,
) -> HubResult<HvmRegistryWatchtowerDecisionV2> {
    let hub_view = decide_registry_watchtower_action(snapshot, binding, latest)?;
    if hub_view == HvmRegistryWatchtowerDecisionV2::NoAction && snapshot.channel.status.value == 2 {
        return Ok(HvmRegistryWatchtowerDecisionV2::OpenChallengeWithLatestBill);
    }
    if hub_view == HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill
        && !registry_respond_defends_left_payout(snapshot, latest)
    {
        return Ok(HvmRegistryWatchtowerDecisionV2::NoAction);
    }
    Ok(hub_view)
}

/// Would answering this challenge with our bill leave the left party no worse
/// off than the chain already has them?
///
/// # Why this exists
///
/// The Hub's watchtower asks one question — is the chain carrying an older
/// serial than mine — and answers `RespondWithLatestBill` if so. That is the
/// right question *from the Hub's chair*, because the Hub is claiming what it
/// earned. Taken from the left party's chair, or from a watchtower running on
/// the left party's behalf, it is the wrong question, and on this rail it is
/// exactly backwards.
///
/// Every non-initial bill is minted by one function, which subtracts from the
/// left balance and adds to the Hub's (`hvm_registry_ledger`), and a non-zero
/// `right_hub_deposit_zhu` is refused outright (`hvm_registry`). So a higher
/// serial *always* means a lower left balance. A hostile Hub that challenges
/// with a stale bill is handing money back; a watcher that dutifully answers
/// with the newest bill takes that money away again. Measured on chain: a
/// stale challenge left the user owed 950,000 zhu, the "protective" response
/// installed the newest serial, and the user was paid 300,000. The watcher
/// cost its own user 650,000 zhu and a fee.
///
/// So the guard is stated in terms of the *amount*, not the serial. It does
/// not assume the rail is one-directional; it measures the direction of this
/// particular response. Nothing here weakens a check — a party may still
/// always respond in its own favour, and the Hub's own path is untouched.
pub fn registry_respond_defends_left_payout(
    snapshot: &HvmRegistryLiveSnapshotV2,
    latest: &HvmRegistryBillV2,
) -> bool {
    latest.left_balance_zhu >= snapshot.channel.left_balance.value
}

/// Blocks left between the verified height and the challenge deadline.
///
/// Saturating on purpose: a deadline at or behind the observed height is a
/// window of zero, never a wrapped enormous number.
pub fn registry_response_window_blocks(snapshot: &HvmRegistryLiveSnapshotV2) -> u64 {
    snapshot
        .channel
        .deadline
        .value
        .saturating_sub(snapshot.observed_height)
}

/// Is there enough of the challenge window left to build, sign, submit and
/// still be mined before `respond` stops being accepted?
pub fn registry_response_window_is_safe(snapshot: &HvmRegistryLiveSnapshotV2) -> bool {
    registry_response_window_blocks(snapshot) >= HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS
}

/// Refuse to reason about a deadline on evidence that is not current.
///
/// Two independent ways a fullnode can hand back a height that is not the
/// chain's height, both of which make the remaining challenge window a
/// fiction, and both of which the previous code trusted blindly:
///
/// * the registry endpoint answers from a view behind the node's own tip;
/// * the node itself has stopped following the chain, so its tip is a real
///   height that stopped being the top of the chain some time ago.
///
/// The first is bounded in blocks, the second in wall clock. Neither bound is
/// a substitute for the other.
pub fn require_fresh_registry_evidence(
    snapshot: &HvmRegistryLiveSnapshotV2,
    node_tip_height: u64,
    node_tip_age_seconds: u64,
) -> HubResult<()> {
    if node_tip_age_seconds > HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS {
        return Err(HubError::Node(format!(
            "fullnode chain tip is stale for watchtower evidence ({node_tip_age_seconds}s, limit {HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS}s)"
        )));
    }
    let behind = node_tip_height.saturating_sub(snapshot.observed_height);
    if behind > HVM_REGISTRY_MAX_SNAPSHOT_TIP_DRIFT_BLOCKS {
        return Err(HubError::Node(format!(
            "live HVM registry evidence is stale: observed height {} trails the node tip {node_tip_height} by {behind} blocks",
            snapshot.observed_height
        )));
    }
    Ok(())
}

/// The exact durable facts that make one watchtower situation different from
/// another.
///
/// This is what a scheduler has instead of the human-typed operation label the
/// CLI derives its `operation_id` from. Everything in it is a fact the chain
/// or the durable ledger asserts, and every field earns its place:
///
/// * `status`, `chain_serial`, `left_balance_zhu`, `hub_balance_zhu`,
///   `deadline` and `left_claimed` are exactly the inputs
///   [`decide_registry_watchtower_action`] reads. If none of them moved, the
///   decision cannot have moved either, so it is the same situation and a
///   retry must be the same operation.
/// * `durable_bill_serial` is the serial this Hub would respond *with*. Two
///   challenges answered with different bills are different situations even
///   when the chain half of the tuple happens to match.
///
/// What is deliberately **absent** is `observed_height`. It changes with every
/// block, so folding it in would make every tick a brand-new situation, every
/// tick would try to open a brand-new operation, and the tower would spawn
/// duplicates or wedge behind its own unresolved record. The window it feeds
/// is a safety gate, not an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvmRegistryWatchtowerSituationV2 {
    pub status: u8,
    pub chain_serial: u64,
    pub left_balance_zhu: u64,
    pub hub_balance_zhu: u64,
    pub deadline: u64,
    pub left_claimed: bool,
    pub durable_bill_serial: u64,
}

impl HvmRegistryWatchtowerSituationV2 {
    pub fn from_evidence(snapshot: &HvmRegistryLiveSnapshotV2, latest: &HvmRegistryBillV2) -> Self {
        Self {
            status: snapshot.channel.status.value,
            chain_serial: snapshot.channel.serial.value,
            left_balance_zhu: snapshot.channel.left_balance.value,
            hub_balance_zhu: snapshot.channel.hub_balance.value,
            deadline: snapshot.channel.deadline.value,
            left_claimed: snapshot.channel.left_claimed.value,
            durable_bill_serial: latest.serial,
        }
    }

    /// A collision-resistant name for this situation on this binding.
    ///
    /// The binding commitment is length-prefixed and every other field is a
    /// fixed-width big-endian encoding, so no two distinct situations can
    /// produce the same pre-image by rearranging their bytes.
    pub fn digest(&self, binding_commitment: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"hpay-hvm-registry-watchtower-situation/2");
        hasher.update((binding_commitment.len() as u64).to_be_bytes());
        hasher.update(binding_commitment.as_bytes());
        hasher.update([self.status]);
        hasher.update(self.chain_serial.to_be_bytes());
        hasher.update(self.left_balance_zhu.to_be_bytes());
        hasher.update(self.hub_balance_zhu.to_be_bytes());
        hasher.update(self.deadline.to_be_bytes());
        hasher.update([u8::from(self.left_claimed)]);
        hasher.update(self.durable_bill_serial.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

pub fn registry_challenge_call_source(
    binding: &HvmRegistryBindingV2,
    bill: &HvmRegistryBillV2,
) -> HubResult<String> {
    bill.validate_fully_signed(binding)?;
    checked_registry_call(binding, &registry_bill_call("challenge", binding, bill))
}

pub fn registry_respond_call_source(
    binding: &HvmRegistryBindingV2,
    bill: &HvmRegistryBillV2,
) -> HubResult<String> {
    bill.validate_fully_signed(binding)?;
    checked_registry_call(binding, &registry_bill_call("respond", binding, bill))
}

pub fn registry_finalize_call_source(binding: &HvmRegistryBindingV2) -> HubResult<String> {
    checked_registry_call(binding, &format!("finalize({})", binding.left_address))
}

pub fn registry_renew_all_call_source(
    binding: &HvmRegistryBindingV2,
    periods: u64,
) -> HubResult<String> {
    if periods == 0 || periods > HVM_LEASE_RENEWAL_MAX_PERIODS {
        return Err(HubError::State(format!(
            "HVM registry lease periods must be between 1 and {HVM_LEASE_RENEWAL_MAX_PERIODS}"
        )));
    }
    registry_contract_call_source(
        binding,
        &format!(
            "var registry_result = Registry.renew_registry({periods})\nassert registry_result == 0\nvar channel_result = Registry.renew_channel({}, {periods})\nassert channel_result == 0",
            binding.left_address
        ),
    )
}

/// The 12 storage keys of one channel, renewed on their own.
///
/// Split out of [`registry_renew_all_call_source`] because the two halves have
/// genuinely different owners and genuinely different gas budgets. These 12
/// keys belong to one user's channel; the 6 globals are shared by every
/// channel in the deployment. Renewing only the channel fits far more periods
/// under the same Type 3 storage-gas cap than renewing all 18 at once — the
/// combined helper is capped at [`HVM_LEASE_RENEWAL_MAX_PERIODS`] = 100 for
/// exactly that reason — so a user buying runway for their own deposit gets
/// strictly more life per fee from this call.
///
/// # This number is the contract's, not ours
///
/// It was 200 — a gas measurement taken against an older revision of the
/// contract — while the reviewed contract asserts `periods <= MAX_RENT_STEP`
/// with `MAX_RENT_STEP = 150`. Nothing tied the two together, so the wallet
/// happily signed `renew_channel(left, 200)` and the chain threw it out. That
/// mattered more than an ordinary off-by-one: the lease is the only clock in
/// this system that destroys a deposit outright, and the driver answers a
/// short lease by renewing *first*, so the one rescue path a user has was a
/// transaction that could never execute.
///
/// It is now [`HPAY_REGISTRY_MAX_RENT_STEP`], and
/// `registry_rent_step_matches_the_reviewed_contract` re-reads the constant
/// out of the contract source itself and fails if the two ever drift again.
/// The gas headroom the old figure was chasing is still there — the contract's
/// own comment records that 200 is the last step that executes and 250 dies
/// with `OutOfGas`, so 150 sits under the cliff with margin.
pub const HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS: u64 = HPAY_REGISTRY_MAX_RENT_STEP;

/// The 6 shared registry globals, renewed on their own.
///
/// If these lapse, *every* channel in the deployment is affected, not just
/// one. Any address may renew them — the call takes no party argument and
/// carries no signer check — so the shared fate is repairable by anybody, but
/// it is a named property of the shared profile rather than a surprise.
///
/// Capped by the contract's own `MAX_RENT_STEP`, exactly like the channel
/// half above and for the same reason: `renew_registry` asserts
/// `periods <= MAX_RENT_STEP` before it touches a key, so the 400 this used to
/// advertise was a transaction the chain refused. The gas ceiling measured for
/// this call is higher than the channel call's — it touches 6 keys rather than
/// 12 — but the contract's assertion binds first, so the gas headroom is not
/// the limit that matters.
pub const HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS: u64 = HPAY_REGISTRY_MAX_RENT_STEP;

pub fn registry_renew_channel_call_source(
    binding: &HvmRegistryBindingV2,
    periods: u64,
) -> HubResult<String> {
    if periods == 0 || periods > HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS {
        return Err(HubError::State(format!(
            "HVM registry channel lease periods must be between 1 and {HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS}"
        )));
    }
    checked_registry_call(
        binding,
        &format!("renew_channel({}, {periods})", binding.left_address),
    )
}

pub fn registry_renew_registry_call_source(
    binding: &HvmRegistryBindingV2,
    periods: u64,
) -> HubResult<String> {
    if periods == 0 || periods > HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS {
        return Err(HubError::State(format!(
            "HVM registry global lease periods must be between 1 and {HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS}"
        )));
    }
    checked_registry_call(binding, &format!("renew_registry({periods})"))
}

/// Canonical descriptor of an Action 14 claim.
///
/// A claim is not a fitsh call: it carries no Action 44 and compiles nothing.
/// It still needs one canonical, re-derivable string so that the durable
/// record can be checked against the binding on every load, exactly like the
/// compiled call sources of the other kinds. This is that string, and it
/// commits to every field the payout depends on.
///
/// Refusing here is the point. The contract's `PermitHAC` hook demands
/// `amount == c_left_balance_` to the zhu, so an amount that cannot be carried
/// exactly by an on-wire `Amount` is not "close enough" — it is unpayable, and
/// guessing at it would either throw on chain or, worse, move a different
/// number than the one the operator approved.
pub fn registry_claim_payout_source(
    binding: &HvmRegistryBindingV2,
    payee: &str,
    amount_zhu: u64,
) -> HubResult<String> {
    binding.validate()?;
    // The hub side of `PermitHAC` draws down the pooled `g_hub_claimable`
    // counter, which carries no per-channel marker: nothing in the contract
    // records that this channel's hub share was already taken, so a hub payout
    // can be neither made exactly idempotent nor verified exactly afterwards.
    // Only the left party's share has that evidence (`c_left_claimed_`).
    if payee != binding.left_address {
        return Err(HubError::State(
            "registry claim payee must be the exact channel left address".into(),
        ));
    }
    exact_claim_amount(amount_zhu)?;
    Ok(format!(
        "hpay-hvm-registry-claim/2\ncontract={}\nchain_id={}\nnetwork_instance={}\nchannel_id={}\nreuse={}\nto={payee}\nzhu={amount_zhu}",
        binding.contract_address,
        binding.chain_id,
        binding.network_instance_id,
        binding.channel_id,
        binding.reuse_version,
    ))
}

/// An `Amount` that does not read back as the exact same zhu count cannot be
/// used to satisfy the contract's exact-equality payout check.
fn exact_claim_amount(amount_zhu: u64) -> HubResult<Amount> {
    if amount_zhu == 0 {
        return Err(HubError::State(
            "registry claim amount must be positive".into(),
        ));
    }
    let amount = Amount::zhu(amount_zhu);
    let readback = amount.to_zhu_u64().map_err(|error| {
        HubError::State(format!("registry claim amount is not readable: {error}"))
    })?;
    if readback != amount_zhu {
        return Err(HubError::State(
            "registry claim amount is not exactly representable on the wire".into(),
        ));
    }
    Ok(amount)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHvmRegistryCallTransactionV2 {
    pub transaction_hash: String,
    pub signed_transaction_hex: String,
    pub call_source: String,
}

/// Which party of the binding is asking for a registry transaction to be
/// built, **stated by the caller** and then verified here against the binding.
///
/// The builders used to open with a bare `signer.readable() !=
/// binding.right_hub_address`. That predicate was not the chain's rule — the
/// `hpay_channel_registry_v2` contract puts no signer check on `challenge`,
/// `respond`, `finalize` or `renew_channel`, and the Action 14 payout is
/// authorised by `PermitHAC` rather than by `tx.main` — it was a description
/// of the only caller that existed. Left as-is it is the whole reason a user
/// cannot walk out of a channel the chain would happily let them walk out of.
///
/// So the predicate is not removed. It is made to belong to a role the caller
/// has to name, so that:
///
/// * the Hub's rule is byte-for-byte the rule it always had, and every Hub
///   call site still passes [`HvmRegistryCallerRole::Hub`];
/// * the user's rule is its own named, separately tested rule
///   (`signer == binding.left_address`) rather than an absence;
/// * a third role — a fee-paying watchtower that is neither party — cannot
///   appear by omission. It has to be added here deliberately, with its own
///   test, on the day somebody actually operates one.
///
/// That day is this one, and [`HvmRegistryCallerRole::ThirdPartyFeePayer`]
/// below is the deliberate addition. It exists because the responder for a
/// sleeping user cannot be either party: the Hub is the one challenging, and
/// the user is asleep. It is used by exactly one caller,
/// [`crate::hvm_registry_response_watch`], which can only ever ask for
/// `respond`, `finalize` and the left-party payout, and has no way to express
/// a `challenge`.
///
/// What makes the user role safe is not this check at all; it is the payee
/// restriction that already existed and is untouched:
/// [`registry_claim_payout_source`] refuses any payee that is not
/// `binding.left_address`, and the contract's `PermitHAC` pins the amount to
/// `c_left_balance_`. `tx.main` only pays the network fee. It has no authority
/// over where the coin goes, which is precisely why widening who may build
/// these bytes cannot widen who gets paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvmRegistryCallerRole {
    /// The Hub's own settlement key. Today's exact rule, unchanged.
    Hub,
    /// The channel's left party — the user whose deposit is inside.
    ChannelLeft,
    /// Neither party: a key that does nothing but pay the network fee for a
    /// step the contract already lets anybody take.
    ///
    /// This role names no address, and that is not a hole. There is no
    /// address it *could* name: the whole point of a responder is that it
    /// stands in for a user who is not there, so it is by construction
    /// somebody else. What keeps it safe is that `tx.main` on these
    /// transactions buys nothing but inclusion:
    ///
    /// * `respond` and `finalize` carry no signer check in the contract at
    ///   all; the bill's own two signatures are the authority, and a
    ///   responder that has not been handed a valid fully-signed bill cannot
    ///   build a `respond` in the first place.
    /// * the Action 14 payout is authorised by `PermitHAC`, which pins the
    ///   destination to the channel's left party and the amount to
    ///   `c_left_balance_` to the zhu. A third party that tries to pay itself
    ///   gets `Nil` for `c_status_` and the payout aborts; a third party that
    ///   tries a different number gets `HPAY_LEFT_PAYOUT_MISMATCH`. Both were
    ///   measured on a real chain, not reasoned about.
    ///
    /// So the only thing this role can spend is its own fees, and the only
    /// thing it can leak is the channel balance it was already given. The one
    /// rule enforced here is the one that is actually checkable: the signer
    /// must be a spendable key, not a contract, because a contract address
    /// cannot sign a Type 3 and a transaction built for one would be dead
    /// bytes that still looked like protection.
    ThirdPartyFeePayer,
}

impl HvmRegistryCallerRole {
    const fn noun(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::ChannelLeft => "channel left party",
            Self::ThirdPartyFeePayer => "fee-paying responder",
        }
    }

    const fn parse_label(self) -> &'static str {
        match self {
            Self::Hub => "registry watchtower",
            Self::ChannelLeft => "registry channel left party",
            Self::ThirdPartyFeePayer => "registry response watch",
        }
    }
}

/// Verify a caller-stated role against the binding.
///
/// The role is an assertion the caller makes about itself; this is where the
/// assertion is checked. A caller that names the wrong role is refused with
/// the word "signer" in the message, because that is what is wrong.
pub fn require_registry_caller(
    signer: &Account,
    binding: &HvmRegistryBindingV2,
    role: HvmRegistryCallerRole,
) -> HubResult<()> {
    let expected = match role {
        HvmRegistryCallerRole::Hub => &binding.right_hub_address,
        HvmRegistryCallerRole::ChannelLeft => &binding.left_address,
        // No address to compare against, by construction. What is checkable
        // is that the signer is a key that can actually sign, and that it is
        // not the registry contract itself — a contract address is not a
        // privakey, so bytes built for one would never be admitted.
        HvmRegistryCallerRole::ThirdPartyFeePayer => {
            let main = parse_address(signer.readable(), role.parse_label())?;
            if ContractAddress::from_addr(main).is_ok()
                || signer.readable() == binding.contract_address
            {
                return Err(HubError::State(
                    "registry call signer is a contract address, not a fee-paying key".into(),
                ));
            }
            return Ok(());
        }
    };
    if signer.readable() != *expected {
        return Err(HubError::State(format!(
            "registry call signer is not the {} of this binding",
            role.noun()
        )));
    }
    Ok(())
}

pub fn build_signed_hvm_registry_call_transaction(
    signer: &Account,
    binding: &HvmRegistryBindingV2,
    role: HvmRegistryCallerRole,
    call_source: String,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<SignedHvmRegistryCallTransactionV2> {
    binding.validate()?;
    require_registry_caller(signer, binding, role)?;
    if network_fee_zhu == 0 || timestamp == 0 || gas_max == 0 {
        return Err(HubError::State(
            "registry call fee, timestamp or gas limit is invalid".into(),
        ));
    }
    let main = parse_address(signer.readable(), role.parse_label())?;
    let contract = parse_address(&binding.contract_address, "registry contract")?;
    ContractAddress::from_addr(contract)
        .map_err(|_| HubError::State("registry target is not an HVM contract".into()))?;
    let codes = vm::lang::lang_to_bytecode(&call_source)
        .map_err(|error| HubError::State(format!("registry call compilation failed: {error}")))?;
    let action = ContractMainCall::from_bytecode(codes)
        .map_err(|error| HubError::State(format!("HVM Action 44 build failed: {error}")))?;
    let mut transaction = TransactionType3::new_by(main, Amount::zhu(network_fee_zhu), timestamp);
    transaction.addrlist = AddrOrList::from_list(vec![main, contract])
        .map_err(|error| HubError::State(format!("HVM address list failed: {error}")))?;
    transaction.gas_max = Uint1::from(gas_max);
    let mut chain_allow = ChainAllow::new();
    chain_allow.chains = ChainIDList::from_list(vec![Uint4::from(binding.chain_id)])
        .map_err(|error| HubError::State(format!("HVM ChainAllow build failed: {error}")))?;
    transaction
        .push_action(Box::new(chain_allow))
        .map_err(|error| HubError::State(format!("HVM chain guard append failed: {error}")))?;
    transaction
        .push_action(Box::new(action))
        .map_err(|error| HubError::State(format!("HVM action append failed: {error}")))?;
    transaction
        .fill_sign(signer)
        .map_err(|error| HubError::State(format!("registry watchtower signing failed: {error}")))?;
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM Type 3 signature failed: {error}")))?;
    Ok(SignedHvmRegistryCallTransactionV2 {
        transaction_hash: hex::encode(transaction.hash()),
        signed_transaction_hex: hex::encode(transaction.serialize()),
        call_source,
    })
}

/// Build the exact Action 14 payout that walks the settled principal back out
/// of the shared registry contract.
///
/// Shape is deliberately identical to the Action 44 builder above except for
/// the payload action: Type 3, non-zero gas, `[ChainAllow(0x0411) bound to
/// binding.chain_id, HacFromToTrs(14)]`. There is no fitsh call and no Action
/// 44.
///
/// The claim is permissionless by construction. Action 14 declares
/// `req_sign = [self.from]`, but `TransactionType3::intrinsic_req_sign` only
/// adds an address to the required-signer set when it `is_privakey()`, and a
/// contract address is not. So the contract never signs: its consent *is* the
/// `PermitHAC` hook. The signer here is only `tx.main`, and `tx.main` only
/// pays the fee — it has no authority over where the coin goes.
// Every argument here is a distinct fact the signed bytes commit to, and
// bundling them into a struct would only move the same list somewhere the
// caller has to fill in by name instead of by position.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_hvm_registry_claim_transaction(
    signer: &Account,
    binding: &HvmRegistryBindingV2,
    role: HvmRegistryCallerRole,
    payee: &str,
    amount_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<SignedHvmRegistryCallTransactionV2> {
    let call_source = registry_claim_payout_source(binding, payee, amount_zhu)?;
    require_registry_caller(signer, binding, role)?;
    if network_fee_zhu == 0 || timestamp == 0 || gas_max == 0 {
        return Err(HubError::State(
            "registry claim fee, timestamp or gas limit is invalid".into(),
        ));
    }
    let main = parse_address(signer.readable(), role.parse_label())?;
    let contract = parse_address(&binding.contract_address, "registry contract")?;
    ContractAddress::from_addr(contract)
        .map_err(|_| HubError::State("registry target is not an HVM contract".into()))?;
    let to = parse_address(payee, "registry claim payee")?;
    if to == contract || ContractAddress::from_addr(to).is_ok() {
        return Err(HubError::State(
            "registry claim payee must not be a contract address".into(),
        ));
    }
    let hacash = exact_claim_amount(amount_zhu)?;
    let mut action = HacFromToTrs::new();
    // Embedded Val1 addresses only: a pointer would make the payout depend on
    // a list this builder does not control.
    action.from = AddrOrPtr::from_addr(contract);
    action.to = AddrOrPtr::from_addr(to);
    action.hacash = hacash;
    let mut transaction = TransactionType3::new_by(main, Amount::zhu(network_fee_zhu), timestamp);
    transaction.addrlist = AddrOrList::from_list(vec![main, contract])
        .map_err(|error| HubError::State(format!("HVM address list failed: {error}")))?;
    transaction.gas_max = Uint1::from(gas_max);
    let mut chain_allow = ChainAllow::new();
    chain_allow.chains = ChainIDList::from_list(vec![Uint4::from(binding.chain_id)])
        .map_err(|error| HubError::State(format!("HVM ChainAllow build failed: {error}")))?;
    transaction
        .push_action(Box::new(chain_allow))
        .map_err(|error| HubError::State(format!("HVM chain guard append failed: {error}")))?;
    transaction
        .push_action(Box::new(action))
        .map_err(|error| HubError::State(format!("HVM Action 14 append failed: {error}")))?;
    transaction
        .fill_sign(signer)
        .map_err(|error| HubError::State(format!("registry claim signing failed: {error}")))?;
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM Type 3 signature failed: {error}")))?;
    let signed_transaction_hex = hex::encode(transaction.serialize());
    // Read the bytes we are about to hand out back through the same reader the
    // recovery path uses. A builder that cannot be read exactly is not exact.
    read_exact_registry_claim_transaction(&signed_transaction_hex, binding, payee, amount_zhu)?;
    Ok(SignedHvmRegistryCallTransactionV2 {
        transaction_hash: hex::encode(transaction.hash()),
        signed_transaction_hex,
        call_source,
    })
}

/// Can a key that is **not** the Hub's own key build the registry exit
/// transactions at all?
///
/// This is the question a unilateral exit actually turns on, and until this
/// function was written nothing in either repository asked it. The
/// `hpay_channel_registry_v2` contract is permissionless where it matters —
/// `finalize` carries no signer check, and the Action 14 payout needs no
/// signature from the contract because a contract address is not a privakey,
/// so `TransactionType3::intrinsic_req_sign` never demands one. A user holding
/// a Hub-countersigned bill is therefore *permitted* by the chain to walk out
/// alone.
///
/// Being permitted is not the same as being able. The only code in this
/// workspace that can construct those transactions is
/// [`build_signed_hvm_registry_call_transaction`] and
/// [`build_signed_hvm_registry_claim_transaction`], and both open with
/// `signer.readable() != binding.right_hub_address` — every signer that is not
/// the Hub is refused before a byte is built. No crate under `crates/wallet-core`,
/// `crates/agent-wallet-core`, `apps/desktop` or `apps/mobile` constructs a
/// challenge, respond, finalize or claim transaction by any other route. The
/// door is open and there is no handle on the user's side of it.
///
/// So this probes the builders rather than reading a flag: it synthesises a
/// reviewed-profile binding, then asks the two builders to work for the
/// channel's *left* party — the user — and reports whether they will. It is
/// pure computation against a throwaway key, touches no chain and no network,
/// and cannot be satisfied by configuration, by an operator assertion, or by
/// editing a literal. The day someone makes the builders signer-aware rather
/// than Hub-only, this starts reporting `true` on its own and for the right
/// reason.
///
/// A `false` here means: whatever the chain would allow, this software cannot
/// put an exit transaction in a user's hands.
pub fn user_key_can_build_registry_exit_transactions() -> bool {
    // The builders serialise real actions through the consensus codec
    // registry, which panics if it was never installed. This measurement must
    // be safe to call from anywhere, including a process that has not touched
    // the chain yet, so install it here; the call is idempotent.
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let Ok(left) = Account::create_by("registry-user-side-exit-probe-left") else {
        return false;
    };
    let Ok(hub) = Account::create_by("registry-user-side-exit-probe-hub") else {
        return false;
    };
    let left_address = Address::from(*left.address()).to_readable();
    let binding = HvmRegistryBindingV2 {
        schema: crate::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: "11".repeat(32),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: "33".repeat(16),
        reuse_version: 0,
        left_address: left_address.clone(),
        right_hub_address: Address::from(*hub.address()).to_readable(),
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    // If the synthetic binding itself stops matching the reviewed profile the
    // probe has lost its subject, and an answer it cannot stand behind must be
    // the closed one.
    if binding.validate().is_err() {
        return false;
    }
    let Ok(finalize) = registry_finalize_call_source(&binding) else {
        return false;
    };
    // `finalize` is the permissionless step the contract grants to anybody,
    // and the Action 14 claim is the only door HAC leaves the contract by. A
    // user who cannot build both cannot complete an exit alone.
    build_signed_hvm_registry_call_transaction(
        &left,
        &binding,
        HvmRegistryCallerRole::ChannelLeft,
        finalize,
        1,
        1,
        1,
    )
    .is_ok()
        && build_signed_hvm_registry_claim_transaction(
            &left,
            &binding,
            HvmRegistryCallerRole::ChannelLeft,
            &left_address,
            binding.left_deposit_zhu,
            1,
            1,
            1,
        )
        .is_ok()
}

/// Read side of the claim: decode signed bytes and prove they are exactly the
/// approved payout and nothing else.
///
/// `AddrOrPtr::Val2` is refused outright. A pointer resolves against the
/// transaction's own address list, so accepting one would mean the payee is
/// whatever that list happens to say — the payout would no longer be pinned by
/// these bytes alone.
pub fn read_exact_registry_claim_transaction(
    signed_transaction_hex: &str,
    binding: &HvmRegistryBindingV2,
    payee: &str,
    amount_zhu: u64,
) -> HubResult<()> {
    binding.validate()?;
    let contract = parse_address(&binding.contract_address, "registry contract")?;
    let expected_payee = parse_address(payee, "registry claim payee")?;
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|_| HubError::State("registry claim bytes are not hex".into()))?;
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| HubError::State(format!("registry claim bytes are invalid: {error}")))?;
    if consumed != raw.len() {
        return Err(HubError::State(
            "registry claim bytes carry trailing data".into(),
        ));
    }
    if transaction.ty() != 3 {
        return Err(HubError::State(
            "registry claim must be a Type 3 transaction".into(),
        ));
    }
    if transaction.gas_max_byte().is_none_or(|gas| gas == 0) {
        return Err(HubError::State(
            "registry claim must carry a non-zero gas limit".into(),
        ));
    }
    let actions = transaction.actions();
    if actions.len() != 2 || actions[0].kind() != 0x0411 || actions[1].kind() != 14 {
        return Err(HubError::State(
            "registry claim must be exactly a chain guard and one Action 14".into(),
        ));
    }
    let guard = actions[0]
        .as_any()
        .downcast_ref::<ChainAllow>()
        .ok_or_else(|| HubError::State("registry claim chain guard is unreadable".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != binding.chain_id {
        return Err(HubError::State(
            "registry claim is not bound to the exact binding chain".into(),
        ));
    }
    let transfer = actions[1]
        .as_any()
        .downcast_ref::<HacFromToTrs>()
        .ok_or_else(|| HubError::State("registry claim payout action is unreadable".into()))?;
    let from = exact_embedded_address(&transfer.from, "source")?;
    let to = exact_embedded_address(&transfer.to, "payee")?;
    if from != contract {
        return Err(HubError::State(
            "registry claim must draw from the exact registry contract".into(),
        ));
    }
    if to != expected_payee {
        return Err(HubError::State(
            "registry claim pays a different address than approved".into(),
        ));
    }
    let paid = transfer.hacash.to_zhu_u64().map_err(|error| {
        HubError::State(format!("registry claim amount is unreadable: {error}"))
    })?;
    if paid != amount_zhu || paid == 0 {
        return Err(HubError::State(
            "registry claim amount is not the exact approved payout".into(),
        ));
    }
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("registry claim signature failed: {error}")))?;
    Ok(())
}

fn exact_embedded_address(value: &AddrOrPtr, label: &str) -> HubResult<Address> {
    match value {
        AddrOrPtr::Val1(address) => Ok(*address),
        AddrOrPtr::Val2(_) => Err(HubError::State(format!(
            "registry claim {label} cannot use an address pointer"
        ))),
    }
}

fn registry_bill_call(
    function: &str,
    binding: &HvmRegistryBindingV2,
    bill: &HvmRegistryBillV2,
) -> String {
    format!(
        "{function}({}, {}, {}, {}, 0x{}, 0x{})",
        binding.left_address,
        bill.serial,
        bill.left_balance_zhu,
        bill.hub_balance_zhu,
        bill.left_signature_hex,
        bill.hub_signature_hex
    )
}

fn registry_contract_call_source(binding: &HvmRegistryBindingV2, call: &str) -> HubResult<String> {
    binding.validate()?;
    Ok(format!(
        "lib Registry = 1: {}\n{call}\nend",
        binding.contract_address
    ))
}

fn checked_registry_call(binding: &HvmRegistryBindingV2, call: &str) -> HubResult<String> {
    registry_contract_call_source(
        binding,
        &format!("var result = Registry.{call}\nassert result == 0"),
    )
}

fn canonical_commitment(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use field::{Address, Serialize as _, Sign};

    use super::*;
    use crate::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
        HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT,
        HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT,
        HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2,
    };
    use crate::node::HvmStorageEntry;

    fn fixture() -> (Account, HvmRegistryBindingV2, HvmRegistryBillV2) {
        let left = Account::create_by("registry-watchtower-left").unwrap();
        let hub = Account::create_by("registry-watchtower-hub").unwrap();
        let binding = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 2,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: Address::from(*left.address()).to_readable(),
            right_hub_address: Address::from(*hub.address()).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 2,
            left_balance_zhu: 800_000,
            hub_balance_zhu: 200_000,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&binding).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.hub_signature_hex = hex::encode(Sign::create_by(&hub, &hash).serialize());
        (hub, binding, bill)
    }

    fn entry<T>(value: T) -> HvmStorageEntry<T> {
        HvmStorageEntry {
            value,
            live_blocks: 100,
            recover_blocks: 100,
            active: true,
            recoverable: false,
        }
    }

    fn challenged_snapshot(
        binding: &HvmRegistryBindingV2,
        serial: u64,
        left_balance_zhu: u64,
        hub_balance_zhu: u64,
        observed_height: u64,
        deadline: u64,
        status: u8,
    ) -> HvmRegistryLiveSnapshotV2 {
        HvmRegistryLiveSnapshotV2 {
            ret: 0,
            schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            chain_id: binding.chain_id,
            network_instance_id: binding.network_instance_id.clone(),
            observed_height,
            evaluation_height: observed_height + 1,
            contract_address: binding.contract_address.clone(),
            deployment_tx_hash: binding.deployment_tx_hash.clone(),
            deployment_height: binding.deployment_height,
            deployment_action_verified: true,
            bytecode_sha3: binding.bytecode_sha3.clone(),
            hub_address: binding.right_hub_address.clone(),
            left_address: binding.left_address.clone(),
            registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
            channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
            all_keys_active: true,
            minimum_live_blocks: 100,
            minimum_recover_blocks: 100,
            registry: HvmRegistryGlobalStorageV2 {
                g_network: entry(binding.network_instance_id.clone()),
                g_hub: entry(binding.right_hub_address.clone()),
                g_locked: entry(binding.left_deposit_zhu),
                g_left_claimable: entry(0),
                g_hub_claimable: entry(0),
                g_open_count: entry(1),
            },
            channel: HvmRegistryChannelStorageV2 {
                status: entry(status),
                channel_id: entry(binding.channel_id.clone()),
                reuse: entry(binding.reuse_version),
                deposit: entry(binding.left_deposit_zhu),
                paid: entry(binding.left_deposit_zhu),
                total: entry(binding.left_deposit_zhu),
                serial: entry(serial),
                left_balance: entry(left_balance_zhu),
                hub_balance: entry(hub_balance_zhu),
                challenge_blocks: entry(binding.challenge_blocks),
                deadline: entry(deadline),
                left_claimed: entry(false),
            },
        }
    }

    /// The exact Action 14 payout: Type 3, non-zero gas, a chain guard bound
    /// to the binding chain, and one `HacFromToTrs` drawing from the contract.
    /// No fitsh source, no Action 44.
    #[test]
    fn exact_action_14_claim_is_the_only_payout_shape_built() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, _) = fixture();
        let amount_zhu = 800_000;
        let signed = build_signed_hvm_registry_claim_transaction(
            &hub,
            &binding,
            HvmRegistryCallerRole::Hub,
            &binding.left_address,
            amount_zhu,
            10_000,
            123,
            250,
        )
        .unwrap();
        let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
        let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(tx.ty(), 3);
        assert_eq!(tx.gas_max_byte(), Some(250));
        assert_eq!(tx.actions().len(), 2);
        assert_eq!(tx.actions()[0].kind(), 0x0411);
        assert_eq!(tx.actions()[1].kind(), 14);
        assert!(
            tx.actions().iter().all(|action| action.kind() != 44),
            "a claim carries no contract main call"
        );
        let transfer = tx.actions()[1]
            .as_any()
            .downcast_ref::<HacFromToTrs>()
            .unwrap();
        let contract = parse_address(&binding.contract_address, "contract").unwrap();
        let left = parse_address(&binding.left_address, "left").unwrap();
        assert_eq!(
            exact_embedded_address(&transfer.from, "source").unwrap(),
            contract
        );
        assert_eq!(exact_embedded_address(&transfer.to, "payee").unwrap(), left);
        assert_eq!(transfer.hacash.to_zhu_u64().unwrap(), amount_zhu);
        tx.verify_signature().unwrap();
        assert_eq!(hex::encode(tx.hash()), signed.transaction_hash);
        read_exact_registry_claim_transaction(
            &signed.signed_transaction_hex,
            &binding,
            &binding.left_address,
            amount_zhu,
        )
        .unwrap();
    }

    /// The hub half of `PermitHAC` draws on the pooled `g_hub_claimable`
    /// counter, which has no per-channel marker: nothing on chain records that
    /// this channel's hub share was already taken, so such a payout can be
    /// neither made idempotent nor verified. Refusing is the only exact answer.
    #[test]
    fn a_claim_payee_that_is_not_the_channel_left_party_is_refused() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, _) = fixture();
        let stranger = Account::create_by("registry-claim-stranger").unwrap();
        for payee in [
            binding.right_hub_address.clone(),
            binding.contract_address.clone(),
            Address::from(*stranger.address()).to_readable(),
        ] {
            assert!(
                registry_claim_payout_source(&binding, &payee, 800_000).is_err(),
                "payee {payee} must be refused"
            );
            assert!(
                build_signed_hvm_registry_claim_transaction(
                    &hub,
                    &binding,
                    HvmRegistryCallerRole::Hub,
                    &payee,
                    800_000,
                    10_000,
                    123,
                    250
                )
                .is_err(),
                "payee {payee} must never be signed for"
            );
        }
    }

    /// `PermitHAC` throws on a zero payout, and a claim whose amount cannot be
    /// stated exactly has nothing safe to fall back on.
    #[test]
    fn a_claim_amount_that_cannot_be_stated_exactly_is_refused() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, _) = fixture();
        assert!(registry_claim_payout_source(&binding, &binding.left_address, 0).is_err());
        assert!(
            build_signed_hvm_registry_claim_transaction(
                &hub,
                &binding,
                HvmRegistryCallerRole::Hub,
                &binding.left_address,
                0,
                10_000,
                123,
                250
            )
            .is_err()
        );
        // Every u64 zhu count survives the wire round trip today; the guard
        // exists so that an amount which ever stops doing so is refused
        // instead of silently rounded into a different payout.
        for amount_zhu in [1_u64, 7, 10, 999_999, u64::MAX] {
            assert_eq!(
                exact_claim_amount(amount_zhu)
                    .unwrap()
                    .to_zhu_u64()
                    .unwrap(),
                amount_zhu
            );
        }
    }

    /// An `AddrOrPtr::Val2` resolves against the transaction's own address
    /// list, so a pointer would let the list decide who gets paid. The reader
    /// refuses it outright, the same way the L1 channel-close reader does.
    #[test]
    fn the_claim_reader_refuses_address_pointers_and_wrong_payouts() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, _) = fixture();
        let amount_zhu = 800_000;
        let contract = parse_address(&binding.contract_address, "contract").unwrap();
        let left = parse_address(&binding.left_address, "left").unwrap();
        let main = parse_address(hub.readable(), "main").unwrap();

        let build = |from: AddrOrPtr, to: AddrOrPtr, hacash: Amount| {
            let mut action = HacFromToTrs::new();
            action.from = from;
            action.to = to;
            action.hacash = hacash;
            let mut tx = TransactionType3::new_by(main, Amount::zhu(10_000), 123);
            // Type 3 reads its main signer from addrlist[0], so main leads and
            // the pointer indices below are 1 = contract, 2 = left.
            tx.addrlist = AddrOrList::from_list(vec![main, contract, left]).unwrap();
            tx.gas_max = Uint1::from(250);
            let mut chain_allow = ChainAllow::new();
            chain_allow.chains =
                ChainIDList::from_list(vec![Uint4::from(binding.chain_id)]).unwrap();
            tx.push_action(Box::new(chain_allow)).unwrap();
            tx.push_action(Box::new(action)).unwrap();
            tx.fill_sign(&hub).unwrap();
            hex::encode(tx.serialize())
        };

        // Pointer source: the payout would follow the address list, not these
        // bytes.
        assert!(
            read_exact_registry_claim_transaction(
                &build(
                    AddrOrPtr::from_ptr(1),
                    AddrOrPtr::from_addr(left),
                    Amount::zhu(amount_zhu)
                ),
                &binding,
                &binding.left_address,
                amount_zhu,
            )
            .is_err()
        );
        // Pointer payee.
        assert!(
            read_exact_registry_claim_transaction(
                &build(
                    AddrOrPtr::from_addr(contract),
                    AddrOrPtr::from_ptr(2),
                    Amount::zhu(amount_zhu)
                ),
                &binding,
                &binding.left_address,
                amount_zhu,
            )
            .is_err()
        );
        // Right shape, wrong amount.
        assert!(
            read_exact_registry_claim_transaction(
                &build(
                    AddrOrPtr::from_addr(contract),
                    AddrOrPtr::from_addr(left),
                    Amount::zhu(amount_zhu + 1)
                ),
                &binding,
                &binding.left_address,
                amount_zhu,
            )
            .is_err()
        );
        // An amount too large to read back as zhu is unreadable, not "big".
        assert!(
            read_exact_registry_claim_transaction(
                &build(
                    AddrOrPtr::from_addr(contract),
                    AddrOrPtr::from_addr(left),
                    Amount::mei(u64::MAX)
                ),
                &binding,
                &binding.left_address,
                amount_zhu,
            )
            .is_err()
        );
        // Money leaving somewhere other than the registry contract.
        assert!(
            read_exact_registry_claim_transaction(
                &build(
                    AddrOrPtr::from_addr(main),
                    AddrOrPtr::from_addr(left),
                    Amount::zhu(amount_zhu)
                ),
                &binding,
                &binding.left_address,
                amount_zhu,
            )
            .is_err()
        );
        // The honest shape still reads.
        read_exact_registry_claim_transaction(
            &build(
                AddrOrPtr::from_addr(contract),
                AddrOrPtr::from_addr(left),
                Amount::zhu(amount_zhu),
            ),
            &binding,
            &binding.left_address,
            amount_zhu,
        )
        .unwrap();
    }

    #[test]
    fn a_claim_is_never_signed_by_the_wrong_identity_or_off_chain() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, _) = fixture();
        let wrong = Account::create_by("registry-claim-wrong").unwrap();
        assert!(
            build_signed_hvm_registry_claim_transaction(
                &wrong,
                &binding,
                HvmRegistryCallerRole::Hub,
                &binding.left_address,
                800_000,
                10_000,
                123,
                250
            )
            .is_err()
        );
        for (fee, timestamp, gas) in [(0, 123, 250), (10_000, 0, 250), (10_000, 123, 0)] {
            assert!(
                build_signed_hvm_registry_claim_transaction(
                    &hub,
                    &binding,
                    HvmRegistryCallerRole::Hub,
                    &binding.left_address,
                    800_000,
                    fee,
                    timestamp,
                    gas
                )
                .is_err()
            );
        }
        // A claim built for one chain never reads as a claim on another.
        let signed = build_signed_hvm_registry_claim_transaction(
            &hub,
            &binding,
            HvmRegistryCallerRole::Hub,
            &binding.left_address,
            800_000,
            10_000,
            123,
            250,
        )
        .unwrap();
        let mut other_chain = binding.clone();
        other_chain.chain_id += 1;
        assert!(
            read_exact_registry_claim_transaction(
                &signed.signed_transaction_hex,
                &other_chain,
                &other_chain.left_address,
                800_000,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_registry_calls_compile_sign_and_bind_the_chain() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (hub, binding, bill) = fixture();
        for source in [
            registry_challenge_call_source(&binding, &bill).unwrap(),
            registry_respond_call_source(&binding, &bill).unwrap(),
            registry_finalize_call_source(&binding).unwrap(),
            registry_renew_all_call_source(&binding, 100).unwrap(),
        ] {
            let signed = build_signed_hvm_registry_call_transaction(
                &hub,
                &binding,
                HvmRegistryCallerRole::Hub,
                source,
                1,
                123,
                250,
            )
            .unwrap();
            let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
            let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
            assert_eq!(consumed, raw.len());
            assert_eq!(tx.ty(), 3);
            assert_eq!(tx.actions().len(), 2);
            assert_eq!(tx.actions()[0].kind(), 0x0411);
            assert_eq!(tx.actions()[1].kind(), 44);
            tx.verify_signature().unwrap();
            assert_eq!(hex::encode(tx.hash()), signed.transaction_hash);
        }
    }

    #[test]
    fn wrong_signer_fee_or_lease_range_fails_closed() {
        let (_hub, binding, bill) = fixture();
        let wrong = Account::create_by("registry-watchtower-wrong").unwrap();
        let source = registry_challenge_call_source(&binding, &bill).unwrap();
        assert!(
            build_signed_hvm_registry_call_transaction(
                &wrong,
                &binding,
                HvmRegistryCallerRole::Hub,
                source,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(registry_renew_all_call_source(&binding, 0).is_err());
        assert!(
            registry_renew_all_call_source(&binding, HVM_LEASE_RENEWAL_MAX_PERIODS + 1).is_err()
        );
    }

    #[test]
    fn watchtower_responds_before_deadline_and_never_finalizes_stale_state() {
        let (_hub, binding, latest) = fixture();
        let stale = challenged_snapshot(
            &binding,
            latest.serial - 1,
            latest.left_balance_zhu + 100_000,
            latest.hub_balance_zhu - 100_000,
            99,
            100,
            3,
        );
        assert_eq!(
            decide_registry_watchtower_action(&stale, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill
        );

        let mut expired = stale.clone();
        expired.observed_height = expired.channel.deadline.value;
        // Live evidence is only accepted while evaluation_height is exactly one
        // block past observed_height, so moving the observation forward without
        // the evaluation height makes the snapshot inadmissible and the
        // watchtower refuses to read it at all. That refusal is correct, but it
        // is not what this test is here to check: the subject is that an expired
        // challenge yields RecoveryRequired rather than a finalize.
        expired.evaluation_height = expired.observed_height + 1;
        assert_eq!(
            decide_registry_watchtower_action(&expired, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::RecoveryRequired
        );

        let mut finalized_stale = expired;
        finalized_stale.channel.status.value = 4;
        assert_eq!(
            decide_registry_watchtower_action(&finalized_stale, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::RecoveryRequired
        );
    }

    /// One block is not a margin. The decision function still says "respond"
    /// at a window of one — that is what the contract permits — and the margin
    /// is the separate, named refusal layered on top of it.
    #[test]
    fn a_response_window_of_one_block_is_permitted_by_the_contract_and_refused_by_the_margin() {
        let (_hub, binding, latest) = fixture();
        let at_one = challenged_snapshot(
            &binding,
            latest.serial - 1,
            latest.left_balance_zhu + 100_000,
            latest.hub_balance_zhu - 100_000,
            99,
            100,
            3,
        );
        assert_eq!(
            decide_registry_watchtower_action(&at_one, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill,
            "the contract itself still accepts a response here"
        );
        assert_eq!(registry_response_window_blocks(&at_one), 1);
        assert!(!registry_response_window_is_safe(&at_one));

        // Exactly at the margin is safe; one block short of it is not.
        let mut at_margin = at_one.clone();
        at_margin.channel.deadline.value =
            at_margin.observed_height + HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS;
        assert!(registry_response_window_is_safe(&at_margin));
        let mut under_margin = at_margin;
        under_margin.channel.deadline.value -= 1;
        assert!(!registry_response_window_is_safe(&under_margin));

        // A deadline already behind the observation is a window of zero, never
        // a wrapped u64 that would read as an enormous amount of head-room.
        let mut expired = at_one;
        expired.channel.deadline.value = expired.observed_height - 1;
        assert_eq!(registry_response_window_blocks(&expired), 0);
        assert!(!registry_response_window_is_safe(&expired));
    }

    /// Blocks and seconds catch different lies, so both are checked and
    /// neither substitutes for the other.
    #[test]
    fn evidence_behind_the_node_tip_or_behind_the_clock_is_refused() {
        let (_hub, binding, _latest) = fixture();
        let snapshot = challenged_snapshot(&binding, 1, 900_000, 100_000, 1_000, 1_012, 3);

        require_fresh_registry_evidence(&snapshot, 1_000, 0).unwrap();
        // One block of drift is the two endpoints being read a moment apart.
        require_fresh_registry_evidence(
            &snapshot,
            1_000 + HVM_REGISTRY_MAX_SNAPSHOT_TIP_DRIFT_BLOCKS,
            0,
        )
        .unwrap();
        // Two is a different view of the chain.
        assert!(
            require_fresh_registry_evidence(
                &snapshot,
                1_000 + HVM_REGISTRY_MAX_SNAPSHOT_TIP_DRIFT_BLOCKS + 1,
                0,
            )
            .is_err()
        );
        // Ahead of the tip read is the safe direction and stays allowed: it
        // can only make this tower believe it has less window than it does.
        require_fresh_registry_evidence(&snapshot, 900, 0).unwrap();

        require_fresh_registry_evidence(
            &snapshot,
            1_000,
            HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS,
        )
        .unwrap();
        let stalled = require_fresh_registry_evidence(
            &snapshot,
            1_000,
            HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS + 1,
        )
        .unwrap_err();
        assert!(stalled.to_string().contains("stale"));
        // The generic node gate would have accepted this hour-old tip: the
        // watchtower's limit is the tighter of the two, by construction.
        const {
            assert!(
                HVM_REGISTRY_WATCHTOWER_MAX_TIP_AGE_SECONDS
                    < crate::node::FULLNODE_MAX_TIP_AGE_SECONDS
            )
        };
        require_fresh_registry_evidence(
            &snapshot,
            1_000,
            crate::node::FULLNODE_MAX_TIP_AGE_SECONDS,
        )
        .unwrap_err();
    }

    /// The identity of a situation must not move with the chain height, and
    /// must move with everything the decision actually reads.
    #[test]
    fn a_situation_is_named_by_the_decision_inputs_and_never_by_the_block_height() {
        let (_hub, binding, latest) = fixture();
        let commitment = binding.commitment().unwrap();
        let base = challenged_snapshot(&binding, 1, 900_000, 100_000, 1_000, 1_012, 3);
        let situation = HvmRegistryWatchtowerSituationV2::from_evidence(&base, &latest);

        // Six blocks later, nothing about the situation has changed.
        let mut later = base.clone();
        later.observed_height += 6;
        later.evaluation_height += 6;
        assert_eq!(
            HvmRegistryWatchtowerSituationV2::from_evidence(&later, &latest),
            situation,
            "a passing block is not a new situation"
        );
        assert_eq!(
            HvmRegistryWatchtowerSituationV2::from_evidence(&later, &latest).digest(&commitment),
            situation.digest(&commitment)
        );

        // Every field that moves the decision moves the name.
        let mut moved = [situation; 6];
        moved[0].status = 4;
        moved[1].chain_serial += 1;
        moved[2].left_balance_zhu += 1;
        moved[3].hub_balance_zhu += 1;
        moved[4].deadline += 1;
        moved[5].left_claimed = !situation.left_claimed;
        for changed in moved {
            assert_ne!(changed.digest(&commitment), situation.digest(&commitment));
        }
        // So does the bill this Hub would answer with.
        let mut newer_bill = situation;
        newer_bill.durable_bill_serial += 1;
        assert_ne!(
            newer_bill.digest(&commitment),
            situation.digest(&commitment)
        );
        // And so does the binding, so two channels never share a name.
        assert_ne!(
            situation.digest(&commitment),
            situation.digest("00".repeat(32).as_str())
        );
    }

    #[test]
    fn watchtower_requires_exact_balances_before_finalize_or_final_acceptance() {
        let (_hub, binding, latest) = fixture();
        let exact = challenged_snapshot(
            &binding,
            latest.serial,
            latest.left_balance_zhu,
            latest.hub_balance_zhu,
            100,
            100,
            3,
        );
        assert_eq!(
            decide_registry_watchtower_action(&exact, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::Finalize
        );

        let mut wrong_balances = exact.clone();
        wrong_balances.channel.left_balance.value -= 1;
        wrong_balances.channel.hub_balance.value += 1;
        assert_eq!(
            decide_registry_watchtower_action(&wrong_balances, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::RecoveryRequired
        );

        // FINAL with the exact settled balances is where the old chain of
        // custody stopped: `settle()` had moved the accounting but the coin
        // was still inside the contract. That is a claim, not "nothing to do".
        let mut exact_final = exact;
        exact_final.channel.status.value = 4;
        assert_eq!(
            decide_registry_watchtower_action(&exact_final, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::ClaimLeftPayout
        );

        // Already paid — by us or by any third party, since claims are
        // permissionless. Nothing left to claim.
        let mut already_claimed = exact_final.clone();
        already_claimed.channel.left_claimed.value = true;
        assert_eq!(
            decide_registry_watchtower_action(&already_claimed, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::NoAction
        );
    }

    #[test]
    fn a_final_channel_with_nothing_owed_to_the_left_party_is_never_claimed() {
        let (_hub, binding, mut latest) = fixture();
        // Everything went to the hub, so `settle()` marks the left side
        // claimed itself and `PermitHAC` would throw on a zero payout.
        latest.left_balance_zhu = 0;
        latest.hub_balance_zhu = binding.left_deposit_zhu;
        let hash = latest.signing_hash(&binding).unwrap();
        let left = Account::create_by("registry-watchtower-left").unwrap();
        let hub = Account::create_by("registry-watchtower-hub").unwrap();
        latest.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        latest.hub_signature_hex = hex::encode(Sign::create_by(&hub, &hash).serialize());
        let mut settled = challenged_snapshot(
            &binding,
            latest.serial,
            latest.left_balance_zhu,
            latest.hub_balance_zhu,
            100,
            100,
            4,
        );
        settled.channel.left_claimed.value = true;
        assert_eq!(
            decide_registry_watchtower_action(&settled, &binding, &latest).unwrap(),
            HvmRegistryWatchtowerDecisionV2::NoAction
        );
    }

    /// The probe must be measuring a real capability, not merely succeeding.
    ///
    /// It used to record the opposite finding: that the Hub could build both
    /// halves of an exit and the user could build neither, over the identical
    /// binding. The builders are now role-aware, so the finding has changed,
    /// and this test changed with it rather than being deleted — the shape is
    /// the same and the asymmetry it looks for is the one that still matters.
    ///
    /// Both parties can now build their own half. What no party can do is
    /// claim to be the other one: a signer that states the wrong role is
    /// refused, so the widening is one named role and not an open door.
    #[test]
    fn the_builders_work_for_both_parties_in_their_own_role_and_for_neither_in_the_other() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let left = Account::create_by("registry-user-side-exit-probe-left").unwrap();
        let hub = Account::create_by("registry-user-side-exit-probe-hub").unwrap();
        let left_address = Address::from(*left.address()).to_readable();
        let binding = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 2,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: left_address.clone(),
            right_hub_address: Address::from(*hub.address()).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        binding.validate().expect("probe binding must be reviewed");
        let finalize = registry_finalize_call_source(&binding).unwrap();

        // The Hub, in the Hub's role, builds both halves. This is byte for
        // byte the rule it had before roles existed.
        build_signed_hvm_registry_call_transaction(
            &hub,
            &binding,
            HvmRegistryCallerRole::Hub,
            finalize.clone(),
            1,
            1,
            1,
        )
        .expect("the Hub must be able to build finalize");
        build_signed_hvm_registry_claim_transaction(
            &hub,
            &binding,
            HvmRegistryCallerRole::Hub,
            &left_address,
            binding.left_deposit_zhu,
            1,
            1,
            1,
        )
        .expect("the Hub must be able to build the payout");

        // The user, in the user's role, builds both halves over the identical
        // binding. This is the capability that did not exist.
        build_signed_hvm_registry_call_transaction(
            &left,
            &binding,
            HvmRegistryCallerRole::ChannelLeft,
            finalize.clone(),
            1,
            1,
            1,
        )
        .expect("the channel left party must be able to build finalize");
        build_signed_hvm_registry_claim_transaction(
            &left,
            &binding,
            HvmRegistryCallerRole::ChannelLeft,
            &left_address,
            binding.left_deposit_zhu,
            1,
            1,
            1,
        )
        .expect("the channel left party must be able to build the payout");

        // Neither party may borrow the other's role, and a third key has no
        // role to state at all. The predicate was not removed; it was named.
        let stranger = Account::create_by("registry-user-side-exit-probe-stranger").unwrap();
        for (signer, role, who) in [
            (
                &left,
                HvmRegistryCallerRole::Hub,
                "the user posing as the Hub",
            ),
            (
                &hub,
                HvmRegistryCallerRole::ChannelLeft,
                "the Hub posing as the user",
            ),
            (
                &stranger,
                HvmRegistryCallerRole::ChannelLeft,
                "a stranger posing as the user",
            ),
            (
                &stranger,
                HvmRegistryCallerRole::Hub,
                "a stranger posing as the Hub",
            ),
        ] {
            let call_refusal = build_signed_hvm_registry_call_transaction(
                signer,
                &binding,
                role,
                finalize.clone(),
                1,
                1,
                1,
            )
            .expect_err("{who} must be refused finalize");
            let claim_refusal = build_signed_hvm_registry_claim_transaction(
                signer,
                &binding,
                role,
                &left_address,
                binding.left_deposit_zhu,
                1,
                1,
                1,
            )
            .expect_err("{who} must be refused the payout");
            assert!(
                call_refusal.to_string().contains("signer"),
                "{who}: the refusal must be about the signer, not incidental input: {call_refusal}"
            );
            assert!(
                claim_refusal.to_string().contains("signer"),
                "{who}: the refusal must be about the signer, not incidental input: {claim_refusal}"
            );
        }

        // Which is exactly what the probe reports, now, on its own.
        assert!(
            user_key_can_build_registry_exit_transactions(),
            "the builders are role-aware, so the probe must report true"
        );
    }
}
