//! Pure HVM watchtower decisions and exact Type 3 / Action 44 transaction building.

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
use crate::hvm_channel::{HvmChannelBillV1, HvmChannelBindingV1, parse_address};
use crate::node::HvmChannelLiveSnapshot;

pub const HVM_STORAGE_KEYS: [&str; 18] = [
    "status",
    "network",
    "channel_id",
    "reuse",
    "left",
    "right",
    "left_deposit",
    "right_deposit",
    "left_paid",
    "right_paid",
    "total",
    "serial",
    "left_balance",
    "right_balance",
    "challenge_blocks",
    "deadline",
    "left_claimed",
    "right_claimed",
];
pub const HVM_WATCHTOWER_REQUEST_SCHEMA: &str = "hpay-hvm-watchtower-request/1";
/// First line of the canonical Action 14 payout descriptor. It is not a fitsh
/// program and must never be compiled; the schema name is what stops it being
/// mistaken for one.
pub const HVM_CLAIM_PAYOUT_DESCRIPTOR_SCHEMA: &str = "hpay-hvm-channel-claim/1";
pub const HVM_LEASE_RENEWAL_REQUEST_SCHEMA: &str = "hpay-hvm-lease-renewal-request/1";
/// Conservative all-18-key renewal cap. The VM permits more periods per
/// individual storage call, but one HPAY renewal performs both recovery and
/// live-credit updates for every key under the fixed Type 3 storage-gas cap.
pub const HVM_LEASE_RENEWAL_MAX_PERIODS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HvmWatchtowerMode {
    Monitor,
    BeginChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmWatchtowerRequestV1 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub binding_commitment: String,
    pub mode: HvmWatchtowerMode,
    pub network_fee_zhu: u64,
    pub timestamp: u64,
    pub gas_max: u8,
    pub created_unix: u64,
}

impl HvmWatchtowerRequestV1 {
    pub fn validate(&self) -> HubResult<()> {
        if self.schema != HVM_WATCHTOWER_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.binding_commitment.len() != 64
            || !self
                .binding_commitment
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.network_fee_zhu == 0
            || self.timestamp == 0
            || self.gas_max == 0
            || self.created_unix == 0
        {
            return Err(HubError::State("HVM watchtower request is invalid".into()));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("watchtower encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HvmWatchtowerResponseV1 {
    pub operation_id: String,
    pub status: String,
    pub action: String,
    pub transaction_hash: Option<String>,
    pub confirmed_block_height: Option<u64>,
    pub observed_confirmations: u64,
    /// When this operation's bytes were put on the wire.
    ///
    /// The durable record has always carried this and nothing ever read it,
    /// which is how a transaction dropped from the mempool came to look
    /// exactly like one that is merely waiting for a block: both answer
    /// `submitted`, pass after pass, for as long as the process runs. Surfacing
    /// it here is what lets a caller — the scheduler, an operator reading the
    /// API — tell "not mined yet" from "not going to be mined". It changes no
    /// decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_unix: Option<u64>,
    /// Exact payee of a `claim` action, so an operator reading this answer can
    /// see where the coin went without decoding the transaction. Absent for
    /// every other action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_payee: Option<String>,
    /// Exact zhu a `claim` action moves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_amount_zhu: Option<u64>,
    /// Observed height at which the exact approved payout was found already
    /// recorded on chain by somebody else. Claims are permissionless, so a
    /// third party can pay the payee first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_settled_elsewhere_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmLeaseRenewalRequestV1 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub binding_commitment: String,
    pub renew_when_live_blocks_at_or_below: u64,
    pub periods: u64,
    pub network_fee_zhu: u64,
    pub timestamp: u64,
    pub gas_max: u8,
    pub created_unix: u64,
}

impl HvmLeaseRenewalRequestV1 {
    pub fn validate(&self) -> HubResult<()> {
        if self.schema != HVM_LEASE_RENEWAL_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.binding_commitment.len() != 64
            || self.renew_when_live_blocks_at_or_below == 0
            || self.periods == 0
            || self.periods > HVM_LEASE_RENEWAL_MAX_PERIODS
            || self.network_fee_zhu == 0
            || self.timestamp == 0
            || self.gas_max == 0
            || self.created_unix == 0
        {
            return Err(HubError::State(
                "HVM lease renewal request is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("lease request encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HvmWatchtowerDecision {
    NoAction,
    RespondWithLatestBill,
    Finalize,
    /// The channel is FINAL and the left party's settled share is still sitting
    /// inside the contract. `finalize` froze the split; it moved no coin. Only
    /// an Action 14 payout, admitted by the contract's `PermitHAC` hook, walks
    /// the principal back out.
    ClaimLeftPayout,
    RecoveryRequired,
}

/// Does the split standing on chain say exactly what this Hub's own head bill
/// says?
///
/// At FINAL nothing can change the split any more, so this is the whole
/// question of whether the Hub's accounting and the contract agree. Two
/// fully-signed bills carrying one serial and different balances is the only
/// way this can read false with a matching serial, and that is a disagreement
/// a person has to settle, not one a watchtower may spend a key on.
fn chain_matches_latest(snapshot: &HvmChannelLiveSnapshot, latest: &HvmChannelBillV1) -> bool {
    snapshot.storage.serial.value == latest.serial
        && snapshot.storage.left_balance.value == latest.left_balance_zhu
        && snapshot.storage.right_balance.value == latest.right_balance_zhu
}

/// Say which of the several different situations actually produced a
/// [`HvmWatchtowerDecision::RecoveryRequired`].
///
/// [`decide_watchtower_action`] returns that one value from three unrelated
/// places: a chain serial ahead of the Hub's own head bill, a FINAL channel
/// whose split disagrees with that bill, and a chain status the Hub has no
/// handling for at all. The caller used to report all three with the single
/// sentence "chain serial is newer than the authenticated HVM ledger", which is
/// true of the first and is the opposite of the truth for the second, where the
/// serial is behind or equal. An operator reading that went looking for the
/// wrong problem.
///
/// This re-derives the reason from the same two inputs the decision was made
/// from, so it cannot drift away from the branch that fired. It is a
/// diagnostic and changes no decision.
pub fn recovery_required_reason(
    snapshot: &HvmChannelLiveSnapshot,
    latest: &HvmChannelBillV1,
) -> String {
    let chain_serial = snapshot.storage.serial.value;
    let status = snapshot.storage.status.value;
    if chain_serial > latest.serial {
        return format!(
            "chain serial {chain_serial} is newer than the authenticated HVM ledger head bill \
             serial {}",
            latest.serial
        );
    }
    if status == 4 {
        return format!(
            "chain is FINAL on a split the authenticated HVM ledger does not hold: chain serial \
             {chain_serial} left {} right {}, head bill serial {} left {} right {}. No payout is \
             made on a state the Hub cannot explain; a person has to settle this",
            snapshot.storage.left_balance.value,
            snapshot.storage.right_balance.value,
            latest.serial,
            latest.left_balance_zhu,
            latest.right_balance_zhu,
        ) + ". The left party's principal is not stranded by this refusal: the Action 14 payout \
             needs no signature from the contract, so the left party can trigger it themselves \
             at any time";
    }
    format!("chain status {status} has no watchtower handling at chain serial {chain_serial}")
}

pub fn decide_watchtower_action(
    snapshot: &HvmChannelLiveSnapshot,
    binding: &HvmChannelBindingV1,
    latest: &HvmChannelBillV1,
) -> HubResult<HvmWatchtowerDecision> {
    snapshot.validate_runtime_binding(binding, 1, 1)?;
    latest.validate_fully_signed(binding)?;
    let chain_serial = snapshot.storage.serial.value;
    if chain_serial > latest.serial {
        return Ok(HvmWatchtowerDecision::RecoveryRequired);
    }
    match snapshot.storage.status.value {
        2 => Ok(HvmWatchtowerDecision::NoAction),
        3 if snapshot.observed_height >= snapshot.storage.deadline.value => {
            Ok(HvmWatchtowerDecision::Finalize)
        }
        3 if chain_serial < latest.serial => Ok(HvmWatchtowerDecision::RespondWithLatestBill),
        3 => Ok(HvmWatchtowerDecision::NoAction),
        // FINAL. This used to be `NoAction`, and that answer was measured to
        // leave settled principal inside a finalized contract with nothing in
        // the product able to reach it. `finalize` only writes `status`; the
        // coin moves on an Action 14 whose `PermitHAC` hook pins the payee to
        // `left` and the amount to `left_balance`, and marks `left_claimed` so
        // it can happen exactly once. When `left_claimed` is already true the
        // payout has happened — by us or by any third party, since the payout
        // needs no signature from the contract and is therefore permissionless
        // — and there is nothing left to do. A zero left balance is likewise
        // nothing to claim: `PermitHAC` refuses a zero-amount payout.
        4 if chain_matches_latest(snapshot, latest)
            && !snapshot.storage.left_claimed.value
            && snapshot.storage.left_balance.value > 0 =>
        {
            Ok(HvmWatchtowerDecision::ClaimLeftPayout)
        }
        4 if chain_matches_latest(snapshot, latest) => Ok(HvmWatchtowerDecision::NoAction),
        // A FINAL channel settled on a split this Hub's ledger does not hold.
        // On this one-directional rail a chain behind the head bill pays the
        // left party *more* than the Hub's own books say it owes, so claiming
        // here would be the Hub giving away its own earned balance on an
        // unexplained state. That is a person's decision.
        4 => Ok(HvmWatchtowerDecision::RecoveryRequired),
        _ => Ok(HvmWatchtowerDecision::RecoveryRequired),
    }
}

/// The exact durable facts that make one v1 watchtower situation different
/// from another.
///
/// The twin of `HvmRegistryWatchtowerSituationV2`, and it exists for the same
/// reason: a scheduler has no human-typed operation label to name its work
/// after, so the name is derived from the facts the decision was read from.
///
/// Every field here is an input [`decide_watchtower_action`] actually reads. If
/// none of them moved the decision cannot have moved either, so a retry is the
/// same situation and must be the same operation — otherwise the second pass
/// opens a second record, admission refuses it because the first is still
/// unresolved, and a signed transaction is left on the wire with nobody
/// reconciling it. Conversely every confirmed action moves at least one of
/// them (a respond moves `chain_serial`, a finalize moves `status`, a claim
/// moves `left_claimed`), so the next step of the lifecycle always earns a
/// fresh name instead of landing on a finished record and being handed its old
/// outcome back.
///
/// `observed_height` is deliberately **absent**. It changes with every block,
/// so folding it in would make every pass a brand-new situation. It feeds the
/// finalize deadline test, which is a safety gate rather than an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvmWatchtowerSituationV1 {
    pub status: u8,
    pub chain_serial: u64,
    pub left_balance_zhu: u64,
    pub right_balance_zhu: u64,
    pub deadline: u64,
    pub left_claimed: bool,
    pub durable_bill_serial: u64,
}

impl HvmWatchtowerSituationV1 {
    pub fn from_evidence(snapshot: &HvmChannelLiveSnapshot, latest: &HvmChannelBillV1) -> Self {
        Self {
            status: snapshot.storage.status.value,
            chain_serial: snapshot.storage.serial.value,
            left_balance_zhu: snapshot.storage.left_balance.value,
            right_balance_zhu: snapshot.storage.right_balance.value,
            deadline: snapshot.storage.deadline.value,
            left_claimed: snapshot.storage.left_claimed.value,
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
        hasher.update(b"hpay-hvm-watchtower-situation/1");
        hasher.update((binding_commitment.len() as u64).to_be_bytes());
        hasher.update(binding_commitment.as_bytes());
        hasher.update([self.status]);
        hasher.update(self.chain_serial.to_be_bytes());
        hasher.update(self.left_balance_zhu.to_be_bytes());
        hasher.update(self.right_balance_zhu.to_be_bytes());
        hasher.update(self.deadline.to_be_bytes());
        hasher.update([u8::from(self.left_claimed)]);
        hasher.update(self.durable_bill_serial.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

pub fn challenge_call_source(
    binding: &HvmChannelBindingV1,
    bill: &HvmChannelBillV1,
) -> HubResult<String> {
    bill.validate_fully_signed(binding)?;
    checked_single_call_source(binding, &bill_call("challenge", bill))
}

pub fn respond_call_source(
    binding: &HvmChannelBindingV1,
    bill: &HvmChannelBillV1,
) -> HubResult<String> {
    bill.validate_fully_signed(binding)?;
    checked_single_call_source(binding, &bill_call("respond", bill))
}

pub fn finalize_call_source(binding: &HvmChannelBindingV1) -> HubResult<String> {
    checked_single_call_source(binding, "finalize()")
}

pub fn renew_all_call_source(binding: &HvmChannelBindingV1, periods: u64) -> HubResult<String> {
    if periods == 0 || periods > HVM_LEASE_RENEWAL_MAX_PERIODS {
        return Err(HubError::State(format!(
            "HVM lease renewal periods must be between 1 and {HVM_LEASE_RENEWAL_MAX_PERIODS}"
        )));
    }
    let calls = HVM_STORAGE_KEYS
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let quote = char::from(34);
            format!(
                "var renew_{index} = Channel.renew({quote}{key}{quote}, {periods})\nassert renew_{index} == 0"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    contract_call_source(binding, &calls)
}

/// Canonical descriptor of the Action 14 payout that empties the left party's
/// settled share out of a FINAL V1 channel contract.
///
/// A payout is not a fitsh call: it carries no Action 44 and compiles nothing.
/// It still needs one canonical, re-derivable string, because the durable
/// operation record is re-checked against its binding on every state load
/// exactly like the compiled call sources of the other kinds. This is that
/// string, and it commits to every field the payout depends on.
///
/// # Why the payee is only ever the left party
///
/// `PermitHAC` has a right-hand branch too, and on this per-channel contract
/// `right_claimed` makes it exactly as idempotent as the left one. It is
/// deliberately not built here. A watchtower exists to protect the
/// counterparty's principal; the Hub's own `right_balance` share is a treasury
/// operation, and giving the watchtower key an arm that pays the Hub itself is
/// a new authority, not a bug fix. The V1 rail therefore has no automated
/// claim for the Hub's own share, and that limitation is stated rather than
/// left to be discovered.
pub fn claim_left_payout_source(
    binding: &HvmChannelBindingV1,
    payee: &str,
    amount_zhu: u64,
) -> HubResult<String> {
    binding.validate()?;
    if payee != binding.left_address {
        return Err(HubError::State(
            "HVM claim payee must be the exact channel left address".into(),
        ));
    }
    exact_claim_amount(amount_zhu)?;
    Ok(format!(
        "{HVM_CLAIM_PAYOUT_DESCRIPTOR_SCHEMA}\ncontract={}\nchain_id={}\nnetwork_instance={}\nchannel_id={}\nreuse={}\nto={payee}\nzhu={amount_zhu}",
        binding.contract_address,
        binding.chain_id,
        binding.network_instance_id,
        binding.channel_id,
        binding.reuse_version,
    ))
}

/// An `Amount` that does not read back as the exact same zhu count cannot be
/// used to satisfy `PermitHAC`, which demands `amount == left_balance` to the
/// zhu. Refusing here is the point: an amount that cannot be carried exactly
/// on the wire is unpayable, and guessing at it would either throw on chain or
/// move a different number than the one the contract owes.
fn exact_claim_amount(amount_zhu: u64) -> HubResult<Amount> {
    if amount_zhu == 0 {
        return Err(HubError::State("HVM claim amount must be positive".into()));
    }
    let amount = Amount::zhu(amount_zhu);
    let readback = amount
        .to_zhu_u64()
        .map_err(|error| HubError::State(format!("HVM claim amount is not readable: {error}")))?;
    if readback != amount_zhu {
        return Err(HubError::State(
            "HVM claim amount is not exactly representable on the wire".into(),
        ));
    }
    Ok(amount)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHvmCallTransaction {
    pub transaction_hash: String,
    pub signed_transaction_hex: String,
    pub call_source: String,
}

pub fn build_signed_hvm_call_transaction(
    signer: &Account,
    binding: &HvmChannelBindingV1,
    call_source: String,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<SignedHvmCallTransaction> {
    binding.validate()?;
    if signer.readable() != binding.right_hub_address
        || network_fee_zhu == 0
        || timestamp == 0
        || gas_max == 0
    {
        return Err(HubError::State(
            "HVM call signer, fee, timestamp or gas limit is invalid".into(),
        ));
    }
    let main = Address::from_readable(signer.readable())
        .map_err(|error| HubError::State(format!("invalid watchtower address: {error}")))?;
    let contract = Address::from_readable(&binding.contract_address)
        .map_err(|error| HubError::State(format!("invalid HVM contract address: {error}")))?;
    ContractAddress::from_addr(contract)
        .map_err(|_| HubError::State("watchtower target is not an HVM contract address".into()))?;
    let codes = vm::lang::lang_to_bytecode(&call_source)
        .map_err(|error| HubError::State(format!("HVM call compilation failed: {error}")))?;
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
        .map_err(|error| HubError::State(format!("HVM watchtower signing failed: {error}")))?;
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM Type 3 signature failed: {error}")))?;
    Ok(SignedHvmCallTransaction {
        transaction_hash: hex::encode(transaction.hash()),
        signed_transaction_hex: hex::encode(transaction.serialize()),
        call_source,
    })
}

/// Build the exact Action 14 payout that walks the left party's settled share
/// out of a FINAL V1 channel contract.
///
/// Shape is deliberately identical to [`build_signed_hvm_call_transaction`]
/// except for the payload action: Type 3, non-zero gas, `[ChainAllow(0x0411)
/// bound to binding.chain_id, HacFromToTrs(14)]`. There is no fitsh call and
/// no Action 44.
///
/// The payout is permissionless by construction. Action 14 declares
/// `req_sign = [self.from]`, but `TransactionType3::intrinsic_req_sign` only
/// adds an address to the required-signer set when it `is_privakey()`, and a
/// contract address is not. So the contract never signs: its consent *is* the
/// `PermitHAC` hook. The signer here is `tx.main`, and `tx.main` only pays the
/// fee — it has no authority over where the coin goes or how much of it moves.
/// Requiring the Hub key is therefore about who spends the fee, not about who
/// is paid.
// Each argument is a distinct fact the signed bytes commit to; bundling them
// into a struct would only move the same list somewhere the caller fills in by
// name instead of by position.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_hvm_claim_transaction(
    signer: &Account,
    binding: &HvmChannelBindingV1,
    payee: &str,
    amount_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<SignedHvmCallTransaction> {
    let call_source = claim_left_payout_source(binding, payee, amount_zhu)?;
    if signer.readable() != binding.right_hub_address
        || network_fee_zhu == 0
        || timestamp == 0
        || gas_max == 0
    {
        return Err(HubError::State(
            "HVM claim signer, fee, timestamp or gas limit is invalid".into(),
        ));
    }
    let main = parse_address(signer.readable(), "claim signer")?;
    let contract = parse_address(&binding.contract_address, "claim contract")?;
    ContractAddress::from_addr(contract)
        .map_err(|_| HubError::State("HVM claim target is not an HVM contract address".into()))?;
    let to = parse_address(payee, "claim payee")?;
    if to == contract || ContractAddress::from_addr(to).is_ok() {
        return Err(HubError::State(
            "HVM claim payee must not be a contract address".into(),
        ));
    }
    let hacash = exact_claim_amount(amount_zhu)?;
    let mut action = HacFromToTrs::new();
    // Embedded Val1 addresses only: a pointer would make the payout depend on
    // an address list this builder does not control.
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
        .map_err(|error| HubError::State(format!("HVM claim signing failed: {error}")))?;
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM Type 3 signature failed: {error}")))?;
    let signed_transaction_hex = hex::encode(transaction.serialize());
    // Read the bytes we are about to hand out back through the same reader the
    // recovery path uses. A builder that cannot be read exactly is not exact.
    read_exact_hvm_claim_transaction(&signed_transaction_hex, binding, payee, amount_zhu)?;
    Ok(SignedHvmCallTransaction {
        transaction_hash: hex::encode(transaction.hash()),
        signed_transaction_hex,
        call_source,
    })
}

/// Read side of the payout: decode signed bytes and prove they are exactly the
/// approved payout and nothing else.
///
/// `AddrOrPtr::Val2` is refused outright. A pointer resolves against the
/// transaction's own address list, so accepting one would mean the payee is
/// whatever that list happens to say, and the payout would no longer be pinned
/// by these bytes alone.
pub fn read_exact_hvm_claim_transaction(
    signed_transaction_hex: &str,
    binding: &HvmChannelBindingV1,
    payee: &str,
    amount_zhu: u64,
) -> HubResult<()> {
    binding.validate()?;
    let contract = parse_address(&binding.contract_address, "claim contract")?;
    let expected_payee = parse_address(payee, "claim payee")?;
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|_| HubError::State("HVM claim bytes are not hex".into()))?;
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| HubError::State(format!("HVM claim bytes are invalid: {error}")))?;
    if consumed != raw.len() {
        return Err(HubError::State(
            "HVM claim bytes carry trailing data".into(),
        ));
    }
    if transaction.ty() != 3 {
        return Err(HubError::State(
            "HVM claim must be a Type 3 transaction".into(),
        ));
    }
    if transaction.gas_max_byte().is_none_or(|gas| gas == 0) {
        return Err(HubError::State(
            "HVM claim must carry a non-zero gas limit".into(),
        ));
    }
    let actions = transaction.actions();
    if actions.len() != 2 || actions[0].kind() != 0x0411 || actions[1].kind() != 14 {
        return Err(HubError::State(
            "HVM claim must be exactly a chain guard and one Action 14".into(),
        ));
    }
    let guard = actions[0]
        .as_any()
        .downcast_ref::<ChainAllow>()
        .ok_or_else(|| HubError::State("HVM claim chain guard is unreadable".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != binding.chain_id {
        return Err(HubError::State(
            "HVM claim is not bound to the exact binding chain".into(),
        ));
    }
    let transfer = actions[1]
        .as_any()
        .downcast_ref::<HacFromToTrs>()
        .ok_or_else(|| HubError::State("HVM claim payout action is unreadable".into()))?;
    let from = exact_embedded_address(&transfer.from, "source")?;
    let to = exact_embedded_address(&transfer.to, "payee")?;
    if from != contract {
        return Err(HubError::State(
            "HVM claim must draw from the exact channel contract".into(),
        ));
    }
    if to != expected_payee {
        return Err(HubError::State(
            "HVM claim pays a different address than approved".into(),
        ));
    }
    let paid = transfer
        .hacash
        .to_zhu_u64()
        .map_err(|error| HubError::State(format!("HVM claim amount is unreadable: {error}")))?;
    if paid != amount_zhu || paid == 0 {
        return Err(HubError::State(
            "HVM claim amount is not the exact approved payout".into(),
        ));
    }
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM claim signature failed: {error}")))?;
    Ok(())
}

fn exact_embedded_address(value: &AddrOrPtr, label: &str) -> HubResult<Address> {
    match value {
        AddrOrPtr::Val1(address) => Ok(*address),
        AddrOrPtr::Val2(_) => Err(HubError::State(format!(
            "HVM claim {label} cannot use an address pointer"
        ))),
    }
}

fn bill_call(function: &str, bill: &HvmChannelBillV1) -> String {
    format!(
        "{function}({}, {}, {}, 0x{}, 0x{})",
        bill.serial,
        bill.left_balance_zhu,
        bill.right_balance_zhu,
        bill.left_signature_hex,
        bill.right_signature_hex
    )
}

fn contract_call_source(binding: &HvmChannelBindingV1, call: &str) -> HubResult<String> {
    binding.validate()?;
    Ok(format!(
        "lib Channel = 1: {}\n{call}\nend",
        binding.contract_address
    ))
}

fn checked_single_call_source(binding: &HvmChannelBindingV1, call: &str) -> HubResult<String> {
    contract_call_source(
        binding,
        &format!("var result = Channel.{call}\nassert result == 0"),
    )
}

#[cfg(test)]
mod tests {
    use field::{Address, Serialize as _, Sign};

    use super::*;
    use crate::hvm_channel::{HVM_CHANNEL_BILL_SCHEMA, HVM_CHANNEL_BINDING_SCHEMA};
    use crate::node::{
        HACASH_MAINNET_MIN_SAFE_HEIGHT, HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
        HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
    };

    fn binding_and_bill() -> (Account, HvmChannelBindingV1, HvmChannelBillV1) {
        let left = Account::create_by("hvm-watchtower-left").unwrap();
        let right = Account::create_by("hvm-watchtower-right").unwrap();
        let binding = HvmChannelBindingV1 {
            schema: HVM_CHANNEL_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.into(),
            network_mode: "mainnet".into(),
            chain_id: 0,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([7; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: HACASH_MAINNET_MIN_SAFE_HEIGHT,
            bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 7,
            left_address: Address::from(*left.address()).to_readable(),
            right_hub_address: Address::from(*right.address()).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut bill = HvmChannelBillV1 {
            schema: HVM_CHANNEL_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 2,
            left_balance_zhu: 800_000,
            right_balance_zhu: 200_000,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&binding).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());
        (right, binding, bill)
    }

    #[test]
    fn watchtower_builds_signed_challenge_respond_finalize_and_all_18_renewals() {
        let (right, binding, bill) = binding_and_bill();
        for source in [
            challenge_call_source(&binding, &bill).unwrap(),
            respond_call_source(&binding, &bill).unwrap(),
            finalize_call_source(&binding).unwrap(),
            renew_all_call_source(&binding, 100).unwrap(),
        ] {
            let built = build_signed_hvm_call_transaction(
                &right,
                &binding,
                source,
                10_000,
                1_900_000_000,
                u8::MAX,
            )
            .unwrap();
            assert_eq!(built.transaction_hash.len(), 64);
            assert!(!built.signed_transaction_hex.is_empty());

            crate::protocol_registry::ensure_hacash_protocol_setup();
            let raw = hex::decode(&built.signed_transaction_hex).unwrap();
            let (transaction, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
            assert_eq!(consumed, raw.len());
            assert_eq!(transaction.ty(), 3);
            assert_eq!(
                transaction
                    .actions()
                    .iter()
                    .map(|action| action.kind())
                    .collect::<Vec<_>>(),
                vec![0x0411, 44]
            );
            let guard = protocol::action::ChainAllow::downcast(&transaction.actions()[0])
                .expect("first HVM action must be ChainAllow");
            let chains = guard.chains.as_list();
            assert_eq!(chains.len(), 1);
            assert_eq!(chains[0].uint(), binding.chain_id);
        }
        let renew = renew_all_call_source(&binding, 100).unwrap();
        for key in HVM_STORAGE_KEYS {
            let quote = char::from(34);
            assert!(renew.contains(&format!("renew({quote}{key}{quote}, 100)")));
        }
        assert!(renew_all_call_source(&binding, HVM_LEASE_RENEWAL_MAX_PERIODS).is_ok());
        assert!(renew_all_call_source(&binding, HVM_LEASE_RENEWAL_MAX_PERIODS + 1).is_err());
    }

    /// The payout that used to have no builder at all. It is an Action 14 and
    /// not an Action 44, it is pinned to the channel's own left address, and
    /// the bytes read back as exactly the approved payout or not at all.
    #[test]
    fn watchtower_builds_an_exact_action_14_left_payout_and_refuses_every_other_payee() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let (right, binding, _bill) = binding_and_bill();
        let payee = binding.left_address.clone();
        let built = build_signed_hvm_claim_transaction(
            &right,
            &binding,
            &payee,
            800_000,
            10_000,
            1_900_000_000,
            u8::MAX,
        )
        .unwrap();
        assert_eq!(built.transaction_hash.len(), 64);
        assert_eq!(
            built.call_source,
            claim_left_payout_source(&binding, &payee, 800_000).unwrap()
        );
        assert!(
            built
                .call_source
                .starts_with(HVM_CLAIM_PAYOUT_DESCRIPTOR_SCHEMA)
        );
        // The descriptor is not a program. Compiling it must fail rather than
        // ever be mistaken for a contract call.
        assert!(vm::lang::lang_to_bytecode(&built.call_source).is_err());

        let raw = hex::decode(&built.signed_transaction_hex).unwrap();
        let (transaction, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(transaction.ty(), 3);
        assert_eq!(
            transaction
                .actions()
                .iter()
                .map(|action| action.kind())
                .collect::<Vec<_>>(),
            vec![0x0411, 14]
        );
        read_exact_hvm_claim_transaction(&built.signed_transaction_hex, &binding, &payee, 800_000)
            .unwrap();
        // One zhu out and the bytes are no longer the approved payout.
        assert!(
            read_exact_hvm_claim_transaction(
                &built.signed_transaction_hex,
                &binding,
                &payee,
                799_999
            )
            .is_err()
        );
        assert!(
            read_exact_hvm_claim_transaction(
                &built.signed_transaction_hex,
                &binding,
                &binding.right_hub_address.clone(),
                800_000
            )
            .is_err()
        );

        // The Hub's own share has no automated claim on this rail, and the
        // builder refuses to invent one.
        assert!(claim_left_payout_source(&binding, &binding.right_hub_address, 200_000).is_err());
        assert!(claim_left_payout_source(&binding, &binding.contract_address, 800_000).is_err());
        assert!(claim_left_payout_source(&binding, &payee, 0).is_err());
    }
}
