//! Pure HVM watchtower decisions and exact Type 3 / Action 44 transaction building.

use basis::interface::{Transaction, TransactionRead};
use field::{AddrOrList, Address, Amount, Field, Serialize as FieldSerialize, Uint1, Uint4};
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;
use vm::ContractAddress;
use vm::action::ContractMainCall;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{HvmChannelBillV1, HvmChannelBindingV1};
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
    RecoveryRequired,
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
        4 => Ok(HvmWatchtowerDecision::NoAction),
        _ => Ok(HvmWatchtowerDecision::RecoveryRequired),
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
}
