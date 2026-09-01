//! Exact per-channel binding for the separate HPAY HVM settlement profile.
//!
//! This type does not enable mainnet. It prevents a future integration from
//! relabelling a native ChannelPay channel or trusting only a global template
//! deployment.

use basis::method::verify_signature;
use field::{Address, Hash, Parse, Sign};
use serde::{Deserialize, Serialize};
use vm::ContractAddress;

use crate::error::{HubError, HubResult};
use crate::node::{
    HACASH_MAINNET_MIN_SAFE_HEIGHT, HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
    HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
};

pub const HVM_CHANNEL_BINDING_SCHEMA: &str = "hpay-hvm-channel-binding/1";
pub const HVM_CHANNEL_BILL_SCHEMA: &str = "hpay-hvm-channel-bill/1";
pub const HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA: &str = "hpay-hvm-channel-recovery-bundle/1";
const HVM_CHANNEL_BINDING_DOMAIN: &[u8] = b"HPAY/HVM-CHANNEL-BINDING/V1";
const HVM_CHANNEL_BILL_DOMAIN: &[u8] = b"HPAY/HVM-CHANNEL/V1";
const HACASH_SIGN_WIRE_BYTES: usize = 33 + 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelBindingV1 {
    pub schema: String,
    pub settlement_profile: String,
    pub network_mode: String,
    pub chain_id: u32,
    pub network_instance_id: String,
    pub contract_address: String,
    pub deployment_tx_hash: String,
    pub deployment_height: u64,
    pub bytecode_sha3: String,
    pub channel_id: String,
    pub reuse_version: u32,
    pub left_address: String,
    pub right_hub_address: String,
    pub left_deposit_zhu: u64,
    pub right_hub_deposit_zhu: u64,
    pub challenge_blocks: u64,
}

impl HvmChannelBindingV1 {
    pub fn validate(&self) -> HubResult<()> {
        let network_profile_valid = match self.network_mode.as_str() {
            "mainnet" => {
                self.chain_id == 0 && self.deployment_height >= HACASH_MAINNET_MIN_SAFE_HEIGHT
            }
            "testnet" => self.chain_id != 0 && self.deployment_height > 0,
            _ => false,
        };
        if self.schema != HVM_CHANNEL_BINDING_SCHEMA
            || self.settlement_profile != HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE
            || !network_profile_valid
            || !is_lower_hex(&self.network_instance_id, 32)
            || !is_lower_hex(&self.deployment_tx_hash, 32)
            || self.bytecode_sha3 != HPAY_CHANNEL_EXIT_BYTECODE_SHA3
            || !is_lower_hex(&self.channel_id, 16)
            || self.left_deposit_zhu == 0
            || self.right_hub_deposit_zhu != 0
            || self.challenge_blocks == 0
        {
            return Err(HubError::Node(
                "HVM channel binding does not match the reviewed HPAY V1 profile".into(),
            ));
        }
        let contract = parse_address(&self.contract_address, "contract")?;
        ContractAddress::from_addr(contract).map_err(|_| {
            HubError::Node("HVM channel binding address is not a contract address".into())
        })?;
        let left = parse_address(&self.left_address, "left")?;
        let right = parse_address(&self.right_hub_address, "right Hub")?;
        if left == right || left == contract || right == contract {
            return Err(HubError::Node(
                "HVM channel binding parties and contract must be distinct".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate()?;
        let network = decode_hex(&self.network_instance_id)?;
        let deployment_tx = decode_hex(&self.deployment_tx_hash)?;
        let bytecode = decode_hex(&self.bytecode_sha3)?;
        let channel = decode_hex(&self.channel_id)?;
        let contract = parse_address(&self.contract_address, "contract")?;
        let left = parse_address(&self.left_address, "left")?;
        let right = parse_address(&self.right_hub_address, "right Hub")?;

        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(HVM_CHANNEL_BINDING_DOMAIN);
        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(contract.as_bytes());
        bytes.extend_from_slice(&deployment_tx);
        bytes.extend_from_slice(&self.deployment_height.to_be_bytes());
        bytes.extend_from_slice(&bytecode);
        bytes.extend_from_slice(&channel);
        bytes.extend_from_slice(&self.reuse_version.to_be_bytes());
        bytes.extend_from_slice(left.as_bytes());
        bytes.extend_from_slice(right.as_bytes());
        bytes.extend_from_slice(&self.left_deposit_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.right_hub_deposit_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.challenge_blocks.to_be_bytes());
        Ok(hex::encode(sys::sha2(&bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelBillV1 {
    pub schema: String,
    pub binding_commitment: String,
    pub serial: u64,
    pub left_balance_zhu: u64,
    pub right_balance_zhu: u64,
    pub left_signature_hex: String,
    pub right_signature_hex: String,
}

/// Cryptographic recovery material for one exact HVM channel incarnation.
///
/// Validation proves the binding and the two-party initial recovery bill. It
/// deliberately does not claim that the contract is live, funded, confirmed,
/// or that all storage leases are active. Those are separate live activation
/// gates and must be re-verified against the pinned full node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelRecoveryBundleV1 {
    pub schema: String,
    pub binding: HvmChannelBindingV1,
    pub initial_recovery_bill: HvmChannelBillV1,
}

impl HvmChannelRecoveryBundleV1 {
    pub fn validate_crypto(&self) -> HubResult<()> {
        if self.schema != HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA {
            return Err(HubError::Node(
                "HVM channel recovery bundle schema is unsupported".into(),
            ));
        }
        self.binding.validate()?;
        if !self
            .initial_recovery_bill
            .is_initial_recovery_bill(&self.binding)
        {
            return Err(HubError::Node(
                "HVM channel recovery bundle lacks the exact fully signed initial bill".into(),
            ));
        }
        Ok(())
    }
}

impl HvmChannelBillV1 {
    /// Durable commitment to the complete bill, including both signature
    /// slots. This is intentionally distinct from `signing_hash`, which is the
    /// consensus-facing message signed by the two channel parties.
    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("HVM bill encode failed: {error}")))?;
        Ok(hex::encode(sys::sha2(&bytes)))
    }

    pub fn signing_hash(&self, binding: &HvmChannelBindingV1) -> HubResult<Hash> {
        binding.validate()?;
        if self.schema != HVM_CHANNEL_BILL_SCHEMA
            || self.binding_commitment != binding.commitment()?
            || self.serial == 0
        {
            return Err(HubError::Node(
                "HVM bill is not bound to the exact reviewed channel".into(),
            ));
        }
        let total = self
            .left_balance_zhu
            .checked_add(self.right_balance_zhu)
            .ok_or_else(|| HubError::Node("HVM bill balance overflow".into()))?;
        let deposit = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM channel deposit overflow".into()))?;
        if total != deposit {
            return Err(HubError::Node(
                "HVM bill does not conserve the exact channel deposit".into(),
            ));
        }
        let network = decode_hex(&binding.network_instance_id)?;
        let channel = decode_hex(&binding.channel_id)?;
        let contract = parse_address(&binding.contract_address, "contract")?;
        let left = parse_address(&binding.left_address, "left")?;
        let right = parse_address(&binding.right_hub_address, "right Hub")?;
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(HVM_CHANNEL_BILL_DOMAIN);
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(contract.as_bytes());
        bytes.extend_from_slice(&channel);
        bytes.extend_from_slice(&binding.reuse_version.to_be_bytes());
        bytes.extend_from_slice(left.as_bytes());
        bytes.extend_from_slice(right.as_bytes());
        bytes.extend_from_slice(&deposit.to_be_bytes());
        bytes.extend_from_slice(&binding.challenge_blocks.to_be_bytes());
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.extend_from_slice(&self.left_balance_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.right_balance_zhu.to_be_bytes());
        Ok(Hash::from(sys::sha3(bytes)))
    }

    pub fn validate_fully_signed(&self, binding: &HvmChannelBindingV1) -> HubResult<()> {
        let hash = self.signing_hash(binding)?;
        let left = parse_address(&binding.left_address, "left")?;
        let right = parse_address(&binding.right_hub_address, "right Hub")?;
        let left_signature = parse_signature(&self.left_signature_hex)?;
        let right_signature = parse_signature(&self.right_signature_hex)?;
        if !verify_signature(&hash, &left, &left_signature)
            || !verify_signature(&hash, &right, &right_signature)
        {
            return Err(HubError::Node(
                "HVM bill signatures do not match both bound channel parties".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_left_signed(&self, binding: &HvmChannelBindingV1) -> HubResult<()> {
        let hash = self.signing_hash(binding)?;
        let left = parse_address(&binding.left_address, "left")?;
        let left_signature = parse_signature(&self.left_signature_hex)?;
        if !verify_signature(&hash, &left, &left_signature) {
            return Err(HubError::Node(
                "HVM bill left signature does not match the bound user".into(),
            ));
        }
        Ok(())
    }

    pub fn is_initial_recovery_bill(&self, binding: &HvmChannelBindingV1) -> bool {
        self.serial == 1
            && self.left_balance_zhu == binding.left_deposit_zhu
            && self.right_balance_zhu == binding.right_hub_deposit_zhu
            && self.validate_fully_signed(binding).is_ok()
    }
}

pub(crate) fn parse_address(value: &str, label: &str) -> HubResult<Address> {
    Address::from_readable(value)
        .map_err(|_| HubError::Node(format!("HVM channel {label} address is invalid")))
}

pub(crate) fn parse_signature(value: &str) -> HubResult<Sign> {
    if !is_lower_hex(value, HACASH_SIGN_WIRE_BYTES) {
        return Err(HubError::Node(
            "HVM bill signature is not canonical lowercase wire hex".into(),
        ));
    }
    let bytes = decode_hex(value)?;
    let mut signature = Sign::default();
    let used = signature
        .parse(&bytes)
        .map_err(|_| HubError::Node("HVM bill signature cannot be parsed".into()))?;
    if used != bytes.len() {
        return Err(HubError::Node(
            "HVM bill signature has trailing bytes".into(),
        ));
    }
    Ok(signature)
}

pub(crate) fn decode_hex(value: &str) -> HubResult<Vec<u8>> {
    hex::decode(value).map_err(|_| HubError::Node("HVM channel binding hex is invalid".into()))
}

pub(crate) fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use field::Serialize as FieldSerialize;
    use sys::Account;

    fn binding() -> HvmChannelBindingV1 {
        HvmChannelBindingV1 {
            schema: HVM_CHANNEL_BINDING_SCHEMA.to_owned(),
            settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
            network_mode: "mainnet".to_owned(),
            chain_id: 0,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([7_u8; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: HACASH_MAINNET_MIN_SAFE_HEIGHT,
            bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
            channel_id: "33".repeat(16),
            reuse_version: 7,
            left_address: Address::create_privakey([4_u8; 20]).to_readable(),
            right_hub_address: Address::create_privakey([5_u8; 20]).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        }
    }

    fn signed_initial_bill() -> (HvmChannelBindingV1, HvmChannelBillV1) {
        let left = Account::create_by("hpay-hvm-binding-left").unwrap();
        let right = Account::create_by("hpay-hvm-binding-right").unwrap();
        let mut binding = binding();
        binding.left_address = Address::from(*left.address()).to_readable();
        binding.right_hub_address = Address::from(*right.address()).to_readable();
        let mut bill = HvmChannelBillV1 {
            schema: HVM_CHANNEL_BILL_SCHEMA.to_owned(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: binding.left_deposit_zhu,
            right_balance_zhu: 0,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&binding).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());
        (binding, bill)
    }

    #[test]
    fn exact_binding_has_a_stable_commitment() {
        let first = binding();
        let second = first.clone();
        assert_eq!(first.commitment().unwrap(), second.commitment().unwrap());
        assert_eq!(first.commitment().unwrap().len(), 64);
    }

    #[test]
    fn binding_rejects_profile_funding_and_identity_downgrades() {
        let mut cases = Vec::new();
        let mut wrong_profile = binding();
        wrong_profile.settlement_profile = "native-channelpay".to_owned();
        cases.push(wrong_profile);
        let mut mismatched_mainnet = binding();
        mismatched_mainnet.chain_id = 7;
        cases.push(mismatched_mainnet);
        let mut mismatched_testnet = binding();
        mismatched_testnet.network_mode = "testnet".to_owned();
        cases.push(mismatched_testnet);
        let mut wrong_code = binding();
        wrong_code.bytecode_sha3 = "44".repeat(32);
        cases.push(wrong_code);
        let mut hub_principal = binding();
        hub_principal.right_hub_deposit_zhu = 1;
        cases.push(hub_principal);
        let mut ordinary_contract = binding();
        ordinary_contract.contract_address = ordinary_contract.left_address.clone();
        cases.push(ordinary_contract);
        let mut same_party = binding();
        same_party.right_hub_address = same_party.left_address.clone();
        cases.push(same_party);
        let mut zero_challenge = binding();
        zero_challenge.challenge_blocks = 0;
        cases.push(zero_challenge);
        for candidate in cases {
            assert!(candidate.validate().is_err());
        }
    }

    #[test]
    fn testnet_binding_is_isolated_by_nonzero_chain_and_instance() {
        let mut candidate = binding();
        candidate.network_mode = "testnet".to_owned();
        candidate.chain_id = 7;
        candidate.deployment_height = 1;
        candidate.validate().unwrap();

        let testnet_commitment = candidate.commitment().unwrap();
        assert_ne!(testnet_commitment, binding().commitment().unwrap());

        candidate.chain_id = 0;
        assert!(candidate.validate().is_err());
        candidate.chain_id = 7;
        candidate.deployment_height = 0;
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn commitment_changes_for_every_material_channel_field() {
        let base = binding();
        let expected = base.commitment().unwrap();
        let mut cases = Vec::new();
        let mut changed = base.clone();
        changed.network_instance_id = "aa".repeat(32);
        cases.push(changed);
        let mut changed = base.clone();
        changed.deployment_tx_hash = "bb".repeat(32);
        cases.push(changed);
        let mut changed = base.clone();
        changed.channel_id = "cc".repeat(16);
        cases.push(changed);
        let mut changed = base.clone();
        changed.reuse_version += 1;
        cases.push(changed);
        let mut changed = base.clone();
        changed.left_deposit_zhu += 1;
        cases.push(changed);
        let mut changed = base.clone();
        changed.challenge_blocks += 1;
        cases.push(changed);
        for candidate in cases {
            assert_ne!(candidate.commitment().unwrap(), expected);
        }
    }

    #[test]
    fn exact_two_party_initial_recovery_bill_is_dispute_ready() {
        let (binding, bill) = signed_initial_bill();
        bill.validate_fully_signed(&binding).unwrap();
        assert!(bill.is_initial_recovery_bill(&binding));
    }

    #[test]
    fn recovery_bundle_requires_the_exact_initial_bill_and_strict_schema() {
        let (binding, initial_recovery_bill) = signed_initial_bill();
        let bundle = HvmChannelRecoveryBundleV1 {
            schema: HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA.to_owned(),
            binding,
            initial_recovery_bill,
        };
        bundle.validate_crypto().unwrap();

        let mut later_bill = bundle.clone();
        later_bill.initial_recovery_bill.serial = 2;
        assert!(later_bill.validate_crypto().is_err());

        let mut unsigned = bundle.clone();
        unsigned.initial_recovery_bill.right_signature_hex.clear();
        assert!(unsigned.validate_crypto().is_err());

        let mut wrong_schema = serde_json::to_value(&bundle).unwrap();
        wrong_schema["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HvmChannelRecoveryBundleV1>(wrong_schema).is_err());
    }

    #[test]
    fn bill_rejects_wrong_binding_conservation_serial_and_signatures() {
        let (binding, bill) = signed_initial_bill();
        let mut wrong_binding = binding.clone();
        wrong_binding.reuse_version += 1;
        assert!(bill.validate_fully_signed(&wrong_binding).is_err());

        let mut wrong_total = bill.clone();
        wrong_total.left_balance_zhu -= 1;
        assert!(wrong_total.validate_fully_signed(&binding).is_err());

        let mut zero_serial = bill.clone();
        zero_serial.serial = 0;
        assert!(zero_serial.validate_fully_signed(&binding).is_err());

        let attacker = Account::create_by("hpay-hvm-binding-attacker").unwrap();
        let mut wrong_signer = bill.clone();
        let hash = wrong_signer.signing_hash(&binding).unwrap();
        wrong_signer.left_signature_hex =
            hex::encode(Sign::create_by(&attacker, &hash).serialize());
        assert!(wrong_signer.validate_fully_signed(&binding).is_err());

        let mut uppercase = bill.clone();
        uppercase.left_signature_hex = uppercase.left_signature_hex.to_ascii_uppercase();
        assert!(uppercase.validate_fully_signed(&binding).is_err());
    }
}
