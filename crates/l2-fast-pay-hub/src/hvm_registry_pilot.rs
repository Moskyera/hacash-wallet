//! Exact Local Pilot builders for the shared HVM registry V2.
//!
//! This module is compiled only with `local-pilot-tools`. It cannot enable a
//! mainnet profile and never contains a deterministic or published secret.

use field::{
    AddrOrPtr, Address, Amount, BytesW2, Field, Hex, Serialize as FieldSerialize, Sign, Uint4,
};
use protocol::action::HacToTrs;
use sha2::{Digest, Sha256};
use sys::Account;
use vm::ContractAddress;
use vm::action::{ContractDeploy, ContractMainCall};

use crate::error::{HubError, HubResult};
use crate::hvm_pilot::{
    HvmLocalPilotNetwork, HvmPilotDeploymentTransaction, HvmPilotSignedTransaction,
    build_exact_pilot_type3, contract_call_source, parse_contract_address, readable_address,
    validate_durable_pilot_transaction,
};
use crate::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryRecoveryBundleV2,
};
use crate::hvm_registry_ledger::HvmRegistryPaymentRequestV2;
use crate::l1_channel::L1ChannelNetworkBinding;

pub const HPAY_REGISTRY_SOURCE_SHA256: &str =
    "58ab4ba8931190a5b83f5b30a96d842281adf9d7e7069cbf8bf79a68945ae8a8";
const CONTRACT_SOURCE: &str =
    include_str!("../../../../hacash-fullnodedev/vm/contracts/hpay_channel_registry_v2.fitsh");
const CONTRACT_PROTOCOL_COST_238: u64 = 2_000_000_000_000;
pub const HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU: u64 = CONTRACT_PROTOCOL_COST_238 / 100;
pub const HVM_REGISTRY_DEPLOYMENT_PREVIEW_SCHEMA: &str = "hpay-hvm-registry-deployment-preview/2";
const HVM_REGISTRY_DEPLOYMENT_PREVIEW_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY-DEPLOYMENT-PREVIEW/V2";
pub const HVM_REGISTRY_INITIALIZATION_PREVIEW_SCHEMA: &str =
    "hpay-hvm-registry-initialization-preview/2";
const HVM_REGISTRY_INITIALIZATION_PREVIEW_DOMAIN: &[u8] =
    b"HPAY/HVM-REGISTRY-INITIALIZATION-PREVIEW/V2";
pub const HVM_REGISTRY_FUNDING_PREVIEW_SCHEMA: &str = "hpay-hvm-registry-funding-preview/2";
const HVM_REGISTRY_FUNDING_PREVIEW_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY-FUNDING-PREVIEW/V2";
pub const HVM_REGISTRY_PREFUND_PREVIEW_SCHEMA: &str = "hpay-hvm-registry-prefund-preview/1";
const HVM_REGISTRY_PREFUND_PREVIEW_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY-PREFUND-PREVIEW/V1";
const HVM_REGISTRY_PREFUND_VALIDITY_POLICY: &str =
    "exact_timestamp_short_lived_cli_authorization_no_protocol_expiry";
const HVM_REGISTRY_PREFUND_MAX_VALIDITY_SECONDS: u64 = 900;
const HVM_REGISTRY_PREFUND_MAX_FUTURE_SECONDS: u64 = 30;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPilotPrefundPreview {
    pub schema: String,
    pub settlement_profile: String,
    pub network: HvmLocalPilotNetwork,
    pub source_address: String,
    pub destination_address: String,
    pub amount_zhu: u64,
    pub network_fee_zhu: u64,
    pub total_debit_zhu: u128,
    pub timestamp: u64,
    pub valid_until_unix: u64,
    pub validity_policy: String,
    pub gas_max: u8,
    pub address_topology: [String; 2],
    pub action_kinds: [u16; 2],
    pub transfer_action_sha256: String,
    pub unsigned_commitment: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPilotDeploymentPreview {
    pub schema: String,
    pub settlement_profile: String,
    pub network: HvmLocalPilotNetwork,
    pub deployer_address: String,
    pub contract_address: String,
    pub nonce: u32,
    pub action_kinds: [u16; 2],
    pub constructor_argv_hex: String,
    pub source_sha256: String,
    pub bytecode_sha3: String,
    pub protocol_cost_zhu: u64,
    pub network_fee_zhu: u64,
    pub total_debit_zhu: u128,
    pub gas_max: u8,
    pub unsigned_commitment: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPilotInitializationPreview {
    pub schema: String,
    pub settlement_profile: String,
    pub network: HvmLocalPilotNetwork,
    pub left_address: String,
    pub hub_address: String,
    pub contract_address: String,
    pub parameters: HvmRegistryPilotChannelParameters,
    pub action_kinds: [u16; 3],
    pub call_source_sha256: String,
    pub call_action_sha256: String,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub unsigned_commitment: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPilotFundingPreview {
    pub schema: String,
    pub settlement_profile: String,
    pub network: HvmLocalPilotNetwork,
    pub left_address: String,
    pub hub_address: String,
    pub contract_address: String,
    pub amount_zhu: u64,
    pub network_fee_zhu: u64,
    pub total_debit_zhu: u128,
    pub gas_max: u8,
    pub action_kinds: [u16; 2],
    pub transfer_action_sha256: String,
    pub unsigned_commitment: String,
}

pub fn preview_hvm_registry_pilot_prefund(
    source_address: &str,
    destination_address: &str,
    network: &HvmLocalPilotNetwork,
    network_fee_zhu: u64,
    timestamp: u64,
    valid_until_unix: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryPilotPrefundPreview> {
    network.validate()?;
    let source = canonical_private_address(source_address, "prefund source")?;
    let destination = canonical_private_address(destination_address, "prefund destination")?;
    if source == destination
        || network_fee_zhu == 0
        || timestamp == 0
        || gas_max == 0
        || valid_until_unix <= timestamp
        || valid_until_unix.saturating_sub(timestamp) > HVM_REGISTRY_PREFUND_MAX_VALIDITY_SECONDS
    {
        return Err(HubError::State(
            "registry prefund preview identities, fee, gas or validity window are invalid".into(),
        ));
    }
    let transfer = HacToTrs::create_by(
        destination,
        Amount::zhu(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU),
    );
    let transfer_action_sha256 = hex::encode(Sha256::digest(transfer.serialize()));
    let total_debit_zhu = u128::from(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU)
        .checked_add(u128::from(network_fee_zhu))
        .ok_or_else(|| HubError::State("registry prefund total debit overflow".into()))?;
    let source_address = source.to_readable();
    let destination_address = destination.to_readable();
    let address_topology = [source_address.clone(), destination_address.clone()];
    let action_kinds: [u16; 2] = [0x0411, 1];
    let fields = [
        HVM_REGISTRY_PREFUND_PREVIEW_SCHEMA.as_bytes(),
        HPAY_REGISTRY_SETTLEMENT_PROFILE.as_bytes(),
        network.network_kind.as_bytes(),
        network.node_profile_id.as_bytes(),
        network.block_1_hash.as_bytes(),
        network.network_instance_id.as_bytes(),
        source_address.as_bytes(),
        destination_address.as_bytes(),
        address_topology[0].as_bytes(),
        address_topology[1].as_bytes(),
        HVM_REGISTRY_PREFUND_VALIDITY_POLICY.as_bytes(),
        transfer_action_sha256.as_bytes(),
    ];
    let mut digest = Sha256::new();
    digest.update(HVM_REGISTRY_PREFUND_PREVIEW_DOMAIN);
    update_preview_fields(&mut digest, &fields, "prefund")?;
    digest.update(network.chain_id.to_be_bytes());
    digest.update(network.transaction_format_version.to_be_bytes());
    digest.update(action_kinds[0].to_be_bytes());
    digest.update(action_kinds[1].to_be_bytes());
    digest.update(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU.to_be_bytes());
    digest.update(network_fee_zhu.to_be_bytes());
    digest.update(total_debit_zhu.to_be_bytes());
    digest.update(timestamp.to_be_bytes());
    digest.update(valid_until_unix.to_be_bytes());
    digest.update([gas_max]);
    Ok(HvmRegistryPilotPrefundPreview {
        schema: HVM_REGISTRY_PREFUND_PREVIEW_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network: network.clone(),
        source_address,
        destination_address,
        amount_zhu: HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU,
        network_fee_zhu,
        total_debit_zhu,
        timestamp,
        valid_until_unix,
        validity_policy: HVM_REGISTRY_PREFUND_VALIDITY_POLICY.into(),
        gas_max,
        address_topology,
        action_kinds,
        transfer_action_sha256,
        unsigned_commitment: hex::encode(digest.finalize()),
    })
}

impl HvmRegistryPilotPrefundPreview {
    pub fn validate(&self) -> HubResult<()> {
        let expected = preview_hvm_registry_pilot_prefund(
            &self.source_address,
            &self.destination_address,
            &self.network,
            self.network_fee_zhu,
            self.timestamp,
            self.valid_until_unix,
            self.gas_max,
        )?;
        if self != &expected {
            return Err(HubError::State(
                "registry prefund preview is inconsistent".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_signing(&self, now_unix: u64) -> HubResult<()> {
        self.validate()?;
        if now_unix > self.valid_until_unix
            || self.timestamp > now_unix.saturating_add(HVM_REGISTRY_PREFUND_MAX_FUTURE_SECONDS)
        {
            return Err(HubError::State(
                "registry prefund preview is expired or too far in the future".into(),
            ));
        }
        Ok(())
    }
}

struct HvmRegistryDeploymentPlan {
    network: HvmLocalPilotNetwork,
    deployer: Address,
    contract_address: String,
    compiled: vm::contract::Contract,
    source_sha256: String,
    bytecode_sha3: String,
}

fn build_hvm_registry_deployment_plan(
    deployer_address: &str,
    network: &HvmLocalPilotNetwork,
) -> HubResult<HvmRegistryDeploymentPlan> {
    network.validate()?;
    let deployer = Address::from_readable(deployer_address).map_err(|error| {
        HubError::State(format!("registry deployer address is invalid: {error}"))
    })?;
    if !deployer.is_privakey() || deployer.to_readable() != deployer_address {
        return Err(HubError::State(
            "registry deployer must be one canonical private-key address".into(),
        ));
    }
    let compiled = vm::fitshc::compile(CONTRACT_SOURCE)
        .map_err(|error| HubError::State(format!("registry contract compile failed: {error}")))?
        .0;
    let source_sha256 = hex::encode(Sha256::digest(CONTRACT_SOURCE.as_bytes()));
    let bytecode_sha3 = hex::encode(sys::sha3(compiled.serialize()));
    if source_sha256 != HPAY_REGISTRY_SOURCE_SHA256 || bytecode_sha3 != HPAY_REGISTRY_BYTECODE_SHA3
    {
        return Err(HubError::State(
            "shared registry source or bytecode hash drifted".into(),
        ));
    }
    let contract_address = ContractAddress::calculate(&deployer, &Uint4::from(0)).to_readable();
    Ok(HvmRegistryDeploymentPlan {
        network: network.clone(),
        deployer,
        contract_address,
        compiled,
        source_sha256,
        bytecode_sha3,
    })
}

fn registry_deployment_preview_commitment(
    plan: &HvmRegistryDeploymentPlan,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<String> {
    let deployer_address = plan.deployer.to_readable();
    let fields = [
        HVM_REGISTRY_DEPLOYMENT_PREVIEW_SCHEMA.as_bytes(),
        HPAY_REGISTRY_SETTLEMENT_PROFILE.as_bytes(),
        plan.network.network_kind.as_bytes(),
        plan.network.node_profile_id.as_bytes(),
        plan.network.block_1_hash.as_bytes(),
        plan.network.network_instance_id.as_bytes(),
        deployer_address.as_bytes(),
        plan.contract_address.as_bytes(),
        plan.source_sha256.as_bytes(),
        plan.bytecode_sha3.as_bytes(),
    ];
    let mut digest = Sha256::new();
    digest.update(HVM_REGISTRY_DEPLOYMENT_PREVIEW_DOMAIN);
    for field in fields {
        let length = u64::try_from(field.len()).map_err(|_| {
            HubError::State("registry deployment preview field is too large".into())
        })?;
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    digest.update(plan.network.chain_id.to_be_bytes());
    digest.update(plan.network.transaction_format_version.to_be_bytes());
    digest.update(0_u32.to_be_bytes());
    digest.update(0x0411_u16.to_be_bytes());
    digest.update(40_u16.to_be_bytes());
    digest.update(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU.to_be_bytes());
    digest.update(network_fee_zhu.to_be_bytes());
    digest.update([gas_max]);
    Ok(hex::encode(digest.finalize()))
}

pub fn preview_hvm_registry_pilot_deployment(
    deployer_address: &str,
    network: &HvmLocalPilotNetwork,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryPilotDeploymentPreview> {
    if network_fee_zhu == 0 || gas_max == 0 {
        return Err(HubError::State(
            "registry deployment preview fee and gas must be positive".into(),
        ));
    }
    let plan = build_hvm_registry_deployment_plan(deployer_address, network)?;
    let unsigned_commitment =
        registry_deployment_preview_commitment(&plan, network_fee_zhu, gas_max)?;
    let total_debit_zhu = u128::from(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU)
        .checked_add(u128::from(network_fee_zhu))
        .ok_or_else(|| HubError::State("registry deployment total debit overflow".into()))?;
    Ok(HvmRegistryPilotDeploymentPreview {
        schema: HVM_REGISTRY_DEPLOYMENT_PREVIEW_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network: plan.network.clone(),
        deployer_address: plan.deployer.to_readable(),
        contract_address: plan.contract_address.clone(),
        nonce: 0,
        action_kinds: [0x0411, 40],
        constructor_argv_hex: plan.network.network_instance_id.clone(),
        source_sha256: plan.source_sha256,
        bytecode_sha3: plan.bytecode_sha3,
        protocol_cost_zhu: HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU,
        network_fee_zhu,
        total_debit_zhu,
        gas_max,
        unsigned_commitment,
    })
}

impl HvmRegistryPilotDeploymentPreview {
    pub fn validate(&self) -> HubResult<()> {
        let expected = preview_hvm_registry_pilot_deployment(
            &self.deployer_address,
            &self.network,
            self.network_fee_zhu,
            self.gas_max,
        )?;
        if self != &expected {
            return Err(HubError::State(
                "registry deployment preview is inconsistent".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPilotChannelParameters {
    pub channel_id: String,
    pub reuse_version: u32,
    pub left_deposit_zhu: u64,
    pub right_hub_deposit_zhu: u64,
    pub challenge_blocks: u64,
}

impl HvmRegistryPilotChannelParameters {
    pub fn validate(&self) -> HubResult<()> {
        if self.channel_id.len() != 32
            || !self
                .channel_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.reuse_version != 0
            || self.left_deposit_zhu == 0
            || self.right_hub_deposit_zhu != 0
            || self.challenge_blocks == 0
        {
            return Err(HubError::State(
                "shared registry Local Pilot channel parameters are unsafe".into(),
            ));
        }
        Ok(())
    }
}

fn canonical_private_address(value: &str, label: &str) -> HubResult<Address> {
    let address = Address::from_readable(value).map_err(|error| {
        HubError::State(format!("registry {label} address is invalid: {error}"))
    })?;
    if !address.is_privakey() || address.to_readable() != value {
        return Err(HubError::State(format!(
            "registry {label} must be one canonical private-key address"
        )));
    }
    Ok(address)
}

fn update_preview_fields(digest: &mut Sha256, fields: &[&[u8]], stage: &str) -> HubResult<()> {
    for field in fields {
        let length = u64::try_from(field.len())
            .map_err(|_| HubError::State(format!("registry {stage} preview field is too large")))?;
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    Ok(())
}

struct HvmRegistryInitializationPlan {
    network: HvmLocalPilotNetwork,
    left_address: Address,
    hub_address: Address,
    contract: ContractAddress,
    parameters: HvmRegistryPilotChannelParameters,
    action: ContractMainCall,
    call_source_sha256: String,
    call_action_sha256: String,
}

fn build_hvm_registry_initialization_plan(
    left_address: &str,
    hub_address: &str,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    parameters: &HvmRegistryPilotChannelParameters,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryInitializationPlan> {
    network.validate()?;
    parameters.validate()?;
    if network_fee_zhu == 0 || gas_max == 0 {
        return Err(HubError::State(
            "registry initialization preview fee and gas must be positive".into(),
        ));
    }
    let left_address = canonical_private_address(left_address, "left")?;
    let hub_address = canonical_private_address(hub_address, "Hub")?;
    if left_address == hub_address {
        return Err(HubError::State(
            "registry left and Hub identities must be independent".into(),
        ));
    }
    let contract = parse_contract_address(contract_address)?;
    let canonical_contract = ContractAddress::calculate(&hub_address, &Uint4::from(0));
    if contract.to_readable() != canonical_contract.to_readable() {
        return Err(HubError::State(
            "registry initialization contract is not the canonical Hub deployment".into(),
        ));
    }
    let call = format!(
        "init(0x{}, {}, {}, {}, {}, 100)",
        parameters.channel_id,
        parameters.reuse_version,
        left_address.to_readable(),
        parameters.left_deposit_zhu,
        parameters.challenge_blocks,
    );
    let source = contract_call_source(&contract, &call);
    let codes = vm::lang::lang_to_bytecode(&source)
        .map_err(|error| HubError::State(format!("registry init compile failed: {error}")))?;
    let action = ContractMainCall::from_bytecode(codes)
        .map_err(|error| HubError::State(format!("registry init Action 44 failed: {error}")))?;
    let call_source_sha256 = hex::encode(Sha256::digest(source.as_bytes()));
    let call_action_sha256 = hex::encode(Sha256::digest(action.serialize()));
    Ok(HvmRegistryInitializationPlan {
        network: network.clone(),
        left_address,
        hub_address,
        contract,
        parameters: parameters.clone(),
        action,
        call_source_sha256,
        call_action_sha256,
    })
}

fn registry_initialization_preview_commitment(
    plan: &HvmRegistryInitializationPlan,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<String> {
    let left_address = plan.left_address.to_readable();
    let hub_address = plan.hub_address.to_readable();
    let contract_address = plan.contract.to_readable();
    let fields = [
        HVM_REGISTRY_INITIALIZATION_PREVIEW_SCHEMA.as_bytes(),
        HPAY_REGISTRY_SETTLEMENT_PROFILE.as_bytes(),
        plan.network.network_kind.as_bytes(),
        plan.network.node_profile_id.as_bytes(),
        plan.network.block_1_hash.as_bytes(),
        plan.network.network_instance_id.as_bytes(),
        left_address.as_bytes(),
        hub_address.as_bytes(),
        contract_address.as_bytes(),
        plan.parameters.channel_id.as_bytes(),
        plan.call_source_sha256.as_bytes(),
        plan.call_action_sha256.as_bytes(),
    ];
    let mut digest = Sha256::new();
    digest.update(HVM_REGISTRY_INITIALIZATION_PREVIEW_DOMAIN);
    update_preview_fields(&mut digest, &fields, "initialization")?;
    digest.update(plan.network.chain_id.to_be_bytes());
    digest.update(plan.network.transaction_format_version.to_be_bytes());
    digest.update(plan.parameters.reuse_version.to_be_bytes());
    digest.update(plan.parameters.left_deposit_zhu.to_be_bytes());
    digest.update(plan.parameters.right_hub_deposit_zhu.to_be_bytes());
    digest.update(plan.parameters.challenge_blocks.to_be_bytes());
    digest.update(network_fee_zhu.to_be_bytes());
    digest.update([gas_max]);
    for action_kind in [0x0411_u16, 44, 0x0414] {
        digest.update(action_kind.to_be_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
pub fn preview_hvm_registry_pilot_initialization(
    left_address: &str,
    hub_address: &str,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    parameters: &HvmRegistryPilotChannelParameters,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryPilotInitializationPreview> {
    let plan = build_hvm_registry_initialization_plan(
        left_address,
        hub_address,
        contract_address,
        network,
        parameters,
        network_fee_zhu,
        gas_max,
    )?;
    let unsigned_commitment =
        registry_initialization_preview_commitment(&plan, network_fee_zhu, gas_max)?;
    Ok(HvmRegistryPilotInitializationPreview {
        schema: HVM_REGISTRY_INITIALIZATION_PREVIEW_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network: plan.network,
        left_address: plan.left_address.to_readable(),
        hub_address: plan.hub_address.to_readable(),
        contract_address: plan.contract.to_readable(),
        parameters: plan.parameters,
        action_kinds: [0x0411, 44, 0x0414],
        call_source_sha256: plan.call_source_sha256,
        call_action_sha256: plan.call_action_sha256,
        network_fee_zhu,
        gas_max,
        unsigned_commitment,
    })
}

impl HvmRegistryPilotInitializationPreview {
    pub fn validate(&self) -> HubResult<()> {
        let expected = preview_hvm_registry_pilot_initialization(
            &self.left_address,
            &self.hub_address,
            &self.contract_address,
            &self.network,
            &self.parameters,
            self.network_fee_zhu,
            self.gas_max,
        )?;
        if self != &expected {
            return Err(HubError::State(
                "registry initialization preview is inconsistent".into(),
            ));
        }
        Ok(())
    }
}

struct HvmRegistryFundingPlan {
    network: HvmLocalPilotNetwork,
    left_address: Address,
    hub_address: Address,
    contract: ContractAddress,
    amount_zhu: u64,
    action: HacToTrs,
    transfer_action_sha256: String,
}

fn build_hvm_registry_funding_plan(
    left_address: &str,
    hub_address: &str,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    amount_zhu: u64,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryFundingPlan> {
    network.validate()?;
    if amount_zhu == 0 || network_fee_zhu == 0 || gas_max == 0 {
        return Err(HubError::State(
            "registry funding preview amount, fee and gas must be positive".into(),
        ));
    }
    let left_address = canonical_private_address(left_address, "left")?;
    let hub_address = canonical_private_address(hub_address, "Hub")?;
    if left_address == hub_address {
        return Err(HubError::State(
            "registry left and Hub identities must be independent".into(),
        ));
    }
    let contract = parse_contract_address(contract_address)?;
    let canonical_contract = ContractAddress::calculate(&hub_address, &Uint4::from(0));
    if contract.to_readable() != canonical_contract.to_readable() {
        return Err(HubError::State(
            "registry funding contract is not the canonical Hub deployment".into(),
        ));
    }
    let mut action = HacToTrs::new();
    action.to = AddrOrPtr::from_addr(contract.to_addr());
    action.hacash = Amount::zhu(amount_zhu);
    let transfer_action_sha256 = hex::encode(Sha256::digest(action.serialize()));
    Ok(HvmRegistryFundingPlan {
        network: network.clone(),
        left_address,
        hub_address,
        contract,
        amount_zhu,
        action,
        transfer_action_sha256,
    })
}

fn registry_funding_preview_commitment(
    plan: &HvmRegistryFundingPlan,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<String> {
    let left_address = plan.left_address.to_readable();
    let hub_address = plan.hub_address.to_readable();
    let contract_address = plan.contract.to_readable();
    let fields = [
        HVM_REGISTRY_FUNDING_PREVIEW_SCHEMA.as_bytes(),
        HPAY_REGISTRY_SETTLEMENT_PROFILE.as_bytes(),
        plan.network.network_kind.as_bytes(),
        plan.network.node_profile_id.as_bytes(),
        plan.network.block_1_hash.as_bytes(),
        plan.network.network_instance_id.as_bytes(),
        left_address.as_bytes(),
        hub_address.as_bytes(),
        contract_address.as_bytes(),
        plan.transfer_action_sha256.as_bytes(),
    ];
    let mut digest = Sha256::new();
    digest.update(HVM_REGISTRY_FUNDING_PREVIEW_DOMAIN);
    update_preview_fields(&mut digest, &fields, "funding")?;
    digest.update(plan.network.chain_id.to_be_bytes());
    digest.update(plan.network.transaction_format_version.to_be_bytes());
    digest.update(plan.amount_zhu.to_be_bytes());
    digest.update(network_fee_zhu.to_be_bytes());
    digest.update([gas_max]);
    for action_kind in [0x0411_u16, 1] {
        digest.update(action_kind.to_be_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
pub fn preview_hvm_registry_pilot_funding(
    left_address: &str,
    hub_address: &str,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    amount_zhu: u64,
    network_fee_zhu: u64,
    gas_max: u8,
) -> HubResult<HvmRegistryPilotFundingPreview> {
    let plan = build_hvm_registry_funding_plan(
        left_address,
        hub_address,
        contract_address,
        network,
        amount_zhu,
        network_fee_zhu,
        gas_max,
    )?;
    let total_debit_zhu = u128::from(amount_zhu)
        .checked_add(u128::from(network_fee_zhu))
        .ok_or_else(|| HubError::State("registry funding total debit overflow".into()))?;
    let unsigned_commitment = registry_funding_preview_commitment(&plan, network_fee_zhu, gas_max)?;
    Ok(HvmRegistryPilotFundingPreview {
        schema: HVM_REGISTRY_FUNDING_PREVIEW_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network: plan.network,
        left_address: plan.left_address.to_readable(),
        hub_address: plan.hub_address.to_readable(),
        contract_address: plan.contract.to_readable(),
        amount_zhu: plan.amount_zhu,
        network_fee_zhu,
        total_debit_zhu,
        gas_max,
        action_kinds: [0x0411, 1],
        transfer_action_sha256: plan.transfer_action_sha256,
        unsigned_commitment,
    })
}

impl HvmRegistryPilotFundingPreview {
    pub fn validate(&self) -> HubResult<()> {
        let expected = preview_hvm_registry_pilot_funding(
            &self.left_address,
            &self.hub_address,
            &self.contract_address,
            &self.network,
            self.amount_zhu,
            self.network_fee_zhu,
            self.gas_max,
        )?;
        if self != &expected {
            return Err(HubError::State(
                "registry funding preview is inconsistent".into(),
            ));
        }
        Ok(())
    }
}

pub fn build_hvm_registry_pilot_deployment(
    hub: &Account,
    network: &HvmLocalPilotNetwork,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotDeploymentTransaction> {
    let plan = build_hvm_registry_deployment_plan(hub.readable(), network)?;
    let mut action = ContractDeploy::new();
    action.nonce = Uint4::from(0);
    action.contract = plan.compiled.into_sto();
    action.protocol_cost = Amount::unit238(CONTRACT_PROTOCOL_COST_238);
    action.construct_argv = BytesW2::from(
        hex::decode(&plan.network.network_instance_id)
            .map_err(|_| HubError::State("Local Pilot instance is not hex".into()))?,
    )
    .map_err(|error| HubError::State(format!("registry constructor argv failed: {error}")))?;
    let transaction = build_exact_pilot_type3(
        hub,
        &[],
        &plan.network,
        vec![plan.deployer],
        vec![Box::new(action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )?;
    Ok(HvmPilotDeploymentTransaction {
        contract_address: plan.contract_address,
        source_sha256: plan.source_sha256,
        bytecode_sha3: plan.bytecode_sha3,
        transaction,
    })
}

pub(crate) fn validate_hvm_registry_pilot_deployment_transaction(
    deployment: &HvmPilotDeploymentTransaction,
    preview: &HvmRegistryPilotDeploymentPreview,
) -> HubResult<()> {
    preview.validate()?;
    if deployment.contract_address != preview.contract_address
        || deployment.source_sha256 != preview.source_sha256
        || deployment.bytecode_sha3 != preview.bytecode_sha3
    {
        return Err(HubError::State(
            "registry deployment artifact does not match its reviewed preview".into(),
        ));
    }
    let transaction = validate_durable_pilot_transaction(
        &deployment.transaction,
        preview.network.chain_id,
        &preview.action_kinds,
        1,
        &[&preview.deployer_address],
    )?;
    let deploy = ContractDeploy::downcast(&transaction.actions()[1])
        .ok_or_else(|| HubError::State("registry deployment action is malformed".into()))?;
    let expected_instance = hex::decode(&preview.constructor_argv_hex)
        .map_err(|_| HubError::State("registry deployment constructor is invalid".into()))?;
    if transaction.fee() != &Amount::zhu(preview.network_fee_zhu)
        || transaction.gas_max_byte() != Some(preview.gas_max)
        || deploy.protocol_cost.serialize()
            != Amount::unit238(CONTRACT_PROTOCOL_COST_238).serialize()
        || deploy.construct_argv.to_vec() != expected_instance
        || deploy.contract.calc_edition().hash.to_hex() != preview.bytecode_sha3
    {
        return Err(HubError::State(
            "registry deployment transaction does not match its reviewed preview".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_hvm_registry_pilot_prefund_transaction(
    signed: &HvmPilotSignedTransaction,
    preview: &HvmRegistryPilotPrefundPreview,
) -> HubResult<()> {
    preview.validate()?;
    let transaction = validate_durable_pilot_transaction(
        signed,
        preview.network.chain_id,
        &preview.action_kinds,
        1,
        &[&preview.source_address, &preview.destination_address],
    )?;
    let action_sha256 = hex::encode(Sha256::digest(transaction.actions()[1].serialize()));
    if transaction.fee() != &Amount::zhu(preview.network_fee_zhu)
        || transaction.timestamp().uint() != preview.timestamp
        || transaction.gas_max_byte() != Some(preview.gas_max)
        || action_sha256 != preview.transfer_action_sha256
    {
        return Err(HubError::State(
            "registry prefund transaction does not match its reviewed preview".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_hvm_registry_pilot_channel_init(
    left: &Account,
    hub: &Account,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    parameters: &HvmRegistryPilotChannelParameters,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    let plan = build_hvm_registry_initialization_plan(
        left.readable(),
        hub.readable(),
        contract_address,
        network,
        parameters,
        network_fee_zhu,
        gas_max,
    )?;
    build_exact_pilot_type3(
        left,
        &[hub],
        &plan.network,
        vec![plan.left_address, plan.contract.to_addr(), plan.hub_address],
        vec![Box::new(plan.action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_hvm_registry_pilot_exact_funding(
    left: &Account,
    hub_address: &str,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    amount_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    let plan = build_hvm_registry_funding_plan(
        left.readable(),
        hub_address,
        contract_address,
        network,
        amount_zhu,
        network_fee_zhu,
        gas_max,
    )?;
    build_exact_pilot_type3(
        left,
        &[],
        &plan.network,
        vec![plan.left_address, plan.contract.to_addr()],
        vec![Box::new(plan.action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

pub(crate) fn validate_hvm_registry_pilot_initialization_transaction(
    signed: &HvmPilotSignedTransaction,
    preview: &HvmRegistryPilotInitializationPreview,
) -> HubResult<()> {
    preview.validate()?;
    let transaction = validate_durable_pilot_transaction(
        signed,
        preview.network.chain_id,
        &preview.action_kinds,
        2,
        &[
            &preview.left_address,
            &preview.contract_address,
            &preview.hub_address,
        ],
    )?;
    let action_sha256 = hex::encode(Sha256::digest(transaction.actions()[1].serialize()));
    if transaction.fee() != &Amount::zhu(preview.network_fee_zhu)
        || transaction.gas_max_byte() != Some(preview.gas_max)
        || action_sha256 != preview.call_action_sha256
    {
        return Err(HubError::State(
            "registry initialization transaction does not match its reviewed preview".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_hvm_registry_pilot_funding_transaction(
    signed: &HvmPilotSignedTransaction,
    preview: &HvmRegistryPilotFundingPreview,
) -> HubResult<()> {
    preview.validate()?;
    let transaction = validate_durable_pilot_transaction(
        signed,
        preview.network.chain_id,
        &preview.action_kinds,
        1,
        &[&preview.left_address, &preview.contract_address],
    )?;
    let action_sha256 = hex::encode(Sha256::digest(transaction.actions()[1].serialize()));
    if transaction.fee() != &Amount::zhu(preview.network_fee_zhu)
        || transaction.gas_max_byte() != Some(preview.gas_max)
        || action_sha256 != preview.transfer_action_sha256
    {
        return Err(HubError::State(
            "registry funding transaction does not match its reviewed preview".into(),
        ));
    }
    Ok(())
}

pub fn build_hvm_registry_pilot_recovery_bundle(
    left: &Account,
    hub: &Account,
    deployment: &HvmPilotDeploymentTransaction,
    deployment_height: u64,
    parameters: &HvmRegistryPilotChannelParameters,
) -> HubResult<HvmRegistryRecoveryBundleV2> {
    parameters.validate()?;
    let network = HvmLocalPilotNetwork::canonical();
    validate_registry_deployment(deployment, hub, &network)?;
    if deployment_height == 0 {
        return Err(HubError::State(
            "registry deployment evidence is incomplete".into(),
        ));
    }
    let binding = HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id,
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: parameters.channel_id.clone(),
        reuse_version: parameters.reuse_version,
        left_address: left.readable().to_owned(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: parameters.left_deposit_zhu,
        right_hub_deposit_zhu: parameters.right_hub_deposit_zhu,
        challenge_blocks: parameters.challenge_blocks,
    };
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment()?,
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        hub_balance_zhu: 0,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding)?;
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    let bundle = HvmRegistryRecoveryBundleV2 {
        schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
        binding,
        initial_recovery_bill: bill,
    };
    bundle.validate_crypto()?;
    Ok(bundle)
}

fn validate_registry_deployment(
    deployment: &HvmPilotDeploymentTransaction,
    hub: &Account,
    network: &HvmLocalPilotNetwork,
) -> HubResult<()> {
    use protocol::action::ChainAllow;

    if deployment.source_sha256 != HPAY_REGISTRY_SOURCE_SHA256
        || deployment.bytecode_sha3 != HPAY_REGISTRY_BYTECODE_SHA3
    {
        return Err(HubError::State(
            "registry deployment artifact drifted".into(),
        ));
    }
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let raw = hex::decode(&deployment.transaction.signed_transaction_hex)
        .map_err(|_| HubError::State("registry deployment bytes are invalid".into()))?;
    let (transaction, used) = protocol::transaction::transaction_create(&raw)
        .map_err(|_| HubError::State("registry deployment cannot be decoded".into()))?;
    let hub_address = readable_address(hub)?;
    if used != raw.len()
        || transaction.ty() != 3
        || transaction.actions().len() != 2
        || transaction.actions()[0].kind() != 0x0411
        || transaction.actions()[1].kind() != 40
        || transaction.signs().len() != 1
        || transaction.main() != hub_address
        || hex::encode(transaction.hash()) != deployment.transaction.transaction_hash
        || transaction.verify_signature().is_err()
    {
        return Err(HubError::State(
            "registry deployment signer or transaction topology changed".into(),
        ));
    }
    let guard = ChainAllow::downcast(&transaction.actions()[0])
        .ok_or_else(|| HubError::State("registry deployment guard is malformed".into()))?;
    let chains = guard.chains.as_list();
    let deploy = ContractDeploy::downcast(&transaction.actions()[1])
        .ok_or_else(|| HubError::State("registry deployment action is malformed".into()))?;
    let expected_instance = hex::decode(&network.network_instance_id)
        .map_err(|_| HubError::State("Local Pilot instance is not hex".into()))?;
    let expected_contract = ContractAddress::calculate(&hub_address, &deploy.nonce);
    if chains.len() != 1
        || chains[0].uint() != network.chain_id
        || deploy.construct_argv.to_vec() != expected_instance
        || deploy.contract.calc_edition().hash.to_hex() != HPAY_REGISTRY_BYTECODE_SHA3
        || expected_contract.to_readable() != deployment.contract_address
    {
        return Err(HubError::State(
            "registry deployment chain, constructor or bytecode binding changed".into(),
        ));
    }
    Ok(())
}

/// Builds the exact fee-free Local Pilot payment request, fully authorized.
///
/// The payer authorization is produced here rather than left to the caller.
/// `validate_against` refuses a request without it, so a builder that returned
/// one unsigned could only ever produce something the Hub would reject, and the
/// pilot binary is the one caller. Both signatures come from the same `left`
/// key: one over the proposed bill, one over the payment and replay fields.
#[allow(clippy::too_many_arguments)]
pub fn build_hvm_registry_pilot_payment_request(
    left: &Account,
    network_binding: &L1ChannelNetworkBinding,
    binding: &HvmRegistryBindingV2,
    previous: &HvmRegistryBillV2,
    operation_id: &str,
    idempotency_key: &str,
    recipient: &str,
    amount_zhu: u64,
    created_unix: u64,
    expires_unix: u64,
) -> HubResult<HvmRegistryPaymentRequestV2> {
    if binding.network_mode != "testnet"
        || binding.chain_id != HvmLocalPilotNetwork::canonical().chain_id
        || binding.network_instance_id != HvmLocalPilotNetwork::canonical().network_instance_id
        || binding.left_address != left.readable()
        || binding.right_hub_deposit_zhu != 0
    {
        return Err(HubError::Payment(
            "shared registry Local Pilot payment binding is invalid".into(),
        ));
    }
    let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
        network_binding,
        binding,
        previous,
        operation_id,
        idempotency_key,
        recipient,
        amount_zhu,
        created_unix,
        expires_unix,
    )?;
    let hash = request.proposed_bill.signing_hash(binding)?;
    request.proposed_bill.left_signature_hex =
        hex::encode(Sign::create_by(left, &hash).serialize());
    let payer_authorization_hash = request.payer_authorization_hash(binding, previous)?;
    request.payer_authorization_signature_hex =
        hex::encode(Sign::create_by(left, &payer_authorization_hash).serialize());
    request.validate_against(binding, previous, created_unix)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvm_pilot::HVM_PILOT_MIN_FEE_PURITY;

    const FEE: u64 = 500_000;

    #[test]
    fn exact_registry_deploy_init_fund_and_bundle_are_chain_bound() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let network = HvmLocalPilotNetwork::canonical();
        let hub = Account::create_by("registry-pilot-hub").unwrap();
        let left = Account::create_by("registry-pilot-left").unwrap();
        let preview =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX).unwrap();
        let deploy =
            build_hvm_registry_pilot_deployment(&hub, &network, FEE, 100, u8::MAX).unwrap();
        assert_eq!(preview.schema, HVM_REGISTRY_DEPLOYMENT_PREVIEW_SCHEMA);
        assert_eq!(preview.settlement_profile, HPAY_REGISTRY_SETTLEMENT_PROFILE);
        assert_eq!(preview.deployer_address, hub.readable());
        assert_eq!(preview.contract_address, deploy.contract_address);
        assert_eq!(preview.source_sha256, deploy.source_sha256);
        assert_eq!(preview.bytecode_sha3, deploy.bytecode_sha3);
        assert_eq!(
            preview.protocol_cost_zhu,
            HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU
        );
        assert_eq!(preview.action_kinds, [0x0411, 40]);
        assert_eq!(preview.constructor_argv_hex, network.network_instance_id);
        assert_eq!(preview.unsigned_commitment.len(), 64);
        assert_eq!(preview.network_fee_zhu, FEE);
        assert_eq!(preview.gas_max, u8::MAX);
        assert_eq!(deploy.source_sha256, HPAY_REGISTRY_SOURCE_SHA256);
        assert_eq!(deploy.bytecode_sha3, HPAY_REGISTRY_BYTECODE_SHA3);
        let deploy_raw = hex::decode(&deploy.transaction.signed_transaction_hex).unwrap();
        let (deploy_tx, consumed) = protocol::transaction::transaction_create(&deploy_raw).unwrap();
        assert_eq!(consumed, deploy_raw.len());
        assert_eq!(
            deploy_tx
                .actions()
                .iter()
                .map(|action| action.kind())
                .collect::<Vec<_>>(),
            preview.action_kinds
        );
        let deploy_action = ContractDeploy::downcast(&deploy_tx.actions()[1]).unwrap();
        assert_eq!(
            deploy_action.protocol_cost.serialize(),
            Amount::unit238(CONTRACT_PROTOCOL_COST_238).serialize()
        );
        assert_eq!(
            hex::encode(deploy_action.construct_argv.to_vec()),
            preview.constructor_argv_hex
        );
        let parameters = HvmRegistryPilotChannelParameters {
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let initialization_preview = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deploy.contract_address,
            &network,
            &parameters,
            FEE,
            u8::MAX,
        )
        .unwrap();
        let init = build_hvm_registry_pilot_channel_init(
            &left,
            &hub,
            &deploy.contract_address,
            &network,
            &parameters,
            FEE,
            101,
            u8::MAX,
        )
        .unwrap();
        validate_hvm_registry_pilot_initialization_transaction(&init, &initialization_preview)
            .unwrap();
        let funding_preview = preview_hvm_registry_pilot_funding(
            left.readable(),
            hub.readable(),
            &deploy.contract_address,
            &network,
            parameters.left_deposit_zhu,
            FEE,
            u8::MAX,
        )
        .unwrap();
        let funding = build_hvm_registry_pilot_exact_funding(
            &left,
            hub.readable(),
            &deploy.contract_address,
            &network,
            parameters.left_deposit_zhu,
            FEE,
            102,
            u8::MAX,
        )
        .unwrap();
        validate_hvm_registry_pilot_funding_transaction(&funding, &funding_preview).unwrap();
        for signed in [&deploy.transaction, &init, &funding] {
            let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
            let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
            assert_eq!(consumed, raw.len());
            assert_eq!(tx.ty(), 3);
            assert!(tx.fee_purity() >= HVM_PILOT_MIN_FEE_PURITY);
            tx.verify_signature().unwrap();
            assert_eq!(hex::encode(tx.hash()), signed.transaction_hash);
        }
        let bundle =
            build_hvm_registry_pilot_recovery_bundle(&left, &hub, &deploy, 10, &parameters)
                .unwrap();
        bundle.validate_crypto().unwrap();
        assert_eq!(bundle.binding.right_hub_deposit_zhu, 0);
        assert_eq!(bundle.binding.reuse_version, 0);
    }

    #[test]
    fn registry_preview_is_public_stable_and_contains_no_signed_material() {
        let network = HvmLocalPilotNetwork::canonical();
        let hub = Account::create_by("registry-preview-hub").unwrap();
        let preview =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX).unwrap();
        let repeated =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX).unwrap();
        assert_eq!(preview, repeated);
        let json = serde_json::to_string(&preview).unwrap();
        for forbidden in [
            "signed_transaction_hex",
            "transaction_hash",
            "signature",
            "secret",
            "private",
        ] {
            assert!(!json.contains(forbidden));
        }

        let other = Account::create_by("registry-preview-other").unwrap();
        let other_preview =
            preview_hvm_registry_pilot_deployment(other.readable(), &network, FEE, u8::MAX)
                .unwrap();
        assert_ne!(preview.contract_address, other_preview.contract_address);
        assert_ne!(
            preview.unsigned_commitment,
            other_preview.unsigned_commitment
        );

        let mut wrong_network = network;
        wrong_network.chain_id = 0;
        assert!(
            preview_hvm_registry_pilot_deployment(hub.readable(), &wrong_network, FEE, u8::MAX,)
                .is_err()
        );
        let contract = Address::create_contract([7_u8; 20]).to_readable();
        assert!(
            preview_hvm_registry_pilot_deployment(&contract, &wrong_network, FEE, u8::MAX).is_err()
        );
    }

    #[test]
    fn prefund_preview_binds_exact_transfer_and_enforces_short_clock_window() {
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-prefund-preview-left").unwrap();
        let hub = Account::create_by("registry-prefund-preview-hub").unwrap();
        let preview = preview_hvm_registry_pilot_prefund(
            left.readable(),
            hub.readable(),
            &network,
            FEE,
            1_000,
            1_900,
            u8::MAX,
        )
        .unwrap();
        assert_eq!(preview.amount_zhu, HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU);
        assert_eq!(
            preview.address_topology,
            [left.readable().to_owned(), hub.readable().to_owned()]
        );
        assert_eq!(preview.action_kinds, [0x0411, 1]);
        preview.validate_for_signing(1_900).unwrap();
        assert!(preview.validate_for_signing(1_901).is_err());
        assert!(preview.validate_for_signing(969).is_err());
        preview.validate_for_signing(970).unwrap();

        let changed_fee = preview_hvm_registry_pilot_prefund(
            left.readable(),
            hub.readable(),
            &network,
            FEE + 1,
            1_000,
            1_900,
            u8::MAX,
        )
        .unwrap();
        let changed_gas = preview_hvm_registry_pilot_prefund(
            left.readable(),
            hub.readable(),
            &network,
            FEE,
            1_000,
            1_900,
            u8::MAX - 1,
        )
        .unwrap();
        let changed_time = preview_hvm_registry_pilot_prefund(
            left.readable(),
            hub.readable(),
            &network,
            FEE,
            1_001,
            1_900,
            u8::MAX,
        )
        .unwrap();
        assert_ne!(preview.unsigned_commitment, changed_fee.unsigned_commitment);
        assert_ne!(preview.unsigned_commitment, changed_gas.unsigned_commitment);
        assert_ne!(
            preview.unsigned_commitment,
            changed_time.unsigned_commitment
        );
        assert!(
            preview_hvm_registry_pilot_prefund(
                left.readable(),
                hub.readable(),
                &network,
                FEE,
                1_000,
                1_901,
                u8::MAX,
            )
            .is_err()
        );
    }

    #[test]
    fn reviewed_commitments_bind_exact_fee_gas_channel_and_funding_amount() {
        let network = HvmLocalPilotNetwork::canonical();
        let hub = Account::create_by("registry-reviewed-hub").unwrap();
        let left = Account::create_by("registry-reviewed-left").unwrap();
        let deployment =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX).unwrap();
        let changed_deploy_fee =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE + 1, u8::MAX)
                .unwrap();
        let changed_deploy_gas =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX - 1)
                .unwrap();
        assert_ne!(
            deployment.unsigned_commitment,
            changed_deploy_fee.unsigned_commitment
        );
        assert_ne!(
            deployment.unsigned_commitment,
            changed_deploy_gas.unsigned_commitment
        );

        let parameters = HvmRegistryPilotChannelParameters {
            channel_id: "77".repeat(16),
            reuse_version: 0,
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let initialization = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deployment.contract_address,
            &network,
            &parameters,
            FEE,
            u8::MAX,
        )
        .unwrap();
        let repeated_initialization = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deployment.contract_address,
            &network,
            &parameters,
            FEE,
            u8::MAX,
        )
        .unwrap();
        assert_eq!(initialization, repeated_initialization);
        let mut changed_parameters = parameters.clone();
        changed_parameters.challenge_blocks += 1;
        let changed_initialization = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deployment.contract_address,
            &network,
            &changed_parameters,
            FEE,
            u8::MAX,
        )
        .unwrap();
        assert_ne!(
            initialization.unsigned_commitment,
            changed_initialization.unsigned_commitment
        );

        let funding = preview_hvm_registry_pilot_funding(
            left.readable(),
            hub.readable(),
            &deployment.contract_address,
            &network,
            parameters.left_deposit_zhu,
            FEE,
            u8::MAX,
        )
        .unwrap();
        let changed_funding = preview_hvm_registry_pilot_funding(
            left.readable(),
            hub.readable(),
            &deployment.contract_address,
            &network,
            parameters.left_deposit_zhu + 1,
            FEE,
            u8::MAX,
        )
        .unwrap();
        assert_ne!(
            funding.unsigned_commitment,
            changed_funding.unsigned_commitment
        );
        for preview_json in [
            serde_json::to_string(&initialization).unwrap(),
            serde_json::to_string(&funding).unwrap(),
        ] {
            for forbidden in [
                "signed_transaction_hex",
                "transaction_hash",
                "signature",
                "secret",
                "private",
            ] {
                assert!(!preview_json.contains(forbidden));
            }
        }
    }

    #[test]
    fn mainnet_nonzero_hub_deposit_and_wrong_hub_fail_closed() {
        let network = HvmLocalPilotNetwork::canonical();
        let hub = Account::create_by("registry-pilot-hub-negative").unwrap();
        let left = Account::create_by("registry-pilot-left-negative").unwrap();
        let deploy =
            build_hvm_registry_pilot_deployment(&hub, &network, FEE, 100, u8::MAX).unwrap();
        let mut parameters = HvmRegistryPilotChannelParameters {
            channel_id: "44".repeat(16),
            reuse_version: 0,
            left_deposit_zhu: 1,
            right_hub_deposit_zhu: 1,
            challenge_blocks: 12,
        };
        assert!(
            build_hvm_registry_pilot_channel_init(
                &left,
                &hub,
                &deploy.contract_address,
                &network,
                &parameters,
                FEE,
                101,
                u8::MAX,
            )
            .is_err()
        );
        parameters.right_hub_deposit_zhu = 0;
        let wrong_hub = Account::create_by("registry-pilot-wrong-hub").unwrap();
        assert!(
            build_hvm_registry_pilot_recovery_bundle(&left, &wrong_hub, &deploy, 10, &parameters)
                .is_err()
        );
    }
}
