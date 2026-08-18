use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use field::{Address, Amount};
use reqwest::header::HeaderValue;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vm::ContractAddress;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{HvmChannelBindingV1, HvmChannelRecoveryBundleV1};
use crate::hvm_registry::{
    HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2, HvmRegistryRecoveryBundleV2,
};
use crate::l1_channel::L1ChannelNetworkBinding;

pub const CHANNEL_STATUS_OPENING: u8 = 0;
pub const FULLNODE_CAPABILITIES_API_V1: u64 = 1;
pub const HACASH_MAINNET_CHAIN_ID: u32 = 0;
pub const HACASH_MAINNET_BLOCK_ONE_HASH: &str =
    "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
pub const HACASH_MAINNET_MIN_SAFE_HEIGHT: u64 = 765_432;
pub const FULLNODE_MAX_TIP_AGE_SECONDS: u64 = 3_600;
pub const FULLNODE_MAX_FUTURE_SKEW_SECONDS: u64 = 120;
pub const ACTION_CHANNEL_OPEN: u16 = 2;
pub const ACTION_COOPERATIVE_ORIGINAL_CLOSE: u16 = 3;
pub const ACTION_HAC_FROM_TO_TRANSFER: u16 = 14;
pub const HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA: &str = "hpay-hvm-channel-exit-evidence/1";
pub const HPAY_CHANNEL_EXIT_CONTRACT_NAME: &str = "HPAYChannelExitV1";
pub const HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN: &str = "HPAY/HVM-CHANNEL/V1";
pub const HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE: &str = "hpay-hvm-channel-v1";
pub const HPAY_CHANNEL_EXIT_BYTECODE_SHA3: &str =
    "11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349";
pub const HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT: u64 = 18;
pub const HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA: &str = "hpay-hvm-channel-live-snapshot/1";
pub const HPAY_CHANNEL_EXIT_ACTION_KINDS: &[u16] = &[40, 41, 44];
const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const NODE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NODE_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SUBMIT_TRANSACTION_HEX_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmStorageEntry<T> {
    pub value: T,
    pub live_blocks: u64,
    pub recover_blocks: u64,
    pub active: bool,
    pub recoverable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelLiveStorage {
    pub status: HvmStorageEntry<u8>,
    pub network: HvmStorageEntry<String>,
    pub channel_id: HvmStorageEntry<String>,
    pub reuse: HvmStorageEntry<u32>,
    pub left: HvmStorageEntry<String>,
    pub right: HvmStorageEntry<String>,
    pub left_deposit: HvmStorageEntry<u64>,
    pub right_deposit: HvmStorageEntry<u64>,
    pub left_paid: HvmStorageEntry<u64>,
    pub right_paid: HvmStorageEntry<u64>,
    pub total: HvmStorageEntry<u64>,
    pub serial: HvmStorageEntry<u64>,
    pub left_balance: HvmStorageEntry<u64>,
    pub right_balance: HvmStorageEntry<u64>,
    pub challenge_blocks: HvmStorageEntry<u64>,
    pub deadline: HvmStorageEntry<u64>,
    pub left_claimed: HvmStorageEntry<bool>,
    pub right_claimed: HvmStorageEntry<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelLiveSnapshot {
    pub ret: u8,
    pub schema: String,
    pub chain_id: u32,
    pub observed_height: u64,
    pub evaluation_height: u64,
    pub contract_address: String,
    pub deployment_tx_hash: String,
    pub deployment_height: u64,
    pub deployment_action_verified: bool,
    pub bytecode_sha3: String,
    pub storage_key_count: u64,
    pub all_keys_active: bool,
    pub minimum_live_blocks: u64,
    pub minimum_recover_blocks: u64,
    pub storage: HvmChannelLiveStorage,
}

impl HvmChannelLiveSnapshot {
    /// Durable commitment to the complete observed HVM contract and all 18
    /// lease records. An owner approval may bind this value, but callers must
    /// still fetch and validate a fresh snapshot immediately before key use.
    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("HVM snapshot encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn validate_initial_open_binding(
        &self,
        binding: &HvmChannelBindingV1,
        minimum_required_live_blocks: u64,
    ) -> HubResult<()> {
        if minimum_required_live_blocks == 0 {
            return Err(HubError::Node(
                "initial HPAY HVM channel requires a positive live lease minimum".into(),
            ));
        }
        self.validate_open_binding(binding, minimum_required_live_blocks, 0)?;
        let entries = [
            entry_lease(&self.storage.status),
            entry_lease(&self.storage.network),
            entry_lease(&self.storage.channel_id),
            entry_lease(&self.storage.reuse),
            entry_lease(&self.storage.left),
            entry_lease(&self.storage.right),
            entry_lease(&self.storage.left_deposit),
            entry_lease(&self.storage.right_deposit),
            entry_lease(&self.storage.left_paid),
            entry_lease(&self.storage.right_paid),
            entry_lease(&self.storage.total),
            entry_lease(&self.storage.serial),
            entry_lease(&self.storage.left_balance),
            entry_lease(&self.storage.right_balance),
            entry_lease(&self.storage.challenge_blocks),
            entry_lease(&self.storage.deadline),
            entry_lease(&self.storage.left_claimed),
            entry_lease(&self.storage.right_claimed),
        ];
        if self.minimum_recover_blocks != 0
            || entries
                .iter()
                .any(|entry| !entry.2 || entry.3 || entry.1 != 0)
        {
            return Err(HubError::Node(
                "initial HPAY HVM leases must be active, non-recoverable and have zero recovery credit"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn validate_runtime_binding(
        &self,
        binding: &HvmChannelBindingV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        binding.validate()?;
        if self.ret != 0
            || self.schema != HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA
            || self.chain_id != binding.chain_id
            || self.observed_height < binding.deployment_height
            || self.evaluation_height != self.observed_height.checked_add(1).unwrap_or_default()
            || self.contract_address != binding.contract_address
            || self.deployment_tx_hash != binding.deployment_tx_hash
            || self.deployment_height != binding.deployment_height
            || !self.deployment_action_verified
            || self.bytecode_sha3 != binding.bytecode_sha3
            || self.storage_key_count != HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT
            || !self.all_keys_active
            || self.minimum_live_blocks < minimum_required_live_blocks
            || self.minimum_recover_blocks < minimum_required_recover_blocks
        {
            return Err(HubError::Node(
                "live HPAY HVM channel evidence does not match the approved binding".into(),
            ));
        }
        let entries = [
            entry_lease(&self.storage.status),
            entry_lease(&self.storage.network),
            entry_lease(&self.storage.channel_id),
            entry_lease(&self.storage.reuse),
            entry_lease(&self.storage.left),
            entry_lease(&self.storage.right),
            entry_lease(&self.storage.left_deposit),
            entry_lease(&self.storage.right_deposit),
            entry_lease(&self.storage.left_paid),
            entry_lease(&self.storage.right_paid),
            entry_lease(&self.storage.total),
            entry_lease(&self.storage.serial),
            entry_lease(&self.storage.left_balance),
            entry_lease(&self.storage.right_balance),
            entry_lease(&self.storage.challenge_blocks),
            entry_lease(&self.storage.deadline),
            entry_lease(&self.storage.left_claimed),
            entry_lease(&self.storage.right_claimed),
        ];
        let observed_minimum_live = entries
            .iter()
            .map(|entry| entry.0)
            .min()
            .unwrap_or_default();
        let observed_minimum_recover = entries
            .iter()
            .map(|entry| entry.1)
            .min()
            .unwrap_or_default();
        if entries.iter().any(|entry| {
            !entry.2
                || entry.3
                || entry.0 < minimum_required_live_blocks
                || entry.1 < minimum_required_recover_blocks
        }) || self.minimum_live_blocks != observed_minimum_live
            || self.minimum_recover_blocks != observed_minimum_recover
        {
            return Err(HubError::Node(
                "one or more HPAY HVM channel storage leases are not safely active".into(),
            ));
        }
        let expected_total = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM channel deposit overflow".into()))?;
        let observed_total = self
            .storage
            .left_balance
            .value
            .checked_add(self.storage.right_balance.value)
            .ok_or_else(|| HubError::Node("HVM runtime balance overflow".into()))?;
        if !matches!(self.storage.status.value, 2..=4)
            || self.storage.network.value != binding.network_instance_id
            || self.storage.channel_id.value != binding.channel_id
            || self.storage.reuse.value != binding.reuse_version
            || self.storage.left.value != binding.left_address
            || self.storage.right.value != binding.right_hub_address
            || self.storage.left_deposit.value != binding.left_deposit_zhu
            || self.storage.right_deposit.value != binding.right_hub_deposit_zhu
            || self.storage.left_paid.value != binding.left_deposit_zhu
            || self.storage.right_paid.value != binding.right_hub_deposit_zhu
            || self.storage.total.value != expected_total
            || observed_total != expected_total
            || self.storage.challenge_blocks.value != binding.challenge_blocks
        {
            return Err(HubError::Node(
                "live HPAY HVM runtime state is inconsistent with its binding".into(),
            ));
        }
        if self.storage.status.value == 2
            && (self.storage.deadline.value != 0
                || self.storage.left_claimed.value
                || self.storage.right_claimed.value)
        {
            return Err(HubError::Node(
                "open HPAY HVM channel contains challenge or claim residue".into(),
            ));
        }
        if self.storage.status.value == 3 && self.storage.deadline.value == 0 {
            return Err(HubError::Node(
                "challenging HPAY HVM channel has no deadline".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_open_binding(
        &self,
        binding: &HvmChannelBindingV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        self.validate_runtime_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        let expected_total = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM channel deposit overflow".into()))?;
        if self.storage.status.value != 2
            || self.storage.network.value != binding.network_instance_id
            || self.storage.channel_id.value != binding.channel_id
            || self.storage.reuse.value != binding.reuse_version
            || self.storage.left.value != binding.left_address
            || self.storage.right.value != binding.right_hub_address
            || self.storage.left_deposit.value != binding.left_deposit_zhu
            || self.storage.right_deposit.value != binding.right_hub_deposit_zhu
            || self.storage.left_paid.value != binding.left_deposit_zhu
            || self.storage.right_paid.value != binding.right_hub_deposit_zhu
            || self.storage.total.value != expected_total
            || self.storage.serial.value != 0
            || self.storage.left_balance.value != binding.left_deposit_zhu
            || self.storage.right_balance.value != binding.right_hub_deposit_zhu
            || self.storage.challenge_blocks.value != binding.challenge_blocks
            || self.storage.deadline.value != 0
            || self.storage.left_claimed.value
            || self.storage.right_claimed.value
        {
            return Err(HubError::Node(
                "live HPAY HVM contract state is not an exact newly opened channel".into(),
            ));
        }
        Ok(())
    }
}

fn entry_lease<T>(entry: &HvmStorageEntry<T>) -> (u64, u64, bool, bool) {
    (
        entry.live_blocks,
        entry.recover_blocks,
        entry.active,
        entry.recoverable,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelUnilateralExitDeployment {
    pub enabled: bool,
    pub contract_address: Option<String>,
    pub deployment_tx_hash: Option<String>,
    pub deployment_height: Option<u64>,
    pub independently_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelUnilateralExitOnChainVerification {
    pub observed_height: Option<u64>,
    pub confirmed_tx_height: Option<u64>,
    pub deployment_tx_confirmed: bool,
    pub contract_code_sha3: Option<String>,
    pub contract_code_matches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelUnilateralExitFundingModel {
    pub left_deposit: String,
    pub right_hub_deposit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelUnilateralExitEvidence {
    pub schema: String,
    pub manifest_valid: bool,
    pub contract_name: String,
    pub protocol_domain: String,
    pub settlement_profile: String,
    pub source_sha256: String,
    pub bytecode_sha3: String,
    pub required_action_kinds: Vec<u16>,
    pub funding_model: ChannelUnilateralExitFundingModel,
    pub storage_key_count: u64,
    pub must_renew_every_storage_key: bool,
    pub deployment: ChannelUnilateralExitDeployment,
    pub on_chain_verification: ChannelUnilateralExitOnChainVerification,
    pub deployment_verified: bool,
}

impl ChannelUnilateralExitEvidence {
    pub fn validate_candidate(&self) -> HubResult<()> {
        if self.schema != HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA
            || !self.manifest_valid
            || self.contract_name != HPAY_CHANNEL_EXIT_CONTRACT_NAME
            || self.protocol_domain != HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN
            || self.settlement_profile != HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE
            || !is_lower_hex(&self.source_sha256, 32)
            || self.bytecode_sha3 != HPAY_CHANNEL_EXIT_BYTECODE_SHA3
            || self.required_action_kinds != HPAY_CHANNEL_EXIT_ACTION_KINDS
            || self.funding_model.left_deposit != "positive"
            || self.funding_model.right_hub_deposit != "exactly_zero"
            || self.storage_key_count != HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT
            || !self.must_renew_every_storage_key
            || self.deployment_verified != self.deployment.independently_verified
        {
            return Err(HubError::Node(
                "fullnode unilateral-exit evidence does not match the reviewed HPAY HVM V1 artifact"
                    .into(),
            ));
        }
        if self.deployment_verified {
            let address = self.deployment.contract_address.as_deref().ok_or_else(|| {
                HubError::Node("verified unilateral-exit deployment is missing its address".into())
            })?;
            let address = Address::from_readable(address).map_err(|_| {
                HubError::Node("verified unilateral-exit contract address is invalid".into())
            })?;
            ContractAddress::from_addr(address).map_err(|_| {
                HubError::Node(
                    "verified unilateral-exit address is not an HVM contract address".into(),
                )
            })?;
            if !self.deployment.enabled
                || self.deployment.deployment_height < Some(HACASH_MAINNET_MIN_SAFE_HEIGHT)
                || !self
                    .deployment
                    .deployment_tx_hash
                    .as_deref()
                    .is_some_and(|hash| is_lower_hex(hash, 32))
            {
                return Err(HubError::Node(
                    "verified unilateral-exit deployment evidence is incomplete".into(),
                ));
            }
            let deployment_height = self.deployment.deployment_height.unwrap_or_default();
            if self.on_chain_verification.observed_height < Some(deployment_height)
                || self.on_chain_verification.confirmed_tx_height != Some(deployment_height)
                || !self.on_chain_verification.deployment_tx_confirmed
                || self.on_chain_verification.contract_code_sha3.as_deref()
                    != Some(HPAY_CHANNEL_EXIT_BYTECODE_SHA3)
                || !self.on_chain_verification.contract_code_matches
            {
                return Err(HubError::Node(
                    "verified unilateral-exit deployment lacks exact live chain evidence".into(),
                ));
            }
        } else if self.deployment.enabled
            || self.deployment.contract_address.is_some()
            || self.deployment.deployment_tx_hash.is_some()
            || self.deployment.deployment_height.is_some()
            || self.deployment.independently_verified
            || self.on_chain_verification.observed_height.is_some()
            || self.on_chain_verification.confirmed_tx_height.is_some()
            || self.on_chain_verification.contract_code_sha3.is_some()
        {
            return Err(HubError::Node(
                "unverified unilateral-exit candidate contains deployment authority".into(),
            ));
        } else if self.on_chain_verification.deployment_tx_confirmed
            || self.on_chain_verification.contract_code_matches
        {
            return Err(HubError::Node(
                "unverified unilateral-exit candidate claims live chain verification".into(),
            ));
        }
        Ok(())
    }

    pub fn is_verified_mainnet_deployment(&self) -> bool {
        self.validate_candidate().is_ok() && self.deployment_verified
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryUnilateralExitDeployment {
    pub enabled: bool,
    pub contract_address: Option<String>,
    pub deployment_tx_hash: Option<String>,
    pub deployment_height: Option<u64>,
    pub independently_verified: bool,
    /// Carried, published, and deliberately not a term in
    /// [`RegistryUnilateralExitEvidence::validate_candidate`]. An audit is a
    /// judgement about a contract, not a fact this node can re-derive from its
    /// block store, and everything else in this document is the latter. It
    /// travels with the evidence so a person choosing a Hub can see it.
    pub external_audit_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryUnilateralExitOnChainVerification {
    pub observed_height: Option<u64>,
    pub confirmed_tx_height: Option<u64>,
    pub deployment_tx_confirmed: bool,
    pub contract_code_sha3: Option<String>,
    pub contract_code_matches: bool,
    /// The deploying block re-read: this transaction really carries a
    /// `ContractDeploy` whose derived address and code hash are the ones
    /// claimed. V1 has no equivalent because a per-channel contract carries no
    /// bindings; a shared registry carries two, and both live here.
    pub deployment_action_verified: bool,
    /// The deploying transaction's own main signer.
    pub hub_address: Option<String>,
    /// The exact 32-byte constructor argument the deploying transaction
    /// carried, and the network instance id the node computes for itself.
    /// Equal, or the registry belongs to another chain.
    pub constructor_network_instance_id: Option<String>,
    pub node_network_instance_id: Option<String>,
    pub network_binding_matches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryUnilateralExitChannelModel {
    pub left_deposit: String,
    pub right_hub_deposit: String,
    pub maximum_active_channels_per_left_address: u64,
    pub first_reuse: u32,
}

/// The fullnode's evidence about the **shared registry V2** contract — the
/// settlement profile this system actually uses.
///
/// This type exists because [`ChannelUnilateralExitEvidence`] is hard-bound to
/// `hpay-hvm-channel-v1` by
/// [`HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE`], and the path that was built,
/// proven and shipped is
/// [`crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE`]. A gate that
/// weighed the V1 document was weighing a different contract: deploying the
/// registry to mainnet would not have moved it, and — worse in the other
/// direction — deploying the *V1* contract would have moved a flag about a
/// path no user travels.
///
/// Same shape as V1 on purpose. `validate_candidate` is the same two-branch
/// rule: a verified document must carry complete, self-consistent, chain-
/// derived deployment authority, and an unverified one must carry none of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryUnilateralExitEvidence {
    pub schema: String,
    pub manifest_valid: bool,
    pub contract_name: String,
    pub protocol_domain: String,
    pub settlement_profile: String,
    pub source_sha256: String,
    pub bytecode_sha3: String,
    pub required_action_kinds: Vec<u16>,
    pub channel_model: RegistryUnilateralExitChannelModel,
    pub registry_key_count: u64,
    pub channel_key_count: u64,
    pub must_renew_every_registry_key: bool,
    pub must_renew_every_channel_key: bool,
    pub maximum_renewal_step_periods: u64,
    pub deployment: RegistryUnilateralExitDeployment,
    pub on_chain_verification: RegistryUnilateralExitOnChainVerification,
    pub deployment_verified: bool,
}

impl RegistryUnilateralExitEvidence {
    pub fn validate_candidate(&self) -> HubResult<()> {
        if self.schema != crate::hvm_registry::HVM_REGISTRY_EXIT_EVIDENCE_SCHEMA
            || !self.manifest_valid
            || self.contract_name != crate::hvm_registry::HPAY_REGISTRY_CONTRACT_NAME
            || self.protocol_domain != crate::hvm_registry::HPAY_REGISTRY_PROTOCOL_DOMAIN
            || self.settlement_profile != crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE
            || !is_lower_hex(&self.source_sha256, 32)
            || self.bytecode_sha3 != crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3
            || self.required_action_kinds
                != crate::hvm_registry::HPAY_REGISTRY_REQUIRED_ACTION_KINDS
            || self.channel_model.left_deposit != "positive"
            || self.channel_model.right_hub_deposit != "exactly_zero"
            || self.channel_model.maximum_active_channels_per_left_address != 1
            || self.channel_model.first_reuse != 0
            || self.registry_key_count != crate::hvm_registry::HVM_REGISTRY_STORAGE_KEY_COUNT
            || self.channel_key_count != crate::hvm_registry::HVM_REGISTRY_CHANNEL_KEY_COUNT
            || !self.must_renew_every_registry_key
            || !self.must_renew_every_channel_key
            || self.maximum_renewal_step_periods != crate::hvm_registry::HPAY_REGISTRY_MAX_RENT_STEP
            || self.deployment_verified != self.deployment.independently_verified
        {
            return Err(HubError::Node(
                "fullnode registry-exit evidence does not match the reviewed HPAY HVM shared \
                 registry V2 artifact"
                    .into(),
            ));
        }
        if self.deployment_verified {
            let address = self.deployment.contract_address.as_deref().ok_or_else(|| {
                HubError::Node("verified registry-exit deployment is missing its address".into())
            })?;
            let address = Address::from_readable(address).map_err(|_| {
                HubError::Node("verified registry-exit contract address is invalid".into())
            })?;
            ContractAddress::from_addr(address).map_err(|_| {
                HubError::Node(
                    "verified registry-exit address is not an HVM contract address".into(),
                )
            })?;
            if !self.deployment.enabled
                || self.deployment.deployment_height < Some(HACASH_MAINNET_MIN_SAFE_HEIGHT)
                || !self
                    .deployment
                    .deployment_tx_hash
                    .as_deref()
                    .is_some_and(|hash| is_lower_hex(hash, 32))
            {
                return Err(HubError::Node(
                    "verified registry-exit deployment evidence is incomplete".into(),
                ));
            }
            let deployment_height = self.deployment.deployment_height.unwrap_or_default();
            if self.on_chain_verification.observed_height < Some(deployment_height)
                || self.on_chain_verification.confirmed_tx_height != Some(deployment_height)
                || !self.on_chain_verification.deployment_tx_confirmed
                || self.on_chain_verification.contract_code_sha3.as_deref()
                    != Some(crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3)
                || !self.on_chain_verification.contract_code_matches
            {
                return Err(HubError::Node(
                    "verified registry-exit deployment lacks exact live chain evidence".into(),
                ));
            }
            // The two V2-only bindings. A shared registry is one contract for
            // one Hub on one network, so "this code is on chain" is not enough
            // on its own: the deploying transaction has to be the one that put
            // it there, and it has to have been constructed for this network.
            let hub_address = self
                .on_chain_verification
                .hub_address
                .as_deref()
                .ok_or_else(|| {
                    HubError::Node(
                        "verified registry-exit deployment does not name its deploying Hub".into(),
                    )
                })?;
            Address::from_readable(hub_address).map_err(|_| {
                HubError::Node("verified registry-exit Hub address is invalid".into())
            })?;
            let constructor = self
                .on_chain_verification
                .constructor_network_instance_id
                .as_deref();
            if !self.on_chain_verification.deployment_action_verified
                || !self.on_chain_verification.network_binding_matches
                || !constructor.is_some_and(|value| is_lower_hex(value, 32))
                || constructor
                    != self
                        .on_chain_verification
                        .node_network_instance_id
                        .as_deref()
            {
                return Err(HubError::Node(
                    "verified registry-exit deployment is not bound to this node's own network \
                     instance"
                        .into(),
                ));
            }
        } else if self.deployment.enabled
            || self.deployment.contract_address.is_some()
            || self.deployment.deployment_tx_hash.is_some()
            || self.deployment.deployment_height.is_some()
            || self.deployment.independently_verified
            || self.on_chain_verification.observed_height.is_some()
            || self.on_chain_verification.confirmed_tx_height.is_some()
            || self.on_chain_verification.contract_code_sha3.is_some()
            || self.on_chain_verification.hub_address.is_some()
            || self
                .on_chain_verification
                .constructor_network_instance_id
                .is_some()
        {
            return Err(HubError::Node(
                "unverified registry-exit candidate contains deployment authority".into(),
            ));
        } else if self.on_chain_verification.deployment_tx_confirmed
            || self.on_chain_verification.contract_code_matches
            || self.on_chain_verification.deployment_action_verified
            || self.on_chain_verification.network_binding_matches
        {
            return Err(HubError::Node(
                "unverified registry-exit candidate claims live chain verification".into(),
            ));
        }
        Ok(())
    }

    pub fn is_verified_mainnet_deployment(&self) -> bool {
        self.validate_candidate().is_ok() && self.deployment_verified
    }
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullnodeCapabilitiesV1 {
    pub observed_unix: u64,
    pub api_version: u64,
    pub chain_id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
    pub network_kind: String,
    pub node_profile_id: String,
    pub block_1_hash: String,
    pub network_instance_id: Option<String>,
    pub transaction_format_version: u64,
    pub tip_timestamp_unix: u64,
    pub tip_age_seconds: u64,
    pub registered_actions: Vec<u16>,
    pub enabled_actions: Vec<u16>,
    pub enabled_transactions: Vec<u8>,
    pub transaction_submit_bound: bool,
    pub hpay_channel_registry_query: bool,
    /// True only when this exact node can parse, validate and execute the
    /// reviewed channel challenge, response and final-claim lifecycle.
    pub channel_unilateral_exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_unilateral_exit_evidence: Option<ChannelUnilateralExitEvidence>,
    /// The same statement for the shared registry V2 profile — the one this
    /// system settles on. `#[serde(default)]` so a readiness document written
    /// by an older Hub still parses, and defaults to the fail-closed answer.
    #[serde(default)]
    pub channel_registry_unilateral_exit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_registry_unilateral_exit_evidence: Option<RegistryUnilateralExitEvidence>,
}

impl FullnodeCapabilitiesV1 {
    pub fn action_enabled(&self, kind: u16) -> bool {
        self.enabled_actions.binary_search(&kind).is_ok()
    }

    pub fn l1_channel_network_binding(
        &self,
    ) -> HubResult<crate::l1_channel::L1ChannelNetworkBinding> {
        if self.enabled_transactions.binary_search(&2).is_err()
            || self
                .enabled_actions
                .binary_search(&ACTION_CHANNEL_OPEN)
                .is_err()
            || self.enabled_actions.binary_search(&0x0411).is_err()
            || !self.transaction_submit_bound
        {
            return Err(HubError::Node(
                "fullnode cannot execute the exact channel-open transaction topology".into(),
            ));
        }
        crate::l1_channel::L1ChannelNetworkBinding::from_node_identity(
            &self.network_kind,
            self.mainnet,
            self.chain_id,
            &self.block_1_hash,
            &self.node_profile_id,
            self.network_instance_id.as_deref(),
            self.transaction_format_version,
        )
    }

    fn parse(value: &Value) -> HubResult<Self> {
        if value.get("ret").and_then(Value::as_u64) != Some(0) {
            return Err(HubError::Node(
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("fullnode capabilities query failed")
                    .to_string(),
            ));
        }
        let api_version = required_u64(value, "api_version")?;
        if api_version != FULLNODE_CAPABILITIES_API_V1 {
            return Err(HubError::Node(format!(
                "unsupported fullnode capabilities api_version {api_version}"
            )));
        }
        let chain = value
            .get("chain")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing chain object".into()))?;
        let chain_id = u32::try_from(required_object_u64(chain, "id")?)
            .map_err(|_| HubError::Node("fullnode chain id exceeds u32".into()))?;
        let height = required_object_u64(chain, "height")?;
        let next_height = required_object_u64(chain, "next_height")?;
        if height.checked_add(1) != Some(next_height) {
            return Err(HubError::Node(
                "fullnode capabilities next_height is inconsistent".into(),
            ));
        }
        let mainnet = chain
            .get("mainnet")
            .and_then(Value::as_bool)
            .ok_or_else(|| HubError::Node("fullnode chain.mainnet must be boolean".into()))?;
        if mainnet != (chain_id == HACASH_MAINNET_CHAIN_ID) {
            return Err(HubError::Node(
                "fullnode capabilities chain identity is inconsistent".into(),
            ));
        }
        let network = value
            .get("network")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing network".into()))?;
        let network_kind = network
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let node_profile_id = network
            .get("node_profile_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let block_1_hash = network
            .get("block_1_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let transaction_format_version =
            required_object_u64(network, "transaction_format_version")?;
        let network_instance_id = network
            .get("instance_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if mainnet {
            let instance = network_instance_id.as_deref().unwrap_or_default();
            if network_kind != "mainnet" || block_1_hash != HACASH_MAINNET_BLOCK_ONE_HASH {
                return Err(HubError::Node(
                    "fullnode mainnet genesis identity is not the pinned Hacash network".into(),
                ));
            }
            if !is_lower_hex(instance, 32) {
                return Err(HubError::Node(
                    "fullnode mainnet instance_id is invalid".into(),
                ));
            }
        }
        let sync = value
            .get("sync")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing sync object".into()))?;
        let tip_timestamp_unix = required_object_u64(sync, "tip_timestamp_unix")?;
        let max_tip_age = required_object_u64(sync, "max_tip_age_seconds")?;
        let fresh = sync
            .get("fresh")
            .and_then(Value::as_bool)
            .ok_or_else(|| HubError::Node("fullnode sync.fresh must be boolean".into()))?;
        if max_tip_age != FULLNODE_MAX_TIP_AGE_SECONDS {
            return Err(HubError::Node(
                "fullnode sync freshness policy is incompatible".into(),
            ));
        }
        let observed_unix = now_unix();
        if tip_timestamp_unix > observed_unix.saturating_add(FULLNODE_MAX_FUTURE_SKEW_SECONDS) {
            return Err(HubError::Node(
                "fullnode chain tip timestamp is too far in the future".into(),
            ));
        }
        let tip_age_seconds = observed_unix.saturating_sub(tip_timestamp_unix);
        if !fresh || tip_age_seconds > FULLNODE_MAX_TIP_AGE_SECONDS {
            return Err(HubError::Node(format!(
                "fullnode chain tip is stale ({tip_age_seconds}s)"
            )));
        }
        let actions = value
            .get("actions")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing actions".into()))?;
        let registered_actions = parse_action_list(actions.get("registered"), "registered")?;
        let enabled_actions = parse_action_list(actions.get("enabled"), "enabled")?;
        let transactions = value
            .get("transactions")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing transactions".into()))?;
        let enabled_transactions = parse_transaction_list(transactions.get("enabled"), "enabled")?;
        let transaction_submit_bound = value
            .get("api")
            .and_then(Value::as_object)
            .and_then(|api| api.get("transaction_submit_bound"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let hpay_channel_registry_query = value
            .get("api")
            .and_then(Value::as_object)
            .and_then(|api| api.get("hpay_channel_registry_query"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if enabled_actions
            .iter()
            .any(|kind| !registered_actions.contains(kind))
        {
            return Err(HubError::Node(
                "fullnode enabled action is not registered".into(),
            ));
        }
        let channel_unilateral_exit = value
            .get("features")
            .and_then(Value::as_object)
            .and_then(|features| features.get("channel_unilateral_exit"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let channel_unilateral_exit_evidence = value
            .get("features")
            .and_then(Value::as_object)
            .and_then(|features| features.get("channel_unilateral_exit_evidence"))
            .map(|evidence| {
                serde_json::from_value::<ChannelUnilateralExitEvidence>(evidence.clone()).map_err(
                    |_| HubError::Node("fullnode unilateral-exit evidence is malformed".into()),
                )
            })
            .transpose()?;
        if let Some(evidence) = channel_unilateral_exit_evidence.as_ref() {
            evidence.validate_candidate()?;
        }
        if channel_unilateral_exit
            && !channel_unilateral_exit_evidence
                .as_ref()
                .is_some_and(ChannelUnilateralExitEvidence::is_verified_mainnet_deployment)
        {
            return Err(HubError::Node(
                "fullnode claims unilateral exit without an exact verified HVM deployment".into(),
            ));
        }
        let channel_registry_unilateral_exit = value
            .get("features")
            .and_then(Value::as_object)
            .and_then(|features| features.get("channel_registry_unilateral_exit"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let channel_registry_unilateral_exit_evidence = value
            .get("features")
            .and_then(Value::as_object)
            .and_then(|features| features.get("channel_registry_unilateral_exit_evidence"))
            .map(|evidence| {
                serde_json::from_value::<RegistryUnilateralExitEvidence>(evidence.clone()).map_err(
                    |_| HubError::Node("fullnode registry-exit evidence is malformed".into()),
                )
            })
            .transpose()?;
        if let Some(evidence) = channel_registry_unilateral_exit_evidence.as_ref() {
            evidence.validate_candidate()?;
        }
        if channel_registry_unilateral_exit
            && !channel_registry_unilateral_exit_evidence
                .as_ref()
                .is_some_and(RegistryUnilateralExitEvidence::is_verified_mainnet_deployment)
        {
            return Err(HubError::Node(
                "fullnode claims registry unilateral exit without an exact verified HVM \
                 deployment"
                    .into(),
            ));
        }
        // The registry is bound to one network by its constructor. The
        // evidence says which network the *node* thinks it is on; this is the
        // same node's own identity in the same document. If those two ever
        // disagree the node is not describing itself, and nothing it says
        // about a deployment can be relied on.
        if let Some(evidence) = channel_registry_unilateral_exit_evidence.as_ref()
            && evidence.deployment_verified
            && evidence
                .on_chain_verification
                .node_network_instance_id
                .as_deref()
                != network_instance_id.as_deref()
        {
            return Err(HubError::Node(
                "fullnode registry-exit evidence names a different network instance than the \
                 node itself"
                    .into(),
            ));
        }
        Ok(Self {
            observed_unix,
            api_version,
            chain_id,
            height,
            next_height,
            mainnet,
            network_kind,
            node_profile_id,
            block_1_hash,
            network_instance_id,
            transaction_format_version,
            tip_timestamp_unix,
            tip_age_seconds,
            registered_actions,
            enabled_actions,
            enabled_transactions,
            transaction_submit_bound,
            hpay_channel_registry_query,
            channel_unilateral_exit,
            channel_unilateral_exit_evidence,
            channel_registry_unilateral_exit,
            channel_registry_unilateral_exit_evidence,
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ChannelPartyBalance {
    pub address: String,
    pub hacash: String,
    pub satoshi: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct ChannelChallenging {
    #[serde(default)]
    pub assert_bill_auto_number: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ChannelInfo {
    #[serde(default)]
    pub ret: i32,
    pub id: String,
    pub status: u8,
    #[serde(default)]
    pub open_height: u64,
    #[serde(default)]
    pub close_height: u64,
    #[serde(default)]
    pub reuse_version: u64,
    pub left: ChannelPartyBalance,
    pub right: ChannelPartyBalance,
    #[serde(default)]
    pub challenging: Option<ChannelChallenging>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionObservation {
    pub hash: String,
    pub body_hex: String,
    pub pending: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub confirmations: u64,
}

impl ChannelInfo {
    /// On-chain floor for the next bill serial (from an active challenge assert).
    pub fn l1_bill_auto_floor(&self) -> u64 {
        self.challenging
            .as_ref()
            .map(|c| c.assert_bill_auto_number)
            .unwrap_or(0)
    }

    pub fn is_open(&self) -> bool {
        self.status == CHANNEL_STATUS_OPENING
    }

    pub fn party_side(&self, address: &str) -> Option<ChannelSide> {
        if self.left.address == address {
            Some(ChannelSide::Left)
        } else if self.right.address == address {
            Some(ChannelSide::Right)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSide {
    Left,
    Right,
}

pub(crate) fn validate_mainnet_node_url(node_url: &str) -> HubResult<()> {
    let parsed = reqwest::Url::parse(node_url)
        .map_err(|_| HubError::Node("mainnet fullnode URL is invalid".into()))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(HubError::Node(
            "mainnet fullnode URL must be a clean origin without credentials, path, query, or fragment"
                .into(),
        ));
    }
    let loopback = parsed.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(HubError::Node(
            "mainnet fullnode URL must use HTTPS or loopback HTTP".into(),
        ));
    }
    Ok(())
}
pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
    api_token: Option<HeaderValue>,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> HubResult<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(NODE_CONNECT_TIMEOUT)
            .timeout(NODE_REQUEST_TIMEOUT)
            .user_agent(concat!("HPAYFastPayHub/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                HubError::Node(format!("cannot create fullnode HTTP client: {error}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            api_token: None,
        })
    }

    #[cfg(feature = "local-pilot-tools")]
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn with_api_token(mut self, api_token: Option<&str>) -> HubResult<Self> {
        if let Some(token) = api_token.filter(|token| !token.is_empty()) {
            if token.len() > 512 || token.trim() != token {
                return Err(HubError::Node(
                    "fullnode API token is oversized or has surrounding whitespace".into(),
                ));
            }
            let mut value = HeaderValue::from_str(token).map_err(|_| {
                HubError::Node("fullnode API token contains invalid header bytes".into())
            })?;
            value.set_sensitive(true);
            self.api_token = Some(value);
        }
        Ok(self)
    }

    fn get(&self, url: String) -> reqwest::RequestBuilder {
        self.attach_api_token(self.http.get(url))
    }

    fn post(&self, url: String) -> reqwest::RequestBuilder {
        self.attach_api_token(self.http.post(url))
    }

    fn attach_api_token(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_token {
            Some(token) => request.header("x-api-token", token.clone()),
            None => request,
        }
    }

    pub async fn capabilities(&self) -> HubResult<FullnodeCapabilitiesV1> {
        let url = format!("{}/query/capabilities", self.base_url);
        let response = self
            .get(url)
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "capabilities HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "capabilities").await?;
        FullnodeCapabilitiesV1::parse(&value)
    }

    pub async fn hvm_channel_snapshot(
        &self,
        binding: &HvmChannelBindingV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmChannelLiveSnapshot> {
        binding.validate()?;
        let url = format!("{}/query/hpay/channel-exit", self.base_url);
        let deployment_height = binding.deployment_height.to_string();
        let response = self
            .get(url)
            .query(&[
                ("contract", binding.contract_address.as_str()),
                ("deployment_tx_hash", binding.deployment_tx_hash.as_str()),
                ("deployment_height", deployment_height.as_str()),
            ])
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "HPAY HVM channel snapshot HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "HPAY HVM channel snapshot").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            return Err(HubError::Node(
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("fullnode rejected HPAY HVM channel snapshot")
                    .to_owned(),
            ));
        }
        let snapshot: HvmChannelLiveSnapshot = serde_json::from_value(value).map_err(|error| {
            HubError::Node(format!("invalid HPAY HVM channel snapshot: {error}"))
        })?;
        snapshot.validate_open_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        Ok(snapshot)
    }

    pub async fn hvm_channel_runtime_snapshot(
        &self,
        binding: &HvmChannelBindingV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmChannelLiveSnapshot> {
        binding.validate()?;
        let url = format!("{}/query/hpay/channel-exit", self.base_url);
        let deployment_height = binding.deployment_height.to_string();
        let response = self
            .get(url)
            .query(&[
                ("contract", binding.contract_address.as_str()),
                ("deployment_tx_hash", binding.deployment_tx_hash.as_str()),
                ("deployment_height", deployment_height.as_str()),
            ])
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "HPAY HVM channel snapshot HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "HPAY HVM runtime snapshot").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            return Err(HubError::Node(
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("fullnode rejected HPAY HVM runtime snapshot")
                    .to_owned(),
            ));
        }
        let snapshot: HvmChannelLiveSnapshot = serde_json::from_value(value).map_err(|error| {
            HubError::Node(format!("invalid HPAY HVM runtime snapshot: {error}"))
        })?;
        snapshot.validate_runtime_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        Ok(snapshot)
    }

    pub async fn verify_hvm_recovery_bundle(
        &self,
        bundle: &HvmChannelRecoveryBundleV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmChannelLiveSnapshot> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_capabilities_for_binding(&capabilities, &bundle.binding)?;
        self.hvm_channel_snapshot(
            &bundle.binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )
        .await
    }

    pub async fn verify_hvm_initial_recovery_bundle(
        &self,
        bundle: &HvmChannelRecoveryBundleV1,
        minimum_required_live_blocks: u64,
    ) -> HubResult<HvmChannelLiveSnapshot> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_capabilities_for_binding(&capabilities, &bundle.binding)?;
        let snapshot = self
            .hvm_channel_snapshot(&bundle.binding, minimum_required_live_blocks, 0)
            .await?;
        snapshot.validate_initial_open_binding(&bundle.binding, minimum_required_live_blocks)?;
        Ok(snapshot)
    }

    pub async fn verify_hvm_runtime_channel(
        &self,
        bundle: &HvmChannelRecoveryBundleV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmChannelLiveSnapshot> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_capabilities_for_binding(&capabilities, &bundle.binding)?;
        self.hvm_channel_runtime_snapshot(
            &bundle.binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )
        .await
    }

    async fn hvm_registry_snapshot_unchecked(
        &self,
        binding: &HvmRegistryBindingV2,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        binding.validate()?;
        let url = format!("{}/query/hpay/channel-registry", self.base_url);
        let deployment_height = binding.deployment_height.to_string();
        let response = self
            .get(url)
            .query(&[
                ("contract", binding.contract_address.as_str()),
                ("deployment_tx_hash", binding.deployment_tx_hash.as_str()),
                ("deployment_height", deployment_height.as_str()),
                ("left", binding.left_address.as_str()),
            ])
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "HPAY HVM registry snapshot HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "HPAY HVM registry snapshot").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            return Err(HubError::Node(
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("fullnode rejected HPAY HVM registry snapshot")
                    .to_owned(),
            ));
        }
        serde_json::from_value(value)
            .map_err(|error| HubError::Node(format!("invalid HVM registry snapshot: {error}")))
    }

    pub async fn hvm_registry_open_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        let snapshot = self.hvm_registry_snapshot_unchecked(binding).await?;
        snapshot.validate_open_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        Ok(snapshot)
    }

    pub async fn hvm_registry_runtime_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        let snapshot = self.hvm_registry_snapshot_unchecked(binding).await?;
        snapshot.validate_runtime_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        Ok(snapshot)
    }

    pub async fn verify_hvm_registry_initial_bundle(
        &self,
        bundle: &HvmRegistryRecoveryBundleV2,
        minimum_required_live_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_registry_capabilities_for_binding(&capabilities, &bundle.binding)?;
        let snapshot = self
            .hvm_registry_open_snapshot(&bundle.binding, minimum_required_live_blocks, 0)
            .await?;
        snapshot.validate_initial_open_binding(&bundle.binding, minimum_required_live_blocks)?;
        Ok(snapshot)
    }

    /// The last look before the deposit leaves the wallet.
    ///
    /// `init` has confirmed; the contract holds no coin yet. This re-reads the
    /// channel the countersigned bundle names and refuses unless the chain
    /// agrees with the binding the Hub signed over - which is the one thing the
    /// signature itself cannot tell you, because `PayableHAC` never looks at
    /// the channel id, the reuse version or the challenge window and would
    /// happily accept the deposit into a channel whose refund bill hashes to
    /// something `verify_bill` rejects.
    ///
    /// Deliberately not routed through `verify_hvm_registry_initial_bundle`,
    /// whose name suggests it would do: that one requires a channel that is
    /// already funded.
    pub async fn verify_hvm_registry_prefunding_bundle(
        &self,
        bundle: &HvmRegistryRecoveryBundleV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_registry_capabilities_for_binding(&capabilities, &bundle.binding)?;
        let snapshot = self
            .hvm_registry_snapshot_unchecked(&bundle.binding)
            .await?;
        snapshot.validate_prefunding_binding(
            &bundle.binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        Ok(snapshot)
    }

    pub async fn verify_hvm_registry_runtime_bundle(
        &self,
        bundle: &HvmRegistryRecoveryBundleV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_registry_capabilities_for_binding(&capabilities, &bundle.binding)?;
        self.hvm_registry_runtime_snapshot(
            &bundle.binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )
        .await
    }

    pub async fn verify_hvm_registry_open_bundle(
        &self,
        bundle: &HvmRegistryRecoveryBundleV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        bundle.validate_crypto()?;
        let capabilities = self.capabilities().await?;
        validate_hvm_registry_capabilities_for_binding(&capabilities, &bundle.binding)?;
        self.hvm_registry_open_snapshot(
            &bundle.binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )
        .await
    }

    pub async fn query_channel(&self, channel_id_hex: &str) -> HubResult<ChannelInfo> {
        let url = format!(
            "{}/query/channel?unit=fin&id={channel_id_hex}",
            self.base_url
        );
        let resp = self
            .get(url)
            .send()
            .await
            .map_err(|e| HubError::Node(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(HubError::Node(format!("channel HTTP {}", resp.status())));
        }
        let value: Value = read_bounded_json(resp, "channel").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            let message = value
                .get("err")
                .and_then(Value::as_str)
                .unwrap_or("fullnode rejected channel query")
                .trim();
            if message.eq_ignore_ascii_case("channel not found") {
                return Err(HubError::NotFound(format!("channel {channel_id_hex}")));
            }
            return Err(HubError::Node(format!(
                "fullnode channel query rejected: {message}"
            )));
        }
        serde_json::from_value(value)
            .map_err(|error| HubError::Node(format!("invalid fullnode channel response: {error}")))
    }

    pub async fn query_balance_zhu(&self, address: &str) -> HubResult<u128> {
        let url = format!("{}/query/balance?unit=fin&address={address}", self.base_url);
        let response = self
            .get(url)
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "balance HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "balance").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            let message = value
                .get("err")
                .and_then(Value::as_str)
                .unwrap_or("fullnode rejected balance query")
                .trim();
            return Err(HubError::Node(format!(
                "fullnode balance query rejected: {message}"
            )));
        }
        let list = value
            .get("list")
            .and_then(Value::as_array)
            .ok_or_else(|| HubError::Node("fullnode balance response has no list".into()))?;
        let mut exact = list
            .iter()
            .filter(|entry| entry.get("address").and_then(Value::as_str) == Some(address))
            .collect::<Vec<_>>();
        let selected = match exact.len() {
            1 => exact.pop().expect("length checked"),
            0 if list.len() == 1 && list[0].get("address").is_none() => &list[0],
            _ => {
                return Err(HubError::Node(
                    "fullnode balance response does not contain one exact address".into(),
                ));
            }
        };
        let balance = selected
            .get("hacash")
            .and_then(Value::as_str)
            .ok_or_else(|| HubError::Node("fullnode balance response has no HAC value".into()))?;
        parse_fin_balance_zhu(balance)
    }

    pub async fn query_transaction(
        &self,
        transaction_hash: &str,
    ) -> HubResult<Option<TransactionObservation>> {
        self.query_transaction_with_contract(transaction_hash, 2, None)
            .await
    }

    pub async fn query_hvm_transaction(
        &self,
        transaction_hash: &str,
    ) -> HubResult<Option<TransactionObservation>> {
        self.query_transaction_with_contract(transaction_hash, 3, Some(44))
            .await
    }

    /// The shared HVM registry's own Action 44 contract calls — lease renewal,
    /// challenge, respond and finalize. Unlike the v1 HVM path above, a
    /// registry confirmation is judged against an exact canonical block
    /// anchor, so the anchor is resolved here rather than left absent.
    pub async fn query_hvm_registry_call_transaction(
        &self,
        transaction_hash: &str,
    ) -> HubResult<Option<TransactionObservation>> {
        let mut observation = self
            .query_transaction_with_contract(transaction_hash, 3, Some(44))
            .await?;
        self.anchor_confirmed_observation(&mut observation, transaction_hash)
            .await?;
        Ok(observation)
    }

    /// A registry claim carries no Action 44: the coin moves through the
    /// contract's `PermitHAC` hook, which is reached by the Action 14
    /// `HacFromToTrs` itself. Demanding an Action 44 here would reject the
    /// hub's own claim observation, so the proof required is Action 14 —
    /// no weaker, just the correct one for this shape.
    pub async fn query_hvm_registry_claim_transaction(
        &self,
        transaction_hash: &str,
    ) -> HubResult<Option<TransactionObservation>> {
        let mut observation = self
            .query_transaction_with_contract(transaction_hash, 3, Some(14))
            .await?;
        self.anchor_confirmed_observation(&mut observation, transaction_hash)
            .await?;
        Ok(observation)
    }

    /// Give a confirmed observation the canonical block anchor it needs.
    ///
    /// A confirmation is only evidence if it names the exact block it lives
    /// in, so `apply_hvm_registry_observation` refuses any registry
    /// confirmation that arrives without a block hash. Not every fullnode puts
    /// one in the transaction query: this chain's `/query/transaction` answers
    /// with a `block` object carrying only `height` and `timestamp`. Without
    /// this step every Hub-side registry chain operation — lease renewal,
    /// challenge, respond, finalize and the Action 14 claim — latches
    /// `RecoveryRequired` the moment its transaction is mined, because the
    /// anchor it is judged against is never fetched from anywhere.
    ///
    /// The anchor is therefore read from the canonical block itself, exactly
    /// as the Local Pilot lifecycle path already reads it. That is not a
    /// weaker source than an echoed `block.hash`: `parse_block_transaction_anchor`
    /// also proves the block at that height contains this exact transaction
    /// exactly once. When the transaction query does carry a hash it is kept
    /// and no block query is made, so a node that already anchors its own
    /// answers is judged exactly as before.
    async fn anchor_confirmed_observation(
        &self,
        observation: &mut Option<TransactionObservation>,
        transaction_hash: &str,
    ) -> HubResult<()> {
        let Some(confirmed) = observation.as_mut() else {
            return Ok(());
        };
        if confirmed.pending || confirmed.block_hash.is_some() {
            return Ok(());
        }
        let height = confirmed.block_height.ok_or_else(|| {
            HubError::Node("confirmed transaction query has no block height".into())
        })?;
        confirmed.block_hash = Some(
            self.query_block_transaction_anchor(height, transaction_hash)
                .await?,
        );
        Ok(())
    }

    #[cfg(feature = "local-pilot-tools")]
    pub async fn query_hvm_pilot_transaction(
        &self,
        transaction_hash: &str,
        required_action: u16,
    ) -> HubResult<Option<TransactionObservation>> {
        // 14 is the Action 14 `HacFromToTrs` payout claim, the only shape that
        // moves HAC out of the registry contract. The rest of the allowlist is
        // unchanged.
        if !matches!(required_action, 1 | 14 | 40 | 44) {
            return Err(HubError::Node(
                "HVM pilot reconciliation action is not allowlisted".into(),
            ));
        }
        let mut observation = self
            .query_transaction_with_contract(transaction_hash, 3, Some(required_action))
            .await?;
        if let Some(confirmed) = observation.as_mut()
            && !confirmed.pending
        {
            let height = confirmed.block_height.ok_or_else(|| {
                HubError::Node("confirmed HVM pilot transaction has no block height".into())
            })?;
            let anchor = self
                .query_block_transaction_anchor(height, transaction_hash)
                .await?;
            if confirmed
                .block_hash
                .as_ref()
                .is_some_and(|embedded| embedded != &anchor)
            {
                return Err(HubError::Node(
                    "transaction query and canonical block anchor disagree".into(),
                ));
            }
            confirmed.block_hash = Some(anchor);
        }
        Ok(observation)
    }

    async fn query_block_transaction_anchor(
        &self,
        height: u64,
        transaction_hash: &str,
    ) -> HubResult<String> {
        if height == 0 {
            return Err(HubError::Node(
                "transaction block anchor height is zero".into(),
            ));
        }
        let url = format!(
            "{}/query/block/intro?height={height}&tx_hash_list=true",
            self.base_url
        );
        let response =
            self.get(url).send().await.map_err(|error| {
                HubError::Node(format!("block anchor query unavailable: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "block anchor query HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "block anchor query").await?;
        parse_block_transaction_anchor(&value, height, transaction_hash)
    }

    async fn query_transaction_with_contract(
        &self,
        transaction_hash: &str,
        expected_type: u8,
        required_action: Option<u16>,
    ) -> HubResult<Option<TransactionObservation>> {
        if transaction_hash.len() != 64
            || !transaction_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HubError::Node("transaction hash is malformed".into()));
        }
        let url = format!(
            "{}/query/transaction?unit=fin&hash={transaction_hash}&body=true&signature=true&action=true",
            self.base_url
        );
        let response =
            self.get(url).send().await.map_err(|error| {
                HubError::Node(format!("transaction query unavailable: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "transaction query HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "transaction query").await?;
        parse_transaction_observation_kind(&value, transaction_hash, expected_type, required_action)
    }

    pub async fn submit_transaction(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
    ) -> HubResult<String> {
        if signed_transaction_hex.is_empty()
            || signed_transaction_hex.len() > MAX_SUBMIT_TRANSACTION_HEX_BYTES
            || !signed_transaction_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || expected_transaction_hash.len() != 64
            || !expected_transaction_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HubError::Node(
                "signed transaction or expected hash is malformed".into(),
            ));
        }
        let url = format!("{}/submit/transaction?hexbody=true", self.base_url);
        let response = self
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(signed_transaction_hex.to_owned())
            .send()
            .await
            .map_err(|error| HubError::Node(format!("transaction submit unavailable: {error}")))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "transaction submit HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "transaction submit").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            let message = value
                .get("err")
                .or_else(|| value.get("error"))
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("fullnode rejected the transaction");
            return Err(HubError::Node(message.to_owned()));
        }
        if let Some(actual_hash) = value.get("hash").and_then(Value::as_str)
            && !actual_hash.eq_ignore_ascii_case(expected_transaction_hash)
        {
            return Err(HubError::Node(
                "fullnode acknowledged a different transaction hash".into(),
            ));
        }
        Ok(expected_transaction_hash.to_ascii_lowercase())
    }

    pub async fn submit_transaction_bound(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
        network: &L1ChannelNetworkBinding,
    ) -> HubResult<String> {
        network.validate()?;
        self.submit_transaction_bound_identity(
            signed_transaction_hex,
            expected_transaction_hash,
            network.chain_id,
            &network.network_instance_id,
        )
        .await
    }

    pub async fn submit_hvm_transaction_bound(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
        binding: &HvmChannelBindingV1,
    ) -> HubResult<String> {
        binding.validate()?;
        self.submit_transaction_bound_identity(
            signed_transaction_hex,
            expected_transaction_hash,
            binding.chain_id,
            &binding.network_instance_id,
        )
        .await
    }

    pub async fn submit_hvm_registry_transaction_bound(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
        binding: &HvmRegistryBindingV2,
    ) -> HubResult<String> {
        binding.validate()?;
        self.submit_transaction_bound_identity(
            signed_transaction_hex,
            expected_transaction_hash,
            binding.chain_id,
            &binding.network_instance_id,
        )
        .await
    }

    /// Submit a pre-deployment HVM transaction only to the exact pinned
    /// chain-7 Local Pilot. Deployment, init and funding happen before a
    /// durable channel binding exists. There is no mainnet or legacy fallback.
    #[cfg(feature = "local-pilot-tools")]
    pub async fn submit_hvm_local_pilot_transaction_bound(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
        network: &crate::hvm_pilot::HvmLocalPilotNetwork,
    ) -> HubResult<String> {
        network.validate()?;
        self.submit_transaction_bound_identity(
            signed_transaction_hex,
            expected_transaction_hash,
            network.chain_id,
            &network.network_instance_id,
        )
        .await
    }

    async fn submit_transaction_bound_identity(
        &self,
        signed_transaction_hex: &str,
        expected_transaction_hash: &str,
        chain_id: u32,
        network_instance_id: &str,
    ) -> HubResult<String> {
        if signed_transaction_hex.is_empty()
            || signed_transaction_hex.len() > MAX_SUBMIT_TRANSACTION_HEX_BYTES
            || !signed_transaction_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || expected_transaction_hash.len() != 64
            || !expected_transaction_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HubError::Node(
                "signed transaction or expected hash is malformed".into(),
            ));
        }
        if !is_lower_hex(network_instance_id, 32) {
            return Err(HubError::Node(
                "bound transaction network instance is malformed".into(),
            ));
        }
        let url = format!(
            "{}/submit/transaction/hpay-bound?hexbody=true&chain_id={}&network_instance_id={}",
            self.base_url, chain_id, network_instance_id
        );
        let response = self
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(signed_transaction_hex.to_owned())
            .send()
            .await
            .map_err(|error| {
                HubError::Node(format!("bound transaction submit unavailable: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "bound transaction submit HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "bound transaction submit").await?;
        if value.get("ret").and_then(Value::as_i64) != Some(0) {
            let message = value
                .get("err")
                .or_else(|| value.get("error"))
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("fullnode rejected the network-bound transaction");
            return Err(HubError::Node(message.to_owned()));
        }
        let actual_hash = value.get("hash").and_then(Value::as_str).ok_or_else(|| {
            HubError::Node(
                "bound transaction submit omitted the acknowledged transaction hash".into(),
            )
        })?;
        if !actual_hash.eq_ignore_ascii_case(expected_transaction_hash) {
            return Err(HubError::Node(
                "fullnode acknowledged a different bound transaction hash".into(),
            ));
        }
        Ok(expected_transaction_hash.to_ascii_lowercase())
    }
}

fn validate_hvm_capabilities_for_binding(
    capabilities: &FullnodeCapabilitiesV1,
    binding: &HvmChannelBindingV1,
) -> HubResult<()> {
    binding.validate()?;
    let expected_mainnet = binding.network_mode == "mainnet";
    if capabilities.mainnet != expected_mainnet
        || capabilities.chain_id != binding.chain_id
        || capabilities.network_instance_id.as_deref() != Some(binding.network_instance_id.as_str())
        || capabilities.height < binding.deployment_height
        || HPAY_CHANNEL_EXIT_ACTION_KINDS
            .iter()
            .any(|kind| !capabilities.action_enabled(*kind))
    {
        return Err(HubError::Node(
            "fullnode is not the exact HVM-capable network bound by this channel".into(),
        ));
    }
    let evidence = capabilities
        .channel_unilateral_exit_evidence
        .as_ref()
        .ok_or_else(|| HubError::Node("fullnode omitted HPAY HVM artifact evidence".into()))?;
    evidence.validate_candidate()?;
    Ok(())
}

fn validate_hvm_registry_capabilities_for_binding(
    capabilities: &FullnodeCapabilitiesV1,
    binding: &HvmRegistryBindingV2,
) -> HubResult<()> {
    binding.validate()?;
    let expected_mainnet = binding.network_mode == "mainnet";
    if capabilities.mainnet != expected_mainnet
        || capabilities.chain_id != binding.chain_id
        || capabilities.network_instance_id.as_deref() != Some(binding.network_instance_id.as_str())
        || capabilities.height < binding.deployment_height
        || !capabilities.transaction_submit_bound
        || !capabilities.hpay_channel_registry_query
        || capabilities.enabled_transactions.binary_search(&3).is_err()
        || [1_u16, 14, 40, 41, 44, 0x0411, 0x0414]
            .iter()
            .any(|kind| !capabilities.action_enabled(*kind))
    {
        return Err(HubError::Node(
            "fullnode cannot verify and execute the exact shared HVM registry profile".into(),
        ));
    }
    if expected_mainnet {
        validate_mainnet_hvm_registry_deployment(capabilities, binding)?;
    }
    Ok(())
}

/// The mainnet half of the binding check: does the node this Hub talks to
/// actually see the reviewed shared registry deployed, and is it the same
/// deployment this binding names?
///
/// This was a blanket refusal - "shared HVM registry mainnet deployment
/// evidence is not enabled yet" - and that was the honest answer while there
/// was no V2 evidence document to weigh. [`RegistryUnilateralExitEvidence`] is
/// that document, so the refusal is now a measurement. With nothing deployed it
/// refuses in exactly the same place; what changes is that it names the fact
/// that is missing instead of describing the state of this codebase, and that
/// it stops refusing on the day the registry is really on mainnet and this
/// binding names *that* deployment.
///
/// Deliberately stricter than
/// [`crate::readiness::measure_node_reported_unilateral_exit`], which asks only
/// whether some verified deployment exists. Money moves against one binding, so
/// the verified deployment has to be the one the binding names: same contract
/// address, same deploying transaction, same height, same network instance.
/// Without those four terms a Hub could hand over a binding for a contract
/// nobody verified while riding a node that verified a different one.
///
/// `external_audit_complete` is carried in the evidence and deliberately not a
/// term here, for the reason given on
/// [`RegistryUnilateralExitDeployment::external_audit_complete`]: an audit is a
/// judgement, and every term of this function is a fact the node re-derives
/// from its own block store.
fn validate_mainnet_hvm_registry_deployment(
    capabilities: &FullnodeCapabilitiesV1,
    binding: &HvmRegistryBindingV2,
) -> HubResult<()> {
    let evidence = capabilities
        .channel_registry_unilateral_exit_evidence
        .as_ref()
        .ok_or_else(|| {
            HubError::Node(
                "fullnode publishes no shared HVM registry deployment evidence, so a mainnet \
                 channel would have no proven contract to exit through"
                    .into(),
            )
        })?;
    // Cheap on a document that already passed this on parse, and the only
    // thing standing between a caller that builds capabilities another way and
    // an unchecked evidence document.
    evidence.validate_candidate()?;
    if !evidence.deployment_verified {
        return Err(HubError::Node(
            "shared HVM registry contract is not deployed and verified on mainnet: the fullnode \
             carries the reviewed registry artifact with no confirmed deployment of it"
                .into(),
        ));
    }
    if !capabilities.channel_registry_unilateral_exit {
        return Err(HubError::Node(
            "fullnode does not execute the shared HVM registry unilateral-exit lifecycle, so a \
             mainnet channel could not be left without this Hub"
                .into(),
        ));
    }
    if evidence.deployment.contract_address.as_deref() != Some(binding.contract_address.as_str()) {
        return Err(HubError::Node(
            "mainnet binding names a shared HVM registry contract address the fullnode has not \
             verified"
                .into(),
        ));
    }
    if evidence.deployment.deployment_tx_hash.as_deref()
        != Some(binding.deployment_tx_hash.as_str())
        || evidence.deployment.deployment_height != Some(binding.deployment_height)
    {
        return Err(HubError::Node(
            "mainnet binding names a shared HVM registry deploying transaction the fullnode has \
             not verified"
                .into(),
        ));
    }
    if evidence
        .on_chain_verification
        .constructor_network_instance_id
        .as_deref()
        != Some(binding.network_instance_id.as_str())
    {
        return Err(HubError::Node(
            "verified shared HVM registry is constructed for a different network than this \
             mainnet binding"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn parse_transaction_observation(
    value: &Value,
    expected_hash: &str,
) -> HubResult<Option<TransactionObservation>> {
    parse_transaction_observation_kind(value, expected_hash, 2, None)
}

fn parse_transaction_observation_kind(
    value: &Value,
    expected_hash: &str,
    expected_type: u8,
    required_action: Option<u16>,
) -> HubResult<Option<TransactionObservation>> {
    if value.get("ret").and_then(Value::as_i64) != Some(0) {
        let message = value
            .get("err")
            .or_else(|| value.get("error"))
            .or_else(|| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("fullnode rejected transaction query")
            .trim();
        if message.eq_ignore_ascii_case("transaction not found") {
            return Ok(None);
        }
        return Err(HubError::Node(format!(
            "fullnode transaction query rejected: {message}"
        )));
    }
    let hash = value
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| HubError::Node("transaction query response has no hash".into()))?;
    if !hash.eq_ignore_ascii_case(expected_hash) {
        return Err(HubError::Node(
            "transaction query returned a different transaction hash".into(),
        ));
    }
    let actions = value.get("actions").and_then(Value::as_array);
    if value.get("tx_type").and_then(Value::as_u64) != Some(u64::from(expected_type))
        || actions.is_none()
        || value.get("signatures").and_then(Value::as_array).is_none()
    {
        return Err(HubError::Node(
            "transaction query omitted the requested Type2 action or signature proof".into(),
        ));
    }
    if let Some(required) = required_action
        && !actions.is_some_and(|actions| {
            actions.iter().any(|action| {
                action.get("kind").and_then(Value::as_u64) == Some(u64::from(required))
            })
        })
    {
        return Err(HubError::Node(format!(
            "transaction query omitted required Action {required} proof"
        )));
    }
    let body = value
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| HubError::Node("transaction query response has no body".into()))?;
    if body.is_empty()
        || body.len() > MAX_SUBMIT_TRANSACTION_HEX_BYTES
        || body.len() % 2 != 0
        || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HubError::Node(
            "transaction query returned malformed transaction bytes".into(),
        ));
    }
    let decoded = hex::decode(body)
        .map_err(|_| HubError::Node("transaction query body is not valid hex".into()))?;
    let body_hex = hex::encode(decoded);
    let pending = value
        .get("pending")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (block_height, block_hash, confirmations) = if pending {
        if value.get("block").is_some() || value.get("confirm").is_some() {
            return Err(HubError::Node(
                "pending transaction query contains confirmed block data".into(),
            ));
        }
        (None, None, 0)
    } else {
        let block = value
            .get("block")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                HubError::Node("confirmed transaction query has no block evidence".into())
            })?;
        let height = block
            .get("height")
            .and_then(Value::as_u64)
            .filter(|height| *height > 0)
            .ok_or_else(|| {
                HubError::Node("confirmed transaction query has no block height".into())
            })?;
        let confirmations = value
            .get("confirm")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                HubError::Node("confirmed transaction query has no confirmation count".into())
            })?;
        let block_hash = match block.get("hash") {
            Some(Value::String(hash)) => Some(canonical_hash(hash, "transaction block hash")?),
            Some(_) => {
                return Err(HubError::Node(
                    "confirmed transaction query has malformed block hash".into(),
                ));
            }
            None => None,
        };
        (Some(height), block_hash, confirmations)
    };
    Ok(Some(TransactionObservation {
        hash: hash.to_ascii_lowercase(),
        body_hex,
        pending,
        block_height,
        block_hash,
        confirmations,
    }))
}

fn parse_block_transaction_anchor(
    value: &Value,
    expected_height: u64,
    expected_transaction_hash: &str,
) -> HubResult<String> {
    if value.get("ret").and_then(Value::as_i64) != Some(0) {
        return Err(HubError::Node(
            "canonical block anchor query was rejected".into(),
        ));
    }
    if value.get("height").and_then(Value::as_u64) != Some(expected_height) {
        return Err(HubError::Node(
            "canonical block anchor returned a different height".into(),
        ));
    }
    let hash = value
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| HubError::Node("canonical block anchor omitted its hash".into()))?;
    let hash = canonical_hash(hash, "canonical block hash")?;
    let expected_transaction_hash =
        canonical_hash(expected_transaction_hash, "expected transaction hash")?;
    let transaction_hashes = value
        .get("tx_hash_list")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            HubError::Node("canonical block anchor omitted its transaction list".into())
        })?;
    let mut exact_inclusions = 0usize;
    for candidate in transaction_hashes {
        let candidate = candidate.as_str().ok_or_else(|| {
            HubError::Node("canonical block anchor contains a malformed transaction hash".into())
        })?;
        if canonical_hash(candidate, "canonical block transaction hash")?
            == expected_transaction_hash
        {
            exact_inclusions = exact_inclusions.saturating_add(1);
        }
    }
    if exact_inclusions != 1 {
        return Err(HubError::Node(
            "canonical block anchor does not contain the exact transaction once".into(),
        ));
    }
    Ok(hash)
}

fn canonical_hash(value: &str, label: &str) -> HubResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HubError::Node(format!("{label} is malformed")));
    }
    Ok(value.to_ascii_lowercase())
}
pub(crate) fn parse_fin_balance_zhu(wire: &str) -> HubResult<u128> {
    if wire.is_empty() || wire.trim() != wire || !wire.contains(':') {
        return Err(HubError::Node(
            "fullnode returned a malformed financial HAC balance".into(),
        ));
    }
    let amount = Amount::from(wire).map_err(|error| {
        HubError::Node(format!(
            "fullnode returned an invalid financial HAC balance: {error}"
        ))
    })?;
    if amount.is_negative() || amount.to_fin_string() != wire {
        return Err(HubError::Node(
            "fullnode returned a non-canonical financial HAC balance".into(),
        ));
    }
    // Account balances can contain protocol-valid sub-Zhu fee-purity dust
    // (notably unit 238). Hub operations spend whole Zhu, so the canonical
    // Amount conversion deliberately floors that unspendable remainder. This
    // is conservative for every balance-sufficiency check and avoids floats.
    amount
        .to_zhu_u128()
        .map_err(|error| HubError::Node(format!("fullnode HAC balance is too large: {error}")))
}
async fn read_bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    context: &str,
) -> HubResult<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NODE_RESPONSE_BYTES as u64)
    {
        return Err(HubError::Node(format!(
            "fullnode {context} response exceeds {MAX_NODE_RESPONSE_BYTES} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| HubError::Node(format!("fullnode {context} body failed: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_NODE_RESPONSE_BYTES {
            return Err(HubError::Node(format!(
                "fullnode {context} response exceeds {MAX_NODE_RESPONSE_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| HubError::Node(format!("invalid fullnode {context} response: {error}")))
}
fn parse_action_list(value: Option<&Value>, field: &str) -> HubResult<Vec<u16>> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| HubError::Node(format!("actions.{field} must be an array")))?;
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .as_u64()
            .ok_or_else(|| HubError::Node(format!("actions.{field} must contain integers")))?;
        let kind = u16::try_from(raw)
            .map_err(|_| HubError::Node(format!("actions.{field} exceeds u16")))?;
        if !seen.insert(kind) {
            return Err(HubError::Node(format!(
                "actions.{field} contains duplicates"
            )));
        }
        output.push(kind);
    }
    output.sort_unstable();
    Ok(output)
}

fn parse_transaction_list(value: Option<&Value>, field: &str) -> HubResult<Vec<u8>> {
    let actions = parse_action_list(value, field)?;
    actions
        .into_iter()
        .map(|kind| {
            u8::try_from(kind).map_err(|_| {
                HubError::Node(format!(
                    "fullnode transaction {field} contains a value above u8"
                ))
            })
        })
        .collect()
}

fn required_u64(value: &Value, field: &str) -> HubResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| HubError::Node(format!("{field} must be an integer")))
}

fn required_object_u64(value: &serde_json::Map<String, Value>, field: &str) -> HubResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| HubError::Node(format!("{field} must be an integer")))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(actions: Vec<u16>) -> Value {
        let now = now_unix();
        serde_json::json!({
            "ret": 0,
            "api_version": 1,
            "api": {
                "transaction_submit_bound": true
            },
            "chain": {
                "id": 0,
                "height": HACASH_MAINNET_MIN_SAFE_HEIGHT,
                "next_height": HACASH_MAINNET_MIN_SAFE_HEIGHT + 1,
                "mainnet": true
            },
            "network": {
                "kind": "mainnet",
                "node_profile_id": "hacash-mainnet",
                "block_1_hash": HACASH_MAINNET_BLOCK_ONE_HASH,
                "instance_id": "11".repeat(32),
                "transaction_format_version": 2
            },
            "sync": {
                "tip_timestamp_unix": now,
                "max_tip_age_seconds": FULLNODE_MAX_TIP_AGE_SECONDS,
                "fresh": true
            },
            "actions": {
                "registered": actions,
                "enabled": actions
            },
            "transactions": {
                "registered": [2],
                "enabled": [2]
            },
            "features": {
                "channel_unilateral_exit": true,
                "channel_unilateral_exit_evidence": {
                    "schema": HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
                    "manifest_valid": true,
                    "contract_name": HPAY_CHANNEL_EXIT_CONTRACT_NAME,
                    "protocol_domain": HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN,
                    "settlement_profile": HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
                    "source_sha256": "11".repeat(32),
                    "bytecode_sha3": HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
                    "required_action_kinds": HPAY_CHANNEL_EXIT_ACTION_KINDS,
                    "funding_model": {
                        "left_deposit": "positive",
                        "right_hub_deposit": "exactly_zero"
                    },
                    "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
                    "must_renew_every_storage_key": true,
                    "deployment": {
                        "enabled": true,
                        "contract_address":
                            ContractAddress::from_unchecked(Address::create_contract([7_u8; 20]))
                                .to_readable(),
                        "deployment_tx_hash": "22".repeat(32),
                        "deployment_height": HACASH_MAINNET_MIN_SAFE_HEIGHT,
                        "independently_verified": true
                    },
                    "on_chain_verification": {
                        "observed_height": HACASH_MAINNET_MIN_SAFE_HEIGHT,
                        "confirmed_tx_height": HACASH_MAINNET_MIN_SAFE_HEIGHT,
                        "deployment_tx_confirmed": true,
                        "contract_code_sha3": HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
                        "contract_code_matches": true
                    },
                    "deployment_verified": true
                }
            }
        })
    }

    fn hvm_binding() -> HvmChannelBindingV1 {
        HvmChannelBindingV1 {
            schema: crate::hvm_channel::HVM_CHANNEL_BINDING_SCHEMA.to_owned(),
            settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
            network_mode: "mainnet".to_owned(),
            chain_id: HACASH_MAINNET_CHAIN_ID,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([7; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: HACASH_MAINNET_MIN_SAFE_HEIGHT,
            bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
            channel_id: "33".repeat(16),
            reuse_version: 7,
            left_address: Address::create_privakey([4; 20]).to_readable(),
            right_hub_address: Address::create_privakey([5; 20]).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        }
    }

    fn storage_entry(value: Value) -> Value {
        serde_json::json!({
            "value": value,
            "live_blocks": 10_000,
            "recover_blocks": 20_000,
            "active": true,
            "recoverable": false
        })
    }

    fn hvm_snapshot(binding: &HvmChannelBindingV1) -> Value {
        let observed_height = binding
            .deployment_height
            .max(if binding.network_mode == "mainnet" {
                HACASH_MAINNET_MIN_SAFE_HEIGHT
            } else {
                1
            });
        serde_json::json!({
            "ret": 0,
            "schema": HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA,
            "chain_id": binding.chain_id,
            "observed_height": observed_height,
            "evaluation_height": observed_height + 1,
            "contract_address": binding.contract_address,
            "deployment_tx_hash": binding.deployment_tx_hash,
            "deployment_height": binding.deployment_height,
            "deployment_action_verified": true,
            "bytecode_sha3": binding.bytecode_sha3,
            "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
            "all_keys_active": true,
            "minimum_live_blocks": 10_000,
            "minimum_recover_blocks": 20_000,
            "storage": {
                "status": storage_entry(Value::from(2)),
                "network": storage_entry(Value::from(binding.network_instance_id.clone())),
                "channel_id": storage_entry(Value::from(binding.channel_id.clone())),
                "reuse": storage_entry(Value::from(binding.reuse_version)),
                "left": storage_entry(Value::from(binding.left_address.clone())),
                "right": storage_entry(Value::from(binding.right_hub_address.clone())),
                "left_deposit": storage_entry(Value::from(binding.left_deposit_zhu)),
                "right_deposit": storage_entry(Value::from(binding.right_hub_deposit_zhu)),
                "left_paid": storage_entry(Value::from(binding.left_deposit_zhu)),
                "right_paid": storage_entry(Value::from(binding.right_hub_deposit_zhu)),
                "total": storage_entry(Value::from(binding.left_deposit_zhu)),
                "serial": storage_entry(Value::from(0)),
                "left_balance": storage_entry(Value::from(binding.left_deposit_zhu)),
                "right_balance": storage_entry(Value::from(binding.right_hub_deposit_zhu)),
                "challenge_blocks": storage_entry(Value::from(binding.challenge_blocks)),
                "deadline": storage_entry(Value::from(0)),
                "left_claimed": storage_entry(Value::from(false)),
                "right_claimed": storage_entry(Value::from(false))
            }
        })
    }

    fn signed_hvm_recovery_bundle() -> HvmChannelRecoveryBundleV1 {
        signed_hvm_recovery_bundle_for(hvm_binding())
    }

    fn signed_hvm_recovery_bundle_for(
        mut binding: HvmChannelBindingV1,
    ) -> HvmChannelRecoveryBundleV1 {
        use field::{Serialize as FieldSerialize, Sign};
        use sys::Account;

        let left = Account::create_by("hpay-node-verifier-left").unwrap();
        let right = Account::create_by("hpay-node-verifier-right").unwrap();
        binding.left_address = Address::from(*left.address()).to_readable();
        binding.right_hub_address = Address::from(*right.address()).to_readable();
        let mut initial_recovery_bill = crate::hvm_channel::HvmChannelBillV1 {
            schema: crate::hvm_channel::HVM_CHANNEL_BILL_SCHEMA.to_owned(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: binding.left_deposit_zhu,
            right_balance_zhu: binding.right_hub_deposit_zhu,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let hash = initial_recovery_bill.signing_hash(&binding).unwrap();
        initial_recovery_bill.left_signature_hex =
            hex::encode(Sign::create_by(&left, &hash).serialize());
        initial_recovery_bill.right_signature_hex =
            hex::encode(Sign::create_by(&right, &hash).serialize());
        HvmChannelRecoveryBundleV1 {
            schema: crate::hvm_channel::HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA.to_owned(),
            binding,
            initial_recovery_bill,
        }
    }

    fn testnet_capabilities(chain_id: u32, network_instance_id: &str, height: u64) -> Value {
        let mut value = capabilities(vec![40, 41, 44]);
        value["chain"]["id"] = Value::from(chain_id);
        value["chain"]["height"] = Value::from(height);
        value["chain"]["next_height"] = Value::from(height + 1);
        value["chain"]["mainnet"] = Value::from(false);
        value["network"]["kind"] = Value::from("hpay-testnet");
        value["network"]["node_profile_id"] = Value::from("hpay-test-profile");
        value["network"]["block_1_hash"] = Value::from("77".repeat(32));
        value["network"]["instance_id"] = Value::from(network_instance_id);
        value["features"]["channel_unilateral_exit"] = Value::from(false);
        let evidence = &mut value["features"]["channel_unilateral_exit_evidence"];
        evidence["deployment"]["enabled"] = Value::from(false);
        evidence["deployment"]["contract_address"] = Value::Null;
        evidence["deployment"]["deployment_tx_hash"] = Value::Null;
        evidence["deployment"]["deployment_height"] = Value::Null;
        evidence["deployment"]["independently_verified"] = Value::from(false);
        evidence["on_chain_verification"]["observed_height"] = Value::Null;
        evidence["on_chain_verification"]["confirmed_tx_height"] = Value::Null;
        evidence["on_chain_verification"]["deployment_tx_confirmed"] = Value::from(false);
        evidence["on_chain_verification"]["contract_code_sha3"] = Value::Null;
        evidence["on_chain_verification"]["contract_code_matches"] = Value::from(false);
        evidence["deployment_verified"] = Value::from(false);
        value
    }

    #[test]
    fn hvm_live_snapshot_binds_exact_open_state_and_every_lease() {
        let binding = hvm_binding();
        let snapshot: HvmChannelLiveSnapshot =
            serde_json::from_value(hvm_snapshot(&binding)).unwrap();
        snapshot
            .validate_open_binding(&binding, 5_000, 5_000)
            .unwrap();

        let mut cases = Vec::new();
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["status"]["value"] = Value::from(3);
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["network"]["value"] = Value::from("aa".repeat(32));
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["left_paid"]["value"] = Value::from(999_999);
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["serial"]["value"] = Value::from(1);
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["right"]["active"] = Value::from(false);
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["minimum_live_blocks"] = Value::from(9_999);
        cases.push(changed);
        let mut changed = hvm_snapshot(&binding);
        changed["storage"]["left"]["recover_blocks"] = Value::from(4_999);
        cases.push(changed);
        for value in cases {
            let snapshot: HvmChannelLiveSnapshot = serde_json::from_value(value).unwrap();
            assert!(
                snapshot
                    .validate_open_binding(&binding, 5_000, 5_000)
                    .is_err()
            );
        }

        let mut unknown = hvm_snapshot(&binding);
        unknown["unexpected"] = Value::from(true);
        assert!(serde_json::from_value::<HvmChannelLiveSnapshot>(unknown).is_err());
    }

    #[test]
    fn hvm_initial_snapshot_accepts_only_canonical_zero_recovery_leases() {
        let binding = hvm_binding();
        let mut initial = hvm_snapshot(&binding);
        initial["minimum_recover_blocks"] = Value::from(0);
        for entry in initial["storage"].as_object_mut().unwrap().values_mut() {
            entry["active"] = Value::from(true);
            entry["recoverable"] = Value::from(false);
            entry["recover_blocks"] = Value::from(0);
        }
        let snapshot: HvmChannelLiveSnapshot = serde_json::from_value(initial.clone()).unwrap();
        snapshot
            .validate_initial_open_binding(&binding, 5_000)
            .unwrap();
        assert!(snapshot.validate_open_binding(&binding, 5_000, 1).is_err());
        assert!(snapshot.validate_initial_open_binding(&binding, 0).is_err());

        let mut mixed = initial.clone();
        mixed["storage"]["status"]["recover_blocks"] = Value::from(1);
        let mixed: HvmChannelLiveSnapshot = serde_json::from_value(mixed).unwrap();
        assert!(
            mixed
                .validate_initial_open_binding(&binding, 5_000)
                .is_err()
        );

        let mut recoverable = initial;
        recoverable["storage"]["status"]["active"] = Value::from(false);
        recoverable["storage"]["status"]["recoverable"] = Value::from(true);
        let recoverable: HvmChannelLiveSnapshot = serde_json::from_value(recoverable).unwrap();
        assert!(
            recoverable
                .validate_initial_open_binding(&binding, 5_000)
                .is_err()
        );
    }

    #[tokio::test]
    async fn recovery_bundle_verifier_uses_one_exact_live_node_and_contract_query() {
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap;

        let bundle = signed_hvm_recovery_bundle();
        let expected = bundle.binding.clone();
        let snapshot = hvm_snapshot(&bundle.binding);
        let app = Router::new()
            .route(
                "/query/capabilities",
                get(|| async { Json(capabilities(vec![40, 41, 44])) }),
            )
            .route(
                "/query/hpay/channel-exit",
                get(move |Query(query): Query<HashMap<String, String>>| {
                    let expected = expected.clone();
                    let snapshot = snapshot.clone();
                    async move {
                        let exact = query.get("contract") == Some(&expected.contract_address)
                            && query.get("deployment_tx_hash")
                                == Some(&expected.deployment_tx_hash)
                            && query.get("deployment_height")
                                == Some(&expected.deployment_height.to_string());
                        if exact {
                            (StatusCode::OK, Json(snapshot))
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({"ret": 1, "err": "wrong binding"})),
                            )
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = NodeClient::new(format!("http://{address}")).unwrap();
        let verified = client
            .verify_hvm_recovery_bundle(&bundle, 5_000, 5_000)
            .await
            .unwrap();
        assert_eq!(verified.contract_address, bundle.binding.contract_address);
        server.abort();
    }

    #[tokio::test]
    async fn testnet_recovery_verifier_requires_exact_chain_instance_and_deployment() {
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap;

        let mut binding = hvm_binding();
        binding.network_mode = "testnet".to_owned();
        binding.chain_id = 7;
        binding.network_instance_id = "77".repeat(32);
        binding.deployment_height = 2;
        let bundle = signed_hvm_recovery_bundle_for(binding);
        let expected = bundle.binding.clone();
        let snapshot = hvm_snapshot(&bundle.binding);
        let capabilities = testnet_capabilities(
            bundle.binding.chain_id,
            &bundle.binding.network_instance_id,
            bundle.binding.deployment_height,
        );
        let app = Router::new()
            .route(
                "/query/capabilities",
                get(move || {
                    let capabilities = capabilities.clone();
                    async move { Json(capabilities) }
                }),
            )
            .route(
                "/query/hpay/channel-exit",
                get(move |Query(query): Query<HashMap<String, String>>| {
                    let expected = expected.clone();
                    let snapshot = snapshot.clone();
                    async move {
                        let exact = query.get("contract") == Some(&expected.contract_address)
                            && query.get("deployment_tx_hash")
                                == Some(&expected.deployment_tx_hash)
                            && query.get("deployment_height")
                                == Some(&expected.deployment_height.to_string());
                        if exact {
                            (StatusCode::OK, Json(snapshot))
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({"ret": 1, "err": "wrong binding"})),
                            )
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = NodeClient::new(format!("http://{address}")).unwrap();
        let verified = client
            .verify_hvm_recovery_bundle(&bundle, 5_000, 5_000)
            .await
            .unwrap();
        assert_eq!(verified.chain_id, 7);
        assert_eq!(verified.deployment_height, 2);
        server.abort();

        let mut wrong_instance = testnet_capabilities(7, &"88".repeat(32), 2);
        let parsed = FullnodeCapabilitiesV1::parse(&wrong_instance).unwrap();
        assert!(validate_hvm_capabilities_for_binding(&parsed, &bundle.binding).is_err());
        wrong_instance["network"]["instance_id"] =
            Value::from(bundle.binding.network_instance_id.clone());
        wrong_instance["chain"]["id"] = Value::from(8);
        let parsed = FullnodeCapabilitiesV1::parse(&wrong_instance).unwrap();
        assert!(validate_hvm_capabilities_for_binding(&parsed, &bundle.binding).is_err());
    }

    #[test]
    fn mainnet_node_url_never_leaks_credentials_over_remote_http() {
        for allowed in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "https://node.example.com",
        ] {
            validate_mainnet_node_url(allowed).unwrap();
        }
        for rejected in [
            "http://192.168.1.10:8080",
            "http://node.example.com:8080",
            "ftp://127.0.0.1:8080",
            "https://user:secret@node.example.com",
            "https://node.example.com/api",
            "https://node.example.com?token=secret",
        ] {
            assert!(validate_mainnet_node_url(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn capabilities_bind_mainnet_identity_sync_and_actions() {
        let parsed = FullnodeCapabilitiesV1::parse(&capabilities(vec![1, 2, 3])).unwrap();
        assert!(parsed.mainnet);
        assert!(parsed.transaction_submit_bound);
        assert!(parsed.action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE));
        assert!(parsed.channel_unilateral_exit);
        assert!(
            parsed
                .channel_unilateral_exit_evidence
                .as_ref()
                .is_some_and(ChannelUnilateralExitEvidence::is_verified_mainnet_deployment)
        );

        let mut missing_exit = capabilities(vec![1, 2, 3]);
        missing_exit.as_object_mut().unwrap().remove("features");
        assert!(
            !FullnodeCapabilitiesV1::parse(&missing_exit)
                .unwrap()
                .channel_unilateral_exit
        );

        let mut missing_evidence = capabilities(vec![1, 2, 3]);
        missing_evidence["features"]
            .as_object_mut()
            .unwrap()
            .remove("channel_unilateral_exit_evidence");
        assert!(FullnodeCapabilitiesV1::parse(&missing_evidence).is_err());

        let mut wrong_bytecode = capabilities(vec![1, 2, 3]);
        wrong_bytecode["features"]["channel_unilateral_exit_evidence"]["bytecode_sha3"] =
            serde_json::json!("33".repeat(32));
        assert!(FullnodeCapabilitiesV1::parse(&wrong_bytecode).is_err());

        let mut wrong_live_code = capabilities(vec![1, 2, 3]);
        wrong_live_code["features"]["channel_unilateral_exit_evidence"]["on_chain_verification"]
            ["contract_code_sha3"] = serde_json::json!("33".repeat(32));
        assert!(FullnodeCapabilitiesV1::parse(&wrong_live_code).is_err());

        let mut nonzero_hub_funding = capabilities(vec![1, 2, 3]);
        nonzero_hub_funding["features"]["channel_unilateral_exit_evidence"]["funding_model"]["right_hub_deposit"] =
            serde_json::json!("positive");
        assert!(FullnodeCapabilitiesV1::parse(&nonzero_hub_funding).is_err());

        let mut wrong_settlement_profile = capabilities(vec![1, 2, 3]);
        wrong_settlement_profile["features"]["channel_unilateral_exit_evidence"]["settlement_profile"] =
            serde_json::json!("native-channelpay");
        assert!(FullnodeCapabilitiesV1::parse(&wrong_settlement_profile).is_err());

        let mut non_contract_address = capabilities(vec![1, 2, 3]);
        non_contract_address["features"]["channel_unilateral_exit_evidence"]["deployment"]["contract_address"] =
            serde_json::json!("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW");
        assert!(FullnodeCapabilitiesV1::parse(&non_contract_address).is_err());

        let mut unknown_evidence_field = capabilities(vec![1, 2, 3]);
        unknown_evidence_field["features"]["channel_unilateral_exit_evidence"]["shadow_verified"] =
            serde_json::json!(true);
        assert!(FullnodeCapabilitiesV1::parse(&unknown_evidence_field).is_err());

        let mut wrong_deployment_height = capabilities(vec![1, 2, 3]);
        wrong_deployment_height["features"]["channel_unilateral_exit_evidence"]["on_chain_verification"]
            ["confirmed_tx_height"] = serde_json::json!(HACASH_MAINNET_MIN_SAFE_HEIGHT + 1);
        assert!(FullnodeCapabilitiesV1::parse(&wrong_deployment_height).is_err());

        let mut unconfirmed_deployment = capabilities(vec![1, 2, 3]);
        unconfirmed_deployment["features"]["channel_unilateral_exit_evidence"]["on_chain_verification"]
            ["deployment_tx_confirmed"] = serde_json::json!(false);
        assert!(FullnodeCapabilitiesV1::parse(&unconfirmed_deployment).is_err());

        let mut wrong_genesis = capabilities(vec![3]);
        wrong_genesis["network"]["block_1_hash"] = serde_json::json!("00".repeat(32));
        assert!(FullnodeCapabilitiesV1::parse(&wrong_genesis).is_err());

        let duplicate = capabilities(vec![3, 3]);
        assert!(FullnodeCapabilitiesV1::parse(&duplicate).is_err());

        let mut exact_channel_node =
            FullnodeCapabilitiesV1::parse(&capabilities(vec![1, 2, 3, 0x0411])).unwrap();
        exact_channel_node.network_instance_id =
            Some(crate::l1_channel::canonical_network_instance_id(
                &exact_channel_node.network_kind,
                exact_channel_node.chain_id,
                exact_channel_node.mainnet,
                &exact_channel_node.block_1_hash,
                &exact_channel_node.node_profile_id,
                exact_channel_node.transaction_format_version,
            ));
        assert!(exact_channel_node.l1_channel_network_binding().is_ok());
        exact_channel_node.transaction_submit_bound = false;
        assert!(exact_channel_node.l1_channel_network_binding().is_err());

        let mut unregistered = capabilities(vec![3]);
        unregistered["actions"]["enabled"] = serde_json::json!([3, 23]);
        assert!(FullnodeCapabilitiesV1::parse(&unregistered).is_err());
    }

    /// A mainnet shared-registry binding, for the mainnet-gate tests below.
    fn mainnet_registry_binding() -> HvmRegistryBindingV2 {
        HvmRegistryBindingV2 {
            schema: crate::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.to_owned(),
            settlement_profile: crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE.to_owned(),
            network_mode: "mainnet".to_owned(),
            chain_id: HACASH_MAINNET_CHAIN_ID,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([9_u8; 20]))
                .to_readable(),
            deployment_tx_hash: "44".repeat(32),
            deployment_height: HACASH_MAINNET_MIN_SAFE_HEIGHT,
            bytecode_sha3: crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.to_owned(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: Address::create_privakey([4; 20]).to_readable(),
            right_hub_address: Address::create_privakey([5; 20]).to_readable(),
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        }
    }

    /// A node that can do everything the shared registry profile needs and has
    /// nothing at all to say about a registry deployment - which is the state
    /// of every real mainnet node today.
    fn registry_capabilities(binding: &HvmRegistryBindingV2) -> FullnodeCapabilitiesV1 {
        let actions = vec![1_u16, 14, 40, 41, 44, 0x0411, 0x0414];
        let now = now_unix();
        FullnodeCapabilitiesV1 {
            observed_unix: now,
            api_version: FULLNODE_CAPABILITIES_API_V1,
            chain_id: binding.chain_id,
            height: binding.deployment_height,
            next_height: binding.deployment_height + 1,
            mainnet: binding.network_mode == "mainnet",
            network_kind: binding.network_mode.clone(),
            node_profile_id: "hacash-mainnet".to_owned(),
            block_1_hash: HACASH_MAINNET_BLOCK_ONE_HASH.to_owned(),
            network_instance_id: Some(binding.network_instance_id.clone()),
            transaction_format_version: 2,
            tip_timestamp_unix: now,
            tip_age_seconds: 0,
            registered_actions: actions.clone(),
            enabled_actions: actions,
            enabled_transactions: vec![2, 3],
            transaction_submit_bound: true,
            hpay_channel_registry_query: true,
            channel_unilateral_exit: false,
            channel_unilateral_exit_evidence: None,
            channel_registry_unilateral_exit: false,
            channel_registry_unilateral_exit_evidence: None,
        }
    }

    /// Evidence of a fully verified mainnet deployment of the reviewed shared
    /// registry, describing exactly the contract `binding` names.
    ///
    /// It describes a deployment that does not exist. That is the point: it
    /// lets these tests prove each term of the gate is load bearing without
    /// anything being deployed, the same way the readiness fixture does.
    fn verified_registry_evidence(
        binding: &HvmRegistryBindingV2,
    ) -> RegistryUnilateralExitEvidence {
        RegistryUnilateralExitEvidence {
            schema: crate::hvm_registry::HVM_REGISTRY_EXIT_EVIDENCE_SCHEMA.to_owned(),
            manifest_valid: true,
            contract_name: crate::hvm_registry::HPAY_REGISTRY_CONTRACT_NAME.to_owned(),
            protocol_domain: crate::hvm_registry::HPAY_REGISTRY_PROTOCOL_DOMAIN.to_owned(),
            settlement_profile: crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE.to_owned(),
            source_sha256: "33".repeat(32),
            bytecode_sha3: crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.to_owned(),
            required_action_kinds: crate::hvm_registry::HPAY_REGISTRY_REQUIRED_ACTION_KINDS
                .to_vec(),
            channel_model: RegistryUnilateralExitChannelModel {
                left_deposit: "positive".to_owned(),
                right_hub_deposit: "exactly_zero".to_owned(),
                maximum_active_channels_per_left_address: 1,
                first_reuse: 0,
            },
            registry_key_count: crate::hvm_registry::HVM_REGISTRY_STORAGE_KEY_COUNT,
            channel_key_count: crate::hvm_registry::HVM_REGISTRY_CHANNEL_KEY_COUNT,
            must_renew_every_registry_key: true,
            must_renew_every_channel_key: true,
            maximum_renewal_step_periods: crate::hvm_registry::HPAY_REGISTRY_MAX_RENT_STEP,
            deployment: RegistryUnilateralExitDeployment {
                enabled: true,
                contract_address: Some(binding.contract_address.clone()),
                deployment_tx_hash: Some(binding.deployment_tx_hash.clone()),
                deployment_height: Some(binding.deployment_height),
                independently_verified: true,
                external_audit_complete: false,
            },
            on_chain_verification: RegistryUnilateralExitOnChainVerification {
                observed_height: Some(binding.deployment_height),
                confirmed_tx_height: Some(binding.deployment_height),
                deployment_tx_confirmed: true,
                contract_code_sha3: Some(
                    crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.to_owned(),
                ),
                contract_code_matches: true,
                deployment_action_verified: true,
                hub_address: Some(Address::create_privakey([5; 20]).to_readable()),
                constructor_network_instance_id: Some(binding.network_instance_id.clone()),
                node_network_instance_id: Some(binding.network_instance_id.clone()),
                network_binding_matches: true,
            },
            deployment_verified: true,
        }
    }

    /// The same document with every trace of deployment authority removed -
    /// what an honest node that has verified the artifact but seen no
    /// deployment publishes.
    fn unverified_registry_evidence(
        binding: &HvmRegistryBindingV2,
    ) -> RegistryUnilateralExitEvidence {
        let mut evidence = verified_registry_evidence(binding);
        evidence.deployment = RegistryUnilateralExitDeployment {
            enabled: false,
            contract_address: None,
            deployment_tx_hash: None,
            deployment_height: None,
            independently_verified: false,
            external_audit_complete: false,
        };
        evidence.on_chain_verification = RegistryUnilateralExitOnChainVerification {
            observed_height: None,
            confirmed_tx_height: None,
            deployment_tx_confirmed: false,
            contract_code_sha3: None,
            contract_code_matches: false,
            deployment_action_verified: false,
            hub_address: None,
            constructor_network_instance_id: None,
            node_network_instance_id: None,
            network_binding_matches: false,
        };
        evidence.deployment_verified = false;
        evidence
    }

    /// The mainnet gate must be a measurement, not a slogan.
    ///
    /// It used to refuse every mainnet binding with "shared HVM registry
    /// mainnet deployment evidence is not enabled yet", which said something
    /// about this codebase rather than about the chain. With nothing deployed
    /// it must still refuse - and it must name the fact that is missing.
    #[test]
    fn mainnet_registry_binding_refuses_and_names_what_is_missing() {
        let binding = mainnet_registry_binding();

        // 1. A node with nothing to say about a registry deployment.
        let capabilities = registry_capabilities(&binding);
        let message = validate_hvm_registry_capabilities_for_binding(&capabilities, &binding)
            .expect_err("nothing is deployed on mainnet")
            .to_string();
        assert!(
            !message.contains("not enabled yet"),
            "refusal still describes this codebase rather than the chain: {message}"
        );
        assert!(
            message.contains("no shared HVM registry deployment evidence"),
            "refusal does not name the missing evidence: {message}"
        );

        // 2. A node that has verified the artifact and seen no deployment.
        let mut unverified = registry_capabilities(&binding);
        unverified.channel_registry_unilateral_exit_evidence =
            Some(unverified_registry_evidence(&binding));
        let message = validate_hvm_registry_capabilities_for_binding(&unverified, &binding)
            .expect_err("the registry is not deployed on mainnet")
            .to_string();
        assert!(
            message.contains("is not deployed and verified on mainnet"),
            "refusal does not name the missing deployment: {message}"
        );

        // 3. A verified deployment the node cannot actually drive.
        let mut no_lifecycle = registry_capabilities(&binding);
        no_lifecycle.channel_registry_unilateral_exit_evidence =
            Some(verified_registry_evidence(&binding));
        let message = validate_hvm_registry_capabilities_for_binding(&no_lifecycle, &binding)
            .expect_err("the node does not run the exit lifecycle")
            .to_string();
        assert!(
            message.contains("does not execute the shared HVM registry unilateral-exit lifecycle"),
            "refusal does not name the missing lifecycle: {message}"
        );
    }

    /// A verified deployment somewhere is not a verified deployment *here*.
    ///
    /// Money moves against one binding, so the deployment the node verified has
    /// to be the one the binding names.
    #[test]
    fn mainnet_registry_binding_refuses_evidence_for_another_deployment() {
        let binding = mainnet_registry_binding();
        let ready = |mutate: fn(&mut RegistryUnilateralExitEvidence)| {
            let mut capabilities = registry_capabilities(&binding);
            let mut evidence = verified_registry_evidence(&binding);
            mutate(&mut evidence);
            capabilities.channel_registry_unilateral_exit = true;
            capabilities.channel_registry_unilateral_exit_evidence = Some(evidence);
            capabilities
        };

        let other_contract = ready(|evidence| {
            evidence.deployment.contract_address = Some(
                ContractAddress::from_unchecked(Address::create_contract([8_u8; 20])).to_readable(),
            );
        });
        let message = validate_hvm_registry_capabilities_for_binding(&other_contract, &binding)
            .expect_err("the verified contract is not the one this binding names")
            .to_string();
        assert!(message.contains("contract address"), "{message}");

        let other_transaction = ready(|evidence| {
            evidence.deployment.deployment_tx_hash = Some("55".repeat(32));
        });
        assert!(
            validate_hvm_registry_capabilities_for_binding(&other_transaction, &binding).is_err(),
            "a different deploying transaction was accepted"
        );

        let other_network = ready(|evidence| {
            evidence
                .on_chain_verification
                .constructor_network_instance_id = Some("22".repeat(32));
            evidence.on_chain_verification.node_network_instance_id = Some("22".repeat(32));
        });
        assert!(
            validate_hvm_registry_capabilities_for_binding(&other_network, &binding).is_err(),
            "a registry constructed for another network was accepted"
        );
    }

    /// And the other direction: a node that really does see the reviewed
    /// registry deployed at exactly the address, transaction, height and
    /// network this binding names, and that runs the exit lifecycle, passes.
    /// Without this the check would just be the old blanket refusal wearing a
    /// better message.
    #[test]
    fn mainnet_registry_binding_accepts_the_deployment_it_names() {
        let binding = mainnet_registry_binding();
        let mut capabilities = registry_capabilities(&binding);
        capabilities.channel_registry_unilateral_exit = true;
        capabilities.channel_registry_unilateral_exit_evidence =
            Some(verified_registry_evidence(&binding));
        validate_hvm_registry_capabilities_for_binding(&capabilities, &binding)
            .expect("a verified mainnet deployment this binding names must be usable");
    }

    #[test]
    fn transaction_observation_requires_exact_body_and_confirmation_shape() {
        let hash = "ab".repeat(32);
        let confirmed = serde_json::json!({
            "ret": 0,
            "hash": hash,
            "tx_type": 2,
            "body": "0200",
            "actions": [{"kind": 3}, {"kind": 14}],
            "signatures": [{"complete": true}, {"complete": true}],
            "block": {"height": 900001},
            "confirm": 6
        });
        let parsed = parse_transaction_observation(&confirmed, &"ab".repeat(32))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.body_hex, "0200");
        assert_eq!(parsed.block_height, Some(900001));
        assert_eq!(parsed.block_hash, None);
        assert_eq!(parsed.confirmations, 6);
        assert!(!parsed.pending);

        let mut pending = confirmed.clone();
        pending["pending"] = serde_json::json!(true);
        pending.as_object_mut().unwrap().remove("block");
        pending.as_object_mut().unwrap().remove("confirm");
        let parsed = parse_transaction_observation(&pending, &"ab".repeat(32))
            .unwrap()
            .unwrap();
        assert!(parsed.pending);
        assert_eq!(parsed.block_height, None);

        let mut malformed = confirmed;
        malformed["body"] = serde_json::json!("020");
        assert!(parse_transaction_observation(&malformed, &"ab".repeat(32)).is_err());
    }

    #[cfg(feature = "local-pilot-tools")]
    #[test]
    fn canonical_block_anchor_binds_height_hash_and_exact_transaction_once() {
        let transaction_hash = "ab".repeat(32);
        let block_hash = "cd".repeat(32);
        let value = serde_json::json!({
            "ret": 0,
            "height": 900001,
            "hash": block_hash,
            "tx_hash_list": [transaction_hash, "ef".repeat(32)]
        });
        assert_eq!(
            parse_block_transaction_anchor(&value, 900001, &"ab".repeat(32)).unwrap(),
            "cd".repeat(32)
        );

        let mut wrong_height = value.clone();
        wrong_height["height"] = serde_json::json!(900002);
        assert!(parse_block_transaction_anchor(&wrong_height, 900001, &"ab".repeat(32)).is_err());

        let mut missing = value.clone();
        missing["tx_hash_list"] = serde_json::json!(["ef".repeat(32)]);
        assert!(parse_block_transaction_anchor(&missing, 900001, &"ab".repeat(32)).is_err());

        let mut duplicate = value;
        duplicate["tx_hash_list"] = serde_json::json!(["ab".repeat(32), "AB".repeat(32)]);
        assert!(parse_block_transaction_anchor(&duplicate, 900001, &"ab".repeat(32)).is_err());
    }

    #[test]
    fn transaction_observation_distinguishes_not_found_from_mismatch() {
        let hash = "cd".repeat(32);
        assert_eq!(
            parse_transaction_observation(
                &serde_json::json!({"ret": 1, "err": "transaction not found"}),
                &hash,
            )
            .unwrap(),
            None
        );
        let mismatch = serde_json::json!({
            "ret": 0,
            "hash": "ef".repeat(32),
            "tx_type": 2,
            "body": "0200",
            "actions": [],
            "signatures": [],
            "block": {"height": 1},
            "confirm": 0
        });
        assert!(parse_transaction_observation(&mismatch, &hash).is_err());
    }

    #[test]
    fn hvm_transaction_observation_requires_type3_and_action44() {
        let hash = "ac".repeat(32);
        let value = serde_json::json!({
            "ret": 0,
            "hash": hash,
            "tx_type": 3,
            "body": "0300",
            "actions": [{"kind": 44}],
            "signatures": [{"complete": true}],
            "block": {"height": 900010},
            "confirm": 6
        });
        assert!(
            parse_transaction_observation_kind(&value, &"ac".repeat(32), 3, Some(44))
                .unwrap()
                .is_some()
        );
        let mut wrong_type = value.clone();
        wrong_type["tx_type"] = serde_json::json!(2);
        assert!(
            parse_transaction_observation_kind(&wrong_type, &"ac".repeat(32), 3, Some(44)).is_err()
        );
        let mut missing_action = value;
        missing_action["actions"] = serde_json::json!([{"kind": 41}]);
        assert!(
            parse_transaction_observation_kind(&missing_action, &"ac".repeat(32), 3, Some(44))
                .is_err()
        );
    }

    #[tokio::test]
    async fn configured_api_token_is_sent_and_invalid_tokens_fail_closed() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/query/capabilities",
            get(|headers: HeaderMap| async move {
                let authorized = headers
                    .get("x-api-token")
                    .and_then(|value| value.to_str().ok())
                    == Some("node-token");
                let status = if authorized {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                };
                (status, Json(capabilities(vec![1, 2, 3])))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = NodeClient::new(format!("http://{address}"))
            .unwrap()
            .with_api_token(Some("node-token"))
            .unwrap();
        assert!(
            client
                .capabilities()
                .await
                .unwrap()
                .action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE)
        );
        for invalid in ["bad\nheader", " leading", "trailing ", &"x".repeat(513)] {
            assert!(
                NodeClient::new("http://127.0.0.1:1")
                    .unwrap()
                    .with_api_token(Some(invalid))
                    .is_err()
            );
        }

        server.abort();
    }

    #[tokio::test]
    async fn submit_is_authenticated_hash_bound_and_fail_closed() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use axum::{Json, Router};

        let expected_hash = "11".repeat(32);
        let response_hash = expected_hash.clone();
        let app = Router::new().route(
            "/submit/transaction",
            post(move |headers: HeaderMap, body: String| {
                let response_hash = response_hash.clone();
                async move {
                    if headers
                        .get("x-api-token")
                        .and_then(|value| value.to_str().ok())
                        != Some("node-token")
                        || body != "0200"
                    {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({ "ret": 1 })),
                        );
                    }
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({ "ret": 0, "hash": response_hash })),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = NodeClient::new(format!("http://{address}"))
            .unwrap()
            .with_api_token(Some("node-token"))
            .unwrap();
        assert_eq!(
            client
                .submit_transaction("0200", &expected_hash)
                .await
                .unwrap(),
            expected_hash
        );
        assert!(
            client
                .submit_transaction("0200", &"22".repeat(32))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_transaction("not-hex", &expected_hash)
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn channel_submit_requires_the_exact_network_binding_and_never_falls_back() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::extract::Query;
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use axum::{Json, Router};

        let expected_hash = "11".repeat(32);
        let response_hash = expected_hash.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let route_calls = calls.clone();
        let app = Router::new().route(
            "/submit/transaction/hpay-bound",
            post(
                move |headers: HeaderMap,
                      Query(query): Query<HashMap<String, String>>,
                      body: String| {
                    let response_hash = response_hash.clone();
                    let route_calls = route_calls.clone();
                    async move {
                        route_calls.fetch_add(1, Ordering::SeqCst);
                        if headers
                            .get("x-api-token")
                            .and_then(|value| value.to_str().ok())
                            != Some("node-token")
                            || query.get("hexbody").map(String::as_str) != Some("true")
                            || query.get("chain_id").map(String::as_str) != Some("7")
                            || query
                                .get("network_instance_id")
                                .map(String::as_str)
                                != Some(
                                    "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3",
                                )
                            || body != "0200"
                        {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "ret": 1 })),
                            );
                        }
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({ "ret": 0, "hash": response_hash })),
                        )
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = NodeClient::new(format!("http://{address}"))
            .unwrap()
            .with_api_token(Some("node-token"))
            .unwrap();
        let binding = L1ChannelNetworkBinding::from_node_identity(
            "local_pilot_v1",
            false,
            7,
            "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29",
            "hpay-local-pilot-chain-v1",
            Some("9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3"),
            2,
        )
        .unwrap();
        assert_eq!(
            client
                .submit_transaction_bound("0200", &expected_hash, &binding)
                .await
                .unwrap(),
            expected_hash
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();

        let legacy_only = Router::new().route(
            "/submit/transaction",
            post(|| async { Json(serde_json::json!({ "ret": 0, "hash": "11".repeat(32) })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, legacy_only).await.unwrap();
        });
        let client = NodeClient::new(format!("http://{address}")).unwrap();
        assert!(
            client
                .submit_transaction_bound("0200", &"11".repeat(32), &binding)
                .await
                .is_err()
        );
        server.abort();
    }
    #[test]
    fn financial_balance_parser_is_exact_canonical_and_u128_bounded() {
        assert_eq!(parse_fin_balance_zhu("1:248").unwrap(), 100_000_000);
        assert_eq!(parse_fin_balance_zhu("1:245").unwrap(), 100_000);
        assert_eq!(parse_fin_balance_zhu("5961400632:238").unwrap(), 59_614_006);
        assert_eq!(parse_fin_balance_zhu("99:238").unwrap(), 0);
        assert_eq!(parse_fin_balance_zhu("101:238").unwrap(), 1);
        assert_eq!(
            parse_fin_balance_zhu("18446744073709551616:240").unwrap(),
            u128::from(u64::MAX) + 1
        );
        for invalid in ["1.0", "-1:248", "01:248", "100:238", "not-an-amount"] {
            assert!(parse_fin_balance_zhu(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed_and_oversized_responses_fail_closed() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::Router;
        use axum::http::StatusCode;
        use axum::response::Redirect;
        use axum::routing::get;

        let redirected_calls = Arc::new(AtomicUsize::new(0));
        let target_app = Router::new().route(
            "/query/capabilities",
            get({
                let redirected_calls = redirected_calls.clone();
                move || {
                    let redirected_calls = redirected_calls.clone();
                    async move {
                        redirected_calls.fetch_add(1, Ordering::SeqCst);
                        axum::Json(capabilities(vec![1, 2, 3]))
                    }
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target_server = tokio::spawn(async move {
            axum::serve(target_listener, target_app).await.unwrap();
        });

        let redirect_location = format!("http://{target_address}/query/capabilities");
        let redirect_app = Router::new().route(
            "/query/capabilities",
            get(move || {
                let redirect_location = redirect_location.clone();
                async move { Redirect::temporary(&redirect_location) }
            }),
        );
        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let redirect_server = tokio::spawn(async move {
            axum::serve(redirect_listener, redirect_app).await.unwrap();
        });

        let redirect_client = NodeClient::new(format!("http://{redirect_address}"))
            .unwrap()
            .with_api_token(Some("must-not-leak"))
            .unwrap();
        assert!(redirect_client.capabilities().await.is_err());
        assert_eq!(redirected_calls.load(Ordering::SeqCst), 0);

        let oversized_app = Router::new().route(
            "/query/capabilities",
            get(|| async move {
                (
                    StatusCode::OK,
                    "x".repeat(MAX_NODE_RESPONSE_BYTES.saturating_add(1)),
                )
            }),
        );
        let oversized_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oversized_address = oversized_listener.local_addr().unwrap();
        let oversized_server = tokio::spawn(async move {
            axum::serve(oversized_listener, oversized_app)
                .await
                .unwrap();
        });
        let oversized_client = NodeClient::new(format!("http://{oversized_address}")).unwrap();
        assert!(oversized_client.capabilities().await.is_err());

        oversized_server.abort();
        redirect_server.abort();
        target_server.abort();
    }
}
