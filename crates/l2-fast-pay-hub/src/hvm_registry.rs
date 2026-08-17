//! Shared multi-channel HPAY HVM settlement profile.
//!
//! V2 is additive: the reviewed per-channel V1 contract and sealed state stay
//! untouched. One V2 deployment is bound to one Hub and one network, while
//! every user's channel remains cryptographically isolated by left address,
//! channel id and reuse version.

use basis::method::verify_signature;
use field::Hash;
use serde::{Deserialize, Serialize};
use vm::ContractAddress;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{decode_hex, is_lower_hex, parse_address, parse_signature};
use crate::node::{HACASH_MAINNET_MIN_SAFE_HEIGHT, HvmStorageEntry};

pub const HPAY_REGISTRY_SETTLEMENT_PROFILE: &str = "hpay-hvm-shared-registry-v2";
pub const HPAY_REGISTRY_PROTOCOL_DOMAIN: &str = "HPAY/HVM-CHANNEL-REGISTRY/V2";
pub const HPAY_REGISTRY_BYTECODE_SHA3: &str =
    "2fa7429d9e686dd2457eeb1b4476f972c7ddd9be6a0371c9765eff2910209b04";
pub const HVM_REGISTRY_BINDING_SCHEMA: &str = "hpay-hvm-registry-binding/2";
pub const HVM_REGISTRY_BILL_SCHEMA: &str = "hpay-hvm-registry-bill/2";
pub const HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA: &str = "hpay-hvm-registry-recovery-bundle/2";
pub const HVM_REGISTRY_REFUND_COUNTERSIGN_REQUEST_SCHEMA: &str =
    "hpay-hvm-registry-refund-countersign-request/2";
/// The ASK expires; the ANSWER never does. Same five minutes the payment path
/// uses (`HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS`).
pub const HVM_REGISTRY_REFUND_COUNTERSIGN_MAX_LIFETIME_SECONDS: u64 = 5 * 60;
const HVM_REGISTRY_BINDING_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY-BINDING/V2";
const HVM_REGISTRY_BILL_DOMAIN: &[u8] = b"HPAY/HVM-CHANNEL-REGISTRY/V2";
pub const HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA: &str = "hpay-hvm-channel-registry-live-snapshot/2";
pub const HVM_REGISTRY_STORAGE_KEY_COUNT: u64 = 6;
pub const HVM_REGISTRY_CHANNEL_KEY_COUNT: u64 = 12;

/// `MAX_RENT_STEP` as the reviewed registry contract declares it.
///
/// Both `renew_registry` and `renew_channel` open with
/// `assert periods <= MAX_RENT_STEP`, so a lease renewal above this figure is
/// not "a bit greedy" — it aborts, changes nothing, and costs a fee. Since an
/// expired lease is the only way this system destroys a deposit outright, a
/// renewal that cannot execute is the worst kind of dead code: it fails in the
/// exact situation it was written for.
///
/// This is a mirror of a number that lives in another repository, which is
/// exactly the shape that drifted last time — the wallet asked for 200 and 400
/// against a contract that had moved to 150. It is not left to be kept in step
/// by hand: `registry_rent_step_matches_the_reviewed_contract`, in the module
/// that already embeds the contract source, parses `const MAX_RENT_STEP` back
/// out of the contract and fails the build's tests if this constant is not
/// exactly it.
pub const HPAY_REGISTRY_MAX_RENT_STEP: u64 = 150;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryBindingV2 {
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

impl HvmRegistryBindingV2 {
    pub fn validate(&self) -> HubResult<()> {
        let network_profile_valid = match self.network_mode.as_str() {
            "mainnet" => {
                self.chain_id == 0 && self.deployment_height >= HACASH_MAINNET_MIN_SAFE_HEIGHT
            }
            "testnet" => self.chain_id != 0 && self.deployment_height > 0,
            _ => false,
        };
        if self.schema != HVM_REGISTRY_BINDING_SCHEMA
            || self.settlement_profile != HPAY_REGISTRY_SETTLEMENT_PROFILE
            || !network_profile_valid
            || !is_lower_hex(&self.network_instance_id, 32)
            || !is_lower_hex(&self.deployment_tx_hash, 32)
            || self.bytecode_sha3 != HPAY_REGISTRY_BYTECODE_SHA3
            || !is_lower_hex(&self.channel_id, 16)
            || self.left_deposit_zhu == 0
            || self.right_hub_deposit_zhu != 0
            || self.challenge_blocks == 0
        {
            return Err(HubError::Node(
                "HVM registry binding does not match the reviewed shared V2 profile".into(),
            ));
        }
        let contract = parse_address(&self.contract_address, "registry contract")?;
        ContractAddress::from_addr(contract).map_err(|_| {
            HubError::Node("HVM registry binding address is not a contract address".into())
        })?;
        let left = parse_address(&self.left_address, "registry left")?;
        let hub = parse_address(&self.right_hub_address, "registry Hub")?;
        if left == hub || left == contract || hub == contract {
            return Err(HubError::Node(
                "HVM registry parties and contract must be distinct".into(),
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
        let contract = parse_address(&self.contract_address, "registry contract")?;
        let left = parse_address(&self.left_address, "registry left")?;
        let hub = parse_address(&self.right_hub_address, "registry Hub")?;
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(HVM_REGISTRY_BINDING_DOMAIN);
        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(contract.as_bytes());
        bytes.extend_from_slice(&deployment_tx);
        bytes.extend_from_slice(&self.deployment_height.to_be_bytes());
        bytes.extend_from_slice(&bytecode);
        bytes.extend_from_slice(&channel);
        bytes.extend_from_slice(&self.reuse_version.to_be_bytes());
        bytes.extend_from_slice(left.as_bytes());
        bytes.extend_from_slice(hub.as_bytes());
        bytes.extend_from_slice(&self.left_deposit_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.right_hub_deposit_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.challenge_blocks.to_be_bytes());
        Ok(hex::encode(sys::sha2(&bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryBillV2 {
    pub schema: String,
    pub binding_commitment: String,
    pub serial: u64,
    pub left_balance_zhu: u64,
    pub hub_balance_zhu: u64,
    pub left_signature_hex: String,
    pub hub_signature_hex: String,
}

impl HvmRegistryBillV2 {
    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            HubError::State(format!("HVM registry bill encode failed: {error}"))
        })?;
        Ok(hex::encode(sys::sha2(&bytes)))
    }

    pub fn signing_hash(&self, binding: &HvmRegistryBindingV2) -> HubResult<Hash> {
        binding.validate()?;
        if self.schema != HVM_REGISTRY_BILL_SCHEMA
            || self.binding_commitment != binding.commitment()?
            || self.serial == 0
        {
            return Err(HubError::Node(
                "HVM registry bill is not bound to the exact shared channel".into(),
            ));
        }
        let total = self
            .left_balance_zhu
            .checked_add(self.hub_balance_zhu)
            .ok_or_else(|| HubError::Node("HVM registry bill balance overflow".into()))?;
        let deposit = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM registry deposit overflow".into()))?;
        if total != deposit {
            return Err(HubError::Node(
                "HVM registry bill does not conserve the exact deposit".into(),
            ));
        }
        let network = decode_hex(&binding.network_instance_id)?;
        let channel = decode_hex(&binding.channel_id)?;
        let contract = parse_address(&binding.contract_address, "registry contract")?;
        let left = parse_address(&binding.left_address, "registry left")?;
        let hub = parse_address(&binding.right_hub_address, "registry Hub")?;
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(HVM_REGISTRY_BILL_DOMAIN);
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(contract.as_bytes());
        bytes.extend_from_slice(&channel);
        bytes.extend_from_slice(&binding.reuse_version.to_be_bytes());
        bytes.extend_from_slice(left.as_bytes());
        bytes.extend_from_slice(hub.as_bytes());
        bytes.extend_from_slice(&deposit.to_be_bytes());
        bytes.extend_from_slice(&binding.challenge_blocks.to_be_bytes());
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.extend_from_slice(&self.left_balance_zhu.to_be_bytes());
        bytes.extend_from_slice(&self.hub_balance_zhu.to_be_bytes());
        Ok(Hash::from(sys::sha3(bytes)))
    }

    pub fn validate_fully_signed(&self, binding: &HvmRegistryBindingV2) -> HubResult<()> {
        let hash = self.signing_hash(binding)?;
        let left = parse_address(&binding.left_address, "registry left")?;
        let hub = parse_address(&binding.right_hub_address, "registry Hub")?;
        let left_signature = parse_signature(&self.left_signature_hex)?;
        let hub_signature = parse_signature(&self.hub_signature_hex)?;
        if !verify_signature(&hash, &left, &left_signature)
            || !verify_signature(&hash, &hub, &hub_signature)
        {
            return Err(HubError::Node(
                "HVM registry bill signatures do not match both bound parties".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_left_signed(&self, binding: &HvmRegistryBindingV2) -> HubResult<()> {
        let hash = self.signing_hash(binding)?;
        let left = parse_address(&binding.left_address, "registry left")?;
        let signature = parse_signature(&self.left_signature_hex)?;
        if !verify_signature(&hash, &left, &signature) {
            return Err(HubError::Node(
                "HVM registry bill left signature does not match the bound user".into(),
            ));
        }
        Ok(())
    }

    pub fn is_initial_recovery_bill(&self, binding: &HvmRegistryBindingV2) -> bool {
        self.serial == 1
            && self.left_balance_zhu == binding.left_deposit_zhu
            && self.hub_balance_zhu == 0
            && self.validate_fully_signed(binding).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryRecoveryBundleV2 {
    pub schema: String,
    pub binding: HvmRegistryBindingV2,
    pub initial_recovery_bill: HvmRegistryBillV2,
}

impl HvmRegistryRecoveryBundleV2 {
    pub fn validate_crypto(&self) -> HubResult<()> {
        if self.schema != HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA {
            return Err(HubError::Node(
                "HVM registry recovery bundle schema is unsupported".into(),
            ));
        }
        self.binding.validate()?;
        if !self
            .initial_recovery_bill
            .is_initial_recovery_bill(&self.binding)
        {
            return Err(HubError::Node(
                "HVM registry recovery bundle lacks the exact signed initial bill".into(),
            ));
        }
        Ok(())
    }
}

/// What the wallet ASKS the Hub for, before it has parted with anything.
///
/// The wallet builds the whole thing from its own confirmed deployment record:
/// the binding, and the serial-1 full-refund bill signed on the left line only.
/// The Hub is asked for one thing and returns one thing - 97 bytes.
///
/// # Why this is asked for at `init` time and not after funding
///
/// `verify_bill` in the contract refuses while `c_paid_ != c_deposit_`, so a
/// serial-1 refund bill is INERT until the user themselves funds. The Hub risks
/// nothing by signing it early. Asking later is strictly worse: a Hub that
/// refuses after `init` has confirmed permanently burns that `(contract, left)`
/// slot, because re-`init` requires the old channel to be FINAL and claimed and
/// a channel stranded in FUNDING is neither.
///
/// # Why the REQUEST expires and the ANSWER does not
///
/// The lifetime here stops a captured request being replayed at the Hub. The
/// bill itself carries no time field at all, and must not: an expiring refund
/// is a Hub-shaped weapon - wait it out and the user is back to holding
/// nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryRefundCountersignRequestV2 {
    pub schema: String,
    pub binding: HvmRegistryBindingV2,
    pub left_signed_refund_bill: HvmRegistryBillV2,
    pub created_unix: u64,
    pub expires_unix: u64,
}

impl HvmRegistryRefundCountersignRequestV2 {
    /// Everything about the ask that does not depend on wall time.
    ///
    /// Deliberately separate from the lifetime check: the wallet keeps this
    /// request durably long after the ask expires, and re-validating a stored
    /// request must not fail merely because five minutes went by.
    pub fn validate_shape(&self) -> HubResult<()> {
        if self.schema != HVM_REGISTRY_REFUND_COUNTERSIGN_REQUEST_SCHEMA {
            return Err(HubError::Node(
                "HVM registry refund countersign request schema is unsupported".into(),
            ));
        }
        self.binding.validate()?;
        let bill = &self.left_signed_refund_bill;
        if bill.serial != 1
            || bill.left_balance_zhu != self.binding.left_deposit_zhu
            || bill.hub_balance_zhu != 0
            || !bill.hub_signature_hex.is_empty()
        {
            return Err(HubError::Node(
                "HVM registry refund countersign request is not the exact serial-1 full refund"
                    .into(),
            ));
        }
        bill.validate_left_signed(&self.binding)
    }

    pub fn validate(&self, now_unix: u64) -> HubResult<()> {
        self.validate_shape()?;
        if self.created_unix == 0
            || self.expires_unix <= self.created_unix
            || self.expires_unix.saturating_sub(self.created_unix)
                > HVM_REGISTRY_REFUND_COUNTERSIGN_MAX_LIFETIME_SECONDS
            || now_unix >= self.expires_unix
        {
            return Err(HubError::Node(
                "HVM registry refund countersign request is expired or has an invalid lifetime"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Splice the Hub's 97 bytes into the bill the WALLET built, and refuse
    /// unless the result verifies against the WALLET's binding.
    ///
    /// This is the whole point of the exchange, and it is not a courtesy check.
    /// The Hub's own copy of the binding and the bill are discarded by the
    /// caller before this is ever reached, so a Hub cannot express a different
    /// channel id, deposit, reuse version or challenge window - those bytes
    /// never leave the response parser. What is left for it to get wrong is the
    /// signature itself, and [`HvmRegistryBillV2::validate_fully_signed`]
    /// verifies that against `binding.right_hub_address` rather than against
    /// the public key riding inside the wire signature, so a well-formed
    /// signature from any other key fails here too.
    pub fn attach_hub_countersignature(
        &self,
        hub_refund_signature_hex: &str,
    ) -> HubResult<HvmRegistryRecoveryBundleV2> {
        self.validate_shape()?;
        parse_signature(hub_refund_signature_hex)?;
        let mut bill = self.left_signed_refund_bill.clone();
        bill.hub_signature_hex = hub_refund_signature_hex.trim().to_ascii_lowercase();
        let bundle = HvmRegistryRecoveryBundleV2 {
            schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
            binding: self.binding.clone(),
            initial_recovery_bill: bill,
        };
        bundle.validate_crypto()?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryGlobalStorageV2 {
    pub g_network: HvmStorageEntry<String>,
    pub g_hub: HvmStorageEntry<String>,
    pub g_locked: HvmStorageEntry<u64>,
    pub g_left_claimable: HvmStorageEntry<u64>,
    pub g_hub_claimable: HvmStorageEntry<u64>,
    pub g_open_count: HvmStorageEntry<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryChannelStorageV2 {
    pub status: HvmStorageEntry<u8>,
    pub channel_id: HvmStorageEntry<String>,
    pub reuse: HvmStorageEntry<u32>,
    pub deposit: HvmStorageEntry<u64>,
    pub paid: HvmStorageEntry<u64>,
    pub total: HvmStorageEntry<u64>,
    pub serial: HvmStorageEntry<u64>,
    pub left_balance: HvmStorageEntry<u64>,
    pub hub_balance: HvmStorageEntry<u64>,
    pub challenge_blocks: HvmStorageEntry<u64>,
    pub deadline: HvmStorageEntry<u64>,
    pub left_claimed: HvmStorageEntry<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryLiveSnapshotV2 {
    pub ret: u8,
    pub schema: String,
    pub settlement_profile: String,
    pub chain_id: u32,
    pub network_instance_id: String,
    pub observed_height: u64,
    pub evaluation_height: u64,
    pub contract_address: String,
    pub deployment_tx_hash: String,
    pub deployment_height: u64,
    pub deployment_action_verified: bool,
    pub bytecode_sha3: String,
    pub hub_address: String,
    pub left_address: String,
    pub registry_key_count: u64,
    pub channel_key_count: u64,
    pub all_keys_active: bool,
    pub minimum_live_blocks: u64,
    pub minimum_recover_blocks: u64,
    pub registry: HvmRegistryGlobalStorageV2,
    pub channel: HvmRegistryChannelStorageV2,
}

impl HvmRegistryLiveSnapshotV2 {
    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            HubError::State(format!("HVM registry snapshot encode failed: {error}"))
        })?;
        Ok(hex::encode(sys::sha2(bytes)))
    }

    fn leases(&self) -> [(u64, u64, bool, bool); 18] {
        [
            entry_lease(&self.registry.g_network),
            entry_lease(&self.registry.g_hub),
            entry_lease(&self.registry.g_locked),
            entry_lease(&self.registry.g_left_claimable),
            entry_lease(&self.registry.g_hub_claimable),
            entry_lease(&self.registry.g_open_count),
            entry_lease(&self.channel.status),
            entry_lease(&self.channel.channel_id),
            entry_lease(&self.channel.reuse),
            entry_lease(&self.channel.deposit),
            entry_lease(&self.channel.paid),
            entry_lease(&self.channel.total),
            entry_lease(&self.channel.serial),
            entry_lease(&self.channel.left_balance),
            entry_lease(&self.channel.hub_balance),
            entry_lease(&self.channel.challenge_blocks),
            entry_lease(&self.channel.deadline),
            entry_lease(&self.channel.left_claimed),
        ]
    }

    /// The identity, deployment and lease half of the snapshot check.
    ///
    /// Split out of [`Self::validate_runtime_binding`] so the pre-funding check
    /// can reuse it verbatim. Every field compared here is true of a channel at
    /// any point in its life, including before the deposit is paid in; the
    /// runtime-only assertions (status 2..=4, `paid == deposit`) stay in the
    /// caller.
    fn validate_snapshot_identity(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        binding.validate()?;
        if self.ret != 0
            || self.schema != HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA
            || self.settlement_profile != HPAY_REGISTRY_SETTLEMENT_PROFILE
            || self.chain_id != binding.chain_id
            || self.network_instance_id != binding.network_instance_id
            || self.observed_height < binding.deployment_height
            || self.evaluation_height != self.observed_height.checked_add(1).unwrap_or_default()
            || self.contract_address != binding.contract_address
            || self.deployment_tx_hash != binding.deployment_tx_hash
            || self.deployment_height != binding.deployment_height
            || !self.deployment_action_verified
            || self.bytecode_sha3 != binding.bytecode_sha3
            || self.hub_address != binding.right_hub_address
            || self.left_address != binding.left_address
            || self.registry_key_count != HVM_REGISTRY_STORAGE_KEY_COUNT
            || self.channel_key_count != HVM_REGISTRY_CHANNEL_KEY_COUNT
            || !self.all_keys_active
            || self.minimum_live_blocks < minimum_required_live_blocks
            || self.minimum_recover_blocks < minimum_required_recover_blocks
        {
            return Err(HubError::Node(
                "live HVM registry evidence does not match the approved binding".into(),
            ));
        }
        let leases = self.leases();
        let observed_live = leases.iter().map(|entry| entry.0).min().unwrap_or_default();
        let observed_recover = leases.iter().map(|entry| entry.1).min().unwrap_or_default();
        if leases.iter().any(|entry| {
            !entry.2
                || entry.3
                || entry.0 < minimum_required_live_blocks
                || entry.1 < minimum_required_recover_blocks
        }) || self.minimum_live_blocks != observed_live
            || self.minimum_recover_blocks != observed_recover
        {
            return Err(HubError::Node(
                "one or more shared HVM registry leases are not safely active".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_runtime_binding(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        self.validate_snapshot_identity(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        let total = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM registry deposit overflow".into()))?;
        let observed_total = self
            .channel
            .left_balance
            .value
            .checked_add(self.channel.hub_balance.value)
            .ok_or_else(|| HubError::Node("HVM registry runtime balance overflow".into()))?;
        if !matches!(self.channel.status.value, 2..=4)
            || self.registry.g_network.value != binding.network_instance_id
            || self.registry.g_hub.value != binding.right_hub_address
            || self.channel.channel_id.value != binding.channel_id
            || self.channel.reuse.value != binding.reuse_version
            || self.channel.deposit.value != binding.left_deposit_zhu
            || self.channel.paid.value != binding.left_deposit_zhu
            || self.channel.total.value != total
            || observed_total != total
            || self.channel.challenge_blocks.value != binding.challenge_blocks
        {
            return Err(HubError::Node(
                "live shared HVM channel state is inconsistent with its binding".into(),
            ));
        }
        if matches!(self.channel.status.value, 2 | 3)
            && (self.registry.g_locked.value < total || self.registry.g_open_count.value == 0)
        {
            return Err(HubError::Node(
                "shared HVM registry accounting does not cover the live channel".into(),
            ));
        }
        if self.channel.status.value == 2
            && (self.channel.deadline.value != 0 || self.channel.left_claimed.value)
        {
            return Err(HubError::Node(
                "open shared HVM channel contains challenge or claim residue".into(),
            ));
        }
        if self.channel.status.value == 3 && self.channel.deadline.value == 0 {
            return Err(HubError::Node(
                "challenging shared HVM channel has no deadline".into(),
            ));
        }
        Ok(())
    }

    /// The on-chain re-check the wallet runs after `init` confirms and BEFORE
    /// it parts with the deposit.
    ///
    /// This is load-bearing, not decoration. `PayableHAC` in the contract
    /// checks only status, prior payment and deposit size - it does not look at
    /// the channel id, the reuse version or the challenge window. So a Hub that
    /// co-signs an `init` whose parameters differ from the binding hands over a
    /// refund bill that is cryptographically perfect and permanently
    /// unpresentable: funding would succeed, and `verify_bill` would then
    /// compute its hash from the contract's own `c_challenge_` and refuse the
    /// signature. Catching that here is the difference between a countersigned
    /// refund and a countersigned souvenir.
    ///
    /// Every existing validator on this type requires a channel that is already
    /// funded, so none of them can be reused: `validate_runtime_binding`
    /// rejects status 1 outright and demands `paid == left_deposit_zhu`.
    pub fn validate_prefunding_binding(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        self.validate_snapshot_identity(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        let total = binding
            .left_deposit_zhu
            .checked_add(binding.right_hub_deposit_zhu)
            .ok_or_else(|| HubError::Node("HVM registry deposit overflow".into()))?;
        if self.channel.status.value != 1
            || self.channel.paid.value != 0
            || self.channel.serial.value != 0
            || self.channel.deadline.value != 0
            || self.channel.left_claimed.value
            || self.registry.g_network.value != binding.network_instance_id
            || self.registry.g_hub.value != binding.right_hub_address
            || self.channel.channel_id.value != binding.channel_id
            || self.channel.reuse.value != binding.reuse_version
            || self.channel.deposit.value != binding.left_deposit_zhu
            || self.channel.total.value != total
            || self.channel.left_balance.value != binding.left_deposit_zhu
            || self.channel.hub_balance.value != 0
            || self.channel.challenge_blocks.value != binding.challenge_blocks
        {
            return Err(HubError::Node(
                "shared HVM contract state is not the exact unfunded channel this binding names"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn validate_open_binding(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<()> {
        self.validate_runtime_binding(
            binding,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
        )?;
        if self.channel.status.value != 2
            || self.channel.serial.value != 0
            || self.channel.left_balance.value != binding.left_deposit_zhu
            || self.channel.hub_balance.value != 0
            || self.channel.deadline.value != 0
            || self.channel.left_claimed.value
        {
            return Err(HubError::Node(
                "shared HVM contract state is not an exact newly opened channel".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_initial_open_binding(
        &self,
        binding: &HvmRegistryBindingV2,
        minimum_required_live_blocks: u64,
    ) -> HubResult<()> {
        if minimum_required_live_blocks == 0 {
            return Err(HubError::Node(
                "initial shared HVM channel requires a positive live lease minimum".into(),
            ));
        }
        self.validate_open_binding(binding, minimum_required_live_blocks, 0)?;
        if self.minimum_recover_blocks != 0
            || self
                .leases()
                .iter()
                .any(|entry| !entry.2 || entry.3 || entry.1 != 0)
        {
            return Err(HubError::Node(
                "initial shared HVM leases must have zero recovery credit".into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use field::{Address, Serialize as FieldSerialize};
    use sys::Account;

    fn fixture() -> (Account, Account, HvmRegistryBindingV2) {
        let left = Account::create_by("hvm-registry-left").unwrap();
        let hub = Account::create_by("hvm-registry-hub").unwrap();
        (
            left.clone(),
            hub.clone(),
            HvmRegistryBindingV2 {
                schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
                settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
                network_mode: "testnet".into(),
                chain_id: 7,
                network_instance_id: "11".repeat(32),
                contract_address: Address::create_contract([7_u8; 20]).to_readable(),
                deployment_tx_hash: "22".repeat(32),
                deployment_height: 10,
                bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
                channel_id: "33".repeat(16),
                reuse_version: 0,
                left_address: left.readable().to_owned(),
                right_hub_address: hub.readable().to_owned(),
                left_deposit_zhu: 1_000_000,
                right_hub_deposit_zhu: 0,
                challenge_blocks: 12,
            },
        )
    }

    fn entry<T>(value: T, recover_blocks: u64) -> HvmStorageEntry<T> {
        HvmStorageEntry {
            value,
            live_blocks: 100,
            recover_blocks,
            active: true,
            recoverable: false,
        }
    }

    fn snapshot(binding: &HvmRegistryBindingV2, recover_blocks: u64) -> HvmRegistryLiveSnapshotV2 {
        HvmRegistryLiveSnapshotV2 {
            ret: 0,
            schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            chain_id: binding.chain_id,
            network_instance_id: binding.network_instance_id.clone(),
            observed_height: 20,
            evaluation_height: 21,
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
            minimum_recover_blocks: recover_blocks,
            registry: HvmRegistryGlobalStorageV2 {
                g_network: entry(binding.network_instance_id.clone(), recover_blocks),
                g_hub: entry(binding.right_hub_address.clone(), recover_blocks),
                g_locked: entry(binding.left_deposit_zhu, recover_blocks),
                g_left_claimable: entry(0, recover_blocks),
                g_hub_claimable: entry(0, recover_blocks),
                g_open_count: entry(1, recover_blocks),
            },
            channel: HvmRegistryChannelStorageV2 {
                status: entry(2, recover_blocks),
                channel_id: entry(binding.channel_id.clone(), recover_blocks),
                reuse: entry(binding.reuse_version, recover_blocks),
                deposit: entry(binding.left_deposit_zhu, recover_blocks),
                paid: entry(binding.left_deposit_zhu, recover_blocks),
                total: entry(binding.left_deposit_zhu, recover_blocks),
                serial: entry(0, recover_blocks),
                left_balance: entry(binding.left_deposit_zhu, recover_blocks),
                hub_balance: entry(0, recover_blocks),
                challenge_blocks: entry(binding.challenge_blocks, recover_blocks),
                deadline: entry(0, recover_blocks),
                left_claimed: entry(false, recover_blocks),
            },
        }
    }

    #[test]
    fn exact_bill_signatures_and_generation_binding_validate() {
        let (left, hub, binding) = fixture();
        let mut bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: 1_000_000,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&binding).unwrap();
        bill.left_signature_hex = hex::encode(field::Sign::create_by(&left, &hash).serialize());
        bill.hub_signature_hex = hex::encode(field::Sign::create_by(&hub, &hash).serialize());
        assert!(bill.validate_fully_signed(&binding).is_ok());
        assert!(bill.is_initial_recovery_bill(&binding));

        let mut wrong_generation = binding.clone();
        wrong_generation.reuse_version = 1;
        assert!(bill.validate_fully_signed(&wrong_generation).is_err());
        let mut wrong_profile = binding.clone();
        wrong_profile.settlement_profile = "hpay-hvm-channel-v1".into();
        assert!(wrong_profile.validate().is_err());
    }

    #[test]
    fn unknown_fields_and_nonzero_hub_deposit_fail_closed() {
        let (_, _, mut binding) = fixture();
        binding.right_hub_deposit_zhu = 1;
        assert!(binding.validate().is_err());
        let mut value = serde_json::to_value(fixture().2).unwrap();
        value["future"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HvmRegistryBindingV2>(value).is_err());
    }

    /// The pre-funding re-check catches the one substitution a perfect Hub
    /// signature cannot: an `init` whose on-chain parameters differ from the
    /// binding the refund bill was signed over.
    #[test]
    fn prefunding_snapshot_catches_an_init_that_does_not_match_the_signed_binding() {
        let (_, _, binding) = fixture();
        let mut unfunded = snapshot(&binding, 10);
        unfunded.channel.status.value = 1;
        unfunded.channel.paid.value = 0;
        assert!(unfunded.validate_prefunding_binding(&binding, 1, 1).is_ok());
        // Every existing validator requires a channel that is already funded,
        // which is exactly why this one had to exist.
        assert!(unfunded.validate_runtime_binding(&binding, 1, 1).is_err());
        assert!(unfunded.validate_open_binding(&binding, 1, 1).is_err());

        // THE TRAP. `PayableHAC` checks only status, prior payment and deposit
        // size, so a channel opened with a different challenge window would
        // take the deposit and then refuse the refund bill for ever.
        let mut wrong_window = unfunded.clone();
        wrong_window.channel.challenge_blocks.value = binding.challenge_blocks + 1;
        assert!(
            wrong_window
                .validate_prefunding_binding(&binding, 1, 1)
                .is_err()
        );
        for mutate in [
            (|s: &mut HvmRegistryLiveSnapshotV2| s.channel.channel_id.value = "44".repeat(16))
                as fn(&mut HvmRegistryLiveSnapshotV2),
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.reuse.value = 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.deposit.value = 999_999,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.total.value = 999_999,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.left_balance.value = 999_999,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.hub_balance.value = 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.paid.value = 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.serial.value = 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.deadline.value = 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.left_claimed.value = true,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.status.value = 2,
        ] {
            let mut mutated = unfunded.clone();
            mutate(&mut mutated);
            assert!(
                mutated.validate_prefunding_binding(&binding, 1, 1).is_err(),
                "a mutated pre-funding channel must not validate"
            );
        }
    }

    #[test]
    fn exact_snapshot_validates_and_every_binding_or_lease_mutation_fails() {
        let (_, _, binding) = fixture();
        let operational = snapshot(&binding, 10);
        assert!(operational.validate_open_binding(&binding, 1, 1).is_ok());
        let bootstrap = snapshot(&binding, 0);
        assert!(bootstrap.validate_initial_open_binding(&binding, 1).is_ok());
        assert!(bootstrap.validate_open_binding(&binding, 1, 1).is_err());

        let mut wrong_channel = operational.clone();
        wrong_channel.channel.channel_id.value = "44".repeat(16);
        assert!(
            wrong_channel
                .validate_runtime_binding(&binding, 1, 1)
                .is_err()
        );
        let mut inactive = operational.clone();
        inactive.registry.g_network.active = false;
        assert!(inactive.validate_runtime_binding(&binding, 1, 1).is_err());
        let mut wrong_accounting = operational.clone();
        wrong_accounting.registry.g_locked.value = binding.left_deposit_zhu - 1;
        assert!(
            wrong_accounting
                .validate_runtime_binding(&binding, 1, 1)
                .is_err()
        );
        let mut wrong_hub = operational.clone();
        wrong_hub.hub_address = fixture().0.readable().to_owned();
        assert!(wrong_hub.validate_runtime_binding(&binding, 1, 1).is_err());
    }
}
