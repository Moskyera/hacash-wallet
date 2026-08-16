//! Authenticated Agent-only binding to one shared HPAY HVM registry V2 slot.
//!
//! This is deliberately separate from the per-channel HVM V1 binding. The
//! owner adopts one exact registry/channel incarnation from authenticated Hub
//! evidence and a fresh pinned-node proof. Adoption alone grants no signing
//! authority; payment execution has its own durable reviewed state machine.

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::settings::validate_service_url;
use l2_fast_pay_hub::hvm_registry::HvmRegistryRecoveryBundleV2;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_CHANNEL_STATUS_SCHEMA, HvmRegistryChannelStatusV2,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use serde::{Deserialize, Serialize};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use super::AgentWalletManager;

const AGENT_HVM_REGISTRY_BINDING_SCHEMA: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryBinding {
    schema_version: u32,
    wallet_id: AgentWalletId,
    network_mode: String,
    network_binding: L1ChannelNetworkBinding,
    hub_url: String,
    hub_address: String,
    binding_commitment: String,
    recovery_bundle: HvmRegistryRecoveryBundleV2,
    activation_snapshot_commitment: String,
    minimum_required_live_blocks: u64,
    minimum_required_recover_blocks: u64,
    adopted_at: u64,
}

impl AgentHvmRegistryBinding {
    pub(crate) fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }

    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    pub fn hub_address(&self) -> &str {
        &self.hub_address
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    pub fn recovery_bundle(&self) -> &HvmRegistryRecoveryBundleV2 {
        &self.recovery_bundle
    }

    pub fn network_binding(&self) -> &L1ChannelNetworkBinding {
        &self.network_binding
    }

    pub const fn minimum_required_live_blocks(&self) -> u64 {
        self.minimum_required_live_blocks
    }

    pub const fn operational_recover_blocks(&self) -> u64 {
        if self.minimum_required_recover_blocks == 0 {
            1
        } else {
            self.minimum_required_recover_blocks
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(super) fn matches_status(&self, status: &HvmRegistryChannelStatusV2) -> bool {
        status.schema == HVM_REGISTRY_CHANNEL_STATUS_SCHEMA
            && status.binding_commitment == self.binding_commitment
            && status.recovery_bundle == self.recovery_bundle
            && status.activation_snapshot_commitment == self.activation_snapshot_commitment
            && status.minimum_required_live_blocks == self.minimum_required_live_blocks
            && status.minimum_required_recover_blocks == self.minimum_required_recover_blocks
            && status
                .latest_fully_signed_bill
                .validate_fully_signed(&self.recovery_bundle.binding)
                .is_ok()
    }

    pub(crate) fn validate(
        &self,
        expected_wallet_id: &AgentWalletId,
        expected_address: &str,
        expected_network_mode: &str,
    ) -> AgentWalletResult<()> {
        self.network_binding
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        self.recovery_bundle
            .validate_crypto()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = &self.recovery_bundle.binding;
        let canonical_hub_url = validate_service_url(&self.hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if self.schema_version != AGENT_HVM_REGISTRY_BINDING_SCHEMA
            || &self.wallet_id != expected_wallet_id
            || self.network_mode != expected_network_mode
            || self.network_binding.mainnet != (expected_network_mode == "mainnet")
            || self.network_binding.chain_id != binding.chain_id
            || self.network_binding.network_instance_id != binding.network_instance_id
            || binding.network_mode != expected_network_mode
            || binding.left_address != expected_address
            || binding.right_hub_address != self.hub_address
            || canonical_hub_url != self.hub_url
            || expected_network_mode == "mainnet" && !self.hub_url.starts_with("https://")
            || self.minimum_required_live_blocks == 0
            || !is_lower_hash(&self.activation_snapshot_commitment)
            || binding
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?
                != self.binding_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn from_verified_status(
        wallet_id: AgentWalletId,
        address: &str,
        network_mode: &str,
        network_binding: L1ChannelNetworkBinding,
        hub_url: String,
        hub_address: String,
        status: HvmRegistryChannelStatusV2,
        adopted_at: u64,
    ) -> AgentWalletResult<Self> {
        if status.schema != HVM_REGISTRY_CHANNEL_STATUS_SCHEMA
            || status.minimum_required_live_blocks == 0
            || !is_lower_hash(&status.activation_snapshot_commitment)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        status
            .latest_fully_signed_bill
            .validate_fully_signed(&status.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = Self {
            schema_version: AGENT_HVM_REGISTRY_BINDING_SCHEMA,
            wallet_id: wallet_id.clone(),
            network_mode: network_mode.to_owned(),
            network_binding,
            hub_url,
            hub_address,
            binding_commitment: status.binding_commitment,
            recovery_bundle: status.recovery_bundle,
            activation_snapshot_commitment: status.activation_snapshot_commitment,
            minimum_required_live_blocks: status.minimum_required_live_blocks,
            minimum_required_recover_blocks: status.minimum_required_recover_blocks,
            adopted_at,
        };
        binding.validate(&wallet_id, address, network_mode)?;
        Ok(binding)
    }
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentWalletManager {
    /// Adopt one exact operational shared-registry channel. This flow is
    /// owner-only, requires payments to remain suspended, and never signs.
    pub async fn verify_and_bind_hvm_registry(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        binding_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryBinding> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let original = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if original.network_mode != "testnet"
            || !original.payments_suspended
            || super::state::active_reservations(&original)? != crate::amount::HacUnits::ZERO
            || !original.hvm_payment_operations.is_empty()
            || original.hvm_channel_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let hub_url = validate_service_url(hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let hub = L2HubClient::new_for_wallet_policy(hub_url.clone(), "testnet", false);
        let health = hub
            .health()
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !hub_fee_is_zero(&health)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hub_address = health
            .hub_address
            .clone()
            .filter(|address| !address.is_empty())
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        let status = hub
            .hvm_registry_channel_status(binding_commitment)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;

        let verified_node = crate::node_binding::verified_agent_node(
            &original.node_url,
            &original.network_mode,
            &original.block_one_fingerprint,
        )
        .await?;
        let node_snapshot = verified_node.snapshot();
        let network_binding = L1ChannelNetworkBinding::from_node_identity(
            &node_snapshot.network_kind,
            node_snapshot.mainnet,
            node_snapshot.chain_id,
            &node_snapshot.block_one_fingerprint,
            &node_snapshot.node_profile_id,
            Some(&node_snapshot.network_instance_id),
            node_snapshot.transaction_format_version,
        )
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let protocol_binding = &status.recovery_bundle.binding;
        if protocol_binding.left_address != original.address
            || protocol_binding.right_hub_address != hub_address
            || protocol_binding.chain_id != network_binding.chain_id
            || protocol_binding.network_instance_id != network_binding.network_instance_id
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hvm_node = l2_fast_pay_hub::node::NodeClient::new(original.node_url.clone())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let runtime = hvm_node
            .verify_hvm_registry_runtime_bundle(
                &status.recovery_bundle,
                status.minimum_required_live_blocks,
                status.minimum_required_recover_blocks.max(1),
            )
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if runtime.channel.serial.value > status.latest_fully_signed_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let candidate = AgentHvmRegistryBinding::from_verified_status(
            wallet_id.clone(),
            &original.address,
            &original.network_mode,
            network_binding,
            hub_url,
            hub_address,
            status,
            now,
        )?;

        // Close the adoption TOCTOU window before touching authenticated
        // wallet state. No await is permitted after the final state reload.
        let final_status = hub
            .hvm_registry_channel_status(candidate.binding_commitment())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !candidate.matches_status(&final_status) {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let final_runtime = hvm_node
            .verify_hvm_registry_runtime_bundle(
                candidate.recovery_bundle(),
                candidate.minimum_required_live_blocks(),
                candidate.operational_recover_blocks(),
            )
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if final_runtime.channel.serial.value > final_status.latest_fully_signed_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.address != original.address
            || current.network_mode != original.network_mode
            || current.node_url != original.node_url
            || current.block_one_fingerprint != original.block_one_fingerprint
            || current.policy_epoch != original.policy_epoch
            || current.signer_epoch != original.signer_epoch
            || current.emergency_epoch != original.emergency_epoch
            || !current.payments_suspended
            || super::state::active_reservations(&current)? != crate::amount::HacUnits::ZERO
            || !current.hvm_payment_operations.is_empty()
            || current.hvm_channel_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = current.hvm_registry_binding.as_ref() {
            return if existing == &candidate {
                Ok(existing.clone())
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        current.hvm_registry_binding = Some(candidate.clone());
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmBindingVerified,
            None,
            None,
            now,
        )?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::is_lower_hash;

    #[test]
    fn binding_commitments_require_canonical_lowercase_sha256_hex() {
        assert!(is_lower_hash(&"ab".repeat(32)));
        assert!(!is_lower_hash(&"AB".repeat(32)));
        assert!(!is_lower_hash(&"ab".repeat(31)));
        assert!(!is_lower_hash(&"zz".repeat(32)));
    }
}
