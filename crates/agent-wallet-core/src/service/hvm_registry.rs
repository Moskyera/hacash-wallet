//! Authenticated Agent-only binding to one shared HPAY HVM registry V2 slot.
//!
//! This is deliberately separate from the per-channel HVM V1 binding. The
//! owner adopts one exact registry/channel incarnation from authenticated Hub
//! evidence and a fresh pinned-node proof. Adoption alone grants no signing
//! authority; payment execution has its own durable reviewed state machine.

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::settings::validate_service_url;
use l2_fast_pay_hub::hvm_registry::{HvmRegistryBillV2, HvmRegistryRecoveryBundleV2};
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
// The head is a *serialised* field of wallet state, so the type and its schema
// tag must exist in every build - a build that dropped them would silently
// discard a user's exit evidence on the next save. Only the code that reads and
// advances it is pilot-gated, which is what makes these look unused without the
// feature.
#[cfg_attr(not(feature = "agent-wallet-testnet-pilot"), allow(dead_code))]
const AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA: u32 = 1;

/// The newest fully-signed registry bill this wallet has ever held, kept as an
/// explicit monotone field of authenticated wallet state.
///
/// # Why this exists as its own field
///
/// The binding is already durable here. The evidence built *from* the binding
/// was not: the only durable home of a fully-signed registry bill was inside
/// an `AgentHvmPaymentOperation`, one record per payment, and finding the
/// newest one meant scanning that map. That makes a user's only route to their
/// own money depend on the operation map staying complete and on a pruning
/// predicate staying the way it is today. A wallet restored from a trimmed
/// backup would still hold a valid binding and would no longer hold the bill
/// that binding is worthless without.
///
/// So the head is one field, advanced in the same journalled transition that
/// commits the bill, and never accepting a lower serial than the one it
/// already carries. An out-of-order or replayed commit cannot walk it
/// backwards, which matters because on this rail an older bill always pays the
/// user *more* and the Hub *less* — presenting one is not an accident that
/// costs the user money, it is an accident that looks like the user attacking
/// the Hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryExitHead {
    schema_version: u32,
    binding_commitment: String,
    bill: HvmRegistryBillV2,
    accepted_at: u64,
}

#[cfg_attr(not(feature = "agent-wallet-testnet-pilot"), allow(dead_code))]
impl AgentHvmRegistryExitHead {
    /// Seed the head at adoption from the binding's own initial recovery bill.
    ///
    /// The serial-1 full-refund bill is the weakest evidence the user will
    /// ever hold and the one they are guaranteed to hold: it is the bill the
    /// recovery bundle is validated against, so if the binding is adoptable
    /// this bill exists and is fully signed. Seeding with it means the exit
    /// head is never empty from the first moment a channel is bound, and the
    /// worst case of losing every later bill is an exit that refunds the whole
    /// deposit rather than an exit that cannot start.
    pub(crate) fn seed(binding: &AgentHvmRegistryBinding, now: u64) -> Self {
        Self {
            schema_version: AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA,
            binding_commitment: binding.binding_commitment.clone(),
            bill: binding.recovery_bundle.initial_recovery_bill.clone(),
            accepted_at: now,
        }
    }

    pub fn bill(&self) -> &HvmRegistryBillV2 {
        &self.bill
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    pub const fn accepted_at(&self) -> u64 {
        self.accepted_at
    }

    /// Accept a newer fully-signed bill, or refuse.
    ///
    /// Returns `true` when the head moved. A bill at the serial already held
    /// is accepted only if it is byte-identical, so a second bill minted at
    /// one serial is a `RecoveryRequired`, not a silent overwrite.
    pub(crate) fn advance(
        &mut self,
        binding: &AgentHvmRegistryBinding,
        bill: &HvmRegistryBillV2,
        now: u64,
    ) -> AgentWalletResult<bool> {
        if self.schema_version != AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA
            || self.binding_commitment != binding.binding_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        bill.validate_fully_signed(&binding.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if bill.serial < self.bill.serial {
            return Ok(false);
        }
        if bill.serial == self.bill.serial {
            return if bill == &self.bill {
                Ok(false)
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        self.bill = bill.clone();
        self.accepted_at = now;
        Ok(true)
    }

    /// Re-verify the head against the binding it claims to belong to.
    pub(crate) fn validate(&self, binding: &AgentHvmRegistryBinding) -> AgentWalletResult<()> {
        if self.schema_version != AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA
            || self.binding_commitment() != binding.binding_commitment()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.bill
            .validate_fully_signed(&binding.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if self.bill.serial < binding.recovery_bundle.initial_recovery_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }

    /// Build the exportable exit kit: the binding plus this head.
    ///
    /// The kit carries no private key. Every registry entry point takes the
    /// left address as a parameter and checks the bill's own two signatures
    /// rather than the transaction signer, so a holder can finish this exit in
    /// the user's favour and cannot redirect a single zhu of it.
    pub fn exit_kit(
        &self,
        binding: &AgentHvmRegistryBinding,
    ) -> AgentWalletResult<hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1> {
        self.validate(binding)?;
        hacash_wallet_core::hvm_registry_exit::build_exit_kit(
            binding.recovery_bundle.binding.clone(),
            self.bill.clone(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)
    }
}

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
    /// The binding and the newest fully-signed bill this wallet holds —
    /// everything needed to finish this channel's exit in the user's favour,
    /// and nothing else.
    ///
    /// Reads only authenticated wallet state. It asks the Hub nothing, and
    /// returns the same answer with the Hub's process deleted; that is the
    /// property the whole exit turns on, so it is a property of this accessor
    /// rather than of a code path taken when the Hub happens to be down.
    ///
    /// # The head is derived when it is missing, never demanded
    ///
    /// `hvm_registry_exit_head` is `#[serde(default)]` and is written at
    /// adoption or on the next committed bill. A wallet bound *before* that
    /// field existed therefore carries `None`, and refusing on `None` handed
    /// exactly the wrong answer to exactly the wrong person: a user whose
    /// channel predates this code and whose Hub has since died would be told
    /// their wallet needs recovery, when re-adoption is the one repair that
    /// requires the Hub to be alive.
    ///
    /// So a missing head falls back to the binding's own serial-1 recovery
    /// bill — the same seed `AgentHvmRegistryExitHead::seed` uses at adoption.
    /// That bill is guaranteed to exist, because the binding is not adoptable
    /// without it, and it is guaranteed to be fully signed for the same
    /// reason. It is also the *weakest* evidence the user can hold, which on
    /// this rail means it refunds the whole deposit: the failure mode of the
    /// fallback is a dead Hub forfeiting fees it already earned, not a user
    /// losing principal.
    pub fn hvm_registry_exit_kit(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let binding = state
            .hvm_registry_binding
            .as_ref()
            .ok_or(AgentWalletError::OperationNotFound)?;
        match state.hvm_registry_exit_head.as_ref() {
            Some(head) => head.exit_kit(binding),
            None => AgentHvmRegistryExitHead::seed(binding, 0).exit_kit(binding),
        }
    }

    /// The serial and accepted time of the wallet's own exit head, for a
    /// surface that wants to say which receipt it would exit with.
    ///
    /// `None` means this wallet has no registry channel at all. A wallet that
    /// has one always has a head, because a missing one falls back to the
    /// binding's serial-1 recovery bill exactly as
    /// [`Self::hvm_registry_exit_kit`] does — the two must never disagree
    /// about which receipt an exit would use, or the screen would name one
    /// bill and the driver would sign another.
    pub fn hvm_registry_exit_head_serial(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<Option<(u64, u64)>> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let Some(binding) = state.hvm_registry_binding.as_ref() else {
            return Ok(None);
        };
        let head = match state.hvm_registry_exit_head.as_ref() {
            Some(head) => head.clone(),
            None => AgentHvmRegistryExitHead::seed(binding, 0),
        };
        head.validate(binding)?;
        Ok(Some((head.bill().serial, head.accepted_at())))
    }

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
        // Seed the exit head in the same journalled transition that adopts the
        // binding. Adoption is legitimately Hub-dependent — the Hub is alive
        // at this moment and is where the channel is learned from — which is
        // exactly why everything the wallet will later need without the Hub
        // has to be copied into its own state right here. The binding already
        // was. The evidence built from it was not.
        current.hvm_registry_exit_head = Some(AgentHvmRegistryExitHead::seed(&candidate, now));
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

    /// A wallet bound before the exit head existed still has a route out.
    ///
    /// `hvm_registry_exit_head` is `#[serde(default)]` and is written at
    /// adoption or on the next committed bill. Any wallet whose channel
    /// predates that field therefore loads with `None` — and the accessor used
    /// to answer `None` with `RecoveryRequired`, which is the worst possible
    /// answer to the worst possible person: someone whose provider has already
    /// died, being told to re-adopt, when re-adoption is the one repair that
    /// needs the provider alive.
    ///
    /// The fallback is the binding's own serial-1 refund bill: guaranteed to
    /// exist, because the binding is not adoptable without it, and guaranteed
    /// to verify, for the same reason.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn a_wallet_with_no_stored_exit_head_still_has_an_exit_kit() {
        let (binding, _) = super::tests_support::binding_with_signed_refund();

        // Exactly what a wallet bound before this field existed carries.
        let head: Option<super::AgentHvmRegistryExitHead> = None;
        let kit = match head.as_ref() {
            Some(head) => head.exit_kit(&binding),
            None => super::AgentHvmRegistryExitHead::seed(&binding, 0).exit_kit(&binding),
        }
        .expect("a bound channel must always yield an exit kit");

        assert_eq!(
            kit.latest_bill, binding.recovery_bundle.initial_recovery_bill,
            "the fallback must be the refund bill the binding was adopted against"
        );
        kit.validate_crypto()
            .expect("the fallback kit must stand on its own signatures");
    }
}

/// Fixtures shared by this module's tests. Kept beside the type so a test can
/// build a binding whose fields are private to this file.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
mod tests_support {
    use super::*;
    use field::{Serialize as _, Sign};
    use l2_fast_pay_hub::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
        HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HvmRegistryBindingV2,
    };

    pub(super) fn binding_with_signed_refund() -> (AgentHvmRegistryBinding, u64) {
        l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
        let left = sys::Account::create_by("exit-head-fallback-left").unwrap();
        let hub = sys::Account::create_by("exit-head-fallback-hub").unwrap();
        let deposit = 1_000_000_u64;
        let contract =
            vm::ContractAddress::from_unchecked(field::Address::create_contract([7; 20]))
                .to_readable();
        let inner = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: "11".repeat(32),
            contract_address: contract,
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 2,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: field::Address::from(*left.address()).to_readable(),
            right_hub_address: field::Address::from(*hub.address()).to_readable(),
            left_deposit_zhu: deposit,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: inner.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: deposit,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&inner).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.hub_signature_hex = hex::encode(Sign::create_by(&hub, &hash).serialize());

        let commitment = inner.commitment().unwrap();
        let binding = AgentHvmRegistryBinding {
            schema_version: AGENT_HVM_REGISTRY_BINDING_SCHEMA,
            wallet_id: AgentWalletId::new(),
            network_mode: "testnet".into(),
            network_binding: L1ChannelNetworkBinding {
                network_kind: "testnet".into(),
                chain_id: 7,
                mainnet: false,
                block_1_hash: "55".repeat(32),
                node_profile_id: "66".repeat(32),
                network_instance_id: "11".repeat(32),
                transaction_format_version: 1,
            },
            hub_url: "http://127.0.0.1:8790".into(),
            hub_address: inner.right_hub_address.clone(),
            binding_commitment: commitment,
            recovery_bundle: HvmRegistryRecoveryBundleV2 {
                schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
                binding: inner,
                initial_recovery_bill: bill,
            },
            activation_snapshot_commitment: "44".repeat(32),
            minimum_required_live_blocks: 500,
            minimum_required_recover_blocks: 100,
            adopted_at: 1_700_000_000,
        };
        (binding, deposit)
    }
}
