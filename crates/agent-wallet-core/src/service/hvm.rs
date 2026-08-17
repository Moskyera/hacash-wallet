//! Authenticated Agent-only binding to one operational HPAY HVM channel.
//!
//! The browser/mobile UI never constructs this value. The owner adoption flow
//! derives it from authenticated Hub evidence plus a fresh, pinned full-node
//! verification of the exact deployment, channel incarnation and all leases.

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::settings::validate_service_url;
use l2_fast_pay_hub::hvm_channel::HvmChannelRecoveryBundleV1;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use l2_fast_pay_hub::hvm_ledger::{HVM_CHANNEL_STATUS_SCHEMA, HvmChannelStatusV1};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use serde::{Deserialize, Serialize};

#[cfg(feature = "agent-wallet-testnet-pilot")]
use crate::emergency::AgentSafetyPermit;
use crate::error::{AgentWalletError, AgentWalletResult};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use crate::hvm_payment_operation::{
    AgentHvmPaymentOperation, AgentHvmPaymentOperationView, AgentHvmPaymentRequest,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use crate::policy::{AgentPermission, AgentRecord, AgentStatus};
use crate::types::AgentWalletId;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use super::AgentWalletManager;

const AGENT_HVM_BINDING_SCHEMA: u32 = 1;

/// Move the wallet's own monotone exit head onto a freshly committed bill.
///
/// Silent about wallets that hold no registry binding — a committed HVM V1
/// bill has no registry head to advance. Loud about a head that refuses the
/// bill: `advance` returns `RecoveryRequired` only for a *different* bill at a
/// serial already held, which is two histories at one serial and must never be
/// resolved by overwriting one of them.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn advance_registry_exit_head(
    state: &mut super::AgentWalletState,
    bill: &l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2,
    now: u64,
) -> AgentWalletResult<()> {
    let Some(binding) = state.hvm_registry_binding.clone() else {
        return Ok(());
    };
    if let Some(head) = state.hvm_registry_exit_head.as_mut() {
        head.advance(&binding, bill, now)?;
        return Ok(());
    }
    // A binding adopted before this field existed. Seed it from the binding's
    // own initial recovery bill, then take the committed one, so the upgrade
    // path never leaves a bound channel with no exit evidence.
    let mut head = super::AgentHvmRegistryExitHead::seed(&binding, now);
    head.advance(&binding, bill, now)?;
    state.hvm_registry_exit_head = Some(head);
    Ok(())
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Clone, Copy)]
enum HvmReadinessPhase {
    Approved,
    SigningPrepared,
    PostSigned,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
struct VerifiedHvmReadiness {
    view: AgentHvmPaymentOperationView,
    binding: VerifiedAgentHvmBinding,
    permit: AgentSafetyPermit,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Clone)]
enum VerifiedAgentHvmBinding {
    ChannelV1(AgentHvmChannelBinding),
    RegistryV2(super::AgentHvmRegistryBinding),
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
enum PreparedAgentHvmEvidence {
    ChannelV1 {
        binding: AgentHvmChannelBinding,
        status: HvmChannelStatusV1,
        snapshot: l2_fast_pay_hub::node::HvmChannelLiveSnapshot,
    },
    RegistryV2 {
        binding: super::AgentHvmRegistryBinding,
        status: l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryChannelStatusV2,
        snapshot: l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
    },
}

// Boxing the wide variant would save stack bytes and cost a change at every
// construction and match site inside the payment evidence path. That is a
// layout gain with no correctness gain, and this is not the code to churn for
// it. The size difference is accepted deliberately.
#[allow(clippy::large_enum_variant)]
#[cfg(feature = "agent-wallet-testnet-pilot")]
enum ExpectedAgentHvmEvidence {
    ChannelV1 {
        binding: AgentHvmChannelBinding,
        prepared_snapshot: l2_fast_pay_hub::node::HvmChannelLiveSnapshot,
        previous_bill: l2_fast_pay_hub::hvm_channel::HvmChannelBillV1,
        signed_request: Option<l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1>,
    },
    RegistryV2 {
        binding: super::AgentHvmRegistryBinding,
        prepared_snapshot: l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
        previous_bill: l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2,
        signed_request: Option<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2>,
    },
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl VerifiedAgentHvmBinding {
    fn hub_url(&self) -> &str {
        match self {
            Self::ChannelV1(binding) => binding.hub_url(),
            Self::RegistryV2(binding) => binding.hub_url(),
        }
    }

    const fn is_registry_v2(&self) -> bool {
        matches!(self, Self::RegistryV2(_))
    }

    fn hub_address(&self) -> &str {
        match self {
            Self::ChannelV1(binding) => binding.hub_address(),
            Self::RegistryV2(binding) => binding.hub_address(),
        }
    }

    fn binding_commitment(&self) -> &str {
        match self {
            Self::ChannelV1(binding) => binding.binding_commitment(),
            Self::RegistryV2(binding) => binding.binding_commitment(),
        }
    }
}

// Same reasoning as ExpectedAgentHvmEvidence: a layout-only lint, on an enum
// that carries signed payment requests through the durable transition path.
#[allow(clippy::large_enum_variant)]
#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Clone)]
enum HvmDurableTransition {
    SigningPrepared,
    Signed(l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1),
    SignedRegistry(l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2),
    Submitted,
    Committed(l2_fast_pay_hub::hvm_channel::HvmChannelBillV1),
    CommittedRegistry(l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2),
    RecoveryRequired,
    ExactRetryReady,
    UnsignedSigningAbandoned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmChannelBinding {
    schema_version: u32,
    wallet_id: AgentWalletId,
    network_mode: String,
    network_binding: L1ChannelNetworkBinding,
    hub_url: String,
    hub_address: String,
    binding_commitment: String,
    recovery_bundle: HvmChannelRecoveryBundleV1,
    activation_snapshot_commitment: String,
    minimum_required_live_blocks: u64,
    minimum_required_recover_blocks: u64,
    adopted_at: u64,
}

impl AgentHvmChannelBinding {
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

    pub fn recovery_bundle(&self) -> &HvmChannelRecoveryBundleV1 {
        &self.recovery_bundle
    }

    pub fn network_binding(&self) -> &L1ChannelNetworkBinding {
        &self.network_binding
    }

    pub const fn minimum_required_live_blocks(&self) -> u64 {
        self.minimum_required_live_blocks
    }

    /// A bootstrap activation records zero recovery credit. Runtime payment
    /// authority always requires a positive recovery floor after lease renewal.
    pub const fn operational_recover_blocks(&self) -> u64 {
        if self.minimum_required_recover_blocks == 0 {
            1
        } else {
            self.minimum_required_recover_blocks
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn matches_status(&self, status: &HvmChannelStatusV1) -> bool {
        status.schema == HVM_CHANNEL_STATUS_SCHEMA
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
        let canonical_hub_url = validate_service_url(&self.hub_url, "Agent HVM Fast Pay hub")
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if self.schema_version != AGENT_HVM_BINDING_SCHEMA
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
        status: HvmChannelStatusV1,
        adopted_at: u64,
    ) -> AgentWalletResult<Self> {
        if status.schema != HVM_CHANNEL_STATUS_SCHEMA
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
            schema_version: AGENT_HVM_BINDING_SCHEMA,
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

/// The highest serial this wallet can *prove* one channel reached, from its own
/// encrypted operation state.
///
/// Read in two places and computed in one: before signing, to refuse a Hub
/// offering a head below what this wallet has already paid past, and at
/// acceptance, as the independent floor the rollback-anchor memory is measured
/// against. Both need the same number and neither may quietly use a different
/// one.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn committed_channel_serial_floor(
    state: &super::AgentWalletState,
    binding_commitment: &str,
) -> u64 {
    state
        .hvm_payment_operations
        .values()
        .filter(|operation| operation.binding_commitment() == binding_commitment)
        .map(AgentHvmPaymentOperation::committed_channel_serial)
        .max()
        .unwrap_or(0)
}

/// Keep the rollback-anchor verdicts apart from "something broke".
///
/// `RecoveryRequired` is answered by reconciling, and reconciling is how a
/// bill becomes committed. Flattening a parked witness decision, a rolled-back
/// Hub or a rewound anchor store into it points the owner at the one control
/// that would commit the bill the refusal exists to stop. The prefixes matched
/// here are public constants in `hacash_wallet_core::l2_safety`, carried on
/// the error precisely so this mapping is possible.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn classify_anchor_error(error: hacash_wallet_core::WalletError) -> AgentWalletError {
    let message = error.to_string();
    if message.contains(hacash_wallet_core::l2_safety::ANCHOR_WITNESS_DECISION_REQUIRED) {
        AgentWalletError::AnchorWitnessDecisionRequired
    } else if message.contains(hacash_wallet_core::l2_safety::REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET) {
        AgentWalletError::AnchorMemoryBehindWallet
    } else if message.contains(hacash_wallet_core::l2_safety::REFUSAL_WITNESS_BEHIND_HUB) {
        AgentWalletError::RollbackDetected
    } else {
        AgentWalletError::RecoveryRequired
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
    /// Create one fee-free HVM payment intent and the exact mobile approval
    /// commitment. No private key is used and no Hub mutation is called.
    pub(super) async fn request_hvm_payment_intent(
        &mut self,
        authorization: &super::AgentAuthorization,
        request: AgentHvmPaymentRequest,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let wallet_id = super::payment::wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(&wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let mut original = self.load_verified_state(&wallet_id, &state_master, &journal_key)?;
        let agent = super::validate_authorization(&original, authorization)?.clone();
        if authorization.capability() != AgentPermission::CreatePaymentIntent {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        super::payment::require_agent_spending_network(
            &original.network_mode,
            original.trusted_mainnet_fast_pay_pilot,
        )?;
        if original.network_mode != "testnet" {
            return Err(AgentWalletError::SigningBlocked);
        }
        request.validate(now)?;
        self.sweep_expired_pre_signing_operations(&mut original, &state_master, &journal_key, now)?;
        self.compact_aged_terminal_pre_signing_operations(
            &mut original,
            &state_master,
            &journal_key,
            now,
        )?;
        let scoped_key = super::state::scoped_idempotency_key(
            authorization.agent_id(),
            &request.idempotency_key,
        );
        let request_commitment = request.commitment_hex();
        if let Some(existing) = original.idempotency.get(&scoped_key) {
            if existing.rail != super::OperationRail::HvmFastPay
                || existing.request_commitment != request_commitment
            {
                return Err(AgentWalletError::IdempotencyConflict);
            }
            return original
                .hvm_payment_operations
                .get(existing.operation_id.as_str())
                .map(AgentHvmPaymentOperation::view)
                .ok_or(AgentWalletError::RecoveryRequired);
        }
        super::payment::ensure_operation_capacity(&original)?;
        super::payment::ensure_agent_request_rate(&original, authorization.agent_id(), now)?;
        super::payment::validate_policy_for_payment(
            &original,
            &agent,
            &request.recipient,
            request.amount_units,
            now,
        )?;
        if original
            .hvm_payment_operations
            .values()
            .any(|operation| operation.status().retains_reservation())
        {
            return Err(AgentWalletError::TooManyPendingOperations);
        }
        let selected_binding = match (
            original.hvm_channel_binding.clone(),
            original.hvm_registry_binding.clone(),
        ) {
            (Some(binding), None) => VerifiedAgentHvmBinding::ChannelV1(binding),
            (None, Some(binding)) => VerifiedAgentHvmBinding::RegistryV2(binding),
            _ => return Err(AgentWalletError::SigningBlocked),
        };
        let safety = self
            .emergency_controller(&wallet_id)?
            .issue_safety_permit(original.payments_suspended)?;
        safety.checkpoint(original.payments_suspended)?;

        let prepared = match &selected_binding {
            VerifiedAgentHvmBinding::ChannelV1(binding) => {
                let (status, snapshot) = verified_hvm_evidence(
                    binding,
                    &original.node_url,
                    &original.block_one_fingerprint,
                    &safety,
                    original.payments_suspended,
                )
                .await?;
                PreparedAgentHvmEvidence::ChannelV1 {
                    binding: binding.clone(),
                    status,
                    snapshot,
                }
            }
            VerifiedAgentHvmBinding::RegistryV2(binding) => {
                let (status, snapshot) = verified_hvm_registry_evidence(
                    binding,
                    &original.node_url,
                    &original.block_one_fingerprint,
                    &safety,
                    original.payments_suspended,
                )
                .await?;
                PreparedAgentHvmEvidence::RegistryV2 {
                    binding: binding.clone(),
                    status,
                    snapshot,
                }
            }
        };
        // The head this proposal will be built on is whatever the Hub says it
        // is. A Hub restored from an older backup offers an older head, and a
        // payer who signs onto it hands that Hub a second payer signature at a
        // serial it has already spent. The counterparty ratchet refuses the
        // co-signed bill afterwards — but the signature exists by then, and
        // the Hub keeps it. So the comparison happens here, before the signer
        // is entered, against this wallet's own record of what the channel
        // reached.
        let offered_head = match &prepared {
            PreparedAgentHvmEvidence::ChannelV1 { status, .. } => {
                status.latest_fully_signed_bill.serial
            }
            PreparedAgentHvmEvidence::RegistryV2 { status, .. } => {
                status.latest_fully_signed_bill.serial
            }
        };
        let known_head =
            committed_channel_serial_floor(&original, selected_binding.binding_commitment());
        if offered_head < known_head {
            return Err(AgentWalletError::RollbackDetected);
        }
        safety.checkpoint(original.payments_suspended)?;
        let amount_zhu = request.amount_zhu()?;
        let available_zhu = match &prepared {
            PreparedAgentHvmEvidence::ChannelV1 { status, .. } => {
                status.latest_fully_signed_bill.left_balance_zhu
            }
            PreparedAgentHvmEvidence::RegistryV2 { status, .. } => {
                status.latest_fully_signed_bill.left_balance_zhu
            }
        };
        if amount_zhu > available_zhu {
            return Err(AgentWalletError::InsufficientAgentBalance);
        }

        let mut current = self.load_verified_state(&wallet_id, &state_master, &journal_key)?;
        let current_agent = super::validate_authorization(&current, authorization)?.clone();
        if current_agent != agent
            || current.policy_epoch != original.policy_epoch
            || current.signer_epoch != original.signer_epoch
            || current.emergency_epoch != original.emergency_epoch
            || match &selected_binding {
                VerifiedAgentHvmBinding::ChannelV1(binding) => {
                    current.hvm_channel_binding.as_ref() != Some(binding)
                        || current.hvm_registry_binding.is_some()
                }
                VerifiedAgentHvmBinding::RegistryV2(binding) => {
                    current.hvm_registry_binding.as_ref() != Some(binding)
                        || current.hvm_channel_binding.is_some()
                }
            }
            || current.payments_suspended != original.payments_suspended
            || current.idempotency.contains_key(&scoped_key)
            || current
                .hvm_payment_operations
                .values()
                .any(|operation| operation.status().retains_reservation())
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        super::payment::ensure_operation_capacity(&current)?;
        super::payment::ensure_agent_request_rate(&current, authorization.agent_id(), now)?;
        super::payment::validate_policy_for_payment(
            &current,
            &current_agent,
            &request.recipient,
            request.amount_units,
            now,
        )?;
        safety.checkpoint(current.payments_suspended)?;

        let mut operation = match prepared {
            PreparedAgentHvmEvidence::ChannelV1 {
                binding,
                status,
                snapshot,
            } => {
                let mut operation = AgentHvmPaymentOperation::new(
                    crate::types::OperationId::new(),
                    authorization.agent_id().clone(),
                    wallet_id.clone(),
                    request,
                    &current.network_mode,
                    binding.network_binding().clone(),
                    binding.hub_url(),
                    binding.hub_address(),
                    binding.recovery_bundle().binding.clone(),
                    current_agent.authorization_epoch,
                    current.policy_epoch,
                    current.signer_epoch,
                    current.emergency_epoch,
                    now,
                )?;
                operation.reserve()?;
                operation.prepare_unsigned(&snapshot, status.latest_fully_signed_bill, now)?;
                operation
            }
            PreparedAgentHvmEvidence::RegistryV2 {
                binding,
                status,
                snapshot,
            } => {
                let mut operation = AgentHvmPaymentOperation::new_registry(
                    crate::types::OperationId::new(),
                    authorization.agent_id().clone(),
                    wallet_id.clone(),
                    request,
                    &current.network_mode,
                    binding.network_binding().clone(),
                    binding.hub_url(),
                    binding.hub_address(),
                    binding.recovery_bundle().binding.clone(),
                    current_agent.authorization_epoch,
                    current.policy_epoch,
                    current.signer_epoch,
                    current.emergency_epoch,
                    now,
                )?;
                operation.reserve()?;
                operation.prepare_unsigned_registry(
                    &snapshot,
                    status.latest_fully_signed_bill,
                    now,
                )?;
                operation
            }
        };
        let desktop_device_id =
            hpay_companion_protocol::DeviceId::parse(current.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
        operation.request_approval(desktop_device_id, now)?;
        let view = operation.view();
        current.idempotency.insert(
            scoped_key,
            super::IdempotencyRecord {
                rail: super::OperationRail::HvmFastPay,
                request_commitment,
                operation_id: view.operation_id.clone(),
            },
        );
        current
            .hvm_payment_operations
            .insert(view.operation_id.as_str().to_owned(), operation);
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::ApprovalRequested,
            Some(view.operation_id.as_str().as_bytes()),
            Some(authorization.agent_id().as_str().as_bytes()),
            now,
        )?;
        Ok(view)
    }

    pub(super) fn hvm_payment_operation_for_verified(
        &mut self,
        authorization: &super::AgentAuthorization,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let state = self.hvm_state_for_permission(
            authorization,
            AgentPermission::ReadOwnOperationStatus,
            now,
        )?;
        state
            .hvm_payment_operations
            .get(operation_id.as_str())
            .filter(|operation| operation.agent_id() == authorization.agent_id())
            .map(AgentHvmPaymentOperation::view)
            .ok_or(AgentWalletError::OperationNotFound)
    }

    pub(super) fn list_hvm_operations_for_agent(
        &mut self,
        authorization: &super::AgentAuthorization,
        now: u64,
    ) -> AgentWalletResult<Vec<crate::types::OperationId>> {
        let state =
            self.hvm_state_for_permission(authorization, AgentPermission::ListOwnOperations, now)?;
        Ok(state
            .hvm_payment_operations
            .values()
            .filter(|operation| operation.agent_id() == authorization.agent_id())
            .map(|operation| operation.operation_id().clone())
            .collect())
    }

    pub(super) fn cancel_hvm_own_unsigned(
        &mut self,
        authorization: &super::AgentAuthorization,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let wallet_id = super::payment::wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = self.load_verified_state(&wallet_id, &state_master, &journal_key)?;
        super::validate_authorization(&state, authorization)?;
        if authorization.capability() != AgentPermission::CancelOwnUnsignedOperation {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        let operation = state
            .hvm_payment_operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if operation.agent_id() != authorization.agent_id() {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        if operation.status() == crate::hvm_payment_operation::AgentHvmPaymentStatus::Cancelled {
            return Ok(operation.view());
        }
        if !operation.cancel_pre_signing() {
            return Err(AgentWalletError::InvalidOperationState);
        }
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::PaymentFailed,
            Some(operation_id.as_str().as_bytes()),
            Some(authorization.agent_id().as_str().as_bytes()),
            now,
        )?;
        state
            .hvm_payment_operations
            .get(operation_id.as_str())
            .map(AgentHvmPaymentOperation::view)
            .ok_or(AgentWalletError::RecoveryRequired)
    }

    fn hvm_state_for_permission(
        &mut self,
        authorization: &super::AgentAuthorization,
        permission: AgentPermission,
        now: u64,
    ) -> AgentWalletResult<super::AgentWalletState> {
        let wallet_id = super::payment::wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        super::validate_authorization(&state, authorization)?;
        if authorization.capability() != permission {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        Ok(state)
    }

    pub fn list_hvm_operations_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<AgentHvmPaymentOperationView>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        Ok(state
            .hvm_payment_operations
            .values()
            .map(AgentHvmPaymentOperation::view)
            .collect())
    }

    /// Owner-triggered execution of one exact mobile-approved HVM payment.
    ///
    /// The signature is durably stored before submission, Submitted is durably
    /// stored before the Hub call, and every unknown outcome retains the
    /// reservation in RecoveryRequired. There is no L1 fallback and no re-sign.
    pub async fn execute_approved_hvm_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        self.verified_hvm_operation_readiness(
            wallet_id,
            operation_id,
            now,
            HvmReadinessPhase::Approved,
        )
        .await?;
        self.persist_hvm_transition(
            wallet_id,
            operation_id,
            now,
            HvmDurableTransition::SigningPrepared,
        )?;

        let verified = match self
            .verified_hvm_operation_readiness(
                wallet_id,
                operation_id,
                now,
                HvmReadinessPhase::SigningPrepared,
            )
            .await
        {
            Ok(verified) => verified,
            Err(error) => {
                let _ = self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::RecoveryRequired,
                );
                return Err(error);
            }
        };
        verified.permit.checkpoint(false)?;
        let guard = verified.permit.irreversible_checkpoint(false)?;
        let signed_view = if verified.binding.is_registry_v2() {
            let (authority, previous, unsigned) = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                let operation = state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?;
                (
                    operation.registry_signer_binding()?,
                    operation.previous_registry_bill()?.clone(),
                    operation.unsigned_registry_request()?.clone(),
                )
            };
            let signed = {
                let session = self.session(wallet_id)?;
                session.signer.sign_exact_hvm_registry_payment(
                    &authority,
                    &previous,
                    unsigned,
                    &verified.permit,
                    now,
                )?
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::SignedRegistry(signed),
            )
        } else {
            let (authority, previous, unsigned) = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                let operation = state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?;
                (
                    operation.signer_binding()?,
                    operation.previous_bill()?.clone(),
                    operation.unsigned_request()?.clone(),
                )
            };
            let signed = {
                let session = self.session(wallet_id)?;
                session.signer.sign_exact_hvm_payment(
                    &authority,
                    &previous,
                    unsigned,
                    &verified.permit,
                    now,
                )?
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Signed(signed),
            )
        };
        drop(guard);
        let signed_view = match signed_view {
            Ok(view) => view,
            Err(error) => {
                let _ = self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::RecoveryRequired,
                );
                return Err(error);
            }
        };
        if let Err(error) = verified.permit.checkpoint(false) {
            let _ = self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::RecoveryRequired,
            );
            return Err(error);
        }
        debug_assert_eq!(
            signed_view.status,
            crate::hvm_payment_operation::AgentHvmPaymentStatus::Signed
        );

        let verified = match self
            .verified_hvm_operation_readiness(
                wallet_id,
                operation_id,
                now,
                HvmReadinessPhase::PostSigned,
            )
            .await
        {
            Ok(verified) => verified,
            Err(error) => {
                let _ = self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::RecoveryRequired,
                );
                return Err(error);
            }
        };
        let is_registry_v2 = verified.binding.is_registry_v2();
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url().to_owned(),
            "testnet",
            false,
        );
        let committed = if is_registry_v2 {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_registry_request()?
                    .clone()
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Submitted,
            )?;
            verified.permit.checkpoint(false)?;
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            let fully_signed = hub
                .cosign_hvm_registry_payment(
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
                .map_err(classify_anchor_error);
            let fully_signed = match fully_signed {
                Ok(bill) => bill,
                Err(error) => {
                    let _ = self.persist_hvm_transition(
                        wallet_id,
                        operation_id,
                        now,
                        HvmDurableTransition::RecoveryRequired,
                    );
                    return Err(error);
                }
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::CommittedRegistry(fully_signed),
            )?
        } else {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_request()?
                    .clone()
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Submitted,
            )?;
            verified.permit.checkpoint(false)?;
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            let fully_signed = hub
                .cosign_hvm_payment(
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
                .map_err(classify_anchor_error);
            let fully_signed = match fully_signed {
                Ok(bill) => bill,
                Err(error) => {
                    let _ = self.persist_hvm_transition(
                        wallet_id,
                        operation_id,
                        now,
                        HvmDurableTransition::RecoveryRequired,
                    );
                    return Err(error);
                }
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Committed(fully_signed),
            )?
        };
        verified.permit.checkpoint(false)?;
        Ok(committed)
    }

    /// Read-only reconciliation against the exact bound Hub. It never signs,
    /// submits, changes ids or falls back to L1.
    ///
    /// It is, however, the *second* way a bill becomes this wallet's committed
    /// head, and that made it the hole that defeated the whole rollback-anchor
    /// rule. A Hub that co-signs, persists, and then answers the payment POST
    /// with a 503 or a truncated body drives the wallet here — the co-sign
    /// error becomes `RecoveryRequired`, `RecoveryRequired` is a shipped
    /// "Reconcile" button, and this function used to commit
    /// `status.fully_signed_bill` having opened no anchor store and read none
    /// of the receipts the Hub publishes right beside it. Every refusal the
    /// design is proud of — dropped witness, counter gone backwards, serial at
    /// or below the accepted head, a decision already parked, a channel
    /// already closing — was one dropped TCP connection away from being
    /// skipped.
    ///
    /// So the ratchet runs on this path too, inside
    /// [`L2HubClient::reconcile_hvm_registry_payment`] and its V1 twin, which
    /// return the status only after it has passed.
    pub async fn reconcile_hvm_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let verified = self
            .verified_hvm_operation_readiness(
                wallet_id,
                operation_id,
                now,
                HvmReadinessPhase::PostSigned,
            )
            .await?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url().to_owned(),
            "testnet",
            false,
        );
        if verified.binding.is_registry_v2() {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_registry_request()?
                    .clone()
            };
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            let status = hub
                .reconcile_hvm_registry_payment(
                    &verified.view.hub_operation_id,
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
                .map_err(classify_anchor_error)?;
            drop(anchor_safety);
            verified.permit.checkpoint(false)?;
            if status.request != signed_request
                || status.request_commitment
                    != signed_request
                        .commitment()
                        .map_err(|_| AgentWalletError::RecoveryRequired)?
            {
                return Err(AgentWalletError::ApprovalCommitmentMismatch);
            }
            match status.status.as_str() {
                "fully_signed" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::CommittedRegistry(
                        status
                            .fully_signed_bill
                            .ok_or(AgentWalletError::RecoveryRequired)?,
                    ),
                ),
                "user_proposal_persisted" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::ExactRetryReady,
                ),
                "hub_signature_may_exist" | "recovery_required" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::RecoveryRequired,
                ),
                _ => Err(AgentWalletError::RecoveryRequired),
            }
        } else {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_request()?
                    .clone()
            };
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            let status = hub
                .reconcile_hvm_payment(
                    &verified.view.hub_operation_id,
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
                .map_err(classify_anchor_error)?;
            drop(anchor_safety);
            verified.permit.checkpoint(false)?;
            if status.request != signed_request
                || status.request_commitment
                    != signed_request
                        .commitment()
                        .map_err(|_| AgentWalletError::RecoveryRequired)?
            {
                return Err(AgentWalletError::ApprovalCommitmentMismatch);
            }
            match status.status.as_str() {
                "fully_signed" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::Committed(
                        status
                            .fully_signed_bill
                            .ok_or(AgentWalletError::RecoveryRequired)?,
                    ),
                ),
                "user_proposal_persisted" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::ExactRetryReady,
                ),
                "hub_signature_may_exist" | "recovery_required" => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::RecoveryRequired,
                ),
                _ => Err(AgentWalletError::RecoveryRequired),
            }
        }
    }

    /// Recover every durable HVM client boundary without guessing. A
    /// SigningPrepared record can be abandoned because no Hub call is allowed
    /// before Signed is durable. A Signed record can become exact-retry-ready
    /// because no Hub call is allowed before Submitted is durable. Submitted
    /// and later states require exact Hub reconciliation.
    pub async fn recover_hvm_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let status = {
            let session = self.session(wallet_id)?;
            let state =
                self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
            state
                .hvm_payment_operations
                .get(operation_id.as_str())
                .ok_or(AgentWalletError::OperationNotFound)?
                .status()
        };
        match status {
            crate::hvm_payment_operation::AgentHvmPaymentStatus::SigningPrepared => self
                .persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::UnsignedSigningAbandoned,
                ),
            crate::hvm_payment_operation::AgentHvmPaymentStatus::Signed => {
                self.verified_hvm_operation_readiness(
                    wallet_id,
                    operation_id,
                    now,
                    HvmReadinessPhase::PostSigned,
                )
                .await?;
                self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::ExactRetryReady,
                )
            }
            crate::hvm_payment_operation::AgentHvmPaymentStatus::ExactRetryReady => {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .map(AgentHvmPaymentOperation::view)
                    .ok_or(AgentWalletError::OperationNotFound)
            }
            crate::hvm_payment_operation::AgentHvmPaymentStatus::Submitted
            | crate::hvm_payment_operation::AgentHvmPaymentStatus::RecoveryRequired => {
                self.reconcile_hvm_payment(wallet_id, operation_id, now)
                    .await
            }
            _ => Err(AgentWalletError::InvalidOperationState),
        }
    }

    /// Owner-triggered exact retry after reconciliation proved that the Hub
    /// holds only the same durable user proposal. The same signature and ids
    /// are reused; this method never enters the signer.
    pub async fn retry_reconciled_hvm_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let verified = self
            .verified_hvm_operation_readiness(
                wallet_id,
                operation_id,
                now,
                HvmReadinessPhase::PostSigned,
            )
            .await?;
        if verified.view.status
            != crate::hvm_payment_operation::AgentHvmPaymentStatus::ExactRetryReady
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url().to_owned(),
            "testnet",
            false,
        );
        if verified.binding.is_registry_v2() {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_registry_request()?
                    .clone()
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Submitted,
            )?;
            verified.permit.checkpoint(false)?;
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            match hub
                .cosign_hvm_registry_payment(
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
            {
                Ok(fully_signed) => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::CommittedRegistry(fully_signed),
                ),
                Err(error) => {
                    let _ = self.persist_hvm_transition(
                        wallet_id,
                        operation_id,
                        now,
                        HvmDurableTransition::RecoveryRequired,
                    );
                    Err(classify_anchor_error(error))
                }
            }
        } else {
            let signed_request = {
                let session = self.session(wallet_id)?;
                let state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
                state
                    .hvm_payment_operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .signed_request()?
                    .clone()
            };
            self.persist_hvm_transition(
                wallet_id,
                operation_id,
                now,
                HvmDurableTransition::Submitted,
            )?;
            verified.permit.checkpoint(false)?;
            let floor =
                self.anchor_serial_floor(wallet_id, verified.binding.binding_commitment())?;
            let mut anchor_safety = self.open_hvm_anchor_safety(wallet_id, &verified.binding)?;
            match hub
                .cosign_hvm_payment(
                    &signed_request,
                    &mut anchor_safety,
                    verified.binding.hub_address(),
                    floor,
                )
                .await
            {
                Ok(fully_signed) => self.persist_hvm_transition(
                    wallet_id,
                    operation_id,
                    now,
                    HvmDurableTransition::Committed(fully_signed),
                ),
                Err(error) => {
                    let _ = self.persist_hvm_transition(
                        wallet_id,
                        operation_id,
                        now,
                        HvmDurableTransition::RecoveryRequired,
                    );
                    Err(classify_anchor_error(error))
                }
            }
        }
    }

    /// The highest serial this wallet can *prove* the channel reached, read
    /// from Agent Wallet's own encrypted state rather than from the L2 anchor
    /// store the ratchet lives in.
    ///
    /// Two stores, two keys, two journals, and only one of them is the one an
    /// attacker deletes to reset the ratchet. Handing this number to
    /// `accept_anchored_bill` is what turns "the counterparty remembers" into
    /// something that survives the counterparty's own disk being rewound: a
    /// missing or behind anchor memory is refused rather than re-baselined.
    fn anchor_serial_floor(
        &self,
        wallet_id: &AgentWalletId,
        binding_commitment: &str,
    ) -> AgentWalletResult<u64> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(committed_channel_serial_floor(&state, binding_commitment))
    }

    /// The parked rollback-anchor decision for the channel this operation is
    /// on, if a human still owes an answer.
    ///
    /// The evidence is durable, so a user interface that crashed mid-prompt
    /// comes back to the same question rather than losing it.
    pub fn pending_hvm_anchor_decision(
        &self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
    ) -> AgentWalletResult<Option<hacash_wallet_core::l2_safety::AnchorWitnessChangeV1>> {
        let (binding, safety) = self.anchor_store_for_operation(wallet_id, operation_id)?;
        Ok(safety.pending_anchor_decision(&binding))
    }

    /// Ask the Hub for its rollback-anchor continuity declaration on this
    /// channel and adjudicate it here, in this wallet's own store.
    ///
    /// # When this is the only thing that works
    ///
    /// A Hub has exactly one witness. Replace that witness's durable store and
    /// the Hub's pin no longer matches it: its startup probe can never agree
    /// again and it refuses to co-sign anything, permanently. Every ordinary
    /// path into the ratchet - [`Self::submit_hvm_payment`] and the
    /// reconciliation twins - runs `accept_anchored_bill` on a *new* bill, and
    /// there is no new bill and never will be, so none of them can ever be
    /// reached again on that channel. Without this call the owner's evidence is
    /// a channel that stopped working and a Hub log they cannot see.
    ///
    /// The declaration is the channel's existing head - same serial, same bill
    /// commitment - re-anchored under the witness answering now. It runs
    /// through the same [`hacash_wallet_core::l2_safety::ClientL2Safety::
    /// accept_anchored_bill`] as every payment, with the same independent
    /// serial floor from this wallet's own encrypted state, so the answer is
    /// produced by the rule rather than beside it.
    ///
    /// Returns the parked decision when one is now owed - which, for a genuine
    /// single-witness swap, is always, and always as the strong zero-overlap
    /// prompt. `AgentWalletError::AnchorWitnessDecisionRequired` and the parked
    /// change are the same event seen from two sides; the change is returned
    /// rather than the error because the caller needs the evidence to show.
    /// A hard refusal - a declaration below this wallet's accepted head, or one
    /// whose receipts do not verify - is an `Err` and never a prompt.
    ///
    /// Answered with [`Self::resolve_hvm_anchor_decision`].
    pub async fn refresh_hvm_anchor_continuity(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
    ) -> AgentWalletResult<Option<hacash_wallet_core::l2_safety::AnchorWitnessChangeV1>> {
        let binding = self.anchor_binding_for_operation(wallet_id, operation_id)?;
        let binding_commitment = binding.binding_commitment().to_owned();
        let hub =
            L2HubClient::new_for_wallet_policy(binding.hub_url().to_owned(), "testnet", false);
        let floor = self.anchor_serial_floor(wallet_id, &binding_commitment)?;
        let mut safety = self.open_hvm_anchor_safety(wallet_id, &binding)?;
        let outcome = hub
            .adjudicate_anchor_continuity(
                &binding_commitment,
                &mut safety,
                binding.hub_address(),
                floor,
            )
            .await;
        match outcome {
            // The head re-affirmed and still fully covered. Nothing was
            // dropped, so there is nothing to decide - and nothing was written.
            Ok(()) => Ok(safety.pending_anchor_decision(&binding_commitment)),
            Err(error) => match classify_anchor_error(error) {
                // The parked change is durable in this wallet's store by the
                // time the error comes back, so it is read out rather than
                // rebuilt. A user interface that dies here comes back to the
                // same question.
                AgentWalletError::AnchorWitnessDecisionRequired => {
                    Ok(safety.pending_anchor_decision(&binding_commitment))
                }
                classified => Err(classified),
            },
        }
    }

    /// Record the owner's answer to a parked rollback-anchor decision.
    ///
    /// There are exactly two answers and no third. Accepting adopts the new
    /// witness set as the baseline and retires — never erases — what was
    /// dropped. Closing latches the channel on its last accepted bill, whose
    /// receipt set is intact, and refuses to advance it further; the close
    /// itself runs against that bill and needs nothing from the Hub's anchor.
    pub fn resolve_hvm_anchor_decision(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        decision: hacash_wallet_core::l2_safety::AnchorWitnessDecision,
    ) -> AgentWalletResult<()> {
        let (binding, mut safety) = self.anchor_store_for_operation(wallet_id, operation_id)?;
        safety
            .resolve_anchor_witness_change(&binding, decision)
            .map_err(classify_anchor_error)
    }

    fn anchor_store_for_operation(
        &self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
    ) -> AgentWalletResult<(String, hacash_wallet_core::l2_safety::ClientL2Safety)> {
        let binding = self.anchor_binding_for_operation(wallet_id, operation_id)?;
        let binding_commitment = binding.binding_commitment().to_owned();
        let safety = self.open_hvm_anchor_safety(wallet_id, &binding)?;
        Ok((binding_commitment, safety))
    }

    /// The verified binding this operation is on, re-derived from durable state
    /// and cross-checked against the operation's own recorded commitment.
    ///
    /// Split out of [`Self::anchor_store_for_operation`] because the continuity
    /// path needs the Hub URL and address as well as the store, and re-deriving
    /// the binding a second way would be a second place for the two to drift.
    fn anchor_binding_for_operation(
        &self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
    ) -> AgentWalletResult<VerifiedAgentHvmBinding> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .hvm_payment_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let binding_commitment = operation.binding_commitment().to_owned();
        let binding = match (
            state.hvm_channel_binding.clone(),
            state.hvm_registry_binding.clone(),
        ) {
            (Some(binding), None) => VerifiedAgentHvmBinding::ChannelV1(binding),
            (None, Some(binding)) => VerifiedAgentHvmBinding::RegistryV2(binding),
            _ => return Err(AgentWalletError::SigningBlocked),
        };
        if binding.binding_commitment() != binding_commitment {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(binding)
    }

    /// Open the per-channel authenticated store that holds this channel's
    /// rollback-anchor witness memory.
    ///
    /// It is keyed by `binding_commitment` rather than by a channel id: the
    /// binding carries the reuse version, so a new incarnation is a genuinely
    /// new channel that legitimately starts a fresh ratchet.
    ///
    /// The anchored HVM paths did not open this store before. They had to
    /// start: the memory has to live somewhere lock-guarded, journalled and
    /// inside a state commitment, and this is that store.
    fn open_hvm_anchor_safety(
        &self,
        wallet_id: &AgentWalletId,
        binding: &VerifiedAgentHvmBinding,
    ) -> AgentWalletResult<hacash_wallet_core::l2_safety::ClientL2Safety> {
        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let wallet_scope = session.signer.wallet_scope().as_str().to_owned();
        hacash_wallet_core::l2_safety::ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            &wallet_scope,
            "testnet",
            binding.hub_address(),
            binding.binding_commitment(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)
    }

    async fn verified_hvm_operation_readiness(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
        phase: HvmReadinessPhase,
    ) -> AgentWalletResult<VerifiedHvmReadiness> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if state.network_mode != "testnet" {
            return Err(AgentWalletError::SigningBlocked);
        }
        let operation = state
            .hvm_payment_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let expected = if operation.is_registry_v2() {
            let binding = state
                .hvm_registry_binding
                .clone()
                .ok_or(AgentWalletError::SigningBlocked)?;
            if state.hvm_channel_binding.is_some() || !operation.matches_registry_binding(&binding)
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            ExpectedAgentHvmEvidence::RegistryV2 {
                binding,
                prepared_snapshot: operation.prepared_registry_snapshot()?.clone(),
                previous_bill: operation.previous_registry_bill()?.clone(),
                signed_request: if matches!(phase, HvmReadinessPhase::PostSigned) {
                    Some(operation.signed_registry_request()?.clone())
                } else {
                    None
                },
            }
        } else {
            let binding = state
                .hvm_channel_binding
                .clone()
                .ok_or(AgentWalletError::SigningBlocked)?;
            if state.hvm_registry_binding.is_some() || !operation.matches_channel_binding(&binding)
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            ExpectedAgentHvmEvidence::ChannelV1 {
                binding,
                prepared_snapshot: operation.prepared_snapshot()?.clone(),
                previous_bill: operation.previous_bill()?.clone(),
                signed_request: if matches!(phase, HvmReadinessPhase::PostSigned) {
                    Some(operation.signed_request()?.clone())
                } else {
                    None
                },
            }
        };
        let agent = state
            .agents
            .get(operation.agent_id().as_str())
            .cloned()
            .ok_or(AgentWalletError::AgentNotPaired)?;
        require_active_hvm_agent(&agent)?;
        let view = match phase {
            HvmReadinessPhase::Approved => operation.approved_signing_view(
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
                &state.network_mode,
                now,
            )?,
            HvmReadinessPhase::SigningPrepared => operation.signing_prepared_view(
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
                &state.network_mode,
                now,
            )?,
            HvmReadinessPhase::PostSigned => operation.signed_submission_view(
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
                &state.network_mode,
            )?,
        };
        super::payment::revalidate_approved_payment_policy(
            &state,
            &agent,
            &view.recipient,
            view.amount_units,
            now,
        )?;
        let node_url = state.node_url.clone();
        let block_one_fingerprint = state.block_one_fingerprint.clone();
        let payments_suspended = state.payments_suspended;
        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(payments_suspended)?;
        permit.checkpoint(payments_suspended)?;
        drop(state);

        let verified_binding = match &expected {
            ExpectedAgentHvmEvidence::ChannelV1 {
                binding,
                prepared_snapshot,
                previous_bill,
                signed_request,
            } => {
                let (status, snapshot) = verified_hvm_evidence(
                    binding,
                    &node_url,
                    &block_one_fingerprint,
                    &permit,
                    payments_suspended,
                )
                .await?;
                let ledger_matches = if status.latest_fully_signed_bill == *previous_bill {
                    true
                } else if let Some(signed_request) = signed_request.as_ref() {
                    let mut hub_unsigned = status.latest_fully_signed_bill;
                    hub_unsigned.right_signature_hex.clear();
                    hub_unsigned == signed_request.proposed_bill
                } else {
                    false
                };
                if !ledger_matches || !same_hvm_value_state(prepared_snapshot, &snapshot) {
                    return Err(AgentWalletError::RecoveryRequired);
                }
                VerifiedAgentHvmBinding::ChannelV1(binding.clone())
            }
            ExpectedAgentHvmEvidence::RegistryV2 {
                binding,
                prepared_snapshot,
                previous_bill,
                signed_request,
            } => {
                let (status, snapshot) = verified_hvm_registry_evidence(
                    binding,
                    &node_url,
                    &block_one_fingerprint,
                    &permit,
                    payments_suspended,
                )
                .await?;
                let ledger_matches = if status.latest_fully_signed_bill == *previous_bill {
                    true
                } else if let Some(signed_request) = signed_request.as_ref() {
                    let mut hub_unsigned = status.latest_fully_signed_bill;
                    hub_unsigned.hub_signature_hex.clear();
                    hub_unsigned == signed_request.proposed_bill
                } else {
                    false
                };
                if !ledger_matches || !same_hvm_registry_value_state(prepared_snapshot, &snapshot) {
                    return Err(AgentWalletError::RecoveryRequired);
                }
                VerifiedAgentHvmBinding::RegistryV2(binding.clone())
            }
        };
        permit.checkpoint(payments_suspended)?;

        let current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let current_agent = current
            .agents
            .get(agent.agent_id.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?;
        let binding_unchanged = match &verified_binding {
            VerifiedAgentHvmBinding::ChannelV1(binding) => {
                current.hvm_channel_binding.as_ref() == Some(binding)
                    && current.hvm_registry_binding.is_none()
            }
            VerifiedAgentHvmBinding::RegistryV2(binding) => {
                current.hvm_registry_binding.as_ref() == Some(binding)
                    && current.hvm_channel_binding.is_none()
            }
        };
        if !binding_unchanged || current_agent != &agent {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let current_operation = current
            .hvm_payment_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let current_view = match phase {
            HvmReadinessPhase::Approved => current_operation.approved_signing_view(
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
                &current.network_mode,
                now,
            )?,
            HvmReadinessPhase::SigningPrepared => current_operation.signing_prepared_view(
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
                &current.network_mode,
                now,
            )?,
            HvmReadinessPhase::PostSigned => current_operation.signed_submission_view(
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
                &current.network_mode,
            )?,
        };
        super::payment::revalidate_approved_payment_policy(
            &current,
            current_agent,
            &current_view.recipient,
            current_view.amount_units,
            now,
        )?;
        if current_view != view {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        permit.checkpoint(current.payments_suspended)?;
        Ok(VerifiedHvmReadiness {
            view: current_view,
            binding: verified_binding,
            permit,
        })
    }

    fn persist_hvm_transition(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &crate::types::OperationId,
        now: u64,
        transition: HvmDurableTransition,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        let session = self.session(wallet_id)?;
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let operation = state
            .hvm_payment_operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        match &transition {
            HvmDurableTransition::SigningPrepared => operation.mark_signing_prepared(now)?,
            HvmDurableTransition::Signed(request) => {
                operation.record_signed_request(request.clone(), now)?
            }
            HvmDurableTransition::SignedRegistry(request) => {
                operation.record_signed_registry_request(request.clone(), now)?
            }
            HvmDurableTransition::Submitted => operation.mark_submitted()?,
            HvmDurableTransition::Committed(bill) => {
                operation.record_committed(bill.clone(), now)?
            }
            HvmDurableTransition::CommittedRegistry(bill) => {
                operation.record_committed_registry(bill.clone(), now)?
            }
            HvmDurableTransition::RecoveryRequired => operation.mark_recovery_required()?,
            HvmDurableTransition::ExactRetryReady => operation.mark_exact_retry_ready()?,
            HvmDurableTransition::UnsignedSigningAbandoned => operation.mark_signing_abandoned()?,
        }
        let view = operation.view();
        // Advance the wallet's own exit head inside the same journalled
        // transition that commits the bill, and before the event is written.
        // There must be no window in which a bill is durably committed while
        // the user's only route out of the channel still points at an older
        // one, and no way for the head to move without the journal recording
        // that it did.
        if let HvmDurableTransition::CommittedRegistry(bill) = &transition {
            advance_registry_exit_head(&mut state, bill, now)?;
        }
        state.updated_at = now;
        let event = match transition {
            HvmDurableTransition::SigningPrepared => {
                crate::journal::AgentJournalEventKind::HvmSigningPrepared
            }
            HvmDurableTransition::Signed(_) | HvmDurableTransition::SignedRegistry(_) => {
                crate::journal::AgentJournalEventKind::HvmSigned
            }
            HvmDurableTransition::Submitted => crate::journal::AgentJournalEventKind::HvmSubmitted,
            HvmDurableTransition::Committed(_) | HvmDurableTransition::CommittedRegistry(_) => {
                crate::journal::AgentJournalEventKind::HvmCommitted
            }
            HvmDurableTransition::RecoveryRequired => {
                crate::journal::AgentJournalEventKind::HvmRecoveryRequired
            }
            HvmDurableTransition::ExactRetryReady => {
                crate::journal::AgentJournalEventKind::HvmExactRetryReady
            }
            HvmDurableTransition::UnsignedSigningAbandoned => {
                crate::journal::AgentJournalEventKind::PaymentFailed
            }
        };
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            event,
            Some(operation_id.as_str().as_bytes()),
            Some(view.agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(view)
    }

    /// Adopt one already deployed and operational Agent-only HVM channel.
    ///
    /// This owner operation performs no signing or payment. Mainnet remains
    /// deliberately unavailable until the production HVM deployment gate is
    /// separately enabled and proven.
    pub async fn verify_and_bind_hvm_channel(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        binding_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentHvmChannelBinding> {
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
            || original.hvm_registry_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let hub_url = validate_service_url(hub_url, "Agent HVM Fast Pay hub")
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
            .hvm_channel_status(binding_commitment)
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
        if status.recovery_bundle.binding.left_address != original.address
            || status.recovery_bundle.binding.right_hub_address != hub_address
            || status.recovery_bundle.binding.chain_id != network_binding.chain_id
            || status.recovery_bundle.binding.network_instance_id
                != network_binding.network_instance_id
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hvm_node = l2_fast_pay_hub::node::NodeClient::new(original.node_url.clone())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let runtime = hvm_node
            .verify_hvm_runtime_channel(
                &status.recovery_bundle,
                status.minimum_required_live_blocks,
                status.minimum_required_recover_blocks.max(1),
            )
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if runtime.storage.serial.value > status.latest_fully_signed_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let candidate = AgentHvmChannelBinding::from_verified_status(
            wallet_id.clone(),
            &original.address,
            &original.network_mode,
            network_binding,
            hub_url,
            hub_address,
            status,
            now,
        )?;

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
            || current.hvm_registry_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = current.hvm_channel_binding.as_ref() {
            return if existing == &candidate {
                Ok(existing.clone())
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        current.hvm_channel_binding = Some(candidate.clone());
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

#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn verified_hvm_evidence(
    binding: &AgentHvmChannelBinding,
    node_url: &str,
    block_one_fingerprint: &str,
    permit: &AgentSafetyPermit,
    payments_suspended: bool,
) -> AgentWalletResult<(
    HvmChannelStatusV1,
    l2_fast_pay_hub::node::HvmChannelLiveSnapshot,
)> {
    let hub = L2HubClient::new_for_wallet_policy(binding.hub_url.clone(), "testnet", false);
    let health = hub
        .health()
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    permit.checkpoint(payments_suspended)?;
    if !health.ok
        || health.version < 7
        || !health.settlement_ready
        || !health.cross_channel_ready
        || !hub_fee_is_zero(&health)
        || health.hub_address.as_deref() != Some(binding.hub_address.as_str())
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    let status = hub
        .hvm_channel_status(&binding.binding_commitment)
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    permit.checkpoint(payments_suspended)?;
    if !binding.matches_status(&status) {
        return Err(AgentWalletError::RecoveryRequired);
    }
    let verified_node =
        crate::node_binding::verified_agent_node(node_url, "testnet", block_one_fingerprint)
            .await?;
    permit.checkpoint(payments_suspended)?;
    let node_identity = verified_node.snapshot();
    if node_identity.network_kind != binding.network_binding.network_kind
        || node_identity.chain_id != binding.network_binding.chain_id
        || node_identity.mainnet != binding.network_binding.mainnet
        || node_identity.block_one_fingerprint != binding.network_binding.block_1_hash
        || node_identity.node_profile_id != binding.network_binding.node_profile_id
        || node_identity.network_instance_id != binding.network_binding.network_instance_id
        || node_identity.transaction_format_version
            != binding.network_binding.transaction_format_version
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    let node = l2_fast_pay_hub::node::NodeClient::new(node_url.to_owned())
        .map_err(|_| AgentWalletError::NodeRejected)?;
    let snapshot = node
        .verify_hvm_runtime_channel(
            &binding.recovery_bundle,
            binding.minimum_required_live_blocks,
            binding.operational_recover_blocks(),
        )
        .await
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
    permit.checkpoint(payments_suspended)?;
    if snapshot.storage.serial.value > status.latest_fully_signed_bill.serial {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok((status, snapshot))
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn verified_hvm_registry_evidence(
    binding: &super::AgentHvmRegistryBinding,
    node_url: &str,
    block_one_fingerprint: &str,
    permit: &AgentSafetyPermit,
    payments_suspended: bool,
) -> AgentWalletResult<(
    l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryChannelStatusV2,
    l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
)> {
    let hub = L2HubClient::new_for_wallet_policy(binding.hub_url().to_owned(), "testnet", false);
    let health = hub
        .health()
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    permit.checkpoint(payments_suspended)?;
    if !health.ok
        || health.version < 7
        || !health.settlement_ready
        || !health.cross_channel_ready
        || !hub_fee_is_zero(&health)
        || health.hub_address.as_deref() != Some(binding.hub_address())
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    let status = hub
        .hvm_registry_channel_status(binding.binding_commitment())
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    permit.checkpoint(payments_suspended)?;
    if !binding.matches_status(&status) {
        return Err(AgentWalletError::RecoveryRequired);
    }
    let verified_node =
        crate::node_binding::verified_agent_node(node_url, "testnet", block_one_fingerprint)
            .await?;
    permit.checkpoint(payments_suspended)?;
    let node_identity = verified_node.snapshot();
    let expected = binding.network_binding();
    if node_identity.network_kind != expected.network_kind
        || node_identity.chain_id != expected.chain_id
        || node_identity.mainnet != expected.mainnet
        || node_identity.block_one_fingerprint != expected.block_1_hash
        || node_identity.node_profile_id != expected.node_profile_id
        || node_identity.network_instance_id != expected.network_instance_id
        || node_identity.transaction_format_version != expected.transaction_format_version
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    let node = l2_fast_pay_hub::node::NodeClient::new(node_url.to_owned())
        .map_err(|_| AgentWalletError::NodeRejected)?;
    let snapshot = node
        .verify_hvm_registry_open_bundle(
            binding.recovery_bundle(),
            binding.minimum_required_live_blocks(),
            binding.operational_recover_blocks(),
        )
        .await
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
    permit.checkpoint(payments_suspended)?;
    if snapshot.channel.serial.value > status.latest_fully_signed_bill.serial {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok((status, snapshot))
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
fn require_active_hvm_agent(agent: &AgentRecord) -> AgentWalletResult<()> {
    if agent.status != AgentStatus::Active
        || agent.authorization_epoch == 0
        || !agent
            .policy
            .permissions
            .contains(&AgentPermission::CreatePaymentIntent)
    {
        return Err(AgentWalletError::AgentPermissionDenied);
    }
    Ok(())
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
fn same_hvm_value_state(
    approved: &l2_fast_pay_hub::node::HvmChannelLiveSnapshot,
    current: &l2_fast_pay_hub::node::HvmChannelLiveSnapshot,
) -> bool {
    approved.chain_id == current.chain_id
        && approved.contract_address == current.contract_address
        && approved.deployment_tx_hash == current.deployment_tx_hash
        && approved.deployment_height == current.deployment_height
        && approved.bytecode_sha3 == current.bytecode_sha3
        && approved.storage.status.value == current.storage.status.value
        && approved.storage.network.value == current.storage.network.value
        && approved.storage.channel_id.value == current.storage.channel_id.value
        && approved.storage.reuse.value == current.storage.reuse.value
        && approved.storage.left.value == current.storage.left.value
        && approved.storage.right.value == current.storage.right.value
        && approved.storage.left_deposit.value == current.storage.left_deposit.value
        && approved.storage.right_deposit.value == current.storage.right_deposit.value
        && approved.storage.left_paid.value == current.storage.left_paid.value
        && approved.storage.right_paid.value == current.storage.right_paid.value
        && approved.storage.total.value == current.storage.total.value
        && approved.storage.serial.value == current.storage.serial.value
        && approved.storage.left_balance.value == current.storage.left_balance.value
        && approved.storage.right_balance.value == current.storage.right_balance.value
        && approved.storage.challenge_blocks.value == current.storage.challenge_blocks.value
        && approved.storage.deadline.value == current.storage.deadline.value
        && approved.storage.left_claimed.value == current.storage.left_claimed.value
        && approved.storage.right_claimed.value == current.storage.right_claimed.value
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
fn same_hvm_registry_value_state(
    approved: &l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
    current: &l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
) -> bool {
    approved.chain_id == current.chain_id
        && approved.network_instance_id == current.network_instance_id
        && approved.contract_address == current.contract_address
        && approved.deployment_tx_hash == current.deployment_tx_hash
        && approved.deployment_height == current.deployment_height
        && approved.bytecode_sha3 == current.bytecode_sha3
        && approved.hub_address == current.hub_address
        && approved.left_address == current.left_address
        && approved.registry.g_network.value == current.registry.g_network.value
        && approved.registry.g_hub.value == current.registry.g_hub.value
        && approved.registry.g_locked.value == current.registry.g_locked.value
        && approved.registry.g_left_claimable.value == current.registry.g_left_claimable.value
        && approved.registry.g_hub_claimable.value == current.registry.g_hub_claimable.value
        && approved.registry.g_open_count.value == current.registry.g_open_count.value
        && approved.channel.status.value == current.channel.status.value
        && approved.channel.channel_id.value == current.channel.channel_id.value
        && approved.channel.reuse.value == current.channel.reuse.value
        && approved.channel.deposit.value == current.channel.deposit.value
        && approved.channel.paid.value == current.channel.paid.value
        && approved.channel.total.value == current.channel.total.value
        && approved.channel.serial.value == current.channel.serial.value
        && approved.channel.left_balance.value == current.channel.left_balance.value
        && approved.channel.hub_balance.value == current.channel.hub_balance.value
        && approved.channel.challenge_blocks.value == current.channel.challenge_blocks.value
        && approved.channel.deadline.value == current.channel.deadline.value
        && approved.channel.left_claimed.value == current.channel.left_claimed.value
}
