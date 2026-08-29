//! Live, non-signing re-verification for one approved Agent Fast Pay operation.
//!
//! A successful result is evidence for the caller, never transferable signing
//! authority. The eventual signer must run this boundary again immediately
//! before key use and must keep its own emergency checkpoints.

use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::channel::{ChannelInfo, query_channel};
use hacash_wallet_core::l2_hub::{FastPayRequest, HubHealth, L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::l2_safety::{
    ClientL2Safety, ClientOperationIdentity, ClientOperationStatus, RestrictedSenderAuthority,
};
use hpay_companion_protocol::AgentFastPayNetworkBinding;

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::fast_pay_operation::AgentFastPayOperationView;
use crate::node_binding::{AgentNodeSnapshot, verified_agent_node};
use crate::policy::{AgentPermission, AgentRecord, AgentStatus};
use crate::types::{AgentWalletId, OperationId};

use super::{AgentL2Binding, AgentWalletManager};
use crate::operation::ApprovalMode;
use crate::service::{
    AgentWalletState, payment::revalidate_approved_payment_policy, require_agent_spending_network,
};

#[derive(Clone)]
struct ApprovedReadinessSnapshot {
    view: AgentFastPayOperationView,
    binding: AgentL2Binding,
    agent: AgentRecord,
    node_url: String,
    block_one_fingerprint: String,
    payments_suspended: bool,
    trusted_mainnet_fast_pay_pilot: bool,
}

struct VerifiedAgentFastPayReadiness {
    view: AgentFastPayOperationView,
    binding: AgentL2Binding,
    channel: ChannelInfo,
    trusted_mainnet_fast_pay_pilot: bool,
}

#[derive(Clone, Copy)]
enum FastPayReadinessPhase {
    PreSigning,
    SignedSubmission,
    PostSignRecovery,
}

#[derive(Clone, Copy)]
enum FastPayDurableTransition {
    ReconciledUnsignedPrepared,
    ReconciledUnsignedCancelled,
    Signed,
    Submitted,
    ReconciledSubmitted,
    AwaitingRecipient,
    Committed,
    RecoveryRequired,
    ExactRetryReady,
}

impl AgentWalletManager {
    /// Re-checks every live dependency of an approved Agent Fast Pay request.
    ///
    /// This method never accesses a private key, signs a bill, calls a Hub
    /// payment endpoint, changes operation state or enables mainnet. A future
    /// executor must repeat this check at its final signing boundary.
    pub async fn reverify_approved_fast_pay_readiness(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        Ok(self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PreSigning,
            )
            .await?
            .view)
    }

    async fn verified_fast_pay_readiness(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
        phase: FastPayReadinessPhase,
    ) -> AgentWalletResult<VerifiedAgentFastPayReadiness> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        require_agent_spending_network(&state.network_mode, state.trusted_mainnet_fast_pay_pilot)?;
        let binding = state
            .l2_binding
            .as_ref()
            .ok_or(AgentWalletError::SigningBlocked)?;
        if !binding.is_active() {
            return Err(AgentWalletError::SigningBlocked);
        }
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let agent = state
            .agents
            .get(operation.agent_id().as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?
            .clone();
        let view = match phase {
            FastPayReadinessPhase::PreSigning => operation.approved_signing_view(
                binding,
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
                now,
            )?,
            FastPayReadinessPhase::SignedSubmission => operation.signed_submission_view(
                binding,
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
            )?,
            FastPayReadinessPhase::PostSignRecovery => operation.post_sign_recovery_view(
                binding,
                agent.authorization_epoch,
                state.policy_epoch,
                state.signer_epoch,
                state.emergency_epoch,
            )?,
        };
        validate_current_agent(&state, &agent, &view, now)?;
        let snapshot = ApprovedReadinessSnapshot {
            view,
            binding: binding.clone(),
            agent,
            node_url: state.node_url.clone(),
            block_one_fingerprint: state.block_one_fingerprint.clone(),
            payments_suspended: state.payments_suspended,
            trusted_mainnet_fast_pay_pilot: state.trusted_mainnet_fast_pay_pilot,
        };
        let safety = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(snapshot.payments_suspended)?;
        safety.checkpoint(snapshot.payments_suspended)?;
        drop(state);

        let node = verified_agent_node(
            &snapshot.node_url,
            snapshot.binding.network_mode(),
            &snapshot.block_one_fingerprint,
        )
        .await?;
        safety.checkpoint(snapshot.payments_suspended)?;
        require_exact_node_binding(node.snapshot(), &snapshot.binding)?;

        let channel = query_channel(&node, snapshot.binding.channel_id())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        safety.checkpoint(snapshot.payments_suspended)?;
        require_exact_live_channel(&snapshot.binding, node.snapshot(), &channel, now)?;

        let hub = L2HubClient::new_for_wallet_policy(
            snapshot.binding.hub_url(),
            snapshot.binding.network_mode(),
            snapshot.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .health()
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        safety.checkpoint(snapshot.payments_suspended)?;
        require_exact_hub_health(
            &health,
            &snapshot.binding,
            snapshot.trusted_mainnet_fast_pay_pilot,
        )?;
        if snapshot.binding.network_mode() == "mainnet" {
            hub.require_mainnet_payment_ready(Some(&snapshot.view.amount_units.to_decimal()))
                .await
                .map_err(|_| AgentWalletError::SigningBlocked)?;
            safety.checkpoint(snapshot.payments_suspended)?;
        }

        let session = self.session(wallet_id)?;
        let current =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let current_binding = current
            .l2_binding
            .as_ref()
            .ok_or(AgentWalletError::SigningBlocked)?;
        if !current_binding.is_active()
            || current_binding != &snapshot.binding
            || current.trusted_mainnet_fast_pay_pilot != snapshot.trusted_mainnet_fast_pay_pilot
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let current_agent = current
            .agents
            .get(snapshot.agent.agent_id.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?;
        if current_agent != &snapshot.agent {
            return Err(AgentWalletError::AgentSessionExpired);
        }
        validate_current_agent(&current, current_agent, &snapshot.view, now)?;
        let current_operation = current
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let current_view = match phase {
            FastPayReadinessPhase::PreSigning => current_operation.approved_signing_view(
                current_binding,
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
                now,
            )?,
            FastPayReadinessPhase::SignedSubmission => current_operation.signed_submission_view(
                current_binding,
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
            )?,
            FastPayReadinessPhase::PostSignRecovery => current_operation.post_sign_recovery_view(
                current_binding,
                current_agent.authorization_epoch,
                current.policy_epoch,
                current.signer_epoch,
                current.emergency_epoch,
            )?,
        };
        if current_view != snapshot.view {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        safety.checkpoint(current.payments_suspended)?;
        Ok(VerifiedAgentFastPayReadiness {
            view: current_view,
            binding: snapshot.binding,
            channel,
            trusted_mainnet_fast_pay_pilot: snapshot.trusted_mainnet_fast_pay_pilot,
        })
    }

    /// Durably enters the pre-Hub execution state in both authenticated
    /// journals.
    ///
    /// This still performs no Hub payment request, key use, signature or
    /// settlement. Once this succeeds the owner cannot cancel the operation
    /// through the pre-sign path; a restart must resume the same exact Hub
    /// identity and owner-authority commitment.
    pub async fn prepare_approved_fast_pay_execution(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.reverify_approved_fast_pay_readiness(wallet_id, operation_id, now)
            .await?;
        self.persist_approved_fast_pay_execution_journals(wallet_id, operation_id, now)
    }

    /// Obtains and durably stores the exact unsigned Hub bill after opening
    /// both Agent-scoped execution journals. No signing key is exposed or used.
    /// A caller must perform another complete live verification before asking
    /// the restricted signer to add the Agent signature.
    pub async fn prepare_approved_fast_pay_unsigned_bill(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.prepare_approved_fast_pay_execution(wallet_id, operation_id, now)
            .await?;
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PreSigning,
            )
            .await?;

        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let signer_binding = operation.signer_binding()?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let request = FastPayRequest {
            operation_id: signer_binding.hub_operation_id,
            idempotency_key: signer_binding.hub_idempotency_key,
            payer: signer_binding.payer,
            payee: signer_binding.payee,
            amount: signer_binding.amount,
            channel_id: signer_binding.channel_id,
            fee_payer: Some("sender".to_owned()),
        };
        let prepared = hub
            .prepare_and_persist_sender_bill(
                &request,
                &bills,
                &mut safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .await;
        if let Err(_error) = prepared {
            #[cfg(test)]
            eprintln!("Agent Fast Pay unsigned-bill preparation failed: {_error}");
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            drop(safety);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            drop(safety);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        drop(safety);

        // The Hub response grants no signing authority. Re-run the complete
        // owner, node, Hub and channel gate before returning to the signer
        // coordinator.
        let current = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PreSigning,
            )
            .await?;
        if current.view != verified.view
            || current.binding != verified.binding
            || current.channel != verified.channel
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(current.view)
    }

    /// Adds the Agent signature only after the exact unsigned bill is durable
    /// and the complete live gate has passed again. The signed bytes remain in
    /// the Agent-scoped recovery journal and are never submitted by this
    /// method. A restart from `Signed` therefore requires explicit settlement
    /// reconciliation rather than another signature or an L1 fallback.
    pub async fn sign_prepared_approved_fast_pay_bill(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.prepare_approved_fast_pay_unsigned_bill(wallet_id, operation_id, now)
            .await?;
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PreSigning,
            )
            .await?;

        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let signer_binding = operation.signer_binding()?;
        let owner_authority = signer_binding
            .restricted_sender_authority
            .owner_authority_commitment
            .clone();
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let request = FastPayRequest {
            operation_id: signer_binding.hub_operation_id.clone(),
            idempotency_key: signer_binding.hub_idempotency_key.clone(),
            payer: signer_binding.payer.clone(),
            payee: signer_binding.payee.clone(),
            amount: signer_binding.amount.clone(),
            channel_id: signer_binding.channel_id.clone(),
            fee_payer: Some("sender".to_owned()),
        };
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let durable = safety
            .operation(&verified.view.hub_operation_id)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if durable.status != ClientOperationStatus::PersistedBeforeSigning
            || durable.owner_authority_commitment.as_deref() != Some(owner_authority.as_str())
            || durable.unsigned_bill_hex.is_none()
            || durable.signed_bill_hex.is_some()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        hub.revalidate_persisted_sender_bill(
            &request,
            &bills,
            &safety,
            &verified.channel,
            verified.binding.hub_address(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        safety_permit.checkpoint(false)?;
        let signing_guard = safety_permit.irreversible_checkpoint(false)?;
        let restricted_signer =
            session
                .signer
                .restrict_fast_pay(signer_binding, &safety_permit, now)?;
        let signing_result = hub.sign_and_persist_prepared_sender_bill(
            &mut safety,
            &restricted_signer,
            &verified.view.hub_operation_id,
        );
        drop(restricted_signer);
        drop(signing_guard);

        if signing_result.is_err() {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            drop(safety);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            drop(safety);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        drop(safety);

        match self.persist_fast_pay_signed(wallet_id, operation_id, now) {
            Ok(view) => Ok(view),
            Err(error) => {
                let session = self.session(wallet_id)?;
                let l2_root = self.storage.paths(wallet_id)?.l2_dir();
                if let Ok(mut safety) = ClientL2Safety::open_scoped_with_key_provider_for_network(
                    &session.signer,
                    l2_root,
                    verified.binding.wallet_scope().as_str(),
                    verified.binding.network_mode(),
                    verified.binding.hub_address(),
                    verified.binding.channel_id(),
                ) {
                    let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
                }
                let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
                Err(error)
            }
        }
    }

    /// Mirrors Submitted in the Agent and client journals before the first
    /// signed Hub confirmation request. This method never re-signs and never
    /// falls back to L1. Unknown outcomes retain the reservation and enter
    /// explicit recovery.
    pub async fn submit_signed_approved_fast_pay_bill(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::SignedSubmission,
            )
            .await?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let hub_idempotency_key = operation.hub_idempotency_key().to_owned();
        let owner_authority = verified
            .view
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let mut bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let request = FastPayRequest {
            operation_id: verified.view.hub_operation_id.clone(),
            idempotency_key: hub_idempotency_key,
            payer: verified.view.payer.clone(),
            payee: verified.view.recipient.clone(),
            amount: verified.view.amount_units.to_decimal(),
            channel_id: verified.binding.channel_id().to_owned(),
            fee_payer: Some("sender".to_owned()),
        };
        let durable = hub
            .revalidate_persisted_signed_sender_bill(
                &request,
                &bills,
                &safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if durable.owner_authority_commitment.as_deref() != Some(owner_authority.as_str()) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        safety_permit.checkpoint(false)?;

        if self
            .persist_fast_pay_submitted(wallet_id, operation_id, now)
            .is_err()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if safety
            .mark_submitted(&verified.view.hub_operation_id)
            .is_err()
        {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }

        let result = hub
            .confirm_submitted_sender_bill(
                &request,
                &mut bills,
                &mut safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .await;
        if result.is_err() {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        let execution = result.map_err(|_| AgentWalletError::RecoveryRequired)?;
        let persisted = match execution.status.as_str() {
            "awaiting_recipient" => {
                self.persist_fast_pay_awaiting_recipient(wallet_id, operation_id, now)
            }
            "settled" => self.persist_fast_pay_committed(wallet_id, operation_id, now),
            _ => Err(AgentWalletError::RecoveryRequired),
        };
        match persisted {
            Ok(view) => Ok(view),
            Err(error) => {
                let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
                Err(error)
            }
        }
    }

    /// Reconciles one post-sign operation against the exact bound Hub. It is
    /// read-only at the network boundary: no signature, resubmission, new id,
    /// or L1 fallback is possible.
    pub async fn reconcile_signed_fast_pay_bill(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PostSignRecovery,
            )
            .await?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let hub_idempotency_key = operation.hub_idempotency_key().to_owned();
        let owner_authority = verified
            .view
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let durable = safety
            .operation(&verified.view.hub_operation_id)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if durable.owner_authority_commitment.as_deref() != Some(owner_authority.as_str())
            || durable.signed_bill_hex.is_none()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let mut bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let request = FastPayRequest {
            operation_id: verified.view.hub_operation_id.clone(),
            idempotency_key: hub_idempotency_key,
            payer: verified.view.payer.clone(),
            payee: verified.view.recipient.clone(),
            amount: verified.view.amount_units.to_decimal(),
            channel_id: verified.binding.channel_id().to_owned(),
            fee_payer: Some("sender".to_owned()),
        };
        safety_permit.checkpoint(false)?;
        let result = hub
            .reconcile_sender_bill(
                &request,
                &mut bills,
                &mut safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .await;
        if result.is_err() {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        let execution = result.map_err(|_| AgentWalletError::RecoveryRequired)?;
        let persisted = match execution.status.as_str() {
            "pending" => self.persist_fast_pay_exact_retry_ready(wallet_id, operation_id, now),
            "awaiting_recipient" => {
                self.persist_fast_pay_awaiting_recipient(wallet_id, operation_id, now)
            }
            "settled" => self.persist_fast_pay_committed(wallet_id, operation_id, now),
            _ => Err(AgentWalletError::RecoveryRequired),
        };
        match persisted {
            Ok(view) => Ok(view),
            Err(error) => {
                let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
                Err(error)
            }
        }
    }

    /// Recovers either side of the pre-sign/post-sign uncertainty boundary.
    /// A missing durable signature uses the read-only unsigned recovery path;
    /// a durable signature delegates to exact signed reconciliation. No branch
    /// signs, submits, changes identifiers, or falls back to L1.
    pub async fn recover_fast_pay_operation(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PostSignRecovery,
            )
            .await?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let hub_idempotency_key = operation.hub_idempotency_key().to_owned();
        let owner_authority = verified
            .view
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let durable = safety
            .operation(&verified.view.hub_operation_id)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if durable.owner_authority_commitment.as_deref() != Some(owner_authority.as_str()) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        if durable.signed_bill_hex.is_some() {
            drop(safety);
            return self
                .reconcile_signed_fast_pay_bill(wallet_id, operation_id, now)
                .await;
        }

        let bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let request = FastPayRequest {
            operation_id: verified.view.hub_operation_id.clone(),
            idempotency_key: hub_idempotency_key,
            payer: verified.view.payer.clone(),
            payee: verified.view.recipient.clone(),
            amount: verified.view.amount_units.to_decimal(),
            channel_id: verified.binding.channel_id().to_owned(),
            fee_payer: Some("sender".to_owned()),
        };
        safety_permit.checkpoint(false)?;
        if hub
            .reconcile_unsigned_sender_bill(
                &request,
                &bills,
                &mut safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .await
            .is_err()
        {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        if now >= verified.view.expires_at {
            safety
                .reject_reconciled_unsigned(&verified.view.hub_operation_id)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            drop(safety);
            return self.persist_fast_pay_reconciled_unsigned_cancelled(
                wallet_id,
                operation_id,
                now,
            );
        }
        drop(safety);
        self.persist_fast_pay_reconciled_unsigned_prepared(wallet_id, operation_id, now)
    }

    /// Owner-triggered retry of the exact durable signature after a prior
    /// reconciliation proved that the Hub still holds the same pending bill.
    pub async fn retry_reconciled_fast_pay_submission(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let verified = self
            .verified_fast_pay_readiness(
                wallet_id,
                operation_id,
                now,
                FastPayReadinessPhase::PostSignRecovery,
            )
            .await?;
        if verified.view.status != crate::fast_pay_operation::AgentFastPayStatus::ExactRetryReady {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let hub_idempotency_key = operation.hub_idempotency_key().to_owned();
        let owner_authority = verified
            .view
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            &l2_root,
            verified.binding.wallet_scope().as_str(),
            verified.binding.network_mode(),
            verified.binding.hub_address(),
            verified.binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let durable = safety
            .operation(&verified.view.hub_operation_id)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if durable.status != ClientOperationStatus::RecoveryRequired
            || durable.owner_authority_commitment.as_deref() != Some(owner_authority.as_str())
            || durable.signed_bill_hex.is_none()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let mut bills = BillStore::load_at(l2_root.join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let hub = L2HubClient::new_for_wallet_policy(
            verified.binding.hub_url(),
            verified.binding.network_mode(),
            verified.trusted_mainnet_fast_pay_pilot,
        );
        let request = FastPayRequest {
            operation_id: verified.view.hub_operation_id.clone(),
            idempotency_key: hub_idempotency_key,
            payer: verified.view.payer.clone(),
            payee: verified.view.recipient.clone(),
            amount: verified.view.amount_units.to_decimal(),
            channel_id: verified.binding.channel_id().to_owned(),
            fee_payer: Some("sender".to_owned()),
        };
        safety_permit.checkpoint(false)?;
        self.persist_fast_pay_reconciled_submitted(wallet_id, operation_id, now)?;
        let result = hub
            .retry_reconciled_sender_bill(
                &request,
                &mut bills,
                &mut safety,
                &verified.channel,
                verified.binding.hub_address(),
            )
            .await;
        if result.is_err() {
            let _ = safety.mark_recovery_required(&verified.view.hub_operation_id);
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Err(error) = safety_permit.checkpoint(false) {
            let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
            return Err(error);
        }
        let execution = result.map_err(|_| AgentWalletError::RecoveryRequired)?;
        match execution.status.as_str() {
            "awaiting_recipient" => {
                self.persist_fast_pay_awaiting_recipient(wallet_id, operation_id, now)
            }
            "settled" => self.persist_fast_pay_committed(wallet_id, operation_id, now),
            _ => {
                let _ = self.persist_fast_pay_recovery_required(wallet_id, operation_id, now);
                Err(AgentWalletError::RecoveryRequired)
            }
        }
    }

    fn persist_fast_pay_signed(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::Signed,
        )
    }

    fn persist_fast_pay_submitted(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::Submitted,
        )
    }

    fn persist_fast_pay_reconciled_submitted(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::ReconciledSubmitted,
        )
    }

    fn persist_fast_pay_reconciled_unsigned_prepared(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::ReconciledUnsignedPrepared,
        )
    }

    fn persist_fast_pay_reconciled_unsigned_cancelled(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::ReconciledUnsignedCancelled,
        )
    }

    fn persist_fast_pay_exact_retry_ready(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::ExactRetryReady,
        )
    }

    fn persist_fast_pay_awaiting_recipient(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::AwaitingRecipient,
        )
    }

    fn persist_fast_pay_committed(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::Committed,
        )
    }

    fn persist_fast_pay_recovery_required(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_fast_pay_post_signature_status(
            wallet_id,
            operation_id,
            now,
            FastPayDurableTransition::RecoveryRequired,
        )
    }

    fn persist_fast_pay_post_signature_status(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
        transition: FastPayDurableTransition,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let session = self.session(wallet_id)?;
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let operation = state
            .fast_pay_operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        match transition {
            FastPayDurableTransition::ReconciledUnsignedPrepared => {
                operation.mark_reconciled_unsigned_prepared()?
            }
            FastPayDurableTransition::ReconciledUnsignedCancelled => {
                operation.mark_reconciled_unsigned_cancelled()?
            }
            FastPayDurableTransition::Signed => operation.mark_signed()?,
            FastPayDurableTransition::Submitted => operation.mark_submitted()?,
            FastPayDurableTransition::ReconciledSubmitted => {
                operation.mark_reconciled_submitted()?
            }
            FastPayDurableTransition::AwaitingRecipient => operation.mark_awaiting_recipient()?,
            FastPayDurableTransition::Committed => operation.mark_committed(now)?,
            FastPayDurableTransition::RecoveryRequired => operation.mark_recovery_required()?,
            FastPayDurableTransition::ExactRetryReady => operation.mark_exact_retry_ready()?,
        }
        let view = operation.view();
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            match transition {
                FastPayDurableTransition::ReconciledUnsignedPrepared => {
                    crate::journal::AgentJournalEventKind::FastPayUnsignedRecovered
                }
                FastPayDurableTransition::ReconciledUnsignedCancelled => {
                    crate::journal::AgentJournalEventKind::PaymentFailed
                }
                FastPayDurableTransition::Signed => {
                    crate::journal::AgentJournalEventKind::TransactionSigned
                }
                FastPayDurableTransition::Submitted => {
                    crate::journal::AgentJournalEventKind::FastPaySubmitted
                }
                FastPayDurableTransition::ReconciledSubmitted => {
                    crate::journal::AgentJournalEventKind::FastPaySubmitted
                }
                FastPayDurableTransition::AwaitingRecipient => {
                    crate::journal::AgentJournalEventKind::FastPayAwaitingRecipient
                }
                FastPayDurableTransition::Committed => {
                    crate::journal::AgentJournalEventKind::PaymentCommitted
                }
                FastPayDurableTransition::RecoveryRequired => {
                    crate::journal::AgentJournalEventKind::RecoveryRequired
                }
                FastPayDurableTransition::ExactRetryReady => {
                    crate::journal::AgentJournalEventKind::FastPayExactRetryReady
                }
            },
            Some(operation_id.as_str().as_bytes()),
            Some(view.agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(view)
    }

    fn persist_approved_fast_pay_execution_journals(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let binding = state
            .l2_binding
            .as_ref()
            .ok_or(AgentWalletError::SigningBlocked)?
            .clone();
        if !binding.is_active() {
            return Err(AgentWalletError::SigningBlocked);
        }
        let operation = state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let restricted_sender_authority = operation.restricted_sender_authority()?;
        let agent_authorization_epoch = state
            .agents
            .get(operation.agent_id().as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?
            .authorization_epoch;
        let approved = operation.approved_signing_view(
            &binding,
            agent_authorization_epoch,
            state.policy_epoch,
            state.signer_epoch,
            state.emergency_epoch,
            now,
        )?;
        let owner_authority_commitment = approved
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let hub_idempotency_key = operation.hub_idempotency_key().to_owned();
        let safety = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        safety.checkpoint(state.payments_suspended)?;

        state
            .fast_pay_operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .mark_execution_prepared()?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::TransactionPrepared,
            Some(operation_id.as_str().as_bytes()),
            Some(approved.agent_id.as_str().as_bytes()),
            now,
        )?;
        safety.checkpoint(state.payments_suspended)?;
        drop(state);

        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let session = self.session(wallet_id)?;
        let mut l2 = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &session.signer,
            l2_root,
            binding.wallet_scope().as_str(),
            binding.network_mode(),
            binding.hub_address(),
            binding.channel_id(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let amount = approved.amount_units.to_decimal();
        let mirrored = l2
            .begin_or_resume_restricted_sender(
                ClientOperationIdentity {
                    operation_id: &approved.hub_operation_id,
                    idempotency_key: &hub_idempotency_key,
                },
                RestrictedSenderAuthority {
                    ..restricted_sender_authority.clone()
                },
                &approved.payer,
                &approved.recipient,
                &amount,
                approved.amount_units.to_millimeis_exact()?,
                binding.channel_reuse_version(),
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if mirrored.owner_authority_commitment.as_deref()
            != Some(owner_authority_commitment.as_str())
            || mirrored.operation_id != approved.hub_operation_id
            || mirrored.idempotency_key != hub_idempotency_key
            || mirrored.restricted_sender_authority.as_ref() != Some(&restricted_sender_authority)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        drop(l2);

        let session = self.session(wallet_id)?;
        let current =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let current_operation = current
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let current_view = current_operation.view();
        if current_view.status != crate::fast_pay_operation::AgentFastPayStatus::ExecutionPrepared
            || current_view.owner_authority_commitment.as_deref()
                != Some(owner_authority_commitment.as_str())
            || current_view.hub_operation_id != approved.hub_operation_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        safety.checkpoint(current.payments_suspended)?;
        Ok(current_view)
    }

    #[cfg(test)]
    pub(crate) fn test_persist_approved_fast_pay_execution_journals(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.persist_approved_fast_pay_execution_journals(wallet_id, operation_id, now)
    }
}

fn validate_current_agent(
    state: &AgentWalletState,
    agent: &AgentRecord,
    view: &AgentFastPayOperationView,
    now: u64,
) -> AgentWalletResult<()> {
    if agent.status != AgentStatus::Active {
        return Err(AgentWalletError::AgentRevoked);
    }
    if agent.authorization_epoch != view.agent_authorization_epoch
        || !agent
            .policy
            .permissions
            .contains(&AgentPermission::CreatePaymentIntent)
        || !matches!(
            agent.policy.approval_mode,
            ApprovalMode::MobileManual | ApprovalMode::EitherTrustedDevice
        )
    {
        return Err(AgentWalletError::AgentPermissionDenied);
    }
    revalidate_approved_payment_policy(state, agent, &view.recipient, view.total_debit_units, now)
}

pub(super) fn require_exact_node_binding(
    node: &AgentNodeSnapshot,
    binding: &AgentL2Binding,
) -> AgentWalletResult<()> {
    let live = AgentFastPayNetworkBinding {
        network_mode: binding.network_mode().to_owned(),
        chain_id: node.chain_id,
        genesis_identifier: node.block_one_fingerprint.clone(),
        node_profile_id: node.node_profile_commitment.clone(),
        network_instance_id: node.network_instance_id.clone(),
        transaction_format_version: node.transaction_format_version,
    };
    // `funding_confirmed` is now SCOPED to the pilot rail, on the owner's
    // explicit decision, and the scope is keyed on the WALLET'S OWN STORED
    // MODE.
    //
    // The fact this answers, pinned by the tests below: a healthy, fully synced,
    // real mainnet node reports `funding_confirmed: false`. The flag is a LOCAL
    // PILOT signal that mainnet has no equivalent of. `valid_local_pilot`
    // requires it and `valid_mainnet` deliberately omits it;
    // `supports_agent_local_pilot_payment` reads it and
    // `supports_agent_mainnet_payment` does not; both crates' mainnet fixtures
    // hardcode it false. So on mainnet the term could never be satisfied, and it
    // sat on the close voucher path and all three cooperative close paths but
    // NOT on the channel open path. A mainnet agent channel could be funded and
    // never left. On mainnet this term protected nothing and only locked the
    // exit, so there it no longer applies.
    //
    // On testnet and the local pilot the flag means something real and is
    // still required, so the pilot arm keeps failing closed.
    //
    // WHY IT IS KEYED ON `binding.network_mode()` AND NOT ON `node.mainnet`:
    // `node.mainnet` is written by the remote node being judged. Keying the
    // pilot arm on it would let a node choose which arm judges it, by claiming
    // to be mainnet. `binding.network_mode()` is stored by this wallet when the
    // channel was bound and the node cannot move it. The term is scoped rather
    // than deleted because deleting it would drop the pilot check entirely.
    //
    // WHAT MUST NOT BE RELAXED. This is one term and the authorisation covered
    // exactly one term. The remaining three here carry the safety now:
    // `node.mainnet` must still agree with the stored mode, the node must still
    // be `transaction_ready`, and the whole live network binding (chain id,
    // genesis fingerprint, node profile commitment, network instance,
    // transaction format version) must still equal the stored one byte for
    // byte. Do not weaken any of them, and do not make the mainnet capability
    // contract report `funding_confirmed: true` to get past this: that would
    // put a false value in the field and break the open path that reads it
    // honestly.
    //
    // On the fee: this deliberately does NOT check that the agent address can
    // pay the close transaction's L1 fee. The chain subtracts the fee AFTER the
    // actions execute, and ChannelClose credits the principal to the party's
    // ordinary balance inside that same loop, so a delta-zero voucher close
    // funds its own fee out of the money it releases. A balance precondition
    // here would read the balance before the close changes it and could only
    // ever produce a false refusal, on the exit path, against the person whose
    // ordinary balance is empty because everything went into the channel. The
    // main wallet's close paths check no balance either; the one balance check
    // in this codebase is on the channel OPEN path, where the money must come
    // from outside.
    if node.mainnet != (binding.network_mode() == "mainnet")
        || (binding.network_mode() != "mainnet" && !node.funding_confirmed)
        || !node.transaction_ready
        || &live != binding.network_binding()
    {
        return Err(AgentWalletError::NodeNetworkMismatch);
    }
    Ok(())
}

pub(super) fn require_exact_live_channel(
    binding: &AgentL2Binding,
    node: &AgentNodeSnapshot,
    channel: &ChannelInfo,
    now: u64,
) -> AgentWalletResult<()> {
    let live = AgentL2Binding::from_verified_channel(
        binding.wallet_id().clone(),
        binding.network_mode(),
        binding.network_binding().clone(),
        binding.agent_address(),
        binding.hub_url(),
        binding.hub_address(),
        channel,
        node.current_height,
        now,
    )?;
    if !binding.same_channel_identity(&live) {
        return Err(AgentWalletError::ApprovalCommitmentMismatch);
    }
    Ok(())
}

/// Re-verify the provider identity and liveness contract behind an existing
/// binding.
///
/// This weighs only what `/v1/health` can actually answer without fullnode
/// I/O: identity, fee, routing support, and the profile label the provider
/// publishes. The mainnet hard guarantees are deliberately not read here -
/// `/v1/health` cannot measure them, so a gate reading them could never open.
/// Every mainnet caller pairs this with the readiness document
/// (`require_mainnet_hard_guarantees` or `require_mainnet_payment_ready`),
/// which is the authority for `trustless_finality` and
/// `unilateral_l1_enforceable`.
pub(super) fn require_exact_hub_health(
    health: &HubHealth,
    binding: &AgentL2Binding,
    trusted_mainnet_fast_pay_pilot: bool,
) -> AgentWalletResult<()> {
    let mainnet_profile_ready = if binding.network_mode() != "mainnet" {
        true
    } else if trusted_mainnet_fast_pay_pilot {
        health.trusted_bounded_pilot_ready
            && health.deployment_profile.as_deref() == Some("mainnet-bounded-pilot")
    } else {
        !health.trusted_bounded_pilot_ready
            && health.deployment_profile.as_deref() == Some("mainnet-pilot")
    };
    if !health.ok
        || health.version < 7
        || !health.settlement_ready
        || !health.cross_channel_ready
        || !hub_fee_is_zero(health)
        || health.hub_address.as_deref() != Some(binding.hub_address())
        || !mainnet_profile_ready
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hacash_wallet_core::account::WalletAccount;
    use hacash_wallet_core::channel::{
        CHANNEL_STATUS_OPENING, ChannelPartyBalance, derive_channel_id,
    };

    fn fixture() -> (AgentL2Binding, AgentNodeSnapshot, ChannelInfo, HubHealth) {
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let channel = ChannelInfo {
            ret: 0,
            id: derive_channel_id(&agent.address(), &hub.address(), 1),
            status: CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version: 1,
            arbitration_lock: 5_000,
            left: ChannelPartyBalance {
                address: agent.address(),
                hacash: "1".to_owned(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: hub.address(),
                hacash: "0".to_owned(),
                satoshi: 0,
            },
            challenging: None,
        };
        let node = AgentNodeSnapshot {
            node_name: "hacash-fullnode".to_owned(),
            node_version: "1.0.10".to_owned(),
            network_kind: "hpay_local_pilot".to_owned(),
            node_profile_id: "hpay-local-pilot-v1".to_owned(),
            node_profile_commitment: "77".repeat(32),
            chain_id: 7,
            mainnet: false,
            current_height: 105,
            block_one_fingerprint: "11".repeat(32),
            network_instance_id: "pilot-instance".to_owned(),
            funding_confirmed: true,
            transaction_ready: true,
            transaction_format_version: 2,
        };
        let network = AgentFastPayNetworkBinding {
            network_mode: "testnet".to_owned(),
            chain_id: node.chain_id,
            genesis_identifier: node.block_one_fingerprint.clone(),
            node_profile_id: node.node_profile_commitment.clone(),
            network_instance_id: node.network_instance_id.clone(),
            transaction_format_version: node.transaction_format_version,
        };
        let binding = AgentL2Binding::from_verified_channel(
            AgentWalletId::new(),
            "testnet",
            network,
            &agent.address(),
            "https://hub.example",
            &hub.address(),
            &channel,
            node.current_height,
            1_000,
        )
        .unwrap();
        let health = HubHealth {
            ok: true,
            version: 7,
            name: Some("HPAY Hub".to_owned()),
            hub_address: Some(hub.address()),
            hub_fee_mei: Some(serde_json::json!("0")),
            settlement_ready: true,
            cross_channel_ready: true,
            official_channelpay_ready: false,
            trusted_bounded_pilot_ready: false,
            deployment_profile: Some("testnet".to_owned()),
        };
        (binding, node, channel, health)
    }

    #[test]
    fn exact_live_evidence_is_accepted() {
        let (binding, node, channel, health) = fixture();
        require_exact_node_binding(&node, &binding).unwrap();
        require_exact_live_channel(&binding, &node, &channel, 1_001).unwrap();
        require_exact_hub_health(&health, &binding, false).unwrap();
    }

    #[test]
    fn any_node_identity_or_readiness_drift_fails_closed() {
        let (binding, node, _, _) = fixture();
        let mut cases = Vec::new();
        let mut changed = node.clone();
        changed.chain_id += 1;
        cases.push(changed);
        let mut changed = node.clone();
        changed.network_instance_id.push_str("-other");
        cases.push(changed);
        let mut changed = node.clone();
        changed.transaction_format_version += 1;
        cases.push(changed);
        let mut changed = node.clone();
        changed.funding_confirmed = false;
        cases.push(changed);
        let mut changed = node;
        changed.transaction_ready = false;
        cases.push(changed);
        for changed in cases {
            assert!(require_exact_node_binding(&changed, &binding).is_err());
        }
    }

    #[test]
    fn channel_and_hub_drift_matrix_fails_closed() {
        let (binding, node, channel, health) = fixture();
        let mut channels = Vec::new();
        let mut changed = channel.clone();
        changed.reuse_version += 1;
        channels.push(changed);
        let mut changed = channel.clone();
        changed.open_height += 1;
        channels.push(changed);
        let mut changed = channel.clone();
        changed.left.hacash = "0.999".to_owned();
        channels.push(changed);
        let mut changed = channel;
        changed.close_height = 106;
        channels.push(changed);
        for changed in channels {
            assert!(require_exact_live_channel(&binding, &node, &changed, 1_001).is_err());
        }

        let mut hubs = Vec::new();
        let mut changed = health.clone();
        changed.hub_fee_mei = Some(serde_json::json!("0.001"));
        hubs.push(changed);
        let mut changed = health.clone();
        changed.hub_address = Some(WalletAccount::create_random().unwrap().address());
        hubs.push(changed);
        let mut changed = health.clone();
        changed.settlement_ready = false;
        hubs.push(changed);
        let mut changed = health;
        changed.cross_channel_ready = false;
        hubs.push(changed);
        for changed in hubs {
            assert!(require_exact_hub_health(&changed, &binding, false).is_err());
        }
    }

    #[test]
    fn bounded_mainnet_health_requires_the_exact_trusted_profile() {
        let (mut binding, _node, _channel, mut health) = fixture();
        binding.network_mode = "mainnet".to_owned();
        health.deployment_profile = Some("mainnet-bounded-pilot".to_owned());
        health.trusted_bounded_pilot_ready = true;
        assert!(require_exact_hub_health(&health, &binding, true).is_ok());
        assert!(require_exact_hub_health(&health, &binding, false).is_err());

        health.deployment_profile = Some("mainnet-pilot".to_owned());
        health.trusted_bounded_pilot_ready = false;
        assert!(require_exact_hub_health(&health, &binding, false).is_ok());
        assert!(require_exact_hub_health(&health, &binding, true).is_err());

        // The profile label is a liveness fact and is all this check may weigh.
        // The hard guarantees are not on `HubHealth` at all any more, so no
        // amount of health drift can open the mainnet money path on its own.
        health.deployment_profile = Some("mainnet-bounded-pilot".to_owned());
        assert!(require_exact_hub_health(&health, &binding, false).is_err());
    }

    /// The owner's real mainnet node, read from its own `/query/capabilities`
    /// on 2026-08-25 while it was serving at height 776330. Every field here is
    /// what that node reported, including `funding_confirmed: false`, which is
    /// what mainnet always reports: `mainnet_agent_capabilities` in
    /// `crates/wallet-core/src/node_capabilities.rs` sets it false, and
    /// `valid_mainnet` there never reads it.
    fn real_mainnet_fixture() -> (AgentL2Binding, AgentNodeSnapshot, ChannelInfo) {
        const MAINNET_BLOCK_ONE: &str =
            "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
        const MAINNET_INSTANCE: &str =
            "5a310ec0f487a37156a182c67778495f66e5c7502f9871829edc790023b123cf";
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let channel = ChannelInfo {
            ret: 0,
            id: derive_channel_id(&agent.address(), &hub.address(), 1),
            status: CHANNEL_STATUS_OPENING,
            open_height: 776_300,
            close_height: 0,
            reuse_version: 1,
            arbitration_lock: 5_000,
            left: ChannelPartyBalance {
                address: agent.address(),
                hacash: "1".to_owned(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: hub.address(),
                hacash: "0".to_owned(),
                satoshi: 0,
            },
            challenging: None,
        };
        let node = AgentNodeSnapshot {
            node_name: "hacash-fullnode".to_owned(),
            node_version: "1.0.10".to_owned(),
            network_kind: "mainnet".to_owned(),
            node_profile_id: "hacash-mainnet".to_owned(),
            node_profile_commitment: "5c".repeat(32),
            chain_id: 0,
            mainnet: true,
            current_height: 776_330,
            block_one_fingerprint: MAINNET_BLOCK_ONE.to_owned(),
            network_instance_id: MAINNET_INSTANCE.to_owned(),
            // The real node reports this false on mainnet.
            funding_confirmed: false,
            transaction_ready: true,
            transaction_format_version: 2,
        };
        // A binding that agrees with that node in every respect.
        let network = AgentFastPayNetworkBinding {
            network_mode: "mainnet".to_owned(),
            chain_id: node.chain_id,
            genesis_identifier: node.block_one_fingerprint.clone(),
            node_profile_id: node.node_profile_commitment.clone(),
            network_instance_id: node.network_instance_id.clone(),
            transaction_format_version: node.transaction_format_version,
        };
        let binding = AgentL2Binding::from_verified_channel(
            AgentWalletId::new(),
            "mainnet",
            network,
            &agent.address(),
            "https://hub.example",
            &hub.address(),
            &channel,
            node.current_height,
            1_000,
        )
        .unwrap();
        (binding, node, channel)
    }

    /// The one term this change moved, asserted from both sides in one place.
    ///
    /// This test used to be called `..._is_refused_by_...` and asserted
    /// `Err`. It was written to pin the BUG: a healthy, fully synced, real
    /// mainnet node was refused by the gate that stands on the close voucher
    /// path, so a mainnet agent channel could be funded and never left. The
    /// owner decided to scope the term to the pilot rail where it means
    /// something, so the assertion inverts on the mainnet side and the pilot
    /// side is asserted here rather than left to another file, because a
    /// scoped term with only one arm under test is half untested.
    #[test]
    fn real_mainnet_node_is_accepted_and_the_pilot_arm_still_demands_funding_confirmed() {
        let (binding, node, _channel) = real_mainnet_fixture();
        let outcome = require_exact_node_binding(&node, &binding);
        assert!(
            outcome.is_ok(),
            "a healthy real mainnet node reporting funding_confirmed: false must pass, \
             got {outcome:?}"
        );
        // Not vacuously: the node really does report the pilot flag false, so
        // the Ok above is the scoped arm doing its job and not a fixture that
        // quietly satisfies the old term.
        assert!(!node.funding_confirmed);

        // THE PILOT ARM. On a binding this wallet stored as testnet the flag
        // still means something and is still required. Without this half the
        // scoping would be indistinguishable from deleting the term.
        let (pilot_binding, pilot_node, _channel, _health) = fixture();
        assert_eq!(pilot_binding.network_mode(), "testnet");
        require_exact_node_binding(&pilot_node, &pilot_binding)
            .expect("a healthy pilot node with funding_confirmed: true still passes");
        let mut unfunded = pilot_node;
        unfunded.funding_confirmed = false;
        let pilot_outcome = require_exact_node_binding(&unfunded, &pilot_binding);
        assert!(
            matches!(pilot_outcome, Err(AgentWalletError::NodeNetworkMismatch)),
            "on the pilot rail funding_confirmed: false must still fail closed, \
             got {pilot_outcome:?}"
        );

        // The scope is keyed on the WALLET'S stored mode, not on the node's own
        // `mainnet` claim, so a node cannot talk its way into the lenient arm.
        // A node that claims mainnet against a testnet binding is refused by
        // the first term before the flag is ever weighed.
        let mut liar = unfunded;
        liar.mainnet = true;
        assert!(require_exact_node_binding(&liar, &pilot_binding).is_err());

        // And nothing else about the real mainnet node is wrong: each remaining
        // readiness and identity term is satisfied on its own.
        assert!(node.mainnet && binding.network_mode() == "mainnet");
        assert!(node.transaction_ready);
        assert_eq!(node.chain_id, binding.network_binding().chain_id);
        assert_eq!(
            node.block_one_fingerprint,
            binding.network_binding().genesis_identifier
        );
        assert_eq!(
            node.node_profile_commitment,
            binding.network_binding().node_profile_id
        );
        assert_eq!(
            node.network_instance_id,
            binding.network_binding().network_instance_id
        );
        assert_eq!(
            node.transaction_format_version,
            binding.network_binding().transaction_format_version
        );
    }

    /// The gate immediately after `require_exact_node_binding` on every one of
    /// the five paths that carry a close.
    ///
    /// This decided whether the `funding_confirmed` term was the whole wall or
    /// only the first course of it: if `require_exact_live_channel` also
    /// refused a real mainnet node, scoping `funding_confirmed` would have
    /// moved the refusal rather than lifted it. It does not refuse. The same
    /// real node and the same real channel pass here, which is why scoping the
    /// one term actually opens the exit.
    ///
    /// The `expect_err` precondition this test used to open with is gone,
    /// because the binding gate no longer refuses that node. What the test
    /// proves is unchanged and is still worth proving: the next gate along is
    /// not a second copy of the same refusal.
    #[test]
    fn the_live_channel_gate_accepts_the_real_mainnet_node_and_its_channel() {
        let (binding, node, channel) = real_mainnet_fixture();
        require_exact_live_channel(&binding, &node, &channel, 1_000)
            .expect("the live channel gate accepts the real mainnet node and its channel");

        // Negative control on that acceptance, so the Ok is known to be a
        // judgement and not an unconditional Ok: drift the channel and it
        // refuses.
        let mut reopened = channel.clone();
        reopened.reuse_version += 1;
        require_exact_live_channel(&binding, &node, &reopened, 1_000)
            .expect_err("channel drift must still fail closed");
    }

    /// The terms that carry the safety now that `funding_confirmed` is scoped
    /// off mainnet, exercised on the REAL mainnet fixture.
    ///
    /// `any_node_identity_or_readiness_drift_fails_closed` runs on the testnet
    /// fixture, and it never touched these two fields at all. So before this
    /// test the identity commitments that decide whether the node in front of a
    /// mainnet close is the node the channel was bound to had no executed test
    /// pointing at them on mainnet. They are the wall now, and a wall nobody
    /// pushes on is a wall nobody knows is standing.
    ///
    /// Both are substituted through the LIVE snapshot only, leaving the stored
    /// binding untouched, which is the real shape of the attack: a different
    /// node answering the same URL.
    #[test]
    fn mainnet_node_identity_commitment_drift_fails_closed() {
        let (binding, node, _channel) = real_mainnet_fixture();
        // Precondition, so an Err below is known to come from the drift and not
        // from a fixture that never passed.
        require_exact_node_binding(&node, &binding)
            .expect("precondition: the undrifted real mainnet node passes");

        // A different node profile commitment. This is the whole capability
        // profile the wallet agreed to, reduced to one hash.
        let mut other_profile = node.clone();
        other_profile.node_profile_commitment = "5d".repeat(32);
        assert_ne!(
            other_profile.node_profile_commitment,
            node.node_profile_commitment
        );
        let outcome = require_exact_node_binding(&other_profile, &binding);
        assert!(
            matches!(outcome, Err(AgentWalletError::NodeNetworkMismatch)),
            "node_profile_commitment drift must fail closed on mainnet, got {outcome:?}"
        );

        // A different genesis fingerprint. A node serving a different chain
        // from block one is the one substitution that could make a close land
        // somewhere the money is not.
        let mut other_genesis = node.clone();
        other_genesis.block_one_fingerprint = "00".repeat(32);
        assert_ne!(
            other_genesis.block_one_fingerprint,
            node.block_one_fingerprint
        );
        let outcome = require_exact_node_binding(&other_genesis, &binding);
        assert!(
            matches!(outcome, Err(AgentWalletError::NodeNetworkMismatch)),
            "block_one_fingerprint drift must fail closed on mainnet, got {outcome:?}"
        );

        // And an empty value is drift too, not a hole that reads as "not
        // reported yet" and passes.
        let mut blank_profile = node.clone();
        blank_profile.node_profile_commitment = String::new();
        assert!(require_exact_node_binding(&blank_profile, &binding).is_err());
        let mut blank_genesis = node;
        blank_genesis.block_one_fingerprint = String::new();
        assert!(require_exact_node_binding(&blank_genesis, &binding).is_err());
    }
}
