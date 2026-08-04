//! Authenticated external rollback witness state for the strict testnet pilot.
//!
//! Witness authority lives inside the encrypted, journal-authenticated Agent
//! Wallet state. The paired mobile stores the independent high-water mark.

use hpay_companion_protocol::{
    CompanionError, DeviceId, DevicePermission, DeviceRole, RollbackAnchor, RollbackOperationPhase,
    SignedRollbackAnchor, SignedWitnessReceipt, WitnessReconciliationStatus,
    WitnessReservationState, WitnessSubmissionStatus, WitnessTransactionState,
};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::node_binding::verified_agent_node;
use crate::operation::{OperationStatus, PaymentOperationView};
use crate::types::{AgentWalletId, OperationId};

use super::super::state::state_commitment;
use super::super::{
    AgentWalletManager, AuthenticatedCompletedWitness, AuthenticatedPendingWitness,
    AuthenticatedRollbackWitnessState,
};
use super::session::composite_registry;

const STORE_VERSION: u64 = 1;
const JOURNAL_EPOCH: u64 = 1;
const WITNESS_EPOCH: u64 = 1;
const CAPABILITY_EPOCH: u64 = 1;
const ANCHOR_LIFETIME_SECS: u64 = 5 * 60;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl AuthenticatedRollbackWitnessState {
    fn new(mobile_device_id: DeviceId) -> Self {
        Self {
            state_version: STORE_VERSION,
            witness_epoch: WITNESS_EPOCH,
            mobile_device_id,
            last_anchor_sequence: 0,
            last_anchor_hash: ZERO_HASH.to_owned(),
            pending: None,
            last_completed: None,
            history: Vec::new(),
        }
    }
}

impl AgentWalletManager {
    pub async fn pending_rollback_anchor(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        mobile_device_id: &DeviceId,
        now: u64,
    ) -> AgentWalletResult<SignedRollbackAnchor> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let signer = session.desktop_companion_signer.clone();
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation_status = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status();
        if state.network_mode != "testnet"
            || !matches!(
                operation_status,
                OperationStatus::SignedAwaitingWitness
                    | OperationStatus::SubmittedAwaitingFinalWitness
                    | OperationStatus::BroadcastUncertain
                    | OperationStatus::ReconciledAwaitingFinalWitness
            )
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        if state.operations.values().any(|operation| {
            operation.operation_id() != operation_id
                && matches!(
                    operation.status(),
                    OperationStatus::SignedAwaitingWitness
                        | OperationStatus::WitnessedAwaitingBroadcast
                        | OperationStatus::BroadcastSubmitted
                        | OperationStatus::BroadcastUncertain
                        | OperationStatus::SubmittedAwaitingFinalWitness
                        | OperationStatus::ReconciliationRequired
                        | OperationStatus::ReconciledAwaitingFinalWitness
                        | OperationStatus::RecoveryRequired
                )
        }) {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let registry = composite_registry(&state, &signer, now)?;
        let mobile = registry
            .require(
                mobile_device_id,
                wallet_id.as_str(),
                DeviceRole::Mobile,
                DevicePermission::WitnessRollbackAnchor,
            )
            .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;

        if state.rollback_witness.is_none() {
            state.rollback_witness = Some(AuthenticatedRollbackWitnessState::new(
                mobile_device_id.clone(),
            ));
            state.external_rollback_anchor_ready = true;
            state.updated_at = now;
            self.persist_event(
                &mut state,
                &session.state_master,
                &session.journal_key,
                AgentJournalEventKind::RollbackWitnessInitialized,
                None,
                Some(mobile_device_id.as_str().as_bytes()),
                now,
            )?;
            state =
                self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        }

        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        if witness.mobile_device_id != *mobile_device_id {
            return Err(AgentWalletError::RollbackDetected);
        }
        if let Some(pending) = &witness.pending {
            if pending.operation_id == operation_id.as_str() {
                match pending.proposal.verify(&registry, now) {
                    Ok(_) => return Ok(pending.proposal.clone()),
                    Err(CompanionError::Expired) => {
                        return Err(AgentWalletError::RecoveryRequired);
                    }
                    Err(_) => return Err(AgentWalletError::RollbackDetected),
                }
            }
            return Err(AgentWalletError::RollbackWitnessRequired);
        }

        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        let approval = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .stored_approval()?;
        let binding = approval
            .network_binding
            .as_ref()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        if approval.approval_version != 3
            || binding.network_id != node.network_kind()
            || binding.chain_id != node.chain_id()
            || binding.genesis_identifier != state.block_one_fingerprint
            || binding.node_profile_id != node.node_profile_id()
            || binding.transaction_format_version != node.transaction_format_version()
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        let anchor_sequence = witness
            .last_anchor_sequence
            .checked_add(1)
            .ok_or(AgentWalletError::RollbackDetected)?;
        let operation = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let operation_view = operation.view();
        let (operation_phase, submission_status, reconciliation_status, reservation_state) =
            match operation_status {
                OperationStatus::SignedAwaitingWitness => (
                    RollbackOperationPhase::SignedPreBroadcast,
                    WitnessSubmissionStatus::NotSubmitted,
                    WitnessReconciliationStatus::NotStarted,
                    WitnessReservationState::Held,
                ),
                OperationStatus::SubmittedAwaitingFinalWitness => (
                    RollbackOperationPhase::Submitted,
                    WitnessSubmissionStatus::Submitted,
                    WitnessReconciliationStatus::NotStarted,
                    WitnessReservationState::Held,
                ),
                OperationStatus::BroadcastUncertain => (
                    RollbackOperationPhase::Submitted,
                    WitnessSubmissionStatus::Uncertain,
                    WitnessReconciliationStatus::Unknown,
                    WitnessReservationState::Held,
                ),
                OperationStatus::ReconciledAwaitingFinalWitness => (
                    RollbackOperationPhase::ReconciledFinal,
                    WitnessSubmissionStatus::Submitted,
                    WitnessReconciliationStatus::Confirmed,
                    WitnessReservationState::Consumed,
                ),
                _ => return Err(AgentWalletError::InvalidOperationState),
            };
        let anchor = RollbackAnchor {
            anchor_version: 2,
            anchor_id: format!("anchor_{}", uuid::Uuid::new_v4()),
            agent_wallet_id: wallet_id.to_string(),
            desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            mobile_device_id: mobile_device_id.clone(),
            desktop_authorization_epoch: state.signer_epoch,
            mobile_authorization_epoch: mobile.authorization_epoch,
            network_id: node.network_kind().to_owned(),
            genesis_identifier: state.block_one_fingerprint.clone(),
            node_profile_id: node.node_profile_id().to_owned(),
            transaction_format_version: node.transaction_format_version(),
            signer_epoch: state.signer_epoch,
            journal_epoch: JOURNAL_EPOCH,
            witness_epoch: witness.witness_epoch,
            anchor_sequence,
            previous_anchor_hash: witness.last_anchor_hash.clone(),
            journal_sequence: state.journal_sequence,
            journal_head_hash: state.journal_head_hash.clone(),
            materialized_state_commitment: hex::encode(state_commitment(&state)?.as_bytes()),
            last_operation_id: Some(operation_id.to_string()),
            operation_phase,
            transaction_state: Some(WitnessTransactionState {
                operation_id: operation_id.to_string(),
                agent_id: operation_view.agent_id.to_string(),
                signed_transaction_commitment: operation.signed_transaction_commitment()?,
                transaction_id: operation_view.tx_hash,
                submission_status,
                reconciliation_status,
                block_height: None,
                block_hash: None,
                reservation_state,
            }),
            policy_epoch: state.policy_epoch,
            capability_epoch: CAPABILITY_EPOCH,
            created_at: now,
            expires_at: now.saturating_add(ANCHOR_LIFETIME_SECS),
        };
        let proposal = SignedRollbackAnchor::sign(anchor, &signer)
            .await
            .map_err(|_| AgentWalletError::Crypto)?;
        proposal
            .verify(&registry, now)
            .map_err(|_| AgentWalletError::Crypto)?;
        state
            .rollback_witness
            .as_mut()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?
            .pending = Some(AuthenticatedPendingWitness {
            operation_id: operation_id.to_string(),
            proposal: proposal.clone(),
            receipt: None,
        });
        state.updated_at = now;
        let proposal_event = match operation_phase {
            RollbackOperationPhase::SignedPreBroadcast => {
                AgentJournalEventKind::RollbackWitnessProposed
            }
            RollbackOperationPhase::Submitted => AgentJournalEventKind::PostSubmitWitnessProposed,
            RollbackOperationPhase::ReconciledFinal => AgentJournalEventKind::FinalWitnessProposed,
            _ => return Err(AgentWalletError::InvalidOperationState),
        };
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            proposal_event,
            Some(operation_id.as_str().as_bytes()),
            Some(mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(proposal)
    }

    pub async fn apply_mobile_witness_and_broadcast(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedWitnessReceipt,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;

        if let Some(completed) = &witness.last_completed
            && completed.receipt == signed
        {
            let operation_id = OperationId::parse(completed.operation_id.clone())?;
            let operation = state
                .operations
                .get(operation_id.as_str())
                .ok_or(AgentWalletError::OperationNotFound)?;
            return Ok(operation.view());
        }

        let pending = witness
            .pending
            .as_ref()
            .cloned()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;

        let operation_id = OperationId::parse(pending.operation_id.clone())?;
        let mut status = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status();
        let phase = pending.proposal.anchor.operation_phase;
        if pending.receipt.is_none() {
            let signer = session.desktop_companion_signer.clone();
            let registry = composite_registry(&state, &signer, now)?;
            signed
                .verify(&pending.proposal, &registry, now)
                .map_err(|_| AgentWalletError::RollbackDetected)?;
            let anchor_hash = pending
                .proposal
                .anchor
                .canonical_sha256_hex()
                .map_err(|_| AgentWalletError::Crypto)?;
            let witness = state
                .rollback_witness
                .as_mut()
                .ok_or(AgentWalletError::RollbackWitnessRequired)?;
            witness.last_anchor_sequence = pending.proposal.anchor.anchor_sequence;
            witness.last_anchor_hash = anchor_hash;
            witness
                .pending
                .as_mut()
                .ok_or(AgentWalletError::RollbackWitnessRequired)?
                .receipt = Some(signed.clone());
            let mobile_device_id = witness.mobile_device_id.clone();
            if matches!(
                phase,
                RollbackOperationPhase::SignedPreBroadcast
                    | RollbackOperationPhase::SignedAwaitingWitness
            ) {
                state
                    .operations
                    .get_mut(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .mark_witnessed()?;
                status = OperationStatus::WitnessedAwaitingBroadcast;
            }
            state.updated_at = now;
            self.persist_event(
                &mut state,
                &session.state_master,
                &session.journal_key,
                AgentJournalEventKind::RollbackWitnessAccepted,
                Some(operation_id.as_str().as_bytes()),
                Some(mobile_device_id.as_str().as_bytes()),
                now,
            )?;
        } else if pending.receipt.as_ref() != Some(&signed) {
            return Err(AgentWalletError::RollbackDetected);
        }

        match phase {
            RollbackOperationPhase::SignedPreBroadcast
            | RollbackOperationPhase::SignedAwaitingWitness => {
                if status == OperationStatus::WitnessedAwaitingBroadcast {
                    match self.resume_payment(wallet_id, &operation_id, now).await {
                        Ok(result)
                            if matches!(
                                result.status,
                                OperationStatus::SubmittedAwaitingFinalWitness
                                    | OperationStatus::BroadcastSubmitted
                            ) => {}
                        Ok(result) => return Ok(result),
                        Err(AgentWalletError::BroadcastUncertain) => {}
                        Err(error) => return Err(error),
                    }
                }
                self.archive_completed_witness(wallet_id, &operation_id, &signed, now)
            }
            RollbackOperationPhase::Submitted => {
                if !matches!(
                    status,
                    OperationStatus::SubmittedAwaitingFinalWitness
                        | OperationStatus::BroadcastUncertain
                ) {
                    return Err(AgentWalletError::InvalidOperationState);
                }
                self.archive_completed_witness(wallet_id, &operation_id, &signed, now)
            }
            RollbackOperationPhase::ReconciledFinal => {
                if status != OperationStatus::ReconciledAwaitingFinalWitness {
                    return Err(AgentWalletError::InvalidOperationState);
                }
                self.archive_completed_witness(wallet_id, &operation_id, &signed, now)
            }
            _ => Err(AgentWalletError::InvalidOperationState),
        }
    }

    fn archive_completed_witness(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        signed: &SignedWitnessReceipt,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let witness = state
            .rollback_witness
            .as_mut()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        let pending = witness
            .pending
            .take()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        if pending.operation_id != operation_id.as_str() || pending.receipt.as_ref() != Some(signed)
        {
            witness.pending = Some(pending);
            return Err(AgentWalletError::RollbackDetected);
        }
        let phase = pending.proposal.anchor.operation_phase;
        let completed = AuthenticatedCompletedWitness {
            operation_id: pending.operation_id,
            proposal: pending.proposal,
            receipt: signed.clone(),
        };
        if witness.history.len() >= 4_096 {
            witness.pending = Some(AuthenticatedPendingWitness {
                operation_id: completed.operation_id,
                proposal: completed.proposal,
                receipt: Some(completed.receipt),
            });
            return Err(AgentWalletError::RecoveryRequired);
        }
        witness.history.push(completed.clone());
        witness.last_completed = Some(completed);
        let mobile_device_id = witness.mobile_device_id.clone();
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let event = match phase {
            RollbackOperationPhase::SignedPreBroadcast
            | RollbackOperationPhase::SignedAwaitingWitness => {
                if operation.status() == OperationStatus::BroadcastSubmitted {
                    operation.mark_submitted_awaiting_final_witness()?;
                }
                if !matches!(
                    operation.status(),
                    OperationStatus::SubmittedAwaitingFinalWitness
                        | OperationStatus::BroadcastUncertain
                ) {
                    return Err(AgentWalletError::InvalidOperationState);
                }
                AgentJournalEventKind::RollbackWitnessArchived
            }
            RollbackOperationPhase::Submitted => {
                operation.mark_reconciliation_required()?;
                AgentJournalEventKind::PostSubmitWitnessAccepted
            }
            RollbackOperationPhase::ReconciledFinal => {
                operation.mark_committed_after_final_witness()?;
                AgentJournalEventKind::FinalWitnessAccepted
            }
            _ => return Err(AgentWalletError::InvalidOperationState),
        };
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            event,
            Some(operation_id.as_str().as_bytes()),
            Some(mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }
}
