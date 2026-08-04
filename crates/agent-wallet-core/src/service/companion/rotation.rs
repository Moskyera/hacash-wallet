use hpay_companion_protocol::{
    DeviceId, DevicePermission, DevicePublicRecord, DeviceRole, HPAY_LOCAL_PILOT_NETWORK_ID,
    RollbackAnchor, RollbackOperationPhase, RotationPairingTicket, SignedRollbackAnchor,
    SignedRotationCandidateAcceptance, SignedRotationPairingTicket, SignedWitnessReceipt,
    SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt, WitnessRotationMode,
    WitnessRotationPhase, WitnessRotationReason, WitnessRotationRecord,
};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::node_binding::verified_agent_node;
use crate::operation::OperationStatus;
use crate::types::AgentWalletId;

use super::super::state::state_commitment;
use super::super::{AgentWalletManager, AgentWalletState, AuthenticatedWitnessRotationState};
use super::session::composite_registry;

const JOURNAL_EPOCH: u64 = 1;
const CAPABILITY_EPOCH: u64 = 1;
const ROTATION_LIFETIME_SECS: u64 = 15 * 60;

impl AuthenticatedWitnessRotationState {
    pub(crate) fn validate_completed_history(
        &self,
        state: &AgentWalletState,
    ) -> AgentWalletResult<()> {
        if self.phase != WitnessRotationPhase::Completed
            || self.record.agent_wallet_id != state.wallet_id.as_str()
            || self.record.desktop_device_id.as_str() != state.primary_signing_device_id
            || self.record.network_id != HPAY_LOCAL_PILOT_NETWORK_ID
            || self.record.genesis_identifier != state.block_one_fingerprint
            || self.record.journal_epoch != JOURNAL_EPOCH
            || self.record.old_mobile_device_id == self.record.new_mobile_device_id
            || self.record.new_witness_epoch
                != self
                    .record
                    .old_witness_epoch
                    .checked_add(1)
                    .ok_or(AgentWalletError::IntegerOverflow)?
            || self.new_mobile_baseline.is_none()
            || self.candidate_device.is_none()
            || self.candidate_acceptance.is_none()
            || self.ticket_consumed_at.is_none()
            || self.completion_anchor.is_none()
            || self.completion_receipt.is_none()
            || (self.record.rotation_mode == WitnessRotationMode::Normal
                && !self
                    .old_mobile_authorization
                    .as_ref()
                    .is_some_and(|value| value.rotation == self.record))
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let baseline = self
            .new_mobile_baseline
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let anchor = self
            .completion_anchor
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let receipt = self
            .completion_receipt
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let candidate = self
            .candidate_device
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if baseline.receipt.rotation_id != self.record.rotation_id
            || baseline.receipt.agent_wallet_id != self.record.agent_wallet_id
            || baseline.receipt.new_mobile_device_id != candidate.device_id
            || baseline.receipt.witness_epoch != self.record.new_witness_epoch
            || anchor.anchor.agent_wallet_id != self.record.agent_wallet_id
            || anchor.anchor.mobile_device_id != candidate.device_id
            || anchor.anchor.witness_epoch != self.record.new_witness_epoch
            || receipt.receipt.anchor_id != anchor.anchor.anchor_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }

    pub(crate) fn validate(&self, state: &AgentWalletState) -> AgentWalletResult<()> {
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if self.record.agent_wallet_id != state.wallet_id.as_str()
            || self.record.desktop_device_id.as_str() != state.primary_signing_device_id
            || self.record.network_id != HPAY_LOCAL_PILOT_NETWORK_ID
            || self.record.genesis_identifier != state.block_one_fingerprint
            || self.record.signer_epoch != state.signer_epoch
            || self.record.journal_epoch != JOURNAL_EPOCH
            || self.record.policy_epoch != state.policy_epoch
            || self.record.old_mobile_device_id == self.record.new_mobile_device_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let completed = self.phase == WitnessRotationPhase::Completed;
        let authority_transitioned = matches!(
            self.phase,
            WitnessRotationPhase::CandidateBaselineVerified
                | WitnessRotationPhase::AwaitingOldDeviceRevocation
                | WitnessRotationPhase::AwaitingCompletionAnchor
                | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                | WitnessRotationPhase::Completed
        );
        let candidate = self.candidate_device.as_ref();
        let expected_mobile = if completed {
            &candidate
                .ok_or(AgentWalletError::RecoveryRequired)?
                .device_id
        } else {
            &self.record.old_mobile_device_id
        };
        let expected_epoch = if authority_transitioned {
            self.record.new_witness_epoch
        } else {
            self.record.old_witness_epoch
        };
        if &witness.mobile_device_id != expected_mobile || witness.witness_epoch != expected_epoch {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let normal_authorization_valid = self.record.rotation_mode != WitnessRotationMode::Normal
            || matches!(
                self.phase,
                WitnessRotationPhase::AwaitingOldWitnessAuthorization
            )
            || self
                .old_mobile_authorization
                .as_ref()
                .is_some_and(|signed| signed.rotation == self.record);
        let baseline_required = matches!(
            self.phase,
            WitnessRotationPhase::CandidateBaselineVerified
                | WitnessRotationPhase::AwaitingOldDeviceRevocation
                | WitnessRotationPhase::AwaitingCompletionAnchor
                | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                | WitnessRotationPhase::Completed
        );
        if !normal_authorization_valid
            || (baseline_required && self.new_mobile_baseline.is_none())
            || (self.phase == WitnessRotationPhase::Completed
                && (self.completion_anchor.is_none() || self.completion_receipt.is_none()))
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(anchor) = &self.completion_anchor
            && (anchor.anchor.agent_wallet_id != state.wallet_id.as_str()
                || anchor.anchor.mobile_device_id
                    != candidate
                        .ok_or(AgentWalletError::RecoveryRequired)?
                        .device_id
                || anchor.anchor.witness_epoch != self.record.new_witness_epoch
                || anchor.anchor.operation_phase != RollbackOperationPhase::WalletState
                || anchor.anchor.transaction_state.is_some())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }
}

impl AgentWalletManager {
    pub fn current_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<WitnessRotationRecord>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(state
            .witness_rotation
            .as_ref()
            .map(|rotation| rotation.record.clone()))
    }

    pub fn witness_rotation_step_for_device(
        &mut self,
        wallet_id: &AgentWalletId,
        mobile_device_id: &DeviceId,
        requested_rotation_id: Option<&str>,
        now: u64,
    ) -> AgentWalletResult<(WitnessRotationPhase, WitnessRotationRecord)> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let candidate_id = rotation
            .candidate_device
            .as_ref()
            .map(|record| &record.device_id);
        if requested_rotation_id.is_some_and(|value| value != rotation.record.rotation_id)
            || (mobile_device_id != &rotation.record.old_mobile_device_id
                && candidate_id != Some(mobile_device_id))
        {
            return Err(AgentWalletError::RotationDeviceNotInRotation);
        }
        let record = if candidate_id == Some(mobile_device_id) {
            candidate_bound_record(
                &rotation.record,
                rotation
                    .candidate_device
                    .as_ref()
                    .ok_or(AgentWalletError::RecoveryRequired)?,
            )
        } else {
            rotation.record.clone()
        };
        Ok((rotation.phase, record))
    }

    pub fn is_restricted_rotation_candidate(
        &mut self,
        wallet_id: &AgentWalletId,
        mobile_device_id: &DeviceId,
        now: u64,
    ) -> AgentWalletResult<bool> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(state.witness_rotation.as_ref().is_some_and(|rotation| {
            rotation
                .candidate_device
                .as_ref()
                .is_some_and(|candidate| candidate.device_id == *mobile_device_id)
                && rotation.ticket_consumed_at.is_some()
                && rotation.candidate_acceptance.is_some()
                && matches!(
                    rotation.phase,
                    WitnessRotationPhase::CandidatePairedRestricted
                        | WitnessRotationPhase::CandidateBaselineVerified
                        | WitnessRotationPhase::AwaitingOldDeviceRevocation
                        | WitnessRotationPhase::AwaitingCompletionAnchor
                        | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                )
        }))
    }

    pub fn has_restricted_rotation_candidate(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<bool> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(state.witness_rotation.as_ref().is_some_and(|rotation| {
            rotation.candidate_device.is_some()
                && rotation.candidate_acceptance.is_some()
                && rotation.ticket_consumed_at.is_some()
                && matches!(
                    rotation.phase,
                    WitnessRotationPhase::CandidatePairedRestricted
                        | WitnessRotationPhase::CandidateBaselineVerified
                        | WitnessRotationPhase::AwaitingOldDeviceRevocation
                        | WitnessRotationPhase::AwaitingCompletionAnchor
                        | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                )
        }))
    }

    pub fn cancel_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        if rotation.record.rotation_id != rotation_id {
            return Err(AgentWalletError::IdempotencyConflict);
        }
        if !matches!(
            rotation.phase,
            WitnessRotationPhase::RotationRequested
                | WitnessRotationPhase::AwaitingOldWitnessAuthorization
                | WitnessRotationPhase::AwaitingCandidatePairing
                | WitnessRotationPhase::RotationTicketIssued
                | WitnessRotationPhase::CandidatePairedRestricted
        ) || rotation.new_mobile_baseline.is_some()
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        if witness.mobile_device_id != rotation.record.old_mobile_device_id
            || witness.witness_epoch != rotation.record.old_witness_epoch
            || witness.pending.is_some()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let old_mobile = state
            .companion_security
            .as_ref()
            .ok_or(AgentWalletError::RotationOldDeviceNotRegistered)?
            .device_registry
            .records()
            .find(|record| record.device_id == rotation.record.old_mobile_device_id)
            .ok_or(AgentWalletError::RotationOldDeviceNotRegistered)?;
        if old_mobile.is_revoked() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let candidate_id = rotation
            .candidate_device
            .as_ref()
            .map(|candidate| candidate.device_id.as_str().as_bytes().to_vec())
            .unwrap_or_else(|| {
                rotation
                    .record
                    .new_mobile_device_id
                    .as_str()
                    .as_bytes()
                    .to_vec()
            });
        state.witness_rotation = None;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationCancelled,
            None,
            Some(&candidate_id),
            now,
        )?;
        Ok(())
    }

    pub fn is_pending_witness_rotation_receipt(
        &mut self,
        wallet_id: &AgentWalletId,
        receipt: &SignedWitnessReceipt,
        now: u64,
    ) -> AgentWalletResult<bool> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let Some(rotation) = state.witness_rotation.as_ref() else {
            return Ok(false);
        };
        let Some(anchor) = rotation.completion_anchor.as_ref() else {
            return Ok(false);
        };
        let anchor_hash = anchor
            .anchor
            .canonical_sha256_hex()
            .map_err(|_| AgentWalletError::Crypto)?;
        Ok(matches!(
            rotation.phase,
            WitnessRotationPhase::AwaitingCompletionAnchor
                | WitnessRotationPhase::AwaitingRotationCompletionAnchor
        ) && receipt.receipt.anchor_id == anchor.anchor.anchor_id
            && receipt.receipt.anchor_hash == anchor_hash)
    }

    pub async fn prepare_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: String,
        candidate_slot_id: &DeviceId,
        mode: WitnessRotationMode,
        reason: WitnessRotationReason,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if state.network_mode != "testnet" {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        if let Some(existing) = &state.witness_rotation {
            if existing.record.rotation_id == rotation_id
                && &existing.record.new_mobile_device_id == candidate_slot_id
                && existing.record.rotation_mode == mode
                && existing.record.rotation_reason == reason
            {
                return Ok(existing.record.clone());
            }
            if existing.phase != WitnessRotationPhase::Completed {
                return Err(AgentWalletError::IdempotencyConflict);
            }
        }
        if state.witness_rotation.is_some() {
            if state.witness_rotation_history.len() >= 4_096 {
                return Err(AgentWalletError::RecoveryRequired);
            }
            let completed = state
                .witness_rotation
                .take()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            completed.validate_completed_history(&state)?;
            state.witness_rotation_history.push(completed);
        }
        if state.operations.values().any(|operation| {
            operation.status().retains_reservation()
                || matches!(
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
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        if witness.pending.is_some() {
            return Err(AgentWalletError::RollbackWitnessRequired);
        }
        let signer = session.desktop_companion_signer.clone();
        let registry = composite_registry(&state, &signer, now)?;
        let old_record = registry
            .require(
                &witness.mobile_device_id,
                wallet_id.as_str(),
                DeviceRole::Mobile,
                DevicePermission::WitnessRollbackAnchor,
            )
            .map_err(|_| AgentWalletError::RotationOldDeviceNotAuthorized)?;
        if mode == WitnessRotationMode::LostPhoneRecovery {
            verified_agent_node(
                &state.node_url,
                &state.network_mode,
                &state.block_one_fingerprint,
            )
            .await?;
        }
        if &witness.mobile_device_id == candidate_slot_id {
            return Err(AgentWalletError::RotationCandidateIsCurrentDevice);
        }
        let record = WitnessRotationRecord {
            rotation_version: 1,
            rotation_id,
            agent_wallet_id: wallet_id.to_string(),
            desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            old_mobile_device_id: witness.mobile_device_id.clone(),
            new_mobile_device_id: candidate_slot_id.clone(),
            network_id: HPAY_LOCAL_PILOT_NETWORK_ID.to_owned(),
            genesis_identifier: state.block_one_fingerprint.clone(),
            signer_epoch: state.signer_epoch,
            journal_epoch: JOURNAL_EPOCH,
            old_witness_epoch: witness.witness_epoch,
            new_witness_epoch: witness
                .witness_epoch
                .checked_add(1)
                .ok_or(AgentWalletError::IntegerOverflow)?,
            old_mobile_authorization_epoch: old_record.authorization_epoch,
            new_mobile_authorization_epoch: 1,
            last_accepted_anchor_sequence: witness.last_anchor_sequence,
            last_accepted_anchor_hash: witness.last_anchor_hash.clone(),
            journal_sequence: state.journal_sequence,
            journal_head_hash: state.journal_head_hash.clone(),
            policy_epoch: state.policy_epoch,
            rotation_reason: reason,
            rotation_mode: mode,
            created_at: now,
            expires_at: now.saturating_add(ROTATION_LIFETIME_SECS),
        };
        record
            .canonical_bytes()
            .map_err(|_| AgentWalletError::Crypto)?;
        let phase = if mode == WitnessRotationMode::Normal {
            WitnessRotationPhase::AwaitingOldWitnessAuthorization
        } else {
            WitnessRotationPhase::AwaitingCandidatePairing
        };
        state.witness_rotation = Some(AuthenticatedWitnessRotationState {
            phase,
            record: record.clone(),
            old_mobile_authorization: None,
            pairing_ticket: None,
            candidate_device: None,
            candidate_acceptance: None,
            ticket_consumed_at: None,
            new_mobile_baseline: None,
            completion_anchor: None,
            completion_receipt: None,
        });
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            if mode == WitnessRotationMode::Normal {
                AgentJournalEventKind::WitnessRotationPrepared
            } else {
                AgentJournalEventKind::WitnessRecoveryRotationPrepared
            },
            None,
            Some(candidate_slot_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }

    pub fn authorize_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedWitnessRotationAuthorization,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.phase != WitnessRotationPhase::AwaitingOldWitnessAuthorization
            || signed.rotation != rotation.record
        {
            return Err(AgentWalletError::RotationAuthorizationMismatch);
        }
        let signer = session.desktop_companion_signer.clone();
        let registry = composite_registry(&state, &signer, now)?;
        signed
            .verify(&registry, now)
            .map_err(|_| AgentWalletError::RotationAuthorizationSignatureInvalid)?;
        let record = signed.rotation.clone();
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.old_mobile_authorization = Some(signed);
        rotation.phase = WitnessRotationPhase::AwaitingCandidatePairing;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationAuthorized,
            None,
            Some(record.old_mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }

    pub(crate) fn require_rotation_candidate_pairing(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.record.rotation_id != rotation_id
            || rotation.phase != WitnessRotationPhase::AwaitingCandidatePairing
            || rotation.pairing_ticket.is_some()
            || rotation.candidate_device.is_some()
            || rotation.candidate_acceptance.is_some()
            || rotation.ticket_consumed_at.is_some()
            || (rotation.record.rotation_mode == WitnessRotationMode::Normal
                && rotation.old_mobile_authorization.is_none())
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        Ok(())
    }

    pub(crate) async fn issue_rotation_pairing_ticket(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        pairing_id: String,
        candidate: DevicePublicRecord,
        now: u64,
        pairing_expires_at: u64,
    ) -> AgentWalletResult<SignedRotationPairingTicket> {
        self.require_rotation_candidate_pairing(wallet_id, rotation_id, now)?;
        candidate
            .validate()
            .map_err(|_| AgentWalletError::RotationCandidateRecordInvalid)?;
        if candidate.role != DeviceRole::Mobile
            || candidate.agent_wallet_id != wallet_id.as_str()
            || candidate.is_revoked()
        {
            return Err(AgentWalletError::RotationCandidateNotEligible);
        }
        let session = self.session(wallet_id)?;
        let signer = session.desktop_companion_signer.clone();
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let registry = composite_registry(&state, &signer, now)?;
        if registry
            .records()
            .any(|record| record.device_id == candidate.device_id)
        {
            return Err(AgentWalletError::RotationCandidateAlreadyRegistered);
        }
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if candidate.device_id == rotation.record.old_mobile_device_id {
            return Err(AgentWalletError::RotationCandidateIsCurrentDevice);
        }
        let old_commitment = rotation
            .old_mobile_authorization
            .as_ref()
            .map(|authorization| authorization.authorization_commitment())
            .transpose()
            .map_err(|_| AgentWalletError::Crypto)?;
        if rotation.record.rotation_mode == WitnessRotationMode::Normal && old_commitment.is_none()
        {
            return Err(AgentWalletError::RotationOldDeviceApprovalMissing);
        }
        let ticket = RotationPairingTicket {
            ticket_version: 1,
            ticket_id: format!("rotation_ticket_{}", uuid::Uuid::new_v4().simple()),
            pairing_id,
            rotation_id: rotation.record.rotation_id.clone(),
            agent_wallet_id: wallet_id.to_string(),
            desktop_device_id: rotation.record.desktop_device_id.clone(),
            old_mobile_device_id: rotation.record.old_mobile_device_id.clone(),
            expected_candidate_device_id: candidate.device_id.clone(),
            expected_candidate_identity_fingerprint: candidate.identity_fingerprint.clone(),
            network_id: rotation.record.network_id.clone(),
            genesis_identifier: rotation.record.genesis_identifier.clone(),
            current_witness_epoch: rotation.record.old_witness_epoch,
            next_witness_epoch: rotation.record.new_witness_epoch,
            current_mobile_authorization_epoch: rotation.record.old_mobile_authorization_epoch,
            next_mobile_authorization_epoch: candidate.authorization_epoch,
            latest_anchor_sequence: rotation.record.last_accepted_anchor_sequence,
            latest_anchor_hash: rotation.record.last_accepted_anchor_hash.clone(),
            journal_sequence: rotation.record.journal_sequence,
            journal_head_hash: rotation.record.journal_head_hash.clone(),
            policy_epoch: rotation.record.policy_epoch,
            old_mobile_authorization_commitment: old_commitment,
            single_use_nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at: now,
            expires_at: pairing_expires_at.min(now.saturating_add(5 * 60)),
        };
        let signed = SignedRotationPairingTicket::sign(ticket, &signer)
            .await
            .map_err(|_| AgentWalletError::Crypto)?;
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.pairing_ticket = Some(signed.clone());
        rotation.candidate_device = Some(candidate);
        rotation.phase = WitnessRotationPhase::RotationTicketIssued;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationTicketIssued,
            None,
            Some(signed.ticket.ticket_id.as_bytes()),
            now,
        )?;
        Ok(signed)
    }

    pub(crate) fn accept_rotation_candidate(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        candidate: DevicePublicRecord,
        signed_acceptance: SignedRotationCandidateAcceptance,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let signer = session.desktop_companion_signer.clone();
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let registry = composite_registry(&state, &signer, now)?;
        let desktop = registry
            .records()
            .find(|record| record.device_id.as_str() == state.primary_signing_device_id)
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.record.rotation_id != rotation_id
            || rotation.phase != WitnessRotationPhase::RotationTicketIssued
            || rotation.ticket_consumed_at.is_some()
            || rotation.candidate_device.as_ref() != Some(&candidate)
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let ticket = rotation
            .pairing_ticket
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        ticket
            .verify(desktop, now)
            .map_err(|_| AgentWalletError::RotationTicketInvalid)?;
        signed_acceptance
            .verify(ticket, &candidate, now)
            .map_err(|_| AgentWalletError::RotationCandidateAcceptanceInvalid)?;
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.candidate_acceptance = Some(signed_acceptance);
        rotation.ticket_consumed_at = Some(now);
        rotation.phase = WitnessRotationPhase::CandidatePairedRestricted;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationCandidateAccepted,
            None,
            Some(candidate.device_id.as_str().as_bytes()),
            now,
        )
    }

    pub fn accept_witness_rotation_baseline(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedWitnessRotationBaselineReceipt,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.phase != WitnessRotationPhase::CandidatePairedRestricted {
            if rotation
                .new_mobile_baseline
                .as_ref()
                .is_some_and(|existing| existing == &signed)
            {
                return Ok(rotation.record.clone());
            }
            return Err(AgentWalletError::InvalidOperationState);
        }
        if rotation.record.rotation_mode == WitnessRotationMode::Normal
            && rotation.old_mobile_authorization.is_none()
        {
            return Err(AgentWalletError::RotationOldDeviceApprovalMissing);
        }
        let signer = session.desktop_companion_signer.clone();
        let mut registry = composite_registry(&state, &signer, now)?;
        let candidate = rotation
            .candidate_device
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .clone();
        registry
            .register(candidate.clone())
            .map_err(|_| AgentWalletError::RotationCandidateAlreadyRegistered)?;
        let bound_record = candidate_bound_record(&rotation.record, &candidate);
        signed
            .verify(&bound_record, &registry, now)
            .map_err(|_| AgentWalletError::RotationBaselineReceiptInvalid)?;
        let record = rotation.record.clone();
        let baseline_already_durable = rotation.new_mobile_baseline.as_ref() == Some(&signed);
        if rotation.new_mobile_baseline.is_some() && !baseline_already_durable {
            return Err(AgentWalletError::RotationBaselineAlreadyRecorded);
        }
        if !baseline_already_durable {
            state
                .witness_rotation
                .as_mut()
                .ok_or(AgentWalletError::RecoveryRequired)?
                .new_mobile_baseline = Some(signed);
            state.updated_at = now;
            self.persist_event(
                &mut state,
                &session.state_master,
                &session.journal_key,
                AgentJournalEventKind::WitnessRotationBaselineAccepted,
                None,
                Some(candidate.device_id.as_str().as_bytes()),
                now,
            )?;
        }

        state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RotationOldDeviceRevokeFailed)?
            .device_registry
            .revoke(&record.old_mobile_device_id, now)
            .map_err(|_| AgentWalletError::RotationOldDeviceRevokeFailed)?;
        let witness = state
            .rollback_witness
            .as_mut()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.witness_epoch = record.new_witness_epoch;
        witness.pending = None;
        state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .phase = WitnessRotationPhase::AwaitingCompletionAnchor;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationOldDeviceRevoked,
            None,
            Some(record.old_mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }

    pub async fn pending_witness_rotation_completion_anchor(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        now: u64,
    ) -> AgentWalletResult<SignedRollbackAnchor> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let signer = session.desktop_companion_signer.clone();
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.record.rotation_id != rotation_id
            || !matches!(
                rotation.phase,
                WitnessRotationPhase::AwaitingCompletionAnchor
                    | WitnessRotationPhase::AwaitingRotationCompletionAnchor
            )
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        if let Some(existing) = &rotation.completion_anchor {
            return Ok(existing.clone());
        }
        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        let mut registry = composite_registry(&state, &signer, now)?;
        let candidate = rotation
            .candidate_device
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .clone();
        registry
            .register(candidate.clone())
            .map_err(|_| AgentWalletError::RotationCandidateAlreadyRegistered)?;
        let mobile = registry
            .require(
                &candidate.device_id,
                wallet_id.as_str(),
                DeviceRole::Mobile,
                DevicePermission::WitnessRollbackAnchor,
            )
            .map_err(|_| AgentWalletError::RotationCandidateNotAuthorized)?;
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        let anchor = RollbackAnchor {
            anchor_version: 1,
            anchor_id: format!("rotation_anchor_{}", uuid::Uuid::new_v4()),
            agent_wallet_id: wallet_id.to_string(),
            desktop_device_id: rotation.record.desktop_device_id.clone(),
            mobile_device_id: candidate.device_id.clone(),
            desktop_authorization_epoch: state.signer_epoch,
            mobile_authorization_epoch: mobile.authorization_epoch,
            network_id: node.network_kind().to_owned(),
            genesis_identifier: state.block_one_fingerprint.clone(),
            node_profile_id: node.node_profile_id().to_owned(),
            transaction_format_version: node.transaction_format_version(),
            signer_epoch: state.signer_epoch,
            journal_epoch: JOURNAL_EPOCH,
            witness_epoch: witness.witness_epoch,
            anchor_sequence: witness
                .last_anchor_sequence
                .checked_add(1)
                .ok_or(AgentWalletError::RollbackDetected)?,
            previous_anchor_hash: witness.last_anchor_hash.clone(),
            journal_sequence: state.journal_sequence,
            journal_head_hash: state.journal_head_hash.clone(),
            materialized_state_commitment: hex::encode(state_commitment(&state)?.as_bytes()),
            last_operation_id: None,
            operation_phase: RollbackOperationPhase::WalletState,
            transaction_state: None,
            policy_epoch: state.policy_epoch,
            capability_epoch: CAPABILITY_EPOCH,
            created_at: now,
            expires_at: now.saturating_add(5 * 60),
        };
        let signed = SignedRollbackAnchor::sign(anchor, &signer)
            .await
            .map_err(|_| AgentWalletError::Crypto)?;
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.completion_anchor = Some(signed.clone());
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationCompletionProposed,
            None,
            Some(signed.anchor.mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(signed)
    }

    pub fn complete_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedWitnessReceipt,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if rotation.phase == WitnessRotationPhase::Completed
            && rotation.completion_receipt.as_ref() == Some(&signed)
        {
            return Ok(rotation.record.clone());
        }
        if !matches!(
            rotation.phase,
            WitnessRotationPhase::AwaitingCompletionAnchor
                | WitnessRotationPhase::AwaitingRotationCompletionAnchor
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let proposal = rotation
            .completion_anchor
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?
            .clone();
        let signer = session.desktop_companion_signer.clone();
        let mut registry = composite_registry(&state, &signer, now)?;
        let candidate = rotation
            .candidate_device
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .clone();
        registry
            .register(candidate.clone())
            .map_err(|_| AgentWalletError::RotationCandidateAlreadyRegistered)?;
        signed
            .verify(&proposal, &registry, now)
            .map_err(|_| AgentWalletError::RollbackDetected)?;
        let anchor_hash = proposal
            .anchor
            .canonical_sha256_hex()
            .map_err(|_| AgentWalletError::Crypto)?;
        let witness = state
            .rollback_witness
            .as_mut()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.last_anchor_sequence = proposal.anchor.anchor_sequence;
        witness.last_anchor_hash = anchor_hash;
        witness.mobile_device_id = candidate.device_id.clone();
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        companion
            .device_registry
            .register(candidate.clone())
            .map_err(|_| AgentWalletError::RotationCandidateRegistrationFailed)?;
        let record = rotation.record.clone();
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.completion_receipt = Some(signed);
        rotation.phase = WitnessRotationPhase::Completed;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationCompleted,
            None,
            Some(candidate.device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }
}

fn candidate_bound_record(
    record: &WitnessRotationRecord,
    candidate: &DevicePublicRecord,
) -> WitnessRotationRecord {
    let mut bound = record.clone();
    bound.new_mobile_device_id = candidate.device_id.clone();
    bound.new_mobile_authorization_epoch = candidate.authorization_epoch;
    bound
}
