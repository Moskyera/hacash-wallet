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

/// An operation in this state stops the witness pin from being moved.
///
/// Stated once and asked twice - by `prepare_witness_rotation` and by
/// `retarget_preconditions` - because two copies of this list is exactly how a
/// rotation becomes reachable at one door and refused at the next.
pub(super) const fn blocks_witness_rotation(status: OperationStatus) -> bool {
    status.retains_reservation()
        || matches!(
            status,
            OperationStatus::SignedAwaitingWitness
                | OperationStatus::WitnessedAwaitingBroadcast
                | OperationStatus::BroadcastSubmitted
                | OperationStatus::BroadcastUncertain
                | OperationStatus::SubmittedAwaitingFinalWitness
                | OperationStatus::ReconciliationRequired
                | OperationStatus::ReconciledAwaitingFinalWitness
                | OperationStatus::RecoveryRequired
        )
}

/// The one operation that is holding the whole wallet open with nothing
/// outstanding that could ever resolve it, when that is the ONLY thing blocking
/// a phone replacement. `None` means rotation is blocked for some other reason,
/// or is not blocked at all.
///
/// WHY THIS EXISTS. Re-issuing a dead anchor is the recovery in every phase that
/// issues one, and it works whenever the phone has not already consumed that
/// chain position. A phone that DID durably accept the dead anchor before the
/// exchange broke has advanced its own `last_anchor_sequence` past it, and the
/// desktop's replacement - correctly, honestly - sits on the same position, so
/// that phone refuses it with `RollbackDetected`. Nobody is misbehaving and the
/// anti-rollback rule must not be weakened to paper over it. The only thing that
/// resets a phone which has run ahead is a new witness epoch, which is to say a
/// rotation.
///
/// Rotation was refused outright while any operation sat in the witness
/// lifecycle. Pre-broadcast the owner could abandon the payment and then rotate,
/// which costs one payment and no money because a `SignedAwaitingWitness`
/// payment provably never reached the node. POST-SUBMIT the money has already
/// moved, `abandon_stranded_witness_operation` is refused for exactly that
/// reason and must stay refused, and that left the owner with no exit of any
/// kind: no further payment, no rotation, and a real transaction on the network
/// that the wallet could never finish accounting for.
///
/// So this admits rotation, and only rotation, from exactly that dead end:
///   * one operation, and no other, is blocking anything at all;
///   * it is `SignedAwaitingWitness`, the pre-broadcast phase; and
///   * the single pending slot is empty, so nothing is outstanding that could
///     still become a witness for it.
///
/// WHY ONLY THE PRE-BROADCAST PHASE, EXECUTED RATHER THAN ASSUMED. A rotated-in
/// phone starts from `MobileWitnessState::from_rotation_baseline`, which carries
/// a chain position and no transaction state, because `WitnessRotationRecord`
/// has no transaction-state field. A phone with no `last_transaction_state`
/// refuses every anchor whose phase is not `SignedPreBroadcast`
/// (`crates/companion-protocol/src/witness.rs:1046`), and that rule is what
/// stops a desktop from handing a freshly paired handset a "this was already
/// submitted, sign here" claim it has no way to check. So a rotation can rescue
/// the pre-broadcast dead end completely and can rescue a post-submit one not at
/// all: admitting it there would burn the owner's old phone and leave the
/// payment exactly as stuck. It is refused there for that reason and not
/// because post-submit is safe - it is not, and the residue is documented in
/// `witness_phase_expiry.rs`.
///
/// The empty-slot condition is deliberately the strict one. A dead anchor still
/// sitting in the slot is not admitted here; the owner drops it first, with
/// `release_dead_witness_anchor`, which is the step that proves it dead. That
/// keeps this a single unconditional gate, keeps rotation from ever discarding a
/// proposal on the owner's behalf, and leaves the refusal an owner already sees
/// while an anchor is outstanding exactly as it was.
///
/// WHAT IT COSTS AND WHAT IT PRESERVES. Nothing here touches the operation. Its
/// status, its `tx_hash` and its reservation are exactly as they were, so
/// nothing says or implies the payment did not happen, and the payment is kept
/// rather than given up. It moves no money and submits nothing. After the
/// rotation the payment is still unwitnessed and still needs a real signature
/// from the NEW phone over a real anchor before it can advance one step - the
/// witness requirement is untouched, it is only the handset that may change.
pub(super) fn witness_dead_end(state: &AgentWalletState) -> Option<&str> {
    let mut blocking = state
        .operations
        .values()
        .filter(|operation| blocks_witness_rotation(operation.status()));
    let operation = blocking.next()?;
    // More than one thing is stuck. This escape is for the single dead end it
    // can reason about completely, and nothing else.
    if blocking.next().is_some() {
        return None;
    }
    if operation.status() != OperationStatus::SignedAwaitingWitness {
        return None;
    }
    // Something is still outstanding that could become a witness: a live anchor
    // the phone may be signing this second, a real receipt the lifecycle owns,
    // or a dead one the owner has not yet been shown and released. Not a dead
    // end, or not yet provably one.
    if state
        .rollback_witness
        .as_ref()
        .is_none_or(|witness| witness.pending.is_some())
    {
        return None;
    }
    Some(operation.operation_id().as_str())
}

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
        cancel_preconditions(&state, rotation)?;
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

    /// Which rotation controls this desktop may actually offer right now.
    ///
    /// The desktop asks instead of guessing from the phase, so a control is
    /// never shown that the core would refuse and never withheld when it is the
    /// only way out. `accept_witness_rotation_baseline` revokes the old phone
    /// and advances the witness epoch in one step, after which the cancel
    /// refuses twice over and only the replacement phone can finish; if that
    /// handset is unavailable the wallet refuses every agent write forever.
    pub fn witness_rotation_controls(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationControls> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let Some(rotation) = state.witness_rotation.as_ref() else {
            return Ok(WitnessRotationControls::default());
        };
        Ok(WitnessRotationControls {
            cancellable: cancel_preconditions(&state, rotation).is_ok(),
            retargetable: retarget_preconditions(&state, rotation).is_ok(),
        })
    }

    /// Points a stranded rotation at a different replacement phone.
    ///
    /// This is the only way out of `AwaitingCompletionAnchor` when the handset
    /// that was paired as the candidate can no longer complete the rotation. It
    /// does not un-revoke the old phone, does not roll the witness epoch back,
    /// does not touch the anchor chain or the journal, and moves no money. It
    /// discards exactly the abandoned candidate's baseline receipt and its
    /// registration: that handset can never serve this wallet again, because the
    /// witness epoch it was admitted at is burned. The caller must say so before
    /// the press.
    ///
    /// The replacement still signs a real baseline and a real completion receipt
    /// over the exact anchor, so the witness guarantee is unchanged.
    pub fn retarget_witness_rotation(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        new_rotation_id: String,
        candidate_slot_id: &DeviceId,
        now: u64,
    ) -> AgentWalletResult<WitnessRotationRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if state.network_mode != "testnet" {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        let rotation = state
            .witness_rotation
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        // An exact retry of the same re-target is idempotent, so a lost response
        // never strands the owner a second time.
        if rotation.record.rotation_id == new_rotation_id {
            if &rotation.record.new_mobile_device_id == candidate_slot_id
                && rotation.phase == WitnessRotationPhase::AwaitingCandidatePairing
            {
                return Ok(rotation.record.clone());
            }
            return Err(AgentWalletError::IdempotencyConflict);
        }
        if rotation.record.rotation_id != rotation_id
            || new_rotation_id.is_empty()
            || state
                .witness_rotation_history
                .iter()
                .any(|entry| entry.record.rotation_id == new_rotation_id)
        {
            return Err(AgentWalletError::IdempotencyConflict);
        }
        retarget_preconditions(&state, rotation)?;
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        if candidate_slot_id == &witness.mobile_device_id
            || rotation
                .candidate_device
                .as_ref()
                .is_some_and(|candidate| &candidate.device_id == candidate_slot_id)
        {
            return Err(AgentWalletError::RotationCandidateIsCurrentDevice);
        }
        let signer = session.desktop_companion_signer.clone();
        let registry = composite_registry(&state, &signer, now)?;
        if registry
            .records()
            .any(|record| &record.device_id == candidate_slot_id)
        {
            return Err(AgentWalletError::RotationCandidateAlreadyRegistered);
        }
        let previous = rotation.record.clone();
        let abandoned_candidate = rotation
            .candidate_device
            .as_ref()
            .map(|candidate| candidate.device_id.clone());
        let record = WitnessRotationRecord {
            rotation_version: 1,
            rotation_id: new_rotation_id,
            agent_wallet_id: wallet_id.to_string(),
            desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            old_mobile_device_id: witness.mobile_device_id.clone(),
            new_mobile_device_id: candidate_slot_id.clone(),
            network_id: HPAY_LOCAL_PILOT_NETWORK_ID.to_owned(),
            genesis_identifier: state.block_one_fingerprint.clone(),
            signer_epoch: state.signer_epoch,
            journal_epoch: JOURNAL_EPOCH,
            // The witness epoch already advanced when the abandoned candidate's
            // baseline was accepted. It is never rolled back: the new attempt
            // starts from the epoch the wallet is actually at, so the abandoned
            // candidate's epoch can never be admitted again.
            old_witness_epoch: witness.witness_epoch,
            new_witness_epoch: witness
                .witness_epoch
                .checked_add(1)
                .ok_or(AgentWalletError::IntegerOverflow)?,
            old_mobile_authorization_epoch: previous.old_mobile_authorization_epoch,
            new_mobile_authorization_epoch: 1,
            last_accepted_anchor_sequence: witness.last_anchor_sequence,
            last_accepted_anchor_hash: witness.last_anchor_hash.clone(),
            journal_sequence: state.journal_sequence,
            journal_head_hash: state.journal_head_hash.clone(),
            policy_epoch: state.policy_epoch,
            // The reason is why this attempt exists: the replacement handset is
            // gone. A compromise reason is never downgraded.
            rotation_reason: if previous.rotation_reason == WitnessRotationReason::CompromisedDevice
            {
                WitnessRotationReason::CompromisedDevice
            } else {
                WitnessRotationReason::LostPhone
            },
            // The old phone was revoked by the abandoned attempt, so it can no
            // longer authorize anything. The re-targeted attempt is a recovery
            // rotation in fact, and is recorded as one rather than carrying a
            // stale authorization forward.
            rotation_mode: WitnessRotationMode::LostPhoneRecovery,
            created_at: now,
            expires_at: now.saturating_add(ROTATION_LIFETIME_SECS),
        };
        record
            .canonical_bytes()
            .map_err(|_| AgentWalletError::Crypto)?;
        let rotation = state
            .witness_rotation
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        rotation.phase = WitnessRotationPhase::AwaitingCandidatePairing;
        rotation.record = record.clone();
        rotation.old_mobile_authorization = None;
        rotation.pairing_ticket = None;
        rotation.candidate_device = None;
        rotation.candidate_acceptance = None;
        rotation.ticket_consumed_at = None;
        rotation.new_mobile_baseline = None;
        rotation.completion_anchor = None;
        rotation.completion_receipt = None;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::WitnessRotationRetargeted,
            None,
            Some(
                abandoned_candidate
                    .as_ref()
                    .map(|device| device.as_str())
                    .unwrap_or(previous.rotation_id.as_str())
                    .as_bytes(),
            ),
            now,
        )?;
        Ok(record)
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
        // A payment mid-flight still blocks the replacement, and must: the
        // witness may not be rotated out from under an operation that depends on
        // it. `witness_dead_end` is the one exception, and it is an exception
        // only where that operation can provably never resolve with the phone
        // this wallet is pinned to - see its own note for what that costs.
        if state
            .operations
            .values()
            .any(|operation| blocks_witness_rotation(operation.status()))
            && witness_dead_end(&state).is_none()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        // The dead anchor is dropped first, by `release_dead_witness_anchor`, so
        // that this stays a single unconditional gate. Rotation never discards a
        // proposal on the owner's behalf.
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

        let registry = &mut state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RotationOldDeviceRevokeFailed)?
            .device_registry;
        // The old device is revoked exactly once, but this checkpoint is reached
        // again by a re-targeted rotation (`retarget_witness_rotation`), whose old
        // device was already revoked by the abandoned attempt. `revoke` refuses a
        // second call, so the invariant is asserted rather than re-applied: the
        // device must exist and must end up revoked. Nothing is un-revoked here
        // and an unknown device still fails closed.
        let already_revoked = registry
            .records()
            .find(|device| device.device_id == record.old_mobile_device_id)
            .ok_or(AgentWalletError::RotationOldDeviceRevokeFailed)?
            .is_revoked();
        if !already_revoked {
            registry
                .revoke(&record.old_mobile_device_id, now)
                .map_err(|_| AgentWalletError::RotationOldDeviceRevokeFailed)?;
        }
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

/// Which of the two desktop-only rotation escapes are live right now.
///
/// Both are false by default, so a state this module does not understand offers
/// nothing rather than offering the wrong thing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct WitnessRotationControls {
    /// `cancel_witness_rotation` would succeed: nothing has been discarded and
    /// the old phone is still the witness.
    pub cancellable: bool,
    /// `retarget_witness_rotation` would succeed: the rotation is past the
    /// authority transition, unfinished, and has no other way out.
    pub retargetable: bool,
}

/// The exact conditions under which `cancel_witness_rotation` succeeds.
///
/// Shared with [`AgentWalletManager::witness_rotation_controls`] so the desktop
/// can never offer a cancel that the core refuses. In particular a re-targeted
/// rotation is never cancellable: its old phone is already revoked, so undoing
/// it would leave the wallet naming a revoked witness.
fn cancel_preconditions(
    state: &AgentWalletState,
    rotation: &AuthenticatedWitnessRotationState,
) -> AgentWalletResult<()> {
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
    Ok(())
}

/// True when the rotation's own old phone is already revoked, so
/// [`cancel_preconditions`] can never succeed again at any phase.
///
/// Fail-closed: a device that is not in the registry at all is not reported as
/// revoked, because that is a corrupt state for `validate` to refuse rather
/// than for an escape to paper over.
fn old_mobile_already_revoked(
    state: &AgentWalletState,
    rotation: &AuthenticatedWitnessRotationState,
) -> bool {
    state
        .companion_security
        .as_ref()
        .and_then(|companion| {
            companion
                .device_registry
                .records()
                .find(|record| record.device_id == rotation.record.old_mobile_device_id)
        })
        .is_some_and(|record| record.is_revoked())
}

/// The exact state in which a rotation is stranded and re-targeting is safe.
///
/// Fail-closed on every count: the rotation must be unfinished, must have no
/// ordinary way out, no witness proposal may be outstanding, and no operation
/// may hold funds or sit mid-flight. Nothing here is advisory - the desktop asks
/// the same question before it offers the control.
fn retarget_preconditions(
    state: &AgentWalletState,
    rotation: &AuthenticatedWitnessRotationState,
) -> AgentWalletResult<()> {
    // Past the authority transition the abandoned candidate's baseline is
    // durable and the old phone has been revoked: the classic stranded state.
    let stranded_after_transition = matches!(
        rotation.phase,
        WitnessRotationPhase::AwaitingCompletionAnchor
            | WitnessRotationPhase::AwaitingRotationCompletionAnchor
    );
    // A rotation whose old phone is already revoked - because a previous
    // re-target left it that way, or because the owner revoked it by hand - can
    // never be cancelled again at any phase. If its replacement handset then
    // fails at the pairing step, the ticket cannot be re-issued
    // (`require_rotation_candidate_pairing` refuses once a candidate is bound),
    // so without this the owner would have no control at all: the escape would
    // have created a second dead end one step past the first. Nothing has been
    // discarded at these phases - there is no baseline yet and no witness epoch
    // has been consumed - so re-targeting here costs strictly less than the case
    // above.
    let stranded_mid_pairing = matches!(
        rotation.phase,
        WitnessRotationPhase::RotationTicketIssued
            | WitnessRotationPhase::CandidatePairedRestricted
    ) && rotation.new_mobile_baseline.is_none()
        && old_mobile_already_revoked(state, rotation);
    if (!stranded_after_transition && !stranded_mid_pairing)
        || rotation.completion_receipt.is_some()
    {
        return Err(AgentWalletError::InvalidOperationState);
    }
    let witness = state
        .rollback_witness
        .as_ref()
        .ok_or(AgentWalletError::RollbackWitnessRequired)?;
    if witness.pending.is_some() {
        return Err(AgentWalletError::RollbackWitnessRequired);
    }
    // The same exception `prepare_witness_rotation` makes, asked the same way.
    // A rotation that was admitted out of the witness dead end and then stranded
    // mid-pairing must be re-targetable, or the escape would have built a second
    // dead end one step past the first - which is the exact shape of the defect
    // it exists to remove.
    if state
        .operations
        .values()
        .any(|operation| blocks_witness_rotation(operation.status()))
        && witness_dead_end(state).is_none()
    {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok(())
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
