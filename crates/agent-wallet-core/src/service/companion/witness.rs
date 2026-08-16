//! Authenticated external rollback witness state for the strict testnet pilot.
//!
//! Witness authority lives inside the encrypted, journal-authenticated Agent
//! Wallet state. The paired mobile stores the independent high-water mark.

use hpay_companion_protocol::{
    CompanionError, DeviceId, DevicePermission, DeviceRole, RollbackAnchor, RollbackOperationPhase,
    SignedRollbackAnchor, SignedWitnessReceipt, WitnessReconciliationStatus,
    WitnessReservationState, WitnessRotationPhase, WitnessSubmissionStatus,
    WitnessTransactionState,
};
use serde::{Deserialize, Serialize};

use crate::amount::HacUnits;
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
use super::rotation::witness_dead_end;
use super::session::composite_registry;

/// A payment that is stranded waiting for a phone witness, with the facts the
/// owner needs before pressing anything.
///
/// `amount_units`, `total_debit_units` and `recipient` are here so the desktop
/// can name what is being given up. Nothing in here says a payment is
/// witnessed; a stranded payment is one that never was.
///
/// FOUR statuses reach this shape, not one, and only the first of them is
/// pre-broadcast. In the other three the transaction is already on the network,
/// so `status`, `submitted` and `transaction_id` are here to make that
/// impossible to render as "nothing was sent": the owner is entitled to know
/// their money moved, and to the transaction id that lets them check it against
/// the chain rather than against this wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrandedWitnessRecovery {
    pub operation_id: String,
    pub agent_id: String,
    pub asset: String,
    pub amount_units: HacUnits,
    pub total_debit_units: HacUnits,
    pub recipient: String,
    /// The exact lifecycle status this payment is stuck in.
    pub status: OperationStatus,
    /// The transaction is on the network. From here nothing may say, imply or
    /// arrange for the payment not to have happened.
    pub submitted: bool,
    /// The id of the signed transaction, so the owner can look the payment up
    /// on chain themselves rather than take this wallet's word for it. It
    /// exists from signing onward, so it is NOT the answer to "did the money
    /// move" - `submitted` is. Pre-broadcast this names a transaction that was
    /// never sent.
    pub transaction_id: Option<String>,
    /// An anchor is recorded against this payment. False means none was ever
    /// handed out, or one was and the payment has since been released from it.
    pub anchor_issued: bool,
    pub anchor_expires_at: Option<u64>,
    /// Asking the phone for an anchor again will succeed. A dead anchor is
    /// replaced by a fresh one at the same chain position.
    pub retryable: bool,
    /// `abandon_stranded_witness_operation` will succeed right now. Always false
    /// once the payment has been submitted: giving it up would return the
    /// reservation and mark it `Cancelled`, which would assert the payment did
    /// not happen when it did.
    pub abandonable: bool,
    /// `release_dead_witness_anchor` will succeed right now.
    pub anchor_releasable: bool,
    /// This payment no longer blocks `prepare_witness_rotation`, so replacing
    /// the phone is available and will KEEP the payment rather than give it up.
    /// That is the only exit when the phone itself has run ahead of this
    /// desktop and can never sign for this payment again.
    ///
    /// It is only ever true pre-broadcast. A rotated-in phone baselines with no
    /// transaction state and therefore refuses any anchor that is not
    /// `SignedPreBroadcast`, so post-submit a replacement would burn the
    /// owner's old phone and leave the payment exactly as stuck - the core
    /// refuses it there and this never offers it.
    pub phone_replacement_unblocked: bool,
}

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
        // The admitted set is `OperationStatus::awaits_mobile_witness` rather
        // than a local `matches!`, because the companion snapshot filter
        // discloses an operation id to a witness phone under exactly the same
        // predicate. Restating it here would let the two drift.
        if state.network_mode != "testnet" || !operation_status.awaits_mobile_witness() {
            return Err(AgentWalletError::InvalidOperationState);
        }
        // A rotation in flight is moving the witness pin itself, and
        // `complete_authority_transition` clears the pending slot when it does.
        // Minting an operation anchor across that transition would hand the OLD
        // phone something real to sign and then throw it away. Refuse rather
        // than race it. Nothing reaches this that could not before: no intent can
        // be created while a rotation is in flight, and a rotation can only start
        // from a wallet with nothing mid-flight or from the witness dead end,
        // whose anchor has already been released.
        if state
            .witness_rotation
            .as_ref()
            .is_some_and(|rotation| rotation.phase != WitnessRotationPhase::Completed)
        {
            return Err(AgentWalletError::RecoveryRequired);
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
            // A durable write with a second step after it - the anchor itself is
            // minted below - so the sweep injects a crash here too. Test builds
            // only.
            #[cfg(test)]
            {
                if self.crash_after_witness_state_initialized {
                    return Err(AgentWalletError::RecoveryRequired);
                }
            }
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
        // An anchor lives five minutes. Before this arm existed, an anchor that
        // expired before its receipt came back left `pending` occupied by an
        // object nothing could ever clear - `pending` is only vacated against a
        // receipt that verifies, and a receipt for a dead anchor never does -
        // and that one slot then refused every future payment, every witness
        // rotation and the reservation behind the stranded payment, for good.
        //
        // Re-issuing is the recovery, and it replaces rather than adds:
        // reaching this arm at all is the proof that the stored anchor can no
        // longer be witnessed by anyone, so there is never a moment with two
        // live anchors for one operation. The replacement is rebuilt from
        // current state a few lines below - phase, journal head and state
        // commitment are re-derived, never copied - and it sits at the same
        // chain position, because issuing an anchor has never advanced
        // `last_anchor_sequence` or `last_anchor_hash`; only an accepted receipt
        // does. Only `anchor_id`, `created_at` and `expires_at` differ, and the
        // new `anchor_id` is exactly what makes the old receipt unusable against
        // it: `WitnessReceipt::matches_anchor` pins both the id and the hash.
        //
        // The window itself is untouched. It stops being one-shot; it does not
        // get longer.
        let mut reissuing_expired_anchor = false;
        if let Some(pending) = &witness.pending {
            if pending.operation_id == operation_id.as_str() {
                match pending.proposal.verify(&registry, now) {
                    Ok(_) => return Ok(pending.proposal.clone()),
                    // A receipt already sits against this anchor. That witness
                    // is real, the lifecycle owns it, and expiry does not
                    // entitle anybody to a second one for the same phase.
                    Err(CompanionError::Expired) if pending.receipt.is_none() => {
                        reissuing_expired_anchor = true;
                    }
                    Err(CompanionError::Expired) => {
                        return Err(AgentWalletError::RecoveryRequired);
                    }
                    Err(_) => return Err(AgentWalletError::RollbackDetected),
                }
            } else {
                return Err(AgentWalletError::RollbackWitnessRequired);
            }
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
            || binding.node_profile_id != node.node_profile_commitment()
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
            node_profile_id: node.node_profile_commitment().to_owned(),
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
        let proposal_event = if reissuing_expired_anchor {
            AgentJournalEventKind::RollbackWitnessAnchorReissued
        } else {
            match operation_phase {
                RollbackOperationPhase::SignedPreBroadcast => {
                    AgentJournalEventKind::RollbackWitnessProposed
                }
                RollbackOperationPhase::Submitted => {
                    AgentJournalEventKind::PostSubmitWitnessProposed
                }
                RollbackOperationPhase::ReconciledFinal => {
                    AgentJournalEventKind::FinalWitnessProposed
                }
                _ => return Err(AgentWalletError::InvalidOperationState),
            }
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

    /// The stranded payment the desktop may offer a recovery control for, if
    /// there is one, and exactly which controls would succeed right now.
    ///
    /// The predicates are the ones `abandon_stranded_witness_operation`,
    /// `release_dead_witness_anchor`, `pending_rollback_anchor` and
    /// `prepare_witness_rotation` enforce, evaluated here rather than restated,
    /// so the desktop never offers a control that is then refused and never
    /// hides the only one that still works.
    ///
    /// It answers for EVERY phase that awaits a mobile witness, not only the
    /// pre-broadcast one. Post-submit is where the owner needs this most - the
    /// money has already moved and the wallet will take no further payment - and
    /// it was exactly where the desktop showed nothing at all.
    pub fn stranded_witness_recovery(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<StrandedWitnessRecovery>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        // The same admission `pending_rollback_anchor` uses, so the desktop
        // reports every payment a phone could still be asked to witness and no
        // payment it could not.
        let Some(operation) = state
            .operations
            .values()
            .find(|operation| operation.status().awaits_mobile_witness())
        else {
            return Ok(None);
        };
        let status = operation.status();
        let view = operation.view();
        let operation_id = view.operation_id.to_string();
        let pending = state
            .rollback_witness
            .as_ref()
            .and_then(|witness| witness.pending.as_ref())
            .filter(|pending| pending.operation_id == operation_id);
        let outstanding_receipt = pending.is_some_and(|pending| pending.receipt.is_some());
        let anchor_expires_at = pending.map(|pending| pending.proposal.anchor.expires_at);
        // Not `is_none_or`: an anchor that no longer exists and an anchor that
        // is dead are the same thing to the owner - nothing is outstanding that
        // could still turn into a witness.
        let nothing_outstanding =
            !outstanding_receipt && anchor_expires_at.is_none_or(|expires_at| expires_at <= now);
        Ok(Some(StrandedWitnessRecovery {
            operation_id,
            agent_id: view.agent_id.to_string(),
            asset: view.asset,
            amount_units: view.amount_units,
            total_debit_units: view.total_debit_units,
            recipient: view.recipient,
            status,
            // Everything except the pre-broadcast phase is past the node.
            submitted: status != OperationStatus::SignedAwaitingWitness,
            transaction_id: view.tx_hash,
            anchor_issued: pending.is_some(),
            anchor_expires_at,
            // A live anchor is re-served as-is and a dead one is replaced, so
            // asking the phone again is worth offering in both cases. Only a
            // receipt already sitting against the pending anchor takes the
            // payment out of this path.
            retryable: !outstanding_receipt,
            // `abandon_stranded_witness_operation` refuses anything past
            // `SignedAwaitingWitness`, and must: it marks the operation
            // `Cancelled` and hands the reservation back.
            abandonable: nothing_outstanding && status == OperationStatus::SignedAwaitingWitness,
            anchor_releasable: pending.is_some() && nothing_outstanding,
            phone_replacement_unblocked: witness_dead_end(&state).is_some(),
        }))
    }

    /// Drops an anchor that expired unwitnessed out of the single pending slot,
    /// leaving the payment exactly where it stands.
    ///
    /// WHAT IT COSTS: nothing. Reaching the preconditions is the proof that the
    /// anchor is already worthless - `SignedWitnessReceipt::verify` re-verifies
    /// the anchor, so a receipt for a dead one is refused no matter who signed
    /// it or when it arrives.
    ///
    /// WHAT IT DOES NOT DO: it does not touch the operation. Status, `tx_hash`
    /// and reservation are returned unchanged, and the returned view is the
    /// proof of that. It marks nothing witnessed, submits nothing, cancels
    /// nothing, and it does not advance `last_anchor_sequence` or
    /// `last_anchor_hash` - so the very next anchor still sits at the same chain
    /// position, and the payment still needs a real phone signature over a real
    /// anchor to move one step.
    ///
    /// WHY IT IS SEPARATE FROM RE-ISSUE: re-issue is the recovery whenever the
    /// phone can still take the replacement, and it is what the desktop and the
    /// phone should try first, in every phase. This is for the case re-issue
    /// cannot reach - a phone that durably accepted the dead anchor and has
    /// therefore consumed that chain position - where the cure is a new witness
    /// epoch and `prepare_witness_rotation` requires an empty pending slot.
    pub fn release_dead_witness_anchor(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if state.network_mode != "testnet" {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        if !state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status()
            .awaits_mobile_witness()
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let witness = state
            .rollback_witness
            .as_ref()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?;
        witness.validate(wallet_id)?;
        let pending = witness
            .pending
            .as_ref()
            .ok_or(AgentWalletError::WitnessRecoveryNotAvailable)?;
        // The slot belongs to some other operation. Dropping it here would leave
        // that one with nothing to resolve it, which is the trap this whole
        // family of commands exists to remove.
        if pending.operation_id != operation_id.as_str() {
            return Err(AgentWalletError::RollbackWitnessRequired);
        }
        // Refused while anything is still outstanding that could become a
        // witness - a live anchor, or a receipt already recorded against this
        // one - so it can never be used to race a phone that is signing.
        if pending.receipt.is_some() || pending.proposal.anchor.expires_at > now {
            return Err(AgentWalletError::WitnessRecoveryNotAvailable);
        }
        let mobile_device_id = witness.mobile_device_id.as_str().to_owned();
        state
            .rollback_witness
            .as_mut()
            .ok_or(AgentWalletError::RollbackWitnessRequired)?
            .pending = None;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::RollbackWitnessAnchorReleased,
            Some(operation_id.as_str().as_bytes()),
            Some(mobile_device_id.as_bytes()),
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    /// Abandons a signed payment that no phone can witness any more.
    ///
    /// WHAT IT COSTS: that payment is given up. The agent has to ask again. The
    /// reserved funds come straight back, because a `SignedAwaitingWitness`
    /// payment provably never reached the node - `mark_witnessed`, which needs a
    /// real receipt, is the only route from there to a broadcast.
    ///
    /// WHAT IT DOES NOT DO: it does not mark anything witnessed, it does not
    /// submit, and it does not advance `last_anchor_sequence` or
    /// `last_anchor_hash`. Advancing them would claim the phone accepted the
    /// dead anchor, which the desktop cannot know; if the phone did not, the
    /// desktop would silently run one step ahead of it and the next payment
    /// would be refused by the phone instead.
    ///
    /// It is refused while anything is still outstanding that could become a
    /// witness - a live anchor, or a receipt already recorded against the
    /// pending one - so it can never be used to race a phone that is signing.
    pub fn abandon_stranded_witness_operation(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if state.network_mode != "testnet" {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        if state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status()
            != OperationStatus::SignedAwaitingWitness
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let mut clears_pending = false;
        if let Some(witness) = state.rollback_witness.as_ref() {
            witness.validate(wallet_id)?;
            if let Some(pending) = &witness.pending {
                // The pending slot belongs to some other operation. Abandoning
                // this one would leave that anchor behind with nothing to
                // resolve it, which is the trap this command exists to remove.
                if pending.operation_id != operation_id.as_str() {
                    return Err(AgentWalletError::RollbackWitnessRequired);
                }
                if pending.receipt.is_some() || pending.proposal.anchor.expires_at > now {
                    return Err(AgentWalletError::WitnessRecoveryNotAvailable);
                }
                clears_pending = true;
            }
        }
        let mobile_device_id = state
            .rollback_witness
            .as_ref()
            .map(|witness| witness.mobile_device_id.as_str().to_owned());
        if clears_pending {
            state
                .rollback_witness
                .as_mut()
                .ok_or(AgentWalletError::RollbackWitnessRequired)?
                .pending = None;
        }
        state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .abandon_awaiting_witness()?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::RollbackWitnessAbandoned,
            Some(operation_id.as_str().as_bytes()),
            mobile_device_id.as_deref().map(str::as_bytes),
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
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
            // THE FIRST DURABLE BOUNDARY. Above this line the receipt, the new
            // chain position and - pre-broadcast - `WitnessedAwaitingBroadcast`
            // are on disk. Below it the payment still has to be broadcast and
            // the witness still has to be archived. Test builds only.
            #[cfg(test)]
            {
                if self.crash_after_witness_accepted {
                    return Err(AgentWalletError::RecoveryRequired);
                }
            }
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

    /// The receipt that was durably accepted and never archived, if there is
    /// one, with the phase it was signed for and where the payment stands now.
    ///
    /// `apply_mobile_witness_and_broadcast` writes the receipt into the pending
    /// slot and journals `RollbackWitnessAccepted` BEFORE it broadcasts and
    /// BEFORE it archives. A process that dies in that window leaves exactly
    /// this shape on disk, and nothing else does: the uninterrupted path always
    /// takes the receipt back out of the slot in the same call that put it in.
    ///
    /// A receipt sitting here is not a claim - it is a receipt the desktop
    /// already verified against a live anchor, whose acceptance already moved
    /// `last_anchor_sequence` and `last_anchor_hash`, and which
    /// `AuthenticatedRollbackWitnessState::validate` re-checks against that
    /// chain position on every load. The recovery finishes it; it never makes
    /// one.
    fn interrupted_witness(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<
        Option<(
            OperationId,
            SignedWitnessReceipt,
            RollbackOperationPhase,
            OperationStatus,
        )>,
    > {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let Some(witness) = state.rollback_witness.as_ref() else {
            return Ok(None);
        };
        witness.validate(wallet_id)?;
        let Some(pending) = witness.pending.as_ref() else {
            return Ok(None);
        };
        let Some(receipt) = pending.receipt.as_ref() else {
            return Ok(None);
        };
        let operation_id = OperationId::parse(pending.operation_id.clone())?;
        let status = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status();
        Ok(Some((
            operation_id,
            receipt.clone(),
            pending.proposal.anchor.operation_phase,
            status,
        )))
    }

    /// Finishes an interrupted witness whose remaining step needs no network.
    ///
    /// This runs on every unlock. It is a no-op on every wallet that was not
    /// interrupted, because the pending slot only ever holds a receipt between
    /// the two durable writes of one call.
    ///
    /// WHAT IT DOES: exactly the archive the interrupted call was about to do,
    /// with exactly the receipt that call had already written, through the same
    /// `archive_completed_witness` the uninterrupted path uses. The payment
    /// moves the one step the uninterrupted call would have moved it, and no
    /// further.
    ///
    /// WHAT IT DOES NOT DO: it does not verify anything against the clock, and
    /// it must not - a wallet that crashed is not going to be reopened inside
    /// the anchor's five minutes, and the receipt's verification against a LIVE
    /// anchor already happened before it was written. It does not contact the
    /// phone, does not broadcast, does not advance the witness chain (the
    /// accepted receipt already did), and does not mark anything witnessed that
    /// was not already marked witnessed on disk.
    ///
    /// It declines rather than forces when the payment is not in the status the
    /// archive is defined for - notably the pre-broadcast residue that is still
    /// `WitnessedAwaitingBroadcast`, which needs the broadcast finished first
    /// and is handled by `resume_interrupted_witness`.
    pub(crate) fn resume_interrupted_witness_archive(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<PaymentOperationView>> {
        let Some((operation_id, receipt, phase, status)) =
            self.interrupted_witness(wallet_id, now)?
        else {
            return Ok(None);
        };
        // THE THIRD BOUNDARY INSIDE THIS ONE CALL, and the one the first sweep
        // read past. `resume_payment` persists `BroadcastSubmitted` BEFORE it
        // posts the signed bytes, deliberately, so that a restart in that gap
        // may not assume the transaction went out - and may not assume it did
        // not. A crash there leaves exactly `BroadcastSubmitted` with the
        // receipt still parked, which is byte-for-byte what a crash one instant
        // AFTER a successful post leaves. The two are indistinguishable on
        // disk, and they must be, because that is what persisting first buys.
        //
        // The archive below would resolve that ambiguity by promoting the
        // payment to `SubmittedAwaitingFinalWitness`, which asserts the money
        // moved. On the pre-network half of the window it did not, and the
        // wallet has no way to tell which half it is in - so the assertion is
        // one this code cannot support, and it was being made on every unlock.
        //
        // The reconstruction that IS available from disk is the honest one:
        // the outcome is unknown. `BroadcastUncertain` is this wallet's own
        // name for that, written here through the same `mark_broadcast_uncertain`
        // and the same `RecoveryRequired` journal event `resume_payment` uses
        // when a live submission cannot be tied to its acknowledgement. It says
        // the money may have moved and never that it did not, it keeps the
        // payment out of every control that would hand the reservation back,
        // and it is what the post-submit anchor then tells the phone -
        // `WitnessSubmissionStatus::Uncertain`, not `Submitted`.
        let status =
            self.reconcile_interrupted_broadcast(wallet_id, &operation_id, phase, status, now)?;
        // The admitted sets are `archive_completed_witness`'s own, restated as
        // a precondition so a residue it would refuse is left untouched instead
        // of turning every unlock into an error.
        let archivable = match phase {
            RollbackOperationPhase::SignedPreBroadcast
            | RollbackOperationPhase::SignedAwaitingWitness => matches!(
                status,
                OperationStatus::BroadcastSubmitted
                    | OperationStatus::SubmittedAwaitingFinalWitness
                    | OperationStatus::BroadcastUncertain
            ),
            RollbackOperationPhase::Submitted => matches!(
                status,
                OperationStatus::SubmittedAwaitingFinalWitness
                    | OperationStatus::BroadcastUncertain
            ),
            RollbackOperationPhase::ReconciledFinal => {
                status == OperationStatus::ReconciledAwaitingFinalWitness
            }
            _ => false,
        };
        if !archivable {
            return Ok(None);
        }
        self.archive_completed_witness(wallet_id, &operation_id, &receipt, now)
            .map(Some)
    }

    /// The whole interrupted sequence, including the one residue that needs the
    /// node: a payment the phone witnessed pre-broadcast whose broadcast never
    /// ran.
    ///
    /// That residue is durable `WitnessedAwaitingBroadcast` - a status reachable
    /// only by crashing inside `apply_mobile_witness_and_broadcast`, and one
    /// that is NOT in `OperationStatus::awaits_mobile_witness`, so before this
    /// existed the desktop's entire recovery surface answered `None` for it
    /// while the wallet refused every further payment.
    ///
    /// It resumes the payment through `resume_payment`, which is the same call
    /// the uninterrupted path makes at that point and which re-checks the node
    /// binding, the approval commitment and the emergency interlock, and
    /// persists the local transaction hash before the first network call. It
    /// cannot submit twice: `resume_payment` admits `WitnessedAwaitingBroadcast`
    /// and nothing past it.
    ///
    /// A witness is still required for anything to move here. The only reason
    /// this operation is resumable at all is that a real receipt from the paired
    /// phone over a live anchor was already verified and written to disk.
    pub async fn resume_interrupted_witness(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<PaymentOperationView>> {
        let Some((operation_id, _, phase, status)) = self.interrupted_witness(wallet_id, now)?
        else {
            return Ok(None);
        };
        if matches!(
            phase,
            RollbackOperationPhase::SignedPreBroadcast
                | RollbackOperationPhase::SignedAwaitingWitness
        ) && status == OperationStatus::WitnessedAwaitingBroadcast
        {
            // Byte for byte what `apply_mobile_witness_and_broadcast` does with
            // this result, so an interrupted call and a completed one land in
            // the same place.
            match self.resume_payment(wallet_id, &operation_id, now).await {
                Ok(result)
                    if matches!(
                        result.status,
                        OperationStatus::SubmittedAwaitingFinalWitness
                            | OperationStatus::BroadcastSubmitted
                    ) => {}
                Ok(result) => return Ok(Some(result)),
                Err(AgentWalletError::BroadcastUncertain) => {}
                Err(error) => return Err(error),
            }
        }
        self.resume_interrupted_witness_archive(wallet_id, now)
    }

    /// Turns an interrupted pre-network `BroadcastSubmitted` residue into the
    /// only statement about it this wallet can support, and leaves every other
    /// residue exactly as it found it.
    ///
    /// It runs on the recovery path only. The uninterrupted pilot path never
    /// returns from `resume_payment` holding `BroadcastSubmitted` - it either
    /// marks the payment submitted-awaiting-final-witness, marks it uncertain
    /// itself, or fails - so an owner who was never interrupted never reaches
    /// this at all.
    ///
    /// It moves nothing else: no chain position, no receipt, no reservation, no
    /// transaction hash, and it never contacts the node.
    fn reconcile_interrupted_broadcast(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        phase: RollbackOperationPhase,
        status: OperationStatus,
        now: u64,
    ) -> AgentWalletResult<OperationStatus> {
        if !matches!(
            phase,
            RollbackOperationPhase::SignedPreBroadcast
                | RollbackOperationPhase::SignedAwaitingWitness
        ) || status != OperationStatus::BroadcastSubmitted
        {
            return Ok(status);
        }
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .mark_broadcast_uncertain()?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::RecoveryRequired,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )?;
        Ok(OperationStatus::BroadcastUncertain)
    }

    fn archive_completed_witness(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        signed: &SignedWitnessReceipt,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        // THE SECOND DURABLE BOUNDARY. Everything the caller did before
        // reaching here - including, on the pre-broadcast path, the broadcast
        // itself - is already on disk. Test builds only.
        #[cfg(test)]
        {
            if self.crash_before_witness_archive {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
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
