use hpay_companion_protocol::{ApprovalCommitment, ApprovalNetworkBinding, DeviceId};
use rand::RngCore;

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::node_binding::verified_agent_node;
use crate::operation::{
    AgentOperation, AgentPaymentRequest, ApprovalMode, OperationStatus, PaymentOperationView,
};
use crate::policy::{AgentPermission, AgentRecord, AgentStatus};
use crate::signer::SignedAgentEnvelope;
use crate::types::{AgentId, AgentWalletId, OperationId, WalletScope};

use super::state::{active_reservations, exposure_for_agent_in_window, scoped_idempotency_key};
use super::{
    AgentAuthorization, AgentWalletManager, AgentWalletState, IdempotencyRecord,
    MAX_APPROVAL_SECONDS, MAX_OPERATIONS_PER_WALLET, MAX_REQUESTS_PER_AGENT_PER_MINUTE,
};

fn requires_node_reconciliation(status: OperationStatus) -> bool {
    if cfg!(feature = "agent-wallet-testnet-pilot") {
        status == OperationStatus::ReconciliationRequired
    } else {
        matches!(
            status,
            OperationStatus::BroadcastSubmitted | OperationStatus::BroadcastUncertain
        )
    }
}
impl AgentWalletManager {
    pub(super) async fn create_payment_intent(
        &mut self,
        authorization: &AgentAuthorization,
        request: AgentPaymentRequest,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        let agent = validate_authorization(&state, authorization)?.clone();
        require_permission(&agent, authorization, AgentPermission::CreatePaymentIntent)?;
        require_agent_spending_network(&state.network_mode)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let emergency = self.emergency_controller(&wallet_id)?;
        let safety_permit = emergency.issue_safety_permit(state.payments_suspended)?;

        request.validate(now)?;
        hacash_wallet_core::require_address_for_network(&request.recipient, &state.network_mode)
            .map_err(|_| AgentWalletError::RecipientNotAllowed)?;
        let network_fee = HacUnits::MIN_NETWORK_FEE;
        let total_debit = request.amount_units.checked_add(network_fee)?;

        safety_permit.checkpoint(state.payments_suspended)?;
        self.compact_aged_terminal_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        safety_permit.checkpoint(state.payments_suspended)?;

        let idempotency_key = scoped_idempotency_key(&agent.agent_id, &request.idempotency_key);
        let request_commitment = request.commitment_hex()?;
        if let Some(existing) = state.idempotency.get(&idempotency_key) {
            if existing.request_commitment != request_commitment {
                return Err(AgentWalletError::IdempotencyConflict);
            }
            return state
                .operations
                .get(existing.operation_id.as_str())
                .map(AgentOperation::view)
                .ok_or(AgentWalletError::RecoveryRequired);
        }

        #[cfg(feature = "agent-wallet-testnet-pilot")]
        if state
            .witness_rotation
            .as_ref()
            .is_some_and(|rotation| !rotation.phase.permits_agent_writes())
            || state.operations.values().any(|operation| {
                matches!(
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
            })
        {
            return Err(AgentWalletError::RecoveryRequired);
        }

        ensure_operation_capacity(&state)?;
        ensure_agent_request_rate(&state, &agent.agent_id, now)?;
        validate_policy_for_request(&state, &agent, &request, total_debit, now)?;

        let mut operation = AgentOperation::new(
            OperationId::new(),
            agent.agent_id.clone(),
            wallet_id.clone(),
            request,
            now,
        )?;
        operation.reserve(network_fee)?;
        let total = operation.view().total_debit_units;

        safety_permit.checkpoint(state.payments_suspended)?;
        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        let approval_network_binding = Some(ApprovalNetworkBinding {
            network_id: node.network_kind().to_owned(),
            chain_id: node.chain_id(),
            genesis_identifier: state.block_one_fingerprint.clone(),
            node_profile_id: node.node_profile_id().to_owned(),
            transaction_format_version: node.transaction_format_version(),
        });
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        let approval_network_binding: Option<ApprovalNetworkBinding> = None;
        safety_permit.checkpoint(state.payments_suspended)?;
        let balance = node
            .query_balance_entry(&state.address, false)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)
            .and_then(|entry| HacUnits::from_decimal(entry.hacash_decimal()))?;
        safety_permit.checkpoint(state.payments_suspended)?;
        let reserved = active_reservations(&state)?;
        let available = balance
            .checked_sub(reserved)
            .map_err(|_| AgentWalletError::InsufficientAgentBalance)?;
        if available < total {
            return Err(AgentWalletError::InsufficientAgentBalance);
        }

        let operation_id = operation.operation_id().clone();
        state.idempotency.insert(
            idempotency_key,
            IdempotencyRecord {
                request_commitment,
                operation_id: operation_id.clone(),
            },
        );
        state
            .operations
            .insert(operation_id.as_str().to_owned(), operation);
        safety_permit.checkpoint(state.payments_suspended)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::FundsReserved,
            Some(operation_id.as_str().as_bytes()),
            Some(agent.agent_id.as_str().as_bytes()),
            now,
        )?;
        // A durable write with a second step after it - the node still has to
        // build the transaction and the approval still has to be requested - so
        // the sweep injects a crash here too. Test builds only.
        #[cfg(test)]
        {
            if self.crash_after_funds_reserved {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }

        // Only HPAY constructs the transaction. The agent never supplies raw
        // bytes, fees, or transaction actions.
        let operation = state
            .operations
            .get(&operation_id.to_string())
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let view = operation.view();
        let amount = view.amount_units.to_decimal();
        let network_fee = view.network_fee_units.to_decimal();
        let transfers = [(view.recipient.as_str(), amount.as_str())];
        safety_permit.checkpoint(state.payments_suspended)?;
        let built = node
            .build_send_hac_tx_actions(&state.address, &network_fee, &transfers)
            .await;
        safety_permit.checkpoint(state.payments_suspended)?;
        let verified_body = built
            .map_err(|_| AgentWalletError::NodeRejected)
            .and_then(|response| response.body.ok_or(AgentWalletError::NodeRejected))
            .and_then(|body| {
                hacash_wallet_core::tx_binding::verify_hac_transfers(
                    &body,
                    &state.address,
                    &network_fee,
                    &transfers,
                )
                .map_err(|_| AgentWalletError::NodeRejected)?;
                Ok(body)
            });
        let body = match verified_body {
            Ok(body) => body,
            Err(error) => {
                let operation = state
                    .operations
                    .get_mut(operation_id.as_str())
                    .ok_or(AgentWalletError::RecoveryRequired)?;
                operation.fail_unsigned("transaction_build_failed")?;
                state.updated_at = now;
                self.persist_event(
                    &mut state,
                    &session.state_master,
                    &session.journal_key,
                    AgentJournalEventKind::PaymentFailed,
                    Some(operation_id.as_str().as_bytes()),
                    Some(agent.agent_id.as_str().as_bytes()),
                    now,
                )?;
                return Err(error);
            }
        };
        safety_permit.checkpoint(state.payments_suspended)?;
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::RecoveryRequired)?;
        operation.persist_unsigned_transaction(body)?;
        let view = operation.view();
        let approval = ApprovalCommitment {
            approval_version: if cfg!(feature = "agent-wallet-testnet-pilot") {
                3
            } else {
                2
            },
            approval_id: random_token("approval"),
            operation_id: view.operation_id.to_string(),
            agent_wallet_id: view.agent_wallet_id.to_string(),
            agent_id: view.agent_id.to_string(),
            desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            transaction_commitment: view
                .transaction_commitment
                .ok_or(AgentWalletError::InvalidOperationState)?,
            amount_units: view.amount_units.get(),
            fee_units: view.network_fee_units.get(),
            wallet_fee_units: view.wallet_fee_units.get(),
            total_debit_units: view.total_debit_units.get(),
            recipient: view.recipient,
            policy_epoch: state.policy_epoch,
            challenge_nonce: random_challenge_nonce(),
            issued_at: now,
            expires_at: view
                .expires_at
                .min(now.saturating_add(MAX_APPROVAL_SECONDS)),
            network_binding: approval_network_binding,
        };
        operation.request_approval(approval, state.policy_epoch, now)?;
        safety_permit.checkpoint(state.payments_suspended)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::ApprovalRequested,
            Some(operation_id.as_str().as_bytes()),
            Some(agent.agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::RecoveryRequired)?
            .view())
    }

    pub fn pending_approval(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<ApprovalCommitment> {
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
        let operation = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if operation.status() != OperationStatus::ApprovalRequested {
            return Err(AgentWalletError::InvalidOperationState);
        }
        operation.stored_approval().and_then(|approval| {
            if approval.expires_at <= now {
                Err(AgentWalletError::ApprovalExpired)
            } else {
                Ok(approval.clone())
            }
        })
    }

    /// Desktop manual approval. Approval is durably persisted, reloaded and
    /// revalidated before the signer is called. Signed bytes are durably stored
    /// before any broadcast attempt.
    pub async fn approve_desktop_and_broadcast(
        &mut self,
        wallet_id: &AgentWalletId,
        approval: ApprovalCommitment,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        require_agent_spending_network(&state.network_mode)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        let operation_id = OperationId::parse(approval.operation_id.clone())
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let approving_agent = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .agent_id()
            .clone();
        let approval_mode = state
            .agents
            .get(approving_agent.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?
            .policy
            .approval_mode;
        if !matches!(
            approval_mode,
            ApprovalMode::DesktopManual | ApprovalMode::EitherTrustedDevice
        ) {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        // Under the Testnet Pilot this used to refuse EVERY approval that
        // reached this line, however valid. The reason was downstream, not here:
        // completing a desktop approval signs the transaction into
        // OperationStatus::SignedAwaitingWitness, and at the time nothing could
        // move it. The phone signed a witness receipt only for an operation it
        // had approved itself, and it was never told a desktop-approved
        // operation existed, so the payment stranded in a status no sweep can
        // expire, holding its reservation, blocking every later payment from
        // obtaining a rollback anchor.
        //
        // Both halves of that are now closed, and the whole path is executed end
        // to end - agent intent, desktop approval, real signing, discovery,
        // anchor, receipt, one submission - in
        // service/companion/tests/desktop_witness_flow.rs. If that test is ever
        // deleted or weakened, this call has lost the evidence it stands on.
        //
        // ONE PART OF THE OLD REFUSAL SURVIVES, NARROWED TO WHAT STILL JUSTIFIES
        // IT. Under the pilot a completed approval signs into
        // SignedAwaitingWitness, and only a registered phone holding
        // `WitnessRollbackAnchor` can move it from there: that permission is
        // what `pending_rollback_anchor` requires, and it is the same permission
        // the witness disclosure is gated on. With no such phone the payment
        // would sign into a status that no sweep can expire, that holds its
        // reservation, and that refuses every later payment an anchor - the
        // exact stranding the blanket refusal existed to prevent, still
        // reachable while the owner has not paired a phone yet.
        //
        // It is not a device-trust rule and it is not a build rule: pair a
        // witness phone and this same approval goes through.
        //
        // The throwaway probe clone is kept, and it is kept for the same reason
        // it was written: so that a malformed, expired, mismatched or
        // wrong-epoch approval still returns its own specific error instead of
        // being absorbed by the refusal below, and so that the refusal is
        // reached only by an approval that was otherwise valid. It mutates
        // nothing - `state` is untouched, no journal event is written, the
        // clone is dropped - which is why the error can promise that nothing
        // was signed and that the payment is still awaiting a decision.
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            let mut probe = state
                .operations
                .get(operation_id.as_str())
                .ok_or(AgentWalletError::OperationNotFound)?
                .clone();
            probe.record_approval(
                approval.clone(),
                ApprovalMode::DesktopManual,
                state.policy_epoch,
                now,
            )?;
            // "Some phone could witness" is the right question only until a
            // rollback witness record exists. From then on `rollback_witness`
            // pins one `mobile_device_id`, and `pending_rollback_anchor`
            // refuses every other device with `RollbackDetected`. An ordinary
            // revoke-and-re-pair leaves that pin on the revoked phone - only
            // `complete_witness_rotation` moves it - so asking the registry
            // alone would sign a payment that the newly paired phone can never
            // witness, and `SignedAwaitingWitness` has no exit: no sweep
            // expires it, `prepare_witness_rotation` refuses while it exists,
            // and no further intent can be created. So ask about the exact
            // device that would have to produce the anchor.
            if !pinned_witness_phone_can_sign(&state) {
                return Err(AgentWalletError::WitnessPhoneRequiredForApproval);
            }
        }
        // `record_approval` validates before it mutates, and the journal event
        // that makes any of it durable is written after that, so every refusal
        // below this line also leaves the payment exactly where it was.
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        operation.record_approval(
            approval,
            ApprovalMode::DesktopManual,
            state.policy_epoch,
            now,
        )?;
        safety_permit.checkpoint(state.payments_suspended)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::ApprovalGranted,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )?;

        // A durable write with a second step after it, so the sweep injects a
        // crash here too. Test builds only.
        #[cfg(test)]
        {
            if self.crash_after_approval_granted {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        self.resume_payment(wallet_id, &operation_id, now).await
    }

    /// Finishes an approval that a crash interrupted between its durable write
    /// and the signature.
    ///
    /// BOTH approval paths have this boundary, and the first sweep named only
    /// one of them. `approve_desktop_and_broadcast` journals `ApprovalGranted`
    /// and then calls `resume_payment`; `apply_mobile_approval_and_broadcast`
    /// journals the phone's decision AND the replay-guard snapshot that
    /// consumes it, in one write, and then calls `resume_payment`. A process
    /// that dies in either gap leaves a payment durably `Approved`.
    ///
    /// On the desktop side the owner could in principle press Approve again.
    /// On the phone side they cannot, and that is what makes the mobile
    /// boundary a real one: the decision's replay token was consumed by the
    /// same durable write that recorded the decision, so the identical receipt
    /// is refused with `CompanionReplayRejected` for ever - executed in
    /// `the_mobile_approval_crash_is_finished_on_unlock`. The owner said yes on
    /// their phone, the wallet wrote it down, and then silently dropped the
    /// payment and showed them nothing.
    ///
    /// WHAT IT DOES: exactly the call the interrupted path was about to make,
    /// on the approval that is already durable - `resume_payment`, which
    /// re-reads the stored approval, re-checks the node binding, the approval
    /// commitment, the policy epoch and the emergency interlock before the
    /// signer is touched. Under the pilot that leaves the payment
    /// `SignedAwaitingWitness`, which is precisely where the uninterrupted call
    /// leaves it.
    ///
    /// WHAT IT DOES NOT DO: it approves nothing. `Approved` is only ever
    /// written against a decision that was already verified - a desktop
    /// commitment or a phone signature - so there is no approval here to
    /// manufacture, and nothing runs without one already on disk. It signs
    /// nothing that has expired: `resume_payment` sweeps expired pre-signing
    /// operations first, so an approval the owner left behind is cancelled and
    /// its reservation returned rather than signed late.
    ///
    /// It declines rather than forces in every case it cannot reason about
    /// completely: more than one payment durably `Approved`, anything already
    /// in the witness lifecycle, or - under the pilot - a wallet whose pinned
    /// witness phone could not sign the anchor that a freshly signed payment
    /// would need. That last one is the same question
    /// `approve_desktop_and_broadcast` asks before it records an approval,
    /// asked through the same predicate so the two cannot drift: without it,
    /// resuming would sign into `SignedAwaitingWitness` on a wallet whose phone
    /// has since been revoked, which is the stranding that check exists to
    /// prevent.
    pub async fn resume_interrupted_approval(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<PaymentOperationView>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if state.operations.values().any(|operation| {
            matches!(
                operation.status(),
                OperationStatus::Signed
                    | OperationStatus::SignedAwaitingWitness
                    | OperationStatus::WitnessedAwaitingBroadcast
                    | OperationStatus::BroadcastSubmitted
                    | OperationStatus::BroadcastUncertain
                    | OperationStatus::SubmittedAwaitingFinalWitness
                    | OperationStatus::ReconciliationRequired
                    | OperationStatus::ReconciledAwaitingFinalWitness
                    | OperationStatus::RecoveryRequired
            )
        }) {
            return Ok(None);
        }
        let mut approved = state
            .operations
            .values()
            .filter(|operation| operation.status() == OperationStatus::Approved);
        let Some(operation) = approved.next() else {
            return Ok(None);
        };
        if approved.next().is_some() {
            return Ok(None);
        }
        // An approval the owner left behind is not resumed at all. The
        // predicate is `sweep_expired_pre_signing_operations`'s own, asked here
        // rather than restated, so a payment this declines is exactly a payment
        // the next ordinary call cancels and hands the reservation back for.
        if operation.expires_at() <= now {
            return Ok(None);
        }
        let operation_id = operation.operation_id().clone();
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        if !pinned_witness_phone_can_sign(&state) {
            return Ok(None);
        }
        drop(state);
        self.resume_payment(wallet_id, &operation_id, now)
            .await
            .map(Some)
    }

    /// Explicitly resumes only states whose prior durable transition proves
    /// that no network submission could already have happened.
    ///
    /// Approved may be signed once. Signed may be submitted once after first
    /// persisting BroadcastSubmitted. Submitted or uncertain states require
    /// reconciliation and are never auto-rebroadcast.
    pub async fn resume_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        require_agent_spending_network(&state.network_mode)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let safety_permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;

        safety_permit.checkpoint(state.payments_suspended)?;
        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        safety_permit.checkpoint(state.payments_suspended)?;
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
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
        }

        match state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .status()
        {
            OperationStatus::Approved => {
                let persisted = state
                    .operations
                    .get(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .persisted_unsigned()?;
                let approved = persisted.into_approved(
                    state
                        .operations
                        .get(operation_id.as_str())
                        .ok_or(AgentWalletError::OperationNotFound)?,
                    now,
                )?;
                safety_permit.checkpoint(state.payments_suspended)?;
                let signed: SignedAgentEnvelope = session.signer.sign(
                    approved,
                    session.signer.wallet_scope(),
                    state.signer_epoch,
                    now,
                )?;
                safety_permit.checkpoint(state.payments_suspended)?;
                let tx_hash = signed.tx_hash.clone();
                state
                    .operations
                    .get_mut(operation_id.as_str())
                    .ok_or(AgentWalletError::OperationNotFound)?
                    .record_signed(&signed.transaction, tx_hash)?;
                safety_permit.checkpoint(state.payments_suspended)?;
                state.updated_at = now;
                self.persist_event(
                    &mut state,
                    &session.state_master,
                    &session.journal_key,
                    AgentJournalEventKind::TransactionSigned,
                    Some(operation_id.as_str().as_bytes()),
                    None,
                    now,
                )?;
                // A durable write with a second step after it - under the pilot
                // the call returns here, but off the pilot it goes on to
                // broadcast - so the sweep injects a crash here too. Test builds
                // only.
                #[cfg(test)]
                {
                    if self.crash_after_transaction_signed {
                        return Err(AgentWalletError::RecoveryRequired);
                    }
                }
                state = self.load_verified_state(
                    wallet_id,
                    &session.state_master,
                    &session.journal_key,
                )?;
            }
            OperationStatus::Signed if !cfg!(feature = "agent-wallet-testnet-pilot") => {}
            OperationStatus::SignedAwaitingWitness => {
                return Err(AgentWalletError::RollbackWitnessRequired);
            }
            OperationStatus::WitnessedAwaitingBroadcast => {}
            OperationStatus::BroadcastSubmitted | OperationStatus::BroadcastUncertain => {
                return Err(AgentWalletError::BroadcastUncertain);
            }
            _ => return Err(AgentWalletError::InvalidOperationState),
        }

        let operation = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if cfg!(feature = "agent-wallet-testnet-pilot")
            && operation.status() == OperationStatus::SignedAwaitingWitness
        {
            return Ok(operation.view());
        }
        let expected_broadcast_state = if cfg!(feature = "agent-wallet-testnet-pilot") {
            OperationStatus::WitnessedAwaitingBroadcast
        } else {
            OperationStatus::Signed
        };
        if operation.status() != expected_broadcast_state {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let signed_hex = operation.signed_tx_hex()?.to_owned();
        let tx_hash = operation
            .view()
            .tx_hash
            .ok_or(AgentWalletError::RecoveryRequired)?;

        // Persist the exact local hash before the first network call. A
        // restart in this state must reconcile; it must never auto-rebroadcast.
        safety_permit.checkpoint(state.payments_suspended)?;
        state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .mark_broadcast_submitted(tx_hash.clone())?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::TransactionBroadcast,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )?;
        // THE BROADCAST BOUNDARY. `BroadcastSubmitted` is durable and the bytes
        // have provably not left this process. Test builds only.
        #[cfg(test)]
        {
            if self.crash_after_broadcast_persisted {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        safety_permit.checkpoint(state.payments_suspended)?;

        let submit_result = node.submit_tx_hex(&signed_hex).await;
        // A stop racing an in-flight HTTP request makes the external outcome
        // unknowable, even when the node returned success. Never surface that
        // as a normal submitted state; require exact-hash reconciliation.
        if safety_permit.checkpoint(state.payments_suspended).is_err() {
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
            return Err(AgentWalletError::BroadcastUncertain);
        }

        match submit_result {
            Ok(response) => {
                if let Some(acknowledged_hash) = response.hash
                    && !acknowledged_hash.eq_ignore_ascii_case(&tx_hash)
                {
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
                    return Err(AgentWalletError::BroadcastUncertain);
                }
            }
            Err(_) => {
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
                return Err(AgentWalletError::BroadcastUncertain);
            }
        }
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            state
                .operations
                .get_mut(operation_id.as_str())
                .ok_or(AgentWalletError::OperationNotFound)?
                .mark_submitted_awaiting_final_witness()?;
            state.updated_at = now;
            self.persist_event(
                &mut state,
                &session.state_master,
                &session.journal_key,
                AgentJournalEventKind::TransactionSubmissionAcknowledged,
                Some(operation_id.as_str().as_bytes()),
                None,
                now,
            )?;
        }
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    /// Returns the one operation whose network outcome still needs an exact
    /// hash lookup. More than one is an invariant violation and fails closed.
    pub fn reconciliation_required_operation(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<PaymentOperationView>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let mut matches = state
            .operations
            .values()
            .filter(|operation| requires_node_reconciliation(operation.status()));
        let Some(operation) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(Some(operation.view()))
    }

    /// Reconciles an uncertain broadcast against the wallet's pinned,
    /// capability-verified node. A mempool result is deliberately insufficient:
    /// durable state advances only when the exact local hash is block-backed.
    pub async fn reconcile_broadcast_from_node(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let operation = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if !requires_node_reconciliation(operation.status()) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let tx_hash = operation
            .view()
            .tx_hash
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let node_url = state.node_url.clone();
        let network_mode = state.network_mode.clone();
        let block_one_fingerprint = state.block_one_fingerprint.clone();
        let node = verified_agent_node(&node_url, &network_mode, &block_one_fingerprint).await?;
        let response = node
            .query_transaction(&tx_hash)
            .await
            .map_err(|_| AgentWalletError::BroadcastNotConfirmed)?;
        if !response.is_confirmed() {
            return Err(AgentWalletError::BroadcastNotConfirmed);
        }
        self.confirm_broadcast(wallet_id, operation_id, &tx_hash, now)
    }

    /// Finalizes accounting only after an external reconciliation source has
    /// confirmed the exact locally signed transaction hash.
    pub fn confirm_broadcast(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        confirmed_tx_hash: &str,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        require_agent_spending_network(&state.network_mode)?;
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let view = operation.view();
        let reconcilable = if cfg!(feature = "agent-wallet-testnet-pilot") {
            view.status == OperationStatus::ReconciliationRequired
        } else {
            matches!(
                view.status,
                OperationStatus::BroadcastSubmitted | OperationStatus::BroadcastUncertain
            )
        };
        if !reconcilable || view.tx_hash.as_deref() != Some(confirmed_tx_hash) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        operation.mark_reconciled_awaiting_final_witness(confirmed_tx_hash.to_owned(), now)?;
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        operation.mark_committed(confirmed_tx_hash.to_owned(), "confirmed".to_owned(), now)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            if cfg!(feature = "agent-wallet-testnet-pilot") {
                AgentJournalEventKind::TransactionReconciled
            } else {
                AgentJournalEventKind::PaymentCommitted
            },
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    pub fn reject_payment(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &OperationId,
        mode: ApprovalMode,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
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
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if operation.status() == OperationStatus::Rejected {
            return Ok(operation.view());
        }
        operation.record_rejection(mode, now)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::ApprovalRejected,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    pub(super) fn cancel_own_unsigned(
        &mut self,
        authorization: &AgentAuthorization,
        operation_id: &OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        let agent = validate_authorization(&state, authorization)?;
        require_permission(
            agent,
            authorization,
            AgentPermission::CancelOwnUnsignedOperation,
        )?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if operation.agent_id() != authorization.agent_id() {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        if operation.status() == OperationStatus::Cancelled {
            return Ok(operation.view());
        }
        operation.cancel_unsigned()?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::PaymentFailed,
            Some(operation_id.as_str().as_bytes()),
            Some(authorization.agent_id().as_str().as_bytes()),
            now,
        )?;
        Ok(state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    pub(super) fn list_operations_for_agent(
        &mut self,
        authorization: &AgentAuthorization,
        now: u64,
    ) -> AgentWalletResult<Vec<PaymentOperationView>> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        let agent = validate_authorization(&state, authorization)?;
        require_permission(agent, authorization, AgentPermission::ListOwnOperations)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        Ok(state
            .operations
            .values()
            .filter(|operation| operation.agent_id() == authorization.agent_id())
            .map(AgentOperation::view)
            .collect())
    }
}

/// Whether the exact device that would have to produce the rollback anchor for
/// a freshly signed payment is an active witness right now.
///
/// "Some phone could witness" is the right question only until a rollback
/// witness record exists. From then on `rollback_witness` pins one
/// `mobile_device_id`, and `pending_rollback_anchor` refuses every other device
/// with `RollbackDetected`. An ordinary revoke-and-re-pair leaves that pin on
/// the revoked phone - only `complete_witness_rotation` moves it - so asking the
/// registry alone would admit a payment that the newly paired phone can never
/// witness, and `SignedAwaitingWitness` has no exit: no sweep expires it,
/// `prepare_witness_rotation` refuses while it exists, and no further intent can
/// be created. So ask about the exact device that would have to produce the
/// anchor.
///
/// Asked in two places - by `approve_desktop_and_broadcast` before it records an
/// approval, and by `resume_interrupted_approval` before it finishes one a crash
/// interrupted - and stated once, because two copies of this question is exactly
/// how a payment becomes admitted at one door and unwitnessable at the next.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(super) fn pinned_witness_phone_can_sign(state: &AgentWalletState) -> bool {
    match state.rollback_witness.as_ref() {
        Some(witness) => state
            .companion_security
            .as_ref()
            .is_some_and(|companion| companion.is_active_witness_device(&witness.mobile_device_id)),
        None => state
            .companion_security
            .as_ref()
            .is_some_and(super::companion::CompanionSecurityState::has_active_witness_device),
    }
}

pub(super) fn validate_authorization<'a>(
    state: &'a AgentWalletState,
    authorization: &AgentAuthorization,
) -> AgentWalletResult<&'a AgentRecord> {
    if authorization.wallet_id != state.wallet_id
        || authorization
            .wallet_scope
            .validate_for(&state.wallet_id)
            .is_err()
        || authorization.identity_key_sha256.len() != 64
        || !authorization
            .identity_key_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AgentWalletError::AgentSessionExpired);
    }
    let agent = state
        .agents
        .get(authorization.agent_id.as_str())
        .ok_or(AgentWalletError::AgentNotPaired)?;
    if agent.status != AgentStatus::Active {
        return Err(AgentWalletError::AgentRevoked);
    }
    if agent.authorization_epoch != authorization.authorization_epoch
        || agent.identity_key_sha256 != authorization.identity_key_sha256
    {
        return Err(AgentWalletError::AgentSessionExpired);
    }
    if !agent.policy.permissions.contains(&authorization.capability) {
        return Err(AgentWalletError::AgentPermissionDenied);
    }
    Ok(agent)
}

fn require_permission(
    agent: &AgentRecord,
    authorization: &AgentAuthorization,
    permission: AgentPermission,
) -> AgentWalletResult<()> {
    if authorization.capability == permission && agent.policy.permissions.contains(&permission) {
        Ok(())
    } else {
        Err(AgentWalletError::AgentPermissionDenied)
    }
}

pub(super) fn agent_spending_ready(network_mode: &str) -> bool {
    network_mode != "mainnet"
}

pub(super) fn require_agent_spending_network(network_mode: &str) -> AgentWalletResult<()> {
    if agent_spending_ready(network_mode) {
        Ok(())
    } else {
        Err(AgentWalletError::SigningBlocked)
    }
}
pub(super) fn validate_policy_for_request(
    state: &AgentWalletState,
    agent: &AgentRecord,
    request: &AgentPaymentRequest,
    total_debit: HacUnits,
    now: u64,
) -> AgentWalletResult<()> {
    let policy = &agent.policy;
    if total_debit > policy.max_per_payment_units {
        return Err(AgentWalletError::PaymentLimitExceeded);
    }
    // The blocklist is absolute and is checked on its own. No policy flag and no
    // owner approval can admit a blocked recipient.
    if policy.blocked_recipients.contains(&request.recipient) {
        return Err(AgentWalletError::RecipientNotAllowed);
    }
    // The allowlist keeps its meaning: a recipient on it is one the owner has
    // already vetted. A recipient off it is refused here unless the owner has
    // deliberately turned on `allow_unlisted_recipient_with_approval` for this
    // agent, in which case the agent may only propose the payment. It still has
    // to pass every check below, and it is still admitted only by the exact
    // owner approval ceremony, which nothing here bypasses. Being proposed and
    // approved never adds the recipient to `allowed_recipients`.
    if !policy.allowed_recipients.contains(&request.recipient)
        && !policy.allow_unlisted_recipient_with_approval
    {
        return Err(AgentWalletError::RecipientNotAllowed);
    }
    let pending = state
        .operations
        .values()
        .filter(|operation| {
            operation.agent_id() == &agent.agent_id && operation.status().retains_reservation()
        })
        .count();
    if pending >= usize::from(policy.max_pending_operations) {
        return Err(AgentWalletError::TooManyPendingOperations);
    }
    let today_exposure = exposure_for_agent_in_window(state, &agent.agent_id, now, 86_400)?;
    if today_exposure.checked_add(total_debit)? > policy.max_daily_units {
        return Err(AgentWalletError::DailyLimitExceeded);
    }
    if !policy.approval_mode.requires_explicit_user_action() {
        return Err(AgentWalletError::ApprovalRequired);
    }
    Ok(())
}

fn wallet_id_from_scope(scope: &WalletScope) -> AgentWalletResult<AgentWalletId> {
    let raw = scope
        .as_str()
        .strip_prefix("agent_wallet:")
        .ok_or(AgentWalletError::InvalidWalletScope)?;
    let wallet_id = AgentWalletId::parse(raw)?;
    scope.validate_for(&wallet_id)?;
    Ok(wallet_id)
}

pub(super) fn ensure_agent_request_rate(
    state: &AgentWalletState,
    agent_id: &AgentId,
    now: u64,
) -> AgentWalletResult<()> {
    let recent_requests = state
        .operations
        .values()
        .filter(|operation| {
            operation.agent_id() == agent_id && operation.created_at() >= now.saturating_sub(60)
        })
        .count();
    if recent_requests >= MAX_REQUESTS_PER_AGENT_PER_MINUTE {
        Err(AgentWalletError::RateLimited)
    } else {
        Ok(())
    }
}
pub(super) fn ensure_operation_capacity(state: &AgentWalletState) -> AgentWalletResult<()> {
    if state.operations.len() >= MAX_OPERATIONS_PER_WALLET
        || state.idempotency.len() >= MAX_OPERATIONS_PER_WALLET
    {
        Err(AgentWalletError::RateLimited)
    } else {
        Ok(())
    }
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

pub(super) fn random_challenge_nonce() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
