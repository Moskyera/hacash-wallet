use sha2::{Digest, Sha256};

use super::*;
use crate::l1_channel_close::{
    ChannelCloseSettlement, ExpectedChannelIncarnation, L1_CHANNEL_CLOSE_SCHEMA,
    L1_CHANNEL_CLOSE_VOUCHER_STATUS, L1ChannelCloseRequest, L1ChannelCloseResponse,
    close_request_commitment, validate_and_cosign_channel_close, validate_channel_close,
};
use crate::node::ChannelInfo;
use crate::storage::{
    ChannelLifecycleStatus, L1ChannelCloseStatus, L1ChannelCloseVoucherStatus,
    PersistedChannelLifecycle, PersistedL1ChannelClose, PersistedL1ChannelCloseVoucher,
};
const SUBMITTED_EXACT_RETRY_GRACE_SECONDS: u64 = 30;
const L1_CLOSE_MIN_CONFIRMATIONS: u64 = 6;

/// What a person is told when their close freeze is released, written to be
/// read by the person and not by a grep.
pub(crate) const EXPIRED_UNSIGNED_CLOSE_REASON: &str = "the channel-close authorization expired before the Hub ever signed it. The durable record \
     carries no signed bytes, so nothing was broadcast and nothing can land on chain. The channel \
     has been unfrozen and is ready for a fresh close attempt.";

pub(super) fn retired_close_has_finality_evidence(operation: &PersistedL1ChannelClose) -> bool {
    operation.status == L1ChannelCloseStatus::Retired
        && operation
            .confirmed_block_height
            .is_some_and(|height| height > 0)
        && operation.observed_confirmations >= L1_CLOSE_MIN_CONFIRMATIONS
        && operation.final_ledger.is_some()
        && terminal_transaction_evidence_is_valid(
            operation.signed_transaction_hex.as_deref(),
            operation.signed_transaction_commitment.as_deref(),
            operation.transaction_hash.as_deref(),
        )
}

impl HubState {
    pub async fn close_channel(
        &self,
        request: &L1ChannelCloseRequest,
    ) -> HubResult<L1ChannelCloseResponse> {
        // Before anything else, including the settlement-ready gate: a
        // never-signed freeze that has lapsed is released here. It has to run
        // ahead of `ensure_settlement_ready` because one such record left in
        // `RecoveryRequired` by an older build latches that very gate, and it
        // has to run ahead of `existing_channel_close` because a second attempt
        // on the same channel is otherwise turned away by the commitment index
        // and never reaches the state machine at all.
        self.cancel_expired_unsigned_channel_closes()?;
        let request_commitment = close_request_commitment(request)?;
        let live_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        if let Some(existing) = self.existing_channel_close(request, &request_commitment)? {
            let expected = ExpectedChannelIncarnation {
                channel_id: existing.channel_id.clone(),
                user_address: existing.user_address.clone(),
                hub_address: existing.hub_address.clone(),
                reuse_version: existing.reuse_version,
                open_height: existing.open_height,
            };
            validate_channel_close(request, &expected, &live_network, existing.created_unix)?;
            {
                let guard = self
                    .inner
                    .read()
                    .map_err(|_| HubError::State("state lock poisoned".into()))?;
                self.ensure_l1_close_recovery_allowed(&guard, &existing.operation_id)?;
            }
            return self.resume_channel_close(&existing.operation_id).await;
        }
        self.ensure_settlement_ready()?;

        // Reject malformed, expired, wrongly signed, or wrong-Hub requests
        // before readiness/fullnode I/O. Chain incarnation is checked again
        // against the authoritative node response immediately afterwards.
        let claimed = ExpectedChannelIncarnation {
            channel_id: request.channel_id.clone(),
            user_address: request.user_address.clone(),
            hub_address: self.hub_address.clone(),
            reuse_version: request.reuse_version,
            open_height: request.open_height,
        };
        let claimed_intent =
            validate_channel_close(request, &claimed, &live_network, crate::node::now_unix())?;
        self.require_mainnet_cooperative_close_ready(matches!(
            claimed_intent.settlement,
            ChannelCloseSettlement::PrincipalTransfer { .. }
        ))
        .await?;
        let channel = self.node.query_channel(&request.channel_id).await?;
        let expected = expected_incarnation(&channel, request, &self.hub_address, true)?;
        let intent =
            validate_channel_close(request, &expected, &live_network, crate::node::now_unix())?;
        let original_ledger = channel_ledger_from_l1(&channel)?;

        let operation = {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if let Some(existing) =
                existing_channel_close_from_state(&guard, request, &request_commitment)?
            {
                existing
            } else {
                // One channel, one Hub signature over one close. If a voucher
                // was already issued here, the owner is holding countersigned
                // close bytes that can land at any future height, so
                // countersigning a cooperative close as well would put two
                // conflicting signed closes for one channel into the world.
                if guard.l1_channel_close_vouchers.contains_key(&channel.id) {
                    return Err(HubError::Channel(
                        "this channel already has a delta-zero close voucher and cannot also be closed cooperatively"
                            .into(),
                    ));
                }
                let effective_ledger = require_channel_can_freeze(
                    &guard,
                    &channel,
                    &self.hub_address,
                    &original_ledger,
                    &intent.settlement,
                )?;
                let ledger_commitment = ledger_commitment(&effective_ledger)?;
                if guard.channel_lifecycle.contains_key(&channel.id) {
                    return Err(HubError::Channel(
                        "another durable close or retired incarnation already owns this channel"
                            .into(),
                    ));
                }
                let now = crate::node::now_unix();
                let operation = PersistedL1ChannelClose {
                    operation_id: request.operation_id.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    request_commitment: request_commitment.clone(),
                    network: live_network.network_kind.clone(),
                    chain_id: live_network.chain_id,
                    mainnet: live_network.mainnet,
                    block_1_hash: live_network.block_1_hash.clone(),
                    node_profile_id: live_network.node_profile_id.clone(),
                    network_instance_id: live_network.network_instance_id.clone(),
                    transaction_format_version: live_network.transaction_format_version,
                    channel_id: channel.id.clone(),
                    hub_address: self.hub_address.clone(),
                    user_address: expected.user_address,
                    reuse_version: expected.reuse_version,
                    open_height: expected.open_height,
                    original_ledger,
                    final_ledger: Some(effective_ledger),
                    partial_transaction_hex: request.partial_transaction_hex.clone(),
                    partial_transaction_commitment: request.partial_transaction_commitment.clone(),
                    authorization_public_key_hex: request.authorization_public_key_hex.clone(),
                    authorization_signature_hex: request.authorization_signature_hex.clone(),
                    transaction_hash: Some(intent.transaction_hash),
                    signed_transaction_hex: None,
                    signed_transaction_commitment: None,
                    confirmed_block_height: None,
                    observed_confirmations: 0,
                    status: L1ChannelCloseStatus::FreezeIntentPersisted,
                    created_unix: request.created_unix,
                    expires_unix: request.expires_unix,
                    updated_unix: now,
                    last_error: None,
                };
                let mut next = guard.clone();
                next.l1_channel_close_idempotency.insert(
                    operation.idempotency_key.clone(),
                    operation.operation_id.clone(),
                );
                next.l1_channel_close_commitments.insert(
                    operation.partial_transaction_commitment.clone(),
                    operation.operation_id.clone(),
                );
                next.l1_channel_closes
                    .insert(operation.operation_id.clone(), operation.clone());
                next.channel_lifecycle.insert(
                    operation.channel_id.clone(),
                    PersistedChannelLifecycle {
                        operation_id: operation.operation_id.clone(),
                        channel_id: operation.channel_id.clone(),
                        reuse_version: operation.reuse_version,
                        open_height: operation.open_height,
                        status: ChannelLifecycleStatus::FreezeIntentPersisted,
                        state_commitment: ledger_commitment,
                        updated_unix: now,
                    },
                );
                self.commit_channel_close_transition(
                    &mut guard,
                    next,
                    &operation,
                    JournalPhase::L1CloseFreezeIntentPersisted,
                )?;

                let mut frozen = operation.clone();
                frozen.status = L1ChannelCloseStatus::FrozenBeforeSigning;
                frozen.updated_unix = crate::node::now_unix();
                let mut next = guard.clone();
                next.l1_channel_closes
                    .insert(frozen.operation_id.clone(), frozen.clone());
                update_lifecycle(
                    &mut next,
                    &frozen,
                    ChannelLifecycleStatus::FrozenBeforeSigning,
                )?;
                self.commit_channel_close_transition(
                    &mut guard,
                    next,
                    &frozen,
                    JournalPhase::L1CloseFrozenBeforeSigning,
                )?;
                frozen
            }
        };
        self.resume_channel_close(&operation.operation_id).await
    }

    /// Countersign one delta-zero close for one channel and hand the exact
    /// bytes back, without freezing the channel and without broadcasting.
    ///
    /// This is deliberately a separate entry point from [`Self::close_channel`]
    /// and shares none of its state. `close_channel` writes `channel_lifecycle`
    /// at request time and refuses a second close forever after, which is its
    /// safety property and not an oversight: it guarantees the Hub can never
    /// hold two conflicting signed closes. Asking that path for a countersigned
    /// close therefore permanently freezes the channel, which is exactly what a
    /// voucher must not do, because the whole point is that the channel keeps
    /// working afterwards.
    ///
    /// What this path gives up in exchange is stated plainly:
    ///
    /// * It is not trustless and must never be described as such. The Hub
    ///   chooses to countersign, once, at the start of the channel's life, and
    ///   nothing in Hacash can compel it. If it never signs, the deposit stays
    ///   in the channel until the Hub cooperates. There is a real hostage
    ///   window between the open confirming and the voucher arriving, because
    ///   the Hub cannot countersign a close for a channel that does not exist
    ///   on chain yet. That window is minimised, not argued away.
    /// * Once the owner holds these bytes the Hub carries the whole exposure.
    ///   The owner can spend the channel down to zero and still broadcast a
    ///   close that refunds the full deposit recorded at open, because
    ///   `close_channel_default` refunds the balances stored at open and the
    ///   transaction never names any later balance. That is acceptable here
    ///   only because the owner runs the Hub.
    ///
    /// The one rule that makes the exposure bounded rather than open-ended:
    /// exactly one voucher per channel, ever, at delta zero, never refreshed.
    /// It is enforced by [`HubPersistedState::l1_channel_close_vouchers`] being
    /// keyed by channel ID and written under the same lock that checks it.
    pub async fn issue_channel_close_voucher(
        &self,
        request: &L1ChannelCloseRequest,
    ) -> HubResult<L1ChannelCloseResponse> {
        self.ensure_settlement_ready()?;
        let request_commitment = close_request_commitment(request)?;

        // A dropped response must not cost the owner their exit, so replaying
        // the exact same request returns the exact same bytes. That is not a
        // second voucher: it is the same transaction hash, and only one copy
        // of it can ever be mined.
        if let Some(existing) = self.existing_close_voucher(&request.channel_id)? {
            return self.replay_channel_close_voucher(&existing, request, &request_commitment);
        }

        let live_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        let claimed = ExpectedChannelIncarnation {
            channel_id: request.channel_id.clone(),
            user_address: request.user_address.clone(),
            hub_address: self.hub_address.clone(),
            reuse_version: request.reuse_version,
            open_height: request.open_height,
        };
        let claimed_intent =
            validate_channel_close(request, &claimed, &live_network, crate::node::now_unix())?;
        require_delta_zero_voucher_settlement(&claimed_intent.settlement)?;
        self.require_mainnet_cooperative_close_ready(false).await?;

        let channel = self.node.query_channel(&request.channel_id).await?;
        let expected = expected_incarnation(&channel, request, &self.hub_address, true)?;
        let intent =
            validate_channel_close(request, &expected, &live_network, crate::node::now_unix())?;
        require_delta_zero_voucher_settlement(&intent.settlement)?;
        let original_ledger = channel_ledger_from_l1(&channel)?;

        // No liquidity check and no fee check for the Hub: at delta zero
        // nothing moves to or from the Hub, the owner pays the network fee out
        // of their own balance at whatever future height they broadcast, and
        // this Hub broadcasts nothing here.
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub L1 channel signer is not configured".into()))?;

        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;

        // Re-checked under the write lock that also performs the insert, so two
        // concurrent requests for one channel cannot both pass.
        if let Some(existing) = guard.l1_channel_close_vouchers.get(&channel.id).cloned() {
            return self.replay_channel_close_voucher(&existing, request, &request_commitment);
        }
        if guard.channel_lifecycle.contains_key(&channel.id)
            || guard
                .l1_channel_closes
                .values()
                .any(|operation| operation.channel_id == channel.id)
        {
            return Err(HubError::Channel(
                "this channel already has a cooperative close and cannot also be issued a voucher"
                    .into(),
            ));
        }

        let effective_ledger = require_channel_can_freeze(
            &guard,
            &channel,
            &self.hub_address,
            &original_ledger,
            &intent.settlement,
        )?;
        require_untouched_delta_zero_ledger(&effective_ledger, &original_ledger)?;

        let now = crate::node::now_unix();
        let reserved = PersistedL1ChannelCloseVoucher {
            channel_id: channel.id.clone(),
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_commitment: request_commitment.clone(),
            network: live_network.network_kind.clone(),
            chain_id: live_network.chain_id,
            mainnet: live_network.mainnet,
            block_1_hash: live_network.block_1_hash.clone(),
            node_profile_id: live_network.node_profile_id.clone(),
            network_instance_id: live_network.network_instance_id.clone(),
            transaction_format_version: live_network.transaction_format_version,
            hub_address: self.hub_address.clone(),
            user_address: expected.user_address.clone(),
            reuse_version: expected.reuse_version,
            open_height: expected.open_height,
            original_ledger,
            partial_transaction_hex: request.partial_transaction_hex.clone(),
            partial_transaction_commitment: request.partial_transaction_commitment.clone(),
            transaction_hash: intent.transaction_hash.clone(),
            signed_transaction_hex: None,
            signed_transaction_commitment: None,
            status: L1ChannelCloseVoucherStatus::SignatureMayExist,
            created_unix: request.created_unix,
            updated_unix: now,
        };

        // Claim the channel's one voucher slot before the signer is called. A
        // crash between here and the next commit leaves a bytes-less entry that
        // permanently refuses this channel a voucher. That is the intended
        // outcome: an unrecoverable signature is refused, never replaced.
        let mut next = guard.clone();
        next.l1_channel_close_vouchers
            .insert(reserved.channel_id.clone(), reserved.clone());
        self.commit_channel_close_voucher_transition(
            &mut guard,
            next,
            &reserved,
            JournalPhase::L1CloseVoucherSignatureMayExist,
        )?;

        let signed = validate_and_cosign_channel_close(
            request,
            &expected,
            &intent.settlement,
            signer.account(),
            &live_network,
            crate::node::now_unix(),
        )?;
        if signed.transaction_hash != reserved.transaction_hash {
            return Err(HubError::State(
                "RecoveryRequired: close voucher transaction changed during signing".into(),
            ));
        }

        let mut issued = reserved;
        issued.signed_transaction_hex = Some(signed.signed_transaction_hex);
        issued.signed_transaction_commitment = Some(signed.signed_transaction_commitment);
        issued.status = L1ChannelCloseVoucherStatus::Issued;
        issued.updated_unix = crate::node::now_unix();
        let mut next = guard.clone();
        next.l1_channel_close_vouchers
            .insert(issued.channel_id.clone(), issued.clone());
        self.commit_channel_close_voucher_transition(
            &mut guard,
            next,
            &issued,
            JournalPhase::L1CloseVoucherIssued,
        )?;
        // Stops at signed, on purpose. `submit_transaction_bound` is never
        // called on this path; the owner decides if and when these bytes reach
        // a chain.
        Ok(channel_close_voucher_response(&issued))
    }

    /// The stored voucher for a channel, if it has one.
    pub(crate) fn existing_close_voucher(
        &self,
        channel_id: &str,
    ) -> HubResult<Option<PersistedL1ChannelCloseVoucher>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .l1_channel_close_vouchers
            .get(channel_id)
            .cloned())
    }

    /// Serve the one voucher this channel already has, and only for the exact
    /// request that produced it. Anything else is a request for a second
    /// signed close and is refused rather than satisfied.
    fn replay_channel_close_voucher(
        &self,
        existing: &PersistedL1ChannelCloseVoucher,
        request: &L1ChannelCloseRequest,
        request_commitment: &str,
    ) -> HubResult<L1ChannelCloseResponse> {
        if existing.request_commitment != request_commitment
            || existing.operation_id != request.operation_id
            || existing.channel_id != request.channel_id
            || existing.partial_transaction_hex != request.partial_transaction_hex
        {
            return Err(HubError::Channel(
                "this channel already has a close voucher; a second one would be a second signed close and is refused"
                    .into(),
            ));
        }
        // Re-prove the user authorised these exact bytes before handing the
        // signature back, exactly as the cooperative-close replay path does.
        // `created_unix` is the clock the request was written against.
        let expected = ExpectedChannelIncarnation {
            channel_id: existing.channel_id.clone(),
            user_address: existing.user_address.clone(),
            hub_address: existing.hub_address.clone(),
            reuse_version: existing.reuse_version,
            open_height: existing.open_height,
        };
        validate_channel_close(
            request,
            &expected,
            &voucher_network_binding(existing),
            existing.created_unix,
        )?;
        if existing.status != L1ChannelCloseVoucherStatus::Issued
            || existing.signed_transaction_hex.is_none()
        {
            return Err(HubError::State(
                "a close voucher signature may exist for this channel but its exact bytes are unavailable; this channel can never be issued another voucher"
                    .into(),
            ));
        }
        Ok(channel_close_voucher_response(existing))
    }

    fn commit_channel_close_voucher_transition(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        voucher: &PersistedL1ChannelCloseVoucher,
        phase: JournalPhase,
    ) -> HubResult<()> {
        // A voucher is a fresh signature, never a recovery step, so the plain
        // settlement gate applies: a Hub in recovery signs nothing here.
        self.ensure_settlement_ready()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state store is unavailable".into()))?;
        let previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        let new_state_commitment = state_commitment(&next_state)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: voucher.channel_id.clone(),
            channel_reuse_version: voucher.reuse_version,
            operation_id: voucher.operation_id.clone(),
            operation_type: JournalOperationType::L1ChannelClose,
            operation_phase: phase,
            amount_units: 0,
            sender: voucher.user_address.clone(),
            recipient: self.hub_address.clone(),
            previous_state_commitment,
            new_state_commitment: new_state_commitment.clone(),
            idempotency_key: voucher.idempotency_key.clone(),
            request_commitment: voucher.request_commitment.clone(),
            expected_bill_number: Some(voucher.original_ledger.bill_auto_number),
            unsigned_state_commitment: Some(voucher.partial_transaction_commitment.clone()),
            created_at: crate::node::now_unix(),
        })?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = new_state_commitment.clone();
        if let Err(error) = store.save(&next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: close voucher journal advanced but state was not durable: {error}"
            )));
        }
        if let Err(error) = journal.write_checkpoint(&JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: new_state_commitment,
        }) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: close voucher state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        self.refresh_recovery_gate(guard);
        Ok(())
    }

    pub fn channel_close_status(&self, operation_id: &str) -> HubResult<L1ChannelCloseResponse> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let operation = guard
            .l1_channel_closes
            .get(operation_id)
            .ok_or_else(|| HubError::NotFound(format!("channel close {operation_id}")))?;
        Ok(channel_close_response(operation))
    }

    async fn resume_channel_close(&self, operation_id: &str) -> HubResult<L1ChannelCloseResponse> {
        let _single_flight = self.close_recovery_lock.lock().await;
        let mut operation = self.load_channel_close(operation_id)?;
        // Terminal, and terminal early: everything below this line is the
        // signing and broadcast machinery, and driving a released freeze into
        // it would reach "a close signature may exist but its exact bytes are
        // unavailable" and try to mark a terminal record `RecoveryRequired`.
        // Replaying the cancelled request answers with the cancelled record and
        // the reason it was cancelled, which is what the person asked for.
        if operation.status == L1ChannelCloseStatus::CancelledBeforeSigning {
            return Ok(channel_close_response(&operation));
        }
        let expected_network = persisted_close_network_binding(&operation);
        let live_network = self
            .node
            .capabilities()
            .await
            .and_then(|capabilities| capabilities.l1_channel_network_binding());
        if expected_network.validate().is_err()
            || live_network.as_ref().ok() != Some(&expected_network)
        {
            if signature_may_exist(&operation) {
                self.mark_close_recovery_required(
                    operation,
                    "fullnode network identity differs from the durable channel-close binding"
                        .into(),
                )?;
                return self.channel_close_status(operation_id);
            }
            return Err(HubError::Node(
                "fullnode network identity differs from the durable channel-close binding".into(),
            ));
        }
        if retired_close_has_finality_evidence(&operation) {
            return Ok(channel_close_response(&operation));
        }
        if operation.status == L1ChannelCloseStatus::Retired {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(
                "RecoveryRequired: legacy retired channel-close lacks exact transaction finality evidence"
                    .into(),
            ));
        }
        let channel = match self.node.query_channel(&operation.channel_id).await {
            Ok(channel) => channel,
            Err(error) => {
                if signature_may_exist(&operation) {
                    self.mark_close_recovery_required(operation, error.to_string())?;
                    return self.channel_close_status(operation_id);
                }
                return Err(error);
            }
        };
        if !channel.is_open() {
            if let Err(error) = ensure_same_incarnation(&channel, &operation) {
                if signature_may_exist(&operation) {
                    self.mark_close_recovery_required(operation, error.to_string())?;
                    return self.channel_close_status(operation_id);
                }
                return Err(error);
            }
            return match self
                .reconcile_closed_channel(operation.clone(), channel.close_height)
                .await
            {
                Ok(response) => Ok(response),
                Err(error) => {
                    self.mark_close_recovery_required(operation, error.to_string())?;
                    self.channel_close_status(operation_id)
                }
            };
        }
        if let Err(error) = ensure_same_open_incarnation(&channel, &operation) {
            if signature_may_exist(&operation) {
                self.mark_close_recovery_required(operation, error.to_string())?;
                return self.channel_close_status(operation_id);
            }
            return Err(error);
        }

        if operation.status == L1ChannelCloseStatus::ConfirmedClosed {
            self.mark_close_recovery_required(
                operation,
                "confirmed close disappeared before retirement; possible chain reorganization"
                    .into(),
            )?;
            return self.channel_close_status(operation_id);
        }

        if matches!(
            operation.status,
            L1ChannelCloseStatus::FreezeIntentPersisted | L1ChannelCloseStatus::FrozenBeforeSigning
        ) {
            if crate::node::now_unix() > operation.expires_unix {
                // Was `mark_close_recovery_required`, which was the single
                // worst state in this file: an operation that had never been
                // signed was pushed into a status whose own recovery gate
                // demands `signed_transaction_hex`, so it could never satisfy
                // its own way out, and `persisted_state_requires_recovery`
                // latched every payment, open and close on the Hub behind it.
                //
                // The chain has already been consulted above (the channel is
                // not closed) and the durable record carries no signature, so
                // it is provable that nothing happened. Release it.
                self.cancel_close_before_signing(
                    operation,
                    EXPIRED_UNSIGNED_CLOSE_REASON.to_string(),
                )?;
                return self.channel_close_status(operation_id);
            }
            let request = request_from_operation(&operation);
            let expected = ExpectedChannelIncarnation {
                channel_id: operation.channel_id.clone(),
                user_address: operation.user_address.clone(),
                hub_address: self.hub_address.clone(),
                reuse_version: operation.reuse_version,
                open_height: operation.open_height,
            };
            let intent = validate_channel_close(
                &request,
                &expected,
                &expected_network,
                crate::node::now_unix(),
            )?;
            self.require_mainnet_cooperative_close_ready(matches!(
                intent.settlement,
                ChannelCloseSettlement::PrincipalTransfer { .. }
            ))
            .await?;
            self.require_close_liquidity(&operation, &channel, &intent)
                .await?;
            let signing_network = self
                .node
                .capabilities()
                .await?
                .l1_channel_network_binding()?;
            if signing_network != expected_network {
                return Err(HubError::Node(
                    "fullnode network identity changed before channel-close signing".into(),
                ));
            }
            operation = self.sign_frozen_channel_close(operation, &channel, &signing_network)?;
        }

        if operation.status == L1ChannelCloseStatus::Submitted
            && operation.confirmed_block_height.is_some()
        {
            self.mark_close_recovery_required(
                operation,
                "previously observed close disappeared before finality; possible chain reorganization"
                    .into(),
            )?;
            return self.channel_close_status(operation_id);
        }
        if operation.status == L1ChannelCloseStatus::Submitted
            && !submitted_exact_retry_due(operation.updated_unix, crate::node::now_unix())
        {
            return Ok(channel_close_response(&operation));
        }
        let signed_hex = match operation.signed_transaction_hex.clone() {
            Some(signed) => signed,
            None => {
                self.mark_close_recovery_required(
                    operation,
                    "a close signature may exist but its exact bytes are unavailable".into(),
                )?;
                return self.channel_close_status(operation_id);
            }
        };
        let transaction_hash = operation.transaction_hash.clone().ok_or_else(|| {
            HubError::State("durable channel-close transaction hash is missing".into())
        })?;
        let live_before_submit = self
            .node
            .capabilities()
            .await
            .and_then(|capabilities| capabilities.l1_channel_network_binding());
        if live_before_submit.as_ref().ok() != Some(&expected_network) {
            self.mark_close_recovery_required(
                operation,
                "fullnode network identity changed before channel-close broadcast".into(),
            )?;
            return self.channel_close_status(operation_id);
        }

        if operation.status != L1ChannelCloseStatus::SubmissionStarted {
            operation = self.transition_close_status(
                operation,
                L1ChannelCloseStatus::SubmissionStarted,
                ChannelLifecycleStatus::SubmissionStarted,
                JournalPhase::L1CloseSubmissionStarted,
                None,
            )?;
        }
        match self
            .node
            .submit_transaction_bound(&signed_hex, &transaction_hash, &expected_network)
            .await
        {
            Ok(node_hash) if node_hash.eq_ignore_ascii_case(&transaction_hash) => {
                operation = self.transition_close_status(
                    operation,
                    L1ChannelCloseStatus::Submitted,
                    ChannelLifecycleStatus::Submitted,
                    JournalPhase::L1CloseSubmitted,
                    None,
                )?;
            }
            Ok(_) => {
                self.mark_close_recovery_required(
                    operation,
                    "fullnode acknowledged a different close transaction".into(),
                )?;
                return self.channel_close_status(operation_id);
            }
            Err(error) => {
                self.mark_close_recovery_required(operation, error.to_string())?;
                return self.channel_close_status(operation_id);
            }
        }

        match self.node.query_channel(&operation.channel_id).await {
            Ok(channel) if !channel.is_open() => {
                if let Err(error) = ensure_same_incarnation(&channel, &operation) {
                    self.mark_close_recovery_required(operation, error.to_string())?;
                    return self.channel_close_status(operation_id);
                }
                match self
                    .reconcile_closed_channel(operation.clone(), channel.close_height)
                    .await
                {
                    Ok(response) => Ok(response),
                    Err(error) => {
                        self.mark_close_recovery_required(operation, error.to_string())?;
                        self.channel_close_status(operation_id)
                    }
                }
            }
            Ok(channel) => {
                if let Err(error) = ensure_same_open_incarnation(&channel, &operation) {
                    self.mark_close_recovery_required(operation, error.to_string())?;
                    return self.channel_close_status(operation_id);
                }
                Ok(channel_close_response(&operation))
            }
            Err(_) => Ok(channel_close_response(&operation)),
        }
    }

    fn sign_frozen_channel_close(
        &self,
        operation: PersistedL1ChannelClose,
        channel: &ChannelInfo,
        expected_network: &crate::l1_channel::L1ChannelNetworkBinding,
    ) -> HubResult<PersistedL1ChannelClose> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let current = guard
            .l1_channel_closes
            .get(&operation.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable channel-close operation disappeared".into()))?;
        if current.request_commitment != operation.request_commitment
            || !matches!(
                current.status,
                L1ChannelCloseStatus::FreezeIntentPersisted
                    | L1ChannelCloseStatus::FrozenBeforeSigning
            )
        {
            return Ok(current);
        }
        let request = request_from_operation(&current);
        let expected = ExpectedChannelIncarnation {
            channel_id: current.channel_id.clone(),
            user_address: current.user_address.clone(),
            hub_address: self.hub_address.clone(),
            reuse_version: current.reuse_version,
            open_height: current.open_height,
        };
        let intent = validate_channel_close(
            &request,
            &expected,
            expected_network,
            crate::node::now_unix(),
        )?;
        let final_ledger = require_channel_can_freeze(
            &guard,
            channel,
            &self.hub_address,
            &current.original_ledger,
            &intent.settlement,
        )?;
        if current.final_ledger.as_ref() != Some(&final_ledger) {
            return Err(HubError::State(
                "RecoveryRequired: authoritative final close ledger changed before signing".into(),
            ));
        }
        ensure_same_open_incarnation(channel, &current)?;

        // Persist that a signature may exist before the signer is called. A crash
        // after this point can only recover by using the exact persisted bytes.
        let mut signing = current;
        signing.status = L1ChannelCloseStatus::SignatureMayExist;
        signing.updated_unix = crate::node::now_unix();
        let mut next = guard.clone();
        next.l1_channel_closes
            .insert(signing.operation_id.clone(), signing.clone());
        update_lifecycle(
            &mut next,
            &signing,
            ChannelLifecycleStatus::SignatureMayExist,
        )?;
        self.commit_channel_close_transition(
            &mut guard,
            next,
            &signing,
            JournalPhase::L1CloseSignatureMayExist,
        )?;

        let request = request_from_operation(&signing);
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub L1 channel signer is not configured".into()))?;
        let signed = validate_and_cosign_channel_close(
            &request,
            &expected,
            &intent.settlement,
            signer.account(),
            expected_network,
            crate::node::now_unix(),
        )?;
        if signing.transaction_hash.as_deref() != Some(&signed.transaction_hash) {
            return Err(HubError::State(
                "RecoveryRequired: close transaction changed during signing".into(),
            ));
        }
        signing.signed_transaction_hex = Some(signed.signed_transaction_hex);
        signing.signed_transaction_commitment = Some(signed.signed_transaction_commitment);
        signing.status = L1ChannelCloseStatus::Signed;
        signing.updated_unix = crate::node::now_unix();
        let mut next = guard.clone();
        next.l1_channel_closes
            .insert(signing.operation_id.clone(), signing.clone());
        update_lifecycle(&mut next, &signing, ChannelLifecycleStatus::Signed)?;
        self.commit_channel_close_transition(
            &mut guard,
            next,
            &signing,
            JournalPhase::L1SignatureProduced,
        )?;
        Ok(signing)
    }

    async fn require_close_liquidity(
        &self,
        operation: &PersistedL1ChannelClose,
        channel: &ChannelInfo,
        intent: &crate::l1_channel_close::ValidatedChannelCloseIntent,
    ) -> HubResult<()> {
        {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if let Some(other) = guard.l1_channel_closes.values().find(|other| {
                other.operation_id != operation.operation_id
                    && signature_may_exist(other)
                    && other.status != L1ChannelCloseStatus::Retired
            }) {
                // Name it. This is a Hub-wide mutex over cooperative closes,
                // and the old sentence told a person whose own channel was
                // fine that something unnamed was in the way, with no hint of
                // what would clear it or when. The same reservation is now also
                // published in the readiness document, so it is visible before
                // anyone presses Close.
                return Err(HubError::Channel(format!(
                    "another signed channel close is still reserving Hub liquidity: operation {} \
                     on channel {} is {} and holds the reservation until it confirms on chain and \
                     is retired",
                    other.operation_id,
                    other.channel_id,
                    other.status.public_name()
                )));
            }
        }
        let user_balance = self.node.query_balance_zhu(&operation.user_address).await?;
        let hub_balance = self.node.query_balance_zhu(&operation.hub_address).await?;
        let user_refund =
            channel_refund_zhu(channel, &operation.original_ledger, &operation.user_address)?;
        let hub_refund =
            channel_refund_zhu(channel, &operation.original_ledger, &operation.hub_address)?;
        let mut user_available = user_balance
            .checked_add(user_refund)
            .ok_or_else(|| HubError::State("user close liquidity overflow".into()))?;
        let mut hub_available = hub_balance
            .checked_add(hub_refund)
            .ok_or_else(|| HubError::State("Hub close liquidity overflow".into()))?;
        if let ChannelCloseSettlement::PrincipalTransfer {
            from_address,
            to_address,
            amount_millimeis,
        } = &intent.settlement
        {
            let transfer_zhu = u128::from(*amount_millimeis)
                .checked_mul(u128::from(crate::readiness::ZHU_PER_MILLIMEI))
                .ok_or_else(|| HubError::State("close transfer liquidity overflow".into()))?;
            if from_address == &operation.user_address && to_address == &operation.hub_address {
                user_available = user_available.checked_sub(transfer_zhu).ok_or_else(|| {
                    HubError::Channel(
                        "user cannot fund the exact cooperative-close principal transfer".into(),
                    )
                })?;
                hub_available = hub_available
                    .checked_add(transfer_zhu)
                    .ok_or_else(|| HubError::State("Hub close liquidity overflow".into()))?;
            } else if from_address == &operation.hub_address
                && to_address == &operation.user_address
            {
                hub_available = hub_available.checked_sub(transfer_zhu).ok_or_else(|| {
                    HubError::Channel(
                        "Hub cannot fund the exact cooperative-close principal transfer".into(),
                    )
                })?;
                user_available = user_available
                    .checked_add(transfer_zhu)
                    .ok_or_else(|| HubError::State("user close liquidity overflow".into()))?;
            } else {
                return Err(HubError::State(
                    "validated close settlement no longer matches the channel parties".into(),
                ));
            }
        }
        if user_available < u128::from(intent.network_fee_zhu) {
            return Err(HubError::Channel(
                "user cannot fund the cooperative-close network fee after settlement".into(),
            ));
        }
        let _ = hub_available;
        Ok(())
    }

    async fn reconcile_closed_channel(
        &self,
        mut operation: PersistedL1ChannelClose,
        close_height: u64,
    ) -> HubResult<L1ChannelCloseResponse> {
        if close_height == 0 {
            return Err(HubError::State(
                "closed channel is missing an on-chain close height".into(),
            ));
        }
        let transaction_hash = operation.transaction_hash.as_deref().ok_or_else(|| {
            HubError::State("durable channel-close transaction hash is missing".into())
        })?;
        let signed_hex = operation.signed_transaction_hex.as_deref().ok_or_else(|| {
            HubError::State("exact signed channel-close bytes are unavailable".into())
        })?;
        let observation = self
            .node
            .query_transaction(transaction_hash)
            .await?
            .ok_or_else(|| {
                HubError::State(
                    "RecoveryRequired: channel closed but the expected transaction was not found"
                        .into(),
                )
            })?;
        if observation.pending {
            return Err(HubError::State(
                "RecoveryRequired: channel closed while the expected transaction is only pending"
                    .into(),
            ));
        }
        if !observation.body_hex.eq_ignore_ascii_case(signed_hex) {
            return Err(HubError::State(
                "RecoveryRequired: mined close bytes differ from the persisted signed transaction"
                    .into(),
            ));
        }
        if observation.block_height != Some(close_height) {
            return Err(HubError::State(
                "RecoveryRequired: close transaction block does not match channel close height"
                    .into(),
            ));
        }
        operation.confirmed_block_height = observation.block_height;
        operation.observed_confirmations = observation.confirmations;
        if operation.status == L1ChannelCloseStatus::ConfirmedClosed {
            return self.confirm_and_retire_channel_close(operation);
        }
        operation = self.transition_close_status(
            operation,
            L1ChannelCloseStatus::Submitted,
            ChannelLifecycleStatus::Submitted,
            JournalPhase::L1CloseSubmitted,
            None,
        )?;
        if operation.observed_confirmations < L1_CLOSE_MIN_CONFIRMATIONS {
            return Ok(channel_close_response(&operation));
        }
        self.confirm_and_retire_channel_close(operation)
    }

    fn confirm_and_retire_channel_close(
        &self,
        operation: PersistedL1ChannelClose,
    ) -> HubResult<L1ChannelCloseResponse> {
        if operation.confirmed_block_height.is_none()
            || operation.observed_confirmations < L1_CLOSE_MIN_CONFIRMATIONS
            || operation.final_ledger.is_none()
        {
            return Err(HubError::State(
                "close cannot retire without exact final ledger and confirmation evidence".into(),
            ));
        }
        let confirmed = if operation.status == L1ChannelCloseStatus::ConfirmedClosed {
            operation
        } else {
            self.transition_close_status(
                operation,
                L1ChannelCloseStatus::ConfirmedClosed,
                ChannelLifecycleStatus::ConfirmedClosed,
                JournalPhase::L1CloseConfirmed,
                None,
            )?
        };
        let retired = self.transition_close_status(
            confirmed,
            L1ChannelCloseStatus::Retired,
            ChannelLifecycleStatus::Retired,
            JournalPhase::L1CloseRetired,
            None,
        )?;
        Ok(channel_close_response(&retired))
    }

    /// Release one channel-close freeze that the durable record proves was
    /// never signed.
    ///
    /// The reason travels with the record (`last_error`) and is served on
    /// `/v1/l1/channel/close/{id}`, so the person who pressed Close is told why
    /// their attempt was given up instead of meeting a bare `RecoveryRequired`.
    fn cancel_close_before_signing(
        &self,
        operation: PersistedL1ChannelClose,
        reason: String,
    ) -> HubResult<PersistedL1ChannelClose> {
        self.transition_close_status(
            operation,
            L1ChannelCloseStatus::CancelledBeforeSigning,
            ChannelLifecycleStatus::FrozenBeforeSigning,
            JournalPhase::L1CloseCancelledBeforeSigning,
            Some(reason),
        )
    }

    /// Give up every channel-close freeze whose authorization has lapsed and
    /// which the durable record proves was never signed.
    ///
    /// This is the close-side counterpart of `retire_unmined_channel_opens`,
    /// and it exists because the per-operation expiry check inside
    /// `resume_channel_close` is unreachable in the case that matters: a second
    /// attempt on the same channel carries a fresh `operation_id` and expiry,
    /// so it is turned away by the partial-transaction commitment index long
    /// before any status is looked at. Without a sweep the person holding a
    /// dead freeze has no button that reaches the state machine at all.
    ///
    /// Runs before `ensure_settlement_ready` on purpose: a never-signed close
    /// pushed to `RecoveryRequired` latches the whole Hub, and this is the only
    /// thing that can take that latch back down. Every write it makes is
    /// evidence-gated by `close_is_provably_unsigned`.
    fn cancel_expired_unsigned_channel_closes(&self) -> HubResult<()> {
        let now = crate::node::now_unix();
        let expired: Vec<PersistedL1ChannelClose> = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            guard
                .l1_channel_closes
                .values()
                .filter(|operation| {
                    close_is_provably_unsigned(operation) && now > operation.expires_unix
                })
                .cloned()
                .collect()
        };
        for operation in expired {
            let operation_id = operation.operation_id.clone();
            self.cancel_close_before_signing(operation, EXPIRED_UNSIGNED_CLOSE_REASON.to_string())
                .map_err(|error| {
                    HubError::State(format!(
                        "channel-close {operation_id} could not be released: {error}"
                    ))
                })?;
        }
        Ok(())
    }

    fn mark_close_recovery_required(
        &self,
        operation: PersistedL1ChannelClose,
        error: String,
    ) -> HubResult<PersistedL1ChannelClose> {
        self.transition_close_status(
            operation,
            L1ChannelCloseStatus::RecoveryRequired,
            ChannelLifecycleStatus::RecoveryRequired,
            JournalPhase::L1CloseRecoveryRequired,
            Some(error),
        )
    }

    fn transition_close_status(
        &self,
        mut operation: PersistedL1ChannelClose,
        status: L1ChannelCloseStatus,
        lifecycle_status: ChannelLifecycleStatus,
        phase: JournalPhase,
        last_error: Option<String>,
    ) -> HubResult<PersistedL1ChannelClose> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let current = guard
            .l1_channel_closes
            .get(&operation.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable channel-close operation disappeared".into()))?;
        if current.request_commitment != operation.request_commitment {
            return Err(HubError::State(
                "RecoveryRequired: channel-close operation changed".into(),
            ));
        }
        if current.status == L1ChannelCloseStatus::Retired
            || current.status == L1ChannelCloseStatus::CancelledBeforeSigning
        {
            return Ok(current);
        }
        // The proof is re-read from the durable record under the write lock,
        // never from the caller's copy. If anything about this operation says a
        // signature may exist, the cancel is refused and the operation keeps
        // its hold - not knowing is not evidence.
        if status == L1ChannelCloseStatus::CancelledBeforeSigning
            && !close_is_provably_unsigned(&current)
        {
            return Err(HubError::State(format!(
                "channel-close {} cannot be cancelled: the durable record does not prove it is \
                 unsigned (status {}, signed bytes {})",
                current.operation_id,
                current.status.public_name(),
                if current.signed_transaction_hex.is_some() {
                    "present"
                } else {
                    "absent"
                }
            )));
        }
        if !can_transition_close_status(&current.status, &status) {
            return Err(HubError::State(format!(
                "RecoveryRequired: invalid channel-close transition {:?} -> {:?}",
                current.status, status
            )));
        }
        let confirmed_block_height = operation.confirmed_block_height;
        let observed_confirmations = operation.observed_confirmations;
        operation = current;
        if confirmed_block_height.is_some() {
            operation.confirmed_block_height = confirmed_block_height;
            operation.observed_confirmations = observed_confirmations;
        }
        operation.status = status.clone();
        operation.updated_unix = crate::node::now_unix();
        operation.last_error = last_error;
        let mut next = guard.clone();
        next.l1_channel_closes
            .insert(operation.operation_id.clone(), operation.clone());
        if status == L1ChannelCloseStatus::CancelledBeforeSigning {
            // Give back everything the freeze took. The channel is unfrozen so
            // Fast Pay works again, and the partial-transaction commitment
            // index is released so a *fresh* close request for the same channel
            // is not turned away by "commitment maps to different request
            // content" - which is what happens when only the status changes.
            //
            // The operation record and its idempotency key stay: replaying the
            // exact cancelled request returns `cancelled_before_signing` with
            // the reason attached, rather than silently starting a second one.
            next.channel_lifecycle.remove(&operation.channel_id);
            next.l1_channel_close_commitments
                .remove(&operation.partial_transaction_commitment);
        } else {
            update_lifecycle(&mut next, &operation, lifecycle_status)?;
        }
        if status == L1ChannelCloseStatus::Retired {
            // On-chain agreement-close confirmation makes the old L2 ledger
            // unusable. Remove only the active indexes; the signed open/close
            // audit records remain durable for idempotent historical recovery.
            next.channel_lifecycle.remove(&operation.channel_id);
            next.channels.remove(&operation.channel_id);
        }
        self.commit_channel_close_transition(&mut guard, next, &operation, phase)?;
        Ok(operation)
    }

    fn existing_channel_close(
        &self,
        request: &L1ChannelCloseRequest,
        commitment: &str,
    ) -> HubResult<Option<PersistedL1ChannelClose>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        existing_channel_close_from_state(&guard, request, commitment)
    }

    fn load_channel_close(&self, operation_id: &str) -> HubResult<PersistedL1ChannelClose> {
        self.inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .l1_channel_closes
            .get(operation_id)
            .cloned()
            .ok_or_else(|| HubError::NotFound(format!("channel close {operation_id}")))
    }

    fn commit_channel_close_transition(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        operation: &PersistedL1ChannelClose,
        phase: JournalPhase,
    ) -> HubResult<()> {
        self.ensure_l1_close_recovery_allowed(guard, &operation.operation_id)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state store is unavailable".into()))?;
        let previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        let new_state_commitment = state_commitment(&next_state)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: operation.channel_id.clone(),
            channel_reuse_version: operation.reuse_version,
            operation_id: operation.operation_id.clone(),
            operation_type: JournalOperationType::L1ChannelClose,
            operation_phase: phase,
            amount_units: 0,
            sender: operation.user_address.clone(),
            recipient: self.hub_address.clone(),
            previous_state_commitment,
            new_state_commitment: new_state_commitment.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: Some(
                operation
                    .final_ledger
                    .as_ref()
                    .unwrap_or(&operation.original_ledger)
                    .bill_auto_number,
            ),
            unsigned_state_commitment: Some(operation.partial_transaction_commitment.clone()),
            created_at: crate::node::now_unix(),
        })?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = new_state_commitment.clone();
        if let Err(error) = store.save(&next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: close journal advanced but state was not durable: {error}"
            )));
        }
        if let Err(error) = journal.write_checkpoint(&JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: new_state_commitment,
        }) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: close state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        self.refresh_recovery_gate(guard);
        Ok(())
    }
}

fn submitted_exact_retry_due(updated_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(updated_unix) >= SUBMITTED_EXACT_RETRY_GRACE_SECONDS
}
fn can_transition_close_status(
    current: &L1ChannelCloseStatus,
    next: &L1ChannelCloseStatus,
) -> bool {
    use L1ChannelCloseStatus::*;
    match current {
        FreezeIntentPersisted => {
            matches!(
                next,
                FrozenBeforeSigning | CancelledBeforeSigning | RecoveryRequired
            )
        }
        FrozenBeforeSigning => {
            matches!(
                next,
                SignatureMayExist | CancelledBeforeSigning | RecoveryRequired
            )
        }
        // SubmissionStarted remains accepted from SignatureMayExist only to
        // recover authenticated v6 state that already persisted exact bytes.
        SignatureMayExist => matches!(next, SubmissionStarted | RecoveryRequired),
        Signed => matches!(next, SubmissionStarted | Submitted | RecoveryRequired),
        SubmissionStarted => matches!(next, Submitted | RecoveryRequired),
        Submitted => matches!(
            next,
            SubmissionStarted | Submitted | ConfirmedClosed | RecoveryRequired
        ),
        // `CancelledBeforeSigning` is admitted here on purpose, and it is the
        // only way an already-latched Hub can be released. A close can reach
        // `RecoveryRequired` from either side of the signature: from
        // `FreezeIntentPersisted`/`FrozenBeforeSigning`, where nothing was ever
        // signed, or from `Signed`/`Submitted`, where exact bytes are durable
        // and must be driven to the chain instead. `close_is_provably_unsigned`
        // separates the two by reading the record, not by reading a clock, and
        // `transition_close_status` refuses the cancel unless it holds.
        RecoveryRequired => matches!(
            next,
            SubmissionStarted
                | Submitted
                | ConfirmedClosed
                | CancelledBeforeSigning
                | RecoveryRequired
        ),
        ConfirmedClosed => matches!(next, Retired | RecoveryRequired),
        Retired | CancelledBeforeSigning => false,
    }
}

/// Whether the durable record *proves* this close never produced a signature.
///
/// Not "probably", and not "it has been a while". Every field that would exist
/// if the Hub had ever countersigned these bytes is checked to be absent, and
/// the status is one of the three a never-signed close can be sitting in. A
/// cooperative close cannot reach the chain without the Hub's countersignature,
/// so a record that satisfies this describes an operation that did nothing and
/// can never have done anything.
///
/// An unreachable node releases nothing here: this reads only durable state the
/// Hub itself wrote, and every caller has already been past the chain query
/// that would have found the channel closed.
fn close_is_provably_unsigned(operation: &PersistedL1ChannelClose) -> bool {
    matches!(
        operation.status,
        L1ChannelCloseStatus::FreezeIntentPersisted
            | L1ChannelCloseStatus::FrozenBeforeSigning
            | L1ChannelCloseStatus::RecoveryRequired
    ) && operation.signed_transaction_hex.is_none()
        && operation.signed_transaction_commitment.is_none()
        && operation.confirmed_block_height.is_none()
        && operation.observed_confirmations == 0
}
fn existing_channel_close_from_state(
    state: &HubPersistedState,
    request: &L1ChannelCloseRequest,
    commitment: &str,
) -> HubResult<Option<PersistedL1ChannelClose>> {
    if let Some(operation) = state.l1_channel_closes.get(&request.operation_id) {
        if operation.request_commitment != commitment {
            return Err(HubError::Payment(
                "operation_id was already used for different channel-close bytes".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    if let Some(operation_id) = state
        .l1_channel_close_idempotency
        .get(&request.idempotency_key)
    {
        let operation = state.l1_channel_closes.get(operation_id).ok_or_else(|| {
            HubError::State("channel-close idempotency index is inconsistent".into())
        })?;
        if operation.request_commitment != commitment {
            return Err(HubError::Payment(
                "idempotency key was already used for different channel-close bytes".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    if let Some(operation_id) = state
        .l1_channel_close_commitments
        .get(&request.partial_transaction_commitment)
    {
        let operation = state.l1_channel_closes.get(operation_id).ok_or_else(|| {
            HubError::State("channel-close commitment index is inconsistent".into())
        })?;
        if operation.partial_transaction_hex != request.partial_transaction_hex
            || operation.channel_id != request.channel_id
            || operation.request_commitment != commitment
        {
            return Err(HubError::Payment(
                "channel-close commitment maps to different request content".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    Ok(None)
}

fn channel_refund_zhu(
    channel: &ChannelInfo,
    original: &crate::storage::ChannelLedger,
    address: &str,
) -> HubResult<u128> {
    let millimeis = if channel.left.address == address {
        original.left_balance_mei.as_millimeis()
    } else if channel.right.address == address {
        original.right_balance_mei.as_millimeis()
    } else {
        return Err(HubError::State(
            "close liquidity address is not a channel party".into(),
        ));
    };
    u128::from(millimeis)
        .checked_mul(u128::from(crate::readiness::ZHU_PER_MILLIMEI))
        .ok_or_else(|| HubError::State("channel refund liquidity overflow".into()))
}

fn require_channel_can_freeze(
    state: &HubPersistedState,
    channel: &ChannelInfo,
    expected_hub_address: &str,
    original: &crate::storage::ChannelLedger,
    settlement: &ChannelCloseSettlement,
) -> HubResult<crate::storage::ChannelLedger> {
    // `!is_terminal()` was missing here, and it was the whole defect. Every
    // other reservation exclusion in the Hub asks the status; this one asked
    // only the channel id. `Committed` reservations are removed from `pending`,
    // but `Expired` ones are written back and left there forever - so a payment
    // that provably never produced a signature, resolved exactly as designed,
    // took the channel's cooperative exit away permanently, and did it behind a
    // sentence ("has a pending or recovery payment") that was not true.
    if let Some(blocking) = state.pending.values().find(|pending| {
        !pending.status.is_terminal()
            && (pending.channel_id == channel.id
                || pending.payee_channel_id.as_deref() == Some(channel.id.as_str()))
    }) {
        return Err(HubError::Channel(format!(
            "channel has an unresolved Fast Pay reservation ({}, {}) and cannot close until it is \
             reconciled",
            blocking.operation_id,
            blocking.status.public_name()
        )));
    }
    if channel.reuse_version != 1 || channel.left.satoshi != 0 || channel.right.satoshi != 0 {
        return Err(HubError::Channel(
            "cooperative close pilot requires a fresh, never-reused HPAY-managed HAC-only channel"
                .into(),
        ));
    }
    let anchored_open = state.l1_channel_opens.values().any(|open| {
        crate::state::open::confirmed_open_has_finality_evidence(open)
            && open.reuse_version == channel.reuse_version
            && open.channel_id.eq_ignore_ascii_case(&channel.id)
            && open.confirmed_block_height == Some(channel.open_height)
            && open.user_address == channel.left.address
            && channel.right.address == expected_hub_address
            && open.user_deposit_zhu
                == original
                    .left_balance_mei
                    .as_millimeis()
                    .saturating_mul(crate::readiness::ZHU_PER_MILLIMEI)
            && original.right_balance_mei == crate::amount::HacAmount::ZERO
    });
    if !anchored_open {
        return Err(HubError::Channel(
            "cooperative close rejected: authoritative HPAY channel-open anchor is missing".into(),
        ));
    }
    let effective = state.channels.get(&channel.id).ok_or_else(|| {
        HubError::Channel(
            "cooperative close rejected: authoritative latest L2 ledger is missing".into(),
        )
    })?;
    let mut settled_left = original.left_balance_mei;
    let mut settled_right = original.right_balance_mei;
    if let ChannelCloseSettlement::PrincipalTransfer {
        from_address,
        to_address,
        amount_millimeis,
    } = settlement
    {
        let amount = crate::amount::HacAmount::from_millimeis(*amount_millimeis);
        if from_address == &channel.left.address && to_address == &channel.right.address {
            settled_left = settled_left.checked_sub(amount)?;
            settled_right = settled_right.checked_add(amount)?;
        } else if from_address == &channel.right.address && to_address == &channel.left.address {
            settled_right = settled_right.checked_sub(amount)?;
            settled_left = settled_left.checked_add(amount)?;
        } else {
            return Err(HubError::Channel(
                "cooperative close principal transfer does not match the channel parties".into(),
            ));
        }
    }
    if effective.left_balance_mei != settled_left || effective.right_balance_mei != settled_right {
        return Err(HubError::Channel(
            "cooperative close rejected: transaction settlement differs from the authoritative latest L2 ledger"
                .into(),
        ));
    }
    Ok(effective.clone())
}
fn expected_incarnation(
    channel: &ChannelInfo,
    request: &L1ChannelCloseRequest,
    hub_address: &str,
    require_open: bool,
) -> HubResult<ExpectedChannelIncarnation> {
    if require_open && !channel.is_open() {
        return Err(HubError::Channel("channel is not open".into()));
    }
    if channel.open_height == 0 || channel.reuse_version == 0 {
        return Err(HubError::Channel(
            "fullnode did not report a complete channel incarnation".into(),
        ));
    }
    if channel.challenging.is_some() {
        return Err(HubError::Channel(
            "channel has an active challenge and cannot use cooperative close".into(),
        ));
    }
    if !channel.id.eq_ignore_ascii_case(&request.channel_id) {
        return Err(HubError::Channel(
            "fullnode returned a different channel ID".into(),
        ));
    }
    if channel.party_side(hub_address).is_none()
        || channel.party_side(&request.user_address).is_none()
        || request.user_address == hub_address
    {
        return Err(HubError::Channel(
            "channel parties do not match the user and Hub".into(),
        ));
    }
    Ok(ExpectedChannelIncarnation {
        channel_id: channel.id.clone(),
        user_address: request.user_address.clone(),
        hub_address: hub_address.to_owned(),
        reuse_version: channel.reuse_version,
        open_height: channel.open_height,
    })
}

fn ensure_same_incarnation(
    channel: &ChannelInfo,
    operation: &PersistedL1ChannelClose,
) -> HubResult<()> {
    if !channel.id.eq_ignore_ascii_case(&operation.channel_id)
        || channel.open_height != operation.open_height
        || channel.reuse_version != operation.reuse_version
        || channel.party_side(&operation.user_address).is_none()
    {
        return Err(HubError::State(
            "RecoveryRequired: fullnode channel incarnation changed".into(),
        ));
    }
    Ok(())
}

fn ensure_same_open_incarnation(
    channel: &ChannelInfo,
    operation: &PersistedL1ChannelClose,
) -> HubResult<()> {
    ensure_same_incarnation(channel, operation)?;
    if !channel.is_open() || channel.challenging.is_some() {
        return Err(HubError::State(
            "RecoveryRequired: channel is no longer safely open".into(),
        ));
    }
    Ok(())
}

fn update_lifecycle(
    state: &mut HubPersistedState,
    operation: &PersistedL1ChannelClose,
    status: ChannelLifecycleStatus,
) -> HubResult<()> {
    let lifecycle = state
        .channel_lifecycle
        .get_mut(&operation.channel_id)
        .ok_or_else(|| HubError::State("channel lifecycle disappeared".into()))?;
    if lifecycle.operation_id != operation.operation_id
        || lifecycle.open_height != operation.open_height
        || lifecycle.reuse_version != operation.reuse_version
    {
        return Err(HubError::State(
            "channel lifecycle belongs to a different close operation".into(),
        ));
    }
    lifecycle.status = status;
    lifecycle.updated_unix = crate::node::now_unix();
    Ok(())
}

fn request_from_operation(operation: &PersistedL1ChannelClose) -> L1ChannelCloseRequest {
    L1ChannelCloseRequest {
        schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
        network: operation.network.clone(),
        chain_id: operation.chain_id,
        mainnet: operation.mainnet,
        block_1_hash: operation.block_1_hash.clone(),
        node_profile_id: operation.node_profile_id.clone(),
        network_instance_id: operation.network_instance_id.clone(),
        transaction_format_version: operation.transaction_format_version,
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        created_unix: operation.created_unix,
        expires_unix: operation.expires_unix,
        hub_address: operation.hub_address.clone(),
        user_address: operation.user_address.clone(),
        channel_id: operation.channel_id.clone(),
        reuse_version: operation.reuse_version,
        open_height: operation.open_height,
        partial_transaction_hex: operation.partial_transaction_hex.clone(),
        partial_transaction_commitment: operation.partial_transaction_commitment.clone(),
        authorization_public_key_hex: operation.authorization_public_key_hex.clone(),
        authorization_signature_hex: operation.authorization_signature_hex.clone(),
    }
}

fn persisted_close_network_binding(
    operation: &PersistedL1ChannelClose,
) -> crate::l1_channel::L1ChannelNetworkBinding {
    crate::l1_channel::L1ChannelNetworkBinding {
        network_kind: operation.network.clone(),
        chain_id: operation.chain_id,
        mainnet: operation.mainnet,
        block_1_hash: operation.block_1_hash.clone(),
        node_profile_id: operation.node_profile_id.clone(),
        network_instance_id: operation.network_instance_id.clone(),
        transaction_format_version: operation.transaction_format_version,
    }
}

/// The close that is currently holding the Hub-wide close-liquidity
/// reservation, read with exactly the predicate `require_close_liquidity`
/// refuses on, so the document and the gate can never disagree.
pub(super) fn close_liquidity_reservation(
    state: &HubPersistedState,
) -> Option<crate::readiness::CloseLiquidityReservation> {
    state
        .l1_channel_closes
        .values()
        .find(|operation| {
            signature_may_exist(operation) && operation.status != L1ChannelCloseStatus::Retired
        })
        .map(|operation| crate::readiness::CloseLiquidityReservation {
            operation_id: operation.operation_id.clone(),
            channel_id: operation.channel_id.clone(),
            status: operation.status.public_name().to_string(),
            transaction_hash: operation.transaction_hash.clone(),
        })
}

fn signature_may_exist(operation: &PersistedL1ChannelClose) -> bool {
    matches!(
        operation.status,
        L1ChannelCloseStatus::SignatureMayExist
            | L1ChannelCloseStatus::Signed
            | L1ChannelCloseStatus::SubmissionStarted
            | L1ChannelCloseStatus::Submitted
            | L1ChannelCloseStatus::ConfirmedClosed
            | L1ChannelCloseStatus::Retired
            | L1ChannelCloseStatus::RecoveryRequired
    )
}

fn channel_close_response(operation: &PersistedL1ChannelClose) -> L1ChannelCloseResponse {
    L1ChannelCloseResponse {
        schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
        operation_id: operation.operation_id.clone(),
        channel_id: operation.channel_id.clone(),
        reuse_version: operation.reuse_version,
        open_height: operation.open_height,
        status: operation.status.public_name().into(),
        transaction_hash: operation.transaction_hash.clone(),
        // The Hub owns the broadcast on the cooperative-close path, so the
        // signed bytes stay here.
        signed_transaction_hex: None,
        signed_transaction_commitment: None,
        reason: operation.last_error.clone(),
    }
}

fn channel_close_voucher_response(
    voucher: &PersistedL1ChannelCloseVoucher,
) -> L1ChannelCloseResponse {
    L1ChannelCloseResponse {
        schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
        operation_id: voucher.operation_id.clone(),
        channel_id: voucher.channel_id.clone(),
        reuse_version: voucher.reuse_version,
        open_height: voucher.open_height,
        status: L1_CHANNEL_CLOSE_VOUCHER_STATUS.into(),
        transaction_hash: Some(voucher.transaction_hash.clone()),
        signed_transaction_hex: voucher.signed_transaction_hex.clone(),
        signed_transaction_commitment: voucher.signed_transaction_commitment.clone(),
        reason: None,
    }
}

fn voucher_network_binding(
    voucher: &PersistedL1ChannelCloseVoucher,
) -> crate::l1_channel::L1ChannelNetworkBinding {
    crate::l1_channel::L1ChannelNetworkBinding {
        network_kind: voucher.network.clone(),
        chain_id: voucher.chain_id,
        mainnet: voucher.mainnet,
        block_1_hash: voucher.block_1_hash.clone(),
        node_profile_id: voucher.node_profile_id.clone(),
        network_instance_id: voucher.network_instance_id.clone(),
        transaction_format_version: voucher.transaction_format_version,
    }
}

/// A voucher may only ever be the bare two-action form, which refunds the
/// distribution recorded at open and moves nothing else.
///
/// An Action 14 principal transfer is refused outright rather than settled,
/// because a voucher is signed once and lives forever: a transfer signed today
/// would still be spendable after any number of later payments, and would then
/// describe a settlement that no longer matches anything.
fn require_delta_zero_voucher_settlement(settlement: &ChannelCloseSettlement) -> HubResult<()> {
    match settlement {
        ChannelCloseSettlement::OriginalDistribution => Ok(()),
        ChannelCloseSettlement::PrincipalTransfer { .. } => Err(HubError::Channel(
            "a channel-close voucher must be the delta-zero original distribution and cannot carry a principal transfer"
                .into(),
        )),
    }
}

/// The proof that no payment has been made: the authoritative L2 ledger still
/// equals the distribution L1 recorded at open, the whole deposit on the
/// owner's side and nothing on the Hub's.
///
/// A voucher is only ever issued at delta zero, so this is the moment the
/// channel is worth exactly what the voucher pays out, and the Hub's exposure
/// is at its smallest it will ever be.
fn require_untouched_delta_zero_ledger(
    effective: &crate::storage::ChannelLedger,
    original: &crate::storage::ChannelLedger,
) -> HubResult<()> {
    if effective != original {
        return Err(HubError::Channel(
            "a channel-close voucher requires the authoritative L2 ledger to still equal the distribution recorded at open"
                .into(),
        ));
    }
    if original.right_balance_mei != crate::amount::HacAmount::ZERO {
        return Err(HubError::Channel(
            "a channel-close voucher requires a zero Hub-side balance at open".into(),
        ));
    }
    if original.left_balance_mei == crate::amount::HacAmount::ZERO {
        return Err(HubError::Channel(
            "a channel-close voucher requires a funded owner-side deposit".into(),
        ));
    }
    Ok(())
}

pub(super) fn ledger_commitment(ledger: &crate::storage::ChannelLedger) -> HubResult<String> {
    let bytes = serde_json::to_vec(ledger).map_err(|error| HubError::State(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use basis::interface::Transaction;
    use field::{AddrHac, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
    use mint::action::ChannelOpen;
    use protocol::action::{ChainAllow, ChainIDList};
    use protocol::transaction::TransactionType2;
    use sys::Account;

    use crate::amount::HacAmount;
    use crate::channel_id::derive_channel_id;
    use crate::l1_channel::{
        L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, request_commitment, transaction_commitment,
        validate_and_cosign_channel_open,
    };
    use crate::storage::{
        ChannelLedger, L1ChannelOpenStatus, PendingSettlement, PersistedL1ChannelOpen,
    };

    #[test]
    fn a_voucher_requires_the_bare_delta_zero_form_and_an_untouched_ledger() {
        assert!(
            require_delta_zero_voucher_settlement(&ChannelCloseSettlement::OriginalDistribution)
                .is_ok()
        );
        let transfer = ChannelCloseSettlement::PrincipalTransfer {
            from_address: "one".into(),
            to_address: "two".into(),
            amount_millimeis: 1,
        };
        assert!(
            require_delta_zero_voucher_settlement(&transfer)
                .unwrap_err()
                .to_string()
                .contains("cannot carry a principal transfer")
        );

        let original = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(10),
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: 0,
        };
        assert!(require_untouched_delta_zero_ledger(&original, &original).is_ok());

        let moved = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(9),
            right_balance_mei: HacAmount::from_millimeis(1),
            bill_auto_number: 1,
        };
        assert!(require_untouched_delta_zero_ledger(&moved, &original).is_err());

        let hub_funded = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(10),
            right_balance_mei: HacAmount::from_millimeis(1),
            bill_auto_number: 0,
        };
        assert!(
            require_untouched_delta_zero_ledger(&hub_funded, &hub_funded)
                .unwrap_err()
                .to_string()
                .contains("zero Hub-side balance")
        );

        let empty = ChannelLedger {
            left_balance_mei: HacAmount::ZERO,
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: 0,
        };
        assert!(
            require_untouched_delta_zero_ledger(&empty, &empty)
                .unwrap_err()
                .to_string()
                .contains("funded owner-side deposit")
        );
    }

    #[test]
    fn submitted_retry_uses_a_bounded_grace_period() {
        assert!(!submitted_exact_retry_due(100, 129));
        assert!(submitted_exact_retry_due(100, 130));
    }

    fn canonical_open_anchor(
        user: &Account,
        hub: &Account,
        open_height: u64,
    ) -> PersistedL1ChannelOpen {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let channel_id = derive_channel_id(user.readable(), hub.readable(), 1);
        let mut action = ChannelOpen::new();
        action.channel_id =
            ChannelId::from(<[u8; 16]>::try_from(hex::decode(&channel_id).unwrap()).unwrap());
        action.left_bill = AddrHac {
            address: Address::from_readable(user.readable()).unwrap(),
            amount: Amount::from("0.01").unwrap(),
        };
        action.right_bill = AddrHac {
            address: Address::from_readable(hub.readable()).unwrap(),
            amount: Amount::from("0").unwrap(),
        };
        let now = crate::node::now_unix();
        let mut transaction = TransactionType2::new_by(
            Address::from_readable(user.readable()).unwrap(),
            Amount::from("0.0001").unwrap(),
            now,
        );
        let mut guard = ChainAllow::new();
        guard.chains = ChainIDList::from_list(vec![Uint4::from(0)]).unwrap();
        transaction.push_action(Box::new(guard)).unwrap();
        transaction.push_action(Box::new(action)).unwrap();
        let network = crate::l1_channel::L1ChannelNetworkBinding::from_node_identity(
            "mainnet",
            true,
            0,
            crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
            "hacash-mainnet",
            Some(&crate::l1_channel::canonical_network_instance_id(
                "mainnet",
                0,
                true,
                crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
                "hacash-mainnet",
                2,
            )),
            2,
        )
        .unwrap();
        transaction.fill_sign(user).unwrap();
        let partial_transaction_hex = hex::encode(transaction.serialize());
        let mut request = L1ChannelOpenRequest {
            schema: L1_CHANNEL_OPEN_SCHEMA.into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: network.block_1_hash.clone(),
            node_profile_id: network.node_profile_id.clone(),
            network_instance_id: network.network_instance_id.clone(),
            transaction_format_version: 2,
            operation_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            created_unix: now,
            expires_unix: now + 60,
            hub_address: hub.readable().into(),
            channel_id: channel_id.clone(),
            expected_reuse_version: 1,
            partial_transaction_commitment: transaction_commitment(&partial_transaction_hex)
                .unwrap(),
            partial_transaction_hex,
            authorization_public_key_hex: String::new(),
            authorization_signature_hex: String::new(),
        };
        let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        request.authorization_public_key_hex =
            hex::encode(user.public_key().serialize_compressed());
        request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
        let signed =
            validate_and_cosign_channel_open(&request, hub, &network, 1_000_000, now).unwrap();
        let durable_request_commitment = request_commitment(&request).unwrap();
        PersistedL1ChannelOpen {
            operation_id: request.operation_id,
            idempotency_key: request.idempotency_key,
            request_commitment: durable_request_commitment,
            network: network.network_kind,
            chain_id: network.chain_id,
            mainnet: network.mainnet,
            block_1_hash: network.block_1_hash,
            node_profile_id: network.node_profile_id,
            network_instance_id: network.network_instance_id,
            transaction_format_version: network.transaction_format_version,
            channel_id,
            reuse_version: 1,
            user_address: user.readable().into(),
            user_deposit_zhu: signed.user_deposit_zhu,
            network_fee_zhu: signed.network_fee_zhu,
            partial_transaction_hex: request.partial_transaction_hex,
            partial_transaction_commitment: request.partial_transaction_commitment,
            transaction_hash: signed.transaction_hash,
            signed_transaction_hex: Some(signed.signed_transaction_hex),
            signed_transaction_commitment: Some(signed.signed_transaction_commitment),
            confirmed_block_height: Some(open_height),
            broadcast_height: Some(open_height),
            observed_confirmations: 6,
            status: L1ChannelOpenStatus::Confirmed,
            created_unix: now,
            expires_unix: now + 60,
            updated_unix: now,
            last_error: None,
        }
    }

    #[test]
    fn close_rejects_divergent_or_pending_l2_state() {
        let user = Account::create_by("close-anchor-user").unwrap();
        let hub = Account::create_by("close-anchor-hub").unwrap();
        let open = canonical_open_anchor(&user, &hub, 100);
        let original = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(10),
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: 0,
        };
        let channel = ChannelInfo {
            ret: 0,
            id: open.channel_id.clone(),
            status: crate::node::CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version: 1,
            left: crate::node::ChannelPartyBalance {
                address: user.readable().into(),
                hacash: "0.01".into(),
                satoshi: 0,
            },
            right: crate::node::ChannelPartyBalance {
                address: hub.readable().into(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        };
        let mut state = HubPersistedState::default();
        state.l1_channel_opens.insert("open-operation".into(), open);
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_err()
        );
        state.channels.insert(
            channel.id.clone(),
            ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(9),
                right_balance_mei: HacAmount::from_millimeis(1),
                bill_auto_number: 1,
            },
        );
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_err()
        );
        let exact_transfer = ChannelCloseSettlement::PrincipalTransfer {
            from_address: user.readable().into(),
            to_address: hub.readable().into(),
            amount_millimeis: 1,
        };
        let settled = require_channel_can_freeze(
            &state,
            &channel,
            hub.readable(),
            &original,
            &exact_transfer,
        )
        .unwrap();
        assert_eq!(settled, state.channels[&channel.id]);
        state
            .l1_channel_opens
            .get_mut("open-operation")
            .unwrap()
            .observed_confirmations = 5;
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &exact_transfer,
            )
            .unwrap_err()
            .to_string()
            .contains("authoritative HPAY channel-open anchor is missing")
        );
        state
            .l1_channel_opens
            .get_mut("open-operation")
            .unwrap()
            .observed_confirmations = 6;
        let wrong_transfer = ChannelCloseSettlement::PrincipalTransfer {
            from_address: user.readable().into(),
            to_address: hub.readable().into(),
            amount_millimeis: 2,
        };
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &wrong_transfer,
            )
            .is_err()
        );
        state.channels.insert(channel.id.clone(), original.clone());
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_ok()
        );
        let mut reused = channel.clone();
        reused.reuse_version = 2;
        assert!(
            require_channel_can_freeze(
                &state,
                &reused,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_err()
        );
        let mut with_satoshi = channel.clone();
        with_satoshi.left.satoshi = 1;
        assert!(
            require_channel_can_freeze(
                &state,
                &with_satoshi,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_err()
        );

        let pending: PendingSettlement = serde_json::from_value(serde_json::json!({
            "created_at": 1,
            "channel_id": channel.id.clone(),
            "base_ledger": original,
            "next_ledger": {"left_balance_mei": 10, "right_balance_mei": 0, "bill_auto_number": 1},
            "response": {"payment_id":"p", "status":"pending"}
        }))
        .unwrap();
        state.pending.insert("p".into(), pending);
        let original = state.channels.get(&channel.id).unwrap().clone();
        assert!(
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .is_err()
        );
    }

    /// A Fast Pay reservation that resolved is not a reason to refuse a close.
    ///
    /// `require_channel_can_freeze` read `state.pending` by channel id alone,
    /// with no status filter - the only reservation exclusion in the Hub that
    /// did. `Committed` reservations are deleted from `pending`, but `Expired`
    /// ones are written back and stay there for the life of the state file, so
    /// one payment that provably never produced a signature, and that the Hub
    /// resolved exactly as designed, took that channel's cooperative exit away
    /// forever - behind the sentence "channel has a pending or recovery
    /// payment", which was not true of it.
    #[test]
    fn a_resolved_fast_pay_reservation_does_not_take_the_channel_exit_away() {
        let user = Account::create_by("close-terminal-pending-user").unwrap();
        let hub = Account::create_by("close-terminal-pending-hub").unwrap();
        let open = canonical_open_anchor(&user, &hub, 100);
        let original = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(10),
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: 0,
        };
        let channel = ChannelInfo {
            ret: 0,
            id: open.channel_id.clone(),
            status: crate::node::CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version: 1,
            left: crate::node::ChannelPartyBalance {
                address: user.readable().into(),
                hacash: "0.01".into(),
                satoshi: 0,
            },
            right: crate::node::ChannelPartyBalance {
                address: hub.readable().into(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        };
        let mut state = HubPersistedState::default();
        state.l1_channel_opens.insert("open-operation".into(), open);
        state.channels.insert(channel.id.clone(), original.clone());
        require_channel_can_freeze(
            &state,
            &channel,
            hub.readable(),
            &original,
            &ChannelCloseSettlement::OriginalDistribution,
        )
        .expect("a clean channel closes");

        let reservation = |status: crate::operation::ReservationStatus| -> PendingSettlement {
            let mut record: PendingSettlement = serde_json::from_value(serde_json::json!({
                "created_at": 1,
                "channel_id": channel.id.clone(),
                "base_ledger": original,
                "next_ledger": {
                    "left_balance_mei": 10, "right_balance_mei": 0, "bill_auto_number": 1
                },
                "response": {"payment_id":"p", "status":"pending"}
            }))
            .unwrap();
            record.status = status;
            record
        };

        // Unresolved: still refuses, and now says which reservation it is.
        state.pending.insert(
            "p".into(),
            reservation(crate::operation::ReservationStatus::Signed),
        );
        let refusal = require_channel_can_freeze(
            &state,
            &channel,
            hub.readable(),
            &original,
            &ChannelCloseSettlement::OriginalDistribution,
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("Fast Pay reservation"), "{refusal}");
        assert!(refusal.contains("signed"), "{refusal}");

        // Every terminal status releases the exit.
        for status in [
            crate::operation::ReservationStatus::Expired,
            crate::operation::ReservationStatus::Committed,
            crate::operation::ReservationStatus::Rejected,
            crate::operation::ReservationStatus::Released,
        ] {
            state.pending.insert("p".into(), reservation(status));
            require_channel_can_freeze(
                &state,
                &channel,
                hub.readable(),
                &original,
                &ChannelCloseSettlement::OriginalDistribution,
            )
            .unwrap_or_else(|error| {
                panic!("terminal reservation {status:?} still blocks the close: {error}")
            });
        }
    }

    fn unsigned_close_record() -> PersistedL1ChannelClose {
        PersistedL1ChannelClose {
            operation_id: "op".into(),
            idempotency_key: "key".into(),
            request_commitment: "commitment".into(),
            network: "testnet".into(),
            chain_id: 1,
            mainnet: false,
            block_1_hash: "b1".into(),
            node_profile_id: "profile".into(),
            network_instance_id: "instance".into(),
            transaction_format_version: 2,
            channel_id: "channel".into(),
            hub_address: "hub".into(),
            user_address: "user".into(),
            reuse_version: 1,
            open_height: 100,
            original_ledger: ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(10),
                right_balance_mei: HacAmount::ZERO,
                bill_auto_number: 0,
            },
            final_ledger: None,
            partial_transaction_hex: "00".into(),
            partial_transaction_commitment: "pc".into(),
            authorization_public_key_hex: String::new(),
            authorization_signature_hex: String::new(),
            transaction_hash: Some("hash".into()),
            signed_transaction_hex: None,
            signed_transaction_commitment: None,
            confirmed_block_height: None,
            observed_confirmations: 0,
            status: L1ChannelCloseStatus::FrozenBeforeSigning,
            created_unix: 1,
            expires_unix: 2,
            updated_unix: 1,
            last_error: None,
        }
    }

    /// The release is gated on evidence, never on a clock.
    #[test]
    fn only_a_provably_unsigned_close_may_be_cancelled() {
        let mut operation = unsigned_close_record();
        assert!(close_is_provably_unsigned(&operation));

        // Reachable from an already-latched Hub, which is the whole point: a
        // never-signed close that an older build pushed to RecoveryRequired
        // has to have a way back out, or the latch is permanent.
        operation.status = L1ChannelCloseStatus::RecoveryRequired;
        assert!(close_is_provably_unsigned(&operation));

        // Any trace of a signature refuses the release.
        let mut signed = operation.clone();
        signed.signed_transaction_hex = Some("deadbeef".into());
        assert!(!close_is_provably_unsigned(&signed));
        let mut committed = operation.clone();
        committed.signed_transaction_commitment = Some("c".into());
        assert!(!close_is_provably_unsigned(&committed));
        let mut mined = operation.clone();
        mined.confirmed_block_height = Some(900_001);
        assert!(!close_is_provably_unsigned(&mined));
        let mut confirmed = operation.clone();
        confirmed.observed_confirmations = 1;
        assert!(!close_is_provably_unsigned(&confirmed));
        for status in [
            L1ChannelCloseStatus::SignatureMayExist,
            L1ChannelCloseStatus::Signed,
            L1ChannelCloseStatus::SubmissionStarted,
            L1ChannelCloseStatus::Submitted,
            L1ChannelCloseStatus::ConfirmedClosed,
            L1ChannelCloseStatus::Retired,
        ] {
            let mut past = operation.clone();
            past.status = status.clone();
            assert!(!close_is_provably_unsigned(&past), "{status:?}");
        }
    }

    /// The close status machine has a terminal state that is not `Retired`,
    /// and every never-signed status can reach it - including the latched one.
    #[test]
    fn an_unsigned_close_has_somewhere_terminal_to_go() {
        use L1ChannelCloseStatus::*;
        for from in [FreezeIntentPersisted, FrozenBeforeSigning, RecoveryRequired] {
            assert!(
                can_transition_close_status(&from, &CancelledBeforeSigning),
                "{from:?}"
            );
        }
        for to in [
            FreezeIntentPersisted,
            FrozenBeforeSigning,
            SignatureMayExist,
            Signed,
            SubmissionStarted,
            Submitted,
            ConfirmedClosed,
            Retired,
            RecoveryRequired,
            CancelledBeforeSigning,
        ] {
            assert!(
                !can_transition_close_status(&CancelledBeforeSigning, &to),
                "{to:?}"
            );
        }
    }

    /// A released close holds nothing, and the readiness document says who
    /// does hold the Hub-wide close-liquidity reservation.
    #[test]
    fn a_released_close_stops_reserving_and_a_live_one_is_named() {
        let mut state = HubPersistedState::default();
        let mut operation = unsigned_close_record();
        operation.status = L1ChannelCloseStatus::CancelledBeforeSigning;
        state
            .l1_channel_closes
            .insert(operation.operation_id.clone(), operation.clone());
        assert!(close_liquidity_reservation(&state).is_none());

        let mut submitted = operation.clone();
        submitted.operation_id = "live".into();
        submitted.status = L1ChannelCloseStatus::Submitted;
        submitted.signed_transaction_hex = Some("deadbeef".into());
        state
            .l1_channel_closes
            .insert(submitted.operation_id.clone(), submitted);
        let held = close_liquidity_reservation(&state).expect("a submitted close reserves");
        assert_eq!(held.operation_id, "live");
        assert_eq!(held.channel_id, "channel");
        assert_eq!(held.status, "submitted");
        assert_eq!(held.transaction_hash.as_deref(), Some("hash"));
    }
}
