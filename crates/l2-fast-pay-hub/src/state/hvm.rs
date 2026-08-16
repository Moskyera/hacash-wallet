use std::sync::atomic::Ordering;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{HvmChannelBillV1, HvmChannelRecoveryBundleV1};
use crate::hvm_ledger::{
    HVM_CHANNEL_STATUS_SCHEMA, HVM_PAYMENT_STATUS_SCHEMA, HvmBillProgressionStatus,
    HvmChannelStatusV1, HvmPaymentRequestV1, HvmPaymentStatusV1, PersistedHvmBillProgression,
    PersistedHvmChannelLedger,
};
use crate::journal::{JournalEvent, JournalHead, JournalOperationType, JournalPhase};
use crate::storage::{
    HubPersistedState, HvmChainOperationStatus, PersistedHvmChannelActivation, state_commitment,
    validate_hvm_state,
};

use super::{HubState, unix_timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingHvmProgressionDisposition {
    ContinueUnsigned,
    ReturnDurableSignature,
    RequireReconciliation,
}

fn existing_hvm_progression_disposition(
    status: &HvmBillProgressionStatus,
) -> ExistingHvmProgressionDisposition {
    match status {
        HvmBillProgressionStatus::UserProposalPersisted => {
            ExistingHvmProgressionDisposition::ContinueUnsigned
        }
        HvmBillProgressionStatus::FullySigned => {
            ExistingHvmProgressionDisposition::ReturnDurableSignature
        }
        HvmBillProgressionStatus::HubSignatureMayExist
        | HvmBillProgressionStatus::RecoveryRequired => {
            ExistingHvmProgressionDisposition::RequireReconciliation
        }
    }
}

impl HubState {
    /// Verify and durably admit recovery material for a separate HVM channel.
    ///
    /// This does not add the channel to the native ChannelPay payment ledger
    /// and does not authorize signing. Every later operation must repeat the
    /// live node, contract-state and lease verification.
    pub async fn activate_hvm_channel_recovery(
        &self,
        recovery_bundle: HvmChannelRecoveryBundleV1,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<String> {
        self.ensure_settlement_ready()?;
        if minimum_required_live_blocks == 0 {
            return Err(HubError::State(
                "HVM activation requires a positive live lease minimum".into(),
            ));
        }
        if recovery_bundle.binding.right_hub_address != self.hub_address {
            return Err(HubError::State(
                "HVM recovery bundle is bound to a different Hub address".into(),
            ));
        }
        let binding_commitment = recovery_bundle.binding.commitment()?;
        let existing = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            guard
                .hvm_channel_activations
                .get(&binding_commitment)
                .cloned()
        };
        if let Some(existing) = existing {
            if existing.recovery_bundle != recovery_bundle
                || existing.minimum_required_live_blocks != minimum_required_live_blocks
                || existing.minimum_required_recover_blocks != minimum_required_recover_blocks
            {
                return Err(HubError::State(
                    "HVM activation retry does not match the exact persisted activation".into(),
                ));
            }
            if minimum_required_recover_blocks == 0 {
                if self
                    .node
                    .verify_hvm_recovery_bundle(&recovery_bundle, minimum_required_live_blocks, 1)
                    .await
                    .is_err()
                {
                    self.node
                        .verify_hvm_initial_recovery_bundle(
                            &recovery_bundle,
                            minimum_required_live_blocks,
                        )
                        .await?;
                }
            } else {
                self.node
                    .verify_hvm_recovery_bundle(
                        &recovery_bundle,
                        minimum_required_live_blocks,
                        minimum_required_recover_blocks,
                    )
                    .await?;
            }
            return Ok(binding_commitment);
        }
        let activation_snapshot = if minimum_required_recover_blocks == 0 {
            self.node
                .verify_hvm_initial_recovery_bundle(&recovery_bundle, minimum_required_live_blocks)
                .await?
        } else {
            self.node
                .verify_hvm_recovery_bundle(
                    &recovery_bundle,
                    minimum_required_live_blocks,
                    minimum_required_recover_blocks,
                )
                .await?
        };
        let activation = PersistedHvmChannelActivation {
            binding_commitment: binding_commitment.clone(),
            recovery_bundle,
            activation_snapshot,
            minimum_required_live_blocks,
            minimum_required_recover_blocks,
            activated_unix: unix_timestamp(),
        };
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next_state = guard.clone();
        if !insert_hvm_activation(&mut next_state, activation.clone())? {
            return Ok(binding_commitment);
        }
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: activation.recovery_bundle.binding.channel_id.clone(),
            channel_reuse_version: u64::from(activation.recovery_bundle.binding.reuse_version),
            operation_id: format!("hvm-activate-{binding_commitment}"),
            operation_type: JournalOperationType::HvmChannelActivation,
            operation_phase: JournalPhase::HvmChannelActivated,
            amount_units: activation.recovery_bundle.binding.left_deposit_zhu,
            sender: activation.recovery_bundle.binding.left_address.clone(),
            recipient: activation.recovery_bundle.binding.right_hub_address.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: format!("hvm-activate-{binding_commitment}"),
            request_commitment: binding_commitment.clone(),
            expected_bill_number: Some(1),
            unsigned_state_commitment: Some(binding_commitment.clone()),
            created_at: activation.activated_unix,
        };
        self.commit_authenticated_state(&mut guard, next_state, event)?;
        Ok(binding_commitment)
    }

    /// Durably co-sign one exact, user-signed HVM bill.
    ///
    /// HVM mainnet execution remains gated off. This method is the reviewed
    /// ledger primitive used by development and fault-injection tests until a
    /// separately approved testnet/mainnet deployment profile is bound.
    pub async fn cosign_hvm_payment(
        &self,
        request: HvmPaymentRequestV1,
        now_unix: u64,
    ) -> HubResult<HvmChannelBillV1> {
        self.ensure_settlement_ready()?;
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "HVM payment execution is not enabled for a mainnet profile".into(),
            ));
        }
        let _signing_guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        let (activation, previous, existing) = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let activation = guard
                .hvm_channel_activations
                .get(&request.binding_commitment)
                .cloned()
                .ok_or_else(|| HubError::NotFound("HVM channel activation".into()))?;
            let ledger = guard
                .hvm_channel_ledgers
                .get(&request.binding_commitment)
                .ok_or_else(|| HubError::State("HVM channel ledger is missing".into()))?;
            if guard.hvm_chain_operations.values().any(|operation| {
                operation.binding_commitment == request.binding_commitment
                    && operation.status != HvmChainOperationStatus::Confirmed
            }) {
                return Err(HubError::State(
                    "HVM payment is blocked by an unresolved watchtower or lease operation".into(),
                ));
            }
            for progression in guard.hvm_bill_progressions.values() {
                if progression.request.idempotency_key == request.idempotency_key
                    && progression.request.operation_id != request.operation_id
                {
                    return Err(HubError::State(
                        "HVM idempotency key is owned by another operation".into(),
                    ));
                }
                if progression.status.is_unresolved()
                    && progression.request.binding_commitment == request.binding_commitment
                    && progression.request.operation_id != request.operation_id
                {
                    return Err(HubError::State(
                        "HVM channel already has an unresolved bill progression".into(),
                    ));
                }
            }
            let existing = guard
                .hvm_bill_progressions
                .get(&request.operation_id)
                .cloned();
            (
                activation,
                ledger.latest_fully_signed_bill.clone(),
                existing,
            )
        };
        if let Some(existing) = existing.as_ref() {
            if existing.request_commitment != request_commitment || existing.request != request {
                return Err(HubError::State(
                    "HVM operation retry changed the durable request".into(),
                ));
            }
            match existing_hvm_progression_disposition(&existing.status) {
                ExistingHvmProgressionDisposition::ContinueUnsigned => {}
                ExistingHvmProgressionDisposition::ReturnDurableSignature => {
                    return existing.fully_signed_bill.clone().ok_or_else(|| {
                        HubError::State("completed HVM operation lost its signed bill".into())
                    });
                }
                ExistingHvmProgressionDisposition::RequireReconciliation => {
                    return Err(HubError::State(
                        "RecoveryRequired: an HVM Hub signature may already exist; exact reconciliation is required"
                            .into(),
                    ));
                }
            }
        }
        let binding = &activation.recovery_bundle.binding;
        let validation_time = existing.as_ref().map_or_else(
            || now_unix.max(crate::node::now_unix()),
            |_| request.created_unix,
        );
        request.validate_against(binding, &previous, validation_time)?;
        let operational_recover_floor = activation.minimum_required_recover_blocks.max(1);

        let first_snapshot = self
            .node
            .verify_hvm_recovery_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                operational_recover_floor,
            )
            .await?;
        if existing.is_none() {
            let progression = PersistedHvmBillProgression {
                request: request.clone(),
                request_commitment: request_commitment.clone(),
                previous_bill: previous.clone(),
                fully_signed_bill: None,
                status: HvmBillProgressionStatus::UserProposalPersisted,
                observed_height_before_signing: Some(first_snapshot.observed_height),
                updated_unix: now_unix,
                last_error: None,
            };
            self.persist_hvm_progression(
                progression,
                JournalPhase::HvmPaymentProposalPersisted,
                now_unix,
            )?;
        }

        let final_snapshot = self
            .node
            .verify_hvm_recovery_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                operational_recover_floor,
            )
            .await?;
        let mut progression = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let current = guard
                .hvm_bill_progressions
                .get(&request.operation_id)
                .cloned()
                .ok_or_else(|| HubError::State("HVM progression disappeared".into()))?;
            let ledger = guard
                .hvm_channel_ledgers
                .get(&request.binding_commitment)
                .ok_or_else(|| HubError::State("HVM channel ledger disappeared".into()))?;
            if current.request_commitment != request_commitment
                || ledger.latest_fully_signed_bill != previous
                || current.status == HvmBillProgressionStatus::RecoveryRequired
            {
                return Err(HubError::State(
                    "RecoveryRequired: HVM state changed during live pre-sign verification".into(),
                ));
            }
            current
        };
        request.validate_against(binding, &previous, validation_time)?;
        progression.status = HvmBillProgressionStatus::HubSignatureMayExist;
        progression.observed_height_before_signing = Some(final_snapshot.observed_height);
        progression.updated_unix = now_unix;
        self.persist_hvm_progression(
            progression.clone(),
            JournalPhase::HvmPaymentSignatureMayExist,
            now_unix,
        )?;

        // The external monotonic rollback anchor. The reviewed per-channel V1
        // profile reaches the signing key exactly as the shared registry V2
        // profile does, so it is in scope for the anchor exactly as V2 is: a
        // design that covered only V2 would leave this path fully exposed.
        let anchor_receipt = self
            .reserve_rollback_anchor(
                super::rollback_anchor::RollbackAnchorSubject {
                    operation_id: &request.operation_id,
                    settlement_profile: &binding.settlement_profile,
                    network_instance_id: &binding.network_instance_id,
                    binding_commitment: &request.binding_commitment,
                    channel_id: &binding.channel_id,
                    reuse_version: binding.reuse_version,
                    serial: request.proposed_bill.serial,
                    previous_bill_commitment: previous.commitment()?,
                    proposed_bill_commitment: request.proposed_bill.commitment()?,
                    payer: &request.payer,
                    recipient: &request.recipient,
                    amount_units: request.amount_zhu,
                    idempotency_key: &request.idempotency_key,
                },
                now_unix,
            )
            .await?;
        let key_use_time = now_unix.max(crate::node::now_unix());
        super::rollback_anchor::require_receipt_authorises_bill(
            anchor_receipt.as_ref(),
            &request.proposed_bill.commitment()?,
            request.proposed_bill.serial,
            key_use_time,
        )?;
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer is unavailable".into()))?;
        let mut signed_bill = request.proposed_bill.clone();
        signer.sign_hvm_bill(binding, &mut signed_bill)?;
        progression.status = HvmBillProgressionStatus::FullySigned;
        progression.fully_signed_bill = Some(signed_bill.clone());
        progression.updated_unix = now_unix;
        self.persist_hvm_progression(progression, JournalPhase::HvmPaymentFullySigned, now_unix)?;
        Ok(signed_bill)
    }

    fn persist_hvm_progression(
        &self,
        progression: PersistedHvmBillProgression,
        phase: JournalPhase,
        now_unix: u64,
    ) -> HubResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next_state = guard.clone();
        let operation_id = progression.request.operation_id.clone();
        let binding_commitment = progression.request.binding_commitment.clone();
        let activation = next_state
            .hvm_channel_activations
            .get(&binding_commitment)
            .cloned()
            .ok_or_else(|| HubError::State("HVM activation disappeared".into()))?;
        if let Some(current) = next_state.hvm_bill_progressions.get(&operation_id)
            && current.request_commitment != progression.request_commitment
        {
            return Err(HubError::State("HVM progression commitment changed".into()));
        }
        if progression.status == HvmBillProgressionStatus::FullySigned {
            let signed = progression.fully_signed_bill.clone().ok_or_else(|| {
                HubError::State("fully signed HVM progression has no bill".into())
            })?;
            let ledger = next_state
                .hvm_channel_ledgers
                .get_mut(&binding_commitment)
                .ok_or_else(|| HubError::State("HVM ledger disappeared".into()))?;
            if ledger.latest_fully_signed_bill != progression.previous_bill {
                return Err(HubError::State(
                    "HVM ledger head changed before commit".into(),
                ));
            }
            ledger.latest_fully_signed_bill = signed;
            ledger.updated_unix = now_unix;
        }
        next_state
            .hvm_bill_progressions
            .insert(operation_id.clone(), progression.clone());
        validate_hvm_state(&next_state)?;
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: activation.recovery_bundle.binding.channel_id,
            channel_reuse_version: u64::from(activation.recovery_bundle.binding.reuse_version),
            operation_id,
            operation_type: JournalOperationType::HvmPayment,
            operation_phase: phase,
            amount_units: progression.request.amount_zhu,
            sender: progression.request.payer.clone(),
            recipient: progression.request.recipient.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: progression.request.idempotency_key.clone(),
            request_commitment: progression.request_commitment.clone(),
            expected_bill_number: Some(progression.request.proposed_bill.serial),
            unsigned_state_commitment: Some(binding_commitment),
            created_at: now_unix,
        };
        self.commit_authenticated_state(&mut guard, next_state, event)
    }

    pub fn hvm_recovery_activation_recorded(&self, binding_commitment: &str) -> HubResult<bool> {
        if binding_commitment.len() != 64
            || !binding_commitment
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HubError::State(
                "HVM activation commitment is not canonical lowercase SHA-256 hex".into(),
            ));
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        Ok(guard
            .hvm_channel_activations
            .contains_key(binding_commitment))
    }

    pub fn hvm_latest_bill(&self, binding_commitment: &str) -> HubResult<HvmChannelBillV1> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        guard
            .hvm_channel_ledgers
            .get(binding_commitment)
            .map(|ledger| ledger.latest_fully_signed_bill.clone())
            .ok_or_else(|| HubError::NotFound("HVM channel ledger".into()))
    }

    /// Return public, durable evidence for one exact activated HVM channel.
    ///
    /// This is discovery evidence only. A wallet must still verify the bundle,
    /// the Hub identity and a fresh node snapshot before admitting or signing a
    /// payment.
    pub fn hvm_channel_status(&self, binding_commitment: &str) -> HubResult<HvmChannelStatusV1> {
        if binding_commitment.len() != 64
            || !binding_commitment
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HubError::State(
                "HVM activation commitment is not canonical lowercase SHA-256 hex".into(),
            ));
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let activation = guard
            .hvm_channel_activations
            .get(binding_commitment)
            .ok_or_else(|| HubError::NotFound("HVM channel activation".into()))?;
        let ledger = guard
            .hvm_channel_ledgers
            .get(binding_commitment)
            .ok_or_else(|| HubError::NotFound("HVM channel ledger".into()))?;
        if activation.binding_commitment != binding_commitment
            || ledger.binding_commitment != binding_commitment
            || activation.recovery_bundle.binding.commitment()? != binding_commitment
        {
            return Err(HubError::State(
                "HVM channel status does not match the authenticated binding".into(),
            ));
        }
        ledger
            .latest_fully_signed_bill
            .validate_fully_signed(&activation.recovery_bundle.binding)?;
        Ok(HvmChannelStatusV1 {
            schema: HVM_CHANNEL_STATUS_SCHEMA.to_owned(),
            binding_commitment: binding_commitment.to_owned(),
            recovery_bundle: activation.recovery_bundle.clone(),
            activation_snapshot_commitment: activation.activation_snapshot.commitment()?,
            minimum_required_live_blocks: activation.minimum_required_live_blocks,
            minimum_required_recover_blocks: activation.minimum_required_recover_blocks,
            latest_fully_signed_bill: ledger.latest_fully_signed_bill.clone(),
            activated_unix: activation.activated_unix,
            updated_unix: ledger.updated_unix,
        })
    }

    /// Return the exact durable request for an existing pilot operation.
    ///
    /// This lets an operator retry the same command after a lost response
    /// without constructing a new bill or payment identity.
    pub fn hvm_payment_request(
        &self,
        operation_id: &str,
    ) -> HubResult<Option<HvmPaymentRequestV1>> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State("HVM operation id is empty".into()));
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        Ok(guard
            .hvm_bill_progressions
            .get(operation_id)
            .map(|progression| progression.request.clone()))
    }

    pub fn hvm_payment_status(&self, operation_id: &str) -> HubResult<HvmPaymentStatusV1> {
        if operation_id.trim().is_empty() || operation_id.len() > 256 {
            return Err(HubError::State("HVM operation id is invalid".into()));
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let progression = guard
            .hvm_bill_progressions
            .get(operation_id)
            .ok_or_else(|| HubError::NotFound(format!("HVM payment {operation_id}")))?;
        Ok(HvmPaymentStatusV1 {
            schema: HVM_PAYMENT_STATUS_SCHEMA.to_owned(),
            operation_id: operation_id.to_owned(),
            request_commitment: progression.request_commitment.clone(),
            status: progression.status.as_str().to_owned(),
            request: progression.request.clone(),
            fully_signed_bill: progression.fully_signed_bill.clone(),
            updated_unix: progression.updated_unix,
            recovery_required: matches!(
                progression.status,
                HvmBillProgressionStatus::HubSignatureMayExist
                    | HvmBillProgressionStatus::RecoveryRequired
            ),
        })
    }

    pub(super) fn commit_authenticated_state(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        mut event: JournalEvent,
    ) -> HubResult<()> {
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state store is unavailable".into()))?;
        event.previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        event.new_state_commitment = state_commitment(&next_state)?;
        let record = journal.append(event)?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = record.new_state_commitment.clone();
        if let Err(error) = store.save(&next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: HVM activation journal advanced but state was not durable: {error}"
            )));
        }
        let head = JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: record.new_state_commitment,
        };
        if let Err(error) = journal.write_checkpoint(&head) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: HVM activation state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        self.refresh_recovery_gate(guard);
        Ok(())
    }
}

fn insert_hvm_activation(
    state: &mut HubPersistedState,
    activation: PersistedHvmChannelActivation,
) -> HubResult<bool> {
    activation.recovery_bundle.validate_crypto()?;
    let binding = &activation.recovery_bundle.binding;
    if activation.binding_commitment != binding.commitment()? {
        return Err(HubError::State(
            "HVM activation commitment does not match its recovery bundle".into(),
        ));
    }
    if let Some(existing) = state
        .hvm_channel_activations
        .get(&activation.binding_commitment)
    {
        if existing.recovery_bundle == activation.recovery_bundle {
            return Ok(false);
        }
        return Err(HubError::State(
            "HVM activation commitment is already bound to different recovery material".into(),
        ));
    }
    for existing in state.hvm_channel_activations.values() {
        let existing = &existing.recovery_bundle.binding;
        if existing.contract_address == binding.contract_address
            || (existing.channel_id == binding.channel_id
                && existing.reuse_version == binding.reuse_version)
        {
            return Err(HubError::State(
                "HVM contract or channel incarnation is already activated with a different binding"
                    .into(),
            ));
        }
    }
    state
        .hvm_channel_activations
        .insert(activation.binding_commitment.clone(), activation.clone());
    state.hvm_channel_ledgers.insert(
        activation.binding_commitment.clone(),
        PersistedHvmChannelLedger {
            binding_commitment: activation.binding_commitment,
            latest_fully_signed_bill: activation.recovery_bundle.initial_recovery_bill,
            updated_unix: activation.activated_unix,
        },
    );
    validate_hvm_state(state)?;
    Ok(true)
}

#[cfg(test)]
mod payment_recovery_tests {
    use super::{ExistingHvmProgressionDisposition, existing_hvm_progression_disposition};
    use crate::hvm_ledger::HvmBillProgressionStatus;

    #[test]
    fn signature_may_exist_never_enters_the_signing_path_again() {
        assert_eq!(
            existing_hvm_progression_disposition(&HvmBillProgressionStatus::HubSignatureMayExist,),
            ExistingHvmProgressionDisposition::RequireReconciliation,
        );
        assert_eq!(
            existing_hvm_progression_disposition(&HvmBillProgressionStatus::RecoveryRequired),
            ExistingHvmProgressionDisposition::RequireReconciliation,
        );
        assert_eq!(
            existing_hvm_progression_disposition(&HvmBillProgressionStatus::FullySigned),
            ExistingHvmProgressionDisposition::ReturnDurableSignature,
        );
        assert_eq!(
            existing_hvm_progression_disposition(&HvmBillProgressionStatus::UserProposalPersisted),
            ExistingHvmProgressionDisposition::ContinueUnsigned,
        );
    }
}
