use crate::error::{HubError, HubResult};
use crate::hvm_ledger::HvmBillProgressionStatus;
use crate::hvm_registry::{
    HvmRegistryBillV2, HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use crate::hvm_registry_ledger::{
    HVM_REGISTRY_CHANNEL_STATUS_SCHEMA, HVM_REGISTRY_COSIGNED_BILL_SCHEMA,
    HVM_REGISTRY_PAYMENT_STATUS_SCHEMA, HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA,
    HvmRegistryChannelStatusV2, HvmRegistryCosignedBillV2, HvmRegistryPaymentRequestV2,
    HvmRegistryPaymentStatusV2, HvmRegistryRefundCountersignResponseV2, PersistedHvmRegistryLedger,
    PersistedHvmRegistryProgression,
};
use crate::journal::{JournalEvent, JournalOperationType, JournalPhase};
use crate::storage::{HubPersistedState, PersistedHvmRegistryActivation, validate_hvm_state};

use super::{HubState, unix_timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRegistryProgressionDisposition {
    ContinueUnsigned,
    ReturnDurableSignature,
    RequireReconciliation,
}

fn progression_disposition(
    status: &HvmBillProgressionStatus,
) -> ExistingRegistryProgressionDisposition {
    match status {
        HvmBillProgressionStatus::UserProposalPersisted => {
            ExistingRegistryProgressionDisposition::ContinueUnsigned
        }
        HvmBillProgressionStatus::FullySigned => {
            ExistingRegistryProgressionDisposition::ReturnDurableSignature
        }
        HvmBillProgressionStatus::HubSignatureMayExist
        | HvmBillProgressionStatus::RecoveryRequired => {
            ExistingRegistryProgressionDisposition::RequireReconciliation
        }
    }
}

impl HubState {
    pub async fn activate_hvm_registry_recovery(
        &self,
        recovery_bundle: HvmRegistryRecoveryBundleV2,
        minimum_required_live_blocks: u64,
        minimum_required_recover_blocks: u64,
    ) -> HubResult<String> {
        self.ensure_settlement_ready()?;
        if minimum_required_live_blocks == 0 {
            return Err(HubError::State(
                "registry activation requires a positive live lease minimum".into(),
            ));
        }
        if recovery_bundle.binding.right_hub_address != self.hub_address {
            return Err(HubError::State(
                "registry recovery bundle is bound to a different Hub".into(),
            ));
        }
        let binding_commitment = recovery_bundle.binding.commitment()?;
        let existing = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            guard
                .hvm_registry_activations
                .get(&binding_commitment)
                .cloned()
        };
        if let Some(existing) = existing {
            if existing.recovery_bundle != recovery_bundle
                || existing.minimum_required_live_blocks != minimum_required_live_blocks
                || existing.minimum_required_recover_blocks != minimum_required_recover_blocks
            {
                return Err(HubError::State(
                    "registry activation retry changed the persisted activation".into(),
                ));
            }
            if minimum_required_recover_blocks == 0 {
                if self
                    .node
                    .verify_hvm_registry_runtime_bundle(
                        &recovery_bundle,
                        minimum_required_live_blocks,
                        1,
                    )
                    .await
                    .is_err()
                {
                    self.node
                        .verify_hvm_registry_initial_bundle(
                            &recovery_bundle,
                            minimum_required_live_blocks,
                        )
                        .await?;
                }
            } else {
                self.node
                    .verify_hvm_registry_runtime_bundle(
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
                .verify_hvm_registry_initial_bundle(&recovery_bundle, minimum_required_live_blocks)
                .await?
        } else {
            self.node
                .verify_hvm_registry_runtime_bundle(
                    &recovery_bundle,
                    minimum_required_live_blocks,
                    minimum_required_recover_blocks,
                )
                .await?
        };
        let activation = PersistedHvmRegistryActivation {
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
        if !insert_registry_activation(&mut next_state, activation.clone())? {
            return Ok(binding_commitment);
        }
        let binding = &activation.recovery_bundle.binding;
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: binding.channel_id.clone(),
            channel_reuse_version: u64::from(binding.reuse_version),
            operation_id: format!("hvm-registry-activate-{binding_commitment}"),
            operation_type: JournalOperationType::HvmChannelActivation,
            operation_phase: JournalPhase::HvmChannelActivated,
            amount_zhu: binding.left_deposit_zhu,
            sender: binding.left_address.clone(),
            recipient: binding.right_hub_address.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: format!("hvm-registry-activate-{binding_commitment}"),
            request_commitment: binding_commitment.clone(),
            expected_bill_number: Some(1),
            unsigned_state_commitment: Some(binding_commitment.clone()),
            created_at: activation.activated_unix,
        };
        self.commit_authenticated_state(&mut guard, next_state, event)?;
        Ok(binding_commitment)
    }

    /// Countersign the serial-1 full-refund bill for a channel that does not
    /// exist on chain yet.
    ///
    /// # Why the Hub can afford to say yes
    ///
    /// `verify_bill` in the contract refuses while `c_paid_ != c_deposit_`, so
    /// this bill is inert until the user funds with their own money. Signing it
    /// early costs the Hub nothing it was not already going to owe, and it is
    /// the difference between a user who can always leave and a user whose
    /// deposit is stranded the moment this Hub stops answering.
    ///
    /// # What is deliberately NOT checked here
    ///
    /// There is no node call and no chain snapshot. The channel has not been
    /// `init`ed yet - that is the point of asking now - so there is nothing on
    /// chain to look at. Everything this refuses on is in the request itself.
    ///
    /// # Why there is no "signature may exist" boundary before key use
    ///
    /// The payment path writes that boundary durably before it signs, because
    /// a Hub that forgot a signature could be walked into signing a *different*
    /// bill at the same serial. That cannot happen here. For one binding there
    /// is exactly one signable hash: `validate_shape` pins serial to 1, the
    /// left balance to the whole deposit and the Hub balance to zero, and
    /// `signing_hash` covers the binding and those three numbers and nothing
    /// else - not the signatures, not the request timestamps. So a crash
    /// between signing and persisting loses a signature the caller never saw,
    /// and the re-ask can only ever be over the identical hash.
    pub async fn countersign_hvm_registry_initial_refund(
        &self,
        request: HvmRegistryRefundCountersignRequestV2,
        now_unix: u64,
    ) -> HubResult<HvmRegistryRefundCountersignResponseV2> {
        self.ensure_settlement_ready()?;
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "shared HVM registry execution is not enabled for mainnet".into(),
            ));
        }
        if request.binding.right_hub_address != self.hub_address {
            return Err(HubError::State(
                "registry refund countersign request is bound to a different Hub".into(),
            ));
        }
        // The ASK expires. A captured request must not be replayable at this
        // Hub five hours later; the ANSWER, once given, never expires.
        let validation_time = now_unix.max(crate::node::now_unix());
        request.validate(validation_time)?;
        let _signing_guard = self.hvm_signing_lock.lock().await;
        // Re-derived here rather than taken from the caller: a supplied
        // commitment is a supplied opinion.
        let binding_commitment = request.binding.commitment()?;
        let existing = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            guard
                .hvm_registry_open_countersignatures
                .get(&binding_commitment)
                .cloned()
        };
        if let Some(existing) = existing {
            // One binding, one refund. Re-asking with the identical bill gets
            // the identical signature back; asking with a different serial-1
            // bill for the same binding is refused outright, so this Hub can
            // never be walked into having countersigned two different refunds
            // for one channel.
            if existing.request.binding != request.binding
                || existing.request.left_signed_refund_bill != request.left_signed_refund_bill
            {
                return Err(HubError::State(
                    "registry refund countersign retry changed the durable request".into(),
                ));
            }
            return self.registry_refund_countersign_response(
                existing.hub_refund_signature_hex,
                existing.anchor_receipts,
                &binding_commitment,
                &request,
            );
        }
        let anchor_receipt = self
            .reserve_rollback_anchor(
                super::rollback_anchor::RollbackAnchorSubject {
                    operation_id: &format!("hvm-registry-open-refund-{binding_commitment}"),
                    settlement_profile: &request.binding.settlement_profile,
                    network_instance_id: &request.binding.network_instance_id,
                    binding_commitment: &binding_commitment,
                    channel_id: &request.binding.channel_id,
                    reuse_version: request.binding.reuse_version,
                    serial: request.left_signed_refund_bill.serial,
                    previous_bill_commitment: String::new(),
                    proposed_bill_commitment: request.left_signed_refund_bill.commitment()?,
                    payer: &request.binding.left_address,
                    recipient: &request.binding.right_hub_address,
                    amount_zhu: request.binding.left_deposit_zhu,
                    idempotency_key: &format!("hvm-registry-open-refund-{binding_commitment}"),
                },
                now_unix,
            )
            .await?;
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer is unavailable".into()))?;
        let mut signed = request.left_signed_refund_bill.clone();
        signer.sign_hvm_registry_bill(&request.binding, &mut signed)?;
        if !signed.is_initial_recovery_bill(&request.binding) {
            return Err(HubError::State(
                "registry refund countersignature did not produce the exact initial bill".into(),
            ));
        }
        let anchor_receipts: Vec<_> = anchor_receipt
            .iter()
            .map(|verified| verified.signed.clone())
            .collect();
        let record = crate::storage::PersistedHvmRegistryOpenCountersignature {
            binding_commitment: binding_commitment.clone(),
            request: request.clone(),
            hub_refund_signature_hex: signed.hub_signature_hex.clone(),
            anchor_receipts: anchor_receipts.clone(),
            countersigned_unix: now_unix,
        };
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next_state = guard.clone();
        if let Some(current) = next_state
            .hvm_registry_open_countersignatures
            .get(&binding_commitment)
            && current != &record
        {
            return Err(HubError::State(
                "registry refund countersignature already exists for this binding".into(),
            ));
        }
        next_state
            .hvm_registry_open_countersignatures
            .insert(binding_commitment.clone(), record);
        validate_hvm_state(&next_state)?;
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: request.binding.channel_id.clone(),
            channel_reuse_version: u64::from(request.binding.reuse_version),
            operation_id: format!("hvm-registry-open-refund-{binding_commitment}"),
            operation_type: JournalOperationType::HvmChannelActivation,
            operation_phase: JournalPhase::HvmPaymentFullySigned,
            amount_zhu: request.binding.left_deposit_zhu,
            sender: request.binding.left_address.clone(),
            recipient: request.binding.right_hub_address.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: format!("hvm-registry-open-refund-{binding_commitment}"),
            request_commitment: binding_commitment.clone(),
            expected_bill_number: Some(1),
            unsigned_state_commitment: Some(binding_commitment.clone()),
            created_at: now_unix,
        };
        self.commit_authenticated_state(&mut guard, next_state, event)?;
        drop(guard);
        self.registry_refund_countersign_response(
            signed.hub_signature_hex,
            anchor_receipts,
            &binding_commitment,
            &request,
        )
    }

    /// The single constructor for the countersign response, so there is no path
    /// by which a caller obtains a refund signature that skipped the receipt
    /// check.
    ///
    /// This is the most important bill in the channel's life. A Hub that has
    /// lost its witness must not be able to hide that on exactly this one.
    fn registry_refund_countersign_response(
        &self,
        hub_refund_signature_hex: String,
        anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
        binding_commitment: &str,
        request: &HvmRegistryRefundCountersignRequestV2,
    ) -> HubResult<HvmRegistryRefundCountersignResponseV2> {
        super::rollback_anchor::require_receipts_accompany_bill(
            self.rollback_anchor_configured(),
            &anchor_receipts,
            &request.left_signed_refund_bill.commitment()?,
            request.left_signed_refund_bill.serial,
            binding_commitment,
            self.hub_address.trim(),
        )?;
        Ok(HvmRegistryRefundCountersignResponseV2 {
            schema: HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA.into(),
            hub_refund_signature_hex,
            anchor_receipts,
        })
    }

    pub async fn cosign_hvm_registry_payment(
        &self,
        request: HvmRegistryPaymentRequestV2,
        now_unix: u64,
    ) -> HubResult<HvmRegistryCosignedBillV2> {
        self.ensure_settlement_ready()?;
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "shared HVM registry execution is not enabled for mainnet".into(),
            ));
        }
        let _signing_guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        let (activation, previous, existing) =
            {
                let guard = self
                    .inner
                    .read()
                    .map_err(|_| HubError::State("state lock poisoned".into()))?;
                let activation = guard
                    .hvm_registry_activations
                    .get(&request.binding_commitment)
                    .cloned()
                    .ok_or_else(|| HubError::NotFound("HVM registry activation".into()))?;
                let ledger = guard
                    .hvm_registry_ledgers
                    .get(&request.binding_commitment)
                    .ok_or_else(|| HubError::State("HVM registry ledger is missing".into()))?;
                if guard.hvm_bill_progressions.values().any(|progression| {
                    progression.request.idempotency_key == request.idempotency_key
                }) {
                    return Err(HubError::State(
                        "HVM idempotency key is already used by the V1 profile".into(),
                    ));
                }
                for progression in guard.hvm_registry_progressions.values() {
                    if progression.request.idempotency_key == request.idempotency_key
                        && progression.request.operation_id != request.operation_id
                    {
                        return Err(HubError::State(
                            "registry idempotency key is owned by another operation".into(),
                        ));
                    }
                    if progression.status.is_unresolved()
                        && progression.request.binding_commitment == request.binding_commitment
                        && progression.request.operation_id != request.operation_id
                    {
                        return Err(HubError::State(
                            "registry channel already has an unresolved progression".into(),
                        ));
                    }
                }
                let existing = guard
                    .hvm_registry_progressions
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
                    "registry operation retry changed the durable request".into(),
                ));
            }
            match progression_disposition(&existing.status) {
                ExistingRegistryProgressionDisposition::ContinueUnsigned => {}
                ExistingRegistryProgressionDisposition::ReturnDurableSignature => {
                    // The retry answers with the durable receipts too. A retry
                    // that returned the bill bare would be indistinguishable,
                    // to the counterparty, from a Hub that had dropped its
                    // witnesses - so the honest retry would fire the loudest
                    // prompt in the system.
                    let bill = existing.fully_signed_bill.clone().ok_or_else(|| {
                        HubError::State("completed registry operation lost its signed bill".into())
                    })?;
                    return self.registry_cosigned_bill(
                        bill,
                        existing.anchor_receipts.clone(),
                        &request,
                    );
                }
                ExistingRegistryProgressionDisposition::RequireReconciliation => {
                    return Err(HubError::State(
                        "RecoveryRequired: a registry Hub signature may already exist".into(),
                    ));
                }
            }
        }
        let binding = &activation.recovery_bundle.binding;
        let validation_time = now_unix.max(crate::node::now_unix());
        request.validate_against(binding, &previous, validation_time)?;
        let live_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        if request.network_binding != live_network {
            return Err(HubError::Node(
                "registry payer authorization network witness does not match the live node".into(),
            ));
        }
        let recover_floor = activation.minimum_required_recover_blocks.max(1);
        let first_snapshot = self
            .node
            .verify_hvm_registry_open_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                recover_floor,
            )
            .await?;
        if existing.is_none() {
            self.persist_registry_progression(
                PersistedHvmRegistryProgression {
                    request: request.clone(),
                    request_commitment: request_commitment.clone(),
                    previous_bill: previous.clone(),
                    fully_signed_bill: None,
                    anchor_receipts: Vec::new(),
                    status: HvmBillProgressionStatus::UserProposalPersisted,
                    observed_height_before_signing: Some(first_snapshot.observed_height),
                    updated_unix: now_unix,
                    last_error: None,
                },
                JournalPhase::HvmPaymentProposalPersisted,
                now_unix,
            )?;
        }

        let final_snapshot = self
            .node
            .verify_hvm_registry_open_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                recover_floor,
            )
            .await?;
        let mut progression = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let current = guard
                .hvm_registry_progressions
                .get(&request.operation_id)
                .cloned()
                .ok_or_else(|| HubError::State("registry progression disappeared".into()))?;
            let ledger = guard
                .hvm_registry_ledgers
                .get(&request.binding_commitment)
                .ok_or_else(|| HubError::State("registry ledger disappeared".into()))?;
            if current.request_commitment != request_commitment
                || ledger.latest_fully_signed_bill != previous
                || current.status == HvmBillProgressionStatus::RecoveryRequired
            {
                return Err(HubError::State(
                    "RecoveryRequired: registry state changed during verification".into(),
                ));
            }
            current
        };
        let final_validation_time = now_unix.max(crate::node::now_unix());
        request.validate_against(binding, &previous, final_validation_time)?;
        let final_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        if request.network_binding != final_network {
            return Err(HubError::Node(
                "registry payer authorization network witness changed before Hub signing".into(),
            ));
        }
        progression.status = HvmBillProgressionStatus::HubSignatureMayExist;
        progression.observed_height_before_signing = Some(final_snapshot.observed_height);
        progression.updated_unix = now_unix;
        self.persist_registry_progression(
            progression.clone(),
            JournalPhase::HvmPaymentSignatureMayExist,
            now_unix,
        )?;

        // The external monotonic rollback anchor, before the key is used and
        // alongside the pre-use precondition re-verification below rather than
        // instead of it. Every other check on this path is enforced against
        // this Hub's own durable state; this is the one that is not, because
        // the threat is that the durable state was restored.
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
                    amount_zhu: request.amount_zhu,
                    idempotency_key: &request.idempotency_key,
                },
                now_unix,
            )
            .await?;

        // The authenticated may-exist boundary is durable before key use.
        // Refresh wall time after that write so a request expiring during node
        // verification or persistence cannot receive a Hub signature.
        let key_use_time = now_unix.max(crate::node::now_unix());
        request.validate_against(binding, &previous, key_use_time)?;
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
        let mut signed = request.proposed_bill.clone();
        signer.sign_hvm_registry_bill(binding, &mut signed)?;
        // The receipts are collected here, from the reservation this exact
        // signature was made under, and made durable in the same write as the
        // signed bill. They cannot be re-derived afterwards: the receipt binds
        // the PAYER-SIGNED, HUB-UNSIGNED commitment, and `signed` above has
        // just stopped being that bill.
        let anchor_receipts: Vec<_> = anchor_receipt
            .iter()
            .map(|verified| verified.signed.clone())
            .collect();
        progression.status = HvmBillProgressionStatus::FullySigned;
        progression.fully_signed_bill = Some(signed.clone());
        progression.anchor_receipts = anchor_receipts.clone();
        progression.updated_unix = now_unix;
        self.persist_registry_progression(
            progression,
            JournalPhase::HvmPaymentFullySigned,
            now_unix,
        )?;
        self.registry_cosigned_bill(signed, anchor_receipts, &request)
    }

    /// Assemble the response, and refuse to produce one that an anchored Hub
    /// must not serve.
    ///
    /// This is the last gate before the bill leaves the state layer, and it is
    /// deliberately on the *constructor* of the response rather than in the
    /// HTTP handler: there is exactly one way to build an
    /// [`HvmRegistryCosignedBillV2`] from this module, so there is no path by
    /// which a caller obtains a co-signed bill that skipped the check.
    fn registry_cosigned_bill(
        &self,
        bill: HvmRegistryBillV2,
        anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
        request: &HvmRegistryPaymentRequestV2,
    ) -> HubResult<HvmRegistryCosignedBillV2> {
        super::rollback_anchor::require_receipts_accompany_bill(
            self.rollback_anchor_configured(),
            &anchor_receipts,
            // The receipt binds the payer-signed, Hub-unsigned bill, because
            // `HvmRegistryBillV2::commitment` covers the whole struct including
            // signatures and the Hub's own is added afterwards. This is the
            // same commitment the wallet holds durably in its own request, and
            // comparing against the fully signed bill instead would make every
            // honest receipt look forged.
            &request.proposed_bill.commitment()?,
            request.proposed_bill.serial,
            &request.binding_commitment,
            self.hub_address.trim(),
        )?;
        Ok(HvmRegistryCosignedBillV2 {
            schema: HVM_REGISTRY_COSIGNED_BILL_SCHEMA.into(),
            bill,
            anchor_receipts,
        })
    }

    fn persist_registry_progression(
        &self,
        progression: PersistedHvmRegistryProgression,
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
            .hvm_registry_activations
            .get(&binding_commitment)
            .cloned()
            .ok_or_else(|| HubError::State("registry activation disappeared".into()))?;
        if let Some(current) = next_state.hvm_registry_progressions.get(&operation_id)
            && current.request_commitment != progression.request_commitment
        {
            return Err(HubError::State(
                "registry progression commitment changed".into(),
            ));
        }
        if progression.status == HvmBillProgressionStatus::FullySigned {
            let signed = progression.fully_signed_bill.clone().ok_or_else(|| {
                HubError::State("fully signed registry progression has no bill".into())
            })?;
            let ledger = next_state
                .hvm_registry_ledgers
                .get_mut(&binding_commitment)
                .ok_or_else(|| HubError::State("registry ledger disappeared".into()))?;
            if ledger.latest_fully_signed_bill != progression.previous_bill {
                return Err(HubError::State(
                    "registry ledger head changed before commit".into(),
                ));
            }
            ledger.latest_fully_signed_bill = signed;
            // The head and the receipts that authorised it move together, in
            // this one write. A head whose receipts lagged behind it would be
            // served to a recovering wallet as a bill with the wrong anchor
            // evidence, which is worse than none.
            ledger
                .latest_anchor_receipts
                .clone_from(&progression.anchor_receipts);
            ledger.updated_unix = now_unix;
        }
        next_state
            .hvm_registry_progressions
            .insert(operation_id.clone(), progression.clone());
        validate_hvm_state(&next_state)?;
        let binding = &activation.recovery_bundle.binding;
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: binding.channel_id.clone(),
            channel_reuse_version: u64::from(binding.reuse_version),
            operation_id,
            operation_type: JournalOperationType::HvmPayment,
            operation_phase: phase,
            amount_zhu: progression.request.amount_zhu,
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

    pub fn hvm_registry_channel_status(
        &self,
        binding_commitment: &str,
    ) -> HubResult<HvmRegistryChannelStatusV2> {
        require_commitment(binding_commitment)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let activation = guard
            .hvm_registry_activations
            .get(binding_commitment)
            .ok_or_else(|| HubError::NotFound("HVM registry activation".into()))?;
        let ledger = guard
            .hvm_registry_ledgers
            .get(binding_commitment)
            .ok_or_else(|| HubError::NotFound("HVM registry ledger".into()))?;
        if activation.binding_commitment != binding_commitment
            || ledger.binding_commitment != binding_commitment
            || activation.recovery_bundle.binding.commitment()? != binding_commitment
        {
            return Err(HubError::State(
                "registry status does not match its authenticated binding".into(),
            ));
        }
        ledger
            .latest_fully_signed_bill
            .validate_fully_signed(&activation.recovery_bundle.binding)?;
        Ok(HvmRegistryChannelStatusV2 {
            schema: HVM_REGISTRY_CHANNEL_STATUS_SCHEMA.into(),
            binding_commitment: binding_commitment.to_owned(),
            recovery_bundle: activation.recovery_bundle.clone(),
            activation_snapshot_commitment: activation.activation_snapshot.commitment()?,
            minimum_required_live_blocks: activation.minimum_required_live_blocks,
            minimum_required_recover_blocks: activation.minimum_required_recover_blocks,
            latest_fully_signed_bill: ledger.latest_fully_signed_bill.clone(),
            latest_anchor_receipts: ledger.latest_anchor_receipts.clone(),
            activated_unix: activation.activated_unix,
            updated_unix: ledger.updated_unix,
        })
    }

    pub fn hvm_registry_payment_status(
        &self,
        operation_id: &str,
    ) -> HubResult<HvmRegistryPaymentStatusV2> {
        if operation_id.trim().is_empty() || operation_id.len() > 256 {
            return Err(HubError::State("registry operation id is invalid".into()));
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let progression = guard
            .hvm_registry_progressions
            .get(operation_id)
            .ok_or_else(|| HubError::NotFound(format!("registry payment {operation_id}")))?;
        Ok(HvmRegistryPaymentStatusV2 {
            schema: HVM_REGISTRY_PAYMENT_STATUS_SCHEMA.into(),
            operation_id: operation_id.to_owned(),
            request_commitment: progression.request_commitment.clone(),
            status: progression.status.as_str().to_owned(),
            request: progression.request.clone(),
            fully_signed_bill: progression.fully_signed_bill.clone(),
            anchor_receipts: progression.anchor_receipts.clone(),
            updated_unix: progression.updated_unix,
            recovery_required: matches!(
                progression.status,
                HvmBillProgressionStatus::HubSignatureMayExist
                    | HvmBillProgressionStatus::RecoveryRequired
            ),
        })
    }
}

fn insert_registry_activation(
    state: &mut HubPersistedState,
    activation: PersistedHvmRegistryActivation,
) -> HubResult<bool> {
    activation.recovery_bundle.validate_crypto()?;
    let binding = &activation.recovery_bundle.binding;
    if activation.binding_commitment != binding.commitment()? {
        return Err(HubError::State(
            "registry activation commitment does not match its bundle".into(),
        ));
    }
    if let Some(existing) = state
        .hvm_registry_activations
        .get(&activation.binding_commitment)
    {
        if existing.recovery_bundle == activation.recovery_bundle {
            return Ok(false);
        }
        return Err(HubError::State(
            "registry activation is bound to different recovery material".into(),
        ));
    }
    for existing in state.hvm_registry_activations.values() {
        let existing = &existing.recovery_bundle.binding;
        if (existing.contract_address == binding.contract_address
            && existing.left_address == binding.left_address)
            || (existing.contract_address == binding.contract_address
                && existing.channel_id == binding.channel_id
                && existing.reuse_version == binding.reuse_version)
        {
            return Err(HubError::State(
                "registry left slot or channel incarnation is already active".into(),
            ));
        }
    }
    state
        .hvm_registry_activations
        .insert(activation.binding_commitment.clone(), activation.clone());
    state.hvm_registry_ledgers.insert(
        activation.binding_commitment.clone(),
        PersistedHvmRegistryLedger {
            binding_commitment: activation.binding_commitment,
            latest_fully_signed_bill: activation.recovery_bundle.initial_recovery_bill,
            // The opening bill is the on-chain recovery bill, which no witness
            // receipted: it predates the channel's first anchored payment.
            latest_anchor_receipts: Vec::new(),
            updated_unix: activation.activated_unix,
        },
    );
    validate_hvm_state(state)?;
    Ok(true)
}

fn require_commitment(value: &str) -> HubResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HubError::State(
            "registry binding commitment is not canonical lowercase SHA-256 hex".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ExistingRegistryProgressionDisposition, progression_disposition};
    use crate::hvm_ledger::HvmBillProgressionStatus;

    #[test]
    fn signature_may_exist_requires_reconciliation() {
        assert_eq!(
            progression_disposition(&HvmBillProgressionStatus::HubSignatureMayExist),
            ExistingRegistryProgressionDisposition::RequireReconciliation
        );
        assert_eq!(
            progression_disposition(&HvmBillProgressionStatus::RecoveryRequired),
            ExistingRegistryProgressionDisposition::RequireReconciliation
        );
        assert_eq!(
            progression_disposition(&HvmBillProgressionStatus::FullySigned),
            ExistingRegistryProgressionDisposition::ReturnDurableSignature
        );
    }
}
