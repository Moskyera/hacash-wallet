use sha2::{Digest, Sha256};

use super::HubState;
use crate::error::{HubError, HubResult};
use crate::hvm_watchtower::{
    HVM_STORAGE_KEYS, HvmLeaseRenewalRequestV1, HvmWatchtowerDecision, HvmWatchtowerMode,
    HvmWatchtowerRequestV1, HvmWatchtowerResponseV1, HvmWatchtowerSituationV1,
    build_signed_hvm_call_transaction, build_signed_hvm_claim_transaction, challenge_call_source,
    claim_left_payout_source, decide_watchtower_action, finalize_call_source,
    read_exact_hvm_claim_transaction, renew_all_call_source, respond_call_source,
};
use crate::journal::{JournalEvent, JournalOperationType, JournalPhase};
use crate::storage::{
    HvmChainOperationKind, HvmChainOperationStatus, PersistedHvmChainOperation, validate_hvm_state,
};

fn required_recover_blocks(
    activation_recover_floor: u64,
    kind: HvmChainOperationKind,
    postcondition: bool,
) -> u64 {
    if kind == HvmChainOperationKind::RenewAllLeases && !postcondition {
        activation_recover_floor
    } else {
        activation_recover_floor.max(1)
    }
}

/// The exact payee and amount of a durable claim, or an error naming what the
/// record lost. Both halves are re-read from the record on every step that
/// touches the key; neither is ever inferred.
fn hvm_claim_terms(operation: &PersistedHvmChainOperation) -> HubResult<(&str, u64)> {
    if operation.kind != HvmChainOperationKind::Claim {
        return Err(HubError::State(
            "only an HVM claim carries payout terms".into(),
        ));
    }
    let payee = operation
        .claim_payee
        .as_deref()
        .ok_or_else(|| HubError::State("HVM claim lost its exact payee".into()))?;
    let amount_zhu = operation
        .claim_amount_zhu
        .ok_or_else(|| HubError::State("HVM claim lost its exact payout amount".into()))?;
    Ok((payee, amount_zhu))
}

fn lease_renewal_is_due(
    activation_recover_floor: u64,
    minimum_live_blocks: u64,
    renew_when_live_blocks_at_or_below: u64,
) -> bool {
    activation_recover_floor == 0 || minimum_live_blocks <= renew_when_live_blocks_at_or_below
}

impl HubState {
    /// Reconstruct an exact durable lease-renewal request for restart-safe CLI
    /// recovery. The caller supplies the admission threshold because older
    /// persisted operations do not store it separately; the authenticated
    /// request commitment proves whether that threshold is the original one.
    pub fn hvm_lease_renewal_request(
        &self,
        operation_id: &str,
        renew_when_live_blocks_at_or_below: u64,
    ) -> HubResult<Option<HvmLeaseRenewalRequestV1>> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State("HVM operation id is empty".into()));
        }
        let Some(operation) = self.load_hvm_chain_operation(operation_id)? else {
            return Ok(None);
        };
        if operation.kind != HvmChainOperationKind::RenewAllLeases {
            return Err(HubError::State(
                "HVM operation id does not belong to a lease renewal".into(),
            ));
        }
        let request = HvmLeaseRenewalRequestV1 {
            schema: crate::hvm_watchtower::HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
            operation_id: operation.operation_id,
            idempotency_key: operation.idempotency_key,
            binding_commitment: operation.binding_commitment,
            renew_when_live_blocks_at_or_below,
            periods: operation.lease_periods.ok_or_else(|| {
                HubError::State("durable HVM lease renewal omitted its period count".into())
            })?,
            network_fee_zhu: operation.network_fee_zhu,
            timestamp: operation.transaction_timestamp,
            gas_max: operation.gas_max,
            created_unix: operation.created_unix,
        };
        request.validate()?;
        if request.commitment()? != operation.request_commitment {
            return Err(HubError::State(
                "durable HVM lease renewal request commitment is inconsistent".into(),
            ));
        }
        Ok(Some(request))
    }

    /// Reconstruct the exact durable watchtower request for idempotent CLI
    /// recovery. Lease renewals have a different request schema and are not
    /// returned through this method.
    pub fn hvm_watchtower_request(
        &self,
        operation_id: &str,
    ) -> HubResult<Option<HvmWatchtowerRequestV1>> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State("HVM operation id is empty".into()));
        }
        let Some(operation) = self.load_hvm_chain_operation(operation_id)? else {
            return Ok(None);
        };
        let mode = match operation.kind {
            HvmChainOperationKind::Challenge => HvmWatchtowerMode::BeginChallenge,
            HvmChainOperationKind::Respond
            | HvmChainOperationKind::Finalize
            | HvmChainOperationKind::Claim => HvmWatchtowerMode::Monitor,
            HvmChainOperationKind::RenewAllLeases => {
                return Err(HubError::State(
                    "HVM operation id belongs to a lease renewal".into(),
                ));
            }
        };
        let request = HvmWatchtowerRequestV1 {
            schema: crate::hvm_watchtower::HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
            operation_id: operation.operation_id,
            idempotency_key: operation.idempotency_key,
            binding_commitment: operation.binding_commitment,
            mode,
            network_fee_zhu: operation.network_fee_zhu,
            timestamp: operation.transaction_timestamp,
            gas_max: operation.gas_max,
            created_unix: operation.created_unix,
        };
        request.validate()?;
        if request.commitment()? != operation.request_commitment {
            return Err(HubError::State(
                "durable HVM watchtower request commitment is inconsistent".into(),
            ));
        }
        Ok(Some(request))
    }

    pub async fn hvm_lease_maintenance_tick(
        &self,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<crate::hvm_scheduler::HvmLeaseMaintenanceResults> {
        config.validate()?;
        let commitments = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_channel_activations
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            let response = self.hvm_lease_channel_tick(&commitment, config).await;
            results.push(match response {
                Ok(response) => crate::hvm_scheduler::HvmLeaseMaintenanceResult {
                    binding_commitment: commitment,
                    response: Some(response),
                    error: None,
                },
                Err(error) => crate::hvm_scheduler::HvmLeaseMaintenanceResult {
                    binding_commitment: commitment,
                    response: None,
                    error: Some(error.to_string()),
                },
            });
        }
        Ok(results)
    }

    /// One channel's lease pass.
    ///
    /// # Outstanding work first, and only then the clock
    ///
    /// The renewal this tick signed last time comes first, driven by the
    /// byte-identical request it was created from, before any new name is
    /// minted. That ordering is the whole of this function, and it is load
    /// bearing in both directions.
    ///
    /// Signing a renewal puts its record into `Signed` and then `Submitted`,
    /// and `persisted_state_requires_recovery` counts both, so
    /// `refresh_recovery_gate` raises the process-wide `recovery_required`
    /// latch the moment the transaction exists. That latch is correct: a signed
    /// transaction whose fate is unknown is outstanding, and the Hub must not
    /// sign anything new beside it. It is released by nothing but that same
    /// operation reaching `Confirmed`.
    ///
    /// The only code that can carry it there is keyed to its operation id — and
    /// the id is bucketed to a one-minute clock window while the scheduler
    /// interval is at least sixty seconds, so the next pass is always in a
    /// later window and can never say that name again. Asking the clock first
    /// therefore produced a name with no record behind it, fell through to
    /// `ensure_settlement_ready`, and was refused by the latch its own
    /// submission had raised. Forever: the tick renewed exactly once per
    /// process and then reported `state: RecoveryRequired` on every pass, even
    /// when the transaction had confirmed seconds later, because nothing was
    /// left that could notice.
    ///
    /// Looking the outstanding record up by *binding* instead reaches
    /// `run_hvm_lease_renewal`'s resume branch, and through it
    /// `ensure_hvm_chain_reconciliation_allowed` — the door that already exists
    /// for exactly this, and which lets a latched Hub finish one operation only
    /// while it is the sole reason the latch is up and the request is byte for
    /// byte the durable one. Nothing here clears a latch or relaxes a check; it
    /// stops hiding the work from the door built to let it through.
    ///
    /// # Whose operation it is
    ///
    /// A channel is allowed one unresolved chain operation at a time
    /// (`validate_hvm_state`), so anything outstanding against this binding
    /// blocks the tick whether the tick opened it or not. The two cases are not
    /// the same, though: its own it drives, and anybody else's — a CLI renewal,
    /// an operator's challenge — it names and leaves strictly alone. The pass
    /// records that refusal against this binding and moves to the next channel.
    ///
    /// # And only then the clock
    ///
    /// With nothing outstanding, a fresh `now` is read and the window names a
    /// new operation. Within one window a second pass still lands on that same
    /// record, and rebuilds its request from the durable copy rather than
    /// minting one: `commitment()` covers `timestamp` and `created_unix`, so a
    /// fresh `now` a second later would be a different request under the same
    /// name and `run_hvm_lease_renewal` would refuse the Hub's own work.
    async fn hvm_lease_channel_tick(
        &self,
        binding_commitment: &str,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        if let Some(existing) = self.unresolved_hvm_chain_operation(binding_commitment)? {
            let request = self.hvm_lease_tick_request(&existing, config)?;
            return self.run_hvm_lease_renewal(request).await;
        }
        let now = crate::node::now_unix();
        let (operation_id, idempotency_key) =
            crate::hvm_scheduler::operation_identity(binding_commitment, now);
        let request = match self
            .hvm_lease_renewal_request(&operation_id, config.renew_when_live_blocks_at_or_below)?
        {
            Some(existing) => existing,
            None => HvmLeaseRenewalRequestV1 {
                schema: crate::hvm_watchtower::HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
                operation_id,
                idempotency_key,
                binding_commitment: binding_commitment.to_owned(),
                renew_when_live_blocks_at_or_below: config.renew_when_live_blocks_at_or_below,
                periods: config.periods,
                network_fee_zhu: config.network_fee_zhu,
                timestamp: now,
                gas_max: config.gas_max,
                created_unix: now,
            },
        };
        self.run_hvm_lease_renewal(request).await
    }

    /// The one chain operation still outstanding against this channel, if any.
    ///
    /// `validate_hvm_state` permits at most one, so this is a lookup and not a
    /// search: whatever it returns is the single record standing between this
    /// binding and any new work. `Confirmed` is the only status that resolves
    /// one here — the v1 table has no abandonment transition, and a record
    /// carrying it is refused on load — so every other status leaves a signed
    /// transaction whose fate is still open.
    fn unresolved_hvm_chain_operation(
        &self,
        binding_commitment: &str,
    ) -> HubResult<Option<PersistedHvmChainOperation>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_chain_operations
            .values()
            .find(|operation| {
                operation.binding_commitment == binding_commitment
                    && operation.status != HvmChainOperationStatus::Confirmed
            })
            .cloned())
    }

    /// Rebuild the exact durable request an outstanding lease-tick renewal was
    /// created from, or refuse to touch the record.
    ///
    /// Two refusals, and neither is a formality. A record this tick did not
    /// open belongs to whoever did — driving it would broadcast a transaction
    /// on somebody else's behalf — and a record that is not a lease renewal at
    /// all cannot be rebuilt as one. Both leave the operation exactly as it
    /// was found and report against this binding alone.
    ///
    /// The rebuild itself goes through [`Self::hvm_lease_renewal_request`],
    /// which reads every field the commitment covers back off the record and
    /// then re-derives that commitment as a self-check. So this is the original
    /// request rather than a lookalike — and an operator who moved
    /// `renew_when_live_blocks_at_or_below` underneath a live operation is told
    /// so by name, instead of it surfacing later as a bare retry refusal.
    fn hvm_lease_tick_request(
        &self,
        operation: &PersistedHvmChainOperation,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmLeaseRenewalRequestV1> {
        if !crate::hvm_scheduler::lease_tick_owns(
            &operation.operation_id,
            &operation.idempotency_key,
            crate::hvm_scheduler::HVM_LEASE_OPERATION_PREFIX,
            crate::hvm_scheduler::HVM_LEASE_IDEMPOTENCY_PREFIX,
        ) {
            return Err(HubError::State(format!(
                "HVM chain operation {} is unresolved on this channel and was not opened by the lease tick; the tick will not drive it",
                operation.operation_id
            )));
        }
        if operation.kind != HvmChainOperationKind::RenewAllLeases {
            return Err(HubError::State(format!(
                "HVM chain operation {} is not a lease renewal",
                operation.operation_id
            )));
        }
        self.hvm_lease_renewal_request(
            &operation.operation_id,
            config.renew_when_live_blocks_at_or_below,
        )?
        .ok_or_else(|| {
            HubError::State(format!(
                "HVM lease renewal {} vanished between lookup and rebuild",
                operation.operation_id
            ))
        })
    }

    /// Evaluate the v1 watchtower once for every activated HVM channel.
    ///
    /// This is the driver the v1 watchtower never had, and its absence was the
    /// second half of the stranded-payout defect. The claim arm was added to
    /// [`decide_watchtower_action`] and proven on chain, but the only caller of
    /// [`Self::run_hvm_watchtower`] outside the test tree was a CLI behind a
    /// non-default feature. A Hub daemon compiled the decision and never asked
    /// it anything, so an unattended Hub still finalized nothing, claimed
    /// nothing and responded to nothing on this rail. Money the contract was
    /// willing to release stayed inside it unless a person happened to be
    /// watching.
    ///
    /// It rides the existing lease scheduler loop, takes its fee and gas
    /// ceiling from the same operator-set configuration those ticks use, and
    /// reaches the chain only through [`Self::run_hvm_watchtower`] — the same
    /// guarded entry point the CLI calls, in the same `Monitor` mode. It
    /// cannot sign or submit anything the manual path could not, because it is
    /// not a second path: it is a caller of the first one. In particular it
    /// never begins a challenge, which is the one mode that spends a key on a
    /// state the chain has not yet moved to.
    ///
    /// Every channel is attempted and every outcome is recorded against its
    /// own binding, so one channel latched in recovery does not stop the pass.
    pub async fn hvm_watchtower_tick(
        &self,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<crate::hvm_scheduler::HvmWatchtowerMaintenanceResults> {
        config.validate()?;
        // Mainnet stays refused, and refused before any node traffic.
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "HVM watchtower broadcast is not enabled for a mainnet profile".into(),
            ));
        }
        let commitments = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_channel_activations
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            let outcome = self.hvm_watchtower_channel_tick(&commitment, config).await;
            results.push(match outcome {
                Ok(crate::hvm_scheduler::HvmWatchtowerPass::Evaluated(response)) => {
                    crate::hvm_scheduler::HvmWatchtowerMaintenanceResult {
                        binding_commitment: commitment,
                        response: Some(response),
                        deferred_to_lease_operation: None,
                        error: None,
                    }
                }
                Ok(crate::hvm_scheduler::HvmWatchtowerPass::DeferredToLease(operation_id)) => {
                    crate::hvm_scheduler::HvmWatchtowerMaintenanceResult {
                        binding_commitment: commitment,
                        response: None,
                        deferred_to_lease_operation: Some(operation_id),
                        error: None,
                    }
                }
                Err(error) => crate::hvm_scheduler::HvmWatchtowerMaintenanceResult {
                    binding_commitment: commitment,
                    response: None,
                    deferred_to_lease_operation: None,
                    error: Some(error.to_string()),
                },
            });
        }
        Ok(results)
    }

    /// One channel's watchtower pass.
    ///
    /// Outstanding work comes first and is driven by the byte-identical
    /// request it was created from, exactly as the lease tick does. It has to:
    /// our own confirmed response changes the chain, so by the next pass the
    /// situation this channel is in has already moved on from the one that
    /// named the record. Going looking for a fresh name here would strand a
    /// signed transaction nobody is reconciling — which is precisely how the
    /// lease tick used to wedge.
    ///
    /// A record this tick did not open is named and left strictly alone.
    async fn hvm_watchtower_channel_tick(
        &self,
        binding_commitment: &str,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<crate::hvm_scheduler::HvmWatchtowerPass> {
        if let Some(existing) = self.unresolved_hvm_chain_operation(binding_commitment)? {
            // The lease tick runs first on this same loop and a channel gets
            // exactly one unresolved operation, so finding its renewal here is
            // ordinary rather than a fault. Name it, leave it alone, and say so
            // quietly; the tower gets this channel back the pass after that
            // renewal confirms.
            if crate::hvm_scheduler::lease_tick_owns(
                &existing.operation_id,
                &existing.idempotency_key,
                crate::hvm_scheduler::HVM_LEASE_OPERATION_PREFIX,
                crate::hvm_scheduler::HVM_LEASE_IDEMPOTENCY_PREFIX,
            ) {
                return Ok(crate::hvm_scheduler::HvmWatchtowerPass::DeferredToLease(
                    existing.operation_id,
                ));
            }
            let request = hvm_watchtower_tick_request(&existing)?;
            return self
                .run_hvm_watchtower(request)
                .await
                .map(crate::hvm_scheduler::HvmWatchtowerPass::Evaluated);
        }
        let activation = self.hvm_activation(binding_commitment)?;
        let latest = self.hvm_latest_bill(binding_commitment)?;
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        let situation = HvmWatchtowerSituationV1::from_evidence(&snapshot, &latest);
        let (operation_id, idempotency_key) =
            crate::hvm_scheduler::watchtower_operation_identity(binding_commitment, &situation);
        // A record already filed under this name is this same situation seen
        // again. Rebuild its exact request rather than a fresh one: the
        // commitment covers `timestamp` and `created_unix`, so a fresh `now` a
        // second later would be a different request under the same name and
        // `run_hvm_watchtower` would refuse the Hub's own work.
        let request = match self.load_hvm_chain_operation(&operation_id)? {
            Some(existing) => hvm_watchtower_tick_request(&existing)?,
            None => {
                let now = crate::node::now_unix();
                HvmWatchtowerRequestV1 {
                    schema: crate::hvm_watchtower::HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
                    operation_id,
                    idempotency_key,
                    binding_commitment: binding_commitment.to_owned(),
                    mode: HvmWatchtowerMode::Monitor,
                    network_fee_zhu: config.network_fee_zhu,
                    timestamp: now,
                    gas_max: config.gas_max,
                    created_unix: now,
                }
            }
        };
        self.run_hvm_watchtower(request)
            .await
            .map(crate::hvm_scheduler::HvmWatchtowerPass::Evaluated)
    }

    pub async fn run_hvm_lease_renewal(
        &self,
        request: HvmLeaseRenewalRequestV1,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        request.validate()?;
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "HVM lease renewal is not enabled for a mainnet profile".into(),
            ));
        }
        // Serialize admission, intent persistence and signing across both
        // watchtower and lease operations. Without this guard two requests can
        // observe the same empty slot before either durable intent exists.
        let _admission_guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        if let Some(existing) = self.load_hvm_chain_operation(&request.operation_id)? {
            if existing.request_commitment != request_commitment {
                return Err(HubError::State(
                    "HVM lease retry changed the durable request".into(),
                ));
            }
            if existing.status != HvmChainOperationStatus::Confirmed {
                self.ensure_hvm_chain_reconciliation_allowed(&existing)?;
            }
            return self.resume_hvm_chain_operation(existing).await;
        }
        self.ensure_settlement_ready()?;
        let activation = self.hvm_activation(&request.binding_commitment)?;
        {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if guard.hvm_chain_operations.values().any(|operation| {
                operation.idempotency_key == request.idempotency_key
                    || (operation.binding_commitment == request.binding_commitment
                        && operation.status != HvmChainOperationStatus::Confirmed)
            }) {
                return Err(HubError::State(
                    "HVM channel already has an unresolved chain operation".into(),
                ));
            }
        }
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks,
            )
            .await?;
        if !lease_renewal_is_due(
            activation.minimum_required_recover_blocks,
            snapshot.minimum_live_blocks,
            request.renew_when_live_blocks_at_or_below,
        ) {
            return Ok(HvmWatchtowerResponseV1 {
                operation_id: request.operation_id,
                status: "not_due".into(),
                action: "renew_all_leases".into(),
                transaction_hash: None,
                confirmed_block_height: None,
                observed_confirmations: 0,
                submitted_unix: None,
                claim_payee: None,
                claim_amount_zhu: None,
                claim_settled_elsewhere_height: None,
            });
        }
        let source = renew_all_call_source(&activation.recovery_bundle.binding, request.periods)?;
        let operation = PersistedHvmChainOperation {
            operation_id: request.operation_id,
            idempotency_key: request.idempotency_key,
            request_commitment,
            binding_commitment: request.binding_commitment,
            kind: HvmChainOperationKind::RenewAllLeases,
            bill_serial: None,
            expected_left_balance_zhu: None,
            expected_right_balance_zhu: None,
            lease_keys: HVM_STORAGE_KEYS
                .iter()
                .map(|key| (*key).to_owned())
                .collect(),
            claim_payee: None,
            claim_amount_zhu: None,
            claim_settled_elsewhere_height: None,
            lease_periods: Some(request.periods),
            pre_observed_height: snapshot.observed_height,
            pre_status: snapshot.storage.status.value,
            pre_serial: snapshot.storage.serial.value,
            pre_minimum_live_blocks: snapshot.minimum_live_blocks,
            network_fee_zhu: request.network_fee_zhu,
            gas_max: request.gas_max,
            transaction_timestamp: request.timestamp,
            call_source_commitment: hex::encode(Sha256::digest(source.as_bytes())),
            call_source: source,
            signed_transaction_hex: None,
            transaction_hash: None,
            status: HvmChainOperationStatus::IntentPersisted,
            submitted_unix: None,
            confirmed_block_height: None,
            observed_confirmations: 0,
            created_unix: request.created_unix,
            updated_unix: request.created_unix,
            last_error: None,
        };
        self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainIntentPersisted)?;
        self.resume_hvm_chain_operation(operation).await
    }

    pub async fn reconcile_hvm_watchtower(
        &self,
        operation_id: &str,
        allow_exact_resubmit: bool,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "HVM watchtower reconciliation is not enabled for a mainnet profile".into(),
            ));
        }
        let _guard = self.hvm_signing_lock.lock().await;
        let mut operation = self
            .load_hvm_chain_operation(operation_id)?
            .ok_or_else(|| HubError::NotFound(format!("HVM operation {operation_id}")))?;
        if operation.status == HvmChainOperationStatus::Confirmed {
            return Ok(hvm_chain_response(&operation));
        }
        self.ensure_hvm_chain_reconciliation_allowed(&operation)?;
        let is_local_pilot_stale = self.is_local_pilot_stale_challenge(&operation)?;
        if is_local_pilot_stale {
            #[cfg(feature = "local-pilot-tools")]
            self.require_exact_local_pilot().await?;
            #[cfg(not(feature = "local-pilot-tools"))]
            return Err(HubError::Admission(
                "persisted Local Pilot operation is unavailable in this build".into(),
            ));
        }
        let body = operation.signed_transaction_hex.clone().ok_or_else(|| {
            HubError::State("RecoveryRequired: HVM operation has no durable signed bytes".into())
        })?;
        let hash = operation.transaction_hash.clone().ok_or_else(|| {
            HubError::State("RecoveryRequired: HVM operation has no transaction hash".into())
        })?;
        match self.query_hvm_chain_transaction(&operation, &hash).await {
            Ok(Some(observation)) => {
                return self.apply_hvm_observation(operation, observation).await;
            }
            Ok(None) if operation.confirmed_block_height.is_some() => {
                return self.mark_hvm_chain_recovery(
                    operation,
                    "previously observed HVM transaction disappeared before finality",
                );
            }
            Err(error) => {
                return self.mark_hvm_chain_recovery(operation, &error.to_string());
            }
            Ok(None) => {}
        }
        // Our bytes are not on chain. For a claim that is not the same as the
        // payout not having happened: anybody may trigger it, and if the exact
        // approved payout is already recorded then resubmitting ours would
        // only buy a `HPAY_LEFT_ALREADY_CLAIMED` throw and a spent fee.
        if operation.kind == HvmChainOperationKind::Claim {
            let activation = self.hvm_activation(&operation.binding_commitment)?;
            if let Some(height) = self.hvm_claim_already_paid(&operation, &activation).await? {
                return self.settle_hvm_claim_paid_elsewhere(operation, height);
            }
        }
        if !allow_exact_resubmit {
            return Ok(hvm_chain_response(&operation));
        }
        let activation = self.hvm_activation(&operation.binding_commitment)?;
        let recover_floor = required_recover_blocks(
            activation.minimum_required_recover_blocks,
            operation.kind.clone(),
            false,
        );
        self.node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                recover_floor,
            )
            .await?;
        operation.status = HvmChainOperationStatus::SubmissionStarted;
        self.persist_hvm_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainSubmissionStarted,
        )?;
        if let Err(error) = self
            .node
            .submit_hvm_transaction_bound(&body, &hash, &activation.recovery_bundle.binding)
            .await
        {
            return self.mark_hvm_chain_recovery(operation, &error.to_string());
        }
        operation.status = HvmChainOperationStatus::Submitted;
        operation.submitted_unix = Some(crate::node::now_unix());
        operation.last_error = None;
        self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainSubmitted)?;
        match self.query_hvm_chain_transaction(&operation, &hash).await {
            Ok(Some(observation)) => self.apply_hvm_observation(operation, observation).await,
            Ok(None) => Ok(hvm_chain_response(&operation)),
            Err(error) => self.mark_hvm_chain_recovery(operation, &error.to_string()),
        }
    }

    fn ensure_hvm_chain_reconciliation_allowed(
        &self,
        operation: &PersistedHvmChainOperation,
    ) -> HubResult<()> {
        if !self
            .recovery_required
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return self.ensure_settlement_ready();
        }
        if !matches!(
            operation.status,
            HvmChainOperationStatus::Signed
                | HvmChainOperationStatus::SubmissionStarted
                | HvmChainOperationStatus::Submitted
                | HvmChainOperationStatus::RecoveryRequired
        ) || operation.signed_transaction_hex.is_none()
            || operation.transaction_hash.is_none()
        {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        let mut without_target = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .clone();
        let removed = without_target
            .hvm_chain_operations
            .remove(&operation.operation_id)
            .ok_or_else(|| HubError::State("RecoveryRequired".into()))?;
        if removed != *operation || super::persisted_state_requires_recovery(&without_target) {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        self.ensure_durable_storage_ready()
    }

    pub fn hvm_chain_operation_last_error(&self, operation_id: &str) -> HubResult<Option<String>> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State("HVM operation id is empty".into()));
        }
        Ok(self
            .load_hvm_chain_operation(operation_id)?
            .and_then(|operation| operation.last_error))
    }

    pub async fn run_hvm_watchtower(
        &self,
        request: HvmWatchtowerRequestV1,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        self.run_hvm_watchtower_internal(request, false).await
    }

    /// Deliberately submits the initial serial-1 bill after a newer bill is
    /// durable, solely to prove the production respond path on the pinned
    /// loopback chain-7 Local Pilot. It is absent from ordinary server builds.
    #[cfg(feature = "local-pilot-tools")]
    pub async fn run_hvm_local_pilot_stale_challenge(
        &self,
        request: HvmWatchtowerRequestV1,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        self.run_hvm_watchtower_internal(request, true).await
    }

    async fn run_hvm_watchtower_internal(
        &self,
        request: HvmWatchtowerRequestV1,
        local_pilot_stale_challenge: bool,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        request.validate()?;
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "HVM watchtower broadcast is not enabled for a mainnet profile".into(),
            ));
        }
        if local_pilot_stale_challenge {
            #[cfg(feature = "local-pilot-tools")]
            {
                self.require_exact_local_pilot().await?;
                if request.mode != HvmWatchtowerMode::BeginChallenge {
                    return Err(HubError::State(
                        "Local Pilot stale challenge requires begin-challenge mode".into(),
                    ));
                }
            }
            #[cfg(not(feature = "local-pilot-tools"))]
            return Err(HubError::Admission(
                "Local Pilot tools are not compiled into this Hub".into(),
            ));
        }
        let _admission_guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        if let Some(existing) = self.load_hvm_chain_operation(&request.operation_id)? {
            if existing.request_commitment != request_commitment {
                return Err(HubError::State(
                    "HVM watchtower retry changed the durable request".into(),
                ));
            }
            self.require_exact_challenge_variant(&existing, local_pilot_stale_challenge)?;
            if existing.status != HvmChainOperationStatus::Confirmed {
                self.ensure_hvm_chain_reconciliation_allowed(&existing)?;
            }
            return self.resume_hvm_chain_operation(existing).await;
        }
        self.ensure_settlement_ready()?;
        let (activation, latest) = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if guard.hvm_chain_operations.values().any(|operation| {
                operation.idempotency_key == request.idempotency_key
                    || (operation.binding_commitment == request.binding_commitment
                        && operation.status != HvmChainOperationStatus::Confirmed)
            }) {
                return Err(HubError::State(
                    "HVM channel already has an unresolved chain operation".into(),
                ));
            }
            let activation = guard
                .hvm_channel_activations
                .get(&request.binding_commitment)
                .cloned()
                .ok_or_else(|| HubError::NotFound("HVM activation".into()))?;
            let latest = guard
                .hvm_channel_ledgers
                .get(&request.binding_commitment)
                .map(|ledger| ledger.latest_fully_signed_bill.clone())
                .ok_or_else(|| HubError::State("HVM ledger is missing".into()))?;
            (activation, latest)
        };
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        let decision = match request.mode {
            HvmWatchtowerMode::BeginChallenge if snapshot.storage.status.value == 2 => {
                HvmWatchtowerDecision::RespondWithLatestBill
            }
            HvmWatchtowerMode::BeginChallenge => {
                return Err(HubError::State(
                    "HVM challenge can begin only from exact open state".into(),
                ));
            }
            HvmWatchtowerMode::Monitor => {
                decide_watchtower_action(&snapshot, &activation.recovery_bundle.binding, &latest)?
            }
        };
        let challenge_bill = if local_pilot_stale_challenge {
            let initial = &activation.recovery_bundle.initial_recovery_bill;
            initial.validate_fully_signed(&activation.recovery_bundle.binding)?;
            if initial.serial != 1 || latest.serial <= initial.serial {
                return Err(HubError::State(
                    "Local Pilot stale challenge requires a newer authenticated bill".into(),
                ));
            }
            initial
        } else {
            &latest
        };
        let mut claim: Option<(String, u64)> = None;
        let (kind, source, serial, expected_left, expected_right) = match (request.mode, decision) {
            (HvmWatchtowerMode::BeginChallenge, _) => (
                HvmChainOperationKind::Challenge,
                challenge_call_source(&activation.recovery_bundle.binding, challenge_bill)?,
                Some(challenge_bill.serial),
                Some(challenge_bill.left_balance_zhu),
                Some(challenge_bill.right_balance_zhu),
            ),
            (_, HvmWatchtowerDecision::RespondWithLatestBill) => (
                HvmChainOperationKind::Respond,
                respond_call_source(&activation.recovery_bundle.binding, &latest)?,
                Some(latest.serial),
                Some(latest.left_balance_zhu),
                Some(latest.right_balance_zhu),
            ),
            (_, HvmWatchtowerDecision::Finalize) => (
                HvmChainOperationKind::Finalize,
                finalize_call_source(&activation.recovery_bundle.binding)?,
                Some(snapshot.storage.serial.value),
                None,
                None,
            ),
            (_, HvmWatchtowerDecision::ClaimLeftPayout) => {
                // The payout amount is read straight off the live contract
                // storage, never inferred from the durable bill: `PermitHAC`
                // rejects anything that is not exactly `left_balance`, and the
                // payee is the contract's own `left`, which
                // `validate_runtime_binding` has already pinned to
                // `binding.left_address`.
                claim = Some((
                    activation.recovery_bundle.binding.left_address.clone(),
                    snapshot.storage.left_balance.value,
                ));
                let (payee, amount_zhu) = claim.as_ref().expect("just set");
                (
                    HvmChainOperationKind::Claim,
                    claim_left_payout_source(
                        &activation.recovery_bundle.binding,
                        payee,
                        *amount_zhu,
                    )?,
                    None,
                    None,
                    None,
                )
            }
            (_, HvmWatchtowerDecision::NoAction) => {
                return Ok(HvmWatchtowerResponseV1 {
                    operation_id: request.operation_id,
                    status: "no_action".into(),
                    action: "none".into(),
                    transaction_hash: None,
                    confirmed_block_height: None,
                    observed_confirmations: 0,
                    submitted_unix: None,
                    claim_payee: None,
                    claim_amount_zhu: None,
                    claim_settled_elsewhere_height: None,
                });
            }
            (_, HvmWatchtowerDecision::RecoveryRequired) => {
                return Err(HubError::State(format!(
                    "RecoveryRequired: {}",
                    crate::hvm_watchtower::recovery_required_reason(&snapshot, &latest)
                )));
            }
        };
        let operation = PersistedHvmChainOperation {
            operation_id: request.operation_id,
            idempotency_key: request.idempotency_key,
            request_commitment,
            binding_commitment: request.binding_commitment,
            kind,
            bill_serial: serial,
            expected_left_balance_zhu: expected_left,
            expected_right_balance_zhu: expected_right,
            lease_keys: Vec::new(),
            lease_periods: None,
            claim_payee: claim.as_ref().map(|(payee, _)| payee.clone()),
            claim_amount_zhu: claim.as_ref().map(|(_, amount_zhu)| *amount_zhu),
            claim_settled_elsewhere_height: None,
            pre_observed_height: snapshot.observed_height,
            pre_status: snapshot.storage.status.value,
            pre_serial: snapshot.storage.serial.value,
            pre_minimum_live_blocks: snapshot.minimum_live_blocks,
            network_fee_zhu: request.network_fee_zhu,
            gas_max: request.gas_max,
            transaction_timestamp: request.timestamp,
            call_source_commitment: hex::encode(Sha256::digest(source.as_bytes())),
            call_source: source,
            signed_transaction_hex: None,
            transaction_hash: None,
            status: HvmChainOperationStatus::IntentPersisted,
            submitted_unix: None,
            confirmed_block_height: None,
            observed_confirmations: 0,
            created_unix: request.created_unix,
            updated_unix: request.created_unix,
            last_error: None,
        };
        self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainIntentPersisted)?;
        self.resume_hvm_chain_operation(operation).await
    }

    fn require_exact_challenge_variant(
        &self,
        operation: &PersistedHvmChainOperation,
        local_pilot_stale_challenge: bool,
    ) -> HubResult<()> {
        if operation.kind != HvmChainOperationKind::Challenge {
            return Ok(());
        }
        let activation = self.hvm_activation(&operation.binding_commitment)?;
        let latest = self.hvm_latest_bill(&operation.binding_commitment)?;
        let expected = if local_pilot_stale_challenge {
            #[cfg(feature = "local-pilot-tools")]
            {
                let network = crate::hvm_pilot::HvmLocalPilotNetwork::canonical();
                let binding = &activation.recovery_bundle.binding;
                if self.deployment_profile != "local-pilot"
                    || binding.network_mode != "testnet"
                    || binding.chain_id != network.chain_id
                    || binding.network_instance_id != network.network_instance_id
                {
                    return Err(HubError::Admission(
                        "stale challenge binding is not the exact chain-7 Local Pilot".into(),
                    ));
                }
                let initial = &activation.recovery_bundle.initial_recovery_bill;
                if initial.serial != 1 || latest.serial <= initial.serial {
                    return Err(HubError::State(
                        "Local Pilot stale challenge no longer has a newer durable bill".into(),
                    ));
                }
                initial
            }
            #[cfg(not(feature = "local-pilot-tools"))]
            {
                return Err(HubError::Admission(
                    "Local Pilot tools are not compiled into this Hub".into(),
                ));
            }
        } else {
            &latest
        };
        let expected_source = challenge_call_source(&activation.recovery_bundle.binding, expected)?;
        if operation.bill_serial != Some(expected.serial)
            || operation.expected_left_balance_zhu != Some(expected.left_balance_zhu)
            || operation.expected_right_balance_zhu != Some(expected.right_balance_zhu)
            || operation.call_source != expected_source
        {
            return Err(HubError::State(
                "watchtower retry selected a different challenge bill".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "local-pilot-tools")]
    pub(crate) async fn require_exact_local_pilot(&self) -> HubResult<()> {
        if self.deployment_profile != "local-pilot" {
            return Err(HubError::Admission(
                "stale challenge injection requires the local-pilot deployment profile".into(),
            ));
        }
        crate::hvm_pilot::validate_hvm_pilot_node_url(self.node.base_url())?;
        let capabilities = self.node.capabilities().await?;
        crate::hvm_pilot::HvmLocalPilotNetwork::canonical().validate_capabilities(&capabilities)
    }

    async fn resume_hvm_chain_operation(
        &self,
        mut operation: PersistedHvmChainOperation,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        if operation.status == HvmChainOperationStatus::Confirmed {
            return Ok(hvm_chain_response(&operation));
        }
        if operation.status == HvmChainOperationStatus::RecoveryRequired {
            return Ok(hvm_chain_response(&operation));
        }
        if operation.status == HvmChainOperationStatus::IntentPersisted {
            let source = operation.call_source.clone();
            let activation = self.hvm_activation(&operation.binding_commitment)?;
            let is_local_pilot_stale = self.is_local_pilot_stale_challenge(&operation)?;
            if is_local_pilot_stale {
                #[cfg(feature = "local-pilot-tools")]
                self.require_exact_local_pilot().await?;
                #[cfg(not(feature = "local-pilot-tools"))]
                return Err(HubError::Admission(
                    "persisted Local Pilot operation is unavailable in this build".into(),
                ));
            }
            self.verify_hvm_operation_precondition(&operation, &activation)
                .await?;
            operation.status = HvmChainOperationStatus::SignatureMayExist;
            self.persist_hvm_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSignatureMayExist,
            )?;
            let signed = self.sign_hvm_chain_operation(&operation, &activation, source)?;
            operation.signed_transaction_hex = Some(signed.signed_transaction_hex);
            operation.transaction_hash = Some(signed.transaction_hash);
            operation.status = HvmChainOperationStatus::Signed;
            operation.last_error = None;
            self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainSigned)?;
        }
        if operation.status == HvmChainOperationStatus::SignatureMayExist {
            return self
                .mark_hvm_chain_recovery(operation, "signature bytes unavailable after restart");
        }
        if matches!(operation.status, HvmChainOperationStatus::Signed) {
            let activation = self.hvm_activation(&operation.binding_commitment)?;
            let is_local_pilot_stale = self.is_local_pilot_stale_challenge(&operation)?;
            if is_local_pilot_stale {
                #[cfg(feature = "local-pilot-tools")]
                self.require_exact_local_pilot().await?;
                #[cfg(not(feature = "local-pilot-tools"))]
                return Err(HubError::Admission(
                    "persisted Local Pilot operation is unavailable in this build".into(),
                ));
            }
            if let Err(error) = self
                .verify_hvm_operation_precondition(&operation, &activation)
                .await
            {
                return self.mark_hvm_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::SubmissionStarted;
            self.persist_hvm_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSubmissionStarted,
            )?;
        }
        if operation.status == HvmChainOperationStatus::SubmissionStarted {
            let body = operation.signed_transaction_hex.clone().unwrap_or_default();
            let hash = operation.transaction_hash.clone().unwrap_or_default();
            let activation = self.hvm_activation(&operation.binding_commitment)?;
            if let Err(error) = self
                .node
                .submit_hvm_transaction_bound(&body, &hash, &activation.recovery_bundle.binding)
                .await
            {
                return self.mark_hvm_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::Submitted;
            operation.submitted_unix = Some(crate::node::now_unix());
            self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainSubmitted)?;
        }
        let hash = operation.transaction_hash.clone().unwrap_or_default();
        match self.query_hvm_chain_transaction(&operation, &hash).await {
            Ok(Some(observation)) => self.apply_hvm_observation(operation, observation).await,
            Ok(None) if operation.confirmed_block_height.is_some() => self.mark_hvm_chain_recovery(
                operation,
                "previously observed HVM transaction disappeared before finality",
            ),
            Ok(None) if operation.kind == HvmChainOperationKind::Claim => {
                let activation = self.hvm_activation(&operation.binding_commitment)?;
                match self.hvm_claim_already_paid(&operation, &activation).await? {
                    Some(height) => self.settle_hvm_claim_paid_elsewhere(operation, height),
                    None => Ok(hvm_chain_response(&operation)),
                }
            }
            Ok(None) => Ok(hvm_chain_response(&operation)),
            Err(error) => self.mark_hvm_chain_recovery(operation, &error.to_string()),
        }
    }

    /// A claim is observed through its Action 14 proof; every other kind is
    /// observed through its Action 44 proof. Neither is loosened for the other.
    async fn query_hvm_chain_transaction(
        &self,
        operation: &PersistedHvmChainOperation,
        transaction_hash: &str,
    ) -> HubResult<Option<crate::node::TransactionObservation>> {
        if operation.kind == HvmChainOperationKind::Claim {
            return self
                .node
                .query_hvm_claim_transaction(transaction_hash)
                .await;
        }
        self.node.query_hvm_transaction(transaction_hash).await
    }

    /// Has the exact approved payout already been recorded on chain?
    ///
    /// Claims are permissionless: `intrinsic_req_sign` never adds the contract
    /// (it is not `is_privakey()`), so anybody willing to pay the fee can
    /// trigger the payout. When they do, the contract sets `left_claimed` and
    /// the money has already reached the payee. Answering "yes" here is what
    /// stops this Hub from chasing a payout that has happened, and what stops
    /// it latching recovery over somebody else's success.
    ///
    /// The answer is deliberately narrow: the exact amount and the exact payee
    /// are compared too, and a zero amount is never treated as settled.
    async fn hvm_claim_already_paid(
        &self,
        operation: &PersistedHvmChainOperation,
        activation: &crate::storage::PersistedHvmChannelActivation,
    ) -> HubResult<Option<u64>> {
        if operation.kind != HvmChainOperationKind::Claim {
            return Ok(None);
        }
        let (payee, amount_zhu) = hvm_claim_terms(operation)?;
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        let settled = snapshot.storage.status.value == 4
            && snapshot.storage.left_claimed.value
            && amount_zhu > 0
            && snapshot.storage.left_balance.value == amount_zhu
            && snapshot.storage.left.value == payee;
        Ok(settled.then_some(snapshot.observed_height))
    }

    /// Resolve a claim whose payout already happened without us. There is no
    /// transaction of ours to anchor, so none is invented: the durable record
    /// keeps the observed height as its evidence and stays free of block
    /// finality fields it does not own.
    fn settle_hvm_claim_paid_elsewhere(
        &self,
        mut operation: PersistedHvmChainOperation,
        observed_height: u64,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        if operation.kind != HvmChainOperationKind::Claim || observed_height == 0 {
            return Err(HubError::State(
                "only an HVM claim can settle on a third-party payout".into(),
            ));
        }
        operation.claim_settled_elsewhere_height = Some(observed_height);
        operation.confirmed_block_height = None;
        operation.observed_confirmations = 0;
        operation.status = HvmChainOperationStatus::Confirmed;
        operation.last_error = None;
        operation.updated_unix = crate::node::now_unix();
        self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainConfirmed)?;
        Ok(hvm_chain_response(&operation))
    }

    /// Produce the exact signed transaction this operation's kind calls for.
    ///
    /// A claim is an Action 14 payout with no fitsh source to compile; every
    /// other kind is an Action 44 contract call. The durable `call_source` is
    /// the canonical descriptor in both cases and is re-derived here, never
    /// trusted as free text.
    fn sign_hvm_chain_operation(
        &self,
        operation: &PersistedHvmChainOperation,
        activation: &crate::storage::PersistedHvmChannelActivation,
        source: String,
    ) -> HubResult<crate::hvm_watchtower::SignedHvmCallTransaction> {
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer unavailable".into()))?
            .account();
        let binding = &activation.recovery_bundle.binding;
        if operation.kind == HvmChainOperationKind::Claim {
            let (payee, amount_zhu) = hvm_claim_terms(operation)?;
            if claim_left_payout_source(binding, payee, amount_zhu)? != source {
                return Err(HubError::State(
                    "HVM claim payout descriptor is not canonical".into(),
                ));
            }
            let signed = build_signed_hvm_claim_transaction(
                signer,
                binding,
                payee,
                amount_zhu,
                operation.network_fee_zhu,
                operation.transaction_timestamp,
                operation.gas_max,
            )?;
            read_exact_hvm_claim_transaction(
                &signed.signed_transaction_hex,
                binding,
                payee,
                amount_zhu,
            )?;
            return Ok(signed);
        }
        build_signed_hvm_call_transaction(
            signer,
            binding,
            source,
            operation.network_fee_zhu,
            operation.transaction_timestamp,
            operation.gas_max,
        )
    }

    fn is_local_pilot_stale_challenge(
        &self,
        operation: &PersistedHvmChainOperation,
    ) -> HubResult<bool> {
        if operation.kind != HvmChainOperationKind::Challenge {
            return Ok(false);
        }
        let activation = self.hvm_activation(&operation.binding_commitment)?;
        let latest = self.hvm_latest_bill(&operation.binding_commitment)?;
        let initial = &activation.recovery_bundle.initial_recovery_bill;
        let initial_source = challenge_call_source(&activation.recovery_bundle.binding, initial)?;
        let latest_source = challenge_call_source(&activation.recovery_bundle.binding, &latest)?;
        if operation.call_source == latest_source {
            self.require_exact_challenge_variant(operation, false)?;
            return Ok(false);
        }
        if operation.call_source == initial_source
            && initial.serial == 1
            && latest.serial > initial.serial
        {
            self.require_exact_challenge_variant(operation, true)?;
            return Ok(true);
        }
        Err(HubError::State(
            "persisted challenge source does not match the authenticated initial or latest bill"
                .into(),
        ))
    }

    async fn verify_hvm_operation_precondition(
        &self,
        operation: &PersistedHvmChainOperation,
        activation: &crate::storage::PersistedHvmChannelActivation,
    ) -> HubResult<()> {
        let recover_floor = required_recover_blocks(
            activation.minimum_required_recover_blocks,
            operation.kind.clone(),
            false,
        );
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                recover_floor,
            )
            .await?;
        if snapshot.observed_height < operation.pre_observed_height {
            return Err(HubError::State(
                "HVM operation node height moved backwards before signing".into(),
            ));
        }
        match operation.kind {
            HvmChainOperationKind::Challenge => {
                if snapshot.storage.status.value != 2
                    || operation.pre_status != 2
                    || snapshot.storage.serial.value != operation.pre_serial
                {
                    return Err(HubError::State(
                        "HVM challenge precondition changed before signing".into(),
                    ));
                }
            }
            HvmChainOperationKind::Respond => {
                if snapshot.storage.status.value != 3
                    || operation.pre_status != 3
                    || snapshot.storage.serial.value != operation.pre_serial
                    || operation
                        .bill_serial
                        .is_none_or(|serial| serial <= snapshot.storage.serial.value)
                    || snapshot.observed_height >= snapshot.storage.deadline.value
                {
                    return Err(HubError::State(
                        "HVM respond precondition changed or expired before signing".into(),
                    ));
                }
            }
            HvmChainOperationKind::Finalize => {
                if snapshot.storage.status.value != 3
                    || operation.pre_status != 3
                    || Some(snapshot.storage.serial.value) != operation.bill_serial
                    || snapshot.observed_height < snapshot.storage.deadline.value
                {
                    return Err(HubError::State(
                        "HVM finalize precondition changed before signing".into(),
                    ));
                }
            }
            HvmChainOperationKind::RenewAllLeases => {
                let periods = operation.lease_periods.ok_or_else(|| {
                    HubError::State("HVM lease operation lost its renewal periods".into())
                })?;
                if operation.call_source
                    != renew_all_call_source(&activation.recovery_bundle.binding, periods)?
                {
                    return Err(HubError::State(
                        "HVM lease renewal source changed before signing".into(),
                    ));
                }
            }
            HvmChainOperationKind::Claim => {
                let (payee, amount_zhu) = hvm_claim_terms(operation)?;
                // `PermitHAC` pays the left party only from FINAL state, only
                // once, and only the exact `left_balance`. Every one of those
                // is re-read here, against live evidence, immediately before
                // the key is used and again before submission.
                if snapshot.storage.status.value != 4
                    || operation.pre_status != 4
                    || snapshot.storage.left_claimed.value
                    || snapshot.storage.left_balance.value != amount_zhu
                    || amount_zhu == 0
                    || snapshot.storage.left.value != payee
                    || snapshot.storage.serial.value != operation.pre_serial
                {
                    return Err(HubError::State(
                        "HVM claim precondition is no longer true".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn apply_hvm_observation(
        &self,
        mut operation: PersistedHvmChainOperation,
        observation: crate::node::TransactionObservation,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        if observation.body_hex != operation.signed_transaction_hex.clone().unwrap_or_default() {
            return self.mark_hvm_chain_recovery(operation, "confirmed HVM bytes differ");
        }
        if operation.confirmed_block_height.is_some()
            && (observation.pending || observation.block_height != operation.confirmed_block_height)
        {
            return self.mark_hvm_chain_recovery(
                operation,
                "HVM transaction inclusion changed before finality",
            );
        }
        operation.confirmed_block_height = observation.block_height;
        operation.observed_confirmations = observation.confirmations;
        operation.updated_unix = crate::node::now_unix();
        if observation.confirmations >= 6 {
            if let Err(error) = self.verify_hvm_chain_postcondition(&operation).await {
                return self.mark_hvm_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::Confirmed;
            self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainConfirmed)?;
        } else {
            operation.status = HvmChainOperationStatus::Submitted;
            self.persist_hvm_chain_operation(operation.clone(), JournalPhase::HvmChainSubmitted)?;
        }
        Ok(hvm_chain_response(&operation))
    }

    async fn verify_hvm_chain_postcondition(
        &self,
        operation: &PersistedHvmChainOperation,
    ) -> HubResult<()> {
        let activation = self.hvm_activation(&operation.binding_commitment)?;
        let recover_floor = required_recover_blocks(
            activation.minimum_required_recover_blocks,
            operation.kind.clone(),
            true,
        );
        let snapshot = self
            .node
            .verify_hvm_runtime_channel(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                recover_floor,
            )
            .await?;
        if snapshot.observed_height < operation.pre_observed_height {
            return Err(HubError::State(
                "HVM postcondition node height moved backwards".into(),
            ));
        }
        match operation.kind {
            HvmChainOperationKind::Challenge | HvmChainOperationKind::Respond => {
                if snapshot.storage.status.value != 3
                    || Some(snapshot.storage.serial.value) != operation.bill_serial
                    || Some(snapshot.storage.left_balance.value)
                        != operation.expected_left_balance_zhu
                    || Some(snapshot.storage.right_balance.value)
                        != operation.expected_right_balance_zhu
                {
                    return Err(HubError::State(
                        "confirmed HVM bill call did not produce the exact contract state".into(),
                    ));
                }
            }
            HvmChainOperationKind::Finalize => {
                if snapshot.storage.status.value != 4 {
                    return Err(HubError::State(
                        "confirmed HVM finalize did not produce FINAL state".into(),
                    ));
                }
            }
            HvmChainOperationKind::RenewAllLeases => {
                if snapshot.minimum_live_blocks <= operation.pre_minimum_live_blocks {
                    return Err(HubError::State(
                        "confirmed HVM renewal did not increase all lease lifetimes".into(),
                    ));
                }
            }
            HvmChainOperationKind::Claim => {
                let (payee, amount_zhu) = hvm_claim_terms(operation)?;
                // The contract's own evidence that this payout happened, and
                // the only evidence there is: `PermitHAC` sets `left_claimed`
                // and leaves `left_balance` standing as the record of what it
                // paid. A confirmed claim that did not move that flag did not
                // pay anybody.
                if snapshot.storage.status.value != 4
                    || !snapshot.storage.left_claimed.value
                    || snapshot.storage.left_balance.value != amount_zhu
                    || snapshot.storage.left.value != payee
                {
                    return Err(HubError::State(
                        "confirmed HVM claim did not record the exact payout".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn hvm_activation(
        &self,
        commitment: &str,
    ) -> HubResult<crate::storage::PersistedHvmChannelActivation> {
        self.inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_channel_activations
            .get(commitment)
            .cloned()
            .ok_or_else(|| HubError::NotFound("HVM activation".into()))
    }

    fn load_hvm_chain_operation(&self, id: &str) -> HubResult<Option<PersistedHvmChainOperation>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_chain_operations
            .get(id)
            .cloned())
    }

    fn mark_hvm_chain_recovery(
        &self,
        mut operation: PersistedHvmChainOperation,
        error: &str,
    ) -> HubResult<HvmWatchtowerResponseV1> {
        operation.status = HvmChainOperationStatus::RecoveryRequired;
        operation.last_error = Some(error.into());
        self.persist_hvm_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainRecoveryRequired,
        )?;
        Ok(hvm_chain_response(&operation))
    }

    fn persist_hvm_chain_operation(
        &self,
        operation: PersistedHvmChainOperation,
        phase: JournalPhase,
    ) -> HubResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next = guard.clone();
        next.hvm_chain_operations
            .insert(operation.operation_id.clone(), operation.clone());
        validate_hvm_state(&next)?;
        let activation = next
            .hvm_channel_activations
            .get(&operation.binding_commitment)
            .unwrap();
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.clone(),
            channel_id: activation.recovery_bundle.binding.channel_id.clone(),
            channel_reuse_version: u64::from(activation.recovery_bundle.binding.reuse_version),
            operation_id: operation.operation_id.clone(),
            operation_type: if operation.kind == HvmChainOperationKind::RenewAllLeases {
                JournalOperationType::HvmLeaseRenewal
            } else {
                JournalOperationType::HvmWatchtower
            },
            operation_phase: phase,
            amount_zhu: operation.network_fee_zhu,
            sender: self.hub_address.clone(),
            recipient: activation.recovery_bundle.binding.contract_address.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: operation.bill_serial,
            unsigned_state_commitment: Some(operation.call_source_commitment.clone()),
            created_at: operation.updated_unix,
        };
        self.commit_authenticated_state(&mut guard, next, event)
    }
}

/// Rebuild the exact durable request an outstanding watchtower-tick operation
/// was created from, or refuse to touch the record.
///
/// Two refusals, and neither is a formality. A record this tick did not open
/// belongs to whoever did — an operator's `pilot-watch-…` challenge, say — and
/// driving it would put that person's transaction on the wire without them.
/// A record that is not a monitor action cannot be rebuilt as one: the tick
/// monitors, so it never rebuilds a request that would begin a challenge or
/// renew a lease.
fn hvm_watchtower_tick_request(
    operation: &PersistedHvmChainOperation,
) -> HubResult<HvmWatchtowerRequestV1> {
    if !operation
        .operation_id
        .starts_with(crate::hvm_scheduler::HVM_WATCHTOWER_OPERATION_PREFIX)
        || operation
            .operation_id
            .starts_with(crate::hvm_scheduler::HVM_WATCHTOWER_IDEMPOTENCY_PREFIX)
        || !operation
            .idempotency_key
            .starts_with(crate::hvm_scheduler::HVM_WATCHTOWER_IDEMPOTENCY_PREFIX)
    {
        return Err(HubError::State(format!(
            "HVM chain operation {} is unresolved on this channel and was not opened by the watchtower tick; the tick will not drive it",
            operation.operation_id
        )));
    }
    if !matches!(
        operation.kind,
        HvmChainOperationKind::Respond
            | HvmChainOperationKind::Finalize
            | HvmChainOperationKind::Claim
    ) {
        return Err(HubError::State(format!(
            "HVM chain operation {} is not a watchtower monitor action",
            operation.operation_id
        )));
    }
    let request = HvmWatchtowerRequestV1 {
        schema: crate::hvm_watchtower::HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        binding_commitment: operation.binding_commitment.clone(),
        mode: HvmWatchtowerMode::Monitor,
        network_fee_zhu: operation.network_fee_zhu,
        timestamp: operation.transaction_timestamp,
        gas_max: operation.gas_max,
        created_unix: operation.created_unix,
    };
    request.validate()?;
    Ok(request)
}

fn hvm_chain_response(operation: &PersistedHvmChainOperation) -> HvmWatchtowerResponseV1 {
    HvmWatchtowerResponseV1 {
        operation_id: operation.operation_id.clone(),
        status: operation.status.as_str().to_owned(),
        action: operation.kind.as_str().to_owned(),
        transaction_hash: operation.transaction_hash.clone(),
        confirmed_block_height: operation.confirmed_block_height,
        observed_confirmations: operation.observed_confirmations,
        submitted_unix: operation.submitted_unix,
        claim_payee: operation.claim_payee.clone(),
        claim_amount_zhu: operation.claim_amount_zhu,
        claim_settled_elsewhere_height: operation.claim_settled_elsewhere_height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_forces_first_renewal_and_only_renewal_uses_zero_recovery_floor() {
        assert!(lease_renewal_is_due(0, 10_000, 1));
        assert_eq!(
            required_recover_blocks(0, HvmChainOperationKind::RenewAllLeases, false),
            0
        );
        assert_eq!(
            required_recover_blocks(0, HvmChainOperationKind::Challenge, false),
            1
        );
        assert_eq!(
            required_recover_blocks(0, HvmChainOperationKind::RenewAllLeases, true),
            1
        );
        assert!(!lease_renewal_is_due(1, 10_000, 1));
    }
}
