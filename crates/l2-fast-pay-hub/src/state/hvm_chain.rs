use sha2::{Digest, Sha256};

use super::HubState;
use crate::error::{HubError, HubResult};
use crate::hvm_watchtower::{
    HVM_STORAGE_KEYS, HvmLeaseRenewalRequestV1, HvmWatchtowerDecision, HvmWatchtowerMode,
    HvmWatchtowerRequestV1, HvmWatchtowerResponseV1, build_signed_hvm_call_transaction,
    challenge_call_source, decide_watchtower_action, finalize_call_source, renew_all_call_source,
    respond_call_source,
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

/// The Action 14 payout claim belongs to the shared registry (V2) profile,
/// whose contract exposes the `PermitHAC` hook. The V1 HVM channel contract
/// has no payout door at all, so a V1 operation can never carry this kind.
fn v1_cannot_claim() -> HubError {
    HubError::State("V1 HVM chain operations have no registry claim".into())
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
            HvmChainOperationKind::Respond | HvmChainOperationKind::Finalize => {
                HvmWatchtowerMode::Monitor
            }
            HvmChainOperationKind::RenewAllLeases => {
                return Err(HubError::State(
                    "HVM operation id belongs to a lease renewal".into(),
                ));
            }
            HvmChainOperationKind::Claim => return Err(v1_cannot_claim()),
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
    /// The operation is named after a one-minute clock window, so two passes
    /// inside the same minute deliberately land on the same record — that is
    /// what makes a repeat a resume instead of a duplicate. But the name is the
    /// only part of the request the window makes stable: `commitment()` covers
    /// `timestamp` and `created_unix` too, and `run_hvm_lease_renewal` refuses
    /// a retry whose commitment moved. Minting a fresh `now` here would
    /// therefore hand the same record a different request one second later and
    /// the Hub would refuse its own work, leaving a signed transaction with
    /// nobody driving it.
    ///
    /// So the durable record is the tick's memory of when it first acted: if
    /// one exists under this name, its exact request is rebuilt from it, and a
    /// fresh `now` is read only when there is nothing to resume.
    async fn hvm_lease_channel_tick(
        &self,
        binding_commitment: &str,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmWatchtowerResponseV1> {
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
        match self.node.query_hvm_transaction(&hash).await {
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
        match self.node.query_hvm_transaction(&hash).await {
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
            (_, HvmWatchtowerDecision::NoAction) => {
                return Ok(HvmWatchtowerResponseV1 {
                    operation_id: request.operation_id,
                    status: "no_action".into(),
                    action: "none".into(),
                    transaction_hash: None,
                    confirmed_block_height: None,
                    observed_confirmations: 0,
                });
            }
            (_, HvmWatchtowerDecision::RecoveryRequired) => {
                return Err(HubError::State(
                    "RecoveryRequired: chain serial is newer than the authenticated HVM ledger"
                        .into(),
                ));
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
            let signed = build_signed_hvm_call_transaction(
                self.hub_signer
                    .as_ref()
                    .ok_or_else(|| HubError::State("Hub signer unavailable".into()))?
                    .account(),
                &activation.recovery_bundle.binding,
                source,
                operation.network_fee_zhu,
                operation.transaction_timestamp,
                operation.gas_max,
            )?;
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
        match self.node.query_hvm_transaction(&hash).await {
            Ok(Some(observation)) => self.apply_hvm_observation(operation, observation).await,
            Ok(None) if operation.confirmed_block_height.is_some() => self.mark_hvm_chain_recovery(
                operation,
                "previously observed HVM transaction disappeared before finality",
            ),
            Ok(None) => Ok(hvm_chain_response(&operation)),
            Err(error) => self.mark_hvm_chain_recovery(operation, &error.to_string()),
        }
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
            HvmChainOperationKind::Claim => return Err(v1_cannot_claim()),
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
            HvmChainOperationKind::Claim => return Err(v1_cannot_claim()),
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
            amount_units: operation.network_fee_zhu,
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

fn hvm_chain_response(operation: &PersistedHvmChainOperation) -> HvmWatchtowerResponseV1 {
    HvmWatchtowerResponseV1 {
        operation_id: operation.operation_id.clone(),
        status: operation.status.as_str().to_owned(),
        action: operation.kind.as_str().to_owned(),
        transaction_hash: operation.transaction_hash.clone(),
        confirmed_block_height: operation.confirmed_block_height,
        observed_confirmations: operation.observed_confirmations,
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
