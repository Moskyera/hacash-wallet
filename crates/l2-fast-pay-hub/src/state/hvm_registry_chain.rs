use std::sync::atomic::Ordering;

use sha2::{Digest, Sha256};

use crate::error::{HubError, HubResult};
use crate::hvm_registry::{HvmRegistryBillV2, HvmRegistryLiveSnapshotV2};
use crate::hvm_registry_watchtower::{
    HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS, HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA,
    HvmRegistryChainResponseV2, HvmRegistryLeaseRenewalRequestV2, HvmRegistryWatchtowerDecisionV2,
    HvmRegistryWatchtowerModeV2, HvmRegistryWatchtowerRequestV2, HvmRegistryWatchtowerSituationV2,
    build_signed_hvm_registry_call_transaction, build_signed_hvm_registry_claim_transaction,
    decide_registry_watchtower_action, read_exact_registry_claim_transaction,
    registry_challenge_call_source, registry_claim_payout_source, registry_finalize_call_source,
    registry_renew_all_call_source, registry_respond_call_source, registry_response_window_blocks,
    registry_response_window_is_safe, require_fresh_registry_evidence,
};
use crate::hvm_scheduler::{
    HVM_REGISTRY_WATCHTOWER_IDEMPOTENCY_PREFIX, HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX,
    HvmRegistryWatchtowerMaintenanceResult, HvmRegistryWatchtowerMaintenanceResults,
    registry_watchtower_operation_identity,
};
use crate::journal::{JournalEvent, JournalOperationType, JournalPhase};
use crate::node::TransactionObservation;
use crate::storage::{
    HvmChainOperationKind, HvmChainOperationStatus, PersistedHvmRegistryActivation,
    PersistedHvmRegistryChainOperation, is_canonical_block_anchor, validate_hvm_state,
};

use super::HubState;

impl HubState {
    pub async fn hvm_registry_lease_maintenance_tick(
        &self,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<crate::hvm_scheduler::HvmRegistryLeaseMaintenanceResults> {
        config.validate()?;
        let commitments = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_activations
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            let response = self
                .hvm_registry_lease_channel_tick(&commitment, config)
                .await;
            results.push(match response {
                Ok(response) => crate::hvm_scheduler::HvmRegistryLeaseMaintenanceResult {
                    binding_commitment: commitment,
                    response: Some(response),
                    error: None,
                },
                Err(error) => crate::hvm_scheduler::HvmRegistryLeaseMaintenanceResult {
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
    /// `timestamp` and `created_unix` too, and `run_hvm_registry_lease_renewal`
    /// refuses a retry whose commitment moved. Minting a fresh `now` here would
    /// therefore hand the same record a different request one second later and
    /// the Hub would refuse its own work, leaving a signed transaction with
    /// nobody driving it.
    ///
    /// So the durable record is the tick's memory of when it first acted: if
    /// one exists under this name, its exact request is rebuilt from it, and a
    /// fresh `now` is read only when there is nothing to resume.
    async fn hvm_registry_lease_channel_tick(
        &self,
        binding_commitment: &str,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        let now = crate::node::now_unix();
        let (operation_id, idempotency_key) =
            crate::hvm_scheduler::registry_operation_identity(binding_commitment, now);
        let request = match self.hvm_registry_lease_renewal_request(
            &operation_id,
            config.renew_when_live_blocks_at_or_below,
        )? {
            Some(existing) => existing,
            None => HvmRegistryLeaseRenewalRequestV2 {
                schema: crate::hvm_registry_watchtower::HVM_REGISTRY_LEASE_REQUEST_SCHEMA.into(),
                operation_id,
                idempotency_key,
                binding_commitment: binding_commitment.to_owned(),
                renew_when_blocks_at_or_below: config.renew_when_live_blocks_at_or_below,
                periods: config.periods,
                network_fee_zhu: config.network_fee_zhu,
                timestamp: now,
                gas_max: config.gas_max,
                created_unix: now,
            },
        };
        self.run_hvm_registry_lease_renewal(request).await
    }

    /// Evaluate the watchtower once for every activated registry channel.
    ///
    /// This is the driver the watchtower never had. It rides the existing
    /// lease scheduler loop, takes its fee and gas ceiling from the same
    /// operator-set configuration those ticks use, and reaches the chain only
    /// through [`Self::run_hvm_registry_watchtower`] — the same guarded entry
    /// point the CLI calls, in the same `Monitor` mode. It cannot sign or
    /// submit anything the manual path could not, because it is not a second
    /// path: it is a caller of the first one.
    ///
    /// Every channel is attempted and every outcome is recorded against its
    /// own binding. A channel whose node read fails, whose evidence is stale,
    /// or that is latched in recovery produces an error in its own slot and
    /// the pass continues to the next one.
    pub async fn hvm_registry_watchtower_tick(
        &self,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmRegistryWatchtowerMaintenanceResults> {
        config.validate()?;
        // Mainnet stays refused, and refused before any node traffic.
        self.require_registry_non_mainnet()?;
        let commitments = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_activations
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(commitments.len());
        for commitment in commitments {
            let outcome = self
                .hvm_registry_watchtower_channel_tick(&commitment, config)
                .await;
            results.push(match outcome {
                Ok(response) => HvmRegistryWatchtowerMaintenanceResult {
                    binding_commitment: commitment,
                    response: Some(response),
                    error: None,
                },
                Err(error) => HvmRegistryWatchtowerMaintenanceResult {
                    binding_commitment: commitment,
                    response: None,
                    error: Some(error.to_string()),
                },
            });
        }
        Ok(results)
    }

    async fn hvm_registry_watchtower_channel_tick(
        &self,
        binding_commitment: &str,
        config: &crate::hvm_scheduler::HvmLeaseSchedulerConfig,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        // An operation this tick already opened comes first, driven by the
        // byte-identical request it was created from. It has to: our own
        // confirmed response changes the chain, so the situation this channel
        // is in has already moved on from the one that named the record. Going
        // looking for a fresh name here would strand a signed transaction
        // nobody is reconciling.
        if let Some(existing) = self.unresolved_registry_chain_operation(binding_commitment)? {
            let request = registry_watchtower_tick_request(&existing)?;
            return self.run_hvm_registry_watchtower(request).await;
        }
        let activation = self.registry_activation(binding_commitment)?;
        let latest = self.registry_latest_bill(binding_commitment)?;
        // Read the tip before the registry view, so a snapshot that trails it
        // is genuinely trailing rather than merely older by a round trip.
        let capabilities = self.node.capabilities().await?;
        let snapshot = self
            .node
            .verify_hvm_registry_runtime_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        require_fresh_registry_evidence(
            &snapshot,
            capabilities.height,
            capabilities.tip_age_seconds,
        )?;
        let situation = HvmRegistryWatchtowerSituationV2::from_evidence(&snapshot, &latest);
        let (operation_id, idempotency_key) =
            registry_watchtower_operation_identity(binding_commitment, &situation);
        // A record already filed under this name is this same situation seen
        // again. Rebuild its exact request rather than a fresh one: the
        // durable record is the tick's memory of when it first saw this.
        let request = match self.load_hvm_registry_chain_operation(&operation_id)? {
            Some(existing) => registry_watchtower_tick_request(&existing)?,
            None => {
                let now = crate::node::now_unix();
                HvmRegistryWatchtowerRequestV2 {
                    schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
                    operation_id,
                    idempotency_key,
                    binding_commitment: binding_commitment.to_owned(),
                    mode: HvmRegistryWatchtowerModeV2::Monitor,
                    network_fee_zhu: config.network_fee_zhu,
                    timestamp: now,
                    gas_max: config.gas_max,
                    created_unix: now,
                }
            }
        };
        self.run_hvm_registry_watchtower(request).await
    }

    fn unresolved_registry_chain_operation(
        &self,
        binding_commitment: &str,
    ) -> HubResult<Option<PersistedHvmRegistryChainOperation>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_chain_operations
            .values()
            .find(|operation| {
                operation.binding_commitment == binding_commitment
                    && !operation.status.is_resolved()
            })
            .cloned())
    }

    fn registry_latest_bill(&self, binding_commitment: &str) -> HubResult<HvmRegistryBillV2> {
        self.inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_ledgers
            .get(binding_commitment)
            .map(|ledger| ledger.latest_fully_signed_bill.clone())
            .ok_or_else(|| HubError::State("HVM registry ledger is missing".into()))
    }

    pub async fn run_hvm_registry_watchtower(
        &self,
        request: HvmRegistryWatchtowerRequestV2,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        self.run_hvm_registry_watchtower_internal(request, false)
            .await
    }

    /// Submits the exact initial serial-1 bill only on the canonical loopback
    /// chain-7 pilot, so the production Monitor path can prove that it
    /// responds with a newer durable bill. This method is absent from normal
    /// Hub builds and does not add a public HTTP route.
    #[cfg(feature = "local-pilot-tools")]
    pub async fn run_hvm_registry_local_pilot_stale_challenge(
        &self,
        request: HvmRegistryWatchtowerRequestV2,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        self.run_hvm_registry_watchtower_internal(request, true)
            .await
    }

    async fn run_hvm_registry_watchtower_internal(
        &self,
        request: HvmRegistryWatchtowerRequestV2,
        local_pilot_stale_challenge: bool,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        request.validate()?;
        self.require_registry_non_mainnet()?;
        if local_pilot_stale_challenge {
            #[cfg(feature = "local-pilot-tools")]
            {
                self.require_exact_local_pilot().await?;
                if request.mode != HvmRegistryWatchtowerModeV2::BeginChallenge {
                    return Err(HubError::State(
                        "registry stale challenge requires begin-challenge mode".into(),
                    ));
                }
            }
            #[cfg(not(feature = "local-pilot-tools"))]
            return Err(HubError::Admission(
                "Local Pilot tools are not compiled into this Hub".into(),
            ));
        }
        let _guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        if let Some(existing) = self.load_hvm_registry_chain_operation(&request.operation_id)? {
            if existing.request_commitment != request_commitment {
                return Err(HubError::State(
                    "registry watchtower retry changed the durable request".into(),
                ));
            }
            self.require_exact_registry_challenge_variant(&existing, local_pilot_stale_challenge)?;
            if !existing.status.is_resolved() {
                self.ensure_hvm_registry_chain_reconciliation_allowed(&existing)?;
            }
            return self.resume_hvm_registry_chain_operation(existing).await;
        }
        self.ensure_settlement_ready()?;
        let (activation, latest) =
            self.registry_chain_context(&request.binding_commitment, &request.idempotency_key)?;
        // The node's own tip, read before its registry view. `observed_height`
        // used to be taken on trust; every deadline decision below rests on
        // it, so it is cross-checked against the tip and against the clock
        // before it is allowed to mean anything.
        let capabilities = self.node.capabilities().await?;
        let snapshot = self
            .node
            .verify_hvm_registry_runtime_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        require_fresh_registry_evidence(
            &snapshot,
            capabilities.height,
            capabilities.tip_age_seconds,
        )?;
        let challenge_bill = if local_pilot_stale_challenge {
            let initial = &activation.recovery_bundle.initial_recovery_bill;
            initial.validate_fully_signed(&activation.recovery_bundle.binding)?;
            if initial.serial != 1 || latest.serial <= initial.serial {
                return Err(HubError::State(
                    "registry stale challenge requires a newer durable bill".into(),
                ));
            }
            initial
        } else {
            &latest
        };
        let mut claim: Option<(String, u64)> = None;
        let (kind, bill, source) = match request.mode {
            HvmRegistryWatchtowerModeV2::BeginChallenge if snapshot.channel.status.value == 2 => (
                HvmChainOperationKind::Challenge,
                Some(challenge_bill.clone()),
                registry_challenge_call_source(
                    &activation.recovery_bundle.binding,
                    challenge_bill,
                )?,
            ),
            HvmRegistryWatchtowerModeV2::BeginChallenge => {
                return Err(HubError::State(
                    "registry channel is not open for a new challenge".into(),
                ));
            }
            HvmRegistryWatchtowerModeV2::Monitor => {
                match decide_registry_watchtower_action(
                    &snapshot,
                    &activation.recovery_bundle.binding,
                    &latest,
                )? {
                    HvmRegistryWatchtowerDecisionV2::NoAction => {
                        return Ok(no_registry_action_response(&request.operation_id));
                    }
                    HvmRegistryWatchtowerDecisionV2::RecoveryRequired => {
                        return Err(HubError::State(
                            "RecoveryRequired: registry chain state is newer or invalid".into(),
                        ));
                    }
                    // Enough of the challenge window left to build, sign,
                    // submit and still be mined before `respond` closes.
                    HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill
                        if registry_response_window_is_safe(&snapshot) =>
                    {
                        (
                            HvmChainOperationKind::Respond,
                            Some(latest.clone()),
                            registry_respond_call_source(
                                &activation.recovery_bundle.binding,
                                &latest,
                            )?,
                        )
                    }
                    // Not enough. Attempting anyway spends a fee on a
                    // transaction the contract will refuse for being late, and
                    // leaves the stale split standing for anyone to finalise.
                    // Escalate to the RecoveryRequired latch instead, and never
                    // touch the key.
                    HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill => {
                        return Err(self.escalate_registry_response_window(&snapshot));
                    }
                    HvmRegistryWatchtowerDecisionV2::Finalize => (
                        HvmChainOperationKind::Finalize,
                        None,
                        registry_finalize_call_source(&activation.recovery_bundle.binding)?,
                    ),
                    HvmRegistryWatchtowerDecisionV2::ClaimLeftPayout => {
                        // The payout amount is read straight off the live
                        // contract storage, never inferred: `PermitHAC`
                        // rejects anything that is not exactly
                        // `c_left_balance_`.
                        claim = Some((
                            activation.recovery_bundle.binding.left_address.clone(),
                            snapshot.channel.left_balance.value,
                        ));
                        let (payee, amount_zhu) = claim.as_ref().expect("just set");
                        (
                            HvmChainOperationKind::Claim,
                            None,
                            registry_claim_payout_source(
                                &activation.recovery_bundle.binding,
                                payee,
                                *amount_zhu,
                            )?,
                        )
                    }
                }
            }
        };
        let operation = new_registry_chain_operation(
            request.operation_id,
            request.idempotency_key,
            request_commitment,
            request.binding_commitment,
            kind,
            bill,
            None,
            claim,
            &snapshot,
            request.network_fee_zhu,
            request.timestamp,
            request.gas_max,
            source,
            request.created_unix,
        );
        self.persist_hvm_registry_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainIntentPersisted,
        )?;
        self.resume_hvm_registry_chain_operation(operation).await
    }

    /// The challenge window closed below the response margin.
    ///
    /// Nothing durable is written and nothing is signed. That is deliberate,
    /// and it is forced by the durable model rather than chosen around it:
    /// `validate_hvm_state` requires every registry operation past
    /// `IntentPersisted` to carry its exact signed bytes, and an
    /// `IntentPersisted` record is not a status
    /// `persisted_state_requires_recovery` latches on — a later pass would
    /// resume it and sign exactly the response this refusal exists to prevent.
    /// So the escalation takes the shape the rest of the Hub already uses for
    /// a refusal with no signable record behind it: raise the in-process
    /// `RecoveryRequired` latch, which makes `ensure_settlement_ready` refuse
    /// every subsequent signature, and return the `RecoveryRequired:` error
    /// that names the arithmetic.
    fn escalate_registry_response_window(&self, snapshot: &HvmRegistryLiveSnapshotV2) -> HubError {
        self.recovery_required.store(true, Ordering::Release);
        HubError::State(format!(
            "RecoveryRequired: {} blocks left of the challenge window at height {}, below the {HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS}-block response margin; a response cannot land in time",
            registry_response_window_blocks(snapshot),
            snapshot.observed_height
        ))
    }

    fn require_exact_registry_challenge_variant(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
        local_pilot_stale_challenge: bool,
    ) -> HubResult<()> {
        if operation.kind != HvmChainOperationKind::Challenge {
            return Ok(());
        }
        let activation = self.registry_activation(&operation.binding_commitment)?;
        let latest = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_ledgers
            .get(&operation.binding_commitment)
            .map(|ledger| ledger.latest_fully_signed_bill.clone())
            .ok_or_else(|| HubError::State("registry ledger is missing".into()))?;
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
                        "registry stale challenge is not bound to the canonical Local Pilot".into(),
                    ));
                }
                let initial = &activation.recovery_bundle.initial_recovery_bill;
                if initial.serial != 1 || latest.serial <= initial.serial {
                    return Err(HubError::State(
                        "registry stale challenge no longer has a newer durable bill".into(),
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
        let expected_source =
            registry_challenge_call_source(&activation.recovery_bundle.binding, expected)?;
        if operation.bill.as_ref() != Some(expected) || operation.call_source != expected_source {
            return Err(HubError::State(
                "registry challenge retry selected different durable evidence".into(),
            ));
        }
        Ok(())
    }

    /// Reconstruct the exact durable registry lease-renewal request an
    /// operation was created from — the registry twin of
    /// [`Self::hvm_lease_renewal_request`].
    ///
    /// A caller that rebuilds its request on every invocation has to reproduce
    /// the original bytes exactly, or `run_hvm_registry_lease_renewal` refuses
    /// the retry for changing the durable request. Everything the commitment
    /// covers is read back from the record here, so the retry is the original
    /// request rather than a lookalike.
    ///
    /// The caller supplies the admission threshold because it is not stored
    /// separately on the record; the authenticated commitment comparison below
    /// is what proves the supplied threshold is the original one, so a config
    /// changed underneath a live operation is caught here and named, rather
    /// than surfacing later as a bare "retry changed the durable request".
    pub fn hvm_registry_lease_renewal_request(
        &self,
        operation_id: &str,
        renew_when_blocks_at_or_below: u64,
    ) -> HubResult<Option<HvmRegistryLeaseRenewalRequestV2>> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State(
                "registry chain operation id is empty".into(),
            ));
        }
        let Some(operation) = self.load_hvm_registry_chain_operation(operation_id)? else {
            return Ok(None);
        };
        if operation.kind != HvmChainOperationKind::RenewAllLeases {
            return Err(HubError::State(
                "registry chain operation id does not belong to a lease renewal".into(),
            ));
        }
        let request = HvmRegistryLeaseRenewalRequestV2 {
            schema: crate::hvm_registry_watchtower::HVM_REGISTRY_LEASE_REQUEST_SCHEMA.into(),
            operation_id: operation.operation_id,
            idempotency_key: operation.idempotency_key,
            binding_commitment: operation.binding_commitment,
            renew_when_blocks_at_or_below,
            periods: operation.lease_periods.ok_or_else(|| {
                HubError::State("durable registry lease renewal omitted its period count".into())
            })?,
            network_fee_zhu: operation.network_fee_zhu,
            timestamp: operation.transaction_timestamp,
            gas_max: operation.gas_max,
            created_unix: operation.created_unix,
        };
        request.validate()?;
        if request.commitment()? != operation.request_commitment {
            return Err(HubError::State(
                "durable registry lease renewal request commitment is inconsistent".into(),
            ));
        }
        Ok(Some(request))
    }

    pub async fn run_hvm_registry_lease_renewal(
        &self,
        request: HvmRegistryLeaseRenewalRequestV2,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        request.validate()?;
        self.require_registry_non_mainnet()?;
        let _guard = self.hvm_signing_lock.lock().await;
        let request_commitment = request.commitment()?;
        if let Some(existing) = self.load_hvm_registry_chain_operation(&request.operation_id)? {
            if existing.request_commitment != request_commitment {
                return Err(HubError::State(
                    "registry lease retry changed the durable request".into(),
                ));
            }
            if !existing.status.is_resolved() {
                self.ensure_hvm_registry_chain_reconciliation_allowed(&existing)?;
            }
            return self.resume_hvm_registry_chain_operation(existing).await;
        }
        self.ensure_settlement_ready()?;
        let (activation, _) =
            self.registry_chain_context(&request.binding_commitment, &request.idempotency_key)?;
        let snapshot = self.registry_renewal_pre_snapshot(&activation).await?;
        let bootstrap =
            activation.minimum_required_recover_blocks == 0 && snapshot.minimum_recover_blocks == 0;
        if !bootstrap
            && snapshot.minimum_live_blocks > request.renew_when_blocks_at_or_below
            && snapshot.minimum_recover_blocks > request.renew_when_blocks_at_or_below
        {
            return Ok(no_registry_action_response(&request.operation_id));
        }
        let source =
            registry_renew_all_call_source(&activation.recovery_bundle.binding, request.periods)?;
        let operation = new_registry_chain_operation(
            request.operation_id,
            request.idempotency_key,
            request_commitment,
            request.binding_commitment,
            HvmChainOperationKind::RenewAllLeases,
            None,
            Some(request.periods),
            None,
            &snapshot,
            request.network_fee_zhu,
            request.timestamp,
            request.gas_max,
            source,
            request.created_unix,
        );
        self.persist_hvm_registry_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainIntentPersisted,
        )?;
        self.resume_hvm_registry_chain_operation(operation).await
    }

    pub async fn reconcile_hvm_registry_chain_operation(
        &self,
        operation_id: &str,
        allow_exact_resubmit: bool,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State(
                "registry chain operation id is empty".into(),
            ));
        }
        let _guard = self.hvm_signing_lock.lock().await;
        let mut operation = self
            .load_hvm_registry_chain_operation(operation_id)?
            .ok_or_else(|| {
                HubError::NotFound(format!("registry chain operation {operation_id}"))
            })?;
        if operation.status == HvmChainOperationStatus::Confirmed {
            return self.reverify_confirmed_registry_anchor(operation).await;
        }
        // Terminal, and terminal ahead of every branch below — including the
        // `allow_exact_resubmit` one. The exact resubmit path exists to put
        // bytes back in front of a node; these are the bytes that must never
        // be put in front of a node again.
        if operation.status == HvmChainOperationStatus::Abandoned {
            return Ok(registry_chain_response(&operation));
        }
        self.ensure_hvm_registry_chain_reconciliation_allowed(&operation)?;
        if operation.status == HvmChainOperationStatus::SignatureMayExist {
            return self.mark_hvm_registry_chain_recovery(
                operation,
                "signature bytes are unavailable; exact reconciliation is required",
            );
        }
        if let (Some(hash), Some(body)) = (
            operation.transaction_hash.clone(),
            operation.signed_transaction_hex.clone(),
        ) {
            match self
                .query_registry_chain_transaction(&operation, &hash)
                .await
            {
                Ok(Some(observation)) => {
                    return self
                        .apply_hvm_registry_observation(operation, observation)
                        .await;
                }
                // Our claim never landed, yet the payee already holds the
                // exact amount: a permissionless third party got there first.
                // The chain of custody is complete, so this resolves rather
                // than latching recovery over an outcome that is correct.
                Ok(None)
                    if operation.kind == HvmChainOperationKind::Claim
                        && let Some(height) = self
                            .registry_claim_already_paid(
                                &operation,
                                &self.registry_activation(&operation.binding_commitment)?,
                            )
                            .await? =>
                {
                    return self.settle_registry_claim_paid_elsewhere(operation, height);
                }
                Ok(None) if !allow_exact_resubmit => {
                    operation.status = HvmChainOperationStatus::RecoveryRequired;
                    operation.last_error = Some(
                        "transaction is not observable; exact resubmit was not approved".into(),
                    );
                    self.persist_hvm_registry_chain_operation(
                        operation.clone(),
                        JournalPhase::HvmChainRecoveryRequired,
                    )?;
                    return Ok(registry_chain_response(&operation));
                }
                Ok(None) => {
                    let activation = self.registry_activation(&operation.binding_commitment)?;
                    self.verify_hvm_registry_operation_precondition(&operation, &activation)
                        .await?;
                    operation.status = HvmChainOperationStatus::SubmissionStarted;
                    operation.last_error = None;
                    self.persist_hvm_registry_chain_operation(
                        operation.clone(),
                        JournalPhase::HvmChainSubmissionStarted,
                    )?;
                    if let Err(error) = self
                        .node
                        .submit_hvm_registry_transaction_bound(
                            &body,
                            &hash,
                            &activation.recovery_bundle.binding,
                        )
                        .await
                    {
                        return self
                            .mark_hvm_registry_chain_recovery(operation, &error.to_string());
                    }
                    operation.status = HvmChainOperationStatus::Submitted;
                    operation.submitted_unix = Some(crate::node::now_unix());
                    self.persist_hvm_registry_chain_operation(
                        operation.clone(),
                        JournalPhase::HvmChainSubmitted,
                    )?;
                    return Ok(registry_chain_response(&operation));
                }
                Err(error) => {
                    return self.mark_hvm_registry_chain_recovery(operation, &error.to_string());
                }
            }
        }
        if operation.status == HvmChainOperationStatus::IntentPersisted {
            return self.resume_hvm_registry_chain_operation(operation).await;
        }
        self.mark_hvm_registry_chain_recovery(
            operation,
            "durable registry chain operation lost exact signed bytes",
        )
    }

    /// Retire a durable registry chain operation whose exact signed
    /// transaction provably cannot have executed.
    ///
    /// # The hazard
    ///
    /// A signed transaction the Hub cannot account for is why
    /// `RecoveryRequired` latches: until its fate is known, signing anything
    /// else risks two live transactions for one intent. Abandoning such a
    /// record so a replacement can be signed is therefore the most dangerous
    /// transition here. Abandoning one that *did* execute means the
    /// replacement double-submits.
    ///
    /// # Why this is safe
    ///
    /// It never rests on "we did not observe it", which only ever says where
    /// the Hub looked. It rests on two independent things, in this order:
    ///
    /// 1. **A consensus proof.** [`crate::inadmissible`] must show the exact
    ///    stored bytes are refused by a rule that *block verification* itself
    ///    applies — not merely by the submission path. Satisfying such a rule
    ///    excludes the transaction from every valid block, rather than from
    ///    one node's relay. Today that is the timestamp rule
    ///    (`chain/src/check.rs:103` and `chain/src/verify.rs:75`). Without a
    ///    proof this method returns an error and changes nothing. There is no
    ///    flag, and no profile, that skips it.
    /// 2. **A final look.** The transaction is read from the chain once more
    ///    and required to be absent. The proof says it cannot be there; this
    ///    says it is not. Anything the node reports — the transaction, or an
    ///    error — refuses the abandonment.
    ///
    /// It also refuses unless this one record is the only thing holding the
    /// recovery latch up, so the transition releases exactly the latch its own
    /// evidence covers and never quietly clears somebody else's.
    ///
    /// The result is terminal: `Abandoned` is never resumed, never
    /// reconciled and never resubmitted, not even under `allow_exact_resubmit`.
    pub async fn abandon_inadmissible_hvm_registry_chain_operation(
        &self,
        operation_id: &str,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        if operation_id.trim().is_empty() {
            return Err(HubError::State(
                "registry chain operation id is empty".into(),
            ));
        }
        self.require_registry_non_mainnet()?;
        let _guard = self.hvm_signing_lock.lock().await;
        let mut operation = self
            .load_hvm_registry_chain_operation(operation_id)?
            .ok_or_else(|| {
                HubError::NotFound(format!("registry chain operation {operation_id}"))
            })?;
        // Already terminal, and already carrying its proof. Re-proving would
        // reach the node for an answer the durable record already holds.
        if operation.status == HvmChainOperationStatus::Abandoned {
            return Ok(registry_chain_response(&operation));
        }
        // Every other status is either still driveable — in which case
        // reconciliation, not abandonment, is the answer — or `Confirmed`,
        // which executed. Only a record that has already failed into recovery
        // has nothing left to try.
        if operation.status != HvmChainOperationStatus::RecoveryRequired {
            return Err(HubError::State(format!(
                "only a Recovery Required registry chain operation can be abandoned; {operation_id} is {}",
                operation.status.as_str()
            )));
        }
        let (Some(body), Some(hash)) = (
            operation.signed_transaction_hex.clone(),
            operation.transaction_hash.clone(),
        ) else {
            return Err(HubError::State(
                "abandonment needs the exact signed bytes whose inadmissibility it proves".into(),
            ));
        };
        self.ensure_registry_abandon_releases_only_this_operation(&operation)?;
        self.ensure_durable_storage_ready()?;

        let activation = self.registry_activation(&operation.binding_commitment)?;
        let capabilities = self.node.capabilities().await?;
        // Tip evidence from some other chain proves nothing about this one.
        self.require_registry_capabilities_bound(&capabilities, &activation)?;

        // 1. The proof. Nothing durable has changed yet, and nothing will if
        //    this refuses.
        let proof =
            crate::inadmissible::prove_transaction_inadmissible(&body, &hash, &capabilities)?;

        // 2. The final look. A transaction the proof says cannot be in a block
        //    must also not be in one.
        match self
            .query_registry_chain_transaction(&operation, &hash)
            .await
        {
            Ok(None) => {}
            Ok(Some(observation)) => {
                return Err(HubError::State(format!(
                    "registry chain operation {operation_id} is observable on chain at block {:?} despite {}; it must be reconciled, never abandoned",
                    observation.block_height, proof.detail
                )));
            }
            Err(error) => {
                return Err(HubError::Node(format!(
                    "the chain could not be read for a final absence check, so nothing may be abandoned: {error}"
                )));
            }
        }

        let now = crate::node::now_unix();
        operation.status = HvmChainOperationStatus::Abandoned;
        operation.abandoned = Some(crate::storage::PersistedHvmChainAbandonment {
            rule: proof.rule.as_str().into(),
            detail: proof.detail,
            transaction_timestamp: proof.transaction_timestamp,
            chain_tip_timestamp_unix: proof.tip.tip_timestamp_unix,
            observed_unix: proof.tip.observed_unix,
            proof_height: proof.tip.observed_height,
            absent_at_height: capabilities.height,
            abandoned_unix: now,
        });
        // `last_error` is left exactly as it was. It records why the operation
        // failed into recovery in the first place, and that history is part of
        // what makes the abandonment auditable.
        operation.updated_unix = now;
        self.persist_hvm_registry_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainAbandonedInadmissible,
        )?;
        Ok(registry_chain_response(&operation))
    }

    /// Refuse unless this exact record is the only thing latching recovery.
    ///
    /// `persist_hvm_registry_chain_operation` recomputes the in-process gate
    /// from durable state, so abandoning one record would also drop a latch
    /// raised by some unrelated one. Removing the target from a copy of the
    /// state and requiring the remainder to be clean is what keeps the
    /// transition's reach equal to its evidence.
    fn ensure_registry_abandon_releases_only_this_operation(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
    ) -> HubResult<()> {
        let mut without_target = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .clone();
        let removed = without_target
            .hvm_registry_chain_operations
            .remove(&operation.operation_id)
            .ok_or_else(|| HubError::State("registry chain operation disappeared".into()))?;
        if removed != *operation {
            return Err(HubError::State(
                "registry chain operation changed while it was being abandoned".into(),
            ));
        }
        if super::persisted_state_requires_recovery(&without_target) {
            return Err(HubError::State(
                "another durable record still requires recovery, so abandoning this one would release a latch its proof does not cover".into(),
            ));
        }
        Ok(())
    }

    /// The tip reading a proof rests on has to come from the exact chain this
    /// channel lives on.
    fn require_registry_capabilities_bound(
        &self,
        capabilities: &crate::node::FullnodeCapabilitiesV1,
        activation: &PersistedHvmRegistryActivation,
    ) -> HubResult<()> {
        let binding = &activation.recovery_bundle.binding;
        if capabilities.mainnet != (binding.network_mode == "mainnet")
            || capabilities.chain_id != binding.chain_id
            || capabilities.network_instance_id.as_deref()
                != Some(binding.network_instance_id.as_str())
            || capabilities.height < binding.deployment_height
        {
            return Err(HubError::Node(
                "chain tip evidence is not from the exact chain this registry channel is bound to"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Re-check the block anchor of an operation that already latched
    /// `Confirmed`.
    ///
    /// Six confirmations are a strong assumption, not a proof. A deep reorg
    /// after the latch moves the transaction to a different block, or removes
    /// it entirely, and the durable record would otherwise keep asserting a
    /// finality that no longer exists. Re-reading here is what makes that
    /// detectable.
    ///
    /// A transient node failure is reported as an error and never latches
    /// recovery: an unreachable node is not evidence of a reorg.
    async fn reverify_confirmed_registry_anchor(
        &self,
        operation: PersistedHvmRegistryChainOperation,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        // A claim settled by somebody else's payout owns no block, so there is
        // no anchor of ours to re-check. Its evidence is the contract's own
        // `c_left_claimed_` marker, which no reorg can quietly reinterpret
        // without also reverting the settlement itself.
        if operation.claim_settled_elsewhere_height.is_some() {
            return Ok(registry_chain_response(&operation));
        }
        let Some(hash) = operation.transaction_hash.clone() else {
            return Ok(registry_chain_response(&operation));
        };
        match self
            .query_registry_chain_transaction(&operation, &hash)
            .await
        {
            Ok(Some(observation)) => {
                self.apply_hvm_registry_observation(operation, observation)
                    .await
            }
            Ok(None) => self.mark_hvm_registry_chain_recovery(
                operation,
                "confirmed registry transaction is no longer on chain: reorg",
            ),
            Err(error) => Err(error),
        }
    }

    /// Both clock fields already committed for this operation, as
    /// `(transaction_timestamp, created_unix)`.
    ///
    /// A caller that rebuilds its request on every invocation has to reproduce
    /// the original values exactly, or the Hub refuses the retry for changing
    /// the durable request. Reading the committed values back is what lets
    /// that request carry a real clock reading instead of a synthetic one:
    /// `chain::check` on the fullnode rejects outright any transaction whose
    /// timestamp exceeds the node's own clock, so a timestamp invented to be
    /// stable rather than read is a transaction that may never be accepted.
    ///
    /// Both are returned together, and deliberately so. The request commitment
    /// covers `timestamp` and `created_unix` as two independent fields, and
    /// nothing constrains a writer to set them equal. A caller handed only one
    /// of them would have to guess the other, and would rebuild a request that
    /// merely resembles the original the moment any writer set them apart.
    pub fn hvm_registry_chain_operation_request_clock(
        &self,
        operation_id: &str,
    ) -> HubResult<Option<(u64, u64)>> {
        Ok(self
            .load_hvm_registry_chain_operation(operation_id)?
            .map(|operation| (operation.transaction_timestamp, operation.created_unix)))
    }

    pub fn hvm_registry_chain_operation_status(
        &self,
        operation_id: &str,
    ) -> HubResult<Option<HvmRegistryChainResponseV2>> {
        Ok(self
            .load_hvm_registry_chain_operation(operation_id)?
            .as_ref()
            .map(registry_chain_response))
    }

    fn ensure_hvm_registry_chain_reconciliation_allowed(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
    ) -> HubResult<()> {
        if !self.recovery_required.load(Ordering::Acquire) {
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
            .hvm_registry_chain_operations
            .remove(&operation.operation_id)
            .ok_or_else(|| HubError::State("RecoveryRequired".into()))?;
        if removed != *operation || super::persisted_state_requires_recovery(&without_target) {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        self.ensure_durable_storage_ready()
    }

    async fn resume_hvm_registry_chain_operation(
        &self,
        mut operation: PersistedHvmRegistryChainOperation,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        // `Abandoned` lands here through `is_resolved`. Its bytes were proven
        // inadmissible and observed absent; resuming would mean signing or
        // submitting them again, which is the one thing the transition
        // promises never happens.
        if operation.status.is_resolved()
            || operation.status == HvmChainOperationStatus::RecoveryRequired
        {
            return Ok(registry_chain_response(&operation));
        }
        if operation.status == HvmChainOperationStatus::IntentPersisted {
            let activation = self.registry_activation(&operation.binding_commitment)?;
            // Somebody else may have already paid the payee between the intent
            // being written and this resume. Signing a second payout would
            // burn a fee on a transaction the contract is guaranteed to
            // reject, so check before touching the key.
            if let Some(height) = self
                .registry_claim_already_paid(&operation, &activation)
                .await?
            {
                return self.settle_registry_claim_paid_elsewhere(operation, height);
            }
            self.verify_hvm_registry_operation_precondition(&operation, &activation)
                .await?;
            operation.status = HvmChainOperationStatus::SignatureMayExist;
            operation.updated_unix = crate::node::now_unix();
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSignatureMayExist,
            )?;
            let signed = self.sign_registry_chain_operation(&operation, &activation)?;
            operation.signed_transaction_hex = Some(signed.signed_transaction_hex);
            operation.transaction_hash = Some(signed.transaction_hash);
            operation.status = HvmChainOperationStatus::Signed;
            operation.last_error = None;
            operation.updated_unix = crate::node::now_unix();
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSigned,
            )?;
        }
        if operation.status == HvmChainOperationStatus::SignatureMayExist {
            return self.mark_hvm_registry_chain_recovery(
                operation,
                "signature bytes unavailable after restart",
            );
        }
        if operation.status == HvmChainOperationStatus::Signed {
            let hash = operation.transaction_hash.clone().unwrap_or_default();
            if let Some(observation) = self
                .query_registry_chain_transaction(&operation, &hash)
                .await?
            {
                return self
                    .apply_hvm_registry_observation(operation, observation)
                    .await;
            }
            let activation = self.registry_activation(&operation.binding_commitment)?;
            // Our own transaction is not on chain. If the payout nevertheless
            // already happened, a third party made it: the coin is with the
            // payee, and submitting would only pay a fee for a certain
            // rejection.
            if let Some(height) = self
                .registry_claim_already_paid(&operation, &activation)
                .await?
            {
                return self.settle_registry_claim_paid_elsewhere(operation, height);
            }
            if let Err(error) = self
                .verify_hvm_registry_operation_precondition(&operation, &activation)
                .await
            {
                return self.mark_hvm_registry_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::SubmissionStarted;
            operation.updated_unix = crate::node::now_unix();
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSubmissionStarted,
            )?;
        }
        if operation.status == HvmChainOperationStatus::SubmissionStarted {
            let body = operation.signed_transaction_hex.clone().unwrap_or_default();
            let hash = operation.transaction_hash.clone().unwrap_or_default();
            let activation = self.registry_activation(&operation.binding_commitment)?;
            if let Err(error) = self
                .node
                .submit_hvm_registry_transaction_bound(
                    &body,
                    &hash,
                    &activation.recovery_bundle.binding,
                )
                .await
            {
                return self.mark_hvm_registry_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::Submitted;
            operation.submitted_unix = Some(crate::node::now_unix());
            operation.updated_unix = crate::node::now_unix();
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSubmitted,
            )?;
        }
        let hash = operation.transaction_hash.clone().unwrap_or_default();
        match self
            .query_registry_chain_transaction(&operation, &hash)
            .await
        {
            Ok(Some(observation)) => {
                self.apply_hvm_registry_observation(operation, observation)
                    .await
            }
            Ok(None) if operation.confirmed_block_height.is_some() => self
                .mark_hvm_registry_chain_recovery(
                    operation,
                    "previously observed registry transaction disappeared before finality",
                ),
            Ok(None) if operation.kind == HvmChainOperationKind::Claim => {
                let activation = self.registry_activation(&operation.binding_commitment)?;
                match self
                    .registry_claim_already_paid(&operation, &activation)
                    .await?
                {
                    Some(height) => self.settle_registry_claim_paid_elsewhere(operation, height),
                    None => Ok(registry_chain_response(&operation)),
                }
            }
            Ok(None) => Ok(registry_chain_response(&operation)),
            Err(error) => self.mark_hvm_registry_chain_recovery(operation, &error.to_string()),
        }
    }

    /// Produce the exact signed transaction this operation's kind calls for.
    /// A claim is an Action 14 payout with no fitsh source to compile; every
    /// other kind is an Action 44 contract call. The durable `call_source` is
    /// the canonical descriptor in both cases and is re-derived, never trusted
    /// as free text.
    fn sign_registry_chain_operation(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
        activation: &PersistedHvmRegistryActivation,
    ) -> HubResult<crate::hvm_registry_watchtower::SignedHvmRegistryCallTransactionV2> {
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer unavailable".into()))?
            .account();
        let binding = &activation.recovery_bundle.binding;
        if operation.kind == HvmChainOperationKind::Claim {
            let (payee, amount_zhu) = registry_claim_terms(operation)?;
            if registry_claim_payout_source(binding, payee, amount_zhu)? != operation.call_source {
                return Err(HubError::State(
                    "registry claim payout descriptor is not canonical".into(),
                ));
            }
            let signed = build_signed_hvm_registry_claim_transaction(
                signer,
                binding,
                payee,
                amount_zhu,
                operation.network_fee_zhu,
                operation.transaction_timestamp,
                operation.gas_max,
            )?;
            read_exact_registry_claim_transaction(
                &signed.signed_transaction_hex,
                binding,
                payee,
                amount_zhu,
            )?;
            return Ok(signed);
        }
        build_signed_hvm_registry_call_transaction(
            signer,
            binding,
            operation.call_source.clone(),
            operation.network_fee_zhu,
            operation.transaction_timestamp,
            operation.gas_max,
        )
    }

    async fn verify_hvm_registry_operation_precondition(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
        activation: &PersistedHvmRegistryActivation,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        let snapshot = if operation.kind == HvmChainOperationKind::RenewAllLeases {
            self.registry_renewal_pre_snapshot(activation).await?
        } else {
            self.node
                .verify_hvm_registry_runtime_bundle(
                    &activation.recovery_bundle,
                    activation.minimum_required_live_blocks,
                    activation.minimum_required_recover_blocks.max(1),
                )
                .await?
        };
        if snapshot.channel.status.value != operation.pre_status
            || snapshot.channel.serial.value != operation.pre_serial
            || snapshot.channel.left_balance.value != operation.pre_left_balance_zhu
            || snapshot.channel.hub_balance.value != operation.pre_hub_balance_zhu
            || snapshot.channel.deadline.value != operation.pre_deadline
        {
            return Err(HubError::State(
                "registry contract state changed before key use or submission".into(),
            ));
        }
        match operation.kind {
            HvmChainOperationKind::Challenge => {
                let bill = operation.bill.as_ref().ok_or_else(|| {
                    HubError::State("registry challenge lost its exact bill".into())
                })?;
                if snapshot.channel.status.value != 2
                    || snapshot.channel.deadline.value != 0
                    || bill.serial < snapshot.channel.serial.value
                {
                    return Err(HubError::State(
                        "registry challenge precondition is no longer true".into(),
                    ));
                }
            }
            HvmChainOperationKind::Respond => {
                let bill = operation.bill.as_ref().ok_or_else(|| {
                    HubError::State("registry response lost its exact bill".into())
                })?;
                if snapshot.channel.status.value != 3
                    || snapshot.observed_height >= snapshot.channel.deadline.value
                    || bill.serial <= snapshot.channel.serial.value
                {
                    return Err(HubError::State(
                        "registry response precondition is no longer true".into(),
                    ));
                }
            }
            HvmChainOperationKind::Finalize => {
                if snapshot.channel.status.value != 3
                    || snapshot.observed_height < snapshot.channel.deadline.value
                {
                    return Err(HubError::State(
                        "registry finalize precondition is no longer true".into(),
                    ));
                }
            }
            HvmChainOperationKind::RenewAllLeases => {}
            HvmChainOperationKind::Claim => {
                let (payee, amount_zhu) = registry_claim_terms(operation)?;
                // `PermitHAC` pays the left party only from FINAL state, only
                // once, and only the exact `c_left_balance_`. Every one of
                // those is re-read here, against live evidence, immediately
                // before the key is used and again before submission.
                if snapshot.channel.status.value != 4
                    || snapshot.channel.left_claimed.value
                    || snapshot.channel.left_balance.value != amount_zhu
                    || amount_zhu == 0
                    || snapshot.left_address != payee
                {
                    return Err(HubError::State(
                        "registry claim precondition is no longer true".into(),
                    ));
                }
            }
        }
        Ok(snapshot)
    }

    /// Has the exact approved payout already been recorded on chain?
    ///
    /// Claims are permissionless: `intrinsic_req_sign` never adds the contract
    /// (it is not `is_privakey()`), so anybody willing to pay the fee can
    /// trigger the payout. When they do, the contract sets `c_left_claimed_`
    /// and the money has already reached the payee. Answering "yes" here is
    /// what stops this Hub from chasing a payout that has happened.
    ///
    /// The answer is deliberately narrow. `settle()` also sets
    /// `c_left_claimed_` when the left balance is zero, so the exact amount is
    /// compared too, and a zero amount is never treated as settled.
    async fn registry_claim_already_paid(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
        activation: &PersistedHvmRegistryActivation,
    ) -> HubResult<Option<u64>> {
        if operation.kind != HvmChainOperationKind::Claim {
            return Ok(None);
        }
        let (payee, amount_zhu) = registry_claim_terms(operation)?;
        let snapshot = self
            .node
            .verify_hvm_registry_runtime_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        let settled = snapshot.channel.status.value == 4
            && snapshot.channel.left_claimed.value
            && amount_zhu > 0
            && snapshot.channel.left_balance.value == amount_zhu
            && snapshot.left_address == payee;
        Ok(settled.then_some(snapshot.observed_height))
    }

    /// Resolve a claim whose payout already happened without us. There is no
    /// transaction of ours to anchor, so none is invented: the durable record
    /// keeps the observed height as its evidence and stays free of block
    /// finality fields it does not own.
    fn settle_registry_claim_paid_elsewhere(
        &self,
        mut operation: PersistedHvmRegistryChainOperation,
        observed_height: u64,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        if operation.kind != HvmChainOperationKind::Claim || observed_height == 0 {
            return Err(HubError::State(
                "only a registry claim can settle on a third-party payout".into(),
            ));
        }
        operation.claim_settled_elsewhere_height = Some(observed_height);
        operation.confirmed_block_height = None;
        operation.confirmed_block_hash = None;
        operation.observed_confirmations = 0;
        operation.status = HvmChainOperationStatus::Confirmed;
        operation.last_error = None;
        operation.updated_unix = crate::node::now_unix();
        self.persist_hvm_registry_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainConfirmed,
        )?;
        Ok(registry_chain_response(&operation))
    }

    /// A claim is observed through its Action 14 proof; every other kind is
    /// observed through its Action 44 proof. Neither is loosened for the other.
    async fn query_registry_chain_transaction(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
        transaction_hash: &str,
    ) -> HubResult<Option<TransactionObservation>> {
        if operation.kind == HvmChainOperationKind::Claim {
            self.node
                .query_hvm_registry_claim_transaction(transaction_hash)
                .await
        } else {
            self.node
                .query_hvm_registry_call_transaction(transaction_hash)
                .await
        }
    }

    async fn apply_hvm_registry_observation(
        &self,
        mut operation: PersistedHvmRegistryChainOperation,
        observation: TransactionObservation,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        let expected_body = operation
            .signed_transaction_hex
            .as_deref()
            .unwrap_or_default();
        let expected_hash = operation.transaction_hash.as_deref().unwrap_or_default();
        if observation.hash != expected_hash || observation.body_hex != expected_body {
            return self.mark_hvm_registry_chain_recovery(
                operation,
                "registry transaction observation does not match exact durable bytes",
            );
        }
        // Reorg anchoring, carried over from the Local Pilot journal.
        //
        // A confirmation is only evidence if it names the exact block it lives
        // in. Height alone is not enough: a competing block at the same height
        // is a different history. Without both halves a reorg after the
        // six-confirmation latch leaves a durable record still asserting
        // finality in a block that no longer exists.
        if !observation.pending {
            let Some(height) = observation.block_height.filter(|height| *height > 0) else {
                return self.mark_hvm_registry_chain_recovery(
                    operation,
                    "registry confirmation lacks an exact canonical block anchor",
                );
            };
            let anchor = observation
                .block_hash
                .as_deref()
                .map(str::to_ascii_lowercase)
                .filter(|anchor| is_canonical_block_anchor(anchor));
            let Some(anchor) = anchor else {
                return self.mark_hvm_registry_chain_recovery(
                    operation,
                    "registry confirmation lacks an exact canonical block anchor",
                );
            };
            // Records written before anchoring existed carry a height but no
            // hash. They are treated as legacy unanchored: the height still
            // has to agree, and the hash is adopted rather than compared.
            if let Some(previous_height) = operation.confirmed_block_height {
                let legacy_unanchored = operation.confirmed_block_hash.is_none();
                let moved = previous_height != height
                    || (!legacy_unanchored
                        && operation.confirmed_block_hash.as_deref() != Some(anchor.as_str()));
                if moved {
                    return self.mark_hvm_registry_chain_recovery(
                        operation,
                        "registry transaction moved to a different block: reorg",
                    );
                }
            }
            operation.confirmed_block_hash = Some(anchor);
        }
        operation.confirmed_block_height = observation.block_height;
        operation.observed_confirmations = observation.confirmations;
        operation.updated_unix = crate::node::now_unix();
        if observation.confirmations >= 6 {
            if let Err(error) = self.verify_hvm_registry_postcondition(&operation).await {
                return self.mark_hvm_registry_chain_recovery(operation, &error.to_string());
            }
            operation.status = HvmChainOperationStatus::Confirmed;
            operation.last_error = None;
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainConfirmed,
            )?;
        } else {
            operation.status = HvmChainOperationStatus::Submitted;
            self.persist_hvm_registry_chain_operation(
                operation.clone(),
                JournalPhase::HvmChainSubmitted,
            )?;
        }
        Ok(registry_chain_response(&operation))
    }

    async fn verify_hvm_registry_postcondition(
        &self,
        operation: &PersistedHvmRegistryChainOperation,
    ) -> HubResult<()> {
        let activation = self.registry_activation(&operation.binding_commitment)?;
        let snapshot = self
            .node
            .verify_hvm_registry_runtime_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks.max(1),
            )
            .await?;
        match operation.kind {
            HvmChainOperationKind::Challenge => {
                let bill = operation.bill.as_ref().unwrap();
                require_registry_bill_state(&snapshot, 3, bill)?;
                if snapshot.channel.deadline.value <= operation.pre_observed_height {
                    return Err(HubError::State(
                        "confirmed registry challenge has no future deadline".into(),
                    ));
                }
            }
            HvmChainOperationKind::Respond => {
                let bill = operation.bill.as_ref().unwrap();
                require_registry_bill_state(&snapshot, 3, bill)?;
                if snapshot.channel.deadline.value != operation.pre_deadline {
                    return Err(HubError::State(
                        "registry response changed the challenge deadline".into(),
                    ));
                }
            }
            HvmChainOperationKind::Finalize => {
                if snapshot.channel.status.value != 4
                    || snapshot.channel.serial.value != operation.pre_serial
                    || snapshot.channel.left_balance.value != operation.pre_left_balance_zhu
                    || snapshot.channel.hub_balance.value != operation.pre_hub_balance_zhu
                {
                    return Err(HubError::State(
                        "confirmed registry finalize has the wrong settlement state".into(),
                    ));
                }
            }
            HvmChainOperationKind::RenewAllLeases => {
                if snapshot.minimum_live_blocks <= operation.pre_minimum_live_blocks
                    || snapshot.minimum_recover_blocks <= operation.pre_minimum_recover_blocks
                    || snapshot.minimum_recover_blocks == 0
                {
                    return Err(HubError::State(
                        "confirmed registry renewal did not increase all 18 lease credits".into(),
                    ));
                }
            }
            HvmChainOperationKind::Claim => {
                let (payee, amount_zhu) = registry_claim_terms(operation)?;
                // The contract's own single-shot marker is the proof the coin
                // left. `c_left_balance_` is untouched by `PermitHAC`, so it
                // still states the exact amount that was paid, and it must
                // still be the amount we approved. The settlement state itself
                // must not have moved.
                //
                // `g_left_claimable` is deliberately not compared: it is a
                // pooled counter across every channel of this registry, so a
                // concurrent claim elsewhere would move it for reasons that
                // have nothing to do with this payout.
                if !snapshot.channel.left_claimed.value
                    || snapshot.channel.left_balance.value != amount_zhu
                    || snapshot.left_address != payee
                    || snapshot.channel.status.value != 4
                    || snapshot.channel.serial.value != operation.pre_serial
                    || snapshot.channel.hub_balance.value != operation.pre_hub_balance_zhu
                {
                    return Err(HubError::State(
                        "confirmed registry claim did not record the exact payout".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn registry_renewal_pre_snapshot(
        &self,
        activation: &PersistedHvmRegistryActivation,
    ) -> HubResult<HvmRegistryLiveSnapshotV2> {
        if activation.minimum_required_recover_blocks == 0 {
            if let Ok(snapshot) = self
                .node
                .verify_hvm_registry_runtime_bundle(
                    &activation.recovery_bundle,
                    activation.minimum_required_live_blocks,
                    1,
                )
                .await
            {
                return Ok(snapshot);
            }
            return self
                .node
                .verify_hvm_registry_initial_bundle(
                    &activation.recovery_bundle,
                    activation.minimum_required_live_blocks,
                )
                .await;
        }
        self.node
            .verify_hvm_registry_runtime_bundle(
                &activation.recovery_bundle,
                activation.minimum_required_live_blocks,
                activation.minimum_required_recover_blocks,
            )
            .await
    }

    fn registry_chain_context(
        &self,
        binding_commitment: &str,
        idempotency_key: &str,
    ) -> HubResult<(PersistedHvmRegistryActivation, HvmRegistryBillV2)> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        if guard
            .hvm_chain_operations
            .values()
            .any(|operation| operation.idempotency_key == idempotency_key)
            || guard
                .hvm_registry_chain_operations
                .values()
                .any(|operation| {
                    operation.idempotency_key == idempotency_key
                        || (operation.binding_commitment == binding_commitment
                            && !operation.status.is_resolved())
                })
        {
            return Err(HubError::State(
                "registry channel already has an unresolved chain operation".into(),
            ));
        }
        let activation = guard
            .hvm_registry_activations
            .get(binding_commitment)
            .cloned()
            .ok_or_else(|| HubError::NotFound("HVM registry activation".into()))?;
        let latest = guard
            .hvm_registry_ledgers
            .get(binding_commitment)
            .map(|ledger| ledger.latest_fully_signed_bill.clone())
            .ok_or_else(|| HubError::State("HVM registry ledger is missing".into()))?;
        Ok((activation, latest))
    }

    fn registry_activation(
        &self,
        binding_commitment: &str,
    ) -> HubResult<PersistedHvmRegistryActivation> {
        self.inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_activations
            .get(binding_commitment)
            .cloned()
            .ok_or_else(|| HubError::NotFound("HVM registry activation".into()))
    }

    fn load_hvm_registry_chain_operation(
        &self,
        operation_id: &str,
    ) -> HubResult<Option<PersistedHvmRegistryChainOperation>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .hvm_registry_chain_operations
            .get(operation_id)
            .cloned())
    }

    fn persist_hvm_registry_chain_operation(
        &self,
        operation: PersistedHvmRegistryChainOperation,
        phase: JournalPhase,
    ) -> HubResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next = guard.clone();
        next.hvm_registry_chain_operations
            .insert(operation.operation_id.clone(), operation.clone());
        validate_hvm_state(&next)?;
        let activation = next
            .hvm_registry_activations
            .get(&operation.binding_commitment)
            .ok_or_else(|| HubError::State("registry activation disappeared".into()))?;
        let binding = &activation.recovery_bundle.binding;
        let event = JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.clone(),
            channel_id: binding.channel_id.clone(),
            channel_reuse_version: u64::from(binding.reuse_version),
            operation_id: operation.operation_id.clone(),
            operation_type: if operation.kind == HvmChainOperationKind::RenewAllLeases {
                JournalOperationType::HvmLeaseRenewal
            } else {
                JournalOperationType::HvmWatchtower
            },
            operation_phase: phase,
            amount_units: operation.network_fee_zhu,
            sender: self.hub_address.clone(),
            recipient: binding.contract_address.clone(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: operation.bill.as_ref().map(|bill| bill.serial),
            unsigned_state_commitment: Some(operation.call_source_commitment.clone()),
            created_at: operation.updated_unix,
        };
        self.commit_authenticated_state(&mut guard, next, event)?;
        self.refresh_recovery_gate(&guard);
        Ok(())
    }

    fn mark_hvm_registry_chain_recovery(
        &self,
        mut operation: PersistedHvmRegistryChainOperation,
        error: &str,
    ) -> HubResult<HvmRegistryChainResponseV2> {
        operation.status = HvmChainOperationStatus::RecoveryRequired;
        operation.last_error = Some(error.into());
        operation.updated_unix = crate::node::now_unix();
        self.persist_hvm_registry_chain_operation(
            operation.clone(),
            JournalPhase::HvmChainRecoveryRequired,
        )?;
        self.recovery_required.store(true, Ordering::Release);
        Ok(registry_chain_response(&operation))
    }

    fn require_registry_non_mainnet(&self) -> HubResult<()> {
        if crate::readiness::is_mainnet_pilot_profile(&self.deployment_profile) {
            return Err(HubError::Admission(
                "shared HVM registry chain execution is not enabled for mainnet".into(),
            ));
        }
        Ok(())
    }
}

/// Rebuild the exact request a durable operation was created from.
///
/// `HvmRegistryWatchtowerRequestV2::commitment` covers every field including
/// the timestamps, and `run_hvm_registry_watchtower_internal` refuses a retry
/// whose commitment moved. So a retry cannot mint a fresh `now`: it has to
/// reproduce the original request byte for byte, and the durable record is
/// where those bytes are remembered.
///
/// The ownership check is the other half. A record the tick did not open —
/// a human's begin-challenge, a Local Pilot injection — is not the tick's to
/// drive. It is reported and left alone.
fn registry_watchtower_tick_request(
    operation: &PersistedHvmRegistryChainOperation,
) -> HubResult<HvmRegistryWatchtowerRequestV2> {
    if !operation
        .operation_id
        .starts_with(HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX)
        || !operation
            .idempotency_key
            .starts_with(HVM_REGISTRY_WATCHTOWER_IDEMPOTENCY_PREFIX)
    {
        return Err(HubError::State(format!(
            "registry chain operation {} was not opened by the watchtower tick",
            operation.operation_id
        )));
    }
    // The tick monitors. It never begins a challenge and never renews a lease,
    // so it never rebuilds a request that would.
    if !matches!(
        operation.kind,
        HvmChainOperationKind::Respond
            | HvmChainOperationKind::Finalize
            | HvmChainOperationKind::Claim
    ) {
        return Err(HubError::State(format!(
            "registry chain operation {} is not a watchtower monitor action",
            operation.operation_id
        )));
    }
    let request = HvmRegistryWatchtowerRequestV2 {
        schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        binding_commitment: operation.binding_commitment.clone(),
        mode: HvmRegistryWatchtowerModeV2::Monitor,
        network_fee_zhu: operation.network_fee_zhu,
        timestamp: operation.transaction_timestamp,
        gas_max: operation.gas_max,
        created_unix: operation.created_unix,
    };
    request.validate()?;
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
fn new_registry_chain_operation(
    operation_id: String,
    idempotency_key: String,
    request_commitment: String,
    binding_commitment: String,
    kind: HvmChainOperationKind,
    bill: Option<HvmRegistryBillV2>,
    lease_periods: Option<u64>,
    claim: Option<(String, u64)>,
    snapshot: &HvmRegistryLiveSnapshotV2,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
    source: String,
    created_unix: u64,
) -> PersistedHvmRegistryChainOperation {
    let (claim_payee, claim_amount_zhu) = match claim {
        Some((payee, amount_zhu)) => (Some(payee), Some(amount_zhu)),
        None => (None, None),
    };
    PersistedHvmRegistryChainOperation {
        operation_id,
        idempotency_key,
        request_commitment,
        binding_commitment,
        kind,
        bill,
        lease_periods,
        claim_payee,
        claim_amount_zhu,
        claim_settled_elsewhere_height: None,
        pre_observed_height: snapshot.observed_height,
        pre_status: snapshot.channel.status.value,
        pre_serial: snapshot.channel.serial.value,
        pre_left_balance_zhu: snapshot.channel.left_balance.value,
        pre_hub_balance_zhu: snapshot.channel.hub_balance.value,
        pre_deadline: snapshot.channel.deadline.value,
        pre_minimum_live_blocks: snapshot.minimum_live_blocks,
        pre_minimum_recover_blocks: snapshot.minimum_recover_blocks,
        network_fee_zhu,
        gas_max,
        transaction_timestamp: timestamp,
        call_source_commitment: hex::encode(Sha256::digest(source.as_bytes())),
        call_source: source,
        signed_transaction_hex: None,
        transaction_hash: None,
        status: HvmChainOperationStatus::IntentPersisted,
        submitted_unix: None,
        confirmed_block_height: None,
        confirmed_block_hash: None,
        observed_confirmations: 0,
        abandoned: None,
        created_unix,
        updated_unix: created_unix,
        last_error: None,
    }
}

/// The exact payee and zhu a claim was approved for. A claim that has lost
/// either has lost the only thing that made it exact, and there is nothing
/// safe to infer from the rest of the record.
fn registry_claim_terms(operation: &PersistedHvmRegistryChainOperation) -> HubResult<(&str, u64)> {
    let payee = operation
        .claim_payee
        .as_deref()
        .ok_or_else(|| HubError::State("registry claim lost its exact payee".into()))?;
    let amount_zhu = operation
        .claim_amount_zhu
        .ok_or_else(|| HubError::State("registry claim lost its exact payout amount".into()))?;
    if amount_zhu == 0 {
        return Err(HubError::State(
            "registry claim amount must be positive".into(),
        ));
    }
    Ok((payee, amount_zhu))
}

fn require_registry_bill_state(
    snapshot: &HvmRegistryLiveSnapshotV2,
    expected_status: u8,
    bill: &HvmRegistryBillV2,
) -> HubResult<()> {
    if snapshot.channel.status.value != expected_status
        || snapshot.channel.serial.value != bill.serial
        || snapshot.channel.left_balance.value != bill.left_balance_zhu
        || snapshot.channel.hub_balance.value != bill.hub_balance_zhu
    {
        return Err(HubError::State(
            "registry chain postcondition does not match the exact durable bill".into(),
        ));
    }
    Ok(())
}

fn registry_chain_response(
    operation: &PersistedHvmRegistryChainOperation,
) -> HvmRegistryChainResponseV2 {
    HvmRegistryChainResponseV2 {
        operation_id: operation.operation_id.clone(),
        status: operation.status.as_str().into(),
        action: operation.kind.as_str().into(),
        transaction_hash: operation.transaction_hash.clone(),
        confirmed_block_height: operation.confirmed_block_height,
        observed_confirmations: operation.observed_confirmations,
    }
}

fn no_registry_action_response(operation_id: &str) -> HvmRegistryChainResponseV2 {
    HvmRegistryChainResponseV2 {
        operation_id: operation_id.into(),
        status: "no_action".into(),
        action: "none".into(),
        transaction_hash: None,
        confirmed_block_height: None,
        observed_confirmations: 0,
    }
}
