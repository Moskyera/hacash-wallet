//! Owner-reviewed, Agent-scoped L1 channel setup.
//!
//! Preparation performs no signing. Confirmation will consume the exact
//! durable review through the restricted Agent signer; no generic send or
//! arbitrary-signing authority is exposed by this module.

use hacash_wallet_core::channel::{
    build_channel_open_tx_with_dynamic_fee, derive_channel_id, next_channel_reuse_version,
    query_channel,
};
use hacash_wallet_core::l1_channel_flow::exact_l1_channel_network_binding;
use hacash_wallet_core::l1_channel_safety::{
    BeginChannelOpen, ChannelOpenSafety, ChannelOpenStatus,
};
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::send_options::L1FeeSpeed;
use hacash_wallet_core::settings::validate_service_url;

use crate::amount::HacUnits;
use crate::emergency::AgentSafetyPermit;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::fast_pay_operation::AgentFastPayStatus;
use crate::journal::AgentJournalEventKind;
use crate::node_binding::{
    AgentNodeStatus, VerifiedAgentNode, probe_agent_node, verified_agent_node,
};
use crate::service::payment::require_agent_spending_network;
use crate::service::state::active_reservations;
use crate::signer::AgentChannelOpenSigningRequest;
use crate::types::AgentWalletId;
use hpay_companion_protocol::AgentFastPayNetworkBinding;

use super::{
    AgentChannelSetupOperation, AgentChannelSetupPhase, AgentChannelSetupReview, AgentWalletManager,
};

impl AgentWalletManager {
    /// Prepare one exact Agent-owned, zero-Hub-deposit channel for owner review.
    /// This method never touches the Agent signing key.
    pub async fn prepare_l2_channel_setup(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        deposit: &str,
        now: u64,
    ) -> AgentWalletResult<AgentChannelSetupReview> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (session.state_master.clone(), session.journal_key.clone())
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        require_agent_spending_network(&state.network_mode, state.trusted_mainnet_fast_pay_pilot)?;
        if state.l2_binding.is_some()
            || state.l2_channel_setup.is_some()
            || active_reservations(&state)? != HacUnits::ZERO
            || state
                .operations
                .values()
                .any(|operation| !operation.status().is_terminal())
            || state.fast_pay_operations.values().any(|operation| {
                !matches!(
                    operation.status(),
                    AgentFastPayStatus::Committed
                        | AgentFastPayStatus::Rejected
                        | AgentFastPayStatus::Cancelled
                )
            })
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let deposit_amount = l2_fast_pay_hub::amount::parse_amount_mei(deposit)
            .map_err(|_| AgentWalletError::InvalidAmount)?;
        if deposit_amount.as_millimeis() == 0 {
            return Err(AgentWalletError::InvalidAmount);
        }
        let deposit = l2_fast_pay_hub::amount::format_amount_mei(deposit_amount);
        let deposit_units = HacUnits::new(
            deposit_amount
                .as_millimeis()
                .checked_mul(1_000)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        );
        let hub_url = validate_service_url(hub_url, "Agent Fast Pay hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let node = NodeClient::new(&state.node_url).map_err(|_| AgentWalletError::NodeRejected)?;
        let network_binding = exact_l1_channel_network_binding(&node, &state.network_mode)
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let hub = L2HubClient::new_for_wallet_policy(
            hub_url.clone(),
            &state.network_mode,
            state.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .require_channel_open_ready(health_address_hint(&hub).await?.as_str(), &deposit)
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !hub_fee_is_zero(&health)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hub_address = health
            .hub_address
            .clone()
            .filter(|address| !address.is_empty())
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        let channel_id = derive_channel_id(&state.address, &hub_address, 1);
        let reuse_version =
            next_channel_reuse_version(&node, &channel_id, &state.address, &hub_address)
                .await
                .map_err(|_| AgentWalletError::NodeRejected)?;
        if reuse_version != 1 {
            return Err(AgentWalletError::SigningBlocked);
        }
        let (built, network_fee, fee_estimate_degraded) = build_channel_open_tx_with_dynamic_fee(
            &node,
            network_binding.chain_id,
            &state.address,
            &channel_id,
            &state.address,
            &deposit,
            &hub_address,
            "0",
            L1FeeSpeed::Normal,
        )
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
        // This used to refuse outright on a degraded fee, on the stated
        // grounds that an unattended open has no screen and nobody to ask.
        // That was wrong about this function: it returns an
        // `AgentChannelSetupReview` that
        // `agent_wallet_prepare_fast_pay_channel` hands to an owner-controlled
        // panel with its own confirm step, so there IS somebody to ask. The
        // refusal also collapsed the node's own explanation into a bare
        // `NodeRejected`, discarding exactly the reason this work existed to
        // preserve. The warning travels on the review instead, bound by the
        // review commitment, and the owner decides.
        let unsigned_transaction_hex = built.body.ok_or(AgentWalletError::NodeRejected)?;
        let network_fee_units =
            HacUnits::from_decimal(&network_fee).map_err(|_| AgentWalletError::InvalidAmount)?;
        let total_debit_units = deposit_units.checked_add(network_fee_units)?;
        let confirmed = node
            .query_balance_entry(&state.address, false)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let available = HacUnits::from_decimal(confirmed.hacash_decimal())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if available < total_debit_units {
            return Err(AgentWalletError::InsufficientAgentBalance);
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        let review = AgentChannelSetupReview {
            wallet_id: wallet_id.clone(),
            operation_id: operation_id.clone(),
            review_commitment: String::new(),
            expires_at: now
                .checked_add(300)
                .ok_or(AgentWalletError::IntegerOverflow)?,
            network_mode: state.network_mode.clone(),
            hub_url: hub_url.clone(),
            hub_address,
            channel_id,
            channel_reuse_version: reuse_version,
            deposit_units,
            network_fee_units,
            wallet_fee_units: HacUnits::ZERO,
            total_debit_units,
            fee_estimate_degraded,
            phase: AgentChannelSetupPhase::Prepared,
        };
        let mut operation = AgentChannelSetupOperation {
            review,
            idempotency_key: format!("hpay:agent-channel-open:{}", uuid::Uuid::new_v4()),
            created_at: now,
            node_url: state.node_url.clone(),
            network_binding,
            unsigned_transaction_hex,
            deposit,
            network_fee,
            signed_request: None,
            transaction_hash: None,
        };
        operation.review.review_commitment = operation.recompute_review_commitment();
        operation.validate(wallet_id, &state.address)?;

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if serde_json::to_vec(&current).map_err(|_| AgentWalletError::RecoveryRequired)?
            != serde_json::to_vec(&state).map_err(|_| AgentWalletError::RecoveryRequired)?
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        current.l2_channel_setup = Some(operation.clone());
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelSetupPrepared,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(operation.review)
    }

    /// Confirm only the exact owner-reviewed setup. Every network fact is
    /// re-fetched before the signature, and an emergency generation change
    /// after signing leaves the exact bytes in RecoveryRequired state.
    pub async fn confirm_l2_channel_setup(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &str,
        expected_review_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentChannelSetupReview> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (session.state_master.clone(), session.journal_key.clone())
        };
        let initial = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        require_agent_spending_network(
            &initial.network_mode,
            initial.trusted_mainnet_fast_pay_pilot,
        )?;
        let setup = initial
            .l2_channel_setup
            .clone()
            .ok_or(AgentWalletError::InvalidIdentifier)?;
        setup.validate(wallet_id, &initial.address)?;
        if setup.review.operation_id == operation_id
            && setup.review.review_commitment == expected_review_commitment
            && setup.review.phase == AgentChannelSetupPhase::Confirmed
        {
            return Ok(setup.review);
        }
        if setup.review.operation_id != operation_id
            || setup.review.review_commitment != expected_review_commitment
            || setup.review.expires_at <= now && setup.signed_request.is_none()
            || setup.review.phase != AgentChannelSetupPhase::Prepared
                && setup.review.phase != AgentChannelSetupPhase::SignatureMayExist
                && setup.review.phase != AgentChannelSetupPhase::Signed
                && setup.review.phase != AgentChannelSetupPhase::AwaitingConfirmations
                && setup.review.phase != AgentChannelSetupPhase::RecoveryRequired
            || initial.payments_suspended
            || active_reservations(&initial)? != HacUnits::ZERO
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let emergency = self.emergency_controller(wallet_id)?;
        let permit = emergency.issue_safety_permit(initial.payments_suspended)?;

        let (mut node, mut hub) = reverify_channel_setup_context(
            &setup,
            &initial.network_mode,
            &initial.block_one_fingerprint,
            &initial.address,
            initial.trusted_mainnet_fast_pay_pilot,
            &permit,
        )
        .await?;

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.l2_channel_setup.as_ref() != Some(&setup)
            || current.signer_epoch != initial.signer_epoch
            || current.policy_epoch != initial.policy_epoch
            || current.emergency_epoch != initial.emergency_epoch
            || current.payments_suspended
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        permit.checkpoint(current.payments_suspended)?;
        let paths = self.storage.paths(wallet_id)?;
        let wallet_scope = crate::types::WalletScope::for_agent_wallet(wallet_id);
        let mut safety = {
            let signer = &self.session(wallet_id)?.signer;
            ChannelOpenSafety::open_scoped(
                signer,
                paths.l2_dir(),
                wallet_scope.as_str(),
                &setup.review.hub_address,
                &setup.review.channel_id,
                setup.review.channel_reuse_version,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?
        };
        let user_deposit_zhu = l2_fast_pay_hub::amount::parse_amount_mei(&setup.deposit)
            .map_err(|_| AgentWalletError::RecoveryRequired)?
            .as_millimeis()
            .checked_mul(l2_fast_pay_hub::readiness::ZHU_PER_MILLIMEI)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        let durable = safety
            .begin_or_resume(BeginChannelOpen {
                operation_id: &setup.review.operation_id,
                idempotency_key: &setup.idempotency_key,
                user_address: &initial.address,
                reuse_version: setup.review.channel_reuse_version,
                user_deposit_zhu,
                unsigned_transaction_hex: &setup.unsigned_transaction_hex,
                created_unix: setup.created_at,
                expires_unix: setup.review.expires_at,
            })
            .map_err(|_| AgentWalletError::RecoveryRequired)?;

        let signed_request = if let Some(request) = durable.request {
            if setup.signed_request.as_ref() != Some(&request) {
                return Err(AgentWalletError::RecoveryRequired);
            }
            request
        } else {
            if durable.status != ChannelOpenStatus::PersistedBeforeSigning
                || now >= setup.review.expires_at
            {
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_setup_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    now,
                )?;
                return Err(AgentWalletError::RecoveryRequired);
            }
            safety
                .mark_signature_may_exist()
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            current
                .l2_channel_setup
                .as_mut()
                .ok_or(AgentWalletError::RecoveryRequired)?
                .review
                .phase = AgentChannelSetupPhase::SignatureMayExist;
            current.updated_at = now;
            self.persist_event(
                &mut current,
                &state_master,
                &journal_key,
                AgentJournalEventKind::ChannelSetupSignatureMayExist,
                Some(operation_id.as_bytes()),
                None,
                now,
            )?;
            // Close the approval-to-sign TOCTOU window. All live facts are
            // fetched again after the durable may-exist marker and before the
            // restricted signer can touch the Agent transaction key.
            (node, hub) = reverify_channel_setup_context(
                &setup,
                &initial.network_mode,
                &initial.block_one_fingerprint,
                &initial.address,
                initial.trusted_mainnet_fast_pay_pilot,
                &permit,
            )
            .await?;
            let latest = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
            if latest.l2_channel_setup != current.l2_channel_setup
                || latest.signer_epoch != initial.signer_epoch
                || latest.policy_epoch != initial.policy_epoch
                || latest.emergency_epoch != initial.emergency_epoch
                || latest.payments_suspended
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            permit.checkpoint(latest.payments_suspended)?;
            let signer = &self.session(wallet_id)?.signer;
            let request = signer.sign_exact_channel_open(
                AgentChannelOpenSigningRequest {
                    wallet_scope,
                    network_mode: initial.network_mode.clone(),
                    network_binding: setup.network_binding.clone(),
                    hub_address: setup.review.hub_address.clone(),
                    channel_id: setup.review.channel_id.clone(),
                    reuse_version: setup.review.channel_reuse_version,
                    left_deposit: setup.deposit.clone(),
                    right_deposit: "0".into(),
                    network_fee: setup.network_fee.clone(),
                    unsigned_transaction_hex: setup.unsigned_transaction_hex.clone(),
                    operation_id: setup.review.operation_id.clone(),
                    idempotency_key: setup.idempotency_key.clone(),
                    created_unix: setup.created_at,
                    expires_unix: setup.review.expires_at,
                },
                &permit,
                now,
            )?;
            safety
                .persist_user_signed(&request)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            let mut signed_state =
                self.load_verified_state(wallet_id, &state_master, &journal_key)?;
            let stored = signed_state
                .l2_channel_setup
                .as_mut()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            if stored.review.phase != AgentChannelSetupPhase::SignatureMayExist
                || stored.review.review_commitment != expected_review_commitment
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            stored.signed_request = Some(request.clone());
            stored.review.phase = AgentChannelSetupPhase::Signed;
            signed_state.updated_at = now;
            self.persist_event(
                &mut signed_state,
                &state_master,
                &journal_key,
                AgentJournalEventKind::ChannelSetupSigned,
                Some(operation_id.as_bytes()),
                None,
                now,
            )?;
            request
        };

        if permit.checkpoint(false).is_err() {
            safety
                .mark_recovery_required()
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            self.mark_channel_setup_recovery_required(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                now,
            )?;
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        let response = match hub.open_channel(&signed_request).await {
            Ok(response) => response,
            Err(_) => {
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_setup_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    now,
                )?;
                return Err(AgentWalletError::RecoveryRequired);
            }
        };
        if response.operation_id != setup.review.operation_id
            || response.channel_id != setup.review.channel_id
            || response.schema != l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA
            || !matches!(
                response.status.as_str(),
                "submission_started" | "submitted" | "confirmed" | "recovery_required"
            )
        {
            safety
                .mark_recovery_required()
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            self.mark_channel_setup_recovery_required(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                now,
            )?;
            return Err(AgentWalletError::RecoveryRequired);
        }
        safety
            .persist_hub_status(&response)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if response.status == "recovery_required" {
            self.mark_channel_setup_recovery_required(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                now,
            )?;
            return Err(AgentWalletError::RecoveryRequired);
        }
        let tx_hash = response
            .transaction_hash
            .clone()
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if response.status != "confirmed" {
            safety
                .mark_opening()
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            return self.persist_submitted_channel_setup(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                tx_hash,
                now,
            );
        }

        let channel = query_channel(&node, &setup.review.channel_id)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let probe = probe_agent_node(
            &setup.node_url,
            &initial.network_mode,
            &initial.block_one_fingerprint,
        )
        .await;
        permit.checkpoint(false)?;
        if probe.status != AgentNodeStatus::Verified {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let snapshot = probe
            .snapshot
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        if snapshot.current_height < channel.open_height.saturating_add(5) {
            safety
                .mark_opening()
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            return self.persist_submitted_channel_setup(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                tx_hash,
                now,
            );
        }
        let binding = super::AgentL2Binding::from_verified_channel(
            wallet_id.clone(),
            &initial.network_mode,
            AgentFastPayNetworkBinding {
                network_mode: initial.network_mode.clone(),
                chain_id: snapshot.chain_id,
                genesis_identifier: snapshot.block_one_fingerprint,
                node_profile_id: snapshot.node_profile_commitment,
                network_instance_id: snapshot.network_instance_id,
                transaction_format_version: snapshot.transaction_format_version,
            },
            &initial.address,
            &setup.review.hub_url,
            &setup.review.hub_address,
            &channel,
            snapshot.current_height,
            now,
        )?;
        safety
            .mark_confirmed()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let mut final_state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let stored = final_state
            .l2_channel_setup
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if stored.review.review_commitment != expected_review_commitment {
            return Err(AgentWalletError::RecoveryRequired);
        }
        stored.transaction_hash = Some(tx_hash);
        stored.review.phase = AgentChannelSetupPhase::Confirmed;
        final_state.l2_binding = Some(binding);
        final_state.updated_at = now;
        self.persist_event(
            &mut final_state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelSetupConfirmed,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(final_state
            .l2_channel_setup
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .review
            .clone())
    }

    pub async fn recover_l2_channel_setup(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentChannelSetupReview> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (session.state_master.clone(), session.journal_key.clone())
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let review = state
            .l2_channel_setup
            .as_ref()
            .ok_or(AgentWalletError::InvalidIdentifier)?
            .review
            .clone();
        if review.phase == AgentChannelSetupPhase::Confirmed {
            return Ok(review);
        }
        self.confirm_l2_channel_setup(
            wallet_id,
            &review.operation_id,
            &review.review_commitment,
            now,
        )
        .await
    }

    fn mark_channel_setup_recovery_required(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        operation_id: &str,
        now: u64,
    ) -> AgentWalletResult<()> {
        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let setup = state
            .l2_channel_setup
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if setup.review.operation_id != operation_id {
            return Err(AgentWalletError::RecoveryRequired);
        }
        setup.review.phase = AgentChannelSetupPhase::RecoveryRequired;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            state_master,
            journal_key,
            AgentJournalEventKind::RecoveryRequired,
            Some(operation_id.as_bytes()),
            None,
            now,
        )
    }

    fn persist_submitted_channel_setup(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        operation_id: &str,
        transaction_hash: String,
        now: u64,
    ) -> AgentWalletResult<AgentChannelSetupReview> {
        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let setup = state
            .l2_channel_setup
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if setup.review.operation_id != operation_id || setup.signed_request.is_none() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        setup.transaction_hash = Some(transaction_hash);
        setup.review.phase = AgentChannelSetupPhase::AwaitingConfirmations;
        let review = setup.review.clone();
        state.updated_at = now;
        self.persist_event(
            &mut state,
            state_master,
            journal_key,
            AgentJournalEventKind::ChannelSetupSubmitted,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(review)
    }
}

async fn health_address_hint(hub: &L2HubClient) -> AgentWalletResult<String> {
    let health = hub
        .health()
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    if !health.ok || !hub_fee_is_zero(&health) {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    health
        .hub_address
        .filter(|address| !address.is_empty())
        .ok_or(AgentWalletError::NodeCapabilityMismatch)
}

async fn reverify_channel_setup_context(
    setup: &AgentChannelSetupOperation,
    network_mode: &str,
    block_one_fingerprint: &str,
    agent_address: &str,
    trusted_mainnet_fast_pay_pilot: bool,
    permit: &AgentSafetyPermit,
) -> AgentWalletResult<(VerifiedAgentNode, L2HubClient)> {
    let node = verified_agent_node(&setup.node_url, network_mode, block_one_fingerprint).await?;
    permit.checkpoint(false)?;
    let live_network = exact_l1_channel_network_binding(&node, network_mode)
        .await
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
    permit.checkpoint(false)?;
    if live_network != setup.network_binding {
        return Err(AgentWalletError::NodeNetworkMismatch);
    }
    let hub = L2HubClient::new_for_wallet_policy(
        setup.review.hub_url.clone(),
        network_mode,
        trusted_mainnet_fast_pay_pilot,
    );
    let health = hub
        .require_channel_open_ready(&setup.review.hub_address, &setup.deposit)
        .await
        .map_err(|_| AgentWalletError::SigningBlocked)?;
    permit.checkpoint(false)?;
    if health.hub_address.as_deref() != Some(setup.review.hub_address.as_str())
        || !health.ok
        || health.version < 7
        || !health.settlement_ready
        || !health.cross_channel_ready
        || !hub_fee_is_zero(&health)
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    if setup.signed_request.is_none() {
        let reuse = next_channel_reuse_version(
            &node,
            &setup.review.channel_id,
            agent_address,
            &setup.review.hub_address,
        )
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
        permit.checkpoint(false)?;
        if reuse != setup.review.channel_reuse_version || reuse != 1 {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let confirmed = node
            .query_balance_entry(agent_address, false)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        permit.checkpoint(false)?;
        let available = HacUnits::from_decimal(confirmed.hacash_decimal())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if available < setup.review.total_debit_units {
            return Err(AgentWalletError::InsufficientAgentBalance);
        }
    }
    Ok((node, hub))
}
