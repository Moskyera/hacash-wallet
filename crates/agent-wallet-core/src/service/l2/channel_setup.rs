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
use crate::service::AgentWalletState;

/// The exact reasons `prepare_l2_channel_setup` refuses to start a new setup.
///
/// Named rather than inlined so a test can state what a discard is supposed to
/// unblock, and so the stored-setup reason can be cleared without anyone
/// widening the other four by accident.
pub(super) fn channel_setup_prepare_is_blocked(
    state: &AgentWalletState,
) -> AgentWalletResult<bool> {
    Ok(state.l2_binding.is_some()
        || state.l2_channel_setup.is_some()
        || active_reservations(state)? != HacUnits::ZERO
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
        }))
}

/// Whether one stored setup provably never reached the signer.
///
/// `Prepared` is the only phase written before `sign_exact_channel_open` can be
/// called, and it is only reachable while the durable phase on disk still reads
/// `Prepared` (see `discard_unsigned_l2_channel_setup`). The match is
/// exhaustive on purpose: `Submitted` is dead in this flow and a wildcard would
/// silently swallow it, and any variant added later, into the discardable side.
pub(super) fn channel_setup_is_provably_unsigned(setup: &AgentChannelSetupOperation) -> bool {
    match setup.review.phase {
        AgentChannelSetupPhase::Prepared => {}
        AgentChannelSetupPhase::SignatureMayExist
        | AgentChannelSetupPhase::Signed
        | AgentChannelSetupPhase::Submitted
        | AgentChannelSetupPhase::AwaitingConfirmations
        | AgentChannelSetupPhase::RecoveryRequired
        | AgentChannelSetupPhase::Confirmed => return false,
    }
    // Redundant given `AgentChannelSetupOperation::validate`, which makes this
    // a load-time invariant, and stated anyway so this safety does not depend
    // on a validator two modules away.
    setup.signed_request.is_none() && setup.transaction_hash.is_none()
}

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
        if channel_setup_prepare_is_blocked(&state)? {
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
            // The Hub client builds this sentence with `describe_unmet_contract`
            // precisely so a person can read which clause of the provider
            // contract is unmet. It used to be deleted one line later and
            // replaced with "transaction signing is blocked", which names
            // neither the Hub nor the clause.
            .map_err(|error| {
                AgentWalletError::ChannelSetupHubNotReady(hub_refusal_sentence(&error))
            })?;
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
        // Reuse version 1 or nothing, and the whole exit design depends on it.
        //
        // `derive_channel_id` two lines above is called with a hardcoded 1, so
        // one address pair always yields exactly one channel ID. A close
        // voucher names a channel ID and nothing else, and has no expiry, so a
        // voucher kept from an earlier incarnation of that same ID would
        // reanimate against a later one it was never signed for. Refusing any
        // incarnation past the first means a given channel ID is opened once
        // in this wallet's life and a voucher can only ever refer to the
        // channel it was signed for.
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
            last_hub_refusal: None,
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
    ///
    /// The body lives in `confirm_l2_channel_setup_inner` and is reached
    /// through a `Box::pin`, so this state machine is on the heap and not on
    /// the caller's stack. That is not a style choice. This future was 74,696
    /// bytes, and the release binary reserves a command future roughly
    /// twenty-four times over across `respond_async_serialized`,
    /// `tauri::async_runtime::spawn` and `tokio::task::spawn`, all of which run
    /// synchronously on the 1 MiB WebView2 UI thread before the runtime ever
    /// sees it. Pressing this button overflowed that stack at `_alloca_probe`
    /// and killed the wallet with `0xC00000FD`. Nothing below changed; only
    /// where the state machine lives did. See `service/l2/stack_budget.rs`.
    pub async fn confirm_l2_channel_setup(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &str,
        expected_review_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentChannelSetupReview> {
        Box::pin(self.confirm_l2_channel_setup_inner(
            wallet_id,
            operation_id,
            expected_review_commitment,
            now,
        ))
        .await
    }

    async fn confirm_l2_channel_setup_inner(
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
                    Some(if now >= setup.review.expires_at {
                        "This review's signing window closed before it was confirmed, so it can no longer be signed."
                            .to_owned()
                    } else {
                        "This wallet's durable channel-open record is not in a state a fresh signature may be produced from."
                            .to_owned()
                    }),
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
                Some(
                    "Agent Wallet payments were suspended while this open was in flight, so it was stopped."
                        .to_owned(),
                ),
                now,
            )?;
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        let response = match hub.open_channel(&signed_request).await {
            Ok(response) => response,
            // The Hub's sentence is the only copy that exists. It does not log
            // route refusals, so discarding it here - which this line used to
            // do, with `Err(_)` - left nobody on earth able to say why an open
            // failed. It is now stored on the setup so a refreshed panel can
            // still show it, and returned so the caller can show it now.
            Err(error) => {
                let reason = hub_refusal_sentence(&error);
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_setup_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    Some(reason.clone()),
                    now,
                )?;
                return Err(AgentWalletError::ChannelSetupHubRefused(reason));
            }
        };
        if response.operation_id != setup.review.operation_id
            || response.channel_id != setup.review.channel_id
            || response.schema != l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA
            || !matches!(
                response.status.as_str(),
                "submission_started"
                    | "submitted"
                    | "confirmed"
                    | "recovery_required"
                    // The Hub's chain-backed retirement of an open it broadcast
                    // and then found on no chain. The Agent Wallet shares
                    // wallet-core's open store and carried the same wedge: an
                    // unknown status here answered `mark_recovery_required` and
                    // the store had no terminal state to reach afterwards.
                    | "abandoned_unmined"
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
                Some(
                    "The Hub answered about a different operation or channel than the one this wallet asked about."
                        .to_owned(),
                ),
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
                Some(
                    "The Hub accepted this open and then could not carry it through; it reports the operation as needing recovery."
                        .to_owned(),
                ),
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
        let review = final_state
            .l2_channel_setup
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .review
            .clone();
        // The deposit is on chain now, so the exit is taken now.
        //
        // The Hub cannot countersign a channel that does not exist, so there
        // is an unavoidable window between the open confirming and the voucher
        // arriving in which the money is committed and no exit exists. This
        // call is here, immediately after the confirmation and before the
        // caller can do anything else, to make that window as short as the
        // network allows. It is not closed, and nothing here pretends it is.
        //
        // If it fails, this returns the failure rather than a success: the
        // channel is open but unusable, because Fast Pay payments stay refused
        // until the voucher is held. `recover_l2_channel_setup` retries it.
        //
        // Gated because the voucher module itself is: it needs the pilot
        // node-snapshot and channel-close signing paths, which a default build
        // does not compile. Without the gate a default build of this crate does
        // not compile at all, which is how it stood when this was written. A
        // default build therefore behaves exactly as it did before the voucher
        // existed; every build that has a voucher takes one here.
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        self.take_l2_channel_close_voucher(wallet_id, now).await?;
        Ok(review)
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
            // A confirmed open is not a finished setup. If the voucher never
            // arrived, this is the retry: without it Fast Pay stays refused,
            // and the owner has a funded channel with no way out that does not
            // depend on the Hub agreeing to close it.
            #[cfg(feature = "agent-wallet-testnet-pilot")]
            self.take_l2_channel_close_voucher(wallet_id, now).await?;
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

    /// Forget one channel-setup review that provably never reached the signer.
    ///
    /// # Why this exists
    ///
    /// A prepared review expires after 300 seconds. Confirming it afterwards
    /// refuses forever (`confirm_l2_channel_setup_inner` requires
    /// `expires_at > now` while `signed_request` is `None`), `recover` only
    /// re-enters that same refusal, and `prepare` refuses while any setup is
    /// stored. Without this method an owner who missed the window could never
    /// open a Fast Pay channel again on this wallet, on any network, even
    /// though nothing had been signed and no money had moved.
    ///
    /// # Why it cannot lose a signature
    ///
    /// The only channel-open signing call in the tree is
    /// `signer.sign_exact_channel_open` below. It is unreachable unless the
    /// phase was first driven to `SignatureMayExist` **and persisted**:
    /// `persist_event` rewrites the state file, appends the journal record and
    /// reads both back before returning. A persisted phase of `Prepared`
    /// therefore proves the signer never ran, and `validate` makes
    /// `Prepared => signed_request.is_none() && transaction_hash.is_none()` a
    /// load-time invariant besides. Every other phase keeps its existing
    /// behaviour untouched, including `SignatureMayExist`, whose whole contract
    /// is that a signature *may* exist even though the code shows it does not
    /// yet.
    ///
    /// Expiry is deliberately not part of the test. An unexpired `Prepared`
    /// review is exactly as unsigned as an expired one, and making the owner
    /// wait 300 seconds to back out would be a worse wallet. What makes this
    /// safe is the phase plus the durable store status; the owner-supplied
    /// `operation_id` and `review_commitment` are the anti-race gate.
    ///
    /// # Why the durable store is cancelled first
    ///
    /// Clearing the wallet state alone would strand the `ChannelOpenSafety`
    /// operation at `PersistedBeforeSigning`. The store directory is derived
    /// from the channel ID, so a re-prepared setup lands in the same place,
    /// `begin_or_resume` would see a different unresolved operation and refuse
    /// forever, and nothing in the tree can clear it - a worse brick than the
    /// one this fixes, sitting past the confirm button instead of in front of
    /// it. So the store is cancelled first and an already-cancelled store is
    /// accepted as satisfied, which makes a crash between the two writes
    /// recoverable by simply running this again.
    pub fn discard_unsigned_l2_channel_setup(
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
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let setup = state
            .l2_channel_setup
            .clone()
            .ok_or(AgentWalletError::InvalidIdentifier)?;
        setup.validate(wallet_id, &state.address)?;
        // Belt and braces: `validate_state` already refuses to load a
        // non-Confirmed setup alongside a binding.
        if state.l2_binding.is_some() {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        if !channel_setup_is_provably_unsigned(&setup) {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        // The owner is discarding this exact review, not whatever is stored.
        if setup.review.operation_id != operation_id
            || setup.review.review_commitment != expected_review_commitment
        {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }

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
        // `operation()` errors when the store holds none, which is the ordinary
        // case here: `prepare` never opens this store, so it exists only if a
        // confirm reached it. Nothing durable to release then.
        if let Ok(durable) = safety.operation() {
            if durable.request.is_some() || durable.response.is_some() {
                return Err(AgentWalletError::ChannelSetupNotDiscardable);
            }
            match durable.status {
                ChannelOpenStatus::PersistedBeforeSigning => safety
                    .cancel_before_signing()
                    .map_err(|_| AgentWalletError::ChannelSetupNotDiscardable)?,
                // A previous run of this method already got this far and then
                // died before clearing the state. Re-running finishes the job.
                ChannelOpenStatus::CancelledBeforeSigning => {}
                ChannelOpenStatus::SignatureMayExist
                | ChannelOpenStatus::UserSigned
                | ChannelOpenStatus::HubCosigned
                | ChannelOpenStatus::NodeSubmitted
                | ChannelOpenStatus::Opening
                | ChannelOpenStatus::Confirmed
                | ChannelOpenStatus::RecoveryRequired
                // A retired dead request is not an unsigned one. It has its
                // own exit, `abandon_dead_l2_channel_setup`, and the unsigned
                // discard must never be the thing that clears it.
                | ChannelOpenStatus::AbandonedDeadRequest
                // The Hub's own chain-backed retirement. Terminal, and cleared
                // by that retirement rather than by the unsigned discard.
                | ChannelOpenStatus::AbandonedUnmined => {
                    return Err(AgentWalletError::ChannelSetupNotDiscardable);
                }
            }
        }

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.l2_channel_setup.as_ref() != Some(&setup) {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let review = setup.review.clone();
        current.l2_channel_setup = None;
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelSetupDiscarded,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(review)
    }

    /// The exit from a signed request that nobody will ever accept.
    ///
    /// # The state this is for
    ///
    /// An owner prepared an open, confirmed it, the wallet signed, and the Hub
    /// refused. Five minutes later the request envelope closed. From then on:
    /// `confirm` re-posted the same dead bytes and the Hub refused them for a
    /// second reason; `recover` only re-entered `confirm`;
    /// `discard_unsigned_l2_channel_setup` refused because a signature exists;
    /// and `prepare` refused because a setup is stored. There was no exit at
    /// all, on any network, for the life of the wallet. That is the state the
    /// owner of this wallet was actually in.
    ///
    /// # The bar, and it is the discard's bar
    ///
    /// A setup is only forgotten when it is provable that nothing reached the
    /// Hub or the chain. Here that is six facts, every one of them checked
    /// below, and every one of them a refusal on its own:
    ///
    /// 1. The owner named this exact review: operation ID and review
    ///    commitment both match.
    /// 2. A signature exists and no transaction hash does. An unsigned setup
    ///    belongs to `discard_unsigned_l2_channel_setup` and is sent back
    ///    there; a setup carrying a transaction hash reached a node.
    /// 3. The request envelope has closed, so no Hub will cosign it.
    /// 4. The transaction is older than `CHANNEL_OPEN_DEAD_AFTER`, so even a
    ///    Hub that kept the bytes cannot use them: its own transaction-age
    ///    rule has expired too.
    /// 5. The durable store carries no Hub response and no node transaction
    ///    hash. This is read from disk, not from the wallet state, because the
    ///    store is the record that is written first and survives a crash.
    /// 6. This wallet's own pinned fullnode says the channel does not exist.
    ///    Asked live, at the moment of the abandonment, and any answer other
    ///    than a plain "channel not found" refuses - including an unreachable
    ///    node, which proves nothing and must never be read as proof.
    ///
    /// # Why retiring a real signature does not risk the deposit
    ///
    /// The bytes carry one signature, the user's. A `ChannelOpen` action needs
    /// both parties', so they cannot be mined by anyone, the Hub included,
    /// unless the Hub cosigns - and conditions 3 and 4 are exactly when it
    /// will not. If some future Hub broke its own rules and got the old
    /// transaction mined anyway, the wallet still cannot fund the channel
    /// twice: `prepare_l2_channel_setup` re-reads the reuse version from the
    /// chain, would see 2, and refuses before it signs anything.
    ///
    /// # Why the durable store is retired first
    ///
    /// Same reason as the discard. The store directory is derived from the
    /// deterministic channel ID, so a re-prepared setup lands in the same
    /// place; clearing the wallet state alone would leave an unresolved
    /// operation there that nothing in the tree could clear, which is a worse
    /// brick than the one this fixes. An already-retired store is accepted as
    /// satisfied, so a crash between the two writes is fixed by running this
    /// again.
    pub async fn abandon_dead_l2_channel_setup(
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
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let setup = state
            .l2_channel_setup
            .clone()
            .ok_or(AgentWalletError::InvalidIdentifier)?;
        setup.validate(wallet_id, &state.address)?;
        if state.l2_binding.is_some() {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        // (1) The owner is retiring this exact review, not whatever is stored.
        if setup.review.operation_id != operation_id
            || setup.review.review_commitment != expected_review_commitment
        {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        // (2) Signed, and never submitted. The match is exhaustive so a phase
        // added later cannot fall into the abandonable side by accident.
        if setup.signed_request.is_none() || setup.transaction_hash.is_some() {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        match setup.review.phase {
            AgentChannelSetupPhase::Signed | AgentChannelSetupPhase::RecoveryRequired => {}
            AgentChannelSetupPhase::Prepared
            | AgentChannelSetupPhase::SignatureMayExist
            | AgentChannelSetupPhase::Submitted
            | AgentChannelSetupPhase::AwaitingConfirmations
            | AgentChannelSetupPhase::Confirmed => {
                return Err(AgentWalletError::ChannelSetupNotDiscardable);
            }
        }
        // (3) and (4). The clock, both halves.
        let unusable_after = setup
            .created_at
            .checked_add(crate::service::l2::CHANNEL_OPEN_DEAD_AFTER)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        if now <= setup.review.expires_at || now < unusable_after {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }

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
        // (5) The store, read from disk. A setup that reached the signer
        // always has one, so unlike the discard there is no "no store" case
        // here: its absence is a refusal.
        let durable = safety
            .operation()
            .map_err(|_| AgentWalletError::ChannelSetupNotDiscardable)?;
        if durable.request.is_none()
            || durable.response.is_some()
            || durable.node_transaction_hash.is_some()
        {
            return Err(AgentWalletError::ChannelSetupNotDiscardable);
        }
        match durable.status {
            ChannelOpenStatus::SignatureMayExist
            | ChannelOpenStatus::UserSigned
            | ChannelOpenStatus::RecoveryRequired
            | ChannelOpenStatus::AbandonedDeadRequest => {}
            ChannelOpenStatus::PersistedBeforeSigning
            | ChannelOpenStatus::CancelledBeforeSigning
            | ChannelOpenStatus::HubCosigned
            | ChannelOpenStatus::NodeSubmitted
            | ChannelOpenStatus::Opening
            | ChannelOpenStatus::AbandonedUnmined
            | ChannelOpenStatus::Confirmed => {
                return Err(AgentWalletError::ChannelSetupNotDiscardable);
            }
        }

        // (6) The chain, asked now. Only the fullnode's own "channel not
        // found" is proof; an unreachable node, a malformed answer or a
        // channel that exists all refuse.
        let node = verified_agent_node(
            &setup.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        match query_channel(&node, &setup.review.channel_id).await {
            Ok(_) => return Err(AgentWalletError::ChannelSetupNotDiscardable),
            Err(hacash_wallet_core::WalletError::Node(message))
                if message.contains("channel not found") => {}
            Err(_) => return Err(AgentWalletError::NodeRejected),
        }

        safety
            .abandon_dead_request(now)
            .map_err(|_| AgentWalletError::ChannelSetupNotDiscardable)?;

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.l2_channel_setup.as_ref() != Some(&setup) {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let review = setup.review.clone();
        current.l2_channel_setup = None;
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelSetupDiscarded,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(review)
    }

    /// Put the stored setup into `RecoveryRequired` and, this is the point,
    /// record WHY.
    ///
    /// `reason` is shown verbatim on the owner's panel. It is an `Option` so a
    /// caller that genuinely has nothing to add cannot be forced to invent
    /// something, not so that callers may shrug.
    fn mark_channel_setup_recovery_required(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        operation_id: &str,
        reason: Option<String>,
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
        if let Some(reason) = reason {
            setup.review.last_hub_refusal = Some(truncate_for_display(&reason));
        }
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

/// The largest refusal sentence this wallet will store or show.
///
/// A Hub is a remote party. Its error body reaches the owner's screen and the
/// wallet's own state file, so it is bounded here rather than trusted to be
/// short. 600 characters is longer than every message this workspace's Hub
/// produces and short enough to read.
const MAX_REFUSAL_SENTENCE: usize = 600;

/// One remote refusal, made safe to store and to show.
///
/// Bounded in length, stripped of control characters (a Hub cannot paint the
/// owner's panel with newlines or escape sequences), and never empty: an empty
/// reason is the defect this whole change exists to remove, so a Hub that
/// refuses without saying anything is reported as having said nothing.
fn truncate_for_display(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        return "no reason was given".to_owned();
    }
    match cleaned.char_indices().nth(MAX_REFUSAL_SENTENCE) {
        Some((index, _)) => format!("{}...", &cleaned[..index]),
        None => cleaned,
    }
}

/// What the Hub said, as a sentence.
fn hub_refusal_sentence(error: &hacash_wallet_core::WalletError) -> String {
    truncate_for_display(&error.to_string())
}

async fn health_address_hint(hub: &L2HubClient) -> AgentWalletResult<String> {
    let health = hub
        .health()
        .await
        .map_err(|error| AgentWalletError::ChannelSetupHubNotReady(hub_refusal_sentence(&error)))?;
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
        .map_err(|error| AgentWalletError::ChannelSetupHubNotReady(hub_refusal_sentence(&error)))?;
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
