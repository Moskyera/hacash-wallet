//! Owner-reviewed, Agent-scoped cooperative channel close.
//!
//! Preparation never signs. Confirmation revalidates the exact node, Hub,
//! channel incarnation and Agent-only settlement journal before entering the
//! restricted signer. Unknown outcomes retain the exact signed request for
//! idempotent recovery and never fall back to L1 send or a new operation ID.

use std::path::Path;

use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::channel::{
    CHANNEL_STATUS_AGREEMENT_CLOSED, ChannelInfo, prepare_cooperative_channel_close, query_channel,
    validate_cooperative_channel_close_plan,
};
use hacash_wallet_core::l1_channel_close_safety::{
    BeginChannelClose, ChannelCloseSafety, ChannelCloseStatus,
};
use hacash_wallet_core::l1_channel_flow::exact_l1_channel_network_binding;
use hacash_wallet_core::l2_hub::L2HubClient;
use hacash_wallet_core::send_options::L1FeeSpeed;

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::fast_pay_operation::AgentFastPayStatus;
use crate::journal::AgentJournalEventKind;
use crate::node_binding::verified_agent_node;
use crate::service::payment::require_agent_spending_network;
use crate::service::state::active_reservations;
use crate::signer::AgentChannelCloseSigningRequest;
use crate::types::{AgentWalletId, WalletScope};

use super::verification::{
    require_exact_hub_health, require_exact_live_channel, require_exact_node_binding,
};
use super::{
    AgentChannelCloseOperation, AgentChannelClosePhase, AgentChannelCloseReview,
    AgentChannelCloseVoucherBroadcast, AgentChannelCloseVoucherPhase, AgentChannelCloseVoucherView,
    AgentL2Binding, AgentWalletManager, MILLIMEI_IN_AGENT_UNITS,
};

fn is_exact_closed_incarnation(binding: &AgentL2Binding, channel: &ChannelInfo) -> bool {
    channel.status == CHANNEL_STATUS_AGREEMENT_CLOSED
        && channel.close_height > binding.channel_open_height()
        && channel.open_height == binding.channel_open_height()
        && channel.reuse_version == binding.channel_reuse_version()
        && channel.left.address == binding.agent_address()
        && channel.right.address == binding.hub_address()
        && channel.challenging.is_none()
}

impl AgentWalletManager {
    pub async fn prepare_l2_channel_close(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseReview> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (session.state_master.clone(), session.journal_key.clone())
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        require_agent_spending_network(&state.network_mode, state.trusted_mainnet_fast_pay_pilot)?;
        if state.payments_suspended
            || state.l2_channel_close.is_some()
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
        let binding = state
            .l2_binding
            .clone()
            .filter(|binding| binding.is_active())
            .ok_or(AgentWalletError::SigningBlocked)?;
        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        permit.checkpoint(state.payments_suspended)?;
        require_exact_node_binding(node.snapshot(), &binding)?;
        let network_binding = exact_l1_channel_network_binding(&node, &state.network_mode)
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        permit.checkpoint(state.payments_suspended)?;
        let channel = query_channel(&node, binding.channel_id())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        permit.checkpoint(state.payments_suspended)?;
        require_exact_live_channel(&binding, node.snapshot(), &channel, now)?;
        let paths = self.storage.paths(wallet_id)?;
        let bills = BillStore::load_at(paths.l2_dir().join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let plan = prepare_cooperative_channel_close(
            &node,
            network_binding.chain_id,
            &state.address,
            &channel,
            &bills,
            L1FeeSpeed::Normal,
        )
        .await
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        permit.checkpoint(state.payments_suspended)?;
        let hub = L2HubClient::new_for_wallet_policy(
            binding.hub_url(),
            binding.network_mode(),
            state.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .require_channel_close_ready(binding.hub_address(), plan.requires_principal_transfer())
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        permit.checkpoint(state.payments_suspended)?;
        require_exact_hub_health(&health, &binding, state.trusted_mainnet_fast_pay_pilot)?;
        require_mainnet_hard_guarantees(&hub, &binding).await?;
        permit.checkpoint(state.payments_suspended)?;

        let original_agent_units = HacUnits::new(
            plan.original_left_millimeis
                .checked_mul(MILLIMEI_IN_AGENT_UNITS)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        );
        let final_agent_units = HacUnits::new(
            plan.final_left_millimeis
                .checked_mul(MILLIMEI_IN_AGENT_UNITS)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        );
        let network_fee_units = HacUnits::from_decimal(&plan.network_fee)
            .map_err(|_| AgentWalletError::InvalidAmount)?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        let review = AgentChannelCloseReview {
            wallet_id: wallet_id.clone(),
            operation_id: operation_id.clone(),
            review_commitment: String::new(),
            expires_at: now
                .checked_add(300)
                .ok_or(AgentWalletError::IntegerOverflow)?,
            network_mode: state.network_mode.clone(),
            hub_url: binding.hub_url().to_owned(),
            hub_address: binding.hub_address().to_owned(),
            channel_id: binding.channel_id().to_owned(),
            channel_reuse_version: binding.channel_reuse_version(),
            channel_open_height: binding.channel_open_height(),
            bill_auto_number: plan.bill_auto_number,
            original_agent_units,
            final_agent_units,
            network_fee_units,
            wallet_fee_units: HacUnits::ZERO,
            // `prepare_cooperative_channel_close` measures this and used to
            // set it on a struct field nothing ever read. The close is the
            // same money as the open and gets the same disclosure; the
            // asymmetry was an oversight, not a decision.
            fee_estimate_degraded: plan.fee_estimate_degraded.clone(),
            phase: AgentChannelClosePhase::Prepared,
        };
        let mut operation = AgentChannelCloseOperation {
            review,
            idempotency_key: format!("hpay:agent-channel-close:{}", uuid::Uuid::new_v4()),
            created_at: now,
            node_url: state.node_url.clone(),
            network_binding,
            plan,
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
        current.l2_channel_close = Some(operation.clone());
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelClosePrepared,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(operation.review)
    }

    pub async fn confirm_l2_channel_close(
        &mut self,
        wallet_id: &AgentWalletId,
        operation_id: &str,
        expected_review_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseReview> {
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
        let close = initial
            .l2_channel_close
            .clone()
            .ok_or(AgentWalletError::InvalidIdentifier)?;
        close.validate(wallet_id, &initial.address)?;
        if close.review.operation_id == operation_id
            && close.review.review_commitment == expected_review_commitment
            && close.review.phase == AgentChannelClosePhase::Confirmed
        {
            return Ok(close.review);
        }
        if close.review.operation_id != operation_id
            || close.review.review_commitment != expected_review_commitment
            || close.review.expires_at <= now && close.signed_request.is_none()
            || !matches!(
                close.review.phase,
                AgentChannelClosePhase::Prepared
                    | AgentChannelClosePhase::SignatureMayExist
                    | AgentChannelClosePhase::Signed
                    | AgentChannelClosePhase::Submitted
                    | AgentChannelClosePhase::RecoveryRequired
            )
            || initial.payments_suspended
            || active_reservations(&initial)? != HacUnits::ZERO
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let binding = initial
            .l2_binding
            .clone()
            .filter(|binding| binding.is_active())
            .ok_or(AgentWalletError::SigningBlocked)?;
        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(initial.payments_suspended)?;
        let mut node = verified_agent_node(
            &close.node_url,
            &initial.network_mode,
            &initial.block_one_fingerprint,
        )
        .await?;
        permit.checkpoint(initial.payments_suspended)?;
        require_exact_node_binding(node.snapshot(), &binding)?;
        let live_network = exact_l1_channel_network_binding(&node, &initial.network_mode)
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        permit.checkpoint(initial.payments_suspended)?;
        if live_network != close.network_binding {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        let channel = query_channel(&node, binding.channel_id())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        permit.checkpoint(initial.payments_suspended)?;
        let live_closed = is_exact_closed_incarnation(&binding, &channel);
        if channel.is_open() {
            require_exact_live_channel(&binding, node.snapshot(), &channel, now)?;
        } else if !live_closed || close.signed_request.is_none() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let paths = self.storage.paths(wallet_id)?;
        if !live_closed {
            let bills = BillStore::load_at(paths.l2_dir().join("settlement-bills.json"))
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            validate_cooperative_channel_close_plan(
                live_network.chain_id,
                &initial.address,
                &channel,
                &bills,
                &close.plan,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        }
        let mut hub = L2HubClient::new_for_wallet_policy(
            binding.hub_url(),
            binding.network_mode(),
            initial.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .require_channel_close_ready(
                binding.hub_address(),
                close.plan.requires_principal_transfer(),
            )
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        permit.checkpoint(initial.payments_suspended)?;
        require_exact_hub_health(&health, &binding, initial.trusted_mainnet_fast_pay_pilot)?;
        require_mainnet_hard_guarantees(&hub, &binding).await?;
        permit.checkpoint(initial.payments_suspended)?;

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.l2_channel_close.as_ref() != Some(&close)
            || current.l2_binding.as_ref() != Some(&binding)
            || current.signer_epoch != initial.signer_epoch
            || current.policy_epoch != initial.policy_epoch
            || current.emergency_epoch != initial.emergency_epoch
            || current.payments_suspended
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        permit.checkpoint(current.payments_suspended)?;
        let wallet_scope = WalletScope::for_agent_wallet(wallet_id);
        let mut safety = {
            let signer = &self.session(wallet_id)?.signer;
            ChannelCloseSafety::open_scoped(
                signer,
                paths.l2_dir(),
                wallet_scope.as_str(),
                &close.review.hub_address,
                &close.review.channel_id,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?
        };
        let durable = safety
            .begin_or_resume(BeginChannelClose {
                operation_id: &close.review.operation_id,
                idempotency_key: &close.idempotency_key,
                user_address: &initial.address,
                reuse_version: close.review.channel_reuse_version,
                open_height: close.review.channel_open_height,
                unsigned_transaction_hex: &close.plan.unsigned_transaction_hex,
                created_unix: close.created_at,
                expires_unix: close.review.expires_at,
            })
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let signed_request = if let Some(request) = durable.request {
            if close.signed_request.as_ref() != Some(&request) {
                return Err(AgentWalletError::RecoveryRequired);
            }
            request
        } else {
            if durable.status != ChannelCloseStatus::PersistedBeforeSigning
                || now >= close.review.expires_at
            {
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_close_recovery_required(
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
                .l2_channel_close
                .as_mut()
                .ok_or(AgentWalletError::RecoveryRequired)?
                .review
                .phase = AgentChannelClosePhase::SignatureMayExist;
            current.updated_at = now;
            self.persist_event(
                &mut current,
                &state_master,
                &journal_key,
                AgentJournalEventKind::ChannelCloseSignatureMayExist,
                Some(operation_id.as_bytes()),
                None,
                now,
            )?;
            // Re-fetch every mutable authority after the durable may-exist
            // marker. No Agent transaction key is used until this exact
            // node, Hub, channel and authenticated bill check succeeds.
            let l2_root = paths.l2_dir();
            let revalidation = ChannelCloseRevalidation {
                network_mode: &initial.network_mode,
                block_one_fingerprint: &initial.block_one_fingerprint,
                trusted_mainnet_fast_pay_pilot: initial.trusted_mainnet_fast_pay_pilot,
                l2_root: &l2_root,
                now,
                permit: &permit,
            };
            (node, hub) = reverify_channel_close_context(&close, &binding, &revalidation).await?;
            let latest = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
            if latest.l2_channel_close != current.l2_channel_close
                || latest.l2_binding.as_ref() != Some(&binding)
                || latest.signer_epoch != initial.signer_epoch
                || latest.policy_epoch != initial.policy_epoch
                || latest.emergency_epoch != initial.emergency_epoch
                || latest.payments_suspended
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            permit.checkpoint(latest.payments_suspended)?;
            let signer = &self.session(wallet_id)?.signer;
            let request = signer.sign_exact_channel_close(
                AgentChannelCloseSigningRequest {
                    wallet_scope,
                    network_mode: initial.network_mode.clone(),
                    network_binding: close.network_binding.clone(),
                    hub_address: close.review.hub_address.clone(),
                    plan: close.plan.clone(),
                    operation_id: close.review.operation_id.clone(),
                    idempotency_key: close.idempotency_key.clone(),
                    created_unix: close.created_at,
                    expires_unix: close.review.expires_at,
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
                .l2_channel_close
                .as_mut()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            if stored.review.phase != AgentChannelClosePhase::SignatureMayExist
                || stored.review.review_commitment != expected_review_commitment
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            stored.signed_request = Some(request.clone());
            stored.review.phase = AgentChannelClosePhase::Signed;
            signed_state.updated_at = now;
            self.persist_event(
                &mut signed_state,
                &state_master,
                &journal_key,
                AgentJournalEventKind::ChannelCloseSigned,
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
            self.mark_channel_close_recovery_required(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                now,
            )?;
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        let response = match hub.close_channel(&signed_request).await {
            Ok(response) => response,
            Err(_) => {
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_close_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    now,
                )?;
                return Err(AgentWalletError::RecoveryRequired);
            }
        };
        safety
            .validate_hub_response(&response)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        // A retired Hub response is terminal only after the wallet observes
        // the exact closed channel incarnation on-chain. This check must
        // happen before the safety journal becomes terminal.
        let confirmed_evidence = if response.status == "retired" {
            let tx_hash = response
                .transaction_hash
                .clone()
                .filter(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let closed = query_channel(&node, binding.channel_id())
                .await
                .map_err(|_| AgentWalletError::NodeRejected)?;
            permit.checkpoint(false)?;
            if !is_exact_closed_incarnation(&binding, &closed) {
                safety
                    .mark_recovery_required()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                self.mark_channel_close_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    now,
                )?;
                return Err(AgentWalletError::RecoveryRequired);
            }
            Some((tx_hash, closed.close_height))
        } else {
            None
        };
        let durable = safety
            .persist_hub_response(&response)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        match durable.status {
            ChannelCloseStatus::RecoveryRequired => {
                self.mark_channel_close_recovery_required(
                    wallet_id,
                    &state_master,
                    &journal_key,
                    operation_id,
                    now,
                )?;
                Err(AgentWalletError::RecoveryRequired)
            }
            ChannelCloseStatus::HubSubmitted => self.persist_submitted_channel_close(
                wallet_id,
                &state_master,
                &journal_key,
                operation_id,
                response.transaction_hash,
                now,
            ),
            ChannelCloseStatus::Confirmed => {
                let (tx_hash, close_height) =
                    confirmed_evidence.ok_or(AgentWalletError::RecoveryRequired)?;
                let mut final_state =
                    self.load_verified_state(wallet_id, &state_master, &journal_key)?;
                let stored = final_state
                    .l2_channel_close
                    .as_mut()
                    .ok_or(AgentWalletError::RecoveryRequired)?;
                if stored.review.review_commitment != expected_review_commitment {
                    return Err(AgentWalletError::RecoveryRequired);
                }
                stored.transaction_hash = Some(tx_hash.clone());
                stored.review.phase = AgentChannelClosePhase::Confirmed;
                final_state
                    .l2_binding
                    .as_mut()
                    .ok_or(AgentWalletError::RecoveryRequired)?
                    .mark_closed(tx_hash, close_height, now)?;
                final_state.updated_at = now;
                self.persist_event(
                    &mut final_state,
                    &state_master,
                    &journal_key,
                    AgentJournalEventKind::ChannelCloseConfirmed,
                    Some(operation_id.as_bytes()),
                    None,
                    now,
                )?;
                Ok(final_state
                    .l2_channel_close
                    .as_ref()
                    .ok_or(AgentWalletError::RecoveryRequired)?
                    .review
                    .clone())
            }
            _ => Err(AgentWalletError::RecoveryRequired),
        }
    }

    /// Broadcast the stored close voucher, without the Hub.
    ///
    /// This is the escape hatch, and it is the only method here that never
    /// speaks to the Hub at all: not to close, not to countersign, not even to
    /// read state. Every input comes from the wallet's own durable record and
    /// the wallet's own configured fullnode, so it still works when the Hub is
    /// gone, refusing, or hostile.
    ///
    /// It is honest about where the trust was, though. The Hub had to
    /// countersign these bytes once, at the start, and it could have refused;
    /// nothing in Hacash could have forced it. What this method gives the
    /// owner is independence from the Hub *afterwards*, not independence from
    /// it in the first place.
    ///
    /// The stored bytes are re-proved here before they are sent. A close that
    /// is only as good as a JSON field in a state file is not an exit.
    pub async fn broadcast_l2_channel_close_voucher(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseVoucherView> {
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
        let voucher = initial
            .l2_channel_close_voucher
            .clone()
            .ok_or(AgentWalletError::SigningBlocked)?;
        if !voucher.is_held() {
            return Err(AgentWalletError::SigningBlocked);
        }
        let verified = voucher
            .verified_bytes()?
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let signed_transaction_hex = voucher
            .view
            .signed_transaction_hex
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;

        // The wallet's own node, checked against the binding the voucher was
        // signed under. No Hub URL is constructed anywhere on this path.
        let node = verified_agent_node(
            &initial.node_url,
            &initial.network_mode,
            &initial.block_one_fingerprint,
        )
        .await?;
        let live_network = exact_l1_channel_network_binding(&node, &initial.network_mode)
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if live_network != voucher.network_binding {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }

        let submitter = l2_fast_pay_hub::node::NodeClient::new(initial.node_url.clone())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let acknowledged = submitter
            .submit_transaction_bound(
                &signed_transaction_hex,
                &verified.transaction_hash,
                &live_network,
            )
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !acknowledged.eq_ignore_ascii_case(&verified.transaction_hash) {
            return Err(AgentWalletError::RecoveryRequired);
        }

        let mut broadcast = voucher;
        broadcast.view.phase = AgentChannelCloseVoucherPhase::Broadcast;
        broadcast.view.broadcast = Some(AgentChannelCloseVoucherBroadcast {
            transaction_hash: verified.transaction_hash.clone(),
            node_url: initial.node_url.clone(),
            broadcast_at: now,
        });
        let address = initial.address.clone();
        broadcast.validate(wallet_id, &address)?;
        let operation_id = broadcast.view.operation_id.clone();
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if state
            .l2_channel_close_voucher
            .as_ref()
            .map(|stored| &stored.view.transaction_hash)
            != Some(&broadcast.view.transaction_hash)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        state.l2_channel_close_voucher = Some(broadcast.clone());
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelCloseVoucherBroadcast,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(broadcast.view)
    }

    pub async fn recover_l2_channel_close(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseReview> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let review = state
            .l2_channel_close
            .as_ref()
            .ok_or(AgentWalletError::InvalidIdentifier)?
            .review
            .clone();
        if review.phase == AgentChannelClosePhase::Confirmed {
            return Ok(review);
        }
        self.confirm_l2_channel_close(
            wallet_id,
            &review.operation_id,
            &review.review_commitment,
            now,
        )
        .await
    }

    fn mark_channel_close_recovery_required(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        operation_id: &str,
        now: u64,
    ) -> AgentWalletResult<()> {
        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let close = state
            .l2_channel_close
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if close.review.operation_id != operation_id {
            return Err(AgentWalletError::RecoveryRequired);
        }
        close.review.phase = AgentChannelClosePhase::RecoveryRequired;
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

    fn persist_submitted_channel_close(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        operation_id: &str,
        transaction_hash: Option<String>,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseReview> {
        let hash = transaction_hash
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let close = state
            .l2_channel_close
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if close.review.operation_id != operation_id || close.signed_request.is_none() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        close.transaction_hash = Some(hash);
        close.review.phase = AgentChannelClosePhase::Submitted;
        let review = close.review.clone();
        state.updated_at = now;
        self.persist_event(
            &mut state,
            state_master,
            journal_key,
            AgentJournalEventKind::ChannelCloseSubmitted,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(review)
    }
}

struct ChannelCloseRevalidation<'a> {
    network_mode: &'a str,
    block_one_fingerprint: &'a str,
    trusted_mainnet_fast_pay_pilot: bool,
    l2_root: &'a Path,
    now: u64,
    permit: &'a crate::emergency::AgentSafetyPermit,
}

async fn reverify_channel_close_context(
    close: &AgentChannelCloseOperation,
    binding: &AgentL2Binding,
    context: &ChannelCloseRevalidation<'_>,
) -> AgentWalletResult<(crate::node_binding::VerifiedAgentNode, L2HubClient)> {
    let node = verified_agent_node(
        &close.node_url,
        context.network_mode,
        context.block_one_fingerprint,
    )
    .await?;
    context.permit.checkpoint(false)?;
    require_exact_node_binding(node.snapshot(), binding)?;
    let live_network = exact_l1_channel_network_binding(&node, context.network_mode)
        .await
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
    context.permit.checkpoint(false)?;
    if live_network != close.network_binding {
        return Err(AgentWalletError::NodeNetworkMismatch);
    }
    let channel = query_channel(&node, binding.channel_id())
        .await
        .map_err(|_| AgentWalletError::NodeRejected)?;
    context.permit.checkpoint(false)?;
    require_exact_live_channel(binding, node.snapshot(), &channel, context.now)?;
    let bills = BillStore::load_at(context.l2_root.join("settlement-bills.json"))
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
    validate_cooperative_channel_close_plan(
        live_network.chain_id,
        binding.agent_address(),
        &channel,
        &bills,
        &close.plan,
    )
    .map_err(|_| AgentWalletError::RecoveryRequired)?;
    let hub = L2HubClient::new_for_wallet_policy(
        binding.hub_url(),
        binding.network_mode(),
        context.trusted_mainnet_fast_pay_pilot,
    );
    let health = hub
        .require_channel_close_ready(
            binding.hub_address(),
            close.plan.requires_principal_transfer(),
        )
        .await
        .map_err(|_| AgentWalletError::SigningBlocked)?;
    context.permit.checkpoint(false)?;
    require_exact_hub_health(&health, binding, context.trusted_mainnet_fast_pay_pilot)?;
    require_mainnet_hard_guarantees(&hub, binding).await?;
    context.permit.checkpoint(false)?;
    Ok((node, hub))
}

/// On mainnet, re-read `/v1/readiness/mainnet` and require the hard guarantees
/// the configured settlement policy depends on.
///
/// These used to be re-checked off the `HubHealth` payload. They are not on it
/// any more, and could not honestly have been: `/v1/health` performs no
/// fullnode I/O, so its guarantee flags were `false` by construction and this
/// gate could never open. Reading the readiness document keeps the exact same
/// answer today - the external rollback anchor is absent, so the Hub measures
/// `trustless_finality: false` and this denies - and lets it open by itself
/// once the anchor exists. Fails closed when the document is missing,
/// malformed, expired or unreachable.
async fn require_mainnet_hard_guarantees(
    hub: &L2HubClient,
    binding: &AgentL2Binding,
) -> AgentWalletResult<()> {
    if binding.network_mode() != "mainnet" {
        return Ok(());
    }
    hub.require_mainnet_hard_guarantees()
        .await
        .map_err(|_| AgentWalletError::SigningBlocked)?;
    Ok(())
}
