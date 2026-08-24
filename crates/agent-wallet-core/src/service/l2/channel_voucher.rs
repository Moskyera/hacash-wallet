//! The owner's exit from a Fast Pay channel, taken once and never refreshed.
//!
//! # What a voucher is
//!
//! A Hacash `ChannelClose` (Action 3) carries a channel ID and nothing else.
//! Settlement refunds the balances recorded when the channel opened, so for a
//! channel the Hub deposited nothing into, a bare
//! `[ChainAllow, ChannelClose]` signed by both parties refunds the owner in
//! full. Because the transaction names no balance, nothing about it goes
//! stale: it has no expiry, it is not bound to whoever broadcasts it, and the
//! owner needs no on-chain balance when it is signed.
//!
//! # The one rule
//!
//! Exactly one voucher per channel, ever, at delta zero, never refreshed.
//! There is deliberately no refresh entry point in this module and no way to
//! reach one. Re-taking a voucher after payments would leave the owner holding
//! several valid closes for one channel, each with its own transaction hash,
//! and only the first to land would win. The owner would pick whichever pays
//! them most, which is always the oldest, so a refresh is pure loss to the Hub
//! for no owner benefit: the delta-zero voucher already pays the owner the
//! maximum the channel can pay them.
//!
//! # The trust, stated plainly
//!
//! This is not a trustless exit. The Hub must countersign, once, at the start,
//! and nothing in Hacash can compel it. If it refuses, the deposit is stuck
//! and there is no protocol remedy. There is also a genuine window between the
//! open confirming on-chain and the voucher arriving, because the Hub cannot
//! countersign a channel that does not exist yet; this module minimises that
//! window by taking the voucher immediately after the open confirms, and does
//! not pretend it away. And once the owner holds the bytes, the Hub carries
//! the whole exposure, because the owner can spend the channel down and still
//! recover the opening deposit. All of that is acceptable only in this bounded
//! pilot, where the owner runs the Hub.

use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::channel::{prepare_cooperative_channel_close, query_channel};
use hacash_wallet_core::l1_channel_close_safety::{
    transaction_hash_of_hex, verify_channel_close_voucher_bytes,
};
use hacash_wallet_core::l1_channel_flow::exact_l1_channel_network_binding;
use hacash_wallet_core::l2_hub::L2HubClient;
use hacash_wallet_core::send_options::L1FeeSpeed;

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::node_binding::verified_agent_node;
use crate::service::payment::require_agent_spending_network;
use crate::signer::AgentChannelCloseSigningRequest;
use crate::types::{AgentWalletId, WalletScope};

use super::verification::{
    require_exact_hub_health, require_exact_live_channel, require_exact_node_binding,
};
use super::{
    AgentChannelCloseVoucherOperation, AgentChannelCloseVoucherPhase, AgentChannelCloseVoucherView,
    AgentWalletManager, MILLIMEI_IN_AGENT_UNITS,
};

/// How long the signed voucher request stays presentable to the Hub. The Hub
/// refuses an envelope with a longer lifetime than this.
const VOUCHER_REQUEST_LIFETIME_SECONDS: u64 = 300;

impl AgentWalletManager {
    /// Read the one voucher this wallet holds, if it holds one.
    pub fn l2_channel_close_voucher(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<AgentChannelCloseVoucherView>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(state
            .l2_channel_close_voucher
            .as_ref()
            .map(|operation| operation.view.clone()))
    }

    /// Take this channel's one close voucher, or resume taking it.
    ///
    /// Called immediately after the open confirms. Until it succeeds the
    /// wallet refuses to make Fast Pay payments: see
    /// [`super::AgentWalletManager::request_fast_pay_intent`], which requires a
    /// held voucher for the active binding. The sequencing rule is code here,
    /// not a note in a document.
    pub async fn take_l2_channel_close_voucher(
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
        let binding = initial
            .l2_binding
            .clone()
            .filter(|binding| binding.is_active())
            .ok_or(AgentWalletError::SigningBlocked)?;

        // Resume, refuse, or start. There is no fourth option: this channel
        // gets one voucher and one attempt at the signature behind it.
        if let Some(existing) = initial.l2_channel_close_voucher.clone() {
            if !existing.matches_binding(&binding) {
                return Err(AgentWalletError::RecoveryRequired);
            }
            match existing.view.phase {
                AgentChannelCloseVoucherPhase::Held | AgentChannelCloseVoucherPhase::Broadcast => {
                    // Re-prove the stored bytes rather than trusting the
                    // stored phase, then hand them back unchanged.
                    existing.verified_bytes()?;
                    return Ok(existing.view);
                }
                AgentChannelCloseVoucherPhase::RecoveryRequired => {
                    return Err(AgentWalletError::RecoveryRequired);
                }
                AgentChannelCloseVoucherPhase::SignatureMayExist => {
                    // A signature may have been produced whose exact bytes
                    // never became durable. Signing again would produce
                    // different bytes, and the Hub reserved this channel's one
                    // voucher slot before it signed, so it will never serve
                    // them. Refusing is the honest end of this channel's exit:
                    // it is not replaced with a second signed close.
                    self.mark_voucher_recovery_required(
                        wallet_id,
                        &state_master,
                        &journal_key,
                        now,
                    )?;
                    return Err(AgentWalletError::RecoveryRequired);
                }
                AgentChannelCloseVoucherPhase::Signed => {
                    let request = existing
                        .signed_request
                        .clone()
                        .ok_or(AgentWalletError::RecoveryRequired)?;
                    let hub = L2HubClient::new_for_wallet_policy(
                        binding.hub_url(),
                        binding.network_mode(),
                        initial.trusted_mainnet_fast_pay_pilot,
                    );
                    return self
                        .exchange_voucher_request(
                            wallet_id,
                            &state_master,
                            &journal_key,
                            &hub,
                            &existing,
                            &request,
                            now,
                        )
                        .await;
                }
            }
        }

        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(initial.payments_suspended)?;
        let node = verified_agent_node(
            &initial.node_url,
            &initial.network_mode,
            &initial.block_one_fingerprint,
        )
        .await?;
        permit.checkpoint(initial.payments_suspended)?;
        require_exact_node_binding(node.snapshot(), &binding)?;
        let network_binding = exact_l1_channel_network_binding(&node, &initial.network_mode)
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        permit.checkpoint(initial.payments_suspended)?;
        let channel = query_channel(&node, binding.channel_id())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        permit.checkpoint(initial.payments_suspended)?;
        require_exact_live_channel(&binding, node.snapshot(), &channel, now)?;

        let paths = self.storage.paths(wallet_id)?;
        let bills = BillStore::load_at(paths.l2_dir().join("settlement-bills.json"))
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let plan = prepare_cooperative_channel_close(
            &node,
            network_binding.chain_id,
            &initial.address,
            &channel,
            &bills,
            L1FeeSpeed::Normal,
        )
        .await
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        permit.checkpoint(initial.payments_suspended)?;
        // Delta zero or nothing. A plan that settles anything is a plan for a
        // channel that has already moved money, and a voucher is only ever
        // taken before that happens.
        if plan.requires_principal_transfer()
            || plan.final_left_millimeis != plan.original_left_millimeis
            || plan.original_right_millimeis != 0
            || plan.final_right_millimeis != 0
        {
            return Err(AgentWalletError::RecoveryRequired);
        }

        let hub = L2HubClient::new_for_wallet_policy(
            binding.hub_url(),
            binding.network_mode(),
            initial.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .require_channel_close_ready(binding.hub_address(), false)
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        permit.checkpoint(initial.payments_suspended)?;
        require_exact_hub_health(&health, &binding, initial.trusted_mainnet_fast_pay_pilot)?;

        let refund_units = HacUnits::new(
            plan.original_left_millimeis
                .checked_mul(MILLIMEI_IN_AGENT_UNITS)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        );
        let network_fee_units = HacUnits::from_decimal(&plan.network_fee)
            .map_err(|_| AgentWalletError::InvalidAmount)?;
        if refund_units != binding.deposit_units() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        let reserved = AgentChannelCloseVoucherOperation {
            view: AgentChannelCloseVoucherView {
                wallet_id: wallet_id.clone(),
                operation_id: operation_id.clone(),
                network_mode: initial.network_mode.clone(),
                hub_address: binding.hub_address().to_owned(),
                owner_address: initial.address.clone(),
                channel_id: binding.channel_id().to_owned(),
                channel_reuse_version: binding.channel_reuse_version(),
                channel_open_height: binding.channel_open_height(),
                refund_units,
                deposit_units: binding.deposit_units(),
                network_fee_units,
                transaction_hash: None,
                signed_transaction_hex: None,
                signed_transaction_commitment: None,
                issued_at: None,
                phase: AgentChannelCloseVoucherPhase::SignatureMayExist,
                broadcast: None,
            },
            idempotency_key: format!("hpay:agent-channel-close-voucher:{operation_id}"),
            created_at: now,
            expires_at: now
                .checked_add(VOUCHER_REQUEST_LIFETIME_SECONDS)
                .ok_or(AgentWalletError::IntegerOverflow)?,
            node_url: initial.node_url.clone(),
            network_binding: network_binding.clone(),
            plan: plan.clone(),
            signed_request: None,
        };
        reserved.validate(wallet_id, &initial.address)?;

        // Claim the slot before the signer is touched, so a crash in the
        // signing window is visible afterwards rather than silently retried
        // with different bytes.
        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.l2_channel_close_voucher.is_some()
            || current.l2_binding.as_ref() != Some(&binding)
            || current.signer_epoch != initial.signer_epoch
            || current.emergency_epoch != initial.emergency_epoch
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        current.l2_channel_close_voucher = Some(reserved.clone());
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelCloseVoucherSignatureMayExist,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        permit.checkpoint(current.payments_suspended)?;

        let request = {
            let signer = &self.session(wallet_id)?.signer;
            signer.sign_exact_channel_close(
                AgentChannelCloseSigningRequest {
                    wallet_scope: WalletScope::for_agent_wallet(wallet_id),
                    network_mode: initial.network_mode.clone(),
                    network_binding: network_binding.clone(),
                    hub_address: binding.hub_address().to_owned(),
                    plan,
                    operation_id: operation_id.clone(),
                    idempotency_key: reserved.idempotency_key.clone(),
                    created_unix: reserved.created_at,
                    expires_unix: reserved.expires_at,
                },
                &permit,
                now,
            )?
        };
        let mut signed = reserved;
        signed.view.phase = AgentChannelCloseVoucherPhase::Signed;
        signed.signed_request = Some(request.clone());
        signed.validate(wallet_id, &initial.address)?;
        let mut signed_state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if signed_state
            .l2_channel_close_voucher
            .as_ref()
            .map(|stored| stored.view.phase)
            != Some(AgentChannelCloseVoucherPhase::SignatureMayExist)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        signed_state.l2_channel_close_voucher = Some(signed.clone());
        signed_state.updated_at = now;
        self.persist_event(
            &mut signed_state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ChannelCloseVoucherSigned,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;

        self.exchange_voucher_request(
            wallet_id,
            &state_master,
            &journal_key,
            &hub,
            &signed,
            &request,
            now,
        )
        .await
    }

    /// Present the exact signed request to the Hub and store only what the
    /// bytes themselves prove.
    ///
    /// Safe to repeat: the Hub serves the identical bytes for the identical
    /// request, which is one transaction hash served twice, not a second
    /// signed close.
    #[allow(clippy::too_many_arguments)]
    async fn exchange_voucher_request(
        &mut self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        hub: &L2HubClient,
        operation: &AgentChannelCloseVoucherOperation,
        request: &l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest,
        now: u64,
    ) -> AgentWalletResult<AgentChannelCloseVoucherView> {
        let response = hub
            .issue_channel_close_voucher(request)
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        // Everything below is derived from the returned bytes. Nothing the Hub
        // asserts about them is taken on its word: it signed once and could
        // have refused, and this is the only moment at which the owner can
        // still discover that what it signed is not what it claimed.
        if response.schema != l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA
            || response.status != l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_VOUCHER_STATUS
            || response.operation_id != operation.view.operation_id
            || !response
                .channel_id
                .eq_ignore_ascii_case(&operation.view.channel_id)
            || response.reuse_version != operation.view.channel_reuse_version
            || response.open_height != operation.view.channel_open_height
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let transaction_hash = response
            .transaction_hash
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let signed_transaction_hex = response
            .signed_transaction_hex
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let claimed_commitment = response
            .signed_transaction_commitment
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let verified = verify_channel_close_voucher_bytes(
            &signed_transaction_hex,
            &transaction_hash,
            &operation.view.owner_address,
            &operation.view.hub_address,
            &operation.view.channel_id,
            operation.network_binding.chain_id,
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if !verified
            .signed_transaction_commitment
            .eq_ignore_ascii_case(&claimed_commitment)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        // The countersignature must be over the transaction this wallet
        // authored. Co-signing does not change `hash()`, so the voucher's hash
        // is the hash of the wallet's own partial bytes or it is a different
        // transaction.
        if !transaction_hash_of_hex(&request.partial_transaction_hex)
            .map_err(|_| AgentWalletError::RecoveryRequired)?
            .eq_ignore_ascii_case(&transaction_hash)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }

        let mut held = operation.clone();
        held.view.phase = AgentChannelCloseVoucherPhase::Held;
        held.view.transaction_hash = Some(verified.transaction_hash.clone());
        held.view.signed_transaction_hex = Some(signed_transaction_hex);
        held.view.signed_transaction_commitment =
            Some(verified.signed_transaction_commitment.clone());
        held.view.issued_at = Some(now);
        let address = held.view.owner_address.clone();
        held.validate(wallet_id, &address)?;

        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let stored = state
            .l2_channel_close_voucher
            .as_ref()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        match stored.view.phase {
            // Already held. The Hub serves one voucher per channel, so this is
            // the same transaction, and the stored copy stays as it is.
            AgentChannelCloseVoucherPhase::Held | AgentChannelCloseVoucherPhase::Broadcast => {
                if stored.view.transaction_hash.as_deref()
                    != Some(verified.transaction_hash.as_str())
                {
                    return Err(AgentWalletError::RecoveryRequired);
                }
                return Ok(stored.view.clone());
            }
            AgentChannelCloseVoucherPhase::Signed => {}
            _ => return Err(AgentWalletError::RecoveryRequired),
        }
        if stored.signed_request.as_ref() != Some(request) {
            return Err(AgentWalletError::RecoveryRequired);
        }
        state.l2_channel_close_voucher = Some(held.clone());
        state.updated_at = now;
        let operation_id = held.view.operation_id.clone();
        self.persist_event(
            &mut state,
            state_master,
            journal_key,
            AgentJournalEventKind::ChannelCloseVoucherHeld,
            Some(operation_id.as_bytes()),
            None,
            now,
        )?;
        Ok(held.view)
    }

    fn mark_voucher_recovery_required(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        now: u64,
    ) -> AgentWalletResult<()> {
        let mut state = self.load_verified_state(wallet_id, state_master, journal_key)?;
        let voucher = state
            .l2_channel_close_voucher
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if voucher.view.phase != AgentChannelCloseVoucherPhase::SignatureMayExist {
            return Err(AgentWalletError::RecoveryRequired);
        }
        voucher.view.phase = AgentChannelCloseVoucherPhase::RecoveryRequired;
        let operation_id = voucher.view.operation_id.clone();
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
}
