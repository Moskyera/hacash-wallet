use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

use crate::amount::{HacAmount, format_amount_mei, parse_amount_mei};
use crate::api::{FastPayInboxItem, FastPayResponse};
use crate::error::{HubError, HubResult};
use crate::hub_signer::HubSigner;
use crate::idempotency::response_from_state as idempotent_response_from_state;
use crate::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use crate::ledger::{
    apply_credit, apply_debit, channel_ledger_from_l1, next_bill_auto_number, payer_available_mei,
};
use crate::node::NodeClient;
use crate::operation::{
    IdempotencyRecord, ReservationStatus, request_commitment, validate_operation_identity,
};
use crate::routing::{PayeeRoute, resolve_payee_route};
use crate::storage::{
    HubPersistedState, PendingSettlement, acquire_state_lock, initialize_authenticated_state,
    load_state_file, save_state_file, state_commitment,
};
use crate::wire::{
    ChannelPayCompleteDocuments, ChannelWireInput, build_cross_channel_bill,
    build_same_channel_bill,
};

const PENDING_TTL_SECONDS: u64 = 300;
const MAX_PENDING_SETTLEMENTS: usize = 1024;

pub struct HubState {
    pub name: String,
    pub hub_address: String,
    pub node: NodeClient,
    pub hub_fee_mei: HacAmount,
    hub_signer: Option<HubSigner>,
    inner: RwLock<HubPersistedState>,
    state_path: Option<PathBuf>,
    journal: Option<AuthenticatedJournal>,
    recovery_required: AtomicBool,
    _state_lock: Option<fs::File>,
}

impl HubState {
    pub fn new(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: Option<PathBuf>,
        hub_fee_millimeis: u64,
        hub_secret_hex: Option<String>,
    ) -> HubResult<Self> {
        Self::initialize(
            name.into(),
            hub_address.into(),
            node_url.into(),
            state_path,
            hub_fee_millimeis,
            hub_secret_hex,
            None,
        )
    }

    pub fn new_secure(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: PathBuf,
        hub_fee_millimeis: u64,
        hub_secret_hex: Option<String>,
        journal_storage_key_hex: &str,
    ) -> HubResult<Self> {
        Self::initialize(
            name.into(),
            hub_address.into(),
            node_url.into(),
            Some(state_path),
            hub_fee_millimeis,
            hub_secret_hex,
            Some(journal_storage_key_hex),
        )
    }

    fn initialize(
        name: String,
        hub_address: String,
        node_url: String,
        state_path: Option<PathBuf>,
        hub_fee_millimeis: u64,
        hub_secret_hex: Option<String>,
        journal_storage_key_hex: Option<&str>,
    ) -> HubResult<Self> {
        if hub_fee_millimeis != 0 {
            return Err(HubError::State(
                "Fast Pay is fee-free; hub_fee_millimeis must be 0".into(),
            ));
        }
        if hub_address.trim().is_empty() {
            return Err(HubError::State("hub address is required".into()));
        }
        let hub_signer = hub_secret_hex
            .as_deref()
            .filter(|secret| !secret.trim().is_empty())
            .map(HubSigner::from_secret_hex)
            .transpose()?;
        if let Some(signer) = &hub_signer
            && signer.address() != hub_address.trim()
        {
            return Err(HubError::State(format!(
                "hub secret key address {} does not match HACASH_HUB_ADDRESS {}",
                signer.address(),
                hub_address.trim()
            )));
        }

        let state_lock = state_path
            .as_ref()
            .map(|path| acquire_state_lock(path))
            .transpose()?;
        let mut persisted = state_path
            .as_ref()
            .map(|path| load_state_file(path))
            .transpose()?
            .unwrap_or_default();
        let journal = match (state_path.as_ref(), journal_storage_key_hex) {
            (Some(path), Some(key_hex)) => {
                let mut key = hex::decode(key_hex.trim())
                    .map_err(|_| HubError::State("journal storage key must be hex".into()))?;
                if key.len() != 32 {
                    key.zeroize();
                    return Err(HubError::State(
                        "journal storage key must decode to exactly 32 bytes".into(),
                    ));
                }
                let journal = AuthenticatedJournal::open(
                    path.with_extension("journal.jsonl"),
                    &key,
                    JournalBinding {
                        wallet_scope: format!("hub:{}", hub_address.trim()),
                        hub_or_provider_identity: hub_address.trim().to_owned(),
                        channel_id: None,
                    },
                );
                key.zeroize();
                Some(journal?)
            }
            (None, Some(_)) => {
                return Err(HubError::State(
                    "durable state path is required when journal authentication is enabled".into(),
                ));
            }
            _ => None,
        };

        if let (Some(path), Some(journal)) = (state_path.as_ref(), journal.as_ref()) {
            initialize_authenticated_state(path, &mut persisted, journal, &hub_address)?;
        }
        let recovery_required = persisted
            .pending
            .values()
            .any(|pending| pending.status == ReservationStatus::RecoveryRequired);
        Ok(Self {
            name,
            hub_address,
            node: NodeClient::new(node_url),
            hub_fee_mei: HacAmount::ZERO,
            hub_signer,
            inner: RwLock::new(persisted),
            state_path,
            journal,
            recovery_required: AtomicBool::new(recovery_required),
            _state_lock: state_lock,
        })
    }

    pub fn health(&self) -> crate::api::HubHealth {
        let settlement_ready = self.hub_signer.is_some()
            && self.state_path.is_some()
            && self.journal.is_some()
            && !self.recovery_required.load(Ordering::Acquire);
        crate::api::HubHealth {
            ok: true,
            version: crate::api::HUB_API_VERSION,
            name: Some(self.name.clone()),
            hub_address: Some(self.hub_address.clone()),
            hub_fee_mei: Some(format_amount_mei(self.hub_fee_mei)),
            settlement_ready,
            cross_channel_ready: settlement_ready,
            external_rollback_anchor_ready: false,
            l1_dispute_path_ready: false,
            official_channelpay_ready: false,
            production_mainnet_ready: false,
            deployment_profile: Some("legacy_wallet_hub_v4_development".into()),
        }
    }

    pub fn payment_status(&self, payment_id: &str) -> Option<FastPayResponse> {
        let state = self.inner.read().ok()?;
        if let Some(payment) = state.payments.get(payment_id) {
            return Some(payment.clone());
        }
        let pending = state.pending.get(payment_id)?;
        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS {
            if pending.status.signature_may_exist() {
                let mut response = pending.response.clone();
                response.status = "recovery_required".into();
                response.summary = Some(
                    "Fast Pay has a durable signed reservation and requires reconciliation".into(),
                );
                return Some(response);
            }
            return Some(FastPayResponse {
                payment_id: payment_id.to_owned(),
                status: "expired".into(),
                bill_hex: None,
                summary: Some("Fast Pay expired before any signature was produced".into()),
            });
        }
        Some(pending.response.clone())
    }

    pub fn recipient_inbox(&self, payee: &str) -> Vec<FastPayInboxItem> {
        let now = unix_timestamp();
        let mut items = self
            .inner
            .read()
            .ok()
            .map(|state| {
                state
                    .pending
                    .iter()
                    .filter_map(|(payment_id, pending)| {
                        let payee_channel_id = pending.payee_channel_id.as_ref()?;
                        let bill_hex = pending.response.bill_hex.as_ref()?;
                        if pending.payee != payee
                            || pending.response.status != "awaiting_recipient"
                            || now.saturating_sub(pending.created_at) > PENDING_TTL_SECONDS
                        {
                            return None;
                        }
                        Some(FastPayInboxItem {
                            payment_id: payment_id.clone(),
                            idempotency_key: pending.idempotency_key.clone(),
                            payer: pending.payer.clone(),
                            payee: pending.payee.clone(),
                            amount: pending.amount.clone(),
                            channel_id: pending.channel_id.clone(),
                            payee_channel_id: payee_channel_id.clone(),
                            status: pending.response.status.clone(),
                            bill_hex: bill_hex.clone(),
                            summary: pending.response.summary.clone(),
                            created_at: pending.created_at,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        items.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        items
    }

    pub async fn settle_fast_pay(
        &self,
        request: &crate::api::FastPayRequest,
    ) -> HubResult<FastPayResponse> {
        self.ensure_settlement_ready()?;
        validate_operation_identity(request)?;
        let request_commitment = request_commitment(request);
        if let Some(response) =
            self.resume_persisted_before_signing(request, &request_commitment)?
        {
            return Ok(response);
        }
        if let Some(response) = self.idempotent_response(request, &request_commitment)? {
            return Ok(response);
        }
        let signer = self.hub_signer.as_ref().ok_or_else(|| {
            HubError::State(
                "hub settlement signer is not configured; refusing to prepare a payment".into(),
            )
        })?;
        let payer = request.payer.trim();
        let payee = request.payee.trim();
        let amount_wire = request.amount.trim();
        let channel_id = request.channel_id.trim();
        if payer.is_empty() || payee.is_empty() || payer == payee {
            return Err(HubError::Payment(
                "payer and payee must be different valid addresses".into(),
            ));
        }
        if payer == self.hub_address {
            return Err(HubError::Payment(
                "the reference hub accepts customer-originated payments only".into(),
            ));
        }

        let amount_mei = parse_amount_mei(amount_wire)?;
        if amount_mei == HacAmount::ZERO {
            return Err(HubError::Payment("amount must be positive".into()));
        }

        let payer_channel = self.node.query_channel(channel_id).await?;
        if !payer_channel.is_open() {
            return Err(HubError::Channel("payer channel is not open".into()));
        }
        if payer_channel.id != channel_id {
            return Err(HubError::Channel("payer channel id mismatch".into()));
        }
        let payer_side = payer_channel
            .party_side(payer)
            .ok_or_else(|| HubError::Payment(format!("payer {payer} not in payer channel")))?;
        let hub_side = payer_channel.party_side(&self.hub_address).ok_or_else(|| {
            HubError::Payment("payer channel is not connected to this hub".into())
        })?;
        if hub_side == payer_side {
            return Err(HubError::Payment(
                "payer and hub cannot occupy the same channel side".into(),
            ));
        }

        let payee_route = resolve_payee_route(
            &self.node,
            &self.hub_address,
            &payer_channel,
            channel_id,
            payee,
        )
        .await?;

        let payee_channel_l1 = match &payee_route {
            PayeeRoute::CrossChannel { channel_id, .. } => {
                let channel = self.node.query_channel(channel_id).await?;
                if !channel.is_open()
                    || channel.id != *channel_id
                    || channel.party_side(payee).is_none()
                    || channel.party_side(&self.hub_address).is_none()
                {
                    return Err(HubError::Payment(
                        "recipient Fast Pay channel is not open or is not connected to this hub"
                            .into(),
                    ));
                }
                Some(channel)
            }
            PayeeRoute::SameChannel { .. } => None,
        };

        let timestamp = unix_timestamp();
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        if let Some(response) =
            idempotent_response_from_state(&guard, request, &request_commitment)?
        {
            return Ok(response);
        }
        if guard.pending.len() >= MAX_PENDING_SETTLEMENTS {
            return Err(HubError::State(
                "too many pending settlements; retry after pending proposals expire".into(),
            ));
        }

        let payee_channel_id = payee_channel_l1.as_ref().map(|channel| channel.id.as_str());
        if guard.pending.values().any(|pending| {
            if pending.status.is_terminal() {
                return false;
            }
            let pending_payee_channel = pending.payee_channel_id.as_deref();
            pending.channel_id == channel_id
                || pending_payee_channel == Some(channel_id)
                || payee_channel_id == Some(pending.channel_id.as_str())
                || (payee_channel_id.is_some() && payee_channel_id == pending_payee_channel)
        }) {
            return Err(HubError::State(
                "channel has an active Fast Pay reservation; reconcile it before another payment"
                    .into(),
            ));
        }

        let initial_payer_ledger = channel_ledger_from_l1(&payer_channel)?;
        let base_ledger = guard
            .channels
            .get(channel_id)
            .cloned()
            .unwrap_or(initial_payer_ledger);
        if payer_available_mei(&base_ledger, payer_side) < amount_mei {
            return Err(HubError::Payment(format!(
                "insufficient channel balance: need {amount_mei} HAC"
            )));
        }
        let mut next_ledger = base_ledger.clone();
        apply_debit(&mut next_ledger, payer_side, amount_mei)?;
        next_ledger.bill_auto_number = next_bill_auto_number(&base_ledger, &payer_channel)?;

        let (route_label, payee_channel_id, payee_base_ledger, payee_next_ledger, payee_side) =
            match &payee_route {
                PayeeRoute::SameChannel { side } => {
                    apply_credit(&mut next_ledger, *side, amount_mei)?;
                    ("same_channel", None, None, None, None)
                }
                PayeeRoute::CrossChannel { channel_id, side } => {
                    apply_credit(&mut next_ledger, hub_side, amount_mei)?;
                    let payee_channel = payee_channel_l1
                        .as_ref()
                        .ok_or_else(|| HubError::State("recipient channel missing".into()))?;
                    let payee_hub_side =
                        payee_channel.party_side(&self.hub_address).ok_or_else(|| {
                            HubError::State("hub missing from recipient channel".into())
                        })?;
                    if payee_hub_side == *side {
                        return Err(HubError::Payment(
                            "recipient and hub cannot occupy the same channel side".into(),
                        ));
                    }
                    let initial_payee_ledger = channel_ledger_from_l1(payee_channel)?;
                    let base = guard
                        .channels
                        .get(channel_id)
                        .cloned()
                        .unwrap_or(initial_payee_ledger);
                    if payer_available_mei(&base, payee_hub_side) < amount_mei {
                        return Err(HubError::Payment(format!(
                            "hub has insufficient recipient-channel liquidity: need {amount_mei} HAC"
                        )));
                    }
                    let mut next = base.clone();
                    apply_debit(&mut next, payee_hub_side, amount_mei)?;
                    apply_credit(&mut next, *side, amount_mei)?;
                    next.bill_auto_number = next_bill_auto_number(&base, payee_channel)?;
                    (
                        "cross_channel",
                        Some(channel_id.clone()),
                        Some(base),
                        Some(next),
                        Some(*side),
                    )
                }
            };

        let payer_wire = ChannelWireInput {
            channel: payer_channel.clone(),
            channel_id_hex: channel_id.to_owned(),
            left_balance_mei: next_ledger.left_balance_mei,
            right_balance_mei: next_ledger.right_balance_mei,
            left_satoshi: payer_channel.left.satoshi,
            right_satoshi: payer_channel.right.satoshi,
            bill_auto_number: next_ledger.bill_auto_number,
        };

        let mut documents = if route_label == "same_channel" {
            build_same_channel_bill(&payer_wire, payer_side, amount_mei, timestamp)?
        } else {
            let payee_channel = payee_channel_l1
                .as_ref()
                .ok_or_else(|| HubError::State("recipient channel missing".into()))?;
            let payee_channel_id = payee_channel_id
                .as_ref()
                .ok_or_else(|| HubError::State("recipient channel id missing".into()))?;
            let payee_ledger = payee_next_ledger
                .as_ref()
                .ok_or_else(|| HubError::State("recipient ledger missing".into()))?;
            let payee_wire = ChannelWireInput {
                channel: payee_channel.clone(),
                channel_id_hex: payee_channel_id.clone(),
                left_balance_mei: payee_ledger.left_balance_mei,
                right_balance_mei: payee_ledger.right_balance_mei,
                left_satoshi: payee_channel.left.satoshi,
                right_satoshi: payee_channel.right.satoshi,
                bill_auto_number: payee_ledger.bill_auto_number,
            };
            build_cross_channel_bill(
                &payer_wire,
                payer_side,
                amount_mei,
                &payee_wire,
                payee_side.ok_or_else(|| HubError::State("recipient side missing".into()))?,
                amount_mei,
                timestamp,
            )?
        };
        let payment_id = request.operation_id.clone();
        let unsigned_state_commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        let summary = if route_label == "same_channel" {
            format!("Fast Pay prepared {amount_mei} HAC to {payee} on-channel with no fee")
        } else {
            format!(
                "Fast Pay prepared {amount_mei} HAC to {payee}; waiting for recipient confirmation with no fee"
            )
        };
        let unsigned_response = FastPayResponse {
            payment_id: payment_id.clone(),
            status: "persisted_before_signing".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: Some(summary.clone()),
        };
        let pending = PendingSettlement {
            created_at: timestamp,
            operation_id: payment_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_commitment: request_commitment.clone(),
            status: ReservationStatus::PersistedBeforeSigning,
            unsigned_state_commitment: unsigned_state_commitment.clone(),
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: format_amount_mei(amount_mei),
            channel_id: channel_id.to_owned(),
            channel_reuse_version: payer_channel.reuse_version,
            base_ledger,
            next_ledger,
            payee_channel_id,
            payee_base_ledger,
            payee_next_ledger,
            response: unsigned_response,
        };

        let mut next_state = guard.clone();
        next_state.idempotency.insert(
            request.idempotency_key.clone(),
            IdempotencyRecord {
                operation_id: payment_id.clone(),
                request_commitment: request_commitment.clone(),
                created_at: timestamp,
            },
        );
        next_state
            .pending
            .insert(payment_id.clone(), pending.clone());
        next_state
            .channels
            .entry(pending.channel_id.clone())
            .or_insert_with(|| pending.base_ledger.clone());
        if let (Some(channel_id), Some(base)) = (
            pending.payee_channel_id.clone(),
            pending.payee_base_ledger.clone(),
        ) {
            next_state.channels.entry(channel_id).or_insert(base);
        }
        self.commit_transition(
            &mut guard,
            next_state,
            &pending,
            JournalPhase::StatePersistedBeforeSigning,
        )?;

        // The exact reservation and unsigned sign hash are durable before signing.
        signer.sign_documents(&mut documents)?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(
                "hub failed to verify its own settlement signature".into(),
            ));
        }

        let response = FastPayResponse {
            payment_id: payment_id.clone(),
            status: "pending".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: Some(summary),
        };
        let mut signed_pending = guard
            .pending
            .get(&payment_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
        signed_pending.status = ReservationStatus::Signed;
        signed_pending.response = response.clone();
        let mut signed_state = guard.clone();
        signed_state
            .pending
            .insert(payment_id, signed_pending.clone());
        self.commit_transition(
            &mut guard,
            signed_state,
            &signed_pending,
            JournalPhase::SignatureProduced,
        )?;
        Ok(response)
    }

    pub fn confirm_fast_pay(
        &self,
        payment_id: &str,
        idempotency_key: &str,
        signed_bill_hex: &str,
    ) -> HubResult<FastPayResponse> {
        self.ensure_settlement_ready()?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        if let Some(completed) = guard.payments.get(payment_id) {
            if guard
                .idempotency
                .get(idempotency_key)
                .is_none_or(|record| record.operation_id != payment_id)
            {
                return Err(HubError::Payment(
                    "idempotency conflict: confirmation key changed".into(),
                ));
            }
            let final_hex = completed
                .bill_hex
                .as_deref()
                .ok_or_else(|| HubError::State("completed payment bill missing".into()))?;
            let final_bill = ChannelPayCompleteDocuments::from_bill_hex(final_hex)?;
            let submitted = ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex)?;
            if final_bill.chain_payment.sign_stuff_hash()
                != submitted.chain_payment.sign_stuff_hash()
            {
                return Err(HubError::Payment(
                    "idempotency conflict: confirmation payload changed".into(),
                ));
            }
            return Ok(completed.clone());
        }
        let mut pending = guard
            .pending
            .get(payment_id)
            .cloned()
            .ok_or_else(|| HubError::NotFound(format!("pending payment {payment_id}")))?;
        if pending.idempotency_key != idempotency_key {
            return Err(HubError::Payment(
                "idempotency conflict: confirmation key changed".into(),
            ));
        }

        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS
            && pending.status.signature_may_exist()
        {
            pending.status = ReservationStatus::RecoveryRequired;
            pending.response.status = "recovery_required".into();
            pending.response.summary =
                Some("signed Fast Pay reservation expired and requires reconciliation".into());
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), pending.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &pending,
                JournalPhase::RecoveryStarted,
            )?;
            return Err(HubError::State("RecoveryRequired".into()));
        }

        let expected_hex = pending
            .response
            .bill_hex
            .as_deref()
            .ok_or_else(|| HubError::State("pending settlement bill missing".into()))?;
        let mut expected = ChannelPayCompleteDocuments::from_bill_hex(expected_hex)?;
        let submitted = ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex)?;
        if !expected.prove_bindings_valid() || !submitted.prove_bindings_valid() {
            return Err(HubError::Payment(
                "settlement prove bodies do not match the signed channel checkers".into(),
            ));
        }
        if expected.chain_payment.sign_stuff_hash() != submitted.chain_payment.sign_stuff_hash() {
            return Err(HubError::Payment(
                "confirmed settlement does not match the prepared bill".into(),
            ));
        }
        expected
            .chain_payment
            .merge_verified_signatures(&submitted.chain_payment)?;

        if !expected
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            return Err(HubError::Payment(
                "confirmed settlement is missing the verified hub signature".into(),
            ));
        }
        if pending.payer.is_empty()
            || !expected
                .chain_payment
                .signature_verified_for_readable(&pending.payer)
        {
            return Err(HubError::Payment(
                "confirmed settlement is missing the verified payer signature".into(),
            ));
        }

        let merged_bill_hex = expected.to_bill_hex();
        let is_cross_channel = pending.payee_channel_id.is_some();
        if is_cross_channel && !expected.chain_payment.all_signatures_verified() {
            let mut awaiting = pending.clone();
            awaiting.response.status = "awaiting_recipient".into();
            awaiting.response.bill_hex = Some(merged_bill_hex);
            awaiting.response.summary = Some(format!(
                "Fast Pay {} HAC from {} is waiting for recipient confirmation",
                pending.amount, pending.payer
            ));
            awaiting.status = ReservationStatus::AwaitingRecipientConfirmation;
            let response = awaiting.response.clone();
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), awaiting.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &awaiting,
                JournalPhase::RecipientConfirmed,
            )?;
            return Ok(response);
        }

        if !expected.chain_payment.all_signatures_verified() {
            return Err(HubError::Payment(
                "confirmed settlement is missing required verified signatures".into(),
            ));
        }
        if is_cross_channel
            && (pending.payee.is_empty()
                || !expected
                    .chain_payment
                    .signature_verified_for_readable(&pending.payee))
        {
            return Err(HubError::Payment(
                "confirmed routed settlement is missing the verified recipient signature".into(),
            ));
        }

        let payer_is_current = guard
            .channels
            .get(&pending.channel_id)
            .is_some_and(|ledger| ledger == &pending.base_ledger);
        let payee_is_current = match (
            pending.payee_channel_id.as_ref(),
            pending.payee_base_ledger.as_ref(),
        ) {
            (Some(channel_id), Some(base)) => guard
                .channels
                .get(channel_id)
                .is_some_and(|ledger| ledger == base),
            (None, None) => true,
            _ => false,
        };
        if !payer_is_current || !payee_is_current {
            let mut recovery = pending.clone();
            recovery.status = ReservationStatus::RecoveryRequired;
            recovery.response.status = "recovery_required".into();
            recovery.response.summary = Some(
                "prepared settlement conflicts with current channel state; reconciliation required"
                    .into(),
            );
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), recovery.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &recovery,
                JournalPhase::RecoveryStarted,
            )?;
            return Err(HubError::State("ChannelStateRollbackDetected".into()));
        }

        let summary = if is_cross_channel {
            Some(format!(
                "Fast Pay settled {} HAC to {} with no fee",
                pending.amount, pending.payee
            ))
        } else {
            pending
                .response
                .summary
                .clone()
                .map(|summary| summary.replace("prepared", "settled"))
        };
        let response = FastPayResponse {
            payment_id: payment_id.to_owned(),
            status: "settled".into(),
            bill_hex: Some(merged_bill_hex),
            summary,
        };

        let mut next_state = guard.clone();
        next_state
            .channels
            .insert(pending.channel_id.clone(), pending.next_ledger.clone());
        if let (Some(channel_id), Some(next_ledger)) = (
            pending.payee_channel_id.clone(),
            pending.payee_next_ledger.clone(),
        ) {
            next_state.channels.insert(channel_id, next_ledger);
        }
        next_state.pending.remove(payment_id);
        next_state
            .payments
            .insert(payment_id.to_owned(), response.clone());
        next_state
            .completed_request_commitments
            .insert(payment_id.to_owned(), pending.request_commitment.clone());
        let mut committed = pending;
        committed.status = ReservationStatus::Committed;
        committed.response = response.clone();
        self.commit_transition(
            &mut guard,
            next_state,
            &committed,
            JournalPhase::PaymentCommitted,
        )?;
        Ok(response)
    }

    fn ensure_settlement_ready(&self) -> HubResult<()> {
        if self.recovery_required.load(Ordering::Acquire) {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        if self.state_path.is_none() || self.journal.is_none() {
            return Err(HubError::State(
                "durable authenticated L2 storage is required before signing".into(),
            ));
        }
        Ok(())
    }

    fn resume_persisted_before_signing(
        &self,
        request: &crate::api::FastPayRequest,
        commitment: &str,
    ) -> HubResult<Option<FastPayResponse>> {
        let pending = {
            let state = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let Some(response) = idempotent_response_from_state(&state, request, commitment)?
            else {
                return Ok(None);
            };
            let Some(pending) = state.pending.get(&response.payment_id) else {
                return Ok(None);
            };
            if pending.status != ReservationStatus::PersistedBeforeSigning {
                return Ok(None);
            }
            pending.clone()
        };

        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("hub settlement signer is not configured".into()))?;
        let unsigned_hex =
            pending.response.bill_hex.as_deref().ok_or_else(|| {
                HubError::State("durable unsigned settlement bill is missing".into())
            })?;
        let mut documents = ChannelPayCompleteDocuments::from_bill_hex(unsigned_hex)?;
        if !documents.prove_bindings_valid()
            || hex::encode(documents.chain_payment.sign_stuff_hash())
                != pending.unsigned_state_commitment
        {
            return Err(HubError::State(
                "RecoveryRequired: durable unsigned settlement commitment is invalid".into(),
            ));
        }
        signer.sign_documents(&mut documents)?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            return Err(HubError::State(
                "hub failed to verify its recovered settlement signature".into(),
            ));
        }

        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let current = guard
            .pending
            .get(&pending.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
        if current.status != ReservationStatus::PersistedBeforeSigning {
            return idempotent_response_from_state(&guard, request, commitment);
        }
        if current.request_commitment != pending.request_commitment
            || current.unsigned_state_commitment != pending.unsigned_state_commitment
        {
            return Err(HubError::State(
                "RecoveryRequired: durable reservation changed during signature recovery".into(),
            ));
        }
        let response = FastPayResponse {
            payment_id: current.operation_id.clone(),
            status: "pending".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: current.response.summary.clone(),
        };
        let mut signed = current;
        signed.status = ReservationStatus::Signed;
        signed.response = response.clone();
        let mut next_state = guard.clone();
        next_state
            .pending
            .insert(signed.operation_id.clone(), signed.clone());
        self.commit_transition(
            &mut guard,
            next_state,
            &signed,
            JournalPhase::SignatureProduced,
        )?;
        Ok(Some(response))
    }

    fn idempotent_response(
        &self,
        request: &crate::api::FastPayRequest,
        commitment: &str,
    ) -> HubResult<Option<FastPayResponse>> {
        let state = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        idempotent_response_from_state(&state, request, commitment)
    }

    fn commit_transition(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        operation: &PendingSettlement,
        phase: JournalPhase,
    ) -> HubResult<()> {
        self.ensure_settlement_ready()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let path = self
            .state_path
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state path is unavailable".into()))?;
        let previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        let new_state_commitment = state_commitment(&next_state)?;
        let amount = parse_amount_mei(&operation.amount)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: operation.channel_id.clone(),
            channel_reuse_version: operation.channel_reuse_version,
            operation_id: operation.operation_id.clone(),
            operation_type: JournalOperationType::FastPay,
            operation_phase: phase,
            amount_units: amount.as_millimeis(),
            sender: operation.payer.clone(),
            recipient: operation.payee.clone(),
            previous_state_commitment,
            new_state_commitment: new_state_commitment.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: Some(operation.next_ledger.bill_auto_number),
            unsigned_state_commitment: Some(operation.unsigned_state_commitment.clone()),
            created_at: unix_timestamp(),
        })?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = new_state_commitment.clone();
        if let Err(error) = save_state_file(path, &next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: journal advanced but materialized state was not durable: {error}"
            )));
        }
        let head = JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: new_state_commitment,
        };
        if let Err(error) = journal.write_checkpoint(&head) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
