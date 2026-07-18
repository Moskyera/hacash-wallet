use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::amount::{format_amount_mei, parse_amount_mei};
use crate::api::{FastPayInboxItem, FastPayResponse};
use crate::error::{HubError, HubResult};
use crate::hub_signer::HubSigner;
use crate::node::{ChannelInfo, ChannelSide, NodeClient};
use crate::routing::{PayeeRoute, resolve_payee_route};
use crate::wire::{
    ChannelPayCompleteDocuments, ChannelWireInput, build_cross_channel_bill,
    build_same_channel_bill,
};

const PENDING_TTL_SECONDS: u64 = 300;
const MAX_PENDING_SETTLEMENTS: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ChannelLedger {
    pub left_balance_mei: f64,
    pub right_balance_mei: f64,
    pub bill_auto_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSettlement {
    pub created_at: u64,
    #[serde(default)]
    pub payer: String,
    #[serde(default)]
    pub payee: String,
    #[serde(default)]
    pub amount: String,
    pub channel_id: String,
    pub base_ledger: ChannelLedger,
    pub next_ledger: ChannelLedger,
    #[serde(default)]
    pub payee_channel_id: Option<String>,
    #[serde(default)]
    pub payee_base_ledger: Option<ChannelLedger>,
    #[serde(default)]
    pub payee_next_ledger: Option<ChannelLedger>,
    pub response: FastPayResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubPersistedState {
    pub channels: HashMap<String, ChannelLedger>,
    pub payments: HashMap<String, FastPayResponse>,
    #[serde(default)]
    pub pending: HashMap<String, PendingSettlement>,
}

pub struct HubState {
    pub name: String,
    pub hub_address: String,
    pub node: NodeClient,
    pub hub_fee_mei: f64,
    hub_signer: Option<HubSigner>,
    inner: RwLock<HubPersistedState>,
    state_path: Option<PathBuf>,
}

impl HubState {
    pub fn new(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: Option<PathBuf>,
        hub_fee_mei: f64,
        hub_secret_hex: Option<String>,
    ) -> HubResult<Self> {
        if !hub_fee_mei.is_finite() || hub_fee_mei.abs() > f64::EPSILON {
            return Err(HubError::State(
                "Fast Pay is fee-free; hub_fee_mei must be 0".into(),
            ));
        }
        let hub_address = hub_address.into();
        if hub_address.trim().is_empty() {
            return Err(HubError::State("hub address is required".into()));
        }
        let hub_signer = hub_secret_hex
            .as_deref()
            .filter(|s| !s.trim().is_empty())
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
        let persisted = if let Some(path) = &state_path {
            load_state_file(path)?
        } else {
            HubPersistedState::default()
        };
        Ok(Self {
            name: name.into(),
            hub_address,
            node: NodeClient::new(node_url),
            hub_fee_mei,
            hub_signer,
            inner: RwLock::new(persisted),
            state_path,
        })
    }

    pub fn health(&self) -> crate::api::HubHealth {
        let settlement_ready = self.hub_signer.is_some();
        crate::api::HubHealth {
            ok: true,
            version: crate::api::HUB_API_VERSION,
            name: Some(self.name.clone()),
            hub_address: Some(self.hub_address.clone()),
            hub_fee_mei: Some(self.hub_fee_mei),
            settlement_ready,
            cross_channel_ready: settlement_ready,
        }
    }

    pub fn payment_status(&self, payment_id: &str) -> Option<FastPayResponse> {
        let state = self.inner.read().ok()?;
        if let Some(payment) = state.payments.get(payment_id) {
            return Some(payment.clone());
        }
        let pending = state.pending.get(payment_id)?;
        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS {
            return Some(FastPayResponse {
                payment_id: payment_id.to_owned(),
                status: "expired".into(),
                bill_hex: None,
                summary: Some(
                    "Fast Pay expired before all required signatures were collected".into(),
                ),
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
        payer: &str,
        payee: &str,
        amount_wire: &str,
        channel_id: &str,
    ) -> HubResult<FastPayResponse> {
        let signer = self.hub_signer.as_ref().ok_or_else(|| {
            HubError::State(
                "hub settlement signer is not configured; refusing to prepare a payment".into(),
            )
        })?;
        let payer = payer.trim();
        let payee = payee.trim();
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
        if !amount_mei.is_finite() || amount_mei <= 0.0 {
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
        guard.pending.retain(|_, pending| {
            timestamp.saturating_sub(pending.created_at) <= PENDING_TTL_SECONDS
        });
        if guard.pending.len() >= MAX_PENDING_SETTLEMENTS {
            return Err(HubError::State(
                "too many pending settlements; retry after pending proposals expire".into(),
            ));
        }

        let base_ledger = guard
            .channels
            .entry(channel_id.to_owned())
            .or_insert_with(|| channel_ledger_from_l1(&payer_channel))
            .clone();
        if payer_available_mei(&base_ledger, payer_side) < amount_mei {
            return Err(HubError::Payment(format!(
                "insufficient channel balance: need {amount_mei} HAC"
            )));
        }
        let mut next_ledger = base_ledger.clone();
        apply_debit(&mut next_ledger, payer_side, amount_mei);
        next_ledger.bill_auto_number = next_bill_auto_number(&base_ledger, &payer_channel);

        let (route_label, payee_channel_id, payee_base_ledger, payee_next_ledger, payee_side) =
            match &payee_route {
                PayeeRoute::SameChannel { side } => {
                    apply_credit(&mut next_ledger, *side, amount_mei);
                    ("same_channel", None, None, None, None)
                }
                PayeeRoute::CrossChannel { channel_id, side } => {
                    apply_credit(&mut next_ledger, hub_side, amount_mei);
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
                    let base = guard
                        .channels
                        .entry(channel_id.clone())
                        .or_insert_with(|| channel_ledger_from_l1(payee_channel))
                        .clone();
                    if payer_available_mei(&base, payee_hub_side) < amount_mei {
                        return Err(HubError::Payment(format!(
                            "hub has insufficient recipient-channel liquidity: need {amount_mei} HAC"
                        )));
                    }
                    let mut next = base.clone();
                    apply_debit(&mut next, payee_hub_side, amount_mei);
                    apply_credit(&mut next, *side, amount_mei);
                    next.bill_auto_number = next_bill_auto_number(&base, payee_channel);
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
        signer.sign_documents(&mut documents)?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            return Err(HubError::State(
                "hub failed to verify its own settlement signature".into(),
            ));
        }

        let payment_id = uuid::Uuid::new_v4().to_string();
        let summary = if route_label == "same_channel" {
            format!("Fast Pay prepared {amount_mei} HAC to {payee} on-channel with no fee")
        } else {
            format!(
                "Fast Pay prepared {amount_mei} HAC to {payee}; waiting for recipient confirmation with no fee"
            )
        };
        let response = FastPayResponse {
            payment_id: payment_id.clone(),
            status: "pending".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: Some(summary),
        };
        let pending = PendingSettlement {
            created_at: timestamp,
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: format_amount_mei(amount_mei),
            channel_id: channel_id.to_owned(),
            base_ledger,
            next_ledger,
            payee_channel_id,
            payee_base_ledger,
            payee_next_ledger,
            response: response.clone(),
        };

        let mut next_state = guard.clone();
        next_state.pending.insert(payment_id, pending);
        self.commit_state(&mut guard, next_state)?;
        Ok(response)
    }

    pub fn confirm_fast_pay(
        &self,
        payment_id: &str,
        signed_bill_hex: &str,
    ) -> HubResult<FastPayResponse> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let pending = guard
            .pending
            .get(payment_id)
            .cloned()
            .ok_or_else(|| HubError::NotFound(format!("pending payment {payment_id}")))?;

        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS {
            let mut next_state = guard.clone();
            next_state.pending.remove(payment_id);
            self.commit_state(&mut guard, next_state)?;
            return Err(HubError::Payment(
                "pending settlement expired; prepare the payment again".into(),
            ));
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
            let response = awaiting.response.clone();
            let mut next_state = guard.clone();
            next_state.pending.insert(payment_id.to_owned(), awaiting);
            self.commit_state(&mut guard, next_state)?;
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
            let mut next_state = guard.clone();
            next_state.pending.remove(payment_id);
            self.commit_state(&mut guard, next_state)?;
            return Err(HubError::Payment(
                "prepared settlement is stale; prepare the payment again".into(),
            ));
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
            .insert(pending.channel_id.clone(), pending.next_ledger);
        if let (Some(channel_id), Some(next_ledger)) =
            (pending.payee_channel_id, pending.payee_next_ledger)
        {
            next_state.channels.insert(channel_id, next_ledger);
        }
        next_state.pending.remove(payment_id);
        next_state
            .payments
            .insert(payment_id.to_owned(), response.clone());
        self.commit_state(&mut guard, next_state)?;
        Ok(response)
    }

    fn commit_state(
        &self,
        guard: &mut HubPersistedState,
        next_state: HubPersistedState,
    ) -> HubResult<()> {
        if let Some(path) = &self.state_path {
            save_state_file(path, &next_state)?;
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

fn channel_ledger_from_l1(channel: &ChannelInfo) -> ChannelLedger {
    ChannelLedger {
        left_balance_mei: parse_amount_mei(&channel.left.hacash).unwrap_or(0.0),
        right_balance_mei: parse_amount_mei(&channel.right.hacash).unwrap_or(0.0),
        bill_auto_number: channel.l1_bill_auto_floor(),
    }
}

/// Next monotonic bill serial: `max(hub history, L1 assert floor) + 1`.
fn next_bill_auto_number(ledger: &ChannelLedger, channel: &ChannelInfo) -> u64 {
    let last = ledger.bill_auto_number.max(channel.l1_bill_auto_floor());
    last.saturating_add(1)
}

fn payer_available_mei(ledger: &ChannelLedger, side: ChannelSide) -> f64 {
    match side {
        ChannelSide::Left => ledger.left_balance_mei,
        ChannelSide::Right => ledger.right_balance_mei,
    }
}

fn apply_debit(ledger: &mut ChannelLedger, side: ChannelSide, amount_mei: f64) {
    match side {
        ChannelSide::Left => ledger.left_balance_mei -= amount_mei,
        ChannelSide::Right => ledger.right_balance_mei -= amount_mei,
    }
}

fn apply_credit(ledger: &mut ChannelLedger, side: ChannelSide, amount_mei: f64) {
    match side {
        ChannelSide::Left => ledger.left_balance_mei += amount_mei,
        ChannelSide::Right => ledger.right_balance_mei += amount_mei,
    }
}

fn load_state_file(path: &Path) -> HubResult<HubPersistedState> {
    if !path.exists() {
        return Ok(HubPersistedState::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| HubError::State(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| HubError::State(e.to_string()))
}

fn save_state_file(path: &Path, state: &HubPersistedState) -> HubResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| HubError::State(e.to_string()))?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| HubError::State(e.to_string()))?;
    fs::write(path, json).map_err(|e| HubError::State(e.to_string()))
}
