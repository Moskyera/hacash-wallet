use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::amount::{format_amount_mei, parse_amount_mei};
use crate::fee_payer::HubFeePayer;
use crate::api::FastPayResponse;
use crate::hub_signer::HubSigner;
use crate::wire::{
    build_cross_channel_bill, build_same_channel_bill, ChannelWireInput,
};
use crate::error::{HubError, HubResult};
use crate::node::{ChannelInfo, ChannelSide, NodeClient};
use crate::routing::{resolve_payee_route, PayeeRoute};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelLedger {
    pub left_balance_mei: f64,
    pub right_balance_mei: f64,
    pub bill_auto_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubPersistedState {
    pub channels: HashMap<String, ChannelLedger>,
    pub payments: HashMap<String, FastPayResponse>,
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
        let hub_address = hub_address.into();
        if hub_address.trim().is_empty() {
            return Err(HubError::State("hub address is required".into()));
        }
        let hub_signer = hub_secret_hex
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(HubSigner::from_secret_hex)
            .transpose()?;
        if let Some(signer) = &hub_signer {
            if signer.address() != hub_address.trim() {
                return Err(HubError::State(format!(
                    "hub secret key address {} does not match HACASH_HUB_ADDRESS {}",
                    signer.address(),
                    hub_address.trim()
                )));
            }
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
        crate::api::HubHealth {
            ok: true,
            version: crate::api::HUB_API_VERSION,
            name: Some(self.name.clone()),
            hub_address: Some(self.hub_address.clone()),
            hub_fee_mei: Some(self.hub_fee_mei),
        }
    }

    pub fn payment_status(&self, payment_id: &str) -> Option<FastPayResponse> {
        self.inner
            .read()
            .ok()
            .and_then(|s| s.payments.get(payment_id).cloned())
    }

    pub async fn settle_fast_pay(
        &self,
        payer: &str,
        payee: &str,
        amount_wire: &str,
        channel_id: &str,
        fee_payer: HubFeePayer,
    ) -> HubResult<FastPayResponse> {
        let amount_mei = parse_amount_mei(amount_wire)?;
        if amount_mei <= 0.0 {
            return Err(HubError::Payment("amount must be positive".into()));
        }
        let (payer_debit, payee_credit) = match fee_payer {
            HubFeePayer::Sender => (amount_mei + self.hub_fee_mei, amount_mei),
            HubFeePayer::Recipient => {
                if amount_mei <= self.hub_fee_mei {
                    return Err(HubError::Payment(format!(
                        "amount must exceed hub fee ({:.3} HAC) when recipient pays fee",
                        self.hub_fee_mei
                    )));
                }
                (amount_mei, amount_mei - self.hub_fee_mei)
            }
        };

        let payer_channel = self.node.query_channel(channel_id).await?;
        if !payer_channel.is_open() {
            return Err(HubError::Channel("channel is not open".into()));
        }
        if payer_channel.id != channel_id {
            return Err(HubError::Channel("channel id mismatch".into()));
        }

        let payer_side = payer_channel
            .party_side(payer)
            .ok_or_else(|| HubError::Payment(format!("payer {payer} not in channel")))?;

        let payee_route = resolve_payee_route(
            &self.node,
            &self.hub_address,
            &payer_channel,
            channel_id,
            payee,
        )
        .await?;

        let payee_channel_l1 = match &payee_route {
            PayeeRoute::CrossChannel { channel_id: id, .. } => {
                Some(self.node.query_channel(id).await?)
            }
            PayeeRoute::SameChannel { .. } => None,
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;

        {
            let payer_ledger = guard
                .channels
                .entry(channel_id.to_owned())
                .or_insert_with(|| channel_ledger_from_l1(&payer_channel));

            if payer_available_mei(payer_ledger, payer_side) < payer_debit {
                return Err(HubError::Payment(format!(
                    "insufficient channel balance: need {payer_debit} HAC"
                )));
            }

            apply_debit(payer_ledger, payer_side, payer_debit);
            payer_ledger.bill_auto_number =
                next_bill_auto_number(payer_ledger, &payer_channel);

            if let PayeeRoute::SameChannel { side } = &payee_route {
                apply_credit(payer_ledger, *side, payee_credit);
            }
        }

        let (route_label, payee_channel_id, _payee_balances) = match payee_route {
            PayeeRoute::SameChannel { .. } => ("same_channel", None, None),
            PayeeRoute::CrossChannel {
                channel_id: payee_ch_id,
                side,
            } => {
                let payee_channel = payee_channel_l1
                    .as_ref()
                    .ok_or_else(|| HubError::State("payee channel missing".into()))?;
                let payee_ledger = guard
                    .channels
                    .entry(payee_ch_id.clone())
                    .or_insert_with(|| channel_ledger_from_l1(payee_channel));
                apply_credit(payee_ledger, side, payee_credit);
                payee_ledger.bill_auto_number =
                    next_bill_auto_number(payee_ledger, payee_channel);
                let balances = Some((
                    format_amount_mei(payee_ledger.left_balance_mei),
                    format_amount_mei(payee_ledger.right_balance_mei),
                ));
                ("cross_channel", Some(payee_ch_id), balances)
            }
        };

        let payer_ledger = guard
            .channels
            .get(channel_id)
            .ok_or_else(|| HubError::State("payer ledger missing".into()))?;

        let payment_id = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let fee_note = match fee_payer {
            HubFeePayer::Sender => format!(
                "fee {:.3} HAC paid by sender",
                self.hub_fee_mei
            ),
            HubFeePayer::Recipient => format!(
                "fee {:.3} HAC deducted from recipient (receives {payee_credit:.3} HAC)",
                self.hub_fee_mei
            ),
        };
        let summary = match route_label {
            "same_channel" => format!(
                "Fast Pay settled {amount_mei} HAC to {payee} on-channel ({fee_note})"
            ),
            _ => format!(
                "Fast Pay routed {amount_mei} HAC to {payee} via channel {} ({fee_note})",
                payee_channel_id.as_deref().unwrap_or("?"),
            ),
        };

        let payer_wire = ChannelWireInput {
            channel: payer_channel.clone(),
            channel_id_hex: channel_id.to_owned(),
            left_balance_mei: payer_ledger.left_balance_mei,
            right_balance_mei: payer_ledger.right_balance_mei,
            left_satoshi: payer_channel.left.satoshi,
            right_satoshi: payer_channel.right.satoshi,
            bill_auto_number: payer_ledger.bill_auto_number,
        };

        let mut documents = if route_label == "same_channel" {
            build_same_channel_bill(&payer_wire, payer_debit, timestamp)?
        } else {
            let payee_ch_id = payee_channel_id
                .clone()
                .ok_or_else(|| HubError::State("payee channel id missing".into()))?;
            let payee_channel = payee_channel_l1
                .as_ref()
                .ok_or_else(|| HubError::State("payee channel missing".into()))?;
            let payee_ledger = guard
                .channels
                .get(&payee_ch_id)
                .ok_or_else(|| HubError::State("payee ledger missing".into()))?;
            let payee_wire = ChannelWireInput {
                channel: payee_channel.clone(),
                channel_id_hex: payee_ch_id,
                left_balance_mei: payee_ledger.left_balance_mei,
                right_balance_mei: payee_ledger.right_balance_mei,
                left_satoshi: payee_channel.left.satoshi,
                right_satoshi: payee_channel.right.satoshi,
                bill_auto_number: payee_ledger.bill_auto_number,
            };
            build_cross_channel_bill(
                &payer_wire,
                payer_debit,
                &payee_wire,
                payee_credit,
                timestamp,
            )?
        };
        if let Some(signer) = &self.hub_signer {
            signer.sign_documents(&mut documents)?;
        }
        let bill_hex = documents.to_bill_hex();

        let response = FastPayResponse {
            payment_id: payment_id.clone(),
            status: "settled".into(),
            bill_hex: Some(bill_hex),
            summary: Some(summary),
        };
        guard.payments.insert(payment_id, response.clone());
        if let Some(path) = &self.state_path {
            save_state_file(path, &guard)?;
        }
        Ok(response)
    }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| HubError::State(e.to_string()))?;
        }
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| HubError::State(e.to_string()))?;
    fs::write(path, json).map_err(|e| HubError::State(e.to_string()))
}