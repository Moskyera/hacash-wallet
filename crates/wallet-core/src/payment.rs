use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::{query_channel, ChannelInfo, CHANNEL_STATUS_OPENING};
use crate::error::{WalletError, WalletResult};
use crate::l2_hub::{FastPayRequest, L2HubClient};
use crate::node::NodeClient;
use crate::hip23::format_mei_for_node;
use crate::l1_fee::{estimate_hac_l1_fee, format_l1_fee_label};
use crate::send_options::{
    fast_pay_fee_breakdown, HubFeePayer, SendFeeBreakdown, SendOptions, DEFAULT_HUB_FEE_MEI,
};
use crate::settings::WalletSettings;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentRail {
    L2Fast,
    L1OnChain,
    QuantumType4,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentPlan {
    pub rail: PaymentRail,
    pub summary: String,
    pub estimated_fee: String,
    pub channel_id: Option<String>,
    /// Short label for UI, e.g. "Instant (Fast Pay)".
    pub rail_label: String,
    /// One-line explanation shown under the label.
    pub rail_detail: String,
    pub fee_breakdown: SendFeeBreakdown,
}

pub struct PaymentRouter {
    node: NodeClient,
    settings: WalletSettings,
    bills: BillStore,
}

impl PaymentRouter {
    pub fn new(node: NodeClient, settings: WalletSettings, bills: BillStore) -> Self {
        Self {
            node,
            settings,
            bills,
        }
    }

    pub fn has_l2_hub(&self) -> bool {
        self.settings.l2_hub_url.is_some()
    }

    pub fn settings(&self) -> &WalletSettings {
        &self.settings
    }

    pub fn bills(&self) -> &BillStore {
        &self.bills
    }

    pub fn update_settings(&mut self, settings: WalletSettings) {
        if settings.node_url != self.node.base_url() {
            self.node = NodeClient::new(settings.node_url.clone());
        }
        self.settings = settings;
    }

    pub async fn plan_send(
        &self,
        from: &str,
        to: &str,
        amount_mei: f64,
        options: SendOptions,
    ) -> WalletResult<PaymentPlan> {
        if !options.force_l1 {
            if let Some(plan) = self
                .try_l2_plan(from, to, amount_mei, options.hub_fee_payer)
                .await?
            {
                return Ok(plan);
            }
        }
        let _ = self.node.balance_mei(from).await?;
        let amount_wire = format_mei_for_node(amount_mei);
        let fee_est = estimate_hac_l1_fee(&self.node, from, to, &amount_wire).await?;
        let fee_breakdown = SendFeeBreakdown {
            payer_debit_mei: amount_mei + fee_est.fee_mei,
            recipient_credit_mei: amount_mei,
            hub_fee_mei: None,
            hub_fee_payer: options.hub_fee_payer,
            l1_fee_wire: Some(fee_est.fee_wire.clone()),
        };
        Ok(PaymentPlan {
            rail: PaymentRail::L1OnChain,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: format_l1_fee_label(&fee_est),
            channel_id: None,
            rail_label: crate::fast_pay::rail_label(PaymentRail::L1OnChain).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L1OnChain).into(),
            fee_breakdown,
        })
    }

    async fn try_l2_plan(
        &self,
        from: &str,
        to: &str,
        amount_mei: f64,
        hub_fee_payer: HubFeePayer,
    ) -> WalletResult<Option<PaymentPlan>> {
        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };
        let channel_id = match &self.settings.channel_id_hex {
            Some(id) => id.clone(),
            None => return Ok(None),
        };

        let hub = L2HubClient::new(hub_url);
        let health = hub.health().await?;
        if !health.ok {
            return Ok(None);
        }
        let hub_fee_mei = health.hub_fee_mei.unwrap_or(DEFAULT_HUB_FEE_MEI);

        let channel = query_channel(&self.node, &channel_id).await?;
        if !channel_is_ready(&channel, from) {
            return Ok(None);
        }

        let fee_breakdown = fast_pay_fee_breakdown(amount_mei, hub_fee_mei, hub_fee_payer)?;
        let fee_label = match hub_fee_payer {
            HubFeePayer::Sender => format!("~{hub_fee_mei:.3} HAC (you pay)"),
            HubFeePayer::Recipient => format!("~{hub_fee_mei:.3} HAC (recipient pays)"),
        };
        Ok(Some(PaymentPlan {
            rail: PaymentRail::L2Fast,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: fee_label,
            channel_id: Some(channel_id),
            rail_label: crate::fast_pay::rail_label(PaymentRail::L2Fast).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L2Fast).into(),
            fee_breakdown,
        }))
    }

    pub async fn execute_l2(
        &mut self,
        from: &str,
        to: &str,
        _amount_mei: f64,
        amount_wire: &str,
        payer_account: &WalletAccount,
        hub_fee_payer: HubFeePayer,
    ) -> WalletResult<String> {
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("L2 hub not configured".into()))?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::L2("channel not configured".into()))?;

        let hub = L2HubClient::new(hub_url);
        let req = FastPayRequest {
            payer: from.to_owned(),
            payee: to.to_owned(),
            amount: amount_wire.to_owned(),
            channel_id,
            fee_payer: Some(hub_fee_payer.as_str().into()),
        };
        if payer_account.address() != from {
            return Err(WalletError::L2(format!(
                "payer account {} does not match from {}",
                payer_account.address(),
                from
            )));
        }
        hub.execute_and_store_bill(&req, &mut self.bills, payer_account)
            .await
    }
}

fn channel_is_ready(channel: &ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}