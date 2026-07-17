use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::{CHANNEL_STATUS_OPENING, ChannelInfo, query_channel};
use crate::error::{WalletError, WalletResult};
use crate::hip23::format_mei_for_node;
use crate::l1_fee::{L1FeeTierQuote, estimate_hac_l1_fee_tiers, format_l1_fee_label};
use crate::l2_hub::{FastPayExecution, FastPayRequest, L2HubClient};
use crate::node::NodeClient;
use crate::send_options::{
    SendFeeBreakdown, SendOptions, apply_service_fee, fast_pay_fee_breakdown,
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
    #[serde(default)]
    pub l1_fee_tiers: Vec<L1FeeTierQuote>,
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

    pub fn replace_bills(&mut self, bills: BillStore) {
        self.bills = bills;
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
        options: &SendOptions,
    ) -> WalletResult<PaymentPlan> {
        crate::hip23::validate_hac_amount_mei(amount_mei)?;
        options.validate()?;
        if !options.force_l1 {
            if let Some(plan) = self.try_l2_plan(from, to, amount_mei).await? {
                return Ok(plan);
            }
        }
        let _ = self.node.balance_mei(from).await?;
        let amount_wire = format_mei_for_node(amount_mei);
        let tier_set = estimate_hac_l1_fee_tiers(
            &self.node,
            from,
            to,
            &amount_wire,
            amount_mei,
            options.l1_fee_speed,
        )
        .await?;
        let fee_est = tier_set.selected;
        let mut fee_breakdown = SendFeeBreakdown {
            payer_debit_mei: amount_mei + fee_est.fee_mei,
            recipient_credit_mei: amount_mei,
            hub_fee_mei: None,
            hub_fee_payer: options.hub_fee_payer,
            l1_fee_wire: Some(fee_est.fee_wire.clone()),
            l1_fee_mei: Some(fee_est.fee_mei),
            service_fee_mei: None,
            service_fee_rate: None,
            service_fee_treasury: None,
        };
        apply_service_fee(&mut fee_breakdown, amount_mei);
        Ok(PaymentPlan {
            rail: PaymentRail::L1OnChain,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: format_l1_fee_label(&fee_est),
            channel_id: None,
            rail_label: crate::fast_pay::rail_label(PaymentRail::L1OnChain).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L1OnChain).into(),
            fee_breakdown,
            l1_fee_tiers: tier_set.tiers,
        })
    }

    async fn try_l2_plan(
        &self,
        from: &str,
        to: &str,
        amount_mei: f64,
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
        if health.version < 3
            || !health.settlement_ready
            || health.hub_fee_mei.unwrap_or(0.0).abs() > f64::EPSILON
        {
            // Fast Pay is fee-free and must produce a dispute-ready settlement bill.
            return Ok(None);
        }
        let same_channel_payee = health.hub_address.as_deref() == Some(to);
        if !same_channel_payee && !health.cross_channel_ready {
            return Ok(None);
        }

        let channel = query_channel(&self.node, &channel_id).await?;
        if !channel_is_ready(&channel, from) {
            return Ok(None);
        }

        let fee_breakdown = fast_pay_fee_breakdown(amount_mei)?;
        Ok(Some(PaymentPlan {
            rail: PaymentRail::L2Fast,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: "0 HAC".into(),
            channel_id: Some(channel_id),
            rail_label: crate::fast_pay::rail_label(PaymentRail::L2Fast).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L2Fast).into(),
            fee_breakdown,
            l1_fee_tiers: Vec::new(),
        }))
    }

    pub async fn execute_l2(
        &mut self,
        from: &str,
        to: &str,
        amount_wire: &str,
        payer_account: &WalletAccount,
    ) -> WalletResult<FastPayExecution> {
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
        let health = hub.health().await?;
        let hub_address = health.hub_address.clone().ok_or_else(|| {
            WalletError::L2("Fast Pay provider did not publish its hub address".into())
        })?;
        let same_channel_payee = hub_address == to;
        if !health.ok
            || health.version < 3
            || !health.settlement_ready
            || health.hub_fee_mei.unwrap_or(0.0).abs() > f64::EPSILON
            || (!same_channel_payee && !health.cross_channel_ready)
        {
            return Err(WalletError::L2(
                "Fast Pay provider is not ready for a safe, fee-free settlement to this recipient"
                    .into(),
            ));
        }
        let req = FastPayRequest {
            payer: from.to_owned(),
            payee: to.to_owned(),
            amount: amount_wire.to_owned(),
            channel_id,
            fee_payer: None,
        };
        if payer_account.address() != from {
            return Err(WalletError::L2(format!(
                "payer account {} does not match from {}",
                payer_account.address(),
                from
            )));
        }
        let payer_channel = query_channel(&self.node, &req.channel_id).await?;
        hub.execute_and_store_bill(
            &req,
            &mut self.bills,
            payer_account,
            &payer_channel,
            &hub_address,
        )
        .await
    }
}

fn channel_is_ready(channel: &ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}
