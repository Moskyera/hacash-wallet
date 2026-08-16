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
    pub fn update_settings(&mut self, node: NodeClient, settings: WalletSettings) {
        debug_assert_eq!(settings.node_url, node.base_url());
        self.node = node;
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
        crate::address::require_address_for_network(from, &self.settings.network_mode)?;
        crate::address::require_address_for_network(to, &self.settings.network_mode)?;
        if !options.force_l1
            && let Some(plan) = self.try_l2_plan(from, to, amount_mei).await?
        {
            return Ok(plan);
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
        let from_address = crate::address::parse_address(from, &self.settings.network_mode)?;
        let to_address = crate::address::parse_address(to, &self.settings.network_mode)?;
        if !from_address.fast_pay_eligible || !to_address.fast_pay_eligible {
            // Fast Pay v0 is passive-only. Contracts, P2SH and quantum addresses stay on L1.
            return Ok(None);
        }

        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };
        let channel_id = match &self.settings.channel_id_hex {
            Some(id) => id.clone(),
            None => return Ok(None),
        };

        let hub = L2HubClient::new_for_network(hub_url, &self.settings.network_mode);
        let health = match hub.health().await {
            Ok(health) => health,
            Err(_) => return Ok(None),
        };
        if !health.ok {
            return Ok(None);
        }
        if health.version < 3
            || !health.settlement_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            // Fast Pay is fee-free and must produce a dispute-ready settlement bill.
            return Ok(None);
        }
        if self.settings.network_mode == "mainnet" {
            let amount_wire = format_mei_for_node(amount_mei);
            if hub
                .require_mainnet_payment_ready(Some(&amount_wire))
                .await
                .is_err()
            {
                return Ok(None);
            }
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
        let payer = crate::address::require_address_for_network(from, &self.settings.network_mode)?;
        let payee = crate::address::require_address_for_network(to, &self.settings.network_mode)?;
        if !payer.fast_pay_eligible || !payee.fast_pay_eligible {
            return Err(WalletError::L2(
                "Fast Pay v0 supports only passive v0 sender and recipient addresses".into(),
            ));
        }

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

        let hub = L2HubClient::new_for_network(hub_url, &self.settings.network_mode);
        let health = hub.health().await?;
        let hub_address = health.hub_address.clone().ok_or_else(|| {
            WalletError::L2("Fast Pay provider did not publish its hub address".into())
        })?;
        let same_channel_payee = hub_address == to;
        if !health.ok
            || health.version < 3
            || !health.settlement_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
            || (!same_channel_payee && !health.cross_channel_ready)
        {
            return Err(WalletError::L2(
                "Fast Pay provider is not ready for a safe, fee-free settlement to this recipient"
                    .into(),
            ));
        }
        if payer_account.address() != from {
            return Err(WalletError::L2(format!(
                "payer account {} does not match from {}",
                payer_account.address(),
                from
            )));
        }
        if self.settings.network_mode == "mainnet" {
            // Early user-facing failure. execute_and_store_bill repeats this
            // check at the exact signing boundary to close preview races.
            hub.require_mainnet_payment_ready(Some(amount_wire)).await?;
        }
        let payer_channel = query_channel(&self.node, &channel_id).await?;
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(amount_wire)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let mut safety = crate::l2_safety::ClientL2Safety::open_for_network(
            payer_account,
            &self.settings.network_mode,
            &hub_address,
            &channel_id,
        )?;
        let operation = safety.begin_or_resume(
            from,
            to,
            amount_wire,
            amount.as_millimeis(),
            payer_channel.reuse_version,
        )?;
        let req = FastPayRequest {
            operation_id: operation.operation_id,
            idempotency_key: operation.idempotency_key,
            payer: from.to_owned(),
            payee: to.to_owned(),
            amount: amount_wire.to_owned(),
            channel_id,
            fee_payer: Some("sender".to_owned()),
        };
        hub.execute_and_store_bill(
            &req,
            &mut self.bills,
            &mut safety,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_hub_is_only_a_pre_sign_l1_fallback() {
        let payer = WalletAccount::create("payment-router-offline-hub-payer").unwrap();
        let payee = WalletAccount::create("payment-router-offline-hub-payee").unwrap();
        let settings = WalletSettings {
            l2_hub_url: Some("http://127.0.0.1:1".into()),
            channel_id_hex: Some("00112233445566778899aabbccddeeff".into()),
            ..WalletSettings::default()
        };
        let router = PaymentRouter::new(
            NodeClient::new("http://127.0.0.1:2").unwrap(),
            settings,
            BillStore::default(),
        );

        let plan = router
            .try_l2_plan(&payer.address(), &payee.address(), 1.0)
            .await
            .unwrap();
        assert!(plan.is_none());
    }
}
