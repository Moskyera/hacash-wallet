use serde::{Deserialize, Serialize};

use crate::bills::BillStore;
use crate::channel::{query_channel, ChannelInfo, CHANNEL_STATUS_OPENING};
use crate::error::{WalletError, WalletResult};
use crate::l2_hub::{FastPayRequest, L2HubClient};
use crate::node::NodeClient;
use crate::settings::WalletSettings;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentRail {
    L2Fast,
    L1OnChain,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentPlan {
    pub rail: PaymentRail,
    pub summary: String,
    pub estimated_fee: String,
    pub channel_id: Option<String>,
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
    ) -> WalletResult<PaymentPlan> {
        if let Some(plan) = self.try_l2_plan(from, to, amount_mei).await? {
            return Ok(plan);
        }
        let _ = self.node.balance_mei(from).await?;
        Ok(PaymentPlan {
            rail: PaymentRail::L1OnChain,
            summary: format!("On-chain send {amount_mei} HAC to {to}"),
            estimated_fee: "1:244".into(),
            channel_id: None,
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

        let channel = query_channel(&self.node, &channel_id).await?;
        if !channel_is_ready(&channel, from) {
            return Ok(None);
        }

        Ok(Some(PaymentPlan {
            rail: PaymentRail::L2Fast,
            summary: format!("Fast Pay {amount_mei} HAC to {to} via L2 channel"),
            estimated_fee: "~0.001 HAC".into(),
            channel_id: Some(channel_id),
        }))
    }

    pub async fn execute_l2(
        &mut self,
        from: &str,
        to: &str,
        _amount_mei: f64,
        amount_wire: &str,
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
        };
        hub.execute_and_store_bill(&req, &mut self.bills).await
    }
}

fn channel_is_ready(channel: &ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}