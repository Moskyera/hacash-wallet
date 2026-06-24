use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::node::NodeClient;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PaymentRail {
    L2Fast,
    L1OnChain,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentPlan {
    pub rail: PaymentRail,
    pub summary: String,
    pub estimated_fee: String,
}

pub struct PaymentRouter {
    node: NodeClient,
    l2_hub_url: Option<String>,
}

impl PaymentRouter {
    pub fn new(node: NodeClient, l2_hub_url: Option<String>) -> Self {
        Self { node, l2_hub_url }
    }

    pub fn has_l2_hub(&self) -> bool {
        self.l2_hub_url.is_some()
    }

    pub async fn plan_send(
        &self,
        from: &str,
        to: &str,
        amount_mei: f64,
    ) -> WalletResult<PaymentPlan> {
        if let Some(hub) = &self.l2_hub_url {
            if self.l2_available(hub).await.unwrap_or(false) {
                return Ok(PaymentPlan {
                    rail: PaymentRail::L2Fast,
                    summary: format!("Fast Pay {amount_mei} HAC to {to} via L2 hub"),
                    estimated_fee: "~0.001 HAC".into(),
                });
            }
        }
        let _ = self.node.balance_mei(from).await?;
        Ok(PaymentPlan {
            rail: PaymentRail::L1OnChain,
            summary: format!("On-chain send {amount_mei} HAC to {to}"),
            estimated_fee: "1:244".into(),
        })
    }

    async fn l2_available(&self, _hub: &str) -> WalletResult<bool> {
        // Phase 2: probe hub health + open channel state.
        Ok(false)
    }

    pub async fn execute_l2(&self, _from: &str, _to: &str, _amount_mei: f64) -> WalletResult<String> {
        Err(WalletError::L2(
            "L2 Fast Pay hub integration coming in phase 2".into(),
        ))
    }
}