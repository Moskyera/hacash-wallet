//! L2 Fast Pay hub client (Hacash Wallet Hub API v1).
//!
//! CSP operators implement:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay` — initiate synchronous channel-chain payment
//! - `GET /v1/fast-pay/{payment_id}` — poll status
//!
//! Off-chain wire format follows `github.com/hacash/core/channel`.

use serde::{Deserialize, Serialize};

use crate::bills::BillStore;
use crate::error::{WalletError, WalletResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    /// CSP on-chain address (optional Hub API v1 extension).
    #[serde(default)]
    pub hub_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayRequest {
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayResponse {
    pub payment_id: String,
    pub status: String,
    pub bill_hex: Option<String>,
    pub summary: Option<String>,
}

pub struct L2HubClient {
    base_url: String,
    http: reqwest::Client,
}

impl L2HubClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn health(&self) -> WalletResult<HubHealth> {
        let url = format!("{}/v1/health", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WalletError::L2(format!("hub unreachable: {e}")))?;
        if !resp.status().is_success() {
            return Err(WalletError::L2(format!("hub health HTTP {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))
    }

    pub async fn fast_pay(&self, req: &FastPayRequest) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(req)
            .send()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))?;
        let body: FastPayResponse = resp
            .json()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))?;
        if body.status != "settled" && body.status != "pending" {
            return Err(WalletError::L2(format!("hub payment status: {}", body.status)));
        }
        Ok(body)
    }

    pub async fn execute_and_store_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
    ) -> WalletResult<String> {
        let pay = self.fast_pay(req).await?;
        if let Some(bill_hex) = &pay.bill_hex {
            bills.store_bill(&pay.payment_id, bill_hex)?;
        }
        if pay.status != "settled" {
            return Err(WalletError::L2(format!(
                "payment {} not settled yet",
                pay.payment_id
            )));
        }
        Ok(pay.payment_id)
    }
}