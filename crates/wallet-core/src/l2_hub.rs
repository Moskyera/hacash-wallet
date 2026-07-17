//! L2 Fast Pay hub client (Hacash Wallet Hub API v1).
//!
//! CSP operators implement:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`. initiate synchronous channel-chain payment
//! - `GET /v1/fast-pay/{payment_id}`. poll status
//!
//! Off-chain wire format follows `github.com/hacash/core/channel`.

use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::error::{WalletError, WalletResult};
use crate::l2_bill::{cosign_bill_hex, summarize_bill};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    /// CSP on-chain address (optional Hub API v1 extension).
    #[serde(default)]
    pub hub_address: Option<String>,
    /// Per-payment hub fee in HAC (mei), when advertised by the hub.
    #[serde(default)]
    pub hub_fee_mei: Option<f64>,
    /// Hub can sign settlement bills and is safe to use for supported routes.
    #[serde(default)]
    pub settlement_ready: bool,
    /// Hub has a complete recipient-signature exchange for routed payments.
    #[serde(default)]
    pub cross_channel_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayRequest {
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
    /// `sender` (default) or `recipient`. who pays the hub routing fee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayResponse {
    pub payment_id: String,
    pub status: String,
    pub bill_hex: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ConfirmFastPayRequest<'a> {
    bill_hex: &'a str,
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
            return Err(WalletError::L2(format!(
                "hub health HTTP {}",
                resp.status()
            )));
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
            return Err(WalletError::L2(format!(
                "hub payment status: {}",
                body.status
            )));
        }
        Ok(body)
    }

    pub async fn confirm_fast_pay(
        &self,
        payment_id: &str,
        signed_bill_hex: &str,
    ) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}/confirm", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(&ConfirmFastPayRequest {
                bill_hex: signed_bill_hex,
            })
            .send()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(WalletError::L2(format!(
                "hub settlement confirmation HTTP {status}: {detail}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))
    }

    pub async fn execute_and_store_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        payer_account: &WalletAccount,
    ) -> WalletResult<String> {
        let pay = self.fast_pay(req).await?;
        if pay.status != "settled" && pay.status != "pending" {
            return Err(WalletError::L2(format!(
                "payment {} returned unsupported status {}",
                pay.payment_id, pay.status
            )));
        }
        let bill_hex = pay.bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2(format!(
                "payment {} reported settled without a settlement bill",
                pay.payment_id
            ))
        })?;
        let signed_hex = cosign_bill_hex(bill_hex, payer_account)?;
        let settled = if pay.status == "pending" {
            self.confirm_fast_pay(&pay.payment_id, &signed_hex).await?
        } else {
            pay.clone()
        };
        if settled.status != "settled" || settled.payment_id != pay.payment_id {
            return Err(WalletError::L2(format!(
                "hub did not confirm payment {} as settled",
                pay.payment_id
            )));
        }
        let settled_hex = settled.bill_hex.as_deref().unwrap_or(&signed_hex);
        let summary = summarize_bill(&pay.payment_id, settled_hex)?;
        if !summary.dispute_ready {
            return Err(WalletError::L2(format!(
                "payment {} is missing required verified signatures",
                pay.payment_id
            )));
        }
        bills.store_bill(&pay.payment_id, settled_hex)?;
        Ok(pay.payment_id)
    }
}
