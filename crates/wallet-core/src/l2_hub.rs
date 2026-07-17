//! L2 Fast Pay hub client (Hacash Wallet Hub API v4).
//!
//! CSP operators implement:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`. initiate synchronous channel-chain payment
//! - `GET /v1/fast-pay/{payment_id}`. poll status
//! - `GET /v1/fast-pay/inbox/{payee}`. recipient signature requests
//!
//! Off-chain wire format follows `github.com/hacash/core/channel`.

use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::ChannelInfo;
use crate::error::{WalletError, WalletResult};
use crate::l2_bill::{
    cosign_bill_hex, summarize_bill, trusted_channel_state, validate_recipient_bill,
    validate_sender_bill,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    /// CSP on-chain address published by the hub.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayInboxItem {
    pub payment_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
    pub payee_channel_id: String,
    pub status: String,
    pub bill_hex: String,
    #[serde(default)]
    pub summary: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayExecution {
    pub payment_id: String,
    pub status: String,
    pub summary: String,
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

    pub async fn payment_status(&self, payment_id: &str) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}", self.base_url);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(WalletError::L2(format!(
                "hub payment status HTTP {status}: {detail}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))
    }

    pub async fn recipient_inbox(&self, payee: &str) -> WalletResult<Vec<FastPayInboxItem>> {
        let url = format!("{}/v1/fast-pay/inbox/{payee}", self.base_url);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| WalletError::L2(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(WalletError::L2(format!(
                "hub recipient inbox HTTP {status}: {detail}"
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
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(WalletError::L2(format!(
                "hub payment preparation HTTP {status}: {detail}"
            )));
        }
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
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if payer_account.address() != req.payer {
            return Err(WalletError::Policy(
                "Fast Pay payer account does not match the request".into(),
            ));
        }
        let pay = self.fast_pay(req).await?;
        let bill_hex = pay.bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2(format!(
                "payment {} did not include a settlement bill",
                pay.payment_id
            ))
        })?;
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &pay.payment_id,
            bill_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;

        let signed_hex = cosign_bill_hex(bill_hex, payer_account)?;
        let response = if pay.status == "pending" {
            self.confirm_fast_pay(&pay.payment_id, &signed_hex).await?
        } else {
            pay.clone()
        };
        if response.payment_id != pay.payment_id {
            return Err(WalletError::Policy(
                "hub confirmation changed the Fast Pay payment id".into(),
            ));
        }

        let confirmed_hex = response.bill_hex.as_deref().unwrap_or(&signed_hex);
        validate_sender_bill(
            &pay.payment_id,
            confirmed_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;

        if response.status == "awaiting_recipient" {
            let summary = summarize_bill(&pay.payment_id, confirmed_hex)?;
            if !summary
                .signatures
                .iter()
                .any(|signature| signature.address == req.payer && signature.verified)
            {
                return Err(WalletError::Policy(
                    "hub did not retain the verified payer signature".into(),
                ));
            }
            return Ok(FastPayExecution {
                payment_id: pay.payment_id,
                status: response.status,
                summary: response
                    .summary
                    .unwrap_or_else(|| "Fast Pay is waiting for the recipient signature".into()),
            });
        }

        if response.status != "settled" {
            return Err(WalletError::L2(format!(
                "hub returned unsupported Fast Pay status {}",
                response.status
            )));
        }
        let summary = summarize_bill(&pay.payment_id, confirmed_hex)?;
        if !summary.dispute_ready {
            return Err(WalletError::L2(format!(
                "payment {} is missing required verified signatures",
                pay.payment_id
            )));
        }
        bills.store_bill(&pay.payment_id, confirmed_hex)?;
        Ok(FastPayExecution {
            payment_id: pay.payment_id,
            status: response.status,
            summary: response
                .summary
                .unwrap_or_else(|| "Fast Pay settled with no fee".into()),
        })
    }

    pub async fn accept_inbox_item(
        &self,
        item: &FastPayInboxItem,
        bills: &mut BillStore,
        recipient_account: &WalletAccount,
        recipient_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if recipient_account.address() != item.payee {
            return Err(WalletError::Policy(
                "Fast Pay recipient account does not match the inbox request".into(),
            ));
        }
        let trusted = trusted_channel_state(bills, recipient_channel)?;
        validate_recipient_bill(
            &item.payment_id,
            &item.bill_hex,
            &item.payer,
            &item.payee,
            &item.amount,
            hub_address,
            &item.channel_id,
            &item.payee_channel_id,
            &trusted,
        )?;

        let signed_hex = cosign_bill_hex(&item.bill_hex, recipient_account)?;
        let settled = self.confirm_fast_pay(&item.payment_id, &signed_hex).await?;
        if settled.payment_id != item.payment_id || settled.status != "settled" {
            return Err(WalletError::L2(
                "hub did not atomically settle both Fast Pay channels".into(),
            ));
        }
        let settled_hex = settled.bill_hex.as_deref().unwrap_or(&signed_hex);
        validate_recipient_bill(
            &item.payment_id,
            settled_hex,
            &item.payer,
            &item.payee,
            &item.amount,
            hub_address,
            &item.channel_id,
            &item.payee_channel_id,
            &trusted,
        )?;
        let summary = summarize_bill(&item.payment_id, settled_hex)?;
        if !summary.dispute_ready {
            return Err(WalletError::L2(
                "settled Fast Pay bill is not dispute-ready".into(),
            ));
        }
        bills.store_bill(&item.payment_id, settled_hex)?;
        Ok(FastPayExecution {
            payment_id: item.payment_id.clone(),
            status: settled.status,
            summary: settled
                .summary
                .unwrap_or_else(|| "Fast Pay received with no fee".into()),
        })
    }
}
