//! L2 Fast Pay hub client (HPAY Wallet Hub API v4).
//!
//! CSP operators implement:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`. initiate synchronous channel-chain payment
//! - `GET /v1/fast-pay/{payment_id}`. poll status
//! - `GET /v1/fast-pay/inbox/{payee}`. recipient signature requests
//!
//! Off-chain wire format follows `github.com/hacash/core/channel`.

use serde::de::DeserializeOwned;
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
    pub hub_fee_mei: Option<serde_json::Value>,
    /// Hub can sign settlement bills and is safe to use for supported routes.
    #[serde(default)]
    pub settlement_ready: bool,
    /// Hub has a complete recipient-signature exchange for routed payments.
    #[serde(default)]
    pub cross_channel_ready: bool,
    /// Provider anchors the journal head outside rollbackable local storage.
    #[serde(default)]
    pub external_rollback_anchor_ready: bool,
    /// Network has a proven unilateral dispute/final-claim path.
    #[serde(default)]
    pub l1_dispute_path_ready: bool,
    /// Provider speaks an authenticated Official ChannelPay session.
    #[serde(default)]
    pub official_channelpay_ready: bool,
    /// Provider's aggregate production-readiness assertion.
    #[serde(default)]
    pub production_mainnet_ready: bool,
    /// Truthful transport/deployment label.
    #[serde(default)]
    pub deployment_profile: Option<String>,
}

/// Authoritative, fail-closed payment decision published by HPAY Fast Pay Hub.
///
/// The health route is only a liveness/capability signal. Mainnet payment
/// authority comes exclusively from /v1/readiness/mainnet and is re-checked at
/// the signing boundary so an earlier green preview grants no later authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubMainnetReadiness {
    pub schema: String,
    pub evaluated_unix: u64,
    pub valid_until_unix: u64,
    pub profile: String,
    pub payments_enabled: bool,
    pub mainnet_detected: Option<bool>,
    pub fullnode_capabilities: Option<HubFullnodeCapabilities>,
    pub max_payment_hac_zhu: u64,
    pub max_channel_funding_hac_zhu: u64,
    pub max_payment_satoshi: u64,
    pub wallet_fee_hac: String,
    pub trustless_finality: bool,
    pub unilateral_l1_enforceable: bool,
    pub settlement_model: String,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubFullnodeCapabilities {
    pub observed_unix: u64,
    pub api_version: u64,
    pub chain_id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
    pub tip_timestamp_unix: u64,
    pub tip_age_seconds: u64,
    pub enabled_actions: Vec<u16>,
}

const MAINNET_READINESS_SCHEMA: &str = "hpay-fast-pay-mainnet-readiness/1";
const MAINNET_PILOT_PROFILE: &str = "mainnet-pilot";
const MAINNET_PILOT_HARD_MAX_HAC_ZHU: u64 = 100_000_000;
const ZHU_PER_MILLIMEI: u64 = 100_000;
const MAINNET_MIN_SAFE_HEIGHT: u64 = 765_432;
const MAX_TIP_AGE_SECONDS: u64 = 3_600;
const MAX_FUTURE_SKEW_SECONDS: u64 = 120;
const MAX_READINESS_VALIDITY_SECONDS: u64 = 330;
const REQUIRED_COOPERATIVE_CLOSE_ACTION: u16 = 3;

impl HubMainnetReadiness {
    pub fn require_payment_ready(&self, amount_wire: Option<&str>) -> WalletResult<()> {
        if self.schema != MAINNET_READINESS_SCHEMA
            || self.profile != MAINNET_PILOT_PROFILE
            || !self.payments_enabled
            || self.mainnet_detected != Some(true)
            || !self.blockers.is_empty()
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet readiness is not green; payment signing is blocked".into(),
            ));
        }
        let now = unix_now();
        let validity = self
            .valid_until_unix
            .checked_sub(self.evaluated_unix)
            .filter(|seconds| *seconds <= MAX_READINESS_VALIDITY_SECONDS);
        if validity.is_none()
            || self.evaluated_unix > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || now > self.valid_until_unix
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet readiness snapshot is invalid, expired, or from the future"
                    .into(),
            ));
        }
        if !l2_fast_pay_hub::amount::parse_amount_mei(&self.wallet_fee_hac)
            .is_ok_and(|amount| amount == l2_fast_pay_hub::amount::HacAmount::ZERO)
        {
            return Err(WalletError::L2(
                "Fast Pay Hub did not explicitly declare a zero wallet fee".into(),
            ));
        }
        if self.max_payment_hac_zhu < ZHU_PER_MILLIMEI
            || self.max_payment_hac_zhu > MAINNET_PILOT_HARD_MAX_HAC_ZHU
            || self.max_channel_funding_hac_zhu < ZHU_PER_MILLIMEI
            || self.max_channel_funding_hac_zhu > MAINNET_PILOT_HARD_MAX_HAC_ZHU
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet payment or channel-funding cap is missing, below wallet precision, or exceeds the HPAY pilot limit"
                    .into(),
            ));
        }
        let capabilities = self.fullnode_capabilities.as_ref().ok_or_else(|| {
            WalletError::L2("Fast Pay Hub did not publish verified fullnode capabilities".into())
        })?;
        let expected_next_height = capabilities.height.checked_add(1);
        let reported_tip_age = capabilities
            .observed_unix
            .saturating_sub(capabilities.tip_timestamp_unix);
        let local_tip_age = now.saturating_sub(capabilities.tip_timestamp_unix);
        if capabilities.observed_unix != self.evaluated_unix
            || capabilities.api_version != 1
            || capabilities.chain_id != 0
            || !capabilities.mainnet
            || capabilities.height < MAINNET_MIN_SAFE_HEIGHT
            || expected_next_height != Some(capabilities.next_height)
            || capabilities.tip_timestamp_unix
                > capabilities
                    .observed_unix
                    .saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || capabilities.tip_age_seconds != reported_tip_age
            || capabilities.tip_age_seconds > MAX_TIP_AGE_SECONDS
            || local_tip_age > MAX_TIP_AGE_SECONDS
            || !capabilities
                .enabled_actions
                .contains(&REQUIRED_COOPERATIVE_CLOSE_ACTION)
        {
            return Err(WalletError::L2(
                "Fast Pay Hub fullnode capabilities are incompatible or stale".into(),
            ));
        }
        if let Some(amount_wire) = amount_wire {
            let amount = l2_fast_pay_hub::amount::parse_amount_mei(amount_wire)
                .map_err(|error| WalletError::L2(error.to_string()))?;
            let amount_zhu = amount
                .as_millimeis()
                .checked_mul(ZHU_PER_MILLIMEI)
                .ok_or_else(|| WalletError::L2("Fast Pay amount exceeds mainnet limits".into()))?;
            if amount_zhu > self.max_payment_hac_zhu {
                return Err(WalletError::L2(format!(
                    "Fast Pay amount exceeds this Hub's mainnet pilot cap of {} zhu",
                    self.max_payment_hac_zhu
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn require_channel_funding_ready(&self, amount_mei: f64) -> WalletResult<()> {
        self.require_payment_ready(None)?;
        let amount_wire = crate::hip23::format_mei_for_node(amount_mei);
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&amount_wire)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let amount_zhu = amount
            .as_millimeis()
            .checked_mul(ZHU_PER_MILLIMEI)
            .ok_or_else(|| {
                WalletError::L2("Fast Pay channel funding exceeds mainnet limits".into())
            })?;
        if amount_zhu > self.max_channel_funding_hac_zhu {
            return Err(WalletError::L2(format!(
                "Fast Pay channel funding exceeds this Hub's mainnet pilot cap of {} zhu",
                self.max_channel_funding_hac_zhu
            )));
        }
        Ok(())
    }

    pub(crate) fn max_channel_funding_millimeis(&self) -> u64 {
        self.max_channel_funding_hac_zhu / ZHU_PER_MILLIMEI
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayRequest {
    pub operation_id: String,
    pub idempotency_key: String,
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
    pub idempotency_key: String,
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
    idempotency_key: &'a str,
    bill_hex: &'a str,
}

pub fn hub_fee_is_zero(health: &HubHealth) -> bool {
    match health.hub_fee_mei.as_ref() {
        None => false,
        Some(serde_json::Value::String(value)) => l2_fast_pay_hub::amount::parse_amount_mei(value)
            .is_ok_and(|amount| amount == l2_fast_pay_hub::amount::HacAmount::ZERO),
        Some(serde_json::Value::Number(value)) => {
            value.as_u64() == Some(0) || value.as_i64() == Some(0) || value.as_f64() == Some(0.0)
        }
        _ => false,
    }
}

pub fn hub_fee_label(health: &HubHealth) -> Option<String> {
    health.hub_fee_mei.as_ref().map(|value| match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

const MAX_HUB_JSON_BYTES: usize = 2 * 1024 * 1024;

pub struct L2HubClient {
    base_url: String,
    http: Result<reqwest::Client, String>,
    mainnet: bool,
}

impl L2HubClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::new_for_network(base_url, "testnet")
    }

    pub fn new_for_network(base_url: impl Into<String>, network_mode: &str) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: crate::http_client::shared_http_client().cloned(),
            mainnet: network_mode == "mainnet",
        }
    }

    fn http(&self) -> WalletResult<&reqwest::Client> {
        self.http
            .as_ref()
            .map_err(|error| WalletError::L2(error.clone()))
    }

    pub async fn health(&self) -> WalletResult<HubHealth> {
        let url = format!("{}/v1/health", self.base_url);
        let response = self
            .http()?
            .get(&url)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("hub unreachable: {error}")))?;
        Self::read_hub_json(response, "hub health").await
    }

    pub async fn mainnet_readiness(&self) -> WalletResult<HubMainnetReadiness> {
        let url = format!("{}/v1/readiness/mainnet", self.base_url);
        let response = self
            .http()?
            .get(&url)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("hub readiness unavailable: {error}")))?;
        Self::read_hub_json(response, "hub mainnet readiness").await
    }

    pub async fn require_mainnet_payment_ready(
        &self,
        amount_wire: Option<&str>,
    ) -> WalletResult<HubMainnetReadiness> {
        let readiness = self.mainnet_readiness().await?;
        readiness.require_payment_ready(amount_wire)?;
        Ok(readiness)
    }

    pub async fn payment_status(&self, payment_id: &str) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}", self.base_url);
        let response = self
            .http()?
            .get(url)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub payment status").await
    }

    pub async fn recipient_inbox(&self, payee: &str) -> WalletResult<Vec<FastPayInboxItem>> {
        let url = format!("{}/v1/fast-pay/inbox/{payee}", self.base_url);
        let response = self
            .http()?
            .get(url)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub recipient inbox").await
    }

    pub async fn fast_pay(&self, req: &FastPayRequest) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(req)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let body: FastPayResponse =
            Self::read_hub_json(response, "hub payment preparation").await?;
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
        idempotency_key: &str,
        signed_bill_hex: &str,
    ) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}/confirm", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(&ConfirmFastPayRequest {
                idempotency_key,
                bill_hex: signed_bill_hex,
            })
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub settlement confirmation").await
    }

    pub async fn execute_and_store_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_account: &WalletAccount,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if payer_account.address() != req.payer {
            return Err(WalletError::Policy(
                "Fast Pay payer account does not match the request".into(),
            ));
        }
        let before_prepare = safety.operation(&req.operation_id)?;
        if before_prepare.status.requires_explicit_reconciliation() {
            return Err(WalletError::L2(
                "RecoveryRequired: this Fast Pay operation may already have reached the hub; automatic retry and L1 fallback are disabled".into(),
            ));
        }
        let pay = match self.fast_pay(req).await {
            Ok(pay) => pay,
            Err(error) => {
                if before_prepare.signed_bill_hex.is_some() {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                }
                return Err(error);
            }
        };
        if pay.payment_id != req.operation_id {
            return Err(WalletError::Policy(
                "hub changed the durable Fast Pay operation id".into(),
            ));
        }
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

        // Re-fetch after validating the exact bill and before creating or
        // persisting any local signature. Preview readiness grants no authority.
        if self.mainnet {
            self.require_mainnet_payment_ready(Some(&req.amount))
                .await?;
        }
        let prepared = safety.persist_before_signing(&req.operation_id, bill_hex)?;
        let signed_hex = match prepared.signed_bill_hex {
            Some(existing) => existing,
            None => {
                let signed = cosign_bill_hex(bill_hex, payer_account)?;
                safety.persist_signature(&req.operation_id, &signed)?;
                signed
            }
        };
        safety.mark_submitted(&req.operation_id)?;
        let response = match self
            .confirm_fast_pay(&pay.payment_id, &req.idempotency_key, &signed_hex)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(WalletError::L2(format!(
                    "Fast Pay outcome is uncertain; automatic retry and L1 fallback are disabled: {error}"
                )));
            }
        };
        if response.payment_id != pay.payment_id {
            safety.mark_recovery_required(&req.operation_id)?;
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
                safety.mark_recovery_required(&req.operation_id)?;
                return Err(WalletError::Policy(
                    "hub did not retain the verified payer signature".into(),
                ));
            }
            safety.mark_awaiting_recipient(&req.operation_id)?;
            return Ok(FastPayExecution {
                payment_id: pay.payment_id,
                status: response.status,
                summary: response
                    .summary
                    .unwrap_or_else(|| "Fast Pay is waiting for the recipient signature".into()),
            });
        }
        if response.status != "settled" {
            safety.mark_recovery_required(&req.operation_id)?;
            return Err(WalletError::L2(format!(
                "hub returned unsupported Fast Pay status {}",
                response.status
            )));
        }
        let summary = summarize_bill(&pay.payment_id, confirmed_hex)?;
        if !summary.dispute_ready {
            safety.mark_recovery_required(&req.operation_id)?;
            return Err(WalletError::L2(format!(
                "payment {} is missing required verified signatures",
                pay.payment_id
            )));
        }
        if let Err(error) = bills.store_bill(&pay.payment_id, confirmed_hex) {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(error);
        }
        safety.mark_committed(&req.operation_id)?;
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
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&item.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let mut safety = crate::l2_safety::ClientL2Safety::open(
            recipient_account,
            hub_address,
            &item.payee_channel_id,
        )?;
        let imported =
            safety.import_recipient_operation(crate::l2_safety::RecipientOperationInput {
                operation_id: &item.payment_id,
                idempotency_key: &item.idempotency_key,
                payer: &item.payer,
                payee: &item.payee,
                amount: &item.amount,
                amount_units: amount.as_millimeis(),
                channel_reuse_version: recipient_channel.reuse_version,
            })?;
        if imported.status.requires_explicit_reconciliation() {
            return Err(WalletError::L2(
                "RecoveryRequired: this Fast Pay receipt may already have reached the hub; automatic retry is disabled".into(),
            ));
        }
        // Recipient confirmation is a signing boundary too. Re-fetch after
        // validating and importing the exact inbox item.
        if self.mainnet {
            self.require_mainnet_payment_ready(Some(&item.amount))
                .await?;
        }
        let prepared = safety.persist_before_signing(&item.payment_id, &item.bill_hex)?;
        let signed_hex = match prepared.signed_bill_hex {
            Some(existing) => existing,
            None => {
                let signed = cosign_bill_hex(&item.bill_hex, recipient_account)?;
                safety.persist_signature(&item.payment_id, &signed)?;
                signed
            }
        };
        safety.mark_submitted(&item.payment_id)?;
        let settled = match self
            .confirm_fast_pay(&item.payment_id, &item.idempotency_key, &signed_hex)
            .await
        {
            Ok(settled) => settled,
            Err(error) => {
                let _ = safety.mark_recovery_required(&item.payment_id);
                return Err(WalletError::L2(format!(
                    "Fast Pay receipt is uncertain; automatic retry is disabled: {error}"
                )));
            }
        };
        if settled.payment_id != item.payment_id || settled.status != "settled" {
            safety.mark_recovery_required(&item.payment_id)?;
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
            safety.mark_recovery_required(&item.payment_id)?;
            return Err(WalletError::L2(
                "settled Fast Pay bill is not dispute-ready".into(),
            ));
        }
        if let Err(error) = bills.store_bill(&item.payment_id, settled_hex) {
            let _ = safety.mark_recovery_required(&item.payment_id);
            return Err(error);
        }
        safety.mark_committed(&item.payment_id)?;
        Ok(FastPayExecution {
            payment_id: item.payment_id.clone(),
            status: settled.status,
            summary: settled
                .summary
                .unwrap_or_else(|| "Fast Pay received with no fee".into()),
        })
    }

    async fn read_hub_json<T: DeserializeOwned>(
        mut response: reqwest::Response,
        label: &str,
    ) -> WalletResult<T> {
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HUB_JSON_BYTES as u64)
        {
            return Err(WalletError::L2(format!(
                "{label} response exceeds {MAX_HUB_JSON_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| WalletError::L2(format!("{label} response read failed: {error}")))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_HUB_JSON_BYTES {
                return Err(WalletError::L2(format!(
                    "{label} response exceeds {MAX_HUB_JSON_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&body);
            return Err(WalletError::L2(format!("{label} HTTP {status}: {detail}")));
        }
        serde_json::from_slice(&body)
            .map_err(|error| WalletError::L2(format!("{label} returned invalid JSON: {error}")))
    }
}

#[cfg(test)]
mod transport_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::routing::get;
    use axum::{Json, Router, extract::State};

    use super::*;

    fn readiness_json(enabled: bool, blockers: Vec<&str>, cap_zhu: u64) -> serde_json::Value {
        let now = unix_now();
        serde_json::json!({
            "schema": "hpay-fast-pay-mainnet-readiness/1",
            "evaluated_unix": now,
            "valid_until_unix": now + 60,
            "profile": "mainnet-pilot",
            "payments_enabled": enabled,
            "mainnet_detected": true,
            "fullnode_capabilities": {
                "observed_unix": now,
                "api_version": 1,
                "chain_id": 0,
                "height": 900000,
                "next_height": 900001,
                "mainnet": true,
                "tip_timestamp_unix": now,
                "tip_age_seconds": 0,
                "enabled_actions": [1, 2, 3]
            },
            "max_payment_hac_zhu": cap_zhu,
            "max_channel_funding_hac_zhu": cap_zhu.min(MAINNET_PILOT_HARD_MAX_HAC_ZHU),
            "max_payment_satoshi": 0,
            "wallet_fee_hac": "0",
            "trustless_finality": false,
            "unilateral_l1_enforceable": false,
            "settlement_model": "hub-coordinated ordered signatures with durable recovery",
            "blockers": blockers,
            "limitations": ["settled is not unilateral L1 finality"]
        })
    }

    #[test]
    fn health_fee_parser_accepts_only_exact_zero() {
        let mut health = HubHealth {
            ok: true,
            version: 4,
            name: None,
            hub_address: None,
            hub_fee_mei: Some(serde_json::json!("0")),
            settlement_ready: true,
            cross_channel_ready: true,
            external_rollback_anchor_ready: false,
            l1_dispute_path_ready: false,
            official_channelpay_ready: false,
            production_mainnet_ready: false,
            deployment_profile: Some("legacy_wallet_hub_v4_development".into()),
        };
        assert!(hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!("0.001"));
        assert!(!hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!(0));
        assert!(hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!(0.0001));
        assert!(!hub_fee_is_zero(&health));
        health.hub_fee_mei = None;
        assert!(!hub_fee_is_zero(&health));
    }

    #[test]
    fn authoritative_readiness_fails_closed_and_enforces_the_hac_cap() {
        let green: HubMainnetReadiness =
            serde_json::from_value(readiness_json(true, vec![], 100_000_000)).unwrap();
        green.require_payment_ready(Some("1")).unwrap();
        assert_eq!(green.max_channel_funding_millimeis(), 1_000);
        assert!(green.require_payment_ready(Some("1.001")).is_err());

        let mut lower_channel_cap = green.clone();
        lower_channel_cap.max_channel_funding_hac_zhu = 50_000_000;
        lower_channel_cap
            .require_payment_ready(Some("0.75"))
            .unwrap();
        lower_channel_cap
            .require_channel_funding_ready(0.5)
            .unwrap();
        assert!(
            lower_channel_cap
                .require_channel_funding_ready(0.501)
                .is_err()
        );

        let mut expired = green.clone();
        expired.valid_until_unix = unix_now().saturating_sub(1);
        assert!(expired.require_payment_ready(Some("0.001")).is_err());

        let mut stale = green.clone();
        let old_tip = unix_now().saturating_sub(MAX_TIP_AGE_SECONDS + 1);
        {
            let capabilities = stale.fullnode_capabilities.as_mut().unwrap();
            capabilities.tip_timestamp_unix = old_tip;
            capabilities.tip_age_seconds = capabilities.observed_unix.saturating_sub(old_tip);
        }
        assert!(stale.require_payment_ready(Some("0.001")).is_err());

        let mut mismatched_snapshot = green.clone();
        mismatched_snapshot
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .observed_unix -= 1;
        assert!(
            mismatched_snapshot
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let mut nonzero_fee = green.clone();
        nonzero_fee.wallet_fee_hac = "0.001".into();
        assert!(nonzero_fee.require_payment_ready(Some("0.001")).is_err());

        let mut invalid_height = green.clone();
        invalid_height
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .next_height += 1;
        assert!(invalid_height.require_payment_ready(Some("0.001")).is_err());

        let mut missing_action = green.clone();
        missing_action
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .enabled_actions = vec![1, 2];
        assert!(missing_action.require_payment_ready(Some("0.001")).is_err());

        let blocked: HubMainnetReadiness = serde_json::from_value(readiness_json(
            false,
            vec!["fullnode_capability_probe_failed"],
            100_000_000,
        ))
        .unwrap();
        assert!(blocked.require_payment_ready(Some("0.001")).is_err());

        let unsafe_cap: HubMainnetReadiness =
            serde_json::from_value(readiness_json(true, vec![], 100_000_001)).unwrap();
        assert!(unsafe_cap.require_payment_ready(Some("0.001")).is_err());

        let unusable_cap: HubMainnetReadiness =
            serde_json::from_value(readiness_json(true, vec![], ZHU_PER_MILLIMEI - 1)).unwrap();
        assert!(unusable_cap.require_payment_ready(Some("0.001")).is_err());
    }

    #[tokio::test]
    async fn invalid_readiness_response_is_never_treated_as_green() {
        let app = Router::new().route("/v1/readiness/mainnet", get(|| async { "not-json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid JSON"));
        server.abort();
    }

    #[tokio::test]
    async fn missing_readiness_endpoint_is_never_treated_as_green() {
        let app = Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("404"));
        server.abort();
    }

    #[tokio::test]
    async fn readiness_is_refetched_and_a_downgrade_blocks_later_authority() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/v1/readiness/mainnet",
                get(|State(calls): State<Arc<AtomicUsize>>| async move {
                    let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    Json(if first {
                        readiness_json(true, vec![], 100_000_000)
                    } else {
                        readiness_json(false, vec!["fullnode_capability_probe_failed"], 100_000_000)
                    })
                }),
            )
            .with_state(calls);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = L2HubClient::new(format!("http://{address}"));
        client
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap();
        assert!(
            client
                .require_mainnet_payment_ready(Some("0.001"))
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn oversized_hub_json_is_rejected() {
        let body = "x".repeat(MAX_HUB_JSON_BYTES + 1);
        let app = Router::new().route(
            "/v1/health",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .health()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response exceeds"));
        server.abort();
    }
}
