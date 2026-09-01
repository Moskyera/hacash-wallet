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

pub const OFFICIAL_CHANNELPAY_PRODUCTION_PROFILE: &str = "official_channelpay_production";

/// Local wallet capability, not a value supplied by the remote provider.
///
/// The checked-in codec fixtures prove selected wire compatibility only. The
/// authenticated Official ChannelPay WebSocket session, reconnect lifecycle and
/// testnet-proven dispute broadcaster are not implemented yet. A hub must never
/// be able to turn mainnet Fast Pay on by returning optimistic health booleans.
const OFFICIAL_CHANNELPAY_MAINNET_TRANSPORT_IMPLEMENTED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubMainnetReadinessBlocker {
    WalletTransportUnavailable,
    HealthCheckFailed,
    ApiVersionMismatch,
    DeploymentProfileMismatch,
    HubAddressMissing,
    HubAddressInvalid,
    SettlementUnavailable,
    CrossChannelUnavailable,
    NonZeroOrInvalidHubFee,
    ExternalRollbackAnchorUnavailable,
    L1DisputePathUnavailable,
    OfficialChannelpayUnavailable,
    ProviderNotProductionReady,
}

/// Classifies every independent mainnet Fast Pay gate.
///
/// Remote health is evidence about a provider, never proof that this wallet
/// contains the corresponding authenticated transport or recovery machinery.
/// The first blocker is therefore controlled only by compiled wallet code.
pub fn hub_mainnet_readiness_blockers(health: &HubHealth) -> Vec<HubMainnetReadinessBlocker> {
    classify_hub_mainnet_readiness(health, OFFICIAL_CHANNELPAY_MAINNET_TRANSPORT_IMPLEMENTED)
}

fn classify_hub_mainnet_readiness(
    health: &HubHealth,
    wallet_transport_implemented: bool,
) -> Vec<HubMainnetReadinessBlocker> {
    let mut blockers = Vec::new();
    if !wallet_transport_implemented {
        blockers.push(HubMainnetReadinessBlocker::WalletTransportUnavailable);
    }
    if !health.ok {
        blockers.push(HubMainnetReadinessBlocker::HealthCheckFailed);
    }
    if health.version != 4 {
        blockers.push(HubMainnetReadinessBlocker::ApiVersionMismatch);
    }
    if health.deployment_profile.as_deref() != Some(OFFICIAL_CHANNELPAY_PRODUCTION_PROFILE) {
        blockers.push(HubMainnetReadinessBlocker::DeploymentProfileMismatch);
    }
    match health.hub_address.as_deref() {
        None | Some("") => blockers.push(HubMainnetReadinessBlocker::HubAddressMissing),
        Some(address) => {
            match crate::address::require_address_for_network(address, crate::address::MAINNET) {
                Ok(parsed) if parsed.fast_pay_eligible => {}
                _ => blockers.push(HubMainnetReadinessBlocker::HubAddressInvalid),
            }
        }
    }
    if !health.settlement_ready {
        blockers.push(HubMainnetReadinessBlocker::SettlementUnavailable);
    }
    if !health.cross_channel_ready {
        blockers.push(HubMainnetReadinessBlocker::CrossChannelUnavailable);
    }
    if health.hub_fee_mei.is_none() || !hub_fee_is_zero(health) {
        blockers.push(HubMainnetReadinessBlocker::NonZeroOrInvalidHubFee);
    }
    if !health.external_rollback_anchor_ready {
        blockers.push(HubMainnetReadinessBlocker::ExternalRollbackAnchorUnavailable);
    }
    if !health.l1_dispute_path_ready {
        blockers.push(HubMainnetReadinessBlocker::L1DisputePathUnavailable);
    }
    if !health.official_channelpay_ready {
        blockers.push(HubMainnetReadinessBlocker::OfficialChannelpayUnavailable);
    }
    if !health.production_mainnet_ready {
        blockers.push(HubMainnetReadinessBlocker::ProviderNotProductionReady);
    }
    blockers
}

pub fn hub_mainnet_safety_ready(health: &HubHealth) -> bool {
    hub_mainnet_readiness_blockers(health).is_empty()
}

pub fn hub_fee_is_zero(health: &HubHealth) -> bool {
    match health.hub_fee_mei.as_ref() {
        None => true,
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

const MAX_HUB_JSON_BYTES: usize = 2 * 1024 * 1024;

pub struct L2HubClient {
    base_url: String,
    http: Result<reqwest::Client, String>,
}

impl L2HubClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: crate::http_client::shared_http_client().cloned(),
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
    use axum::Router;
    use axum::routing::get;

    use super::*;

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
    }

    fn production_health() -> HubHealth {
        HubHealth {
            ok: true,
            version: 4,
            name: Some("Pinned CSP".into()),
            hub_address: Some("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW".into()),
            hub_fee_mei: Some(serde_json::json!("0")),
            settlement_ready: true,
            cross_channel_ready: true,
            external_rollback_anchor_ready: true,
            l1_dispute_path_ready: true,
            official_channelpay_ready: true,
            production_mainnet_ready: true,
            deployment_profile: Some(OFFICIAL_CHANNELPAY_PRODUCTION_PROFILE.into()),
        }
    }

    #[test]
    fn remote_health_cannot_enable_an_unimplemented_local_transport() {
        let health = production_health();
        assert_eq!(
            hub_mainnet_readiness_blockers(&health),
            vec![HubMainnetReadinessBlocker::WalletTransportUnavailable]
        );
        assert!(!hub_mainnet_safety_ready(&health));
    }

    #[test]
    fn remote_readiness_requires_every_independent_provider_gate() {
        let baseline = production_health();
        assert!(classify_hub_mainnet_readiness(&baseline, true).is_empty());

        let mut cases = Vec::new();
        let mut health = baseline.clone();
        health.ok = false;
        cases.push((HubMainnetReadinessBlocker::HealthCheckFailed, health));
        let mut health = baseline.clone();
        health.version = 3;
        cases.push((HubMainnetReadinessBlocker::ApiVersionMismatch, health));
        let mut health = baseline.clone();
        health.deployment_profile = Some("legacy_wallet_hub_v4_development".into());
        cases.push((
            HubMainnetReadinessBlocker::DeploymentProfileMismatch,
            health,
        ));
        let mut health = baseline.clone();
        health.hub_address = None;
        cases.push((HubMainnetReadinessBlocker::HubAddressMissing, health));
        let mut health = baseline.clone();
        health.hub_address = Some("not-an-address".into());
        cases.push((HubMainnetReadinessBlocker::HubAddressInvalid, health));
        let mut health = baseline.clone();
        health.settlement_ready = false;
        cases.push((HubMainnetReadinessBlocker::SettlementUnavailable, health));
        let mut health = baseline.clone();
        health.cross_channel_ready = false;
        cases.push((HubMainnetReadinessBlocker::CrossChannelUnavailable, health));
        let mut health = baseline.clone();
        health.hub_fee_mei = None;
        cases.push((HubMainnetReadinessBlocker::NonZeroOrInvalidHubFee, health));
        let mut health = baseline.clone();
        health.external_rollback_anchor_ready = false;
        cases.push((
            HubMainnetReadinessBlocker::ExternalRollbackAnchorUnavailable,
            health,
        ));
        let mut health = baseline.clone();
        health.l1_dispute_path_ready = false;
        cases.push((HubMainnetReadinessBlocker::L1DisputePathUnavailable, health));
        let mut health = baseline.clone();
        health.official_channelpay_ready = false;
        cases.push((
            HubMainnetReadinessBlocker::OfficialChannelpayUnavailable,
            health,
        ));
        let mut health = baseline;
        health.production_mainnet_ready = false;
        cases.push((
            HubMainnetReadinessBlocker::ProviderNotProductionReady,
            health,
        ));

        for (expected, health) in cases {
            assert!(
                classify_hub_mainnet_readiness(&health, true).contains(&expected),
                "missing blocker {expected:?}"
            );
        }
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
