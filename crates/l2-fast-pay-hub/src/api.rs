//! Wallet Hub API v7. mirrors `hacash-wallet-core::l2_hub` client types.

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};

pub const HUB_API_VERSION: u32 = 7;

/// The `/v1/health` payload: a cheap liveness answer, served from Hub-local
/// state without any fullnode I/O.
///
/// Because it takes no measurement, it publishes no capability-dependent
/// guarantee - not conservatively, not at all. A guarantee flag on this struct
/// could only ever read `false` for want of evidence, which is indistinguishable
/// from "checked and found absent"; a wallet gating on one would be permanently
/// bricked, and a wallet trusting a `true` one would be trusting an unmeasured
/// assertion. `/v1/readiness/mainnet` is the sole authority: it probes the
/// fullnode, runs `HubHardGuarantees::measure` over the evidence, and publishes
/// the result as `trustless_finality` / `unilateral_l1_enforceable`. That is the
/// document the Hub's own money gate reads, and the one every wallet gate reads.
///
/// Nothing here should ever grow back into a guarantee. Fields on this struct
/// answer "who are you and are you up", never "what are you good for".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_fee_mei: Option<String>,
    /// True only when the hub has an active signing key and can produce dispute-ready bills.
    #[serde(default)]
    pub settlement_ready: bool,
    /// True only when the hub completes the recipient-signature flow for routed payments.
    #[serde(default)]
    pub cross_channel_ready: bool,
    /// True only for an authenticated Official ChannelPay session, not Wallet Hub API v7.
    #[serde(default)]
    pub official_channelpay_ready: bool,
    /// Explicit bounded pilot that depends on Hub availability and configured caps.
    ///
    /// Answerable from Hub-local configuration and the signing key alone, so it
    /// is a liveness fact rather than a measured guarantee. The bounded pilot's
    /// actual settlement authority still comes from `/v1/readiness/mainnet`.
    #[serde(default)]
    pub trusted_bounded_pilot_ready: bool,
    /// Truthful transport/deployment label for UI and diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayRequest {
    /// Stable caller-generated UUID. Reused retries must carry the same value.
    pub operation_id: String,
    /// Stable opaque key bound to the immutable request payload.
    pub idempotency_key: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
    /// `sender` (default) or `recipient`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayResponse {
    pub payment_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bill_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub created_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmFastPayRequest {
    pub idempotency_key: String,
    pub bill_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevBillEnvelope {
    pub v: u32,
    pub kind: String,
    pub payment_id: String,
    /// Payer's channel (always present).
    pub channel_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub left_balance: String,
    pub right_balance: String,
    pub bill_auto_number: u64,
    pub timestamp: u64,
    /// `same_channel` or `cross_channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Set when funds are credited on a different channel than the payer's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_left_balance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_right_balance: Option<String>,
}

impl DevBillEnvelope {
    pub fn to_bill_hex(&self) -> HubResult<String> {
        let json = serde_json::to_vec(self).map_err(|e| HubError::Payment(e.to_string()))?;
        Ok(hex::encode(json))
    }
}
