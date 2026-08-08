//! Wallet Hub API v4. mirrors `hacash-wallet-core::l2_hub` client types.

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};

pub const HUB_API_VERSION: u32 = 4;

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
    /// True only after an external monotonic journal-head anchor is configured.
    #[serde(default)]
    pub external_rollback_anchor_ready: bool,
    /// True only after unilateral dispute and final-claim recovery is proven on this network.
    #[serde(default)]
    pub l1_dispute_path_ready: bool,
    /// True only for an authenticated Official ChannelPay session, not Wallet Hub API v4.
    #[serde(default)]
    pub official_channelpay_ready: bool,
    /// Aggregate operator assertion. Wallets still verify every prerequisite independently.
    #[serde(default)]
    pub production_mainnet_ready: bool,
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
