//! Wallet Hub API v1 — mirrors `hacash-wallet-core::l2_hub` client types.

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};

pub const HUB_API_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bill_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
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