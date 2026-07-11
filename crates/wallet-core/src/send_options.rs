//! Per-send options: hub fee payer and rail preference.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

fn default_prefer_fast_pay() -> bool {
    true
}

/// Persisted defaults for the Send tab (fee payer, rail preference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreferences {
    #[serde(default)]
    pub hub_fee_payer: HubFeePayer,
    #[serde(default = "default_prefer_fast_pay")]
    pub prefer_fast_pay: bool,
}

impl Default for SendPreferences {
    fn default() -> Self {
        Self {
            hub_fee_payer: HubFeePayer::Sender,
            prefer_fast_pay: true,
        }
    }
}

/// Default hub fee when the provider does not advertise one (mei).
pub const DEFAULT_HUB_FEE_MEI: f64 = 0.001;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HubFeePayer {
    /// Payer's channel balance is debited amount + hub fee; payee receives full amount.
    #[default]
    Sender,
    /// Payer debits only the entered amount; payee receives amount − hub fee.
    Recipient,
}

impl HubFeePayer {
    pub fn parse(s: &str) -> WalletResult<Self> {
        match s.trim().to_lowercase().as_str() {
            "sender" | "" => Ok(Self::Sender),
            "recipient" | "payee" => Ok(Self::Recipient),
            other => Err(WalletError::Policy(format!(
                "unknown hub fee payer: {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Recipient => "recipient",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendOptions {
    pub hub_fee_payer: HubFeePayer,
    /// When true, skip Fast Pay even if a channel is ready.
    pub force_l1: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            hub_fee_payer: HubFeePayer::Sender,
            force_l1: false,
        }
    }
}

impl SendOptions {
    pub fn from_preferences(prefs: &SendPreferences) -> Self {
        Self {
            hub_fee_payer: prefs.hub_fee_payer,
            force_l1: !prefs.prefer_fast_pay,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendFeeBreakdown {
    pub payer_debit_mei: f64,
    pub recipient_credit_mei: f64,
    pub hub_fee_mei: Option<f64>,
    pub hub_fee_payer: HubFeePayer,
    pub l1_fee_wire: Option<String>,
}

pub fn fast_pay_fee_breakdown(
    amount_mei: f64,
    hub_fee_mei: f64,
    fee_payer: HubFeePayer,
) -> WalletResult<SendFeeBreakdown> {
    let (payer_debit, recipient_credit) = match fee_payer {
        HubFeePayer::Sender => (amount_mei + hub_fee_mei, amount_mei),
        HubFeePayer::Recipient => {
            if amount_mei <= hub_fee_mei {
                return Err(WalletError::Policy(format!(
                    "amount must exceed hub fee ({hub_fee_mei:.3} HAC) when the recipient pays the fee"
                )));
            }
            (amount_mei, amount_mei - hub_fee_mei)
        }
    };
    Ok(SendFeeBreakdown {
        payer_debit_mei: payer_debit,
        recipient_credit_mei: recipient_credit,
        hub_fee_mei: Some(hub_fee_mei),
        hub_fee_payer: fee_payer,
        l1_fee_wire: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_pays_adds_hub_fee_to_debit() {
        let b = fast_pay_fee_breakdown(10.0, 0.001, HubFeePayer::Sender).unwrap();
        assert!((b.payer_debit_mei - 10.001).abs() < 1e-9);
        assert!((b.recipient_credit_mei - 10.0).abs() < 1e-9);
    }

    #[test]
    fn recipient_pays_deducts_fee_from_credit() {
        let b = fast_pay_fee_breakdown(10.0, 0.001, HubFeePayer::Recipient).unwrap();
        assert!((b.payer_debit_mei - 10.0).abs() < 1e-9);
        assert!((b.recipient_credit_mei - 9.999).abs() < 1e-9);
    }

    #[test]
    fn recipient_pays_rejects_tiny_amount() {
        assert!(fast_pay_fee_breakdown(0.001, 0.001, HubFeePayer::Recipient).is_err());
    }
}