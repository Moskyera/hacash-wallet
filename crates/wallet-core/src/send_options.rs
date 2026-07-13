//! Per-send options: hub fee payer and rail preference.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

fn default_prefer_fast_pay() -> bool {
    true
}

fn default_l1_fee_speed() -> L1FeeSpeed {
    L1FeeSpeed::Normal
}

fn default_service_fee_enabled() -> bool {
    true
}

fn default_service_fee_rate() -> f64 {
    DEFAULT_SERVICE_FEE_RATE
}

/// Default optional ecosystem / DEX service fee (0.3% of send amount).
pub const DEFAULT_SERVICE_FEE_RATE: f64 = 0.003;

/// Moskyera wallet treasury — collects optional ecosystem service fees on sends.
pub const WALLET_TREASURY_ADDRESS: &str = "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa";

/// Persisted defaults for the Send tab (fee payer, rail preference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreferences {
    #[serde(default)]
    pub hub_fee_payer: HubFeePayer,
    #[serde(default = "default_prefer_fast_pay")]
    pub prefer_fast_pay: bool,
    #[serde(default = "default_l1_fee_speed")]
    pub l1_fee_speed: L1FeeSpeed,
    #[serde(default = "default_service_fee_enabled")]
    pub service_fee_enabled: bool,
    #[serde(default = "default_service_fee_rate")]
    pub service_fee_rate: f64,
}

impl Default for SendPreferences {
    fn default() -> Self {
        Self {
            hub_fee_payer: HubFeePayer::Sender,
            prefer_fast_pay: true,
            l1_fee_speed: L1FeeSpeed::Normal,
            service_fee_enabled: true,
            service_fee_rate: DEFAULT_SERVICE_FEE_RATE,
        }
    }
}

/// Default hub fee when the provider does not advertise one (mei).
pub const DEFAULT_HUB_FEE_MEI: f64 = 0.001;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum L1FeeSpeed {
    Slow,
    #[default]
    Normal,
    Fast,
    Ultra,
}

impl L1FeeSpeed {
    pub fn parse(s: &str) -> WalletResult<Self> {
        match s.trim().to_lowercase().as_str() {
            "slow" | "economy" => Ok(Self::Slow),
            "normal" | "standard" | "" => Ok(Self::Normal),
            "fast" | "priority" => Ok(Self::Fast),
            "ultra" | "maximum" => Ok(Self::Ultra),
            other => Err(WalletError::Policy(format!("unknown L1 fee speed: {other}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Slow => "slow",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Ultra => "ultra",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Slow => "Slow",
            Self::Normal => "Normal",
            Self::Fast => "Fast",
            Self::Ultra => "Ultra",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::Slow => "Lowest fee. Slower confirmation.",
            Self::Normal => "Network average. Balanced.",
            Self::Fast => "Higher fee. Faster confirmation.",
            Self::Ultra => "Highest fee. Fastest confirmation.",
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SendOptions {
    pub hub_fee_payer: HubFeePayer,
    /// When true, skip Fast Pay even if a channel is ready.
    pub force_l1: bool,
    pub l1_fee_speed: L1FeeSpeed,
    pub service_fee_enabled: bool,
    pub service_fee_rate: f64,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            hub_fee_payer: HubFeePayer::Sender,
            force_l1: false,
            l1_fee_speed: L1FeeSpeed::Normal,
            service_fee_enabled: true,
            service_fee_rate: DEFAULT_SERVICE_FEE_RATE,
        }
    }
}

impl SendOptions {
    pub fn from_preferences(prefs: &SendPreferences) -> Self {
        Self {
            hub_fee_payer: prefs.hub_fee_payer,
            force_l1: !prefs.prefer_fast_pay,
            l1_fee_speed: prefs.l1_fee_speed,
            service_fee_enabled: prefs.service_fee_enabled,
            service_fee_rate: prefs.service_fee_rate,
        }
    }
}

pub fn compute_service_fee_mei(amount_mei: f64, enabled: bool, rate: f64) -> f64 {
    if !enabled || rate <= 0.0 || amount_mei <= 0.0 {
        return 0.0;
    }
    crate::hip23::normalize_l1_fee_mei(amount_mei * rate)
}

pub fn apply_service_fee(
    breakdown: &mut SendFeeBreakdown,
    amount_mei: f64,
    recipient: &str,
    enabled: bool,
    rate: f64,
) {
    let fee = compute_service_fee_mei(amount_mei, enabled, rate);
    breakdown.service_fee_mei = if fee > 0.0 { Some(fee) } else { None };
    breakdown.service_fee_rate = if enabled && rate > 0.0 {
        Some(rate)
    } else {
        None
    };
    breakdown.service_fee_treasury = if fee > 0.0 && recipient != WALLET_TREASURY_ADDRESS {
        Some(WALLET_TREASURY_ADDRESS.to_string())
    } else {
        None
    };
    if fee > 0.0 {
        breakdown.payer_debit_mei += fee;
    }
}

pub fn format_service_fee_amount_wire(fee_mei: f64) -> String {
    crate::hip23::format_l1_fee_mei_for_node(fee_mei)
}

/// L1 `kind: 1` outputs: primary recipient plus optional treasury service-fee leg.
pub fn hac_send_transfer_pairs(
    recipient: &str,
    amount_wire: &str,
    breakdown: &SendFeeBreakdown,
) -> Vec<(String, String)> {
    let mut out = vec![(recipient.to_string(), amount_wire.to_string())];
    if breakdown.service_fee_treasury.is_some() {
        if let Some(fee_mei) = breakdown.service_fee_mei {
            if fee_mei > 0.0 {
                out.push((
                    WALLET_TREASURY_ADDRESS.to_string(),
                    format_service_fee_amount_wire(fee_mei),
                ));
            }
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendFeeBreakdown {
    pub payer_debit_mei: f64,
    pub recipient_credit_mei: f64,
    pub hub_fee_mei: Option<f64>,
    pub hub_fee_payer: HubFeePayer,
    pub l1_fee_wire: Option<String>,
    pub l1_fee_mei: Option<f64>,
    #[serde(default)]
    pub service_fee_mei: Option<f64>,
    #[serde(default)]
    pub service_fee_rate: Option<f64>,
    #[serde(default)]
    pub service_fee_treasury: Option<String>,
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
        l1_fee_mei: None,
        service_fee_mei: None,
        service_fee_rate: None,
        service_fee_treasury: None,
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

    #[test]
    fn service_fee_defaults_to_point_three_percent() {
        let fee = compute_service_fee_mei(10.0, true, DEFAULT_SERVICE_FEE_RATE);
        assert!((fee - 0.03).abs() < 1e-9);
        let mut b = fast_pay_fee_breakdown(10.0, 0.001, HubFeePayer::Sender).unwrap();
        apply_service_fee(&mut b, 10.0, "1Recipient", true, DEFAULT_SERVICE_FEE_RATE);
        assert!((b.payer_debit_mei - 10.031).abs() < 1e-9);
        assert_eq!(b.service_fee_treasury.as_deref(), Some(WALLET_TREASURY_ADDRESS));
        assert_eq!(b.service_fee_rate, Some(DEFAULT_SERVICE_FEE_RATE));
    }

    #[test]
    fn hac_transfer_pairs_include_treasury_leg() {
        let mut b = fast_pay_fee_breakdown(100.0, 0.001, HubFeePayer::Sender).unwrap();
        apply_service_fee(&mut b, 100.0, "1Payee", true, DEFAULT_SERVICE_FEE_RATE);
        let pairs = hac_send_transfer_pairs("1Payee", "100", &b);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "1Payee");
        assert_eq!(pairs[1].0, WALLET_TREASURY_ADDRESS);
        assert!((pairs[1].1.parse::<f64>().unwrap() - 0.3).abs() < 1e-9);
    }
}