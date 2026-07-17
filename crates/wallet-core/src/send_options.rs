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

/// Mandatory Moskyera wallet service fee: 30 basis points (0.3%).
/// The authoritative rule lives in Rust; caller fields are compatibility only.
pub const WALLET_SERVICE_FEE_BPS: u64 = 30;
pub const DEFAULT_SERVICE_FEE_RATE: f64 = 0.003;

/// Fixed HAC fee per non-fungible HACD transfer transaction.
pub const HACD_SERVICE_FEE_MEI: f64 = 0.003;

/// Moskyera wallet treasury. Collects the mandatory wallet service fee on L1 sends.
pub const WALLET_TREASURY_ADDRESS: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";

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
impl SendPreferences {
    pub fn validate(&self) -> WalletResult<()> {
        Ok(())
    }

    pub fn enforce_mandatory_service_fee(&mut self) {
        self.service_fee_enabled = true;
        self.service_fee_rate = DEFAULT_SERVICE_FEE_RATE;
    }
}

/// Fast Pay is fee-free. Retained for API compatibility.
pub const DEFAULT_HUB_FEE_MEI: f64 = 0.0;

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
            other => Err(WalletError::Policy(format!(
                "unknown L1 fee speed: {other}"
            ))),
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
            service_fee_enabled: true,
            service_fee_rate: DEFAULT_SERVICE_FEE_RATE,
        }
    }
    pub fn validate(&self) -> WalletResult<()> {
        Ok(())
    }

    pub fn enforce_mandatory_service_fee(&mut self) {
        self.service_fee_enabled = true;
        self.service_fee_rate = DEFAULT_SERVICE_FEE_RATE;
    }
}

/// Compute 0.3% using integer micro-mei units and round up to the nearest
/// micro-mei. This prevents caller-controlled fee rates at the signing boundary.
pub fn compute_service_fee_mei(amount_mei: f64) -> f64 {
    if !amount_mei.is_finite() || amount_mei <= 0.0 {
        return 0.0;
    }
    const SCALE: f64 = 1_000_000.0;
    let amount_units = (amount_mei * SCALE).ceil() as u128;
    let fee_units = amount_units
        .saturating_mul(WALLET_SERVICE_FEE_BPS as u128)
        .saturating_add(9_999)
        / 10_000;
    fee_units as f64 / SCALE
}

/// Mandatory 0.3% BTC-on-Hacash fee in satoshi, rounded up to one satoshi.
pub fn compute_btc_service_fee_satoshi(satoshi: u64) -> u64 {
    let fee = (satoshi as u128)
        .saturating_mul(WALLET_SERVICE_FEE_BPS as u128)
        .saturating_add(9_999)
        / 10_000;
    fee.min(u64::MAX as u128) as u64
}

pub fn apply_service_fee(breakdown: &mut SendFeeBreakdown, amount_mei: f64) {
    let fee = compute_service_fee_mei(amount_mei);
    breakdown.service_fee_mei = if fee > 0.0 { Some(fee) } else { None };
    breakdown.service_fee_rate = if fee > 0.0 {
        Some(DEFAULT_SERVICE_FEE_RATE)
    } else {
        None
    };
    breakdown.service_fee_treasury = if fee > 0.0 {
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

pub fn fast_pay_fee_breakdown(amount_mei: f64) -> WalletResult<SendFeeBreakdown> {
    if !amount_mei.is_finite() || amount_mei <= 0.0 {
        return Err(WalletError::Policy(
            "payment amount must be a finite positive number".into(),
        ));
    }
    Ok(SendFeeBreakdown {
        payer_debit_mei: amount_mei,
        recipient_credit_mei: amount_mei,
        hub_fee_mei: Some(0.0),
        hub_fee_payer: HubFeePayer::Sender,
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
    fn fast_pay_has_no_fee() {
        let b = fast_pay_fee_breakdown(10.0).unwrap();
        assert!((b.payer_debit_mei - 10.0).abs() < 1e-9);
        assert!((b.recipient_credit_mei - 10.0).abs() < 1e-9);
        assert_eq!(b.hub_fee_mei, Some(0.0));
        assert!(b.service_fee_mei.is_none());
    }

    #[test]
    fn service_fee_defaults_to_point_three_percent() {
        let fee = compute_service_fee_mei(10.0);
        assert!((fee - 0.03).abs() < 1e-9);
        let mut b = fast_pay_fee_breakdown(10.0).unwrap();
        apply_service_fee(&mut b, 10.0);
        assert!((b.payer_debit_mei - 10.03).abs() < 1e-9);
        assert_eq!(
            b.service_fee_treasury.as_deref(),
            Some(WALLET_TREASURY_ADDRESS)
        );
        assert_eq!(b.service_fee_rate, Some(DEFAULT_SERVICE_FEE_RATE));
    }

    #[test]
    fn hac_transfer_pairs_include_treasury_leg() {
        let mut b = fast_pay_fee_breakdown(100.0).unwrap();
        apply_service_fee(&mut b, 100.0);
        let pairs = hac_send_transfer_pairs("1Payee", "100", &b);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "1Payee");
        assert_eq!(pairs[1].0, WALLET_TREASURY_ADDRESS);
        assert!((pairs[1].1.parse::<f64>().unwrap() - 0.3).abs() < 1e-9);
    }
}
#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn caller_cannot_disable_or_change_service_fee() {
        let mut options = SendOptions::default();
        options.service_fee_enabled = false;
        options.service_fee_rate = 0.0;
        options.enforce_mandatory_service_fee();
        assert!(options.service_fee_enabled);
        assert_eq!(options.service_fee_rate, DEFAULT_SERVICE_FEE_RATE);
        assert!((compute_service_fee_mei(100.0) - 0.3).abs() < 1e-9);
        assert_eq!(compute_btc_service_fee_satoshi(100_000), 300);
    }

    #[test]
    fn rejects_non_finite_payment_inputs() {
        assert!(fast_pay_fee_breakdown(f64::NAN).is_err());
    }
}
