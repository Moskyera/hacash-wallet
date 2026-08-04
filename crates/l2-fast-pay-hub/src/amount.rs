use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{HubError, HubResult};

/// Exact HAC amount stored as integer millimeis (1 HAC = 1,000 millimeis).
///
/// Persisted state serializes this value as a decimal HAC string. Deserialization
/// also accepts the legacy JSON number representation so existing API v4 hub
/// state files migrate without a destructive reset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HacAmount(u64);

impl HacAmount {
    pub const ZERO: Self = Self(0);

    pub const fn from_millimeis(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_millimeis(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> HubResult<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or_else(|| HubError::Payment("HAC amount overflow".into()))
    }

    pub fn checked_sub(self, other: Self) -> HubResult<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or_else(|| HubError::Payment("insufficient channel balance".into()))
    }
}

impl fmt::Display for HacAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&format_amount_mei(*self))
    }
}

impl Serialize for HacAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format_amount_mei(*self))
    }
}

struct HacAmountVisitor;

impl<'de> Visitor<'de> for HacAmountVisitor {
    type Value = HacAmount;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-negative HAC decimal with at most three fractional digits")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_amount_mei(value).map_err(E::custom)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_amount_mei(&value.to_string()).map_err(E::custom)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_amount_mei(&value.to_string()).map_err(E::custom)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.is_finite() || value < 0.0 {
            return Err(E::custom(
                "legacy HAC amount is not finite and non-negative",
            ));
        }
        let millimeis = value * 1000.0;
        let rounded = millimeis.round();
        if !millimeis.is_finite() || (millimeis - rounded).abs() > 1e-9 || rounded > u64::MAX as f64
        {
            return Err(E::custom(
                "legacy HAC amount is not an exact whole-millimei value",
            ));
        }
        Ok(HacAmount::from_millimeis(rounded as u64))
    }
}

impl<'de> Deserialize<'de> for HacAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(HacAmountVisitor)
    }
}

/// Parse HAC amount from node wire (`whole:frac`) or plain decimal HAC.
pub fn parse_amount_mei(wire: &str) -> HubResult<HacAmount> {
    let value = wire.trim();
    if value.is_empty() {
        return Err(HubError::Payment("empty amount".into()));
    }

    if let Some((whole, millimeis)) = value.split_once(':') {
        if millimeis.contains(':')
            || whole.is_empty()
            || millimeis.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !millimeis.bytes().all(|byte| byte.is_ascii_digit())
            || millimeis.len() > 3
        {
            return Err(HubError::Payment(format!("invalid amount: {wire}")));
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| HubError::Payment(format!("amount is too large: {wire}")))?;
        let millimeis = millimeis
            .parse::<u64>()
            .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))?;
        return whole
            .checked_mul(1000)
            .and_then(|whole| whole.checked_add(millimeis))
            .map(HacAmount::from_millimeis)
            .ok_or_else(|| HubError::Payment(format!("amount is too large: {wire}")));
    }

    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction))
            if !fraction.is_empty()
                && !fraction.contains('.')
                && fraction.len() <= 3
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (whole, fraction)
        }
        Some(_) => return Err(HubError::Payment(format!("invalid amount: {wire}"))),
        None => (value, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HubError::Payment(format!("invalid amount: {wire}")));
    }

    let whole = whole
        .parse::<u64>()
        .map_err(|_| HubError::Payment(format!("amount is too large: {wire}")))?;
    let fraction = match fraction.len() {
        0 => 0,
        1 => {
            fraction
                .parse::<u64>()
                .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))?
                * 100
        }
        2 => {
            fraction
                .parse::<u64>()
                .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))?
                * 10
        }
        3 => fraction
            .parse::<u64>()
            .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))?,
        _ => unreachable!("fraction length was bounded above"),
    };
    whole
        .checked_mul(1000)
        .and_then(|whole| whole.checked_add(fraction))
        .map(HacAmount::from_millimeis)
        .ok_or_else(|| HubError::Payment(format!("amount is too large: {wire}")))
}
pub fn format_amount_mei(amount: HacAmount) -> String {
    let whole = amount.as_millimeis() / 1000;
    let fraction = amount.as_millimeis() % 1000;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{fraction:03}")
        .trim_end_matches('0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_wire_exactly() {
        assert_eq!(
            parse_amount_mei("1:244").unwrap(),
            HacAmount::from_millimeis(1244)
        );
    }

    #[test]
    fn colon_uses_raw_millimeis_while_decimal_uses_decimal_places() {
        assert_eq!(parse_amount_mei("1:2").unwrap().as_millimeis(), 1_002);
        assert_eq!(parse_amount_mei("1.2").unwrap().as_millimeis(), 1_200);
        assert!(parse_amount_mei("1:").is_err());
        assert!(parse_amount_mei("1.").is_err());
    }

    #[test]
    fn parses_decimal_exactly() {
        assert_eq!(
            parse_amount_mei("10.5").unwrap(),
            HacAmount::from_millimeis(10_500)
        );
    }

    #[test]
    fn rejects_sub_millimei_or_non_decimal_input() {
        assert!(parse_amount_mei("1.0004").is_err());
        assert!(parse_amount_mei("1e3").is_err());
        assert!(parse_amount_mei("+1").is_err());
    }

    #[test]
    fn rejects_non_canonical_or_negative_values() {
        assert!(parse_amount_mei("1:1000").is_err());
        assert!(parse_amount_mei("NaN").is_err());
        assert!(parse_amount_mei("-1").is_err());
    }

    #[test]
    fn formatting_roundtrips_exact_integer_units() {
        for units in [0, 1, 10, 100, 999, 1000, 1244, u32::MAX as u64] {
            let amount = HacAmount::from_millimeis(units);
            assert_eq!(
                parse_amount_mei(&format_amount_mei(amount)).unwrap(),
                amount
            );
        }
    }

    #[test]
    fn persisted_state_accepts_legacy_float_and_writes_decimal_string() {
        let legacy: HacAmount = serde_json::from_str("7.498").unwrap();
        assert_eq!(legacy, HacAmount::from_millimeis(7498));
        assert_eq!(serde_json::to_string(&legacy).unwrap(), "\"7.498\"");
    }
}
