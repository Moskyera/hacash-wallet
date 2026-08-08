use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{AgentWalletError, AgentWalletResult};

/// Exact HAC accounting unit used by the Agent Wallet.
///
/// One HAC is 1,000,000 units. No Agent Wallet amount crosses the domain as a
/// floating-point value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HacUnits(u64);

impl HacUnits {
    pub const PER_HAC: u64 = 1_000_000;
    pub const ZERO: Self = Self(0);
    pub const MIN_NETWORK_FEE: Self = Self(1_000);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> AgentWalletResult<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AgentWalletError::IntegerOverflow)
    }

    pub fn checked_sub(self, other: Self) -> AgentWalletResult<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AgentWalletError::InsufficientAgentBalance)
    }

    pub fn from_decimal(raw: &str) -> AgentWalletResult<Self> {
        let value = raw.trim();
        if value.is_empty() || value.starts_with(['+', '-']) {
            return Err(AgentWalletError::InvalidAmount);
        }
        let (whole, fraction) = match value.split_once('.') {
            Some((whole, fraction))
                if !fraction.is_empty()
                    && !fraction.contains('.')
                    && fraction.len() <= 6
                    && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                (whole, fraction)
            }
            Some(_) => return Err(AgentWalletError::InvalidAmount),
            None => (value, ""),
        };
        if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AgentWalletError::InvalidAmount);
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| AgentWalletError::IntegerOverflow)?;
        let fraction = if fraction.is_empty() {
            0
        } else {
            let parsed = fraction
                .parse::<u64>()
                .map_err(|_| AgentWalletError::InvalidAmount)?;
            parsed
                .checked_mul(10_u64.pow((6 - fraction.len()) as u32))
                .ok_or(AgentWalletError::IntegerOverflow)?
        };
        whole
            .checked_mul(Self::PER_HAC)
            .and_then(|value| value.checked_add(fraction))
            .map(Self)
            .ok_or(AgentWalletError::IntegerOverflow)
    }

    pub fn to_decimal(self) -> String {
        let whole = self.0 / Self::PER_HAC;
        let fraction = self.0 % Self::PER_HAC;
        if fraction == 0 {
            return whole.to_string();
        }
        format!("{whole}.{fraction:06}")
            .trim_end_matches('0')
            .to_owned()
    }
}

impl fmt::Display for HacUnits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_decimal())
    }
}

impl Serialize for HacUnits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct UnitsVisitor;

impl Visitor<'_> for UnitsVisitor {
    type Value = HacUnits;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an exact non-negative HAC unit count encoded as a decimal string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(E::custom("HAC units must be an unsigned decimal string"));
        }
        value.parse::<u64>().map(HacUnits).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for HacUnits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(UnitsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_roundtrip_is_exact_without_floats() {
        for raw in ["0", "0.000001", "1", "1.23", "999999.999999"] {
            let units = HacUnits::from_decimal(raw).unwrap();
            assert_eq!(HacUnits::from_decimal(&units.to_decimal()).unwrap(), units);
        }
        assert!(HacUnits::from_decimal("-1").is_err());
        assert!(HacUnits::from_decimal("1.0000001").is_err());
        assert!(HacUnits::from_decimal("1e3").is_err());
    }
}
