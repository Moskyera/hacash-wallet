//! Strict JSON representation for values that must cross a JavaScript bridge.
//!
//! Canonical protocol encodings remain fixed-width `u64`. Serde transports use
//! decimal strings so values above JavaScript's safe integer limit cannot be
//! rounded or silently changed.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct DecimalU64Visitor;

    impl Visitor<'_> for DecimalU64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an unsigned 64-bit integer encoded as a decimal string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(E::custom(
                    "unsigned 64-bit values must be strict decimal strings",
                ));
            }
            parse_decimal(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(DecimalU64Visitor)
}
fn parse_decimal(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("unsigned 64-bit values must be strict decimal strings");
    }
    value
        .parse::<u64>()
        .map_err(|_| "unsigned 64-bit decimal string is out of range")
}

pub(crate) mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .as_deref()
            .map(super::parse_decimal)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
