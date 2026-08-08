//! Small shared vocabulary for HPAY agent components.
//!
//! This crate intentionally contains no wallet, transport, authentication, or
//! signing behavior.

use std::fmt;

use serde::{Deserialize, Serialize};

pub type TypeResult<T> = Result<T, TypeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeError {
    InvalidIdentifier,
    ScopeMismatch,
}

impl fmt::Display for TypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "agent identifier is invalid",
            Self::ScopeMismatch => "agent wallet scope does not match",
        })
    }
}

impl std::error::Error for TypeError {}

macro_rules! prefixed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(format!("{}{}", $prefix, uuid::Uuid::new_v4().simple()))
            }

            pub fn parse(raw: impl Into<String>) -> TypeResult<Self> {
                let raw = raw.into();
                let suffix = raw
                    .strip_prefix($prefix)
                    .ok_or(TypeError::InvalidIdentifier)?;
                if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(TypeError::InvalidIdentifier);
                }
                Ok(Self(raw.to_ascii_lowercase()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> TypeResult<()> {
                if Self::parse(self.0.clone())? == *self {
                    Ok(())
                } else {
                    Err(TypeError::InvalidIdentifier)
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

prefixed_id!(AgentId, "agent_");
prefixed_id!(AgentWalletId, "aw_");
prefixed_id!(OperationId, "op_");

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletScope(String);

impl WalletScope {
    pub fn for_agent_wallet(wallet_id: &AgentWalletId) -> Self {
        Self(format!("agent_wallet:{wallet_id}"))
    }

    pub fn validate_for(&self, wallet_id: &AgentWalletId) -> TypeResult<()> {
        wallet_id.validate()?;
        if *self == Self::for_agent_wallet(wallet_id) {
            Ok(())
        } else {
            Err(TypeError::ScopeMismatch)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadWalletInfo,
    ReadBalance,
    CreatePaymentIntent,
    ReadOwnOperationStatus,
    ListOwnOperations,
    CancelOwnUnsignedOperation,
}

impl Capability {
    pub const ALL: [Self; 6] = [
        Self::ReadWalletInfo,
        Self::ReadBalance,
        Self::CreatePaymentIntent,
        Self::ReadOwnOperationStatus,
        Self::ListOwnOperations,
        Self::CancelOwnUnsignedOperation,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_scope_are_canonical_and_wallet_bound() {
        let agent = AgentId::new();
        let wallet = AgentWalletId::new();
        assert_eq!(AgentId::parse(agent.to_string()).unwrap(), agent);
        assert!(
            WalletScope::for_agent_wallet(&wallet)
                .validate_for(&wallet)
                .is_ok()
        );
        assert!(
            WalletScope::for_agent_wallet(&wallet)
                .validate_for(&AgentWalletId::new())
                .is_err()
        );
    }

    #[test]
    fn capability_wire_names_are_stable() {
        assert_eq!(
            serde_json::to_string(&Capability::CreatePaymentIntent).unwrap(),
            "\"create_payment_intent\""
        );
    }
}
