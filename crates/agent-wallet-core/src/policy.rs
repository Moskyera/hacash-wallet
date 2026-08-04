use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::amount::HacUnits;
use crate::types::{AgentId, WalletScope};

pub use hpay_agent_types::Capability as AgentPermission;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    pub permissions: BTreeSet<AgentPermission>,
    pub max_per_payment_units: HacUnits,
    pub max_daily_units: HacUnits,
    pub max_pending_operations: u16,
    pub allowed_recipients: BTreeSet<String>,
    pub blocked_recipients: BTreeSet<String>,
    pub approval_mode: crate::operation::ApprovalMode,
    pub policy_epoch: u64,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            permissions: BTreeSet::new(),
            max_per_payment_units: HacUnits::ZERO,
            max_daily_units: HacUnits::ZERO,
            max_pending_operations: 0,
            allowed_recipients: BTreeSet::new(),
            blocked_recipients: BTreeSet::new(),
            approval_mode: crate::operation::ApprovalMode::DesktopManual,
            policy_epoch: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentRecord {
    pub agent_id: AgentId,
    pub wallet_scope: WalletScope,
    pub name: String,
    pub version: String,
    pub identity_public_key_sec1: String,
    pub identity_fingerprint: String,
    pub identity_key_sha256: String,
    pub server_identity: hpay_agent_connector::PinnedServerIdentity,
    pub status: AgentStatus,
    pub authorization_epoch: u64,
    pub policy: AgentPolicy,
    pub paired_at: u64,
}
