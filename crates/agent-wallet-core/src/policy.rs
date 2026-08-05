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
    /// Owner-only, per-agent, default off.
    ///
    /// When false (the only value any wallet has until its owner deliberately
    /// changes it) a recipient absent from `allowed_recipients` is refused at
    /// intent time, exactly as before this field existed.
    ///
    /// When true the agent may only *propose* such a payment. It still passes
    /// every other limit, still reaches the same approval ceremony bound to the
    /// exact recipient, amount, fee and total debit, and is admitted only by an
    /// exact owner approval. `blocked_recipients` is unaffected and stays
    /// absolute, and approving one payment never writes the recipient into
    /// `allowed_recipients`.
    ///
    /// `skip_serializing_if` is load bearing, not cosmetic: the whole state is
    /// re-serialized by `state_commitment` and compared against the commitment
    /// stored in the authenticated journal head. Omitting the field when false
    /// keeps already-stored wallets byte-identical, so they still verify.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_unlisted_recipient_with_approval: bool,
    pub approval_mode: crate::operation::ApprovalMode,
    pub policy_epoch: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
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
            allow_unlisted_recipient_with_approval: false,
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
