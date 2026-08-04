use std::collections::BTreeSet;
use std::fs;

use hpay_agent_connector::{AgentIdentityKey, PairedAgent, PairedAgentStatus, ServerIdentityKey};
use hpay_companion_protocol::{
    AdminCommand, ApprovalCommitment, DevicePermission, MobileApprovalDecision, SignedAdminCommand,
    SoftwareDeviceIdentity,
};

use super::*;
use crate::journal::AgentJournalEventKind;
use crate::operation::{AgentOperation, AgentPaymentRequest};
use crate::policy::{AgentPermission, AgentPolicy, AgentRecord, AgentStatus};
use crate::service::{
    AgentWalletState, CreateAgentWallet, PENDING_STATE_NAME, STATE_NAME, STATE_SCHEMA_VERSION,
};
use crate::types::{AgentId, WalletScope};

mod decisions;
mod fixtures;
mod lifecycle;
mod pairing;
mod registry;
mod session;
mod snapshot;
mod transport;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod witness;
