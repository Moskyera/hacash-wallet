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

#[cfg(feature = "agent-wallet-testnet-pilot")]
mod backup_recovery_establishment;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod broadcast_crash_recovery;
mod decisions;
mod desktop_approval;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod desktop_witness_flow;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod durable_write_probe;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod fast_pay_decisions;
mod fixtures;
mod lifecycle;
mod pairing;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod pilot_node;
mod registry;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod restore_atomicity;
mod session;
mod snapshot;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod state_backup;
mod transport;
mod unlisted_recipient;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod witness;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod witness_crash_recovery;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod witness_phase_expiry;
