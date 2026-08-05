//! Independent HPAY AI Agent Wallet domain.
//!
//! This crate has no reference to `WalletService` and never selects a wallet
//! through global active state. Every operation carries an explicit
//! [`AgentWalletId`] and the blockchain signer accepts only a persisted,
//! exact, manually approved transaction type.

mod amount;
mod companion_signer;
mod diagnostics;
mod emergency;
mod error;
mod journal;
mod node_binding;
mod operation;
mod pairing_outbox;
mod policy;
mod service;
mod signer;
mod storage;
mod types;
mod vault;

pub use amount::HacUnits;
pub use diagnostics::{
    AgentPilotDiagnostics, AgentPilotDiagnosticsExport, AgentPilotDiagnosticsPreview,
    export_pilot_diagnostics,
};
pub use emergency::{
    AgentEmergencyController, AgentEmergencyStatus, AgentSafetyPermit, EmergencyMarkerHealth,
};
pub use error::{AgentWalletError, AgentWalletResult};
pub use hpay_companion_protocol::{
    ApprovalCommitment, DevicePublicRecord, SignedAdminCommand, SignedApprovalDecision,
};
pub use node_binding::AgentNodeStatus;
pub use operation::{AgentPaymentRequest, ApprovalMode, OperationStatus, PaymentOperationView};
pub use pairing_outbox::PairingCompletionOutboxEntry;
pub use policy::{AgentPermission, AgentPolicy, AgentRecord, AgentStatus};
pub use service::{
    AgentCompanionPairingAttempt, AgentCompletedCompanionPairing, AgentDesktopSessionAttempt,
    AgentPairingAttemptBudget, AgentWalletManager, AgentWalletOverview, CreateAgentWallet,
    MAX_PAIRING_REQUEST_ATTEMPTS, UnlockedAgentWalletStatus,
    WITNESS_PENDING_OPERATION_STATUS_NAMES,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use service::{StrandedWitnessRecovery, WitnessRotationControls};
pub use types::{AgentId, AgentWalletId, OperationId, WalletScope};
