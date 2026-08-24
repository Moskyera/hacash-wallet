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
mod fast_pay_operation;
mod hvm_payment_operation;
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
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use fast_pay_operation::{AgentFastPayOperationView, AgentFastPayRequest, AgentFastPayStatus};
pub use hpay_companion_protocol::{
    ApprovalCommitment, DevicePublicRecord, SignedAdminCommand, SignedApprovalDecision,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use hvm_payment_operation::{
    AgentHvmPaymentOperationView, AgentHvmPaymentRequest, AgentHvmPaymentStatus,
};
pub use node_binding::AgentNodeStatus;
pub use operation::{AgentPaymentRequest, ApprovalMode, OperationStatus, PaymentOperationView};
pub use pairing_outbox::PairingCompletionOutboxEntry;
pub use policy::{AgentPermission, AgentPolicy, AgentRecord, AgentStatus};
pub use service::{
    AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT, AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING,
    AgentWalletBackupAcknowledgement, AgentWalletBackupFile, AgentWalletBackupMetadata,
    AgentWalletBackupPreview, AgentWalletBackupWarning, AgentWalletRestoreOutcome,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub use service::{
    AGENT_REGISTRY_EXIT_GAS_BUDGET, AGENT_REGISTRY_EXIT_GAS_MAX,
    AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES, AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU,
    AGENT_VM_LOWEST_FEE_PURITY_UNIT238, AgentHvmRegistryExitProgress,
    AgentHvmRegistryExitStepProgress, StrandedWitnessRecovery, WitnessRotationControls,
    agent_registry_exit_gas_reserve_zhu, agent_registry_exit_transaction_ceiling_zhu,
};
pub use service::{
    AgentChannelClosePhase, AgentChannelCloseReview, AgentChannelCloseVoucherBroadcast,
    AgentChannelCloseVoucherPhase, AgentChannelCloseVoucherView, AgentChannelSetupPhase,
    AgentChannelSetupReview, AgentCompanionPairingAttempt, AgentCompletedCompanionPairing,
    AgentDesktopSessionAttempt, AgentHvmChannelBinding, AgentHvmRegistryBinding,
    AgentHvmRegistryChannelOpen, AgentHvmRegistryCountersignedRefund, AgentHvmRegistryFunding,
    AgentL2Binding, AgentPairingAttemptBudget, AgentWalletManager, AgentWalletOverview,
    CreateAgentWallet, MAX_PAIRING_REQUEST_ATTEMPTS, UnlockedAgentWalletStatus,
    WITNESS_PENDING_OPERATION_STATUS_NAMES,
};
pub use types::{AgentId, AgentWalletId, OperationId, WalletScope};
