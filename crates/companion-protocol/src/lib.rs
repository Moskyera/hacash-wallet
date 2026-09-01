//! Security primitives and typed messages for the HPAY desktop/mobile companion.
//!
//! This crate deliberately contains no networking implementation and no wallet,
//! blockchain, seed, or private-key type. Device identity keys authenticate
//! companion messages only and must be stored by the platform keystore.

pub const HPAY_LOCAL_PILOT_NETWORK_ID: &str = "local_pilot_v1";

/// The network id the desktop stamps into an L1 binding on mainnet.
///
/// It is `node.network_kind()`, the same accessor that produces
/// [`HPAY_LOCAL_PILOT_NETWORK_ID`] on the local pilot rail, and its value is
/// `HPAY_MAINNET_NETWORK_KIND` in `hacash-wallet-core::node_capabilities`.
pub const HPAY_MAINNET_NETWORK_ID: &str = "mainnet";

/// The `ActivitySummary::status` values that mean "this operation is waiting on
/// the paired phone's rollback witness".
///
/// This is the shared vocabulary for the one narrow disclosure the desktop makes
/// to a phone holding `DevicePermission::WitnessRollbackAnchor`: the id of the
/// single operation that cannot proceed without that phone's signature. The
/// desktop derives its own copy from its operation state machine and asserts
/// equality with this list; the phone matches against this list before it offers
/// the owner anything to confirm.
///
/// It is not a permission and grants nothing. A status outside this set is never
/// a reason to disclose an operation, and an operation inside it is never a
/// reason to skip a check.
pub const WITNESS_PENDING_ACTIVITY_STATUSES: [&str; 4] = [
    "signed_awaiting_witness",
    "submitted_awaiting_final_witness",
    "broadcast_uncertain",
    "reconciled_awaiting_final_witness",
];
const LEGACY_PILOT_NETWORK_ID: &str = "testnet";

/// Whether a companion record names a network this wallet actually runs on.
///
/// The value being tested is always `node.network_kind()`, stamped by the
/// desktop from the verified node probe. There are exactly two rails, and both
/// are pinned by identity predicates in `hacash-wallet-core::node_capabilities`:
/// the local pilot rail stamps `local_pilot_v1`, and mainnet stamps `mainnet`.
/// `testnet` is a declared legacy alias for the pilot rail and is kept only so
/// records written by older builds still decode.
///
/// Before mainnet was listed here, every L1 companion record produced on
/// mainnet failed to encode - not to authorize, to ENCODE - so a paired phone
/// received no status snapshot at all and could never approve or witness a
/// mainnet payment.
pub(crate) fn is_supported_network_id(value: &str) -> bool {
    matches!(
        value,
        HPAY_LOCAL_PILOT_NETWORK_ID | HPAY_MAINNET_NETWORK_ID | LEGACY_PILOT_NETWORK_ID
    )
}

/// The same question for a record that also carries the chain id, where the
/// PAIR is what has to be right.
///
/// Mainnet is chain id 0 and the pilot rail is a non-zero chain id, so a blanket
/// `chain_id != 0` - which is what this predicate replaced - is exactly what
/// excluded mainnet. Keeping the pair together means a mainnet id can never
/// arrive with a pilot chain id, or the reverse.
pub(crate) fn is_supported_network_binding(network_id: &str, chain_id: u32) -> bool {
    match network_id {
        HPAY_MAINNET_NETWORK_ID => chain_id == 0,
        HPAY_LOCAL_PILOT_NETWORK_ID | LEGACY_PILOT_NETWORK_ID => chain_id != 0,
        _ => false,
    }
}

mod admin;
mod approval;
mod codec;
mod envelope;
mod error;
mod fast_pay_approval;
mod hvm_approval;
mod identity;
mod message;
mod pairing;
mod replay;
mod rotation;
mod serde_decimal_u64;
mod session;
mod transport;
mod witness;

pub use admin::{AdminCommand, AdminCommandKind, SignedAdminCommand};
pub use approval::{
    ApprovalCommitment, ApprovalDecision, ApprovalNetworkBinding, MobileApprovalDecision,
    SignedApprovalDecision,
};
pub use envelope::{EncryptedCompanionFrame, FRAME_VERSION, SessionCipher};
pub use error::{CompanionError, CompanionResult};
pub use fast_pay_approval::{
    AGENT_FAST_PAY_APPROVAL_MAX_LIFETIME_SECS, AGENT_FAST_PAY_APPROVAL_VERSION,
    AgentFastPayApprovalCommitment, AgentFastPayApprovalDecision, AgentFastPayNetworkBinding,
    SignedAgentFastPayApprovalDecision,
};
pub use hvm_approval::{
    AGENT_HVM_APPROVAL_MAX_LIFETIME_SECS, AGENT_HVM_APPROVAL_VERSION, AgentHvmApprovalCommitment,
    AgentHvmApprovalDecision, SignedAgentHvmApprovalDecision,
};
#[cfg(feature = "dev-software-identity")]
pub use identity::SoftwareDeviceIdentity;
pub use identity::{
    DeviceId, DevicePermission, DevicePublicRecord, DeviceRegistry, DeviceRole,
    DeviceSignaturePurpose, DeviceSignatureVerifier, DeviceSigningRequest, PlatformDeviceIdentity,
    PlatformDeviceSigner, PlatformP256Signature, PlatformSignFuture,
};
pub use message::{
    ActivitySummary, AgentAuthorizationState, AgentPolicySummary, AgentSummary, CompanionMessage,
    CompanionPayload, CompanionStatus, PROTOCOL_VERSION,
};
pub use pairing::{
    LanEndpoint, MobilePairingAttempt, MobilePairingProof, PairingConfirmation, PairingOffer,
    PairingRequest, PairingResult, PairingSession,
};
pub use replay::{
    MAX_CLOCK_SKEW_SECS, ReplayGuard, ReplayGuardSnapshot, ReplayHighWaterMark, ReplayMetadata,
    ReplayNonceRecord, ReplayPermit,
};
pub use rotation::{
    RotationCandidateAcceptance, RotationPairingTicket, SignedRotationCandidateAcceptance,
    SignedRotationPairingTicket, SignedWitnessRotationAuthorization,
    SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationMode,
    WitnessRotationPhase, WitnessRotationReason, WitnessRotationRecord,
};
pub use session::{
    DesktopChallengeSequence, DesktopSessionAttempt, EstablishedSession,
    MAX_REQUESTED_SESSION_LIFETIME_SECS, MobileSessionAttempt, SESSION_PROTOCOL_VERSION,
    SessionChallenge, SessionConfirmation, SessionResponse,
};
pub use transport::{
    CompanionConnection, CompanionTransport, DisabledRelayCompanionTransport, TransportFuture,
};
pub use witness::{
    MobileWitnessState, RollbackAnchor, RollbackOperationPhase, SignedRollbackAnchor,
    SignedWitnessReceipt, WitnessReceipt, WitnessReconciliationStatus, WitnessReservationState,
    WitnessSubmissionStatus, WitnessTransactionState,
};
