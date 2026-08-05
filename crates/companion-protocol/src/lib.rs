//! Security primitives and typed messages for the HPAY desktop/mobile companion.
//!
//! This crate deliberately contains no networking implementation and no wallet,
//! blockchain, seed, or private-key type. Device identity keys authenticate
//! companion messages only and must be stored by the platform keystore.

pub const HPAY_LOCAL_PILOT_NETWORK_ID: &str = "local_pilot_v1";

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

pub(crate) fn is_supported_pilot_network_id(value: &str) -> bool {
    value == HPAY_LOCAL_PILOT_NETWORK_ID || value == LEGACY_PILOT_NETWORK_ID
}

mod admin;
mod approval;
mod codec;
mod envelope;
mod error;
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
