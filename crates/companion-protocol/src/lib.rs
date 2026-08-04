//! Security primitives and typed messages for the HPAY desktop/mobile companion.
//!
//! This crate deliberately contains no networking implementation and no wallet,
//! blockchain, seed, or private-key type. Device identity keys authenticate
//! companion messages only and must be stored by the platform keystore.

pub const HPAY_LOCAL_PILOT_NETWORK_ID: &str = "local_pilot_v1";
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
