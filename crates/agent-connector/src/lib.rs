//! Local-only HPAY Agent Connector protocol foundation.
//!
//! The connector deliberately exposes a small intent API. It has no Personal
//! Wallet handle, blockchain signer, raw transaction command, TCP listener, or
//! HTTP server. Platform listeners are disabled unless the embedding desktop
//! application explicitly enables them.

pub mod authentication;
pub mod error;
pub mod framing;
pub mod pairing;
mod pairing_completion;
pub mod pairing_protocol;
pub mod protocol;
pub mod server;
pub mod session;
pub mod transport;

pub use authentication::{
    AuthenticationChallenge, AuthenticationChallengeContext, AuthenticationResponse,
    ChallengePayload, ChallengeState, TransportBinding, VerifiedServerChallenge,
    authenticate_response, verify_server_challenge,
};
pub use error::{ConnectorError, ConnectorResult, ErrorCode, ErrorResponse};
pub use framing::{FrameCodec, MAX_FRAME_BYTES};
pub use hpay_agent_types::{AgentId, AgentWalletId, Capability, OperationId, WalletScope};
pub use pairing::{
    AgentIdentityKey, PairedAgent, PairedAgentStatus, PairingBearer, PairingRequest,
    PairingSession, PendingPairing, PinnedServerIdentity, ServerIdentityKey,
};
pub use pairing_completion::{
    AgentIdentitySigner, PAIRING_COMPLETION_TTL_SECS, PairingCompletionChallenge,
    PairingCompletionReceipt, PairingCompletionRequest, PairingSubmissionCommitment,
    verify_pairing_completion_receipt,
};
pub use pairing_protocol::{
    PAIRING_PROTOCOL_VERSION, PairingAcknowledgement, PairingClientEnvelope, PairingClientMessage,
    PairingPayloadClassification, PairingServerEnvelope, PairingServerMessage,
    PairingSubmissionReceipt,
};
pub use protocol::{
    AgentOperationStatus, AgentPaymentRail, AgentRequest, AgentResponse, MessageType, Nonce,
    PROTOCOL_VERSION, ProtocolEnvelope, RequestId, SessionId, WireMessage,
};
pub use server::{
    AgentBackend, AuthenticationStart, ClientEnvelope, ClientMessage, ConnectionPhase,
    ConnectionServer, ServerEnvelope, ServerMessage, ServerOutput, VerifiedAgentRequest,
};
