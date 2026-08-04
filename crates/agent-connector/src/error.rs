use serde::{Deserialize, Serialize};

pub type ConnectorResult<T> = Result<T, ConnectorError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidFrame,
    FrameTooLarge,
    UnsupportedVersion,
    InvalidMessage,
    InvalidIdentifier,
    InvalidTimeWindow,
    Expired,
    PairingInactive,
    PairingConsumed,
    PairingAttemptsExceeded,
    InvalidIdentity,
    AuthenticationFailed,
    ReplayDetected,
    SequenceViolation,
    SessionMismatch,
    SessionExpired,
    CapabilityDenied,
    Revoked,
    ListenerDisabled,
    InsecureLocalEndpoint,
    UnauthorizedPeer,
    PlatformUnavailable,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl ErrorResponse {
    pub fn from_error(error: &ConnectorError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            retryable: matches!(error, ConnectorError::Io | ConnectorError::ListenerDisabled),
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    #[error("local agent frame is malformed")]
    InvalidFrame,
    #[error("local agent frame exceeds the size limit")]
    FrameTooLarge,
    #[error("local agent protocol version is not supported")]
    UnsupportedVersion,
    #[error("local agent message is invalid")]
    InvalidMessage,
    #[error("local agent identifier is invalid")]
    InvalidIdentifier,
    #[error("message time window is invalid")]
    InvalidTimeWindow,
    #[error("message or challenge has expired")]
    Expired,
    #[error("pairing was not explicitly activated")]
    PairingInactive,
    #[error("pairing session has already been consumed")]
    PairingConsumed,
    #[error("pairing attempt limit exceeded")]
    PairingAttemptsExceeded,
    #[error("agent identity key is invalid")]
    InvalidIdentity,
    #[error("agent challenge-response authentication failed")]
    AuthenticationFailed,
    #[error("replayed nonce or challenge was rejected")]
    ReplayDetected,
    #[error("message sequence is stale or out of order")]
    SequenceViolation,
    #[error("session, wallet, agent, or desktop scope does not match")]
    SessionMismatch,
    #[error("capability session has expired")]
    SessionExpired,
    #[error("capability does not permit this request")]
    CapabilityDenied,
    #[error("paired agent identity is revoked or disabled")]
    Revoked,
    #[error("local agent listener is disabled")]
    ListenerDisabled,
    #[error("local endpoint permissions or ownership are unsafe")]
    InsecureLocalEndpoint,
    #[error("local IPC peer belongs to another operating-system user")]
    UnauthorizedPeer,
    #[error("secure local transport is unavailable on this platform")]
    PlatformUnavailable,
    #[error("local IPC operation failed")]
    Io,
}

impl ConnectorError {
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidFrame => ErrorCode::InvalidFrame,
            Self::FrameTooLarge => ErrorCode::FrameTooLarge,
            Self::UnsupportedVersion => ErrorCode::UnsupportedVersion,
            Self::InvalidMessage => ErrorCode::InvalidMessage,
            Self::InvalidIdentifier => ErrorCode::InvalidIdentifier,
            Self::InvalidTimeWindow => ErrorCode::InvalidTimeWindow,
            Self::Expired => ErrorCode::Expired,
            Self::PairingInactive => ErrorCode::PairingInactive,
            Self::PairingConsumed => ErrorCode::PairingConsumed,
            Self::PairingAttemptsExceeded => ErrorCode::PairingAttemptsExceeded,
            Self::InvalidIdentity => ErrorCode::InvalidIdentity,
            Self::AuthenticationFailed => ErrorCode::AuthenticationFailed,
            Self::ReplayDetected => ErrorCode::ReplayDetected,
            Self::SequenceViolation => ErrorCode::SequenceViolation,
            Self::SessionMismatch => ErrorCode::SessionMismatch,
            Self::SessionExpired => ErrorCode::SessionExpired,
            Self::CapabilityDenied => ErrorCode::CapabilityDenied,
            Self::Revoked => ErrorCode::Revoked,
            Self::ListenerDisabled => ErrorCode::ListenerDisabled,
            Self::InsecureLocalEndpoint => ErrorCode::InsecureLocalEndpoint,
            Self::UnauthorizedPeer => ErrorCode::UnauthorizedPeer,
            Self::PlatformUnavailable => ErrorCode::PlatformUnavailable,
            Self::Io => ErrorCode::Io,
        }
    }
}

impl From<hpay_agent_types::TypeError> for ConnectorError {
    fn from(error: hpay_agent_types::TypeError) -> Self {
        match error {
            hpay_agent_types::TypeError::InvalidIdentifier => Self::InvalidIdentifier,
            hpay_agent_types::TypeError::ScopeMismatch => Self::SessionMismatch,
        }
    }
}
