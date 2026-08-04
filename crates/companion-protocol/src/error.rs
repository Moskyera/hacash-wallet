#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CompanionError {
    #[error("companion protocol version is not supported")]
    UnsupportedVersion,
    #[error("companion message is malformed")]
    MalformedMessage,
    #[error("companion message exceeds the size limit")]
    MessageTooLarge,
    #[error("device identifier is invalid")]
    InvalidDeviceId,
    #[error("device identity key is invalid")]
    InvalidIdentityKey,
    #[error("device identity signature is invalid")]
    InvalidSignature,
    #[error("platform device signer is unavailable")]
    PlatformSignerUnavailable,
    #[error("device identity fingerprint does not match")]
    FingerprintMismatch,
    #[error("device is not paired")]
    UnknownDevice,
    #[error("device was revoked")]
    DeviceRevoked,
    #[error("device authorization epoch does not match the current registry state")]
    AuthorizationEpochMismatch,
    #[error("device is already registered; replacement requires an explicit re-pair transition")]
    DeviceAlreadyRegistered,
    #[error("device is paired with another Agent Wallet")]
    WalletScopeMismatch,
    #[error("device permission denied")]
    PermissionDenied,
    #[error("pairing session expired")]
    PairingExpired,
    #[error("pairing session was already used")]
    PairingAlreadyUsed,
    #[error("pairing session was cancelled")]
    PairingCancelled,
    #[error("pairing request does not match this session")]
    PairingMismatch,
    #[error("pairing verification code does not match")]
    VerificationCodeMismatch,
    #[error("message expired")]
    Expired,
    #[error("message issue time is invalid")]
    InvalidIssuedAt,
    #[error("message sequence is stale or duplicated")]
    SequenceReplay,
    #[error("message nonce was already used")]
    NonceReplay,
    #[error("message nonce is invalid")]
    InvalidNonce,
    #[error("approval commitment does not match")]
    ApprovalCommitmentMismatch,
    #[error("rollback anchor commitment does not match")]
    AnchorCommitmentMismatch,
    #[error("rollback anchor chain does not match the accepted witness state")]
    AnchorChainMismatch,
    #[error("rollback or stale state was detected")]
    RollbackDetected,
    #[error("a durable mobile witness receipt is required")]
    WitnessRequired,
    #[error("admin command is not allowed")]
    AdminCommandNotAllowed,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("transport is unavailable")]
    TransportUnavailable,
    #[error("transport session is invalid")]
    InvalidSession,
}

pub type CompanionResult<T> = Result<T, CompanionError>;
