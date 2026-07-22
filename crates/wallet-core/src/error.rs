use thiserror::Error;

pub type WalletResult<T> = Result<T, WalletError>;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("vault: {0}")]
    Vault(String),
    #[error("wallet locked")]
    Locked,
    #[error("wallet already unlocked")]
    AlreadyUnlocked,
    #[error("no wallet on device")]
    NoWallet,
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("unlock temporarily locked. retry in {0}s")]
    UnlockRateLimited(u64),
    #[error("node api: {0}")]
    Node(String),
    #[error("node api: HTTP {status}: {message}")]
    NodeHttpStatus { status: u16, message: String },
    #[error("node api: unsupported address: {0}")]
    UnsupportedAddress(String),
    #[error("price service: {0}")]
    Price(String),
    #[error("transaction: {0}")]
    Transaction(String),
    #[error("security policy blocked: {0}")]
    Policy(String),
    #[error("l2: {0}")]
    L2(String),
    #[error("{0}")]
    Other(String),
}
