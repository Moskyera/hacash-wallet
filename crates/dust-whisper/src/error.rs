use thiserror::Error;

pub type WhisperResult<T> = Result<T, WhisperError>;

#[derive(Debug, Error)]
pub enum WhisperError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("relay: {0}")]
    Relay(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("no relay configured")]
    NoRelay,
}
