use thiserror::Error;

#[derive(Debug, Error)]
pub enum HubError {
    #[error("node: {0}")]
    Node(String),
    #[error("channel: {0}")]
    Channel(String),
    #[error("payment: {0}")]
    Payment(String),
    #[error("state: {0}")]
    State(String),
    #[error("not found: {0}")]
    NotFound(String),
}

pub type HubResult<T> = Result<T, HubError>;