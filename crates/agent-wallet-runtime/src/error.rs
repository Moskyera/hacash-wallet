use std::fmt;

use hpay_agent_connector::ConnectorError;

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    ListenerDisabled,
    AlreadyRunning,
    NotRunning,
    PairingAlreadyActive,
    AgentWalletUnavailable,
    ServerIdentityMismatch,
    PairingCommitFailed,
    InvalidConfiguration,
    StartupTimeout,
    ShutdownTimeout,
    DispatchTimeout,
    ConnectionBudgetExhausted,
    WorkerPanicked,
    Connector(ConnectorError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ListenerDisabled => "agent wallet listener is not enabled",
            Self::AlreadyRunning => "agent wallet runtime is already running",
            Self::NotRunning => "agent wallet runtime is not running",
            Self::PairingAlreadyActive => "an agent pairing session is already active",
            Self::AgentWalletUnavailable => "the selected Agent Wallet is not unlocked",
            Self::ServerIdentityMismatch => {
                "runtime identity does not match the selected Agent Wallet vault"
            }
            Self::PairingCommitFailed => "approved agent pairing could not be committed",
            Self::InvalidConfiguration => "agent wallet runtime configuration is invalid",
            Self::StartupTimeout => "agent wallet runtime startup timed out",
            Self::ShutdownTimeout => "agent wallet runtime shutdown timed out",
            Self::DispatchTimeout => "agent wallet backend dispatch timed out",
            Self::ConnectionBudgetExhausted => "agent wallet connection reached its fairness limit",
            Self::WorkerPanicked => "agent wallet runtime worker panicked",
            Self::Connector(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for RuntimeError {}

impl From<ConnectorError> for RuntimeError {
    fn from(error: ConnectorError) -> Self {
        if error == ConnectorError::ListenerDisabled {
            Self::ListenerDisabled
        } else {
            Self::Connector(error)
        }
    }
}
