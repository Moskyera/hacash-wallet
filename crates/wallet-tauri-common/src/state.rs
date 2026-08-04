use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

use crate::dapp_approval::DappApprovalQueue;
#[cfg(feature = "desktop")]
use crate::desktop_relay::RelayProcess;
use crate::update::UpdateOfferStore;

/// Independent Agent Wallet state. Initialization failure is contained here
/// and never prevents My Wallet from starting.
#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub struct AgentAppState {
    pub inner: Option<Arc<Mutex<agent_wallet_core::AgentWalletManager>>>,
    pub transition: Mutex<()>,
    pub runtime: crate::agent_runtime::AgentRuntimeSupervisor,
    pub companion: crate::companion_runtime::AgentCompanionSupervisor,
    pub initialization_error: Option<String>,
}

#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
impl AgentAppState {
    pub fn open(root: impl AsRef<std::path::Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        {
            Self {
                inner: None,
                transition: Mutex::new(()),
                runtime: crate::agent_runtime::AgentRuntimeSupervisor::unavailable(root),
                companion: crate::companion_runtime::AgentCompanionSupervisor::default(),
                initialization_error: Some(
                    "AI Agent Wallet Testnet Pilot is not enabled in this build.".to_owned(),
                ),
            }
        }
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        match agent_wallet_core::AgentWalletManager::open(&root) {
            Ok(manager) => {
                let runtime = crate::agent_runtime::AgentRuntimeSupervisor::new(&root, &manager);
                Self {
                    inner: Some(Arc::new(Mutex::new(manager))),
                    transition: Mutex::new(()),
                    runtime,
                    companion: crate::companion_runtime::AgentCompanionSupervisor::default(),
                    initialization_error: None,
                }
            }
            Err(error) => Self {
                inner: None,
                transition: Mutex::new(()),
                runtime: crate::agent_runtime::AgentRuntimeSupervisor::unavailable(root),
                companion: crate::companion_runtime::AgentCompanionSupervisor::default(),
                initialization_error: Some(error.to_string()),
            },
        }
    }
}

#[cfg(all(
    test,
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
mod agent_build_tests {
    use super::AgentAppState;

    #[test]
    fn agent_manager_availability_matches_the_backend_pilot_feature() {
        let root = tempfile::tempdir().unwrap();
        let state = AgentAppState::open(root.path());
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            assert!(state.inner.is_some());
            assert!(state.initialization_error.is_none());
        }
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        {
            assert!(state.inner.is_none());
            assert_eq!(
                state.initialization_error.as_deref(),
                Some("AI Agent Wallet Testnet Pilot is not enabled in this build.")
            );
        }
    }
}

pub(crate) const WALLET_BUSY_RETRY: &str = "wallet busy; retry shortly";

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
    #[cfg(feature = "desktop")]
    pub relay: RelayProcess,
    pub dapp_approval: Arc<DappApprovalQueue>,
    pub updates: UpdateOfferStore,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            #[cfg(feature = "desktop")]
            relay: RelayProcess::new(),
            dapp_approval: Arc::new(DappApprovalQueue::new()),
            updates: UpdateOfferStore::new(),
        }
    }
}
