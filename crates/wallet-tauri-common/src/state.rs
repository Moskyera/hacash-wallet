use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

use crate::dapp_approval::DappApprovalQueue;
#[cfg(feature = "desktop")]
use crate::dapp_bridge::DappBridgeHandle;
#[cfg(feature = "desktop")]
use crate::desktop_relay::RelayProcess;

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
    #[cfg(feature = "desktop")]
    pub relay: RelayProcess,
    #[cfg(feature = "desktop")]
    pub dapp_bridge: DappBridgeHandle,
    pub dapp_approval: Arc<DappApprovalQueue>,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            #[cfg(feature = "desktop")]
            relay: RelayProcess::new(),
            #[cfg(feature = "desktop")]
            dapp_bridge: DappBridgeHandle::new(),
            dapp_approval: Arc::new(DappApprovalQueue::new()),
        }
    }
}
