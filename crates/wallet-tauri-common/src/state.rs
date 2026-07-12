use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

#[cfg(feature = "desktop")]
use crate::desktop_relay::RelayProcess;
#[cfg(feature = "desktop")]
use crate::dapp_bridge::DappBridgeHandle;

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
    #[cfg(feature = "desktop")]
    pub relay: RelayProcess,
    #[cfg(feature = "desktop")]
    pub dapp_bridge: DappBridgeHandle,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            #[cfg(feature = "desktop")]
            relay: RelayProcess::new(),
            #[cfg(feature = "desktop")]
            dapp_bridge: DappBridgeHandle::new(),
        }
    }
}