use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

#[cfg(feature = "desktop")]
use crate::desktop_relay::RelayProcess;

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
    #[cfg(feature = "desktop")]
    pub relay: RelayProcess,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            #[cfg(feature = "desktop")]
            relay: RelayProcess::new(),
        }
    }
}