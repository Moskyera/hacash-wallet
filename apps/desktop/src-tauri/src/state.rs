use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

use crate::whisper_relay::RelayProcess;

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
    pub relay: RelayProcess,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            relay: RelayProcess::new(),
        }
    }
}