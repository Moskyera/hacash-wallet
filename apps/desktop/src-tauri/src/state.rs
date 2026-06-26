use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

pub struct AppState {
    pub inner: Arc<Mutex<WalletService>>,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
        }
    }
}