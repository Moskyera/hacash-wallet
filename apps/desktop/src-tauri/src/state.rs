use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

pub struct AppState {
    pub inner: Mutex<WalletService>,
}

impl AppState {
    pub fn new(service: WalletService) -> Self {
        Self {
            inner: Mutex::new(service),
        }
    }
}