use std::sync::Arc;

use hacash_wallet_core::WalletService;
use tokio::sync::Mutex;

use crate::dapp_approval::DappApprovalQueue;
#[cfg(feature = "desktop")]
use crate::desktop_relay::RelayProcess;
use crate::update::UpdateOfferStore;

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
