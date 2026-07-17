//! Serializes wallet-data env overrides for unit tests (process-global, parallel-unsafe).

use std::sync::{Mutex, OnceLock};

static WALLET_DATA_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub struct IsolatedWalletData {
    _guard: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    prev: Option<String>,
}

impl IsolatedWalletData {
    pub fn new() -> Self {
        let guard = WALLET_DATA_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("HACASH_WALLET_DATA").ok();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("wallet-data");
        std::fs::create_dir_all(&root).expect("wallet root");
        // SAFETY: serialized by WALLET_DATA_TEST_LOCK; test-only env override.
        unsafe { std::env::set_var("HACASH_WALLET_DATA", &root) };
        Self {
            _guard: guard,
            _dir: dir,
            prev,
        }
    }
}

impl Drop for IsolatedWalletData {
    fn drop(&mut self) {
        match &self.prev {
            Some(p) => unsafe { std::env::set_var("HACASH_WALLET_DATA", p) },
            None => unsafe { std::env::remove_var("HACASH_WALLET_DATA") },
        }
    }
}
