//! TIER-0: Unlock brute-force backoff (Bitcoin-class rate limiting).

mod common;

use std::time::Duration;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletError;
use hacash_wallet_core::WalletService;

#[test]
fn tier0_unlock_rate_limit_after_failures() {
    tier0_gate("unlock_rate_limit", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("correct-pass-12").unwrap();
            svc.lock();
            assert!(matches!(
                svc.unlock("wrong-passphrase"),
                Err(WalletError::InvalidPassphrase)
            ));
            let err = svc.unlock("wrong-passphrase").unwrap_err();
            assert!(matches!(err, WalletError::UnlockRateLimited(_)));
        });
    });
}

#[test]
fn tier0_unlock_success_resets_rate_limit() {
    tier0_gate("unlock_rate_reset", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("correct-pass-12").unwrap();
            svc.lock();
            let _ = svc.unlock("bad-pass-0000");
            std::thread::sleep(Duration::from_millis(1_100));
            svc.unlock("correct-pass-12").unwrap();
            svc.lock();
            assert!(svc.unlock("correct-pass-12").is_ok());
        });
    });
}