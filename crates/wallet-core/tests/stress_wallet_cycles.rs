//! STRESS: Rapid wallet lifecycle cycles (lock/unlock/passphrase)

mod common;

use common::{stress_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::security::SecurityProfile;

const CYCLES: usize = 100;

#[test]
fn stress_lock_unlock_cycles() {
    stress_gate("lock_unlock_100", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("stress-passphrase-12").unwrap();
            for _ in 0..CYCLES {
                svc.lock();
                assert!(svc.status().locked);
                svc.unlock("stress-passphrase-12").unwrap();
                assert!(!svc.status().locked);
            }
        });
    });
}

#[test]
fn stress_passphrase_rotate_chain() {
    stress_gate("passphrase_rotate_5", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("rotate-pass-0001").unwrap();
            let passes = [
                "rotate-pass-0002",
                "rotate-pass-0003",
                "rotate-pass-0004",
                "rotate-pass-0005",
                "rotate-pass-0006",
            ];
            let mut current = "rotate-pass-0001";
            for next in passes {
                svc.change_passphrase(current, next).unwrap();
                current = next;
            }
            svc.lock();
            svc.unlock(current).unwrap();
            assert!(!svc.status().locked);
        });
    });
}

#[test]
fn stress_security_profile_toggle() {
    stress_gate("profile_toggle_50", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("stress-passphrase-12").unwrap();
            for i in 0..50 {
                if i % 2 == 0 {
                    svc.set_security_profile(SecurityProfile::paranoid())
                        .unwrap();
                } else {
                    svc.set_security_profile(SecurityProfile::default())
                        .unwrap();
                }
            }
            let mut svc2 = WalletService::new(None, None).unwrap();
            svc2.unlock("stress-passphrase-12").unwrap();
            assert!(
                svc2.get_settings().security_profile == "paranoid"
                    || svc2.get_settings().security_profile == "balanced"
            );
        });
    });
}
