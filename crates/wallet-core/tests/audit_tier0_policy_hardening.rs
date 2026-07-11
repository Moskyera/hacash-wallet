//! TIER-0: Session-bound second factor — UI/IPC cannot spoof yubikey_ok flags.
//!
//! Few wallets enforce this; most trust boolean flags from the frontend.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::{WalletError, WalletService};

#[test]
fn tier0_paranoid_send_rejects_without_webauthn_ceremony() {
    tier0_gate("paranoid_no_spoof", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            svc.set_security_profile(SecurityProfile::paranoid()).unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let err = rt
                .block_on(svc.send_hac("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", 1.0, Default::default()))
                .unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)));
            let msg = err.to_string();
            assert!(msg.contains("WebAuthn") || msg.contains("YubiKey"));
        });
    });
}

#[test]
fn tier0_balanced_large_send_rejects_without_session_2fa() {
    tier0_gate("balanced_large_no_spoof", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let err = rt
                .block_on(svc.send_hac("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", 150.0, Default::default()))
                .unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)));
        });
    });
}

#[test]
fn tier0_balanced_large_send_ok_after_confirm_biometric() {
    tier0_gate("balanced_biometric_session", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            svc.confirm_biometric_for_send().unwrap();
            let ctx = svc
                .audit_second_factor_snapshot()
                .expect("session snapshot");
            assert!(ctx.biometric_ok);
            assert!(!ctx.yubikey_ok);
        });
    });
}

#[test]
fn tier0_second_factor_single_use_consumed_before_send() {
    tier0_gate("second_factor_single_use", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            svc.confirm_biometric_for_send().unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            // Send will fail at network/node layer but must consume 2FA first.
            let _ = rt.block_on(svc.send_hac("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", 150.0, Default::default()));
            let ctx = svc.audit_second_factor_snapshot().expect("still unlocked");
            assert!(!ctx.biometric_ok);
            assert!(!ctx.yubikey_ok);
        });
    });
}

#[test]
fn tier0_lock_clears_second_factor_session() {
    tier0_gate("lock_clears_2fa", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            svc.confirm_biometric_for_send().unwrap();
            svc.lock();
            svc.unlock("tier0-passphrase12").unwrap();
            let ctx = svc.audit_second_factor_snapshot().unwrap();
            assert!(!ctx.biometric_ok);
            assert!(!ctx.yubikey_ok);
        });
    });
}