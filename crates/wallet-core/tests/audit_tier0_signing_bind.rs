//! TIER-0: Signing binding — locked gate, garbage bodies, determinism, key isolation.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir, with_protocol_setup};
use hacash_wallet_core::WalletError;
use hacash_wallet_core::WalletService;

#[test]
fn tier0_signing_locked_wallet_rejected() {
    tier0_gate("sign_locked", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            svc.lock();
            let err = svc.audit_sign_tx_body("00").unwrap_err();
            assert!(matches!(err, WalletError::Locked));
        });
    });
}

#[test]
fn tier0_signing_garbage_hex_rejected() {
    tier0_gate("sign_garbage_hex", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            assert!(svc.audit_sign_tx_body("not-hex").is_err());
            assert!(svc.audit_sign_tx_body("zz").is_err());
        });
    });
}

#[test]
fn tier0_signing_empty_body_rejected() {
    tier0_gate("sign_empty", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("tier0-passphrase12").unwrap();
            assert!(svc.audit_sign_tx_body("").is_err());
        });
    });
}

#[test]
fn tier0_signing_deterministic_for_same_body() {
    tier0_gate("sign_deterministic", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let mut svc = WalletService::new(None, None).unwrap();
                svc.create_wallet("tier0-passphrase12").unwrap();
                let body = "0102030405";
                let r1 = svc.audit_sign_tx_body(body);
                let r2 = svc.audit_sign_tx_body(body);
                assert_eq!(r1.is_ok(), r2.is_ok());
                if let (Ok(a), Ok(b)) = (r1, r2) {
                    assert_eq!(a, b, "same key + same body must yield identical signed tx");
                }
            });
        });
    });
}

#[test]
fn tier0_signing_different_wallets_isolated_addresses() {
    tier0_gate("sign_key_isolation", || {
        let mut addr_a = None;
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("wallet-a-pass12").unwrap();
            addr_a = svc.status().address;
        });
        let mut addr_b = None;
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("wallet-b-pass12").unwrap();
            addr_b = svc.status().address;
        });
        assert_ne!(addr_a, addr_b);
    });
}