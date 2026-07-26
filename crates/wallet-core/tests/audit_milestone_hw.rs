//! Milestone: hardware policy, watch-only, native biometric ceremony.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::{WalletError, WalletService};

#[test]
fn milestone_watch_only_cannot_sign() {
    tier0_gate("watch_only_no_sign", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            let addr = svc
                .import_watch_only("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS")
                .unwrap();
            assert!(svc.status().watch_only);
            let err = svc.audit_sign_tx_body("00").unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)));
            assert_eq!(svc.status().address.as_deref(), Some(addr.as_str()));
        });
    });
}

#[test]
fn milestone_webauthn_gate_blocks_sign_without_ceremony() {
    tier0_gate("hw_gate_sign", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("milestone-pass12").unwrap();
            svc.change_hardware_signing_mode("milestone-pass12", HardwareSigningMode::WebAuthnGate)
                .unwrap();
            let err = svc.audit_sign_tx_body("00").unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)));
        });
    });
}

/// The test above covers the on-chain path, which reaches
/// `check_signing_allowed_in_context` through `sign_tx_hex_in_context`. The Fast Pay
/// rail does not: it hands the account straight to the hub router, which cosigns the
/// settlement bill itself. Both UIs use this unprepared command only for that rail, so
/// without an explicit barrier a hardware-gate wallet signs an L2 bill with no ceremony
/// at all while docs/HOW-IT-WORKS.md section 7 promises one for every payment.
#[test]
fn milestone_webauthn_gate_blocks_the_unprepared_send_command() {
    tier0_gate("hw_gate_unprepared_send", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("milestone-pass12").unwrap();
            svc.change_hardware_signing_mode("milestone-pass12", HardwareSigningMode::WebAuthnGate)
                .unwrap();
            // Deliberately far below the 100 HAC profile threshold. The hardware gate
            // must apply to every amount, which is the entire promise of the mode, and
            // the profile threshold cannot express that.
            let rt = tokio::runtime::Runtime::new().unwrap();
            let err = rt
                .block_on(svc.send_hac(
                    "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                    1.0,
                    Default::default(),
                ))
                .unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)), "expected a policy refusal, got {err:?}");
            assert!(
                err.to_string().contains("prepared-operation authorization"),
                "the refusal must name the missing prepared authorization, got: {err}"
            );
        });
    });
}

#[test]
fn milestone_native_biometric_ceremony_nonce() {
    tier0_gate("native_bio_nonce", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("milestone-pass12").unwrap();
            let n1 = svc.begin_native_biometric().unwrap();
            assert!(svc.finish_native_biometric("wrong-nonce").is_err());
            assert!(svc.finish_native_biometric(&n1).is_ok());
            let snap = svc.audit_second_factor_snapshot().unwrap();
            assert!(snap.biometric_ok);
        });
    });
}

#[test]
fn milestone_spoof_biometric_without_begin_fails() {
    tier0_gate("native_bio_spoof", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("milestone-pass12").unwrap();
            assert!(svc.finish_native_biometric("forged-nonce").is_err());
        });
    });
}
