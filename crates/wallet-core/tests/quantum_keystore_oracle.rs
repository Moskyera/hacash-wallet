//! The Quantum keystore IPC must never behave as a password-cracking oracle.
//!
//! `quantum_preview_keystore` answers "does this password decrypt this keystore
//! file", which is precisely the primitive an attacker needs after stealing a
//! keystore. These gates pin the three properties that stop the wallet from
//! answering that question cheaply or anonymously: a live signing session is
//! required, the cold vault refuses outright, and every attempt is throttled.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::{WalletError, WalletService};

const WALLET_PASS: &str = "quantum-oracle-wallet-pass-01";
const QUANTUM_PASS: &str = "quantum-oracle-keystore-pass-01";

fn wallet_with_quantum_keystore() -> (WalletService, String) {
    let mut wallet = WalletService::new(None, None).unwrap();
    wallet.create_wallet(WALLET_PASS).unwrap();
    wallet.quantum_create_pqc(QUANTUM_PASS).unwrap();
    let exported = wallet.quantum_export_keystore(QUANTUM_PASS, None).unwrap();
    (wallet, exported)
}

#[test]
fn a_locked_wallet_answers_no_keystore_password_question() {
    tier0_gate("quantum_preview_requires_unlocked_session", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, keystore) = wallet_with_quantum_keystore();

            wallet.lock();
            assert!(matches!(
                wallet.quantum_preview_keystore(&keystore, QUANTUM_PASS),
                Err(WalletError::Locked)
            ));
            assert!(matches!(
                wallet.quantum_preview_keystore(&keystore, "guess"),
                Err(WalletError::Locked)
            ));
            assert!(matches!(
                wallet.quantum_export_keystore(QUANTUM_PASS, None),
                Err(WalletError::Locked)
            ));
            // A locked wallet must not even pay the KDF cost, so no attempt is
            // recorded and the legitimate user is not thrown into backoff.
            assert_eq!(wallet.audit_quantum_keystore_failures(), 0);

            wallet.unlock(WALLET_PASS).unwrap();
            let info = wallet
                .quantum_preview_keystore(&keystore, QUANTUM_PASS)
                .unwrap();
            assert!(!info.address.is_empty());
        });
    });
}

#[test]
fn wrong_keystore_passwords_are_throttled_like_wallet_unlock() {
    tier0_gate("quantum_preview_backoff", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, keystore) = wallet_with_quantum_keystore();

            assert!(wallet.quantum_preview_keystore(&keystore, "wrong-one").is_err());
            assert_eq!(wallet.audit_quantum_keystore_failures(), 1);

            // The next guess is refused before any key-derivation work, and the
            // backoff applies even to the correct password.
            assert!(matches!(
                wallet.quantum_preview_keystore(&keystore, "wrong-two"),
                Err(WalletError::UnlockRateLimited(_))
            ));
            assert!(matches!(
                wallet.quantum_preview_keystore(&keystore, QUANTUM_PASS),
                Err(WalletError::UnlockRateLimited(_))
            ));
            assert!(matches!(
                wallet.quantum_import_keystore(&keystore, QUANTUM_PASS),
                Err(WalletError::UnlockRateLimited(_))
            ));
            assert!(matches!(
                wallet.quantum_export_keystore(QUANTUM_PASS, None),
                Err(WalletError::UnlockRateLimited(_))
            ));
            // Rejected-while-throttled attempts must not silently reset the
            // counter, which would turn the backoff into a no-op.
            assert_eq!(wallet.audit_quantum_keystore_failures(), 1);
        });
    });
}

#[test]
fn the_cold_vault_refuses_keystore_previews_outright() {
    tier0_gate("quantum_preview_cold_vault_refusal", || {
        with_isolated_wallet_dir(|| {
            let (mut wallet, keystore) = wallet_with_quantum_keystore();
            wallet.audit_activate_cold_vault(WALLET_PASS).unwrap();

            for result in [
                wallet.quantum_preview_keystore(&keystore, QUANTUM_PASS),
                wallet.quantum_preview_keystore(&keystore, "guess"),
                wallet.quantum_import_keystore(&keystore, QUANTUM_PASS),
            ] {
                match result {
                    Err(WalletError::Policy(message)) => assert!(
                        message.contains("cold vault"),
                        "unexpected policy error: {message}"
                    ),
                    other => panic!("expected a Cold Vault refusal, got {other:?}"),
                }
            }
            // Refused before the KDF runs: no attempt is charged to the guard.
            assert_eq!(wallet.audit_quantum_keystore_failures(), 0);
        });
    });
}
