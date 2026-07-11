//! AUDIT-GATE: Wallet lifecycle & access control

mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::WalletError;
use hacash_wallet_core::WalletService;

#[test]
fn audit_double_create_rejected() {
    audit_gate("lifecycle_double_create", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            assert!(matches!(
                svc.create_wallet("otherpass1234").unwrap_err(),
                WalletError::Vault(_)
            ));
        });
    });
}

#[test]
fn audit_double_unlock_rejected() {
    audit_gate("lifecycle_double_unlock", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            assert!(matches!(
                svc.unlock("passphrase1234").unwrap_err(),
                WalletError::AlreadyUnlocked
            ));
        });
    });
}

#[test]
fn audit_lock_clears_session() {
    audit_gate("lifecycle_lock", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            svc.lock();
            assert!(svc.status().locked);
        });
    });
}

#[test]
fn audit_import_duplicate_vault_rejected() {
    audit_gate("lifecycle_import_dup", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            svc.lock();
            let seed = WalletAccount::create("seed2").unwrap().secret_hex();
            assert!(svc.import_wallet(&seed, "newpass1234").is_err());
        });
    });
}

#[test]
fn audit_change_passphrase_wrong_old_rejected() {
    audit_gate("lifecycle_passphrase_wrong", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            assert!(svc.change_passphrase("wrong", "newpass12345").is_err());
        });
    });
}

#[test]
fn audit_export_requires_valid_passphrase() {
    audit_gate("lifecycle_export_auth", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            assert!(svc.export_backup("wrong").is_err());
            let backup = svc.export_backup("passphrase1234").unwrap();
            assert!(!backup.contains("secret"));
        });
    });
}

#[test]
fn audit_locked_wallet_cannot_sign() {
    audit_gate("lifecycle_locked_sign", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            svc.lock();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let err = rt
                .block_on(svc.send_hac("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", 1.0, Default::default()))
                .unwrap_err();
            assert!(matches!(err, WalletError::Locked));
        });
    });
}

#[test]
fn audit_paranoid_profile_persisted_across_reload() {
    audit_gate("lifecycle_profile_persist", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("passphrase1234").unwrap();
            svc.set_security_profile(SecurityProfile::paranoid()).unwrap();
            svc.lock();
            let mut svc2 = WalletService::new(None, None).unwrap();
            svc2.unlock("passphrase1234").unwrap();
            assert_eq!(svc2.get_settings().security_profile, "paranoid");
        });
    });
}