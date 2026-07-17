//! Backup export → import roundtrip and secure delete guards.

mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletError;
use hacash_wallet_core::WalletService;
use hacash_wallet_core::paths::{secure_delete_backup_file, wallet_data_root};
use hacash_wallet_core::vault::EncryptedVault;
use std::fs;

#[test]
fn audit_backup_export_import_roundtrip() {
    audit_gate("backup_roundtrip", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("backup-pass-1234").unwrap();
            let addr_before = svc.status().address.clone().unwrap();
            let backup = svc.export_backup("backup-pass-1234").unwrap();
            assert!(backup.contains("ciphertext"));
            assert!(!backup.contains("private"));

            let preview = EncryptedVault::backup_address_from_json(&backup).unwrap();
            assert_eq!(preview, addr_before);

            svc.reset_wallet().unwrap();
            assert!(!svc.status().has_wallet);

            let addr_after = svc.import_backup(&backup, "backup-pass-1234").unwrap();
            assert_eq!(addr_after, addr_before);
            assert_eq!(svc.status().address.as_deref(), Some(addr_before.as_str()));
            assert!(!svc.status().locked);
        });
    });
}

#[test]
fn audit_backup_import_wrong_passphrase_rejected() {
    audit_gate("backup_wrong_pass", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("backup-pass-1234").unwrap();
            let backup = svc.export_backup("backup-pass-1234").unwrap();
            svc.reset_wallet().unwrap();
            assert!(matches!(
                svc.import_backup(&backup, "wrong-passphrase").unwrap_err(),
                WalletError::InvalidPassphrase
            ));
        });
    });
}

#[test]
fn audit_backup_import_rejects_invalid_json() {
    audit_gate("backup_invalid_json", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            assert!(svc.import_backup("not-json", "backup-pass-1234").is_err());
        });
    });
}

#[test]
fn audit_secure_delete_backup_refuses_wallet_dir() {
    audit_gate("backup_delete_guard", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("backup-pass-1234").unwrap();
            let vault = wallet_data_root().join("vault.json");
            assert!(vault.exists());
            assert!(secure_delete_backup_file(&vault).is_err());

            let outside = std::env::temp_dir()
                .join(format!("hacash-backup-test-{}.json", std::process::id()));
            fs::write(&outside, svc.export_backup("backup-pass-1234").unwrap()).unwrap();
            secure_delete_backup_file(&outside).expect("outside json should delete");
            assert!(!outside.exists());
        });
    });
}
