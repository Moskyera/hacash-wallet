//! TIER-0: Backup/export must never leak plaintext secrets or decrypted material.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;

#[test]
fn tier0_export_json_never_contains_decrypted_secret() {
    tier0_gate("export_no_plaintext", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("export-pass-1234").unwrap();
            let backup = svc.export_backup("export-pass-1234").unwrap();
            let lower = backup.to_lowercase();
            for forbidden in [
                "private",
                "secret_key",
                "mnemonic",
                "seed phrase",
                "privkey",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "export leaked marker: {forbidden}"
                );
            }
            assert!(backup.contains("ciphertext"));
            assert!(backup.contains("salt"));
            assert!(backup.contains("nonce"));
        });
    });
}

#[test]
fn tier0_export_wrong_passphrase_never_returns_body() {
    tier0_gate("export_wrong_pass", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("export-pass-1234").unwrap();
            assert!(svc.export_backup("totally-wrong-passphrase").is_err());
        });
    });
}

#[test]
fn tier0_export_blob_is_valid_vault_json_only() {
    tier0_gate("export_structure", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("export-pass-1234").unwrap();
            let backup = svc.export_backup("export-pass-1234").unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&backup).unwrap();
            assert!(parsed.get("metadata").is_some());
            assert!(parsed.get("ciphertext").is_some());
            assert!(parsed.get("salt").is_some());
            assert!(parsed.get("nonce").is_some());
            assert!(parsed.as_object().unwrap().get("privateKey").is_none());
        });
    });
}
