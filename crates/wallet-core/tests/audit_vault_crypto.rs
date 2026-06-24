//! AUDIT-GATE: Vault cryptography (Argon2id + AES-256-GCM)
//! Modeled after Bitcoin/Electrum wallet crypto test matrices.

mod common;

use common::audit_gate;
use hacash_wallet_core::vault::EncryptedVault;
use hacash_wallet_core::WalletError;

#[test]
fn audit_vault_wrong_passphrase_never_decrypts() {
    audit_gate("vault_wrong_passphrase", || {
        let vault = EncryptedVault::encrypt("deadbeef", "1Audit", "correct-horse", "balanced").unwrap();
        let err = vault.decrypt("wrong-passphrase").unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    });
}

#[test]
fn audit_vault_ciphertext_tamper_detected() {
    audit_gate("vault_ciphertext_tamper", || {
        let vault = EncryptedVault::encrypt("secret", "1Audit", "pass123456", "balanced").unwrap();
        let mut val: serde_json::Value =
            serde_json::from_str(&vault.export_json().unwrap()).unwrap();
        let ct = val["ciphertext"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = ct.chars().collect();
        if let Some(c) = chars.first_mut() {
            *c = if *c == '0' { 'f' } else { '0' };
        }
        val["ciphertext"] = serde_json::Value::String(chars.into_iter().collect());
        let path = std::env::temp_dir().join("hacash-audit-tamper-vault.json");
        std::fs::write(&path, serde_json::to_string(&val).unwrap()).unwrap();
        let loaded = EncryptedVault::load(&path).unwrap();
        assert!(loaded.decrypt("pass123456").is_err());
        let _ = std::fs::remove_file(path);
    });
}

#[test]
fn audit_vault_unique_salt_per_encryption() {
    audit_gate("vault_unique_salt", || {
        let a = EncryptedVault::encrypt("same", "1A", "pass123456", "balanced").unwrap();
        let b = EncryptedVault::encrypt("same", "1A", "pass123456", "balanced").unwrap();
        assert_ne!(a.export_json().unwrap(), b.export_json().unwrap());
    });
}

#[test]
fn audit_vault_reencrypt_roundtrip() {
    audit_gate("vault_reencrypt", || {
        let mut vault =
            EncryptedVault::encrypt("rotate-me", "1Audit", "old-passphrase", "balanced").unwrap();
        vault.reencrypt("old-passphrase", "new-passphrase-99").unwrap();
        assert_eq!(vault.decrypt("new-passphrase-99").unwrap(), "rotate-me");
        assert!(vault.decrypt("old-passphrase").is_err());
    });
}

#[test]
fn audit_vault_export_never_contains_plaintext_secret() {
    audit_gate("vault_export_no_plaintext", || {
        let secret = "f".repeat(64);
        let vault = EncryptedVault::encrypt(&secret, "1Audit", "pass123456", "balanced").unwrap();
        let exported = vault.export_json().unwrap();
        assert!(!exported.contains(&secret));
        assert!(exported.contains("ciphertext"));
    });
}

#[test]
fn audit_vault_save_load_roundtrip() {
    audit_gate("vault_save_load", || {
        common::with_isolated_wallet_dir(|| {
            let path = hacash_wallet_core::vault::default_vault_path();
            let vault = EncryptedVault::encrypt("persist", "1Audit", "pass123456", "balanced").unwrap();
            vault.save(&path).unwrap();
            let loaded = EncryptedVault::load(&path).unwrap();
            assert_eq!(loaded.decrypt("pass123456").unwrap(), "persist");
        });
    });
}

#[test]
fn audit_vault_invalid_hex_fields_rejected() {
    audit_gate("vault_invalid_hex", || {
        common::with_isolated_wallet_dir(|| {
            let path = hacash_wallet_core::vault::default_vault_path();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, r#"{"metadata":{"version":1,"address":"1X","created_at":"t","kdf":"k","security_profile":"balanced"},"salt":"zz","nonce":"aa","ciphertext":"00"}"#).unwrap();
            assert!(EncryptedVault::load(&path).is_err());
        });
    });
}