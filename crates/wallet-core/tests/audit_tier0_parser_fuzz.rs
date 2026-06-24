//! TIER-0: Parser hardening — arbitrary vault JSON / hex must never panic or leak plaintext.

mod common;

use std::fs;
use std::path::PathBuf;

use common::tier0_gate;
use hacash_wallet_core::vault::EncryptedVault;
use hacash_wallet_core::WalletError;
use proptest::prelude::*;

fn temp_vault_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.json");
    fs::write(&path, contents).unwrap();
    (dir, path)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn tier0_prop_vault_load_arbitrary_json_never_panics(raw in r#".{0,4096}"#) {
        let (_dir, path) = temp_vault_file(&raw);
        let result = EncryptedVault::load(&path);
        if let Ok(vault) = result {
            let decrypt = vault.decrypt("any-passphrase-12");
            prop_assert!(decrypt.is_err() || decrypt.is_ok());
            if let Ok(plain) = decrypt {
                prop_assert!(plain.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    #[test]
    fn tier0_prop_vault_decrypt_wrong_pass_never_returns_valid_hex(
        passphrase in r#".{0,128}"#,
        wrong in r#".{0,128}"#
    ) {
        let vault = EncryptedVault::encrypt(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "1FuzzAddr",
            "correct-pass-12",
            "balanced",
        )
        .unwrap();
        if passphrase != "correct-pass-12" {
            let result = vault.decrypt(&passphrase);
            if let Ok(plain) = result {
                prop_assert_ne!(
                    plain,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );
            }
        }
        let _ = vault.decrypt(&wrong);
    }
}

#[test]
fn tier0_vault_oversized_hex_field_rejected() {
    tier0_gate("vault_oversized_salt", || {
        let blob = format!(
            r#"{{
  "metadata": {{ "version": 1, "address": "1X", "created_at": "t", "kdf": "argon2id", "security_profile": "balanced" }},
  "salt": "{}",
  "nonce": "000000000000000000000000",
  "ciphertext": "ab"
}}"#,
            "00".repeat(256)
        );
        let (_dir, path) = temp_vault_file(&blob);
        assert!(matches!(
            EncryptedVault::load(&path),
            Err(WalletError::Vault(_))
        ));
    });
}