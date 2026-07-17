//! STRESS: Vault encrypt/decrypt throughput

mod common;

use common::stress_gate;
use hacash_wallet_core::vault::EncryptedVault;

#[test]
fn stress_vault_encrypt_decrypt_50() {
    stress_gate("vault_50_roundtrips", || {
        let vault = EncryptedVault::encrypt(
            &"ab".repeat(32),
            "1StressVault",
            "vault-stress-pass",
            "balanced",
        )
        .unwrap();
        for _ in 0..50 {
            let plain = vault.decrypt("vault-stress-pass").unwrap();
            assert_eq!(plain.len(), 64);
        }
    });
}

#[test]
fn stress_vault_unique_ciphertext_100() {
    stress_gate("vault_100_unique", || {
        let mut digests = std::collections::HashSet::new();
        for i in 0..100 {
            let v = EncryptedVault::encrypt(
                &format!("secret{i:04}"),
                "1Stress",
                "same-passphrase",
                "balanced",
            )
            .unwrap();
            let exported = v.export_json().unwrap();
            assert!(digests.insert(exported), "duplicate ciphertext at {i}");
        }
    });
}
