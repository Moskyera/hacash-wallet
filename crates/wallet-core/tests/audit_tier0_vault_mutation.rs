//! TIER-0: Vault ciphertext mutation matrix (bit-flip, swap, downgrade, truncation).
//!
//! Modeled on hardware-wallet / Bitcoin Core encrypted wallet adversarial review.

mod common;

use std::fs;
use std::path::PathBuf;

use common::tier0_gate;
use hacash_wallet_core::WalletError;
use hacash_wallet_core::vault::EncryptedVault;
use serde_json::Value;

fn temp_vault_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.json");
    (dir, path)
}

fn seed_vault(path: &PathBuf) -> EncryptedVault {
    let vault =
        EncryptedVault::encrypt("deadbeef", "1Tier0TestAddr", "mutation-pass-12", "balanced")
            .unwrap();
    vault.save(path).unwrap();
    vault
}

fn load_json(path: &PathBuf) -> Value {
    let raw = fs::read_to_string(path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn write_json(path: &PathBuf, v: &Value) {
    fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

#[test]
fn tier0_vault_ciphertext_single_bit_flip_fails_decrypt() {
    tier0_gate("vault_bitflip_cipher", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        let ct = j["ciphertext"].as_str().unwrap().to_string();
        let mut bytes = hex::decode(&ct).unwrap();
        bytes[0] ^= 0x01;
        j["ciphertext"] = Value::String(hex::encode(bytes));
        write_json(&path, &j);
        let vault = EncryptedVault::load(&path).unwrap();
        assert!(matches!(
            vault.decrypt("mutation-pass-12"),
            Err(WalletError::InvalidPassphrase)
        ));
    });
}

#[test]
fn tier0_vault_nonce_bit_flip_fails_decrypt() {
    tier0_gate("vault_bitflip_nonce", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        let nonce = j["nonce"].as_str().unwrap().to_string();
        let mut bytes = hex::decode(&nonce).unwrap();
        bytes[0] ^= 0x80;
        j["nonce"] = Value::String(hex::encode(bytes));
        write_json(&path, &j);
        let vault = EncryptedVault::load(&path).unwrap();
        assert!(vault.decrypt("mutation-pass-12").is_err());
    });
}

#[test]
fn tier0_vault_salt_bit_flip_fails_decrypt() {
    tier0_gate("vault_bitflip_salt", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        let salt = j["salt"].as_str().unwrap().to_string();
        let mut bytes = hex::decode(&salt).unwrap();
        bytes[3] ^= 0x04;
        j["salt"] = Value::String(hex::encode(bytes));
        write_json(&path, &j);
        let vault = EncryptedVault::load(&path).unwrap();
        assert!(vault.decrypt("mutation-pass-12").is_err());
    });
}

#[test]
fn tier0_vault_cross_wallet_ciphertext_swap_fails() {
    tier0_gate("vault_cross_swap", || {
        let (_dir, path_a) = temp_vault_path();
        let (_dir2, path_b) = temp_vault_path();
        seed_vault(&path_a);
        let vault_b =
            EncryptedVault::encrypt("cafebabe", "1OtherAddr", "other-passphrase", "balanced")
                .unwrap();
        vault_b.save(&path_b).unwrap();

        let mut ja = load_json(&path_a);
        let jb = load_json(&path_b);
        ja["ciphertext"] = jb["ciphertext"].clone();
        ja["salt"] = jb["salt"].clone();
        ja["nonce"] = jb["nonce"].clone();
        write_json(&path_a, &ja);

        let vault = EncryptedVault::load(&path_a).unwrap();
        assert!(vault.decrypt("mutation-pass-12").is_err());
        // Vault v2 AAD binds ciphertext to metadata. swapped blob must not decrypt
        // under either wallet passphrase (cross-wallet swap attack blocked).
        assert!(vault.decrypt("other-passphrase").is_err());
    });
}

#[test]
fn tier0_vault_version_downgrade_rejected() {
    tier0_gate("vault_version_downgrade", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        j["metadata"]["version"] = Value::Number(0.into());
        write_json(&path, &j);
        let err = match EncryptedVault::load(&path) {
            Err(e) => e,
            Ok(_) => panic!("expected version downgrade to be rejected"),
        };
        assert!(matches!(err, WalletError::Vault(_)));
        assert!(err.to_string().contains("unsupported vault version"));
    });
}

#[test]
fn tier0_vault_v2_metadata_tamper_without_reencrypt_fails() {
    tier0_gate("vault_aad_tamper", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        j["metadata"]["address"] = serde_json::Value::String("1TamperedAddr".into());
        write_json(&path, &j);
        let vault = EncryptedVault::load(&path).unwrap();
        if vault.metadata.version >= 2 {
            assert!(vault.decrypt("mutation-pass-12").is_err());
        }
    });
}

#[test]
fn tier0_vault_version_future_rejected() {
    tier0_gate("vault_version_future", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        j["metadata"]["version"] = Value::Number(99.into());
        write_json(&path, &j);
        assert!(EncryptedVault::load(&path).is_err());
    });
}

#[test]
fn tier0_vault_empty_ciphertext_rejected() {
    tier0_gate("vault_empty_cipher", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        j["ciphertext"] = Value::String(String::new());
        write_json(&path, &j);
        assert!(matches!(
            EncryptedVault::load(&path),
            Err(WalletError::Vault(_))
        ));
    });
}

#[test]
fn tier0_vault_truncated_ciphertext_hex_rejected_or_undecryptable() {
    tier0_gate("vault_truncated_cipher", || {
        let (_dir, path) = temp_vault_path();
        seed_vault(&path);
        let mut j = load_json(&path);
        let ct = j["ciphertext"].as_str().unwrap();
        let truncated = &ct[..ct.len().saturating_sub(4)];
        j["ciphertext"] = Value::String(truncated.to_string());
        write_json(&path, &j);
        let load_result = EncryptedVault::load(&path);
        if let Ok(vault) = load_result {
            assert!(vault.decrypt("mutation-pass-12").is_err());
        }
    });
}

#[test]
fn tier0_vault_malformed_json_rejected() {
    tier0_gate("vault_malformed_json", || {
        let (_dir, path) = temp_vault_path();
        fs::write(&path, "{not valid json").unwrap();
        assert!(EncryptedVault::load(&path).is_err());
    });
}
