//! TIER-0: Unicode / encoding edge cases for passphrases and import seeds.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::vault::EncryptedVault;
use hacash_wallet_core::WalletService;

#[test]
fn tier0_passphrase_nfc_nfd_are_distinct_keys() {
    tier0_gate("unicode_nfc_nfd", || {
        // "é" as single codepoint (NFC) vs e + combining acute (NFD)
        let nfc = "caf\u{00e9}-pass-12chars";
        let nfd = "caf\u{0065}\u{0301}-pass-12chars";
        assert_ne!(nfc, nfd);
        let vault_nfc =
            EncryptedVault::encrypt("secret01", "1Unicode", nfc, "balanced").unwrap();
        let vault_nfd =
            EncryptedVault::encrypt("secret01", "1Unicode", nfd, "balanced").unwrap();
        assert!(vault_nfc.decrypt(nfc).is_ok());
        assert!(vault_nfc.decrypt(nfd).is_err());
        assert!(vault_nfd.decrypt(nfd).is_ok());
        assert!(vault_nfd.decrypt(nfc).is_err());
    });
}

#[test]
fn tier0_passphrase_null_byte_suffix_not_truncated() {
    tier0_gate("unicode_null_suffix", || {
        let base = "tier0-passphrase12";
        let with_null = format!("{base}\0extra");
        let vault =
            EncryptedVault::encrypt("secret01", "1NullTest", &with_null, "balanced").unwrap();
        assert!(vault.decrypt(&with_null).is_ok());
        assert!(vault.decrypt(base).is_err());
    });
}

#[test]
fn tier0_passphrase_rtl_override_changes_key() {
    tier0_gate("unicode_rtl", || {
        let normal = "tier0-passphrase12";
        let rtl = format!("tier0-\u{202e}passphrase12");
        let v1 = EncryptedVault::encrypt("s1", "1Rtl", normal, "balanced").unwrap();
        let v2 = EncryptedVault::encrypt("s1", "1Rtl", &rtl, "balanced").unwrap();
        assert!(v1.decrypt(normal).is_ok());
        assert!(v2.decrypt(&rtl).is_ok());
        assert!(v1.decrypt(&rtl).is_err());
        assert!(v2.decrypt(normal).is_err());
    });
}

#[test]
fn tier0_import_rejects_whitespace_only_seed() {
    tier0_gate("import_whitespace_seed", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            assert!(svc.import_wallet("   \t\n  ", "passphrase12").is_err());
        });
    });
}

#[test]
fn tier0_import_hex_secret_requires_exact_64_chars() {
    tier0_gate("import_hex_length", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            let short = "a".repeat(63);
            assert!(svc.import_wallet(&short, "passphrase12").is_err());
            let long = "a".repeat(65);
            assert!(svc.import_wallet(&long, "passphrase12").is_err());
        });
    });
}