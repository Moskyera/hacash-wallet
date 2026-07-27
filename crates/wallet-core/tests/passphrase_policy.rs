mod common;

use common::with_isolated_wallet_dir;
use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::vault::EncryptedVault;

#[test]
fn new_wallet_passphrases_count_unicode_scalars_and_require_fifteen() {
    with_isolated_wallet_dir(|| {
        let mut wallet = WalletService::new(None, None).unwrap();
        assert!(wallet.create_wallet("12345678901234").is_err());
        let unicode_fifteen = "κ".repeat(15);
        assert!(wallet.create_wallet(&unicode_fifteen).is_ok());
    });
}

#[test]
fn passphrase_change_rejects_short_and_unreasonably_large_values() {
    with_isolated_wallet_dir(|| {
        let mut wallet = WalletService::new(None, None).unwrap();
        let current = "correct-passphrase-15";
        wallet.create_wallet(current).unwrap();
        assert!(wallet.change_passphrase(current, "short-pass").is_err());
        assert!(
            wallet
                .change_passphrase(current, &"x".repeat(1025))
                .is_err()
        );
    });
}

#[test]
fn legacy_eight_character_encrypted_backup_remains_importable() {
    with_isolated_wallet_dir(|| {
        let passphrase = "old-pass";
        let account = WalletAccount::create("legacy-backup-fixture").unwrap();
        let secret = account.secret_hex();
        let vault =
            EncryptedVault::encrypt(&secret, &account.address(), passphrase, "balanced").unwrap();
        let backup = vault.export_json().unwrap();
        let mut wallet = WalletService::new(None, None).unwrap();
        assert_eq!(
            wallet.import_backup(&backup, passphrase).unwrap(),
            account.address()
        );
    });
}
