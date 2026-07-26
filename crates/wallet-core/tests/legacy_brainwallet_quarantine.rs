//! Brainwallet keys cannot be created by this wallet any more, and the ones that
//! already exist stay quarantined.
//!
//! Upstream derives a key from text with one unsalted SHA-256, so anyone who
//! guesses the phrase reproduces the key without this app. The import path that
//! could produce such a key has been removed outright. Detection has not: vaults
//! created before the removal, and any backup of one, must still be recognised,
//! surfaced, and barred from custody claims the wallet cannot honour.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir, with_protocol_setup};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::vault::{
    EncryptedVault, LEGACY_DERIVATION_BRAINWALLET_SHA256, default_vault_path,
};
use hacash_wallet_core::{WalletError, WalletService};

const PHRASE: &str = "correct horse battery staple";
const PASSPHRASE: &str = "legacy-quarantine-pass-01";
const ROTATED_PASSPHRASE: &str = "legacy-quarantine-pass-02";

/// Write the kind of vault the removed import path used to produce, so the
/// detection and quarantine rules can still be exercised.
fn plant_legacy_vault() -> String {
    let account = WalletAccount::create(PHRASE).unwrap();
    let address = account.address();
    let vault = EncryptedVault::encrypt_legacy_derived(
        &account.secret_hex(),
        &address,
        PASSPHRASE,
        "balanced",
        LEGACY_DERIVATION_BRAINWALLET_SHA256,
    )
    .unwrap();
    vault.save(&default_vault_path()).unwrap();
    address
}

#[test]
fn no_input_at_all_can_derive_a_key_from_text() {
    tier0_gate("legacy_brainwallet_creation_removed", || {
        with_isolated_wallet_dir(|| {
            let mut wallet = WalletService::new(None, None).unwrap();
            let any_address = WalletAccount::create_random().unwrap().address();

            // A memorable sentence, a foreign-chain mnemonic, a passphrase: all of
            // these used to become keys. There is no longer any path that accepts
            // them, acknowledged or otherwise.
            for text in [
                PHRASE,
                "trezor",
                "abandon abandon abandon abandon abandon abandon abandon about",
                "not-hex-at-all",
                "I UNDERSTAND LEGACY BRAINWALLET RISK",
            ] {
                let error = wallet
                    .import_wallet(text, PASSPHRASE, &any_address)
                    .unwrap_err();
                let message = format!("{error}");
                assert!(
                    message.contains("exactly 64 hex characters"),
                    "unexpected error for {text:?}: {message}"
                );
                assert!(
                    message.contains("cannot derive a key from a phrase"),
                    "the error must not point anywhere else: {message}"
                );
            }
            assert!(!default_vault_path().exists());
        });
    });
}

#[test]
fn a_mistyped_key_is_reported_instead_of_importing_a_different_wallet() {
    tier0_gate("legacy_brainwallet_mistyped_key_guard", || {
        with_isolated_wallet_dir(|| {
            let mut wallet = WalletService::new(None, None).unwrap();
            let key = "ab".repeat(32);
            let real = WalletAccount::from_secret_hex(&key).unwrap().address();

            // Wrong length is caught by counting.
            for wrong_length in [&key[..59], format!("{key}abcd").as_str()] {
                let error = wallet
                    .import_wallet(wrong_length, PASSPHRASE, &real)
                    .unwrap_err();
                assert!(format!("{error}").contains("exactly 64"), "{error}");
            }

            // Wrong content is the dangerous case: still 64 valid hex characters,
            // still a perfectly good key, just not this wallet's. Only the address
            // check catches it.
            let mut typo: Vec<char> = key.chars().collect();
            typo[7] = if typo[7] == 'a' { 'b' } else { 'a' };
            let typo: String = typo.into_iter().collect();
            assert_eq!(typo.len(), 64);
            let error = wallet.import_wallet(&typo, PASSPHRASE, &real).unwrap_err();
            assert!(
                format!("{error}").contains("does not belong to that address"),
                "{error}"
            );
            assert!(!default_vault_path().exists());

            // A blank or malformed address is refused too.
            for bad in ["", "   ", "not-an-address"] {
                assert!(wallet.import_wallet(&key, PASSPHRASE, bad).is_err());
            }

            // The real key, including pasted across two lines, imports and matches.
            let split = format!("{} {}", &key[..32], &key[32..]);
            let address = wallet.import_wallet(&split, PASSPHRASE, &real).unwrap();
            assert_eq!(address, real);
            assert_eq!(wallet.status().legacy_key_derivation, None);
        });
    });
}

#[test]
fn an_existing_brainwallet_vault_is_still_recognised_before_unlock() {
    tier0_gate("legacy_brainwallet_marker_detected", || {
        with_isolated_wallet_dir(|| {
            let address = plant_legacy_vault();

            let mut wallet = WalletService::new(None, None).unwrap();
            let status = wallet.status();
            assert_eq!(status.address.as_deref(), Some(address.as_str()));
            assert!(status.locked);
            // Visible while still locked, so a restart cannot hide the warning.
            assert_eq!(
                status.legacy_key_derivation.as_deref(),
                Some(LEGACY_DERIVATION_BRAINWALLET_SHA256)
            );
            wallet.unlock(PASSPHRASE).unwrap();
            assert_eq!(
                wallet.status().legacy_key_derivation.as_deref(),
                Some(LEGACY_DERIVATION_BRAINWALLET_SHA256)
            );
        });
    });
}

#[test]
fn the_marker_survives_passphrase_and_profile_changes() {
    tier0_gate("legacy_brainwallet_marker_persistence", || {
        with_isolated_wallet_dir(|| {
            plant_legacy_vault();
            let mut wallet = WalletService::new(None, None).unwrap();
            wallet.unlock(PASSPHRASE).unwrap();

            wallet
                .change_passphrase(PASSPHRASE, ROTATED_PASSPHRASE)
                .unwrap();
            assert_eq!(
                wallet.status().legacy_key_derivation.as_deref(),
                Some(LEGACY_DERIVATION_BRAINWALLET_SHA256)
            );

            wallet
                .change_security_profile(ROTATED_PASSPHRASE, SecurityProfile::paranoid())
                .unwrap();
            assert_eq!(
                wallet.status().legacy_key_derivation.as_deref(),
                Some(LEGACY_DERIVATION_BRAINWALLET_SHA256)
            );
        });
    });
}

#[test]
fn the_marker_is_authenticated_and_cannot_be_stripped_or_forged() {
    tier0_gate("legacy_brainwallet_marker_authenticated", || {
        with_isolated_wallet_dir(|| {
            plant_legacy_vault();
            let path = default_vault_path();
            let original = std::fs::read(&path).unwrap();

            // Stripping the marker to hide the weakness breaks GCM.
            let mut stripped: serde_json::Value = serde_json::from_slice(&original).unwrap();
            stripped["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("legacy_key_derivation");
            std::fs::write(&path, serde_json::to_vec(&stripped).unwrap()).unwrap();
            assert!(matches!(
                WalletService::new(None, None).unwrap().unlock(PASSPHRASE),
                Err(WalletError::InvalidPassphrase)
            ));

            // An unknown value is refused before any key work.
            let mut edited: serde_json::Value = serde_json::from_slice(&original).unwrap();
            edited["metadata"]["legacy_key_derivation"] = "argon2id".into();
            std::fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
            assert!(
                WalletService::new(None, None)
                    .unwrap()
                    .unlock(PASSPHRASE)
                    .is_err()
            );

            std::fs::write(&path, &original).unwrap();
            assert!(
                WalletService::new(None, None)
                    .unwrap()
                    .unlock(PASSPHRASE)
                    .is_ok()
            );
        });
    });
}

#[test]
fn a_forged_marker_cannot_be_bolted_onto_a_healthy_vault() {
    tier0_gate("legacy_brainwallet_marker_not_forgeable", || {
        with_isolated_wallet_dir(|| {
            let mut wallet = WalletService::new(None, None).unwrap();
            wallet.create_wallet(PASSPHRASE).unwrap();
            assert_eq!(wallet.status().legacy_key_derivation, None);
            drop(wallet);

            let path = default_vault_path();
            let mut forged: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            forged["metadata"]["legacy_key_derivation"] =
                LEGACY_DERIVATION_BRAINWALLET_SHA256.into();
            std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
            assert!(matches!(
                WalletService::new(None, None).unwrap().unlock(PASSPHRASE),
                Err(WalletError::InvalidPassphrase)
            ));
        });
    });
}

#[test]
fn cold_vault_still_refuses_a_key_it_cannot_actually_protect() {
    tier0_gate("legacy_brainwallet_cold_vault_refusal", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                plant_legacy_vault();
                let mut wallet = WalletService::new(None, None).unwrap();
                wallet.unlock(PASSPHRASE).unwrap();

                let error = wallet.prepare_cold_vault_activation().unwrap_err();
                let message = format!("{error}");
                assert!(message.contains("recovery phrase"), "{message}");
                assert!(message.contains("sweep"), "{message}");
                assert_eq!(wallet.status().hardware_signing_mode, "software");
            });
        });
    });
}

#[test]
fn the_vault_layer_rejects_an_unknown_derivation_marker() {
    tier0_gate("legacy_brainwallet_marker_allowlist", || {
        assert!(
            EncryptedVault::encrypt_legacy_derived(
                "ab".repeat(32).as_str(),
                "1Test",
                PASSPHRASE,
                "balanced",
                "sha1",
            )
            .is_err()
        );
    });
}
