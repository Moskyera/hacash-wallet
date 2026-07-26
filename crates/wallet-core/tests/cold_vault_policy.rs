//! Cold Vault security boundary and exact air-gap signing regression gates.

mod common;

use basis::interface::Transaction;
use common::{tier0_gate, with_isolated_wallet_dir, with_protocol_setup};
use field::{Address, Amount, Serialize};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::airgap::{AIRGAP_VERSION, AirgapUnsigned};
use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::send_options::{
    WALLET_TREASURY_ADDRESS, compute_service_fee_mei, format_service_fee_amount_wire,
};
use hacash_wallet_core::settings::{WalletSettings, settings_path};
use hacash_wallet_core::vault::default_vault_path;
use hacash_wallet_core::{WalletError, WalletService};
use protocol::action::HacToTrs;
use protocol::transaction::TransactionType2;
use sys::ToHex;

const PASSPHRASE: &str = "cold-vault-passphrase-01";
const NEW_PASSPHRASE: &str = "cold-vault-passphrase-02";
const TEST_TIMESTAMP: u64 = 1_730_000_000;
const DAPP_ORIGIN: &str = "https://hacd.it";

fn hac_to(to: Address, amount: Amount) -> HacToTrs {
    HacToTrs::create_by(to, amount)
}

fn unsigned_type2(from: &str) -> AirgapUnsigned {
    let recipient = WalletAccount::create("cold-vault-recipient").unwrap();
    let to = Address::from_readable(&recipient.address()).unwrap();
    let from_address = Address::from_readable(from).unwrap();
    let amount_mei = 1.0;
    let amount_wire = "1".to_string();
    let service_fee_mei = compute_service_fee_mei(amount_mei);
    let service_fee_wire = format_service_fee_amount_wire(service_fee_mei);
    let fee = "1:244".to_string();
    let mut tx = TransactionType2::new_by(
        from_address,
        Amount::from(fee.as_str()).unwrap(),
        TEST_TIMESTAMP,
    );
    tx.push_action(Box::new(hac_to(
        to,
        Amount::from(amount_wire.as_str()).unwrap(),
    )))
    .unwrap();
    tx.push_action(Box::new(hac_to(
        Address::from_readable(WALLET_TREASURY_ADDRESS).unwrap(),
        Amount::from(service_fee_wire.as_str()).unwrap(),
    )))
    .unwrap();

    AirgapUnsigned {
        v: AIRGAP_VERSION,
        from: from.into(),
        to: to.to_readable(),
        amount_mei,
        amount_wire,
        fee,
        service_fee_mei,
        service_fee_treasury: Some(WALLET_TREASURY_ADDRESS.into()),
        body_hex: tx.serialize().to_hex(),
        summary: "Cold Vault exact Type 2 fixture".into(),
        tx_type: TransactionType2::TYPE,
    }
}

fn activate_cold_vault() -> (WalletService, String, AirgapUnsigned) {
    let signing_account = WalletAccount::create_random().unwrap();
    let secret = signing_account.secret_hex();
    let mut wallet = WalletService::new(None, None).unwrap();
    let address = wallet
        .import_wallet(&secret, PASSPHRASE, &signing_account.address())
        .unwrap();
    let unsigned = unsigned_type2(&address);

    wallet.set_biometric_unlock_enabled(true).unwrap();
    wallet.confirm_biometric_for_send().unwrap();
    wallet.dapp_connect(DAPP_ORIGIN).unwrap();
    assert!(wallet.dapp_session_active());
    approve_and_activate_cold_vault(&mut wallet, PASSPHRASE);
    (wallet, address, unsigned)
}

/// The production activation path: stage the exact ticket, run the platform
/// ceremony bound to it, then consume it.
fn approve_and_activate_cold_vault(wallet: &mut WalletService, passphrase: &str) {
    let prepared = wallet.prepare_cold_vault_activation().unwrap();
    assert!(prepared.authorization_required);
    let challenge = wallet
        .begin_prepared_native_authorization(&prepared.id)
        .unwrap();
    wallet
        .finish_prepared_native_authorization(&prepared.id, &challenge.nonce)
        .unwrap();
    wallet
        .execute_prepared_cold_vault_activation(&prepared.id, passphrase)
        .unwrap();
}

fn signing_wallet() -> (WalletService, String) {
    let signing_account = WalletAccount::create_random().unwrap();
    let secret = signing_account.secret_hex();
    let mut wallet = WalletService::new(None, None).unwrap();
    let address = wallet
        .import_wallet(&secret, PASSPHRASE, &signing_account.address())
        .unwrap();
    (wallet, address)
}

#[test]
fn activation_is_authenticated_paranoid_and_clears_all_grants() {
    tier0_gate("cold_vault_activation_invariants", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, address, _) = activate_cold_vault();
                let status = wallet.status();
                assert_eq!(status.address.as_deref(), Some(address.as_str()));
                assert_eq!(status.hardware_signing_mode, "airgap_only");
                assert_eq!(status.security_profile, "paranoid");
                assert!(status.signing_available);
                assert!(!status.watch_only);
                assert!(!wallet.dapp_session_active());

                let settings = wallet.get_settings();
                assert_eq!(settings.hardware_signing_mode, "airgap_only");
                assert_eq!(settings.security_profile, "paranoid");
                assert!(!settings.biometric_unlock_enabled);
                let factors = wallet.audit_second_factor_snapshot().unwrap();
                assert!(!factors.biometric_ok);
                assert!(!factors.yubikey_ok);
                assert!(wallet.set_biometric_unlock_enabled(true).is_err());
            });
        });
    });
}

#[test]
fn the_correct_passphrase_alone_can_never_activate_the_cold_vault() {
    tier0_gate("cold_vault_activation_needs_fresh_ceremony", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, _) = signing_wallet();

                // The legacy passphrase-only entrypoint is closed for good.
                assert!(
                    wallet
                        .change_hardware_signing_mode(
                            PASSPHRASE,
                            HardwareSigningMode::AirgapOnly
                        )
                        .is_err()
                );
                assert!(
                    wallet
                        .set_hardware_signing_mode(HardwareSigningMode::AirgapOnly)
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");

                // A staged ticket without a ceremony is worthless, even with the
                // right passphrase, and consuming it does not leave it replayable.
                let prepared = wallet.prepare_cold_vault_activation().unwrap();
                assert!(prepared.authorization_required);
                assert!(!wallet.cold_vault_activation_is_authorized(&prepared.id));
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation(&prepared.id, PASSPHRASE)
                        .is_err()
                );
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation(&prepared.id, PASSPHRASE)
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");

                // An approved ticket authorizes only its own id.
                let prepared = wallet.prepare_cold_vault_activation().unwrap();
                let challenge = wallet
                    .begin_prepared_native_authorization(&prepared.id)
                    .unwrap();
                wallet
                    .finish_prepared_native_authorization(&prepared.id, &challenge.nonce)
                    .unwrap();
                assert!(wallet.cold_vault_activation_is_authorized(&prepared.id));
                assert!(!wallet.cold_vault_activation_is_authorized("attacker-operation"));
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation("attacker-operation", PASSPHRASE)
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");
                assert!(!wallet.cold_vault_activation_is_authorized(&prepared.id));

                // Staging any other operation invalidates an approved activation.
                let prepared = wallet.prepare_cold_vault_activation().unwrap();
                let challenge = wallet
                    .begin_prepared_native_authorization(&prepared.id)
                    .unwrap();
                wallet
                    .finish_prepared_native_authorization(&prepared.id, &challenge.nonce)
                    .unwrap();
                let unsigned = unsigned_type2(wallet.status().address.as_deref().unwrap());
                wallet.prepare_airgap_sign(&unsigned).unwrap();
                assert!(!wallet.cold_vault_activation_is_authorized(&prepared.id));
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation(&prepared.id, PASSPHRASE)
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");

                // Only the full ceremony succeeds, and only once.
                approve_and_activate_cold_vault(&mut wallet, PASSPHRASE);
                assert_eq!(wallet.status().hardware_signing_mode, "airgap_only");
                assert!(wallet.prepare_cold_vault_activation().is_err());
            });
        });
    });
}

#[test]
fn an_approved_activation_ticket_still_fails_on_a_wrong_passphrase_and_is_burned() {
    tier0_gate("cold_vault_activation_passphrase_bound", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, _) = signing_wallet();
                let prepared = wallet.prepare_cold_vault_activation().unwrap();
                let challenge = wallet
                    .begin_prepared_native_authorization(&prepared.id)
                    .unwrap();
                wallet
                    .finish_prepared_native_authorization(&prepared.id, &challenge.nonce)
                    .unwrap();
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation(&prepared.id, "wrong-passphrase")
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");
                // The ceremony does not survive the failed attempt.
                assert!(!wallet.cold_vault_activation_is_authorized(&prepared.id));
                assert!(
                    wallet
                        .execute_prepared_cold_vault_activation(&prepared.id, PASSPHRASE)
                        .is_err()
                );
                assert_eq!(wallet.status().hardware_signing_mode, "software");
            });
        });
    });
}

/// Exact argument list of the call starting at `start`, by paren depth.
fn call_arguments(source: &str, start: usize) -> &str {
    let open = start + source[start..].find('(').expect("call has no argument list");
    let mut depth = 0usize;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced call arguments at byte {start}");
}

#[test]
fn only_the_authorized_path_can_migrate_a_vault_into_cold_mode() {
    tier0_gate("cold_vault_single_activation_path", || {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let wallet = std::fs::read_to_string(crate_root.join("src/wallet.rs")).unwrap();
        let service =
            std::fs::read_to_string(crate_root.join("src/wallet/authorization_service.rs")).unwrap();

        // Passphrase change, profile change, legacy unlock migration, policy
        // change and WebAuthn registration must all carry the vault's existing
        // mode forward. None of them may introduce the irreversible cold mode.
        let mut audited = 0;
        for (index, _) in wallet.match_indices("self.migrate_vault_encryption(") {
            let arguments = call_arguments(&wallet, index);
            assert!(
                !arguments.contains("AirgapOnly"),
                "wallet.rs migrates a vault into cold mode outside the authorized path: {arguments}"
            );
            audited += 1;
        }
        assert!(audited >= 5, "expected every migration call to be audited");

        // Exactly one call may target cold mode, and only after the activation
        // ticket has been consumed together with its platform ceremony.
        let permit = service
            .find("ColdVaultActivationPermit::after_consumed_ticket")
            .expect("cold vault activation permit is gone");
        let migration = service
            .find("self.migrate_vault_encryption(")
            .expect("authorized activation no longer migrates the vault");
        assert!(
            migration > permit,
            "the vault migration must follow the consumed-ticket permit"
        );
        assert!(call_arguments(&service, migration).contains("HardwareSigningMode::AirgapOnly"));
        assert_eq!(service.matches("self.migrate_vault_encryption(").count(), 1);
    });
}

#[test]
fn activation_display_names_the_irreversible_consequences() {
    tier0_gate("cold_vault_activation_trusted_display", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, address) = signing_wallet();
                let prepared = wallet.prepare_cold_vault_activation().unwrap();
                let rendered = format!(
                    "{}|{}|{}",
                    prepared.display.title,
                    prepared.display.summary,
                    prepared
                        .display
                        .fields
                        .iter()
                        .map(|entry| format!("{}={}", entry.label, entry.value))
                        .collect::<Vec<_>>()
                        .join("|")
                );
                assert!(rendered.contains(&address));
                assert!(rendered.contains("airgap_only"));
                assert!(rendered.contains("Reversible=No"));
                // The ceremony must not overstate its own scope: the honest limit
                // is that older backups of the same key still sign online.
                assert!(rendered.contains("Older backups"));
                // The OS prompt the user actually reads must carry the same facts.
                let challenge = wallet
                    .begin_prepared_native_authorization(&prepared.id)
                    .unwrap();
                assert!(challenge.message.contains("Cold Vault"));
                assert_eq!(challenge.operation_digest, prepared.digest);
            });
        });
    });
}

#[test]
fn cold_vault_is_one_way_even_with_the_correct_passphrase() {
    tier0_gate("cold_vault_one_way", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, _, _) = activate_cold_vault();
                assert!(
                    wallet
                        .change_hardware_signing_mode(PASSPHRASE, HardwareSigningMode::Software,)
                        .is_err()
                );
                assert!(
                    wallet
                        .change_security_profile(PASSPHRASE, SecurityProfile::default())
                        .is_err()
                );
                assert!(
                    wallet
                        .set_hardware_signing_mode(HardwareSigningMode::Software)
                        .is_err()
                );
                assert!(
                    wallet
                        .set_security_profile(SecurityProfile::default())
                        .is_err()
                );

                wallet
                    .change_passphrase(PASSPHRASE, NEW_PASSPHRASE)
                    .unwrap();
                wallet.lock();
                wallet.unlock(NEW_PASSPHRASE).unwrap();
                let status = wallet.status();
                assert_eq!(status.hardware_signing_mode, "airgap_only");
                assert_eq!(status.security_profile, "paranoid");
            });
        });
    });
}

#[test]
fn settings_and_vault_metadata_tampering_cannot_downgrade_cold_policy() {
    tier0_gate("cold_vault_tamper_resistance", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (wallet, _, _) = activate_cold_vault();
                let mut settings: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(settings_path()).unwrap()).unwrap();
                settings["hardware_signing_mode"] = "software".into();
                settings["security_profile"] = "balanced".into();
                settings["biometric_unlock_enabled"] = true.into();
                std::fs::write(settings_path(), serde_json::to_vec(&settings).unwrap()).unwrap();
                drop(wallet);

                let mut reopened = WalletService::new(None, None).unwrap();
                let status = reopened.status();
                assert_eq!(status.hardware_signing_mode, "airgap_only");
                assert_eq!(status.security_profile, "paranoid");
                let effective = reopened.get_settings();
                assert!(!effective.biometric_unlock_enabled);
                reopened.unlock(PASSPHRASE).unwrap();
                let mut malicious: WalletSettings = reopened.get_settings();
                malicious.hardware_signing_mode = "software".into();
                malicious.security_profile = "balanced".into();
                malicious.biometric_unlock_enabled = true;
                assert!(reopened.update_settings(malicious).is_err());
                reopened.lock();
                drop(reopened);

                let mut vault: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(default_vault_path()).unwrap()).unwrap();
                vault["metadata"]["hardware_signing_mode"] = "software".into();
                std::fs::write(default_vault_path(), serde_json::to_vec(&vault).unwrap()).unwrap();
                let mut tampered = WalletService::new(None, None).unwrap();
                assert!(matches!(
                    tampered.unlock(PASSPHRASE),
                    Err(WalletError::InvalidPassphrase)
                ));
            });
        });
    });
}

#[test]
fn every_online_or_generic_key_path_fails_closed() {
    tier0_gate("cold_vault_bypass_matrix", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let (mut wallet, _, unsigned) = activate_cold_vault();

                assert!(wallet.begin_native_biometric().is_err());
                assert!(wallet.finish_native_biometric("forged").is_err());
                assert!(wallet.confirm_biometric_for_send().is_err());
                assert!(wallet.webauthn_auth_begin(None).is_err());
                assert!(wallet.webauthn_auth_finish("{}").is_err());
                assert!(wallet.audit_sign_tx_body(&unsigned.body_hex).is_err());
                assert!(wallet.sign_airgap_unsigned(&unsigned).is_err());
                assert!(wallet.messenger_threads().is_err());
                assert!(
                    runtime
                        .block_on(wallet.send_hac(
                            "invalid-recipient",
                            1.0,
                            hacash_wallet_core::send_options::SendOptions::default(),
                        ))
                        .is_err()
                );
                assert!(
                    runtime
                        .block_on(wallet.accept_fast_pay("payment-id"))
                        .is_err()
                );

                let mut settings = wallet.get_settings();
                settings.network_mode = "testnet".into();
                wallet.update_settings(settings).unwrap();
                assert!(
                    runtime
                        .block_on(wallet.quantum_send_type4("invalid", "1", "pass"))
                        .is_err()
                );
                assert!(!wallet.dapp_session_active());
                let response = runtime
                    .block_on(wallet.dapp_sign_tx(DAPP_ORIGIN, &unsigned.body_hex, false))
                    .unwrap();
                assert_eq!(response["err"], "Wallet not connected");
                wallet.dapp_connect(DAPP_ORIGIN).unwrap();
                assert!(matches!(
                    runtime.block_on(wallet.dapp_sign_tx(DAPP_ORIGIN, &unsigned.body_hex, false,)),
                    Err(WalletError::Policy(_))
                ));
            });
        });
    });
}

#[test]
fn only_freshly_authorized_exact_type2_signs_and_then_exhausts_the_key() {
    tier0_gate("cold_vault_exact_airgap_only", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let (mut wallet, address, unsigned) = activate_cold_vault();

                let unauthorized = wallet.prepare_airgap_sign(&unsigned).unwrap();
                assert!(unauthorized.authorization_required);
                assert!(!unauthorized.webauthn_required);
                assert!(
                    wallet
                        .execute_prepared_airgap_sign(&unauthorized.id)
                        .is_err()
                );
                let exhausted = wallet.status();
                assert!(!exhausted.locked);
                assert!(!exhausted.signing_available);
                assert_eq!(exhausted.address.as_deref(), Some(address.as_str()));
                assert_eq!(exhausted.seconds_until_lock, None);

                wallet.unlock(PASSPHRASE).unwrap();
                let prepared = wallet.prepare_airgap_sign(&unsigned).unwrap();
                let challenge = wallet
                    .begin_prepared_native_authorization(&prepared.id)
                    .unwrap();
                wallet
                    .finish_prepared_native_authorization(&prepared.id, &challenge.nonce)
                    .unwrap();
                let signed = wallet.execute_prepared_airgap_sign(&prepared.id).unwrap();
                assert_eq!(signed.envelope.tx_type, TransactionType2::TYPE);
                assert!(!signed.envelope.signed_hex.is_empty());
                assert!(!signed.qr_parts.is_empty());

                let exhausted = wallet.status();
                assert!(!exhausted.locked);
                assert!(!exhausted.signing_available);
                assert_eq!(exhausted.address.as_deref(), Some(address.as_str()));
                assert!(wallet.audit_sign_tx_body(&unsigned.body_hex).is_err());
                assert!(wallet.execute_prepared_airgap_sign(&prepared.id).is_err());
                assert!(
                    wallet
                        .store_quantum_keystore_json("forbidden-secret".into())
                        .is_err()
                );

                wallet
                    .change_passphrase(PASSPHRASE, NEW_PASSPHRASE)
                    .unwrap();
                assert!(!wallet.status().signing_available);
                wallet.unlock(NEW_PASSPHRASE).unwrap();
                assert!(wallet.execute_prepared_airgap_sign(&prepared.id).is_err());
            });
        });
    });
}
