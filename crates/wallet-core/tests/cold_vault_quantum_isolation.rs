//! Adversarial gates for the Cold Vault/Quantum key isolation boundary.

mod common;

use std::fmt::Debug;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::airgap::{AIRGAP_VERSION, AirgapUnsigned};
use hacash_wallet_core::{WalletError, WalletService};

const WALLET_PASS: &str = "cold-quantum-wallet-pass-01";
const ROTATED_WALLET_PASS: &str = "cold-quantum-wallet-pass-02";
const QUANTUM_PASS: &str = "cold-quantum-keystore-pass-01";

fn assert_cold_policy<T: Debug>(result: Result<T, WalletError>) {
    match result {
        Err(WalletError::Policy(message)) => assert!(
            message.contains("cold vault"),
            "unexpected policy error: {message}"
        ),
        other => panic!("expected Cold Vault policy rejection, got {other:?}"),
    }
}

fn invalid_unsigned_type4() -> AirgapUnsigned {
    AirgapUnsigned {
        v: AIRGAP_VERSION,
        from: "attacker-controlled-from".into(),
        to: "attacker-controlled-to".into(),
        amount_mei: 1.0,
        amount_wire: "1".into(),
        fee: "1:244".into(),
        service_fee_mei: 0.003,
        service_fee_treasury: None,
        body_hex: "00".into(),
        summary: "must never be parsed or signed".into(),
        tx_type: 4,
    }
}

#[test]
fn cold_vault_rejects_every_quantum_secret_entrypoint_before_work() {
    tier0_gate("cold_vault_quantum_secret_entrypoints", || {
        with_isolated_wallet_dir(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let mut wallet = WalletService::new(Some("http://127.0.0.1:1".into()), None).unwrap();
            wallet.create_wallet(WALLET_PASS).unwrap();
            let account = wallet.quantum_create_pqc(QUANTUM_PASS).unwrap();
            let exported = wallet.quantum_export_keystore(QUANTUM_PASS, None).unwrap();

            wallet.audit_activate_cold_vault(WALLET_PASS).unwrap();
            assert!(wallet.status().signing_available);

            // Invalid attacker-controlled inputs prove the policy check occurs
            // before parsing, key generation, password work, or signing.
            assert_cold_policy(wallet.quantum_create_pqc("new-password"));
            assert_cold_policy(wallet.quantum_create_hybrid("new-password", None));
            assert_cold_policy(
                wallet.quantum_create_hybrid_from_privakey("not-a-private-key", "new-password"),
            );
            assert_cold_policy(wallet.quantum_import_keystore("{not-json", "wrong-password"));
            assert_cold_policy(wallet.quantum_export_keystore("wrong-password", None));
            assert_cold_policy(
                wallet.quantum_export_keystore("wrong-password", Some("replacement-password")),
            );
            assert_cold_policy(wallet.store_quantum_keystore_json(exported));
            assert_cold_policy(
                wallet.quantum_airgap_sign_type4(&invalid_unsigned_type4(), "wrong-password"),
            );
            assert_cold_policy(runtime.block_on(wallet.quantum_send_type4(
                "invalid-recipient",
                "not-an-amount",
                "wrong-password",
            )));
            assert_cold_policy(runtime.block_on(wallet.quantum_send_test_tx("wrong-password")));

            // Address metadata remains usable without decrypting the keystore.
            let metadata = wallet.quantum_settings().active_account.unwrap();
            assert_eq!(metadata.address, account.address);

            // The authenticated vault policy, not session state, owns the gate.
            wallet.lock();
            assert_cold_policy(wallet.quantum_create_pqc("new-password"));
        });
    });
}

#[test]
fn cold_unlock_and_wallet_password_rotation_never_read_quantum_sidecar() {
    tier0_gate("cold_vault_quantum_unlock_isolation", || {
        with_isolated_wallet_dir(|| {
            let mut wallet = WalletService::new(None, None).unwrap();
            wallet.create_wallet(WALLET_PASS).unwrap();
            let account = wallet.quantum_create_pqc(QUANTUM_PASS).unwrap();
            wallet.audit_activate_cold_vault(WALLET_PASS).unwrap();
            wallet.lock();
            drop(wallet);

            let quantum_path = hacash_wallet_core::paths::quantum_keystore_path();
            assert!(quantum_path.exists());
            let corrupt_sidecar = b"corrupt Quantum sidecar that must remain quarantined";
            std::fs::write(&quantum_path, corrupt_sidecar).unwrap();

            let mut reopened = WalletService::new(None, None).unwrap();
            reopened.unlock(WALLET_PASS).unwrap();
            assert_eq!(
                reopened
                    .quantum_settings()
                    .active_account
                    .as_ref()
                    .map(|meta| meta.address.as_str()),
                Some(account.address.as_str())
            );

            // Rotating the classic wallet password must not derive or use a
            // Quantum key once the authenticated vault is Cold Vault.
            reopened
                .change_passphrase(WALLET_PASS, ROTATED_WALLET_PASS)
                .unwrap();
            assert_eq!(std::fs::read(&quantum_path).unwrap(), corrupt_sidecar);
            reopened.lock();
            drop(reopened);

            let mut final_open = WalletService::new(None, None).unwrap();
            final_open.unlock(ROTATED_WALLET_PASS).unwrap();
            assert!(final_open.status().signing_available);
            assert_cold_policy(final_open.quantum_export_keystore(QUANTUM_PASS, None));
        });
    });
}
