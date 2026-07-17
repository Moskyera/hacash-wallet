//! AUDIT-GATE: Quantum keystore lifecycle (offline + settings persistence).

mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;

fn assert_active_account(
    settings: &hacash_wallet_core::quantum::QuantumSettings,
    expected_kind: &str,
    expected_version: u8,
    expected_address: &str,
) {
    let acc = settings
        .active_account
        .as_ref()
        .expect("active_account should be set");
    assert_eq!(acc.kind, expected_kind);
    assert_eq!(acc.address_version, expected_version);
    assert_eq!(acc.address, expected_address);
}

#[test]
fn audit_quantum_pqc_create_persists_settings() {
    audit_gate("quantum_pqc_persist", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let info = svc.quantum_create_pqc("keystore-pass-123").unwrap();
            assert_eq!(info.kind, "pqckey");
            assert_eq!(info.address_version, 6);

            let settings = svc.quantum_settings();
            assert!(settings.quantum_mode);
            assert_active_account(&settings, "pqckey", 6, &info.address);
        });
    });
}

#[test]
fn audit_quantum_hybrid_create_persists_settings() {
    audit_gate("quantum_hybrid_persist", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let info = svc
                .quantum_create_hybrid("keystore-pass-123", None)
                .unwrap();
            assert_eq!(info.kind, "hybrid");
            assert_eq!(info.address_version, 7);

            let settings = svc.quantum_settings();
            assert!(settings.quantum_mode);
            assert_active_account(&settings, "hybrid", 7, &info.address);
        });
    });
}

#[test]
fn audit_quantum_export_import_roundtrip() {
    audit_gate("quantum_export_import", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let created = svc.quantum_create_hybrid("ks-pass-original", None).unwrap();
            let exported = svc
                .quantum_export_keystore("ks-pass-original", Some("ks-pass-rotated"))
                .unwrap();

            svc.quantum_import_keystore(&exported, "ks-pass-rotated")
                .unwrap();
            let settings = svc.quantum_settings();
            assert_active_account(&settings, "hybrid", 7, &created.address);
        });
    });
}

#[test]
fn audit_quantum_settings_prefers_address_on_kind_mismatch() {
    audit_gate("quantum_kind_addr_mismatch", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let pqc = svc.quantum_create_pqc("ks-pass-12345").unwrap();
            let exported = svc.quantum_export_keystore("ks-pass-12345", None).unwrap();
            let mut v: serde_json::Value = serde_json::from_str(&exported).unwrap();
            v["kind"] = serde_json::Value::String("hybrid".into());
            let tampered = v.to_string();
            svc.store_quantum_keystore_json(tampered).unwrap();

            let settings = svc.quantum_settings();
            assert_active_account(&settings, "pqckey", 6, &pqc.address);
        });
    });
}

#[test]
fn audit_quantum_v6_to_v7_replaces_address_and_kind() {
    audit_gate("quantum_v6_to_v7", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let pqc = svc.quantum_create_pqc("ks-pass-12345").unwrap();
            assert_eq!(pqc.address_version, 6);
            assert_eq!(pqc.kind, "pqckey");

            let hybrid = svc.quantum_create_hybrid("ks-pass-67890", None).unwrap();
            assert_eq!(hybrid.address_version, 7);
            assert_eq!(hybrid.kind, "hybrid");
            assert_ne!(pqc.address, hybrid.address);

            let settings = svc.quantum_settings();
            assert_active_account(&settings, "hybrid", 7, &hybrid.address);
        });
    });
}

#[test]
fn audit_quantum_settings_roundtrip_includes_quantum_fields() {
    audit_gate("quantum_settings_roundtrip", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            svc.quantum_create_pqc("ks-pass-12345").unwrap();
            svc.set_quantum_mode(false).unwrap();

            let reloaded = WalletService::new(None, None).unwrap();
            let settings = reloaded.quantum_settings();
            assert!(!settings.quantum_mode);
            assert!(settings.active_account.is_some());
            assert_eq!(
                settings.active_account.as_ref().map(|a| a.kind.as_str()),
                Some("pqckey")
            );
        });
    });
}

#[test]
fn audit_quantum_pqc_type4_preflight_allowed() {
    audit_gate("quantum_pqc_type4_preflight", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            svc.quantum_create_pqc("ks-pass-12345").unwrap();
            let account = svc.quantum_settings().active_account.unwrap();
            let preflight = hacash_wallet_core::hip23::validate_type4_send(
                &account.kind,
                "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                0.1003,
                0.0,
                "1:244",
            )
            .unwrap();
            assert!(
                !preflight
                    .errors
                    .iter()
                    .any(|e| e.contains("Hybrid (v7) account")),
                "PQC must not be blocked from Type 4 preflight: {:?}",
                preflight.errors
            );
            assert!(
                preflight.warnings.iter().any(|w| w.contains("ML-DSA")),
                "expected PQC signing hint: {:?}",
                preflight.warnings
            );
            assert!(!preflight.ok);
            assert!(preflight.errors.iter().any(|e| e.contains("Insufficient")));
        });
    });
}

#[test]
fn audit_quantum_encrypted_keystore_survives_lock_reload() {
    audit_gate("quantum_encrypted_persist", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let info = svc.quantum_create_hybrid("ks-pass-encrypt", None).unwrap();
            svc.lock();

            let reloaded = WalletService::new(None, None).unwrap();
            let locked_settings = reloaded.quantum_settings();
            assert_active_account(&locked_settings, "hybrid", 7, &info.address);

            let mut unlocked = WalletService::new(None, None).unwrap();
            unlocked.unlock("vault-pass-123456").unwrap();
            let settings = unlocked.quantum_settings();
            assert_active_account(&settings, "hybrid", 7, &info.address);
        });
    });
}
