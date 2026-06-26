//! AUDIT-GATE: Quantum keystore lifecycle (offline + settings persistence).

mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;

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
            assert_eq!(settings.active_address.as_deref(), Some(info.address.as_str()));
            assert_eq!(settings.kind.as_deref(), Some("pqckey"));
            assert_eq!(settings.address_version, Some(6));
        });
    });
}

#[test]
fn audit_quantum_hybrid_create_persists_settings() {
    audit_gate("quantum_hybrid_persist", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("vault-pass-123456").unwrap();
            let info = svc.quantum_create_hybrid("keystore-pass-123", None).unwrap();
            assert_eq!(info.kind, "hybrid");
            assert_eq!(info.address_version, 7);

            let settings = svc.quantum_settings();
            assert!(settings.quantum_mode);
            assert_eq!(settings.kind.as_deref(), Some("hybrid"));
            assert_eq!(settings.address_version, Some(7));
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

            svc.quantum_import_keystore(&exported, "ks-pass-rotated").unwrap();
            let settings = svc.quantum_settings();
            assert_eq!(
                settings.active_address.as_deref(),
                Some(created.address.as_str())
            );
            assert_eq!(settings.kind.as_deref(), Some("hybrid"));
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
            assert_eq!(settings.kind.as_deref(), Some("hybrid"));
            assert_eq!(settings.address_version, Some(7));
            assert_eq!(
                settings.active_address.as_deref(),
                Some(hybrid.address.as_str())
            );
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
            assert!(settings.active_address.is_some());
            assert_eq!(settings.kind.as_deref(), Some("pqckey"));
        });
    });
}