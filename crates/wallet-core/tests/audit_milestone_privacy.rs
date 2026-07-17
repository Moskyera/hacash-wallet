//! Milestone: local privacy controls.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::payment::PaymentRail;
use hacash_wallet_core::privacy::PrivacySettings;

#[test]
fn milestone_privacy_skips_history_storage() {
    tier0_gate("privacy_no_history", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("privacy-passphrase12").unwrap();
            let mut privacy = PrivacySettings::default();
            privacy.store_tx_history = false;
            svc.update_privacy_settings(privacy).unwrap();
            svc.audit_append_history_if_enabled(
                PaymentRail::L1OnChain,
                "abc123",
                "1From",
                "1To",
                1.0,
                "test",
            )
            .unwrap();
            assert!(svc.tx_history().is_empty());
        });
    });
}

#[test]
fn milestone_privacy_clear_history() {
    tier0_gate("privacy_clear", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("privacy-passphrase12").unwrap();
            svc.audit_append_history_if_enabled(
                PaymentRail::L1OnChain,
                "hash1",
                "1A",
                "1B",
                2.0,
                "send",
            )
            .unwrap();
            assert_eq!(svc.tx_history().len(), 1);
            svc.clear_tx_history().unwrap();
            assert!(svc.tx_history().is_empty());
        });
    });
}

#[test]
fn milestone_privacy_redacts_history_view() {
    tier0_gate("privacy_redact", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("privacy-passphrase12").unwrap();
            svc.audit_append_history_if_enabled(
                PaymentRail::L1OnChain,
                "deadbeefcafebabe",
                "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "1B",
                5.5,
                "send",
            )
            .unwrap();
            let mut privacy = PrivacySettings::default();
            privacy.hide_addresses = true;
            privacy.hide_balances = true;
            svc.update_privacy_settings(privacy).unwrap();
            let rows = svc.tx_history();
            assert_eq!(rows.len(), 1);
            assert!(rows[0].from.contains('…'));
            assert!(rows[0].tx_hash.contains('…'));
            assert_eq!(rows[0].summary, "•••• HAC");
        });
    });
}
