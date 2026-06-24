//! AUDIT-GATE: Local storage integrity (history, bills, settings)

mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::history::TxHistory;
use hacash_wallet_core::payment::PaymentRail;
use hacash_wallet_core::settings::WalletSettings;

#[test]
fn audit_history_max_cap_enforced() {
    audit_gate("history_cap", || {
        with_isolated_wallet_dir(|| {
            let mut h = TxHistory::load().unwrap();
            for i in 0..520 {
                h.append(
                    PaymentRail::L1OnChain,
                    &format!("hash{i}"),
                    "1From",
                    "1To",
                    1.0,
                    "test",
                )
                .unwrap();
            }
            assert!(h.list().len() <= 500);
        });
    });
}

#[test]
fn audit_bills_isolated_per_payment_id() {
    audit_gate("bills_isolation", || {
        with_isolated_wallet_dir(|| {
            let mut b = BillStore::load().unwrap();
            b.store_bill("pay-a", "aa").unwrap();
            b.store_bill("pay-b", "bb").unwrap();
            assert_eq!(b.get_bill("pay-a"), Some("aa"));
            assert_eq!(b.get_bill("pay-b"), Some("bb"));
            assert_eq!(b.count(), 2);
        });
    });
}

#[test]
fn audit_settings_roundtrip_preserves_security_profile() {
    audit_gate("settings_roundtrip", || {
        with_isolated_wallet_dir(|| {
            let mut s = WalletSettings::default();
            s.security_profile = "paranoid".into();
            s.l2_hub_url = Some("https://hub.test".into());
            s.save().unwrap();
            let loaded = WalletSettings::load().unwrap();
            assert_eq!(loaded.security_profile, "paranoid");
            assert_eq!(loaded.l2_hub_url.as_deref(), Some("https://hub.test"));
        });
    });
}

#[test]
fn audit_bills_reload_survives_restart() {
    audit_gate("bills_persist", || {
        with_isolated_wallet_dir(|| {
            let mut b = BillStore::load().unwrap();
            b.store_bill("id-1", "deadbeef").unwrap();
            let reloaded = BillStore::load().unwrap();
            assert_eq!(reloaded.get_bill("id-1"), Some("deadbeef"));
        });
    });
}