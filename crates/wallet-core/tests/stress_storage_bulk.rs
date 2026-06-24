//! STRESS: Bulk persistence (history, bills, settings)

mod common;

use common::{stress_gate, with_isolated_wallet_dir};
use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::history::TxHistory;
use hacash_wallet_core::payment::PaymentRail;
use hacash_wallet_core::settings::WalletSettings;

#[test]
fn stress_history_append_2000_respects_cap() {
    stress_gate("history_2000", || {
        with_isolated_wallet_dir(|| {
            let mut h = TxHistory::load().unwrap();
            for i in 0..2000 {
                h.append(
                    PaymentRail::L1OnChain,
                    &format!("hash{i:06}"),
                    "1From",
                    "1To",
                    0.001 * (i as f64),
                    "stress",
                )
                .unwrap();
            }
            assert_eq!(h.list().len(), 500);
            assert_eq!(h.list()[0].tx_hash, "hash001999");
        });
    });
}

#[test]
fn stress_bills_store_1000_entries() {
    stress_gate("bills_1000", || {
        with_isolated_wallet_dir(|| {
            let mut b = BillStore::load().unwrap();
            for i in 0..1000 {
                b.store_bill(&format!("pay-{i:05}"), &format!("{i:064x}")).unwrap();
            }
            assert_eq!(b.count(), 1000);
            let reloaded = BillStore::load().unwrap();
            assert_eq!(reloaded.count(), 1000);
            for sample in [0usize, 500, 999] {
                let pid = format!("pay-{sample:05}");
                let hex = format!("{sample:064x}");
                assert_eq!(reloaded.get_bill(&pid), Some(hex.as_str()));
            }
        });
    });
}

#[test]
fn stress_settings_save_reload_500() {
    stress_gate("settings_500", || {
        with_isolated_wallet_dir(|| {
            for i in 0..500 {
                let mut s = WalletSettings::default();
                s.node_url = format!("https://node{i}.stress.test");
                s.security_profile = if i % 2 == 0 { "balanced" } else { "paranoid" }.into();
                s.save().unwrap();
                let loaded = WalletSettings::load().unwrap();
                assert_eq!(loaded.node_url, format!("https://node{i}.stress.test"));
            }
        });
    });
}