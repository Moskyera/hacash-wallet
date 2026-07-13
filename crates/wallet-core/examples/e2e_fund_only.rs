//! Dev: fund existing quantum PQC from legacy (skip create PQC).

use hacash_wallet_core::WalletService;
use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

fn main() {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _protocol = install_test_scope(setup);

    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let node_url = std::env::var("HACASH_NODE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        let vault_pass = std::env::var("HACASH_DEV_PASSPHRASE")
            .unwrap_or_else(|_| "HacashDev2026!".into());

        let mut svc = WalletService::new(Some(node_url), None).expect("wallet");
        let legacy = svc.unlock(&vault_pass).expect("unlock");
        let legacy_bal = svc.balance_mei().await.unwrap_or(0.0);
        println!("Legacy: {legacy} balance={legacy_bal} HAC");

        let quantum = svc
            .quantum_settings()
            .active_account
            .map(|a| a.address.clone())
            .expect("quantum account in settings");
        println!("Quantum target: {quantum}");

        let fund_amount: f64 = std::env::var("FUND_AMOUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(45.0);
        let preview = svc
            .preview_send(&quantum, fund_amount, &Default::default())
            .await
            .expect("preview");
        println!(
            "Preview ok={} amount={} fee={}",
            preview.hip23.ok, preview.amount_wire, preview.fee
        );

        match svc.send_hac(&quantum, fund_amount, Default::default()).await {
            Ok(r) => println!("Fund OK rail={:?} hash={}", r.rail, r.tx_hash),
            Err(e) => println!("Fund FAIL: {e}"),
        }

        println!(
            "Quantum balance: {} HAC",
            svc.quantum_balance_mei().await.unwrap_or(0.0)
        );
    });
}