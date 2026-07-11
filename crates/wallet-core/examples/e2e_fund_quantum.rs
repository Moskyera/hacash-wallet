//! Dev E2E: fund quantum from legacy balance, then Type 4 preflight.

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
        let ks_pass = std::env::var("HACASH_DEV_KS_PASS")
            .unwrap_or_else(|_| "quantum-ks-12345678".into());

        let mut svc =
            hacash_wallet_core::WalletService::new(Some(node_url), None).expect("wallet");
        let addr = svc.unlock(&vault_pass).expect("unlock");
        println!("Legacy: {addr}");
        println!("Legacy balance: {} HAC", svc.balance_mei().await.unwrap_or(0.0));

        let pqc = svc.quantum_create_pqc(&ks_pass).expect("create PQC");
        println!("Quantum PQC: {} (v{})", pqc.address, pqc.address_version);

        let fund_amount = 45.0_f64;
        let preview = svc
            .preview_send(&pqc.address, fund_amount, Default::default())
            .await
            .expect("preview");
        println!("Fund preview ok={} fee={}", preview.hip23.ok, preview.fee);

        match svc.send_hac(&pqc.address, fund_amount, Default::default()).await {
            Ok(send) => println!("Funded quantum: {}", send.tx_hash),
            Err(e) => println!("Fund send failed: {e}"),
        }

        println!("Quantum balance: {} HAC", svc.quantum_balance_mei().await.unwrap_or(0.0));

        let preflight = svc
            .quantum_preflight_type4("1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9", "0.1")
            .await
            .expect("preflight");
        println!("Type 4 preflight ok={}", preflight.ok);
        println!("  errors: {:?}", preflight.errors);

        if preflight.ok {
            match svc
                .quantum_send_type4("1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9", "0.1", &ks_pass)
                .await
            {
                Ok(tx) => println!("Type 4 sent: hash={} fee={}", tx.hash, tx.fee_used),
                Err(e) => println!("Type 4 send failed: {e}"),
            }
        }
    });
}