//! Dev: Type 4 send after quantum is funded.

use hacash_wallet_core::WalletService;
use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

fn main() {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _protocol = install_test_scope(setup);

    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let mut svc =
            WalletService::new(Some("http://127.0.0.1:8080".into()), None).expect("wallet");
        svc.unlock("HacashDev2026!").expect("unlock");
        let ks_pass = "quantum-ks-12345678";
        let to = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

        println!(
            "Quantum balance: {} HAC",
            svc.quantum_balance_mei().await.unwrap_or(0.0)
        );

        let preflight = svc.quantum_preflight_type4(to, "0.1").await.expect("preflight");
        println!("Type4 preflight ok={} errors={:?}", preflight.ok, preflight.errors);

        if preflight.ok {
            match svc.quantum_send_type4(to, "0.1", ks_pass).await {
                Ok(tx) => println!("Type4 sent hash={} fee={}", tx.hash, tx.fee_used),
                Err(e) => println!("Type4 send failed: {e}"),
            }
        }
    });
}