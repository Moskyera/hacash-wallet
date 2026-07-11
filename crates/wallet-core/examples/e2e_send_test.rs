//! Dev: test L1 send submit to legacy address.

use hacash_wallet_core::WalletService;
use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

fn main() {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _protocol = install_test_scope(setup);

    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let mut svc = WalletService::new(Some("http://127.0.0.1:8080".into()), None).expect("wallet");
        svc.unlock("HacashDev2026!").expect("unlock");
        let to = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";
        match svc.send_hac(to, 1.0, Default::default()).await {
            Ok(r) => println!("OK hash={}", r.tx_hash),
            Err(e) => println!("FAIL: {e}"),
        }
    });
}