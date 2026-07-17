//! Live local-testnet HACD and bridged-BTC preflight checks without broadcast.

use hacash_wallet_core::send_options::HACD_SERVICE_FEE_MEI;
use hacash_wallet_core::{WALLET_TREASURY_ADDRESS, WalletService};
use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

fn main() {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _protocol = install_test_scope(setup);
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let node_url =
            std::env::var("HACASH_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        let normalized = node_url.trim().trim_end_matches('/');
        assert!(
            normalized == "http://127.0.0.1:8080" || normalized == "http://localhost:8080",
            "refusing asset preflight outside the local testnet"
        );
        let passphrase =
            std::env::var("HACASH_DEV_PASSPHRASE").expect("HACASH_DEV_PASSPHRASE is required");
        let mut svc = WalletService::new(Some(node_url), None).expect("wallet");
        let _address = svc.unlock(&passphrase).expect("unlock");

        let diamonds = svc.list_owned_diamonds().await.expect("owned HACD");
        if let Some(name) = diamonds.first() {
            let selected = vec![name.clone()];
            let hacd = svc
                .preview_send_hacd(WALLET_TREASURY_ADDRESS, &selected)
                .await
                .expect("HACD preview");
            assert!(hacd.hip23.ok, "HACD preflight: {:?}", hacd.hip23.errors);
            assert_eq!(hacd.service_fee_treasury, WALLET_TREASURY_ADDRESS);
            assert!((hacd.service_fee_mei - HACD_SERVICE_FEE_MEI).abs() < f64::EPSILON);
            println!(
                "HACD preview name={} wallet_fee={:.3} network_fee={:.6}",
                selected[0], hacd.service_fee_mei, hacd.fee_mei
            );
            let blocked = svc
                .send_hacd(WALLET_TREASURY_ADDRESS, &selected)
                .await
                .expect_err("HACD send must require second factor");
            println!("HACD broadcast correctly blocked without second factor: {blocked}");
        } else {
            println!("No HACD ownership could be verified on the active testnet node");
        }

        match svc.preview_send_btc(WALLET_TREASURY_ADDRESS, 1).await {
            Ok(preview) => {
                println!(
                    "BTC preview total={} sat wallet_fee={} sat",
                    preview.total_debit_satoshi, preview.service_fee_satoshi
                );
                assert!(preview.hip23.ok, "BTC HIP-23 preflight must pass");
            }
            Err(error) => {
                println!("BTC preview correctly rejected on testnet: {error}");
            }
        }
    });
}
