//! Controlled testnet L1 smoke send.
//!
//! Requires HACASH_DEV_PASSPHRASE. Defaults to a 0.01 HAC self-send on
//! the local node and verifies the recipient and treasury actions.

use std::time::Duration;

use hacash_wallet_core::payment::PaymentRail;
use hacash_wallet_core::{WALLET_TREASURY_ADDRESS, WalletService};
use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

fn require_local_testnet(url: &str) {
    let normalized = url.trim().trim_end_matches('/');
    assert!(
        normalized == "http://127.0.0.1:8080" || normalized == "http://localhost:8080",
        "refusing smoke send outside the local testnet node"
    );
}

fn main() {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _protocol = install_test_scope(setup);
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let node_url =
            std::env::var("HACASH_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        require_local_testnet(&node_url);
        let passphrase =
            std::env::var("HACASH_DEV_PASSPHRASE").expect("HACASH_DEV_PASSPHRASE is required");
        let amount_mei = std::env::var("HACASH_TEST_AMOUNT")
            .ok()
            .and_then(|raw| raw.parse::<f64>().ok())
            .unwrap_or(0.01);
        assert!(
            amount_mei.is_finite() && amount_mei > 0.0 && amount_mei <= 0.01,
            "smoke amount must be greater than 0 and at most 0.01 HAC"
        );

        let mut svc = WalletService::new(Some(node_url.clone()), None).expect("wallet");
        let from = svc.unlock(&passphrase).expect("unlock");
        let to = std::env::var("HACASH_TEST_RECIPIENT").unwrap_or_else(|_| from.clone());
        let balance = svc.balance_mei().await.expect("testnet balance");
        println!("Local testnet sender={from} balance={balance:.6} HAC");

        let preview = svc
            .preview_send(&to, amount_mei, &Default::default())
            .await
            .expect("preview");
        assert_eq!(preview.plan.rail, PaymentRail::L1OnChain);
        assert_eq!(
            preview.plan.fee_breakdown.service_fee_treasury.as_deref(),
            Some(WALLET_TREASURY_ADDRESS)
        );
        let wallet_fee = preview
            .plan
            .fee_breakdown
            .service_fee_mei
            .expect("wallet fee");
        println!(
            "Preview amount={amount_mei:.6} wallet_fee={wallet_fee:.6} network_fee={}",
            preview.fee
        );

        let sent = svc
            .send_hac(&to, amount_mei, Default::default())
            .await
            .expect("testnet send");
        println!(
            "Submitted through configured broadcast path hash={}",
            sent.tx_hash
        );

        let client = reqwest::Client::new();
        let query_url = format!(
            "{}/query/transaction?hash={}&action=true&unit=mei",
            node_url.trim_end_matches('/'),
            sent.tx_hash
        );
        let mut tx = None;
        for _ in 0..20 {
            if let Ok(response) = client.get(&query_url).send().await
                && let Ok(body) = response.json::<serde_json::Value>().await
                && body.get("ret").and_then(|v| v.as_i64()) == Some(0)
            {
                tx = Some(body);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let tx = tx.expect("submitted transaction was not found in the local testnet node");
        let actions = tx
            .get("actions")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
            .to_string();
        assert!(actions.contains(&to), "recipient action missing");
        assert!(
            actions.contains(WALLET_TREASURY_ADDRESS),
            "treasury action missing"
        );
        println!("Verified recipient and treasury actions in local testnet transaction");
    });
}
