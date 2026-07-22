//! Controlled local-testnet Type 4 smoke send.

use std::time::Duration;

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
            "refusing Type 4 smoke send outside the local testnet"
        );
        let vault_pass =
            std::env::var("HACASH_DEV_PASSPHRASE").expect("HACASH_DEV_PASSPHRASE is required");
        let amount = std::env::var("HACASH_TEST_TYPE4_AMOUNT").unwrap_or_else(|_| "0.001".into());
        let amount_value = amount.parse::<f64>().expect("Type 4 amount");
        assert!(
            amount_value > 0.0 && amount_value <= 0.001,
            "Type 4 smoke amount must be at most 0.001 HAC"
        );

        let mut svc = WalletService::new(Some(node_url.clone()), None).expect("wallet");
        let legacy = svc.unlock(&vault_pass).expect("unlock");
        let quantum_balance = svc.quantum_balance_mei().await.expect("quantum balance");
        println!("Quantum balance={quantum_balance:.6} HAC recipient={legacy}");

        let preflight = svc
            .quantum_preflight_type4(&legacy, &amount)
            .await
            .expect("Type 4 preflight");
        assert!(
            preflight.ok,
            "Type 4 preflight errors: {:?}",
            preflight.errors
        );
        assert_eq!(preflight.service_fee_treasury, WALLET_TREASURY_ADDRESS);
        println!(
            "Type 4 preview amount={} wallet_fee={:.6} network_fee={:.6}",
            amount, preflight.service_fee_mei, preflight.fee_mei
        );
        if std::env::var("HACASH_TEST_DRY_RUN").as_deref() == Ok("1") {
            println!("Type 4 dry-run preflight verified");
            return;
        }

        let keystore_pass =
            std::env::var("HACASH_DEV_KS_PASS").expect("HACASH_DEV_KS_PASS is required");
        let sent = svc
            .quantum_send_type4(&legacy, &amount, &keystore_pass)
            .await
            .expect("Type 4 testnet send");
        println!(
            "Submitted Type 4 hash={} sign_alg={}",
            sent.hash, sent.sign_alg
        );

        let client = reqwest::Client::new();
        let query_url = format!(
            "{}/query/transaction?hash={}&action=true&unit=mei",
            normalized, sent.hash
        );
        let mut tx = None;
        for _ in 0..40 {
            if let Ok(response) = client.get(&query_url).send().await
                && let Ok(body) = response.json::<serde_json::Value>().await
                && body.get("ret").and_then(|v| v.as_i64()) == Some(0)
            {
                tx = Some(body);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let tx = tx.expect("Type 4 transaction not found in local testnet node");
        assert_eq!(tx.get("type").and_then(|v| v.as_u64()), Some(4));
        let actions = tx
            .get("actions")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
            .to_string();
        assert!(actions.contains(&legacy), "Type 4 recipient action missing");
        assert!(
            actions.contains(WALLET_TREASURY_ADDRESS),
            "Type 4 treasury action missing"
        );
        println!("Verified Type 4 recipient and treasury actions");
    });
}
