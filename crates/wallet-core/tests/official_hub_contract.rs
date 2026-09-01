use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::get;
use axum::{Json, Router};
use hacash_wallet_core::l2_hub::L2HubClient;
use l2_fast_pay_hub::{HubState, build_router};
use serde_json::json;
use sys::Account;

#[tokio::test]
async fn wallet_rejects_unproven_mainnet_hub_and_testnet_skips_mainnet_gate() {
    let capability_calls = Arc::new(AtomicUsize::new(0));
    let node = Router::new().route(
        "/query/capabilities",
        get({
            let capability_calls = capability_calls.clone();
            move || {
                let capability_calls = capability_calls.clone();
                async move {
                    capability_calls.fetch_add(1, Ordering::SeqCst);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    Json(json!({
                        "ret": 0,
                        "api_version": 1,
                        "chain": {
                            "id": 0,
                            "height": 900000,
                            "next_height": 900001,
                            "mainnet": true
                        },
                        "network": {
                            "kind": "mainnet",
                            "block_1_hash": "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
                            "instance_id": "33".repeat(32)
                        },
                        "sync": {
                            "tip_timestamp_unix": now,
                            "max_tip_age_seconds": 3600,
                            "fresh": true
                        },
                        "actions": {
                            "registered": [1, 2, 3],
                            "enabled": [1, 2, 3]
                        }
                    }))
                }
            }
        }),
    );
    let node_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_address = node_listener.local_addr().unwrap();
    let node_task = tokio::spawn(async move {
        axum::serve(node_listener, node).await.unwrap();
    });

    let account = Account::create_by("official-hub-wallet-contract").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let hub = Arc::new(
        HubState::new_secure_with_policy(
            "official contract hub",
            account.readable(),
            format!("http://{node_address}"),
            None,
            directory.path().join("state.json"),
            hex::encode(account.secret_key().serialize()),
            &"62".repeat(32),
            &"63".repeat(32),
            "mainnet-pilot",
            1_000_000,
            500_000,
        )
        .unwrap(),
    );
    let hub_app = build_router(hub);
    let hub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_address = hub_listener.local_addr().unwrap();
    let hub_task = tokio::spawn(async move {
        axum::serve(hub_listener, hub_app).await.unwrap();
    });
    let base = format!("http://{hub_address}");

    let testnet = L2HubClient::new_for_network(&base, "testnet");
    assert!(testnet.health().await.unwrap().settlement_ready);
    assert_eq!(capability_calls.load(Ordering::SeqCst), 0);

    let mainnet = L2HubClient::new_for_network(base, "mainnet");
    let readiness = mainnet.mainnet_readiness().await.unwrap();
    assert!(!readiness.payments_enabled);
    assert_eq!(readiness.max_payment_hac_zhu, 1_000_000);
    assert_eq!(readiness.max_channel_funding_hac_zhu, 500_000);
    assert_eq!(readiness.wallet_fee_hac, "0");
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "external_monotonic_rollback_anchor_is_not_ready")
    );
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "unilateral_l1_dispute_path_is_not_ready")
    );
    let error = mainnet
        .require_mainnet_payment_ready(Some("0.5"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not green"), "{error}");
    assert_eq!(
        capability_calls.load(Ordering::SeqCst),
        1,
        "the short readiness cache must avoid a second node capability probe"
    );

    hub_task.abort();
    node_task.abort();
}
