//! The Hub's mainnet-grade readiness flags must be measurements, not
//! assertions.
//!
//! Every flag here has to read `false` whenever the thing it names is absent,
//! and may read `true` only when that thing is actually present and verified.
//! A flag that is hardcoded `true` is the worst failure available on this
//! path; a flag that is hardcoded `false` is merely useless, because it can
//! never distinguish a real guarantee from a missing one. Both are tested.

use axum::routing::get;
use axum::{Json, Router};
use l2_fast_pay_hub::HubState;
use serde_json::{Value, json};
use sys::Account;
use tokio::task::JoinHandle;

const REVIEWED_BYTECODE_SHA3: &str =
    "11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349";
/// A real HVM contract address, so `ContractAddress::from_addr` accepts it and
/// the evidence validator is exercised rather than short-circuited.
const CONTRACT_ADDRESS: &str = "ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw";
const DEPLOYMENT_TX_HASH: &str = "6a369078f214f7c6f270a732dcb5ba4c53034906d33865b4a50a83819c0714a2";
/// Above `HACASH_MAINNET_MIN_SAFE_HEIGHT` (765_432), which the evidence
/// validator requires of any deployment claiming to be verified.
const DEPLOYMENT_HEIGHT: u64 = 800_000;
const OBSERVED_HEIGHT: u64 = 900_000;

fn test_account(seed: &str) -> Account {
    Account::create_by(seed).unwrap()
}

/// Evidence describing a genuinely verified mainnet deployment of the reviewed
/// exit contract. Shaped to satisfy `ChannelUnilateralExitEvidence::
/// validate_candidate`, which the node client runs at parse time.
fn verified_exit_evidence() -> Value {
    json!({
        "schema": "hpay-hvm-channel-exit-evidence/1",
        "manifest_valid": true,
        "contract_name": "HPAYChannelExitV1",
        "protocol_domain": "HPAY/HVM-CHANNEL/V1",
        "settlement_profile": "hpay-hvm-channel-v1",
        "source_sha256": "c0a430eb9769d1d506641c379bb8aaf708c7bac7d03694b60a4be03fd001dd06",
        "bytecode_sha3": REVIEWED_BYTECODE_SHA3,
        "required_action_kinds": [40, 41, 44],
        "funding_model": {
            "left_deposit": "positive",
            "right_hub_deposit": "exactly_zero"
        },
        "storage_key_count": 18,
        "must_renew_every_storage_key": true,
        "deployment": {
            "enabled": true,
            "contract_address": CONTRACT_ADDRESS,
            "deployment_tx_hash": DEPLOYMENT_TX_HASH,
            "deployment_height": DEPLOYMENT_HEIGHT,
            "independently_verified": true
        },
        "on_chain_verification": {
            "observed_height": OBSERVED_HEIGHT,
            "confirmed_tx_height": DEPLOYMENT_HEIGHT,
            "deployment_tx_confirmed": true,
            "contract_code_sha3": REVIEWED_BYTECODE_SHA3,
            "contract_code_matches": true
        },
        "deployment_verified": true
    })
}

/// The evidence the Local Pilot fullnode actually serves today: the reviewed
/// artifact is known, but nothing is deployed and verified on mainnet.
fn unverified_exit_evidence() -> Value {
    json!({
        "schema": "hpay-hvm-channel-exit-evidence/1",
        "manifest_valid": true,
        "contract_name": "HPAYChannelExitV1",
        "protocol_domain": "HPAY/HVM-CHANNEL/V1",
        "settlement_profile": "hpay-hvm-channel-v1",
        "source_sha256": "c0a430eb9769d1d506641c379bb8aaf708c7bac7d03694b60a4be03fd001dd06",
        "bytecode_sha3": REVIEWED_BYTECODE_SHA3,
        "required_action_kinds": [40, 41, 44],
        "funding_model": {
            "left_deposit": "positive",
            "right_hub_deposit": "exactly_zero"
        },
        "storage_key_count": 18,
        "must_renew_every_storage_key": true,
        "deployment": {
            "enabled": false,
            "contract_address": null,
            "deployment_tx_hash": null,
            "deployment_height": null,
            "independently_verified": false
        },
        "on_chain_verification": {
            "observed_height": null,
            "confirmed_tx_height": null,
            "deployment_tx_confirmed": false,
            "contract_code_sha3": null,
            "contract_code_matches": false
        },
        "deployment_verified": false
    })
}

/// A mainnet fullnode that either does or does not report a verified native
/// unilateral-exit capability.
async fn spawn_node(exit_supported: bool) -> (String, JoinHandle<()>) {
    let features = if exit_supported {
        json!({
            "channel_unilateral_exit": true,
            "channel_unilateral_exit_evidence": verified_exit_evidence(),
        })
    } else {
        json!({
            "channel_unilateral_exit": false,
            "channel_unilateral_exit_evidence": unverified_exit_evidence(),
        })
    };
    let app = Router::new().route(
        "/query/capabilities",
        get(move || {
            let features = features.clone();
            async move {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(json!({
                    "ret": 0,
                    "api_version": 1,
                    "api": {
                        "transaction_submit_bound": true,
                        "hpay_channel_registry_query": true
                    },
                    "chain": {
                        "id": 0,
                        "height": OBSERVED_HEIGHT,
                        "next_height": OBSERVED_HEIGHT + 1,
                        "mainnet": true
                    },
                    "network": {
                        "kind": "mainnet",
                        "node_profile_id": "hacash-mainnet",
                        "block_1_hash":
                            "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
                        "instance_id": "11".repeat(32),
                        "transaction_format_version": 2
                    },
                    "sync": {
                        "tip_timestamp_unix": now,
                        "observed_unix": now,
                        "tip_age_seconds": 0,
                        "max_tip_age_seconds": 3600,
                        "fresh": true
                    },
                    "actions": {
                        "registered": [1, 2, 3, 14, 1041],
                        "enabled": [1, 2, 3, 14, 1041]
                    },
                    "transactions": {"registered": [2], "enabled": [2]},
                    "features": features
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn build_hub(node_url: &str, seed: &str) -> HubState {
    let account = test_account(seed);
    HubState::new(
        "honest-flags",
        account.readable().to_owned(),
        node_url,
        None,
        0,
        Some(hex::encode(account.secret_key().serialize())),
    )
    .unwrap()
}

/// The subject is present: the node reports a verified mainnet deployment of
/// the reviewed exit contract. The dispute-path flag must say so.
#[tokio::test]
async fn l1_dispute_path_flag_is_true_only_when_the_node_proves_a_verified_exit() {
    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "dispute-present-hub");

    let health = hub.health().await;
    assert!(
        health.l1_dispute_path_ready,
        "the node reports a verified unilateral-exit deployment, so the flag must be true"
    );

    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness.unilateral_l1_enforceable,
        "unilateral_l1_enforceable must track the measured dispute path"
    );
    assert!(
        !readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "unilateral_l1_dispute_path_is_not_ready"),
        "a verified exit path must clear its own blocker, got {:?}",
        readiness.blockers
    );
    server.abort();
}

/// The subject is absent: the node reports no verified deployment. The flag
/// must read false, and it must keep reading false everywhere it is mirrored.
#[tokio::test]
async fn l1_dispute_path_flag_is_false_when_the_node_reports_no_verified_exit() {
    let (node_url, server) = spawn_node(false).await;
    let hub = build_hub(&node_url, "dispute-absent-hub");

    let health = hub.health().await;
    assert!(
        !health.l1_dispute_path_ready,
        "no verified deployment is present, so the flag must be false"
    );

    let readiness = hub.mainnet_readiness().await;
    assert!(!readiness.unilateral_l1_enforceable);
    assert!(!readiness.trustless_finality);
    server.abort();
}

/// The Hub has no external monotonic rollback anchor. The flag must therefore
/// be false even on a node that satisfies every other mainnet condition, and
/// the blocker must remain listed.
#[tokio::test]
async fn external_rollback_anchor_flag_is_false_because_no_anchor_exists() {
    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "anchor-absent-hub");

    let health = hub.health().await;
    assert!(
        !health.external_rollback_anchor_ready,
        "no external anchor subsystem exists, so this must never read true"
    );

    let readiness = hub.mainnet_readiness().await;
    assert!(
        !readiness.trustless_finality,
        "trustless finality requires the anchor, which is absent"
    );
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "external_monotonic_rollback_anchor_is_not_ready"),
        "the missing anchor must stay a listed blocker, got {:?}",
        readiness.blockers
    );
    server.abort();
}

/// `production_mainnet_ready` is the strongest claim the Hub makes. It must be
/// false while any of its parts is missing, and the anchor is missing.
#[tokio::test]
async fn production_mainnet_ready_is_false_while_any_part_is_missing() {
    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "production-hub");
    assert!(
        !hub.health().await.production_mainnet_ready,
        "the anchor is absent and the profile is not mainnet-pilot, so this must be false"
    );
    server.abort();

    let (node_url, server) = spawn_node(false).await;
    let hub = build_hub(&node_url, "production-hub-2");
    assert!(!hub.health().await.production_mainnet_ready);
    server.abort();
}

/// A flag must not survive the loss of its evidence. When the node is
/// unreachable the Hub knows nothing, so every measured guarantee reads false.
#[tokio::test]
async fn measured_flags_fail_closed_when_the_node_is_unreachable() {
    let hub = build_hub("http://127.0.0.1:1", "unreachable-hub");
    let health = hub.health().await;
    assert!(!health.l1_dispute_path_ready);
    assert!(!health.external_rollback_anchor_ready);
    assert!(!health.production_mainnet_ready);
}
