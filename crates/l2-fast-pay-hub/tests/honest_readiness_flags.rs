//! The Hub's mainnet-grade readiness flags must be measurements, not
//! assertions.
//!
//! Every flag here has to read `false` whenever the thing it names is absent,
//! and may read `true` only when that thing is actually present and verified.
//! A flag that is hardcoded `true` is the worst failure available on this
//! path; a flag that is hardcoded `false` is merely useless, because it can
//! never distinguish a real guarantee from a missing one. Both are tested.
//!
//! # Which endpoint proves which half
//!
//! The measurement lives on `mainnet_readiness()` (`/v1/readiness/mainnet`),
//! because that is the endpoint that pays for the evidence: it probes the
//! fullnode and runs `HubHardGuarantees::measure` over what comes back. So the
//! discriminating half of every capability-dependent flag - the half that must
//! read `true` exactly when the subject is present - is asserted there.
//!
//! `health()` (`/v1/health`) is a cheap liveness endpoint and performs no node
//! I/O at all, so it has no evidence to weigh and therefore carries no
//! capability-dependent flag whatsoever. It used to carry them, reported
//! conservatively as `false`; that was removed, because a flag that is
//! structurally always `false` cannot distinguish "no evidence here" from
//! "proven absent", and any gate reading one could never open even after the
//! guarantee arrived. Their absence is now a type-level fact, and
//! `health_carries_no_guarantee_flag_while_readiness_measures` pins both halves
//! at once on one Hub: the liveness payload publishes no guarantee key and
//! probes nothing, while the authority probes and reports the measured truth.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// The reviewed **shared registry V2** artifact — the settlement profile this
/// system actually uses, and therefore the one the dispute-path gate measures.
const REVIEWED_REGISTRY_BYTECODE_SHA3: &str =
    "2fa7429d9e686dd2457eeb1b4476f972c7ddd9be6a0371c9765eff2910209b04";
const REVIEWED_REGISTRY_SOURCE_SHA256: &str =
    "37fabe6b8ab54431864715530c0f16c89fed3b609c23c227e592cec24e2ab8b5";
/// The network instance id this fake node publishes for itself. The registry's
/// constructor argument has to be exactly this, or the deployment belongs to
/// another chain.
const NETWORK_INSTANCE_ID: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const REGISTRY_CONTRACT_ADDRESS: &str = "ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw";
const REGISTRY_DEPLOYMENT_TX_HASH: &str =
    "9f2c1d5e4b7a03682d9c4f1a8e6b0d37c25a9418f0e73b6c4d81a2953f6e07bd";
/// The Hub's deploying signer, re-derived by the node from the deploying
/// transaction's own main address.
const REGISTRY_HUB_ADDRESS: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";

/// Everything about the reviewed registry artifact that does not depend on
/// whether it is deployed.
fn registry_evidence_artifact() -> Value {
    json!({
        "schema": "hpay-hvm-channel-registry-exit-evidence/2",
        "manifest_valid": true,
        "contract_name": "HPAYChannelRegistryV2",
        "protocol_domain": "HPAY/HVM-CHANNEL-REGISTRY/V2",
        "settlement_profile": "hpay-hvm-shared-registry-v2",
        "source_sha256": REVIEWED_REGISTRY_SOURCE_SHA256,
        "bytecode_sha3": REVIEWED_REGISTRY_BYTECODE_SHA3,
        "required_action_kinds": [40, 41, 44],
        "channel_model": {
            "left_deposit": "positive",
            "right_hub_deposit": "exactly_zero",
            "maximum_active_channels_per_left_address": 1,
            "first_reuse": 0
        },
        "registry_key_count": 6,
        "channel_key_count": 12,
        "must_renew_every_registry_key": true,
        "must_renew_every_channel_key": true,
        "maximum_renewal_step_periods": 150
    })
}

fn with_registry_artifact(extra: Value) -> Value {
    let mut evidence = registry_evidence_artifact();
    let object = evidence.as_object_mut().expect("evidence is an object");
    for (key, value) in extra.as_object().expect("extra is an object") {
        object.insert(key.clone(), value.clone());
    }
    evidence
}

/// Evidence describing a genuinely verified mainnet deployment of the reviewed
/// registry contract, including both V2-only bindings: the deploying
/// transaction really deployed this artifact, and its constructor argument is
/// this node's own network instance.
fn verified_registry_evidence() -> Value {
    with_registry_artifact(json!({
        "deployment": {
            "enabled": true,
            "contract_address": REGISTRY_CONTRACT_ADDRESS,
            "deployment_tx_hash": REGISTRY_DEPLOYMENT_TX_HASH,
            "deployment_height": DEPLOYMENT_HEIGHT,
            "independently_verified": true,
            "external_audit_complete": false
        },
        "on_chain_verification": {
            "observed_height": OBSERVED_HEIGHT,
            "confirmed_tx_height": DEPLOYMENT_HEIGHT,
            "deployment_tx_confirmed": true,
            "contract_code_sha3": REVIEWED_REGISTRY_BYTECODE_SHA3,
            "contract_code_matches": true,
            "deployment_action_verified": true,
            "hub_address": REGISTRY_HUB_ADDRESS,
            "constructor_network_instance_id": NETWORK_INSTANCE_ID,
            "node_network_instance_id": NETWORK_INSTANCE_ID,
            "network_binding_matches": true
        },
        "deployment_verified": true
    }))
}

/// The evidence the real fullnode serves today: the reviewed registry artifact
/// is known exactly, and nothing is deployed on Hacash mainnet.
fn unverified_registry_evidence() -> Value {
    with_registry_artifact(json!({
        "deployment": {
            "enabled": false,
            "contract_address": null,
            "deployment_tx_hash": null,
            "deployment_height": null,
            "independently_verified": false,
            "external_audit_complete": false
        },
        "on_chain_verification": {
            "observed_height": null,
            "confirmed_tx_height": null,
            "deployment_tx_confirmed": false,
            "contract_code_sha3": null,
            "contract_code_matches": false,
            "deployment_action_verified": false,
            "hub_address": null,
            "constructor_network_instance_id": null,
            "node_network_instance_id": null,
            "network_binding_matches": false
        },
        "deployment_verified": false
    }))
}

/// A mainnet fullnode that either does or does not report a verified native
/// unilateral-exit capability.
async fn spawn_node(exit_supported: bool) -> (String, JoinHandle<()>) {
    let (url, handle, _probes) = spawn_counting_node(exit_supported).await;
    (url, handle)
}

/// A mainnet fullnode with an arbitrary `features` object, for the cases where
/// the two settlement profiles must be told apart.
async fn spawn_node_with_features(features: Value) -> (String, JoinHandle<()>) {
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
                        "instance_id": NETWORK_INSTANCE_ID,
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

/// The regression test for the wrong-contract gate.
///
/// A node that has a fully verified mainnet deployment of the **V1
/// per-channel** contract, and nothing at all for the shared registry, must
/// leave the dispute-path measurement `false`. It was not false before: the
/// gate read `ChannelUnilateralExitEvidence`, which is bound to
/// `hpay-hvm-channel-v1`, while every channel this system opens, funds, bills
/// and exits lives in `hpay-hvm-shared-registry-v2`.
///
/// The mirror case is the point of the whole change: a node that publishes
/// only the registry profile, and has dropped V1 entirely, *does* satisfy the
/// node half. That is the deployment the owner was about to pay for.
#[tokio::test]
async fn the_v1_channel_profile_alone_never_opens_the_gate() {
    let (node_url, server) = spawn_node_with_features(json!({
        "channel_unilateral_exit": true,
        "channel_unilateral_exit_evidence": verified_exit_evidence(),
        "channel_registry_unilateral_exit": false,
        "channel_registry_unilateral_exit_evidence": unverified_registry_evidence(),
    }))
    .await;
    let hub = build_hub(&node_url, "v1-only-hub");
    let readiness = hub.mainnet_readiness().await;
    let capabilities = readiness
        .fullnode_capabilities
        .as_ref()
        .expect("the node answered, so its capabilities parsed");
    assert!(
        capabilities.channel_unilateral_exit,
        "the V1 half is deliberately fully verified in this fixture"
    );
    assert!(
        !l2_fast_pay_hub::readiness::measure_node_reported_unilateral_exit(Some(capabilities)),
        "a verified V1 per-channel deployment is not evidence about the registry \
         profile this system settles on"
    );
    assert!(!readiness.unilateral_l1_enforceable);
    assert!(!readiness.trustless_finality);
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "unilateral_l1_dispute_path_is_not_ready"),
        "the document must still name the missing dispute path, got {:?}",
        readiness.blockers
    );
    server.abort();

    let (node_url, server) = spawn_node_with_features(json!({
        "channel_registry_unilateral_exit": true,
        "channel_registry_unilateral_exit_evidence": verified_registry_evidence(),
    }))
    .await;
    let hub = build_hub(&node_url, "registry-only-hub");
    let capabilities = hub.mainnet_readiness().await.fullnode_capabilities;
    assert!(
        l2_fast_pay_hub::readiness::measure_node_reported_unilateral_exit(capabilities.as_ref()),
        "a node that publishes only the registry profile still answers for the \
         contract this system actually uses"
    );
    server.abort();
}

/// A registry deployed for some other chain must never be presented to this
/// one as its own, and the Hub must not take the node's word for which chain
/// it is on.
#[tokio::test]
async fn a_registry_constructed_for_another_network_is_refused_at_parse_time() {
    let mut foreign = verified_registry_evidence();
    foreign["on_chain_verification"]["constructor_network_instance_id"] =
        Value::from("22".repeat(32));
    foreign["on_chain_verification"]["node_network_instance_id"] = Value::from("22".repeat(32));
    let (node_url, server) = spawn_node_with_features(json!({
        "channel_registry_unilateral_exit": true,
        "channel_registry_unilateral_exit_evidence": foreign,
    }))
    .await;
    let hub = build_hub(&node_url, "foreign-registry-hub");
    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness.fullnode_capabilities.is_none(),
        "evidence that disagrees with the node's own network identity must not parse"
    );
    assert!(!readiness.unilateral_l1_enforceable);
    server.abort();
}

/// The same fullnode, plus a counter of how many capability probes it has been
/// asked to serve. Any endpoint that claims to do no node I/O can be held to it.
async fn spawn_counting_node(exit_supported: bool) -> (String, JoinHandle<()>, Arc<AtomicUsize>) {
    let probes = Arc::new(AtomicUsize::new(0));
    // Both settlement profiles move together in this fixture, so that
    // `exit_supported` still means "the node proves an exit". They are
    // separate keys about separate contracts, and the gate reads only V2 -
    // `the_v1_channel_profile_alone_never_opens_the_gate` below is the test
    // that holds them apart.
    let features = if exit_supported {
        json!({
            "channel_unilateral_exit": true,
            "channel_unilateral_exit_evidence": verified_exit_evidence(),
            "channel_registry_unilateral_exit": true,
            "channel_registry_unilateral_exit_evidence": verified_registry_evidence(),
        })
    } else {
        json!({
            "channel_unilateral_exit": false,
            "channel_unilateral_exit_evidence": unverified_exit_evidence(),
            "channel_registry_unilateral_exit": false,
            "channel_registry_unilateral_exit_evidence": unverified_registry_evidence(),
        })
    };
    let app = Router::new().route(
        "/query/capabilities",
        get({
            let probes = probes.clone();
            move || {
                let features = features.clone();
                let probes = probes.clone();
                async move {
                    probes.fetch_add(1, Ordering::SeqCst);
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
                            "instance_id": NETWORK_INSTANCE_ID,
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
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle, probes)
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
///
/// This is asserted on `mainnet_readiness()` because that is where the
/// measurement happens. `readiness.unilateral_l1_enforceable` is not a
/// paraphrase of the dispute-path flag, it *is* that flag: `mainnet_readiness`
/// probes the node, calls `HubHardGuarantees::measure`, and hands
/// `guarantees.l1_dispute_path_ready` straight to `MainnetReadinessV1::
/// evaluate`, which publishes it verbatim as `unilateral_l1_enforceable`. Same
/// probe, same `measure` call, same boolean - read off the endpoint that owns
/// it instead of the one that has no evidence to read.
#[tokio::test]
async fn l1_dispute_path_flag_is_true_only_when_the_node_proves_a_verified_exit() {
    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "dispute-present-hub");

    let readiness = hub.mainnet_readiness().await;
    // The node's half of the evidence is present and is measured as present.
    assert!(
        l2_fast_pay_hub::readiness::measure_node_reported_unilateral_exit(
            readiness.fullnode_capabilities.as_ref()
        ),
        "the node reports a verified unilateral-exit deployment, so the node \
         half of the measurement must be true"
    );
    // And it is still not a guarantee. A node describing a deployed contract
    // is evidence about a node; the guarantee is about a user, and no wallet
    // in this workspace can build a challenge, respond, finalize or claim
    // transaction. Publishing `true` here would tell wallets they hold a claim
    // on chain when what they hold is a promise from this Hub, which is the
    // one outcome this project ranks worse than never going green at all.
    assert!(
        !readiness.unilateral_l1_enforceable,
        "a node's report about itself must never be enough to publish the \
         guarantee, got {:?}",
        readiness.blockers
    );
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "no_watcher_answers_for_an_offline_owner"),
        "and the document must say which half is missing, got {:?}",
        readiness.blockers
    );
    server.abort();
}

/// The subject is absent: the node reports no verified deployment. The
/// measured flag must read false on the authority that saw the evidence and
/// still said no.
#[tokio::test]
async fn l1_dispute_path_flag_is_false_when_the_node_reports_no_verified_exit() {
    let (node_url, server) = spawn_node(false).await;
    let hub = build_hub(&node_url, "dispute-absent-hub");

    let readiness = hub.mainnet_readiness().await;
    assert!(!readiness.unilateral_l1_enforceable);
    assert!(!readiness.trustless_finality);
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "unilateral_l1_dispute_path_is_not_ready"),
        "an unverified exit path must raise its own blocker, got {:?}",
        readiness.blockers
    );
    server.abort();
}

/// The two endpoints have different jobs, and only one of them may publish a
/// guarantee.
///
/// One Hub, one node that genuinely proves a verified unilateral exit:
///
/// * `health()` must publish no capability-dependent flag at all and must not
///   probe the node even once. That is property A - `/v1/health` is a cheap
///   liveness endpoint and must never make the Hub reach for the mainnet gate
///   on a caller's behalf, whatever network the caller is on. It is checked
///   against the serialized payload, so a flag cannot creep back in under a
///   different name and be read by a client.
/// * `mainnet_readiness()` must be the endpoint that probes and then reports
///   whatever the evidence actually supports. That is property B. Here it
///   reports `false`: the node's half holds, and the user-side half - a wallet
///   that can build the exit transaction - does not exist.
///
/// A guarantee flag on the liveness payload could only ever be an unmeasured
/// constant. When it read `false` it bricked every gate that trusted it; were
/// it ever to read `true` it would be an assertion backed by nothing. The only
/// safe number of guarantee flags on this endpoint is zero.
#[tokio::test]
async fn health_carries_no_guarantee_flag_while_readiness_measures() {
    let (node_url, server, probes) = spawn_counting_node(true).await;
    let hub = build_hub(&node_url, "under-report-hub");

    let health = hub.health();
    assert_eq!(
        probes.load(Ordering::SeqCst),
        0,
        "health() must perform no node I/O"
    );
    let payload = serde_json::to_value(&health).unwrap();
    let keys = payload.as_object().unwrap();
    for guarantee in [
        "external_rollback_anchor_ready",
        "l1_dispute_path_ready",
        "production_mainnet_ready",
        "trustless_finality",
        "unilateral_l1_enforceable",
    ] {
        assert!(
            !keys.contains_key(guarantee),
            "/v1/health must publish no capability-dependent guarantee, found {guarantee} in \
             {payload}"
        );
    }

    let readiness = hub.mainnet_readiness().await;
    assert_eq!(
        probes.load(Ordering::SeqCst),
        1,
        "mainnet_readiness() is the endpoint that pays for the evidence"
    );
    // The subject of this test is which endpoint pays for the evidence, not
    // what the evidence says. It reports the measured truth either way, and
    // the measured truth is that the user-side exit does not exist.
    assert!(
        !readiness.unilateral_l1_enforceable,
        "the authority for the guarantee must report the measured truth"
    );
    server.abort();
}

/// No witness is configured on this Hub. The flag must therefore be false even
/// on a node that satisfies every other mainnet condition, and the blocker
/// must remain listed.
///
/// This is the half that was already true before the anchor existed and must
/// stay true now that it does: a Hub with no witness has no anchor, whatever
/// else is in the build.
#[tokio::test]
async fn external_rollback_anchor_flag_is_false_because_no_anchor_exists() {
    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "anchor-absent-hub");

    assert!(
        !l2_fast_pay_hub::readiness::measure_external_rollback_anchor_ready(None, now_unix()),
        "with no witness configured there is no evidence, so this must never read true"
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The three directions the anchor flag has to be able to point, proven on the
/// endpoint that owns the measurement.
///
/// A flag that can only read one way is not a measurement, and a flag that
/// reads `true` because a URL was configured is worse than no flag at all.
#[cfg(feature = "rollback-witness")]
mod anchor {
    use super::{build_hub, now_unix, spawn_node};
    use l2_fast_pay_hub::HubState;
    use l2_fast_pay_hub::rollback_anchor::witness::{WitnessService, WitnessServiceConfig, router};
    use l2_fast_pay_hub::rollback_anchor::{RollbackAnchorConfig, WitnessPosture};
    use std::sync::Arc;
    use std::time::Duration;
    use sys::Account;
    use tokio::task::JoinHandle;

    const ANCHOR_BLOCKER: &str = "external_monotonic_rollback_anchor_is_not_ready";

    struct Witness {
        url: String,
        service: Arc<WitnessService>,
        authorisation: Account,
        handle: JoinHandle<()>,
        #[allow(dead_code)]
        store: tempfile::TempDir,
    }

    async fn spawn_witness(seed: &str) -> Witness {
        let store = tempfile::tempdir().unwrap();
        let service = Arc::new(
            WitnessService::open(
                WitnessServiceConfig {
                    witness_id: format!("witness-{seed}"),
                    witness_epoch: 1,
                    store_path: store.path().join("witness-log.jsonl"),
                    receipt_account: Account::create_by(&format!("{seed}-receipt")).unwrap(),
                },
                now_unix(),
            )
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = service.clone();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router(served)).await;
        });
        Witness {
            url: format!("http://{address}"),
            service,
            authorisation: Account::create_by(&format!("{seed}-offline")).unwrap(),
            handle,
            store,
        }
    }

    fn config(witness: &Witness, hub_identity: &str, url: &str) -> RollbackAnchorConfig {
        RollbackAnchorConfig {
            witness_url: url.to_owned(),
            witness_id: witness.service.witness_id().to_owned(),
            witness_epoch: witness.service.witness_epoch(),
            witness_receipt_address: witness.service.receipt_address().to_owned(),
            witness_authorisation_address: witness.authorisation.readable().to_owned(),
            attestation: witness
                .service
                .issue_attestation(
                    &witness.authorisation,
                    hub_identity,
                    WitnessPosture::NeutralThirdParty,
                    "Example Neutral Witness Co",
                    "separate operator, separate hosting, separate backup set",
                    now_unix(),
                    30 * 86_400,
                )
                .unwrap(),
            request_timeout: Duration::from_secs(5),
        }
    }

    fn with_anchor(hub: HubState, witness: &Witness, url: &str) -> HubState {
        let identity = hub.hub_address.clone();
        hub.with_rollback_anchor(config(witness, &identity, url))
            .unwrap()
    }

    /// The anchor's strength depends on **who** runs the witness and **where**
    /// it sits, and neither of those is a boolean the flag can carry.
    ///
    /// Before this test existed the readiness document contained no key
    /// matching `witness` or `anchor` at all: the only outward sign that an
    /// anchor existed was the *absence* of a blocker string. A same-operator,
    /// loopback, single-host witness was therefore indistinguishable over the
    /// API from a neutral third party on separate infrastructure, which
    /// contradicts `ROLLBACK-ANCHOR-PROTOCOL.md` section 10 and the doc comment
    /// on `measure_external_rollback_anchor_ready`.
    ///
    /// Asserted against the serialized payload, because the payload is what a
    /// wallet reads. A field that exists in Rust and never reaches the wire is
    /// the bug this test is here to stop coming back.
    #[tokio::test]
    async fn the_readiness_document_publishes_who_witnesses_this_hub_and_where_it_sits() {
        let (node_url, server) = spawn_node(true).await;
        let witness = spawn_witness("published-posture").await;
        let url = witness.url.clone();
        let hub = with_anchor(build_hub(&node_url, "anchor-posture-hub"), &witness, &url);
        hub.run_rollback_anchor_startup_probe().await.unwrap();

        let readiness = hub.mainnet_readiness().await;
        let payload = serde_json::to_value(&readiness).unwrap();
        let anchor = payload
            .get("rollback_anchor")
            .and_then(serde_json::Value::as_object)
            .expect("the readiness document must publish the anchor it measured, got {payload}");

        assert_eq!(
            anchor.get("witness_posture").and_then(|it| it.as_str()),
            Some("neutral_third_party"),
            "a wallet must be able to read who holds the witness key"
        );
        assert_eq!(
            anchor.get("witness_operator").and_then(|it| it.as_str()),
            Some("Example Neutral Witness Co"),
            "the attested operating entity travels with the posture"
        );
        assert_eq!(
            anchor
                .get("witness_endpoint_is_local")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "this witness is on loopback and that must be published, not hidden"
        );
        assert_eq!(
            anchor
                .get("witness_co_located")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "a loopback witness shares this Hub's host, which is the verdict a \
             person choosing a hub actually needs"
        );
        assert!(
            readiness
                .limitations
                .iter()
                .any(|limitation| limitation.contains("co-located")),
            "a witness inside this Hub's own failure domain must be stated in \
             plain words too, got {:?}",
            readiness.limitations
        );

        // And the same document says so honestly when there is nothing to say.
        let bare = build_hub(&node_url, "anchor-posture-bare")
            .mainnet_readiness()
            .await;
        assert!(
            serde_json::to_value(&bare)
                .unwrap()
                .get("rollback_anchor")
                .is_some_and(serde_json::Value::is_null),
            "no witness must publish as an explicit null rather than as silence"
        );

        server.abort();
        witness.handle.abort();
    }

    /// A witness is configured, pinned, and attested - and it is not there.
    /// Configuration is not evidence, so the flag must read false.
    #[tokio::test]
    async fn external_rollback_anchor_flag_is_false_when_the_configured_witness_is_unreachable() {
        let (node_url, server) = spawn_node(true).await;
        let witness = spawn_witness("unreachable-flag").await;
        let hub = with_anchor(
            build_hub(&node_url, "anchor-unreachable-hub"),
            &witness,
            "http://127.0.0.1:1",
        );
        assert!(hub.rollback_anchor_configured());

        assert!(
            hub.run_rollback_anchor_startup_probe().await.is_err(),
            "an unreachable witness must refuse the startup probe"
        );
        assert!(
            hub.rollback_anchor_evidence().await.is_none(),
            "an unreachable witness produces no evidence"
        );
        let readiness = hub.mainnet_readiness().await;
        assert!(
            !readiness.trustless_finality,
            "a configured but unreachable witness must not hold the flag true"
        );
        assert!(
            readiness.blockers.iter().any(|it| it == ANCHOR_BLOCKER),
            "got {:?}",
            readiness.blockers
        );
        server.abort();
        witness.handle.abort();
    }

    /// A live witness, pinned keys, a valid unexpired attestation, a startup
    /// probe that agreed, and a signed answer inside the freshness window.
    /// Now, and only now, the flag reads true.
    #[tokio::test]
    async fn external_rollback_anchor_flag_is_true_with_a_live_witness_returning_valid_receipts() {
        let (node_url, server) = spawn_node(true).await;
        let witness = spawn_witness("live-flag").await;
        let url = witness.url.clone();
        let hub = with_anchor(build_hub(&node_url, "anchor-live-hub"), &witness, &url);

        hub.run_rollback_anchor_startup_probe()
            .await
            .expect("a live witness must agree with a Hub that has signed nothing");

        let evidence = hub
            .rollback_anchor_evidence()
            .await
            .expect("a live witness must produce verified evidence");
        assert!(
            l2_fast_pay_hub::readiness::measure_external_rollback_anchor_ready(
                Some(&evidence),
                now_unix()
            ),
            "a live, pinned, attested witness inside the freshness window must read true"
        );
        assert_eq!(evidence.witness_posture, "neutral_third_party");
        assert_eq!(evidence.witness_operator, "Example Neutral Witness Co");
        assert!(
            evidence.witness_endpoint_is_local,
            "this witness is on loopback, and that must be published rather than hidden"
        );

        let readiness = hub.mainnet_readiness().await;
        assert!(
            !readiness.blockers.iter().any(|it| it == ANCHOR_BLOCKER),
            "a live witness must clear the anchor blocker, got {:?}",
            readiness.blockers
        );
        // `trustless_finality` is `external_rollback_anchor_ready &&
        // l1_dispute_path_ready`. The anchor half is now genuinely true - that
        // is this test's subject and it is proved above. The composite stays
        // false on the other half, because no user can build a unilateral exit
        // transaction, and a Hub must not claim trustless finality while the
        // only way out of a channel runs through the Hub.
        assert!(
            !readiness.trustless_finality,
            "a live anchor is one half; the exit the user drives ships now, and finality still needs \
             somebody answering while they sleep, got {:?}",
            readiness.blockers
        );
        assert!(
            readiness
                .blockers
                .iter()
                .any(|it| it == "no_watcher_answers_for_an_offline_owner"),
            "and the document must say so, got {:?}",
            readiness.blockers
        );

        // And the same Hub loses the anchor half the moment the witness goes
        // away, which is what makes the true above mean something.
        witness.handle.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let readiness = hub.mainnet_readiness().await;
        assert!(
            !readiness.trustless_finality,
            "the flag must not survive the loss of its evidence"
        );
        assert!(
            readiness.blockers.iter().any(|it| it == ANCHOR_BLOCKER),
            "got {:?}",
            readiness.blockers
        );
        server.abort();
    }
}

/// `production_mainnet_ready` is the strongest claim the Hub makes. It must be
/// false while any of its parts is missing, and the anchor is missing.
///
/// Asserted on `HubHardGuarantees::measure`, which is where the claim is
/// computed, and on the readiness document, which is where it is enforced. It
/// is no longer asserted on `health()`, because `health()` no longer publishes
/// it - see `health_carries_no_guarantee_flag_while_readiness_measures`.
#[tokio::test]
async fn production_mainnet_ready_is_false_while_any_part_is_missing() {
    use l2_fast_pay_hub::readiness::HubHardGuarantees;

    let (node_url, server) = spawn_node(true).await;
    let hub = build_hub(&node_url, "production-hub");
    let capabilities = hub.mainnet_readiness().await.fullnode_capabilities;
    assert!(
        capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.mainnet),
        "the probe must have succeeded, otherwise this proves nothing"
    );
    assert!(
        !HubHardGuarantees::measure(
            "mainnet-pilot",
            true,
            capabilities.as_ref(),
            None,
            now_unix()
        )
        .production_mainnet_ready,
        "every other part holds and the anchor is still absent, so this must be false"
    );
    assert!(!hub.mainnet_readiness().await.trustless_finality);
    server.abort();

    let (node_url, server) = spawn_node(false).await;
    let hub = build_hub(&node_url, "production-hub-2");
    let capabilities = hub.mainnet_readiness().await.fullnode_capabilities;
    assert!(
        !HubHardGuarantees::measure(
            "mainnet-pilot",
            true,
            capabilities.as_ref(),
            None,
            now_unix()
        )
        .production_mainnet_ready
    );
    server.abort();
}

/// A flag must not survive the loss of its evidence. When the node is
/// unreachable the Hub knows nothing, so every measured guarantee reads false
/// on the endpoint that tried to measure and failed.
#[tokio::test]
async fn measured_flags_fail_closed_when_the_node_is_unreachable() {
    let hub = build_hub("http://127.0.0.1:1", "unreachable-hub");
    // The liveness endpoint still answers, and still claims nothing.
    assert!(hub.health().ok);

    // The load-bearing half: `mainnet_readiness` did probe, the probe failed,
    // and a failed probe must not leave a guarantee standing.
    let readiness = hub.mainnet_readiness().await;
    assert!(!readiness.unilateral_l1_enforceable);
    assert!(!readiness.trustless_finality);
    assert!(!readiness.payments_enabled);
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("fullnode_capability_probe_failed")),
        "a failed probe must be reported as a blocker, got {:?}",
        readiness.blockers
    );
}
