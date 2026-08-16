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

/// A mainnet fullnode that either does or does not report a verified native
/// unilateral-exit capability.
async fn spawn_node(exit_supported: bool) -> (String, JoinHandle<()>) {
    let (url, handle, _probes) = spawn_counting_node(exit_supported).await;
    (url, handle)
}

/// The same fullnode, plus a counter of how many capability probes it has been
/// asked to serve. Any endpoint that claims to do no node I/O can be held to it.
async fn spawn_counting_node(exit_supported: bool) -> (String, JoinHandle<()>, Arc<AtomicUsize>) {
    let probes = Arc::new(AtomicUsize::new(0));
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
    assert!(
        readiness.unilateral_l1_enforceable,
        "the node reports a verified unilateral-exit deployment, so the measured \
         dispute-path flag must be true"
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
/// * `mainnet_readiness()` must report the guarantee `true`, because it probed
///   and the evidence holds. That is property B.
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
    assert!(
        readiness.unilateral_l1_enforceable,
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
        assert!(
            readiness.trustless_finality,
            "with a verified exit path and a live anchor, this must be true"
        );

        // And the same Hub reads false the moment the witness goes away, which
        // is what makes the true above mean something.
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
