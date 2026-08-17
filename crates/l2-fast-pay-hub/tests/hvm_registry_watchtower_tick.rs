//! The shared HVM registry watchtower, driven by the scheduler instead of by
//! a human at a Windows console.
//!
//! Two separate things are proved here.
//!
//! The first is the *driver*: a challenge that appears on chain with nobody
//! watching is answered by a scheduler tick alone, exactly once, and one
//! channel failing does not stop the others from being serviced.
//!
//! The second is the *margin*. The contract's `respond` requires
//! `block_height() < deadline` at execution time, and `finalize` is callable
//! by anyone once `block_height() >= deadline`. A watchtower that acts with a
//! single block of head-room is betting the whole channel balance on its
//! transaction being mined in the very next block. These tests pin the
//! refusal instead: below the margin the tower escalates and never signs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use field::{Address, Serialize as _, Sign};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryRecoveryBundleV2,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA, HvmRegistryWatchtowerModeV2,
    HvmRegistryWatchtowerRequestV2,
};
use l2_fast_pay_hub::hvm_scheduler::HvmLeaseSchedulerConfig;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;
use vm::ContractAddress;

const NETWORK_KIND: &str = "local_pilot_v1";
const PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
const BLOCK_ONE: &str = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";
const DEPOSIT_ZHU: u64 = 1_000_000;
const OBSERVED_HEIGHT: u64 = 900_000;
/// The stale split the counterparty put on chain when it challenged: serial 0,
/// which is older than the fully signed serial-1 bill this Hub holds.
const STALE_LEFT_ZHU: u64 = 600_000;
const STALE_HUB_ZHU: u64 = 400_000;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn block_anchor() -> String {
    "7e".repeat(32)
}

fn storage_entry(value: Value, live: u64, recover: u64) -> Value {
    json!({
        "value": value,
        "live_blocks": live,
        "recover_blocks": recover,
        "active": true,
        "recoverable": false
    })
}

/// A freshly opened channel: the only shape a registry activation is admitted
/// against.
fn open_snapshot(binding: &HvmRegistryBindingV2) -> Value {
    let mut snapshot = challenged_snapshot(binding, OBSERVED_HEIGHT + 12);
    snapshot["channel"]["status"]["value"] = json!(2);
    snapshot["channel"]["deadline"]["value"] = json!(0);
    snapshot["channel"]["left_balance"]["value"] = json!(DEPOSIT_ZHU);
    snapshot["channel"]["hub_balance"]["value"] = json!(0);
    snapshot
}

/// The counterparty has challenged with a stale serial-0 split and the
/// contract is counting down to `deadline`.
fn challenged_snapshot(binding: &HvmRegistryBindingV2, deadline: u64) -> Value {
    let (live, recover) = (20_000, 30_000);
    json!({
        "ret": 0,
        "schema": HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
        "settlement_profile": HPAY_REGISTRY_SETTLEMENT_PROFILE,
        "chain_id": binding.chain_id,
        "network_instance_id": binding.network_instance_id,
        "observed_height": OBSERVED_HEIGHT,
        "evaluation_height": OBSERVED_HEIGHT + 1,
        "contract_address": binding.contract_address,
        "deployment_tx_hash": binding.deployment_tx_hash,
        "deployment_height": binding.deployment_height,
        "deployment_action_verified": true,
        "bytecode_sha3": binding.bytecode_sha3,
        "hub_address": binding.right_hub_address,
        "left_address": binding.left_address,
        "registry_key_count": HVM_REGISTRY_STORAGE_KEY_COUNT,
        "channel_key_count": HVM_REGISTRY_CHANNEL_KEY_COUNT,
        "all_keys_active": true,
        "minimum_live_blocks": live,
        "minimum_recover_blocks": recover,
        "registry": {
            "g_network": storage_entry(json!(binding.network_instance_id), live, recover),
            "g_hub": storage_entry(json!(binding.right_hub_address), live, recover),
            "g_locked": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "g_left_claimable": storage_entry(json!(0), live, recover),
            "g_hub_claimable": storage_entry(json!(0), live, recover),
            "g_open_count": storage_entry(json!(1), live, recover)
        },
        "channel": {
            "status": storage_entry(json!(3), live, recover),
            "channel_id": storage_entry(json!(binding.channel_id), live, recover),
            "reuse": storage_entry(json!(binding.reuse_version), live, recover),
            "deposit": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "paid": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "total": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "serial": storage_entry(json!(0), live, recover),
            "left_balance": storage_entry(json!(STALE_LEFT_ZHU), live, recover),
            "hub_balance": storage_entry(json!(STALE_HUB_ZHU), live, recover),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": storage_entry(json!(deadline), live, recover),
            "left_claimed": storage_entry(json!(false), live, recover)
        }
    })
}

fn signed_bundle(seed: &str, hub: &Account, contract: &str) -> HvmRegistryRecoveryBundleV2 {
    let left = Account::create_by(seed).unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: INSTANCE.into(),
        contract_address: contract.into(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: hex::encode(sys::sha2(seed.as_bytes()))[..32].into(),
        reuse_version: 0,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*hub.address()).to_readable(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial: 1,
        left_balance_zhu: DEPOSIT_ZHU,
        hub_balance_zhu: 0,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    HvmRegistryRecoveryBundleV2 {
        schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
        binding,
        initial_recovery_bill: bill,
    }
}

struct Mock {
    /// Live registry evidence, keyed by the left address the query names.
    live: Arc<RwLock<HashMap<String, Value>>>,
    /// The height the node reports as its own chain tip in `/query/capabilities`.
    tip_height: Arc<AtomicU64>,
    /// How far behind wall clock the node's tip timestamp is.
    tip_age_seconds: Arc<AtomicU64>,
    /// A left address whose registry query fails, modelling one channel whose
    /// evidence cannot be read while the others can.
    failing_left: Arc<RwLock<Option<String>>>,
    submits: Arc<AtomicUsize>,
    accepted_body: Arc<RwLock<String>>,
    accepted_hash: Arc<RwLock<String>>,
    confirmations: Arc<AtomicU64>,
}

struct Harness {
    contract: String,
    hub_account: Account,
    hub_address: String,
    node_url: String,
    state_path: std::path::PathBuf,
    hub_secret_hex: String,
    mock: Mock,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Harness {
    fn hub(&self) -> HubState {
        HubState::new_secure_with_policy(
            "registry watchtower tick",
            self.hub_address.clone(),
            self.node_url.clone(),
            None,
            self.state_path.clone(),
            self.hub_secret_hex.clone(),
            &"92".repeat(32),
            &"93".repeat(32),
            "local-pilot",
            0,
            0,
        )
        .unwrap()
    }

    fn submits(&self) -> usize {
        self.mock.submits.load(Ordering::SeqCst)
    }

    /// Activate one registry channel and leave it challenged with `deadline`.
    async fn challenge(&self, seed: &str, deadline: u64) -> HvmRegistryBindingV2 {
        let bundle = signed_bundle(seed, &self.hub_account, &self.contract);
        self.mock.live.write().await.insert(
            bundle.binding.left_address.clone(),
            open_snapshot(&bundle.binding),
        );
        self.hub()
            .activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        self.mock.live.write().await.insert(
            bundle.binding.left_address.clone(),
            challenged_snapshot(&bundle.binding, deadline),
        );
        bundle.binding
    }
}

async fn harness(seed: &str) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x5a; 20])).to_readable();
    let mock = Mock {
        live: Arc::new(RwLock::new(HashMap::new())),
        tip_height: Arc::new(AtomicU64::new(OBSERVED_HEIGHT)),
        tip_age_seconds: Arc::new(AtomicU64::new(0)),
        failing_left: Arc::new(RwLock::new(None)),
        submits: Arc::new(AtomicUsize::new(0)),
        accepted_body: Arc::new(RwLock::new(String::new())),
        accepted_hash: Arc::new(RwLock::new(String::new())),
        confirmations: Arc::new(AtomicU64::new(6)),
    };

    let app = Router::new()
        .route(
            "/query/capabilities",
            get({
                let tip_height = mock.tip_height.clone();
                let tip_age = mock.tip_age_seconds.clone();
                move || {
                    let tip_height = tip_height.clone();
                    let tip_age = tip_age.clone();
                    async move {
                        let height = tip_height.load(Ordering::SeqCst);
                        let tip = now_unix().saturating_sub(tip_age.load(Ordering::SeqCst));
                        Json(json!({
                            "ret": 0,
                            "api_version": 1,
                            "api": {
                                "transaction_submit_bound": true,
                                "hpay_channel_registry_query": true
                            },
                            "chain": {
                                "id": 7,
                                "height": height,
                                "next_height": height + 1,
                                "mainnet": false
                            },
                            "network": {
                                "kind": NETWORK_KIND,
                                "node_profile_id": PROFILE_ID,
                                "block_1_hash": BLOCK_ONE,
                                "instance_id": INSTANCE,
                                "transaction_format_version": 2
                            },
                            "sync": {
                                "tip_timestamp_unix": tip,
                                "max_tip_age_seconds": 3_600,
                                "fresh": true
                            },
                            "actions": {
                                "registered": [1, 2, 14, 40, 41, 44, 1041, 1044],
                                "enabled": [1, 2, 14, 40, 41, 44, 1041, 1044]
                            },
                            "transactions": { "enabled": [2, 3] },
                            "features": { "channel_unilateral_exit": false }
                        }))
                    }
                }
            }),
        )
        .route(
            "/query/hpay/channel-registry",
            get({
                let live = mock.live.clone();
                let failing_left = mock.failing_left.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let failing_left = failing_left.clone();
                    async move {
                        let Some(left) = query.get("left").cloned() else {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"ret": 1, "err": "no left address"})),
                            );
                        };
                        if failing_left.read().await.as_deref() == Some(left.as_str()) {
                            return (
                                StatusCode::OK,
                                Json(json!({"ret": 1, "err": "registry storage unavailable"})),
                            );
                        }
                        match live.read().await.get(&left) {
                            Some(snapshot) => (StatusCode::OK, Json(snapshot.clone())),
                            None => (
                                StatusCode::OK,
                                Json(json!({"ret": 1, "err": "unknown left address"})),
                            ),
                        }
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let live = mock.live.clone();
                let accepted_body = mock.accepted_body.clone();
                let accepted_hash = mock.accepted_hash.clone();
                let submits = mock.submits.clone();
                move |body: String| {
                    let live = live.clone();
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let submits = submits.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        submits.fetch_add(1, Ordering::SeqCst);
                        *accepted_body.write().await = body;
                        *accepted_hash.write().await = hash.clone();
                        // What `respond` does: adopt the newer bill's serial
                        // and split, leaving status and deadline alone.
                        for snapshot in live.write().await.values_mut() {
                            if snapshot["channel"]["status"]["value"] == json!(3)
                                && snapshot["channel"]["serial"]["value"] == json!(0)
                            {
                                snapshot["channel"]["serial"]["value"] = json!(1);
                                snapshot["channel"]["left_balance"]["value"] = json!(DEPOSIT_ZHU);
                                snapshot["channel"]["hub_balance"]["value"] = json!(0);
                            }
                        }
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let accepted_body = mock.accepted_body.clone();
                let accepted_hash = mock.accepted_hash.clone();
                let confirmations = mock.confirmations.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let confirmations = confirmations.clone();
                    async move {
                        let body = accepted_body.read().await.clone();
                        let hash = accepted_hash.read().await.clone();
                        if body.is_empty() || query.get("hash") != Some(&hash) {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 1041}, {"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": { "height": OBSERVED_HEIGHT, "hash": block_anchor() },
                            "confirm": confirmations.load(Ordering::SeqCst)
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    Harness {
        contract,
        hub_address: Address::from(*hub_account.address()).to_readable(),
        hub_secret_hex: hex::encode(hub_account.secret_key().serialize()),
        hub_account,
        node_url: format!("http://{address}"),
        state_path: directory.path().join("registry-watchtower-state.json"),
        mock,
        server,
        _directory: directory,
    }
}

fn monitor(binding_commitment: &str, suffix: &str) -> HvmRegistryWatchtowerRequestV2 {
    let now = now_unix();
    HvmRegistryWatchtowerRequestV2 {
        schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: format!("registry-monitor-{suffix}"),
        idempotency_key: format!("registry-monitor-idempotency-{suffix}"),
        binding_commitment: binding_commitment.into(),
        mode: HvmRegistryWatchtowerModeV2::Monitor,
        network_fee_zhu: 10_000,
        timestamp: now,
        gas_max: u8::MAX,
        created_unix: now,
    }
}

/// A response that cannot land is worse than no response: it burns the fee and
/// still loses the channel to `finalize`. With only two blocks left the tower
/// must refuse, latch RecoveryRequired, and never touch the key.
///
/// The window arithmetic: `deadline = height_at_challenge + challenge_blocks`,
/// `respond` needs `block_height() < deadline` at execution, and the margin is
/// three blocks. Here `deadline - observed_height == 2`, which is below it.
#[tokio::test]
async fn a_response_is_refused_not_attempted_when_the_window_is_under_the_margin() {
    let harness = harness("margin").await;
    let binding = harness.challenge("margin-left", OBSERVED_HEIGHT + 2).await;
    let commitment = binding.commitment().unwrap();

    let hub = harness.hub();
    assert!(hub.health().settlement_ready);
    let error = hub
        .run_hvm_registry_watchtower(monitor(&commitment, "margin"))
        .await
        .expect_err("a window under the margin must escalate, not be attempted");
    let error = error.to_string();
    assert!(
        error.contains("RecoveryRequired:"),
        "the refusal must escalate to the recovery latch, got: {error}"
    );
    assert!(
        error.contains("2 blocks left") && error.contains("3-block response margin"),
        "the refusal must state the arithmetic, got: {error}"
    );
    assert!(
        !hub.health().settlement_ready,
        "the RecoveryRequired latch must be raised, not merely reported"
    );
    assert_eq!(
        harness.submits(),
        0,
        "nothing may be broadcast for a response that cannot land in time"
    );
    harness.server.abort();
}

/// The same window one block wider is inside the margin and is answered
/// normally. Without this the margin test above would also pass on a tower
/// that simply refuses everything.
#[tokio::test]
async fn a_response_inside_the_margin_is_still_answered() {
    let harness = harness("margin-ok").await;
    let binding = harness
        .challenge("margin-ok-left", OBSERVED_HEIGHT + 3)
        .await;
    let commitment = binding.commitment().unwrap();

    let hub = harness.hub();
    let response = hub
        .run_hvm_registry_watchtower(monitor(&commitment, "margin-ok"))
        .await
        .unwrap();
    assert_eq!(response.action, "respond");
    assert_eq!(response.status, "confirmed");
    assert_eq!(harness.submits(), 1);
    harness.server.abort();
}

/// `observed_height` is whatever the queried fullnode chose to return. When it
/// trails the node's own reported chain tip, the remaining window is a
/// fiction: the true tip may already be past the deadline. Refuse.
#[tokio::test]
async fn evidence_that_trails_the_node_tip_is_refused() {
    let harness = harness("stale-height").await;
    let binding = harness
        .challenge("stale-height-left", OBSERVED_HEIGHT + 10)
        .await;
    let commitment = binding.commitment().unwrap();
    // The registry endpoint still answers from height 900_000 while the node
    // says its tip is 50 blocks further on. Two views, one chain.
    harness
        .mock
        .tip_height
        .store(OBSERVED_HEIGHT + 50, Ordering::SeqCst);

    let hub = harness.hub();
    let error = hub
        .run_hvm_registry_watchtower(monitor(&commitment, "stale-height"))
        .await
        .expect_err("registry evidence behind the node's own tip must be refused");
    assert!(
        error.to_string().contains("stale"),
        "the refusal must name staleness, got: {error}"
    );
    assert_eq!(harness.submits(), 0);
    harness.server.abort();
}

/// A tip an hour old satisfies the generic fullnode gate
/// (`FULLNODE_MAX_TIP_AGE_SECONDS` is 3600s) and is still useless for a
/// challenge window measured in a handful of blocks. The watchtower holds a
/// tighter line of its own.
#[tokio::test]
async fn evidence_from_a_node_whose_tip_has_stopped_moving_is_refused() {
    let harness = harness("stale-clock").await;
    let binding = harness
        .challenge("stale-clock-left", OBSERVED_HEIGHT + 10)
        .await;
    let commitment = binding.commitment().unwrap();
    // 20 minutes: inside the generic 60-minute node gate, far outside the
    // watchtower's own 5-minute limit.
    harness.mock.tip_age_seconds.store(1_200, Ordering::SeqCst);

    let hub = harness.hub();
    let error = hub
        .run_hvm_registry_watchtower(monitor(&commitment, "stale-clock"))
        .await
        .expect_err("a tip that stopped moving is not evidence for a deadline");
    assert!(
        error.to_string().contains("stale"),
        "the refusal must name staleness, got: {error}"
    );
    assert_eq!(harness.submits(), 0);
    harness.server.abort();
}

fn scheduler_config() -> HvmLeaseSchedulerConfig {
    HvmLeaseSchedulerConfig {
        interval_seconds: 60,
        renew_when_live_blocks_at_or_below: 10_000,
        periods: 100,
        network_fee_zhu: 10_000,
        gas_max: u8::MAX,
    }
}

/// The gap this work closes. A challenge appears on chain; no operator is
/// awake, no CLI is run, no DPAPI identity file is opened, no HTTP route is
/// called. The scheduler tick alone must see it and answer it.
#[tokio::test]
async fn a_challenge_appearing_with_no_human_involved_is_answered_by_the_tick_alone() {
    let harness = harness("driver").await;
    let binding = harness.challenge("driver-left", OBSERVED_HEIGHT + 10).await;
    let commitment = binding.commitment().unwrap();

    let hub = harness.hub();
    let results = hub
        .hvm_registry_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.binding_commitment, commitment);
    assert_eq!(result.error, None, "the tick must not fail closed here");
    let response = result
        .response
        .as_ref()
        .expect("the tick produced no response");
    assert_eq!(response.action, "respond");
    assert_eq!(response.status, "confirmed");
    assert_eq!(harness.submits(), 1);
    harness.server.abort();
}

/// The same situation ticked twice is one operation, not two. The identity is
/// derived from the durable facts of the situation, so a retry lands on the
/// existing record and resumes it.
#[tokio::test]
async fn the_same_situation_ticked_twice_does_not_produce_two_operations() {
    let harness = harness("idempotent").await;
    // Hold the response short of finality so the operation is still live when
    // the second tick arrives: this is the retry that must not duplicate.
    harness.mock.confirmations.store(2, Ordering::SeqCst);
    let binding = harness
        .challenge("idempotent-left", OBSERVED_HEIGHT + 10)
        .await;
    let commitment = binding.commitment().unwrap();

    let hub = harness.hub();
    let config = scheduler_config();
    let first = hub.hvm_registry_watchtower_tick(&config).await.unwrap();
    let first = first[0].response.as_ref().unwrap().clone();
    assert_eq!(first.action, "respond");
    assert_eq!(first.status, "submitted");
    assert_eq!(harness.submits(), 1);

    // Second tick, same situation. The chain has already adopted our bill, so
    // a naive "hash the current chain state" identity would name a different
    // operation and strand the first one.
    let second = hub.hvm_registry_watchtower_tick(&config).await.unwrap();
    let second = second[0].response.as_ref().unwrap().clone();
    assert_eq!(
        second.operation_id, first.operation_id,
        "a retry of the same situation is the same operation"
    );
    assert_eq!(
        harness.submits(),
        1,
        "a second tick must never broadcast a second response"
    );

    let operations = hub.hvm_registry_chain_operation_status(&first.operation_id);
    assert!(operations.unwrap().is_some());
    let _ = commitment;
    harness.server.abort();
}

/// A watchtower runs for as long as the channel does, so its retries land at
/// later and later seconds. The durable request it compares itself against
/// covers `timestamp` and `created_unix`, and a retry whose commitment moved is
/// refused outright with "registry watchtower retry changed the durable
/// request". If the tick derived either field from the caller's clock instead
/// of from the record, the very first retry that crossed a second boundary
/// would refuse its own operation and the record would be stranded forever.
///
/// So the gap here is real wall clock, not a simulated one, and it is crossed
/// repeatedly: every pass after the first must still resolve to the same
/// operation, never error, and never broadcast a second time.
#[tokio::test]
async fn a_retry_a_real_second_later_drives_the_same_operation_and_is_never_refused() {
    let harness = harness("clock-gap").await;
    // Short of finality, so the operation stays live and every later pass is a
    // genuine retry of the durable record rather than a fresh situation.
    harness.mock.confirmations.store(2, Ordering::SeqCst);
    harness
        .challenge("clock-gap-left", OBSERVED_HEIGHT + 10)
        .await;

    let hub = harness.hub();
    let config = scheduler_config();
    let first = hub.hvm_registry_watchtower_tick(&config).await.unwrap();
    let first = first[0].response.as_ref().unwrap().clone();
    assert_eq!(first.action, "respond");
    assert_eq!(first.status, "submitted");
    assert_eq!(harness.submits(), 1);

    let opened_at = now_unix();
    for pass in 1..=4 {
        // Long enough that the unix second has certainly changed since the
        // previous pass. This is the exact condition under which a clock-derived
        // request would produce different bytes.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let results = hub.hvm_registry_watchtower_tick(&config).await.unwrap();
        assert_eq!(
            results[0].error, None,
            "pass {pass} refused its own durable operation"
        );
        let response = results[0].response.as_ref().unwrap();
        assert_eq!(
            response.operation_id, first.operation_id,
            "pass {pass} named a different operation"
        );
        assert_eq!(
            harness.submits(),
            1,
            "pass {pass} broadcast the response a second time"
        );
    }
    assert!(
        now_unix() > opened_at,
        "the passes must genuinely have spanned more than one unix second"
    );
    harness.server.abort();
}

/// One channel whose evidence cannot be read must not take the others down
/// with it. The tick records the failure against that binding and keeps going.
#[tokio::test]
async fn one_channel_failing_does_not_stop_the_others_being_serviced() {
    let harness = harness("isolation").await;
    let broken = harness
        .challenge("isolation-broken", OBSERVED_HEIGHT + 10)
        .await;
    let healthy = harness
        .challenge("isolation-healthy", OBSERVED_HEIGHT + 10)
        .await;
    *harness.mock.failing_left.write().await = Some(broken.left_address.clone());

    let hub = harness.hub();
    let results = hub
        .hvm_registry_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results.len(), 2, "every activated channel is visited");

    let broken_commitment = broken.commitment().unwrap();
    let healthy_commitment = healthy.commitment().unwrap();
    let broken_result = results
        .iter()
        .find(|result| result.binding_commitment == broken_commitment)
        .expect("the broken channel was skipped entirely");
    assert!(
        broken_result.error.is_some() && broken_result.response.is_none(),
        "the unreadable channel must fail closed"
    );

    let healthy_result = results
        .iter()
        .find(|result| result.binding_commitment == healthy_commitment)
        .expect("the healthy channel was never reached");
    let response = healthy_result
        .response
        .as_ref()
        .expect("the healthy channel was not serviced");
    assert_eq!(response.action, "respond");
    assert_eq!(response.status, "confirmed");
    assert_eq!(
        harness.submits(),
        1,
        "exactly the healthy channel's response was broadcast"
    );
    harness.server.abort();
}

/// The margin refusal reached through the tick, which is the path that will
/// actually run in production.
#[tokio::test]
async fn the_tick_escalates_rather_than_attempting_a_response_it_cannot_land() {
    let harness = harness("tick-margin").await;
    let binding = harness
        .challenge("tick-margin-left", OBSERVED_HEIGHT + 1)
        .await;
    let commitment = binding.commitment().unwrap();

    {
        let hub = harness.hub();
        let results = hub
            .hvm_registry_watchtower_tick(&scheduler_config())
            .await
            .expect("a refusal is recorded against its channel, it does not kill the pass");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].binding_commitment, commitment);
        assert!(results[0].response.is_none());
        let error = results[0].error.as_deref().unwrap_or_default();
        assert!(
            error.contains("RecoveryRequired:") && error.contains("1 blocks left"),
            "expected an escalation naming the window, got: {error}"
        );
        assert_eq!(harness.submits(), 0);
        assert!(!hub.health().settlement_ready, "the latch is raised");

        // And the latch holds: the next tick does not quietly try again.
        let again = hub
            .hvm_registry_watchtower_tick(&scheduler_config())
            .await
            .unwrap();
        assert_eq!(again.len(), 1);
        assert!(again[0].response.is_none());
        assert_eq!(
            harness.submits(),
            0,
            "a latched Hub never signs the response it already refused"
        );
    }

    // The escalation writes nothing durable, so it is not remembered across a
    // restart â€” and it must not need to be. A fresh Hub starts with a clear
    // latch and has to reach the same refusal from the live evidence alone.
    // This is the property that actually protects the channel: the margin is
    // re-derived every pass, never trusted to a flag.
    let restarted = harness.hub();
    assert!(
        restarted.health().settlement_ready,
        "a fresh Hub genuinely starts unlatched, so the refusal below is earned"
    );
    let after_restart = restarted
        .hvm_registry_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    let error = after_restart[0].error.as_deref().unwrap_or_default();
    assert!(
        error.contains("RecoveryRequired:") && error.contains("1 blocks left"),
        "the margin must be re-derived from evidence, got: {error}"
    );
    assert!(!restarted.health().settlement_ready);
    assert_eq!(harness.submits(), 0);
    harness.server.abort();
}

/// The tick reads the same stale evidence the manual path does and refuses it
/// the same way, per channel, without stopping the loop.
#[tokio::test]
async fn the_tick_refuses_stale_evidence_without_failing_the_whole_pass() {
    let harness = harness("tick-stale").await;
    let binding = harness
        .challenge("tick-stale-left", OBSERVED_HEIGHT + 10)
        .await;
    let commitment = binding.commitment().unwrap();
    harness
        .mock
        .tip_height
        .store(OBSERVED_HEIGHT + 50, Ordering::SeqCst);

    let hub = harness.hub();
    let results = hub
        .hvm_registry_watchtower_tick(&scheduler_config())
        .await
        .expect("a stale node must not kill the pass");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].binding_commitment, commitment);
    assert!(results[0].response.is_none());
    let error = results[0].error.as_deref().unwrap_or_default();
    assert!(error.contains("stale"), "expected staleness, got: {error}");
    assert_eq!(harness.submits(), 0);
    harness.server.abort();
}
