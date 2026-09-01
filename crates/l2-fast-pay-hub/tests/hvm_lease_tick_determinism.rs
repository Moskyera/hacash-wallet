//! The two lease maintenance ticks, driven twice with real wall clock between
//! the passes.
//!
//! Both ticks name their operation after a one-minute clock window
//! (`hvm_scheduler::operation_identity`), which is deliberate: a repeat inside
//! the same minute is meant to land on the same durable record and *resume* it
//! rather than open a second one. `run_hvm_lease_renewal` and
//! `run_hvm_registry_lease_renewal` build that resume branch explicitly.
//!
//! But the name is the only part of the request the window makes stable. Both
//! request commitments are a hash over the whole request, `timestamp` and
//! `created_unix` included, and both entry points refuse a retry whose
//! commitment moved ("HVM lease retry changed the durable request" /
//! "registry lease retry changed the durable request"). A tick that minted a
//! fresh `now` on every pass would therefore hand the same record a different
//! request one second later and the Hub would refuse its own work — with a
//! signed transaction already on the wire and nobody left to reconcile it.
//! The resume branch would be unreachable from its only caller.
//!
//! So the gap between the passes here is real wall clock, not a simulated one.
//! Both tests park until there is room left in the current window, so the two
//! passes genuinely share an operation name, then assert that the window did
//! not turn over underneath them. Without that guard a rollover would give the
//! second pass a fresh name and the test would pass while proving nothing.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use field::{Address, Serialize as _, Sign};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_channel::{
    HVM_CHANNEL_BILL_SCHEMA, HVM_CHANNEL_BINDING_SCHEMA, HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA,
    HvmChannelBillV1, HvmChannelBindingV1, HvmChannelRecoveryBundleV1,
};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryRecoveryBundleV2,
};
use l2_fast_pay_hub::hvm_scheduler::HvmLeaseSchedulerConfig;
use l2_fast_pay_hub::node::{
    HPAY_CHANNEL_EXIT_ACTION_KINDS, HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
    HPAY_CHANNEL_EXIT_CONTRACT_NAME, HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
    HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN, HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
    HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT, HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA,
};
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;
use vm::ContractAddress;

const NETWORK_KIND: &str = "local_pilot_v1";
const PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
const BLOCK_ONE: &str = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";
const OBSERVED_HEIGHT: u64 = 900_000;
const DEPOSIT_ZHU: u64 = 1_000_000;
/// The window both ticks bucket their operation name into.
const OPERATION_WINDOW_SECONDS: u64 = 60;
/// How much of the window a two-pass test needs left in front of it.
const WINDOW_HEADROOM_SECONDS: u64 = 10;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn operation_window(unix: u64) -> u64 {
    unix / OPERATION_WINDOW_SECONDS
}

/// Park until the current one-minute operation window has enough of itself
/// left for both passes to stay inside it.
///
/// This is setup, not tolerance: the shared window is the precondition that
/// makes the second pass a *retry of the first record* rather than a fresh
/// operation, and it is the only thing being arranged here. Nothing about the
/// assertions moves, and both tests still fail loudly if the window turns over
/// anyway.
async fn wait_for_room_in_the_operation_window() {
    while OPERATION_WINDOW_SECONDS - (now_unix() % OPERATION_WINDOW_SECONDS)
        < WINDOW_HEADROOM_SECONDS
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn scheduler_config(renew_when_live_blocks_at_or_below: u64) -> HvmLeaseSchedulerConfig {
    HvmLeaseSchedulerConfig {
        interval_seconds: 60,
        renew_when_live_blocks_at_or_below,
        periods: 100,
        network_fee_zhu: 10_000,
        gas_max: u8::MAX,
    }
}

fn block_anchor() -> String {
    "7e".repeat(32)
}

fn capabilities(registry: bool) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": {
            "transaction_submit_bound": true,
            "hpay_channel_registry_query": registry
        },
        "chain": {
            "id": 7,
            "height": OBSERVED_HEIGHT,
            "next_height": OBSERVED_HEIGHT + 1,
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
            "tip_timestamp_unix": now_unix(),
            "max_tip_age_seconds": 3_600,
            "fresh": true
        },
        "actions": {
            "registered": [1, 2, 14, 40, 41, 44, 1041, 1044],
            "enabled": [1, 2, 14, 40, 41, 44, 1041, 1044]
        },
        "transactions": { "enabled": [2, 3] },
        "features": features(registry)
    })
}

/// The V1 channel activation proves the exit contract's artifact manifest
/// before it will admit a bundle; the registry profile carries its own proof
/// and does not read this block.
fn features(registry: bool) -> Value {
    if registry {
        return json!({ "channel_unilateral_exit": false });
    }
    json!({
        "channel_unilateral_exit": false,
        "channel_unilateral_exit_evidence": {
            "schema": HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
            "manifest_valid": true,
            "contract_name": HPAY_CHANNEL_EXIT_CONTRACT_NAME,
            "protocol_domain": HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN,
            "settlement_profile": HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
            "source_sha256": "44".repeat(32),
            "bytecode_sha3": HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
            "required_action_kinds": HPAY_CHANNEL_EXIT_ACTION_KINDS,
            "funding_model": {
                "left_deposit": "positive",
                "right_hub_deposit": "exactly_zero"
            },
            "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
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
        }
    })
}

/// A mock fullnode that accepts one bound transaction and then reports it
/// finalised, with a canonical block anchor so the operation can latch
/// `Confirmed` rather than escalating.
fn transaction_routes(
    submits: Arc<AtomicUsize>,
    accepted_body: Arc<RwLock<String>>,
    accepted_hash: Arc<RwLock<String>>,
    action_kinds: Value,
) -> Router {
    Router::new()
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let accepted_body = accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                move |body: String| {
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
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let action_kinds = action_kinds.clone();
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
                            "actions": action_kinds,
                            "signatures": [{"complete": true}],
                            "block": { "height": OBSERVED_HEIGHT, "hash": block_anchor() },
                            "confirm": 6
                        }))
                    }
                }
            }),
        )
}

// ---------------------------------------------------------------------------
// V1 channel harness
// ---------------------------------------------------------------------------

fn v1_storage_entry(value: Value) -> Value {
    json!({
        "value": value,
        "live_blocks": 10_000,
        "recover_blocks": 20_000,
        "active": true,
        "recoverable": false
    })
}

fn v1_snapshot(binding: &HvmChannelBindingV1) -> Value {
    json!({
        "ret": 0,
        "schema": HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA,
        "chain_id": binding.chain_id,
        "observed_height": OBSERVED_HEIGHT,
        "evaluation_height": OBSERVED_HEIGHT + 1,
        "contract_address": binding.contract_address,
        "deployment_tx_hash": binding.deployment_tx_hash,
        "deployment_height": binding.deployment_height,
        "deployment_action_verified": true,
        "bytecode_sha3": binding.bytecode_sha3,
        "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
        "all_keys_active": true,
        "minimum_live_blocks": 10_000,
        "minimum_recover_blocks": 20_000,
        "storage": {
            "status": v1_storage_entry(json!(2)),
            "network": v1_storage_entry(json!(binding.network_instance_id)),
            "channel_id": v1_storage_entry(json!(binding.channel_id)),
            "reuse": v1_storage_entry(json!(binding.reuse_version)),
            "left": v1_storage_entry(json!(binding.left_address)),
            "right": v1_storage_entry(json!(binding.right_hub_address)),
            "left_deposit": v1_storage_entry(json!(binding.left_deposit_zhu)),
            "right_deposit": v1_storage_entry(json!(binding.right_hub_deposit_zhu)),
            "left_paid": v1_storage_entry(json!(binding.left_deposit_zhu)),
            "right_paid": v1_storage_entry(json!(binding.right_hub_deposit_zhu)),
            "total": v1_storage_entry(json!(binding.left_deposit_zhu)),
            "serial": v1_storage_entry(json!(0)),
            "left_balance": v1_storage_entry(json!(binding.left_deposit_zhu)),
            "right_balance": v1_storage_entry(json!(binding.right_hub_deposit_zhu)),
            "challenge_blocks": v1_storage_entry(json!(binding.challenge_blocks)),
            "deadline": v1_storage_entry(json!(0)),
            "left_claimed": v1_storage_entry(json!(false)),
            "right_claimed": v1_storage_entry(json!(false))
        }
    })
}

fn v1_signed_bundle(seed: &str) -> (Account, HvmChannelRecoveryBundleV1) {
    let left = Account::create_by(&format!("{seed}-left")).unwrap();
    let right = Account::create_by(&format!("{seed}-hub")).unwrap();
    let binding = HvmChannelBindingV1 {
        schema: HVM_CHANNEL_BINDING_SCHEMA.to_owned(),
        settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
        network_mode: "testnet".to_owned(),
        chain_id: 7,
        network_instance_id: INSTANCE.to_owned(),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([7; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
        channel_id: "33".repeat(16),
        reuse_version: 7,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*right.address()).to_readable(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let mut bill = HvmChannelBillV1 {
        schema: HVM_CHANNEL_BILL_SCHEMA.to_owned(),
        binding_commitment: binding.commitment().unwrap(),
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        right_balance_zhu: 0,
        left_signature_hex: String::new(),
        right_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
    bill.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());
    (
        right,
        HvmChannelRecoveryBundleV1 {
            schema: HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA.to_owned(),
            binding,
            initial_recovery_bill: bill,
        },
    )
}

struct V1Harness {
    hub: HubState,
    submits: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

async fn v1_harness(seed: &str) -> V1Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let (hub_account, bundle) = v1_signed_bundle(seed);
    let expected = bundle.binding.clone();
    let live = Arc::new(RwLock::new(v1_snapshot(&bundle.binding)));
    let submits = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(capabilities(false)) }),
        )
        .route(
            "/query/hpay/channel-exit",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let expected = expected.clone();
                    async move {
                        assert_eq!(query.get("contract"), Some(&expected.contract_address));
                        (StatusCode::OK, Json(live.read().await.clone()))
                    }
                }
            }),
        )
        .merge(transaction_routes(
            submits.clone(),
            Arc::new(RwLock::new(String::new())),
            Arc::new(RwLock::new(String::new())),
            json!([{"kind": 44}]),
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "v1 lease tick",
        bundle.binding.right_hub_address.clone(),
        format!("http://{address}"),
        None,
        directory.path().join("v1-lease-tick-state.json"),
        hex::encode(hub_account.secret_key().serialize()),
        &"92".repeat(32),
        &"93".repeat(32),
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    hub.activate_hvm_channel_recovery(bundle, 5_000, 5_000)
        .await
        .unwrap();

    V1Harness {
        hub,
        submits,
        server,
        _directory: directory,
    }
}

// ---------------------------------------------------------------------------
// Shared registry harness
// ---------------------------------------------------------------------------

fn registry_storage_entry(value: Value, live: u64, recover: u64) -> Value {
    json!({
        "value": value,
        "live_blocks": live,
        "recover_blocks": recover,
        "active": true,
        "recoverable": false
    })
}

fn registry_snapshot(binding: &HvmRegistryBindingV2, live: u64, recover: u64) -> Value {
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
            "g_network": registry_storage_entry(json!(binding.network_instance_id), live, recover),
            "g_hub": registry_storage_entry(json!(binding.right_hub_address), live, recover),
            "g_locked": registry_storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "g_left_claimable": registry_storage_entry(json!(0), live, recover),
            "g_hub_claimable": registry_storage_entry(json!(0), live, recover),
            "g_open_count": registry_storage_entry(json!(1), live, recover)
        },
        "channel": {
            "status": registry_storage_entry(json!(2), live, recover),
            "channel_id": registry_storage_entry(json!(binding.channel_id), live, recover),
            "reuse": registry_storage_entry(json!(binding.reuse_version), live, recover),
            "deposit": registry_storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "paid": registry_storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "total": registry_storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "serial": registry_storage_entry(json!(0), live, recover),
            "left_balance": registry_storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "hub_balance": registry_storage_entry(json!(0), live, recover),
            "challenge_blocks": registry_storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": registry_storage_entry(json!(0), live, recover),
            "left_claimed": registry_storage_entry(json!(false), live, recover)
        }
    })
}

fn registry_signed_bundle(
    seed: &str,
    hub: &Account,
    contract: &str,
) -> HvmRegistryRecoveryBundleV2 {
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

struct RegistryHarness {
    hub: HubState,
    submits: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

async fn registry_harness(seed: &str) -> RegistryHarness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x5a; 20])).to_readable();
    let bundle = registry_signed_bundle(&format!("{seed}-left"), &hub_account, &contract);
    let expected = bundle.binding.clone();
    // 10_000 live blocks against a 10_000 renewal threshold: the lease is due,
    // so the tick actually opens an operation instead of reporting no action.
    let live = Arc::new(RwLock::new(registry_snapshot(&bundle.binding, 10_000, 0)));
    let submits = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(capabilities(true)) }),
        )
        .route(
            "/query/hpay/channel-registry",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let expected = expected.clone();
                    async move {
                        if query.get("left") == Some(&expected.left_address) {
                            (StatusCode::OK, Json(live.read().await.clone()))
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({"ret": 1, "err": "unknown left address"})),
                            )
                        }
                    }
                }
            }),
        )
        .merge(transaction_routes(
            submits.clone(),
            Arc::new(RwLock::new(String::new())),
            Arc::new(RwLock::new(String::new())),
            json!([{"kind": 1041}, {"kind": 44}]),
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let hub = HubState::new_secure_with_policy(
        "registry lease tick",
        Address::from(*hub_account.address()).to_readable(),
        format!("http://{address}"),
        None,
        directory.path().join("registry-lease-tick-state.json"),
        hex::encode(hub_account.secret_key().serialize()),
        &"92".repeat(32),
        &"93".repeat(32),
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    hub.activate_hvm_registry_recovery(bundle, 5_000, 0)
        .await
        .unwrap();

    RegistryHarness {
        hub,
        submits,
        server,
        _directory: directory,
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// A scheduler runs for as long as the Hub does, so its passes land at later
/// and later seconds. Two passes inside one clock window are the same
/// operation by design, and the second must resume the first rather than be
/// refused for having changed it.
#[tokio::test]
async fn a_v1_lease_pass_a_real_second_later_resumes_its_own_operation() {
    let harness = v1_harness("v1-lease-clock").await;
    let config = scheduler_config(10_000);

    wait_for_room_in_the_operation_window().await;
    let opened_window = operation_window(now_unix());

    let first = harness
        .hub
        .hvm_lease_maintenance_tick(&config)
        .await
        .unwrap();
    assert_eq!(first.len(), 1, "the activated channel must be visited");
    assert_eq!(
        first[0].error, None,
        "the opening pass failed: {:?}",
        first[0].error
    );
    let first = first[0].response.as_ref().unwrap().clone();
    assert_eq!(first.action, "renew_all_leases");
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);

    // Real wall clock, long enough that the unix second has certainly moved.
    // This is the exact condition under which a clock-derived request produces
    // different bytes for the same operation.
    for pass in 1..=3 {
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let results = harness
            .hub
            .hvm_lease_maintenance_tick(&config)
            .await
            .unwrap();
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
            harness.submits.load(Ordering::SeqCst),
            1,
            "pass {pass} broadcast a second renewal"
        );
    }

    assert_eq!(
        operation_window(now_unix()),
        opened_window,
        "the window turned over mid-test, so the passes were never retries of one record"
    );
    harness.server.abort();
}

/// The registry twin of the test above, against the second lease tick.
#[tokio::test]
async fn a_registry_lease_pass_a_real_second_later_resumes_its_own_operation() {
    let harness = registry_harness("registry-lease-clock").await;
    let config = scheduler_config(10_000);

    wait_for_room_in_the_operation_window().await;
    let opened_window = operation_window(now_unix());

    let first = harness
        .hub
        .hvm_registry_lease_maintenance_tick(&config)
        .await
        .unwrap();
    assert_eq!(first.len(), 1, "the activated channel must be visited");
    assert_eq!(
        first[0].error, None,
        "the opening pass failed: {:?}",
        first[0].error
    );
    let first = first[0].response.as_ref().unwrap().clone();
    assert_eq!(first.action, "renew_all_leases");
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);

    for pass in 1..=3 {
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let results = harness
            .hub
            .hvm_registry_lease_maintenance_tick(&config)
            .await
            .unwrap();
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
            harness.submits.load(Ordering::SeqCst),
            1,
            "pass {pass} broadcast a second renewal"
        );
    }

    assert_eq!(
        operation_window(now_unix()),
        opened_window,
        "the window turned over mid-test, so the passes were never retries of one record"
    );
    harness.server.abort();
}

/// The reconstruction helper the registry lease path never had, checked
/// directly rather than only through the tick.
///
/// It is what makes the retry above the *original* request instead of a
/// lookalike, so it has to reproduce the durable bytes exactly — and it has to
/// refuse rather than guess when the admission threshold it is handed is not
/// the one the record committed to.
#[tokio::test]
async fn the_registry_lease_request_is_rebuilt_exactly_or_refused() {
    let harness = registry_harness("registry-lease-rebuild").await;
    let config = scheduler_config(10_000);

    wait_for_room_in_the_operation_window().await;
    let opened = harness
        .hub
        .hvm_registry_lease_maintenance_tick(&config)
        .await
        .unwrap();
    let operation_id = opened[0].response.as_ref().unwrap().operation_id.clone();

    let rebuilt = harness
        .hub
        .hvm_registry_lease_renewal_request(&operation_id, 10_000)
        .unwrap()
        .expect("the durable record must be reconstructible");
    assert_eq!(rebuilt.operation_id, operation_id);
    assert!(
        rebuilt.timestamp != 0 && rebuilt.created_unix != 0,
        "the committed clock fields must be read back, not left blank"
    );

    // Driving the exact rebuilt request is a resume, never a refusal.
    let resumed = harness
        .hub
        .run_hvm_registry_lease_renewal(rebuilt.clone())
        .await
        .unwrap();
    assert_eq!(resumed.operation_id, operation_id);
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);

    // A threshold the record never committed to is a different request, and is
    // named as such here rather than surfacing later as a bare retry refusal.
    let error = harness
        .hub
        .hvm_registry_lease_renewal_request(&operation_id, 9_999)
        .expect_err("a threshold that was never committed to must be refused");
    assert!(
        error.to_string().contains("inconsistent"),
        "the refusal must name the inconsistency, got: {error}"
    );

    // And the guard it protects is genuinely live: the same operation with a
    // moved timestamp is still refused outright.
    let mut moved = rebuilt;
    moved.timestamp += 1;
    moved.created_unix += 1;
    let error = harness
        .hub
        .run_hvm_registry_lease_renewal(moved)
        .await
        .expect_err("a retry whose clock fields moved must be refused");
    assert!(
        error
            .to_string()
            .contains("registry lease retry changed the durable request"),
        "expected the durable-request refusal, got: {error}"
    );
    assert_eq!(
        harness.submits.load(Ordering::SeqCst),
        1,
        "a refused retry must never broadcast"
    );
    harness.server.abort();
}

/// Unless the two ticks can be shown to refuse a genuinely changed request,
/// the tests above would also pass on a Hub that had simply stopped comparing.
/// The V1 guard, checked the same way its registry twin is.
#[tokio::test]
async fn a_v1_lease_retry_that_really_changed_is_still_refused() {
    let harness = v1_harness("v1-lease-guard").await;
    let config = scheduler_config(10_000);

    wait_for_room_in_the_operation_window().await;
    let opened = harness
        .hub
        .hvm_lease_maintenance_tick(&config)
        .await
        .unwrap();
    let operation_id = opened[0].response.as_ref().unwrap().operation_id.clone();

    let rebuilt = harness
        .hub
        .hvm_lease_renewal_request(&operation_id, 10_000)
        .unwrap()
        .expect("the durable record must be reconstructible");
    let mut moved = rebuilt;
    moved.timestamp += 1;
    moved.created_unix += 1;
    let error = harness
        .hub
        .run_hvm_lease_renewal(moved)
        .await
        .expect_err("a retry whose clock fields moved must be refused");
    assert!(
        error
            .to_string()
            .contains("HVM lease retry changed the durable request"),
        "expected the durable-request refusal, got: {error}"
    );
    assert_eq!(
        harness.submits.load(Ordering::SeqCst),
        1,
        "a refused retry must never broadcast"
    );
    harness.server.abort();
}
