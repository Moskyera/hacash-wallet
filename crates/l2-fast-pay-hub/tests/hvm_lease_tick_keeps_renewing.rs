//! The lease scheduler across a clock-window boundary, which is where it lives.
//!
//! `hvm_lease_tick_determinism` drives two passes *inside* one operation window
//! and proves the second resumes the first. That is a real property, but it is
//! not the one a running Hub exercises: `HvmLeaseSchedulerConfig::validate`
//! refuses an interval under sixty seconds, and the operation name is bucketed
//! to a sixty-second window, so every pass a live scheduler ever makes after
//! the first lands in a *later* window than the record it left behind.
//!
//! That is the case this file covers, and the case that was broken. Signing a
//! renewal moves its record to `Signed` and then `Submitted`, both of which
//! `persisted_state_requires_recovery` counts, so `refresh_recovery_gate`
//! raises the process-wide `recovery_required` latch the instant the
//! transaction exists. The latch is right — an outstanding signed transaction
//! must stop the Hub signing beside it — and it comes down only when that same
//! operation reaches `Confirmed`. The only code that can take it there is keyed
//! to the operation id, and the next pass could never say that id again. So the
//! tick renewed once, was refused by the latch its own submission had raised,
//! and stood still for the rest of the process, confirmation or no
//! confirmation.
//!
//! The gaps between passes here are therefore real window boundaries, waited
//! out on the wall clock, and every test asserts the window genuinely turned
//! over. A mock that let the renewal confirm inside the opening pass would
//! prove nothing at all.

use std::collections::{HashMap, HashSet};
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
use l2_fast_pay_hub::hvm_watchtower::{HVM_LEASE_RENEWAL_REQUEST_SCHEMA, HvmLeaseRenewalRequestV1};
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
const OPERATION_WINDOW_SECONDS: u64 = 60;
/// The activation floors, and the recover life the mock always reports.
const ACTIVATION_FLOOR_BLOCKS: u64 = 5_000;
const RECOVER_BLOCKS: u64 = 20_000;
/// Renew whenever the shortest lease is at or under this. The mock moves the
/// reported life around this line to say "due" or "not due".
const RENEW_AT_OR_BELOW: u64 = 10_000;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn operation_window(unix: u64) -> u64 {
    unix / OPERATION_WINDOW_SECONDS
}

/// Park until the current window is nearly spent, so the pass that follows has
/// a boundary close in front of it rather than a whole minute.
///
/// This shortens the wait; it does not create the condition being tested. The
/// boundary is real either way, and every crossing below is asserted.
async fn wait_until_the_window_is_nearly_spent() {
    while now_unix() % OPERATION_WINDOW_SECONDS < OPERATION_WINDOW_SECONDS - 10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait out the real boundary out of the window a pass was made in.
async fn wait_for_the_window_to_turn_over(from: u64) {
    while operation_window(now_unix()) == from {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn scheduler_config() -> HvmLeaseSchedulerConfig {
    HvmLeaseSchedulerConfig {
        interval_seconds: 60,
        renew_when_live_blocks_at_or_below: RENEW_AT_OR_BELOW,
        periods: 100,
        network_fee_zhu: 10_000,
        gas_max: u8::MAX,
    }
}

fn capabilities() -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": { "transaction_submit_bound": true },
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
        "features": {
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
        }
    })
}

fn storage_entry(value: Value, live_blocks: u64) -> Value {
    json!({
        "value": value,
        "live_blocks": live_blocks,
        "recover_blocks": RECOVER_BLOCKS,
        "active": true,
        "recoverable": false
    })
}

fn snapshot(binding: &HvmChannelBindingV1, live_blocks: u64) -> Value {
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
        "minimum_live_blocks": live_blocks,
        "minimum_recover_blocks": RECOVER_BLOCKS,
        "storage": {
            "status": storage_entry(json!(2), live_blocks),
            "network": storage_entry(json!(binding.network_instance_id), live_blocks),
            "channel_id": storage_entry(json!(binding.channel_id), live_blocks),
            "reuse": storage_entry(json!(binding.reuse_version), live_blocks),
            "left": storage_entry(json!(binding.left_address), live_blocks),
            "right": storage_entry(json!(binding.right_hub_address), live_blocks),
            "left_deposit": storage_entry(json!(binding.left_deposit_zhu), live_blocks),
            "right_deposit": storage_entry(json!(binding.right_hub_deposit_zhu), live_blocks),
            "left_paid": storage_entry(json!(binding.left_deposit_zhu), live_blocks),
            "right_paid": storage_entry(json!(binding.right_hub_deposit_zhu), live_blocks),
            "total": storage_entry(json!(binding.left_deposit_zhu), live_blocks),
            "serial": storage_entry(json!(0), live_blocks),
            "left_balance": storage_entry(json!(binding.left_deposit_zhu), live_blocks),
            "right_balance": storage_entry(json!(binding.right_hub_deposit_zhu), live_blocks),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live_blocks),
            "deadline": storage_entry(json!(0), live_blocks),
            "left_claimed": storage_entry(json!(false), live_blocks),
            "right_claimed": storage_entry(json!(false), live_blocks)
        }
    })
}

fn signed_bundle(seed: &str) -> (Account, HvmChannelRecoveryBundleV1) {
    let left = Account::create_by(&format!("{seed}-left")).unwrap();
    let right = Account::create_by(&format!("{seed}-hub")).unwrap();
    let binding = HvmChannelBindingV1 {
        schema: HVM_CHANNEL_BINDING_SCHEMA.to_owned(),
        settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
        network_mode: "testnet".to_owned(),
        chain_id: 7,
        network_instance_id: INSTANCE.to_owned(),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
        channel_id: "35".repeat(16),
        reuse_version: 3,
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

/// A mock fullnode whose mempool is under the test's control.
///
/// A submitted transaction is held pending until the test mines it, which is
/// what a real chain does and what the harness in
/// `hvm_lease_tick_determinism` deliberately does not do. The lease life the
/// contract reports is under the test's control too, so a confirmed renewal
/// can be made to satisfy the `RenewAllLeases` postcondition — the shortest
/// lease strictly longer than it was before the call.
struct Chain {
    submits: Arc<AtomicUsize>,
    mempool: Arc<RwLock<HashMap<String, String>>>,
    mined: Arc<RwLock<HashSet<String>>>,
    live: Arc<RwLock<Value>>,
    binding: HvmChannelBindingV1,
}

impl Chain {
    async fn mine_everything_submitted(&self) {
        let hashes = self
            .mempool
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        self.mined.write().await.extend(hashes);
    }

    /// Report the leases as having whatever life the test says.
    async fn set_lease_life(&self, live_blocks: u64) {
        *self.live.write().await = snapshot(&self.binding, live_blocks);
    }

    fn submitted(&self) -> usize {
        self.submits.load(Ordering::SeqCst)
    }
}

struct Harness {
    hub: HubState,
    chain: Chain,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

async fn harness(seed: &str) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let (hub_account, bundle) = signed_bundle(seed);
    let expected = bundle.binding.clone();
    let live = Arc::new(RwLock::new(snapshot(&bundle.binding, RENEW_AT_OR_BELOW)));
    let submits = Arc::new(AtomicUsize::new(0));
    let mempool: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let mined: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(capabilities()) }),
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
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let mempool = mempool.clone();
                let submits = submits.clone();
                move |body: String| {
                    let mempool = mempool.clone();
                    let submits = submits.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        submits.fetch_add(1, Ordering::SeqCst);
                        mempool.write().await.insert(hash.clone(), body);
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let mempool = mempool.clone();
                let mined = mined.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let mempool = mempool.clone();
                    let mined = mined.clone();
                    async move {
                        let Some(hash) = query.get("hash").cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        let Some(body) = mempool.read().await.get(&hash).cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        if !mined.read().await.contains(&hash) {
                            return Json(json!({
                                "ret": 0,
                                "hash": hash,
                                "tx_type": 3,
                                "body": body,
                                "actions": [{"kind": 44}],
                                "signatures": [{"complete": true}],
                                "pending": true
                            }));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": { "height": OBSERVED_HEIGHT, "hash": "7e".repeat(32) },
                            "confirm": 6
                        }))
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let binding = bundle.binding.clone();
    let hub = HubState::new_secure_with_policy(
        "v1 lease tick across windows",
        bundle.binding.right_hub_address.clone(),
        format!("http://{address}"),
        None,
        directory.path().join("lease-tick-state.json"),
        hex::encode(hub_account.secret_key().serialize()),
        &"92".repeat(32),
        &"93".repeat(32),
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    hub.activate_hvm_channel_recovery(bundle, ACTIVATION_FLOOR_BLOCKS, ACTIVATION_FLOOR_BLOCKS)
        .await
        .unwrap();

    Harness {
        hub,
        chain: Chain {
            submits,
            mempool,
            mined,
            live,
            binding,
        },
        server,
        _directory: directory,
    }
}

// ---------------------------------------------------------------------------
// The shared registry twin
// ---------------------------------------------------------------------------

fn registry_entry(value: Value, live: u64, recover: u64) -> Value {
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
            "g_network": registry_entry(json!(binding.network_instance_id), live, recover),
            "g_hub": registry_entry(json!(binding.right_hub_address), live, recover),
            "g_locked": registry_entry(json!(DEPOSIT_ZHU), live, recover),
            "g_left_claimable": registry_entry(json!(0), live, recover),
            "g_hub_claimable": registry_entry(json!(0), live, recover),
            "g_open_count": registry_entry(json!(1), live, recover)
        },
        "channel": {
            "status": registry_entry(json!(2), live, recover),
            "channel_id": registry_entry(json!(binding.channel_id), live, recover),
            "reuse": registry_entry(json!(binding.reuse_version), live, recover),
            "deposit": registry_entry(json!(DEPOSIT_ZHU), live, recover),
            "paid": registry_entry(json!(DEPOSIT_ZHU), live, recover),
            "total": registry_entry(json!(DEPOSIT_ZHU), live, recover),
            "serial": registry_entry(json!(0), live, recover),
            "left_balance": registry_entry(json!(DEPOSIT_ZHU), live, recover),
            "hub_balance": registry_entry(json!(0), live, recover),
            "challenge_blocks": registry_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": registry_entry(json!(0), live, recover),
            "left_claimed": registry_entry(json!(false), live, recover)
        }
    })
}

fn registry_bundle(seed: &str, hub: &Account, contract: &str) -> HvmRegistryRecoveryBundleV2 {
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
    mempool: Arc<RwLock<HashMap<String, String>>>,
    mined: Arc<RwLock<HashSet<String>>>,
    live: Arc<RwLock<Value>>,
    binding: HvmRegistryBindingV2,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl RegistryHarness {
    async fn mine_everything_submitted(&self) {
        let hashes = self
            .mempool
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        self.mined.write().await.extend(hashes);
    }

    async fn set_lease_life(&self, live: u64, recover: u64) {
        *self.live.write().await = registry_snapshot(&self.binding, live, recover);
    }

    fn submitted(&self) -> usize {
        self.submits.load(Ordering::SeqCst)
    }
}

async fn registry_harness(seed: &str) -> RegistryHarness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x5b; 20])).to_readable();
    let bundle = registry_bundle(&format!("{seed}-left"), &hub_account, &contract);
    let expected = bundle.binding.clone();
    // Bootstrap posture, as the registry determinism harness uses: the lease is
    // due, so the tick opens an operation rather than reporting no action.
    let live = Arc::new(RwLock::new(registry_snapshot(
        &bundle.binding,
        RENEW_AT_OR_BELOW,
        0,
    )));
    let submits = Arc::new(AtomicUsize::new(0));
    let mempool: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let mined: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(registry_capabilities()) }),
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
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let mempool = mempool.clone();
                let submits = submits.clone();
                move |body: String| {
                    let mempool = mempool.clone();
                    let submits = submits.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        submits.fetch_add(1, Ordering::SeqCst);
                        mempool.write().await.insert(hash.clone(), body);
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let mempool = mempool.clone();
                let mined = mined.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let mempool = mempool.clone();
                    let mined = mined.clone();
                    async move {
                        let Some(hash) = query.get("hash").cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        let Some(body) = mempool.read().await.get(&hash).cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        if !mined.read().await.contains(&hash) {
                            return Json(json!({
                                "ret": 0,
                                "hash": hash,
                                "tx_type": 3,
                                "body": body,
                                "actions": [{"kind": 1041}, {"kind": 44}],
                                "signatures": [{"complete": true}],
                                "pending": true
                            }));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 1041}, {"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": { "height": OBSERVED_HEIGHT, "hash": "7e".repeat(32) },
                            "confirm": 6
                        }))
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let binding = bundle.binding.clone();
    let hub = HubState::new_secure_with_policy(
        "registry lease tick across windows",
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
    hub.activate_hvm_registry_recovery(bundle, ACTIVATION_FLOOR_BLOCKS, 0)
        .await
        .unwrap();

    RegistryHarness {
        hub,
        submits,
        mempool,
        mined,
        live,
        binding,
        server,
        _directory: directory,
    }
}

fn registry_capabilities() -> Value {
    let mut value = capabilities();
    value["api"]["hpay_channel_registry_query"] = json!(true);
    value["features"] = json!({ "channel_unilateral_exit": false });
    value
}

/// One pass of the real scheduler tick, returning the single channel's outcome.
async fn pass(
    hub: &HubState,
    config: &HvmLeaseSchedulerConfig,
) -> (Option<String>, Option<String>) {
    let results = hub.hvm_lease_maintenance_tick(config).await.unwrap();
    assert_eq!(results.len(), 1, "the activated channel must be visited");
    let result = &results[0];
    (
        result
            .response
            .as_ref()
            .map(|response| format!("{}:{}", response.operation_id, response.status)),
        result.error.clone(),
    )
}

fn split(outcome: &str) -> (&str, &str) {
    outcome.rsplit_once(':').unwrap()
}

/// The whole defect, and the whole fix, in one run: three renewals, each one
/// opened in one window and confirmed from a later one.
///
/// Before the fix this failed on the very first assertion after the first
/// boundary, with `state: RecoveryRequired` — the scheduler refused by the
/// latch its own submission raised, with no way left to notice the
/// confirmation that had already happened.
#[tokio::test]
async fn the_lease_tick_keeps_renewing_across_window_boundaries() {
    let harness = harness("keeps-renewing").await;
    let config = scheduler_config();
    let hub = &harness.hub;
    let chain = &harness.chain;

    for renewal in 1..=3u64 {
        // The leases are short, so this pass is due to renew.
        chain.set_lease_life(RENEW_AT_OR_BELOW).await;
        wait_until_the_window_is_nearly_spent().await;
        let opened_in = operation_window(now_unix());

        let (response, error) = pass(hub, &config).await;
        assert_eq!(error, None, "renewal {renewal} failed to open");
        let response = response.unwrap();
        let (operation_id, status) = split(&response);
        let operation_id = operation_id.to_owned();
        assert_eq!(
            status, "submitted",
            "renewal {renewal} did not reach the wire"
        );
        assert_eq!(
            chain.submitted(),
            renewal as usize,
            "renewal {renewal} broadcast the wrong number of transactions"
        );
        assert_eq!(
            operation_window(now_unix()),
            opened_in,
            "the window turned over while renewal {renewal} was being opened"
        );

        // A signed transaction is outstanding, so the Hub refuses to sign
        // anything new. This is the latch working, not the defect.
        assert!(
            !hub.health().settlement_ready,
            "renewal {renewal} left a transaction on the wire without raising the latch"
        );

        // The chain does its part: mined, and the leases are longer for it.
        chain.mine_everything_submitted().await;
        chain.set_lease_life(RECOVER_BLOCKS).await;

        // And now the thing a live scheduler always does and this tick never
        // survived: the next pass is in a later window.
        wait_for_the_window_to_turn_over(opened_in).await;
        let (response, error) = pass(hub, &config).await;
        assert_eq!(
            error, None,
            "renewal {renewal} was refused a window later instead of being resumed"
        );
        let response = response.unwrap();
        let (resumed_id, status) = split(&response);
        assert_eq!(
            resumed_id, operation_id,
            "renewal {renewal} was not resumed, a second operation was named"
        );
        assert_eq!(
            status, "confirmed",
            "renewal {renewal} did not reach confirmation from the later window"
        );
        assert_eq!(
            chain.submitted(),
            renewal as usize,
            "resuming renewal {renewal} broadcast a second transaction"
        );
        assert!(
            operation_window(now_unix()) > opened_in,
            "the resume did not happen in a later window"
        );

        // Confirmation is what releases the latch. Nothing else touched it.
        assert!(
            hub.health().settlement_ready,
            "renewal {renewal} confirmed but the Hub stayed latched"
        );

        // With the leases long again the tick has nothing to do, and says so
        // rather than spending a fee to stand still.
        let (response, error) = pass(hub, &config).await;
        assert_eq!(error, None, "the idle pass after renewal {renewal} failed");
        let response = response.unwrap();
        assert_eq!(
            split(&response).1,
            "not_due",
            "the tick renewed again with the leases already long"
        );
        assert_eq!(chain.submitted(), renewal as usize);
    }

    harness.server.abort();
}

/// The registry lease tick is the same tick in the same scheduler loop, and it
/// wedged the same way. One renewal opened in one window and confirmed from a
/// later one, then a second opened, which is what "keeps going" means here.
#[tokio::test]
async fn the_registry_lease_tick_also_survives_the_window_boundary() {
    let harness = registry_harness("registry-keeps-renewing").await;
    let config = scheduler_config();

    wait_until_the_window_is_nearly_spent().await;
    let opened_in = operation_window(now_unix());

    let results = harness
        .hub
        .hvm_registry_lease_maintenance_tick(&config)
        .await
        .unwrap();
    assert_eq!(results[0].error, None, "the opening pass failed");
    let opened = results[0].response.as_ref().unwrap().clone();
    assert_eq!(opened.status, "submitted");
    assert_eq!(harness.submitted(), 1);
    assert_eq!(
        operation_window(now_unix()),
        opened_in,
        "the window turned over while the renewal was being opened"
    );
    assert!(
        !harness.hub.health().settlement_ready,
        "a registry transaction on the wire must raise the latch"
    );

    harness.mine_everything_submitted().await;
    harness.set_lease_life(RECOVER_BLOCKS, RECOVER_BLOCKS).await;
    wait_for_the_window_to_turn_over(opened_in).await;

    let results = harness
        .hub
        .hvm_registry_lease_maintenance_tick(&config)
        .await
        .unwrap();
    assert_eq!(
        results[0].error, None,
        "the registry tick was refused a window later instead of resuming"
    );
    let resumed = results[0].response.as_ref().unwrap();
    assert_eq!(
        resumed.operation_id, opened.operation_id,
        "the registry tick named a second operation instead of resuming"
    );
    assert_eq!(resumed.status, "confirmed");
    assert_eq!(harness.submitted(), 1, "the resume broadcast a second time");
    assert!(
        harness.hub.health().settlement_ready,
        "confirmation must release the latch"
    );

    // Short leases again, and the tick renews again rather than standing still.
    harness.set_lease_life(RENEW_AT_OR_BELOW, 1).await;
    let results = harness
        .hub
        .hvm_registry_lease_maintenance_tick(&config)
        .await
        .unwrap();
    assert_eq!(results[0].error, None, "the second renewal failed to open");
    let second = results[0].response.as_ref().unwrap();
    assert_ne!(
        second.operation_id, opened.operation_id,
        "a genuinely new renewal must be its own operation"
    );
    assert_eq!(second.status, "submitted");
    assert_eq!(harness.submitted(), 2);

    harness.server.abort();
}

/// The tick drives the operation it opened. It does not drive anybody else's.
///
/// A channel may hold one unresolved chain operation at a time, so an operation
/// opened at the CLI blocks the tick either way. What must not happen is the
/// tick picking it up and putting a transaction on the wire on an operator's
/// behalf: it names the record, leaves it exactly as found, and reports against
/// that binding.
#[tokio::test]
async fn the_lease_tick_refuses_to_drive_an_operation_it_did_not_open() {
    let harness = harness("not-mine").await;
    let config = scheduler_config();
    let hub = &harness.hub;
    let chain = &harness.chain;

    // An operator's own renewal, named the way the pilot CLI names one.
    let now = now_unix();
    let operator = HvmLeaseRenewalRequestV1 {
        schema: HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
        operation_id: "pilot-lease-operator-run".into(),
        idempotency_key: "pilot-lease-operator-run".into(),
        binding_commitment: chain.binding.commitment().unwrap(),
        renew_when_live_blocks_at_or_below: RENEW_AT_OR_BELOW,
        periods: config.periods,
        network_fee_zhu: config.network_fee_zhu,
        timestamp: now,
        gas_max: config.gas_max,
        created_unix: now,
    };
    let opened = hub.run_hvm_lease_renewal(operator).await.unwrap();
    assert_eq!(opened.status, "submitted");
    assert_eq!(chain.submitted(), 1);

    let (response, error) = pass(hub, &config).await;
    assert_eq!(
        response, None,
        "the tick adopted an operation it never opened"
    );
    let error = error.expect("the tick must refuse and say why");
    assert!(
        error.contains("pilot-lease-operator-run")
            && error.contains("not opened by the lease tick"),
        "the refusal must name the record and the reason, got: {error}"
    );
    assert_eq!(
        chain.submitted(),
        1,
        "the tick broadcast on an operator's operation"
    );

    harness.server.abort();
}
