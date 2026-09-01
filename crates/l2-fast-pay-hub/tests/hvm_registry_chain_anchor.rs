//! Reorg anchoring for shared HVM registry chain operations.
//!
//! A registry chain operation latches `Confirmed` at six confirmations. Until
//! the confirmation carries an exact canonical block anchor (height *and*
//! block hash), and until that anchor is re-checked, a reorg that moves the
//! transaction to a different block after the latch is invisible: the durable
//! record still claims finality for a block that no longer exists.
//!
//! These tests drive a real `HubState` against a mock fullnode and assert the
//! rule already proven in the Local Pilot journal
//! (`hvm_registry_pilot_state.rs`): a confirmation without a canonical anchor
//! is refused, and a moved anchor is a reorg.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    HVM_REGISTRY_LEASE_REQUEST_SCHEMA, HvmRegistryLeaseRenewalRequestV2,
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

fn anchor_a() -> String {
    "aa".repeat(32)
}

fn anchor_b() -> String {
    "bb".repeat(32)
}

fn capabilities(now: u64) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": {
            "transaction_submit_bound": true,
            "hpay_channel_registry_query": true
        },
        "chain": { "id": 7, "height": 900_000, "next_height": 900_001, "mainnet": false },
        "network": {
            "kind": NETWORK_KIND,
            "node_profile_id": PROFILE_ID,
            "block_1_hash": BLOCK_ONE,
            "instance_id": INSTANCE,
            "transaction_format_version": 2
        },
        "sync": { "tip_timestamp_unix": now, "max_tip_age_seconds": 3_600, "fresh": true },
        "actions": {
            "registered": [1, 2, 14, 40, 41, 44, 1041, 1044],
            "enabled": [1, 2, 14, 40, 41, 44, 1041, 1044]
        },
        "transactions": { "enabled": [2, 3] },
        "features": { "channel_unilateral_exit": false }
    })
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

fn snapshot(binding: &HvmRegistryBindingV2, live: u64, recover: u64) -> Value {
    json!({
        "ret": 0,
        "schema": HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
        "settlement_profile": HPAY_REGISTRY_SETTLEMENT_PROFILE,
        "chain_id": binding.chain_id,
        "network_instance_id": binding.network_instance_id,
        "observed_height": 900_000,
        "evaluation_height": 900_001,
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
            "g_locked": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "g_left_claimable": storage_entry(json!(0), live, recover),
            "g_hub_claimable": storage_entry(json!(0), live, recover),
            "g_open_count": storage_entry(json!(1), live, recover)
        },
        "channel": {
            "status": storage_entry(json!(2), live, recover),
            "channel_id": storage_entry(json!(binding.channel_id), live, recover),
            "reuse": storage_entry(json!(binding.reuse_version), live, recover),
            "deposit": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "paid": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "total": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "serial": storage_entry(json!(0), live, recover),
            "left_balance": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "hub_balance": storage_entry(json!(0), live, recover),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": storage_entry(json!(0), live, recover),
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
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
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

/// Mutable block evidence the mock fullnode reports for the accepted
/// transaction. `hash: None` models a node that omits the block hash.
#[derive(Clone)]
struct BlockEvidence {
    height: u64,
    hash: Option<String>,
    confirmations: u64,
}

/// What the mock fullnode's canonical block query reports. `None` models a
/// node that does not answer `/query/block/intro` at all, so a transaction
/// query that omits `block.hash` leaves nothing to anchor against.
#[derive(Clone)]
struct CanonicalBlock {
    hash: String,
    /// Whether the block at that height lists the accepted transaction. A
    /// block that does not contain it is not an anchor for it.
    contains_transaction: bool,
}

struct Harness {
    hub: HubState,
    binding_commitment: String,
    evidence: Arc<RwLock<BlockEvidence>>,
    submits: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

async fn harness(seed: &str, evidence: BlockEvidence) -> Harness {
    harness_with_canonical_block(seed, evidence, None).await
}

async fn harness_with_canonical_block(
    seed: &str,
    evidence: BlockEvidence,
    canonical: Option<CanonicalBlock>,
) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x41; 20])).to_readable();
    let bundle = signed_bundle(&format!("{seed}-left"), &hub_account, &contract);
    let expected_binding = bundle.binding.clone();
    let live = Arc::new(RwLock::new(snapshot(&bundle.binding, 10_000, 0)));
    let accepted_body = Arc::new(RwLock::new(String::new()));
    let accepted_hash = Arc::new(RwLock::new(String::new()));
    let evidence = Arc::new(RwLock::new(evidence));
    let submits = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-registry",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let expected = expected_binding.clone();
                    async move {
                        let exact = query.get("contract") == Some(&expected.contract_address)
                            && query.get("deployment_tx_hash")
                                == Some(&expected.deployment_tx_hash)
                            && query.get("deployment_height")
                                == Some(&expected.deployment_height.to_string())
                            && query.get("left") == Some(&expected.left_address);
                        if exact {
                            (StatusCode::OK, Json(live.read().await.clone()))
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"ret": 1, "err": "binding mismatch"})),
                            )
                        }
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let live = live.clone();
                let accepted_body = accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                let submits = submits.clone();
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
                        // The renewal postcondition demands every lease credit
                        // strictly increase, so the mock grants them here.
                        let mut current = live.write().await;
                        current["minimum_live_blocks"] = json!(20_000);
                        current["minimum_recover_blocks"] = json!(30_000);
                        for group in ["registry", "channel"] {
                            for entry in current[group].as_object_mut().unwrap().values_mut() {
                                entry["live_blocks"] = json!(20_000);
                                entry["recover_blocks"] = json!(30_000);
                                entry["active"] = json!(true);
                                entry["recoverable"] = json!(false);
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
                let accepted_body = accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                let evidence = evidence.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let evidence = evidence.clone();
                    async move {
                        let body = accepted_body.read().await.clone();
                        let hash = accepted_hash.read().await.clone();
                        if body.is_empty() || query.get("hash") != Some(&hash) {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        }
                        let evidence = evidence.read().await.clone();
                        let mut block = json!({ "height": evidence.height });
                        if let Some(anchor) = evidence.hash {
                            block["hash"] = json!(anchor);
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 1041}, {"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": block,
                            "confirm": evidence.confirmations
                        }))
                    }
                }
            }),
        )
        .route(
            "/query/block/intro",
            get({
                let accepted_hash = accepted_hash.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_hash = accepted_hash.clone();
                    let canonical = canonical.clone();
                    async move {
                        let Some(canonical) = canonical else {
                            return (
                                StatusCode::NOT_FOUND,
                                Json(json!({"ret": 1, "err": "no canonical block"})),
                            );
                        };
                        let height: u64 = query
                            .get("height")
                            .and_then(|height| height.parse().ok())
                            .unwrap_or_default();
                        let listed = if canonical.contains_transaction {
                            accepted_hash.read().await.clone()
                        } else {
                            "cc".repeat(32)
                        };
                        (
                            StatusCode::OK,
                            Json(json!({
                                "ret": 0,
                                "height": height,
                                "hash": canonical.hash,
                                "tx_hash_list": [listed],
                            })),
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let state_path = directory.path().join("registry-anchor-state.json");
    let hub = HubState::new_secure_with_policy(
        "registry anchor",
        bundle.binding.right_hub_address.clone(),
        format!("http://{address}"),
        None,
        state_path,
        hex::encode(hub_account.secret_key().serialize()),
        &"92".repeat(32),
        &"93".repeat(32),
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 0)
        .await
        .unwrap();
    let binding_commitment = bundle.binding.commitment().unwrap();
    Harness {
        hub,
        binding_commitment,
        evidence,
        submits,
        server,
        _directory: directory,
    }
}

fn renewal(binding_commitment: &str, now: u64) -> HvmRegistryLeaseRenewalRequestV2 {
    HvmRegistryLeaseRenewalRequestV2 {
        schema: HVM_REGISTRY_LEASE_REQUEST_SCHEMA.into(),
        operation_id: "registry-anchor-renewal-1".into(),
        idempotency_key: "registry-anchor-renewal-idempotency-1".into(),
        binding_commitment: binding_commitment.into(),
        renew_when_blocks_at_or_below: 1,
        periods: 100,
        network_fee_zhu: 10_000,
        timestamp: now,
        gas_max: u8::MAX,
        created_unix: now,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A six-confirmation observation that carries no canonical block hash is not
/// finality evidence: without an anchor there is nothing a later reorg could
/// be compared against, so the operation must refuse to latch `Confirmed`.
#[tokio::test]
async fn registry_chain_confirmation_without_a_block_anchor_is_refused() {
    let harness = harness(
        "anchor-missing",
        BlockEvidence {
            height: 900_010,
            hash: None,
            confirmations: 6,
        },
    )
    .await;
    let now = now_unix();
    let response = harness
        .hub
        .run_hvm_registry_lease_renewal(renewal(&harness.binding_commitment, now))
        .await
        .unwrap();
    assert_eq!(
        response.status, "recovery_required",
        "an unanchored confirmation must never latch Confirmed"
    );
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);
    harness.server.abort();
}

/// The exact rule proven in the Local Pilot journal: once a confirmation is
/// anchored, an observation that moves the transaction to a different block is
/// a reorg, and a reorg after the six-confirmation latch must be detected.
#[tokio::test]
async fn registry_chain_detects_a_reorg_after_the_confirmation_latch() {
    let harness = harness(
        "anchor-reorg",
        BlockEvidence {
            height: 900_010,
            hash: Some(anchor_a()),
            confirmations: 6,
        },
    )
    .await;
    let now = now_unix();
    let request = renewal(&harness.binding_commitment, now);
    let operation_id = request.operation_id.clone();
    let response = harness
        .hub
        .run_hvm_registry_lease_renewal(request)
        .await
        .unwrap();
    assert_eq!(response.status, "confirmed");
    assert_eq!(response.confirmed_block_height, Some(900_010));

    // The chain reorganises: the very same transaction is now reported in a
    // different block. The durable record still claims finality in 900_010.
    *harness.evidence.write().await = BlockEvidence {
        height: 900_011,
        hash: Some(anchor_b()),
        confirmations: 6,
    };
    let reconciled = harness
        .hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(
        reconciled.status, "recovery_required",
        "a confirmed registry operation whose block anchor moved is a reorg"
    );
    harness.server.abort();
}

/// A reorg that keeps the height but replaces the block is still a reorg. The
/// height alone is not an anchor.
#[tokio::test]
async fn registry_chain_detects_a_same_height_block_replacement() {
    let harness = harness(
        "anchor-replace",
        BlockEvidence {
            height: 900_010,
            hash: Some(anchor_a()),
            confirmations: 6,
        },
    )
    .await;
    let now = now_unix();
    let request = renewal(&harness.binding_commitment, now);
    let operation_id = request.operation_id.clone();
    assert_eq!(
        harness
            .hub
            .run_hvm_registry_lease_renewal(request)
            .await
            .unwrap()
            .status,
        "confirmed"
    );
    *harness.evidence.write().await = BlockEvidence {
        height: 900_010,
        hash: Some(anchor_b()),
        confirmations: 6,
    };
    let reconciled = harness
        .hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(
        reconciled.status, "recovery_required",
        "the same height in a different block is a reorg"
    );
    harness.server.abort();
}

/// The anchor check must not be a false alarm: re-reconciling against the same
/// block must leave the confirmed operation exactly where it was.
#[tokio::test]
async fn registry_chain_keeps_confirmed_when_the_anchor_is_unchanged() {
    let harness = harness(
        "anchor-stable",
        BlockEvidence {
            height: 900_010,
            hash: Some(anchor_a()),
            confirmations: 6,
        },
    )
    .await;
    let now = now_unix();
    let request = renewal(&harness.binding_commitment, now);
    let operation_id = request.operation_id.clone();
    assert_eq!(
        harness
            .hub
            .run_hvm_registry_lease_renewal(request)
            .await
            .unwrap()
            .status,
        "confirmed"
    );
    *harness.evidence.write().await = BlockEvidence {
        height: 900_010,
        hash: Some(anchor_a()),
        confirmations: 12,
    };
    let reconciled = harness
        .hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(reconciled.status, "confirmed");
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);
    harness.server.abort();
}

/// This chain's fullnode answers `/query/transaction` with a `block` object
/// that carries only `height` and `timestamp` — there is no `block.hash` to
/// read. Because a confirmation without an anchor is refused, every Hub-side
/// registry chain operation used to latch `RecoveryRequired` the moment its
/// transaction was mined, which put lease renewal, challenge, respond,
/// finalize and the Action 14 claim permanently out of reach on a real node.
///
/// The anchor must therefore be resolved from the canonical block itself,
/// which also proves that block contains this exact transaction exactly once.
#[tokio::test]
async fn registry_chain_anchors_a_confirmation_from_the_canonical_block() {
    let harness = harness_with_canonical_block(
        "anchor-from-block",
        BlockEvidence {
            height: 900_010,
            hash: None,
            confirmations: 6,
        },
        Some(CanonicalBlock {
            hash: anchor_a(),
            contains_transaction: true,
        }),
    )
    .await;
    let now = now_unix();
    let request = renewal(&harness.binding_commitment, now);
    let operation_id = request.operation_id.clone();
    let response = harness
        .hub
        .run_hvm_registry_lease_renewal(request)
        .await
        .unwrap();
    assert_eq!(
        response.status, "confirmed",
        "a node that omits block.hash must still anchor from its canonical block"
    );
    assert_eq!(response.confirmed_block_height, Some(900_010));
    assert_eq!(harness.submits.load(Ordering::SeqCst), 1);

    // The adopted anchor is the canonical one, so a reorg is still detected
    // against it rather than against nothing.
    *harness.evidence.write().await = BlockEvidence {
        height: 900_011,
        hash: None,
        confirmations: 6,
    };
    let reconciled = harness
        .hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(
        reconciled.status, "recovery_required",
        "an anchor resolved from the canonical block must still catch a reorg"
    );
    harness.server.abort();
}

/// The canonical block is only an anchor for a transaction it actually
/// contains. A block that does not list the transaction must never be adopted
/// as its finality evidence.
#[tokio::test]
async fn registry_chain_refuses_a_canonical_block_without_the_transaction() {
    let harness = harness_with_canonical_block(
        "anchor-not-in-block",
        BlockEvidence {
            height: 900_010,
            hash: None,
            confirmations: 6,
        },
        Some(CanonicalBlock {
            hash: anchor_a(),
            contains_transaction: false,
        }),
    )
    .await;
    let now = now_unix();
    let response = harness
        .hub
        .run_hvm_registry_lease_renewal(renewal(&harness.binding_commitment, now))
        .await
        .unwrap();
    assert_eq!(
        response.status, "recovery_required",
        "a block that does not contain the transaction is not its anchor"
    );
    harness.server.abort();
}

/// A chain operation's committed transaction timestamp must be readable back
/// exactly.
///
/// The Local Pilot CLI rebuilds its request on every invocation, and the Hub
/// refuses a retry whose request commitment changed, so the timestamp has to
/// be identical across invocations. Deriving it from a hashed constant window
/// bought that stability at the price of correctness: the window reached to
/// 1_800_000_000, and the fullnode rejects any transaction whose timestamp
/// exceeds its own clock, so a share of operations could never be submitted.
/// Reading the committed value back is what lets the first attempt use the
/// real clock and every later attempt still rebuild identical bytes.
#[tokio::test]
async fn registry_chain_commits_a_readable_non_future_transaction_time() {
    let harness = harness(
        "request-time",
        BlockEvidence {
            height: 900_010,
            hash: Some(anchor_a()),
            confirmations: 6,
        },
    )
    .await;
    let now = now_unix();
    let request = renewal(&harness.binding_commitment, now);
    let operation_id = request.operation_id.clone();
    let committed_time = request.timestamp;
    assert_eq!(
        harness
            .hub
            .run_hvm_registry_lease_renewal(request)
            .await
            .unwrap()
            .status,
        "confirmed"
    );

    let readback = harness
        .hub
        .hvm_registry_chain_operation_request_clock(&operation_id)
        .unwrap();
    assert_eq!(
        readback,
        Some((committed_time, committed_time)),
        "a rebuilt request can only match the durable one if both committed \
         clock fields read back exactly"
    );
    assert!(
        committed_time <= now_unix(),
        "a committed transaction timestamp must never be in the future"
    );
    assert_eq!(
        harness
            .hub
            .hvm_registry_chain_operation_request_clock("registry-lease-never-created")
            .unwrap(),
        None,
        "a first attempt has nothing to read back and must fall through to the clock"
    );
    harness.server.abort();
}
