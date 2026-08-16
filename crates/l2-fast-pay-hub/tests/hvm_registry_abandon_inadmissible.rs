//! Abandoning a durable chain operation that provably cannot have executed.
//!
//! Two live runs on the private chain-7 pilot produced the situation these
//! tests reproduce. A `finalize` was signed carrying a timestamp far in the
//! future, the fullnode refused it, and the refusal left a durable
//! `RecoveryRequired` record. From that moment `ensure_settlement_ready`
//! refused every new chain operation and the Hub was latched for good:
//! `reconcile --allow-exact-resubmit` can only resubmit the identical bytes,
//! which carry the identical impossible timestamp, and the channel slot cannot
//! be re-initialised because `HPAYChannelRegistryV2` keys it by the left
//! address and demands `FINAL` plus `c_left_claimed_`.
//!
//! Abandoning a chain operation is the most dangerous thing a Hub could do:
//! if the transaction *did* execute, the replacement double-submits. So the
//! capability under test never rests on "we did not observe it". It rests on
//! a consensus rule under which the exact stored bytes cannot be inside a
//! valid block:
//!
//!   * `chain/src/check.rs:103` refuses a future timestamp at submission, and
//!   * `chain/src/verify.rs:75`  refuses any *block* that carries one.
//!
//! The second half is what makes it structural rather than observational.
//! On top of that proof the operation is still read from the chain one last
//! time and required to be absent — belt and braces.
//!
//! What each test pins down:
//!   * a transaction that could still be valid is REFUSED abandonment;
//!   * a provably future-dated transaction is abandoned and releases the latch;
//!   * a fresh operation is then permitted and carries a real clock reading;
//!   * the abandoned record is terminal across restart, reconciliation and
//!     `--allow-exact-resubmit`;
//!   * a transaction that is observable on chain is refused even when the
//!     proof holds.

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
    HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA, HvmRegistryWatchtowerModeV2,
    HvmRegistryWatchtowerRequestV2,
};
use l2_fast_pay_hub::journal::{AuthenticatedJournal, JournalBinding, JournalPhase};
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
/// The exact shape of the live defect: a timestamp derived from a constant
/// plus a hash instead of read from a clock landed 54 days ahead.
const FUTURE_SKEW_SECONDS: u64 = 54 * 86_400;

fn block_anchor() -> String {
    "3f".repeat(32)
}

fn journal_key_hex() -> String {
    "92".repeat(32)
}

fn capabilities(now: u64) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": {
            "transaction_submit_bound": true,
            "hpay_channel_registry_query": true
        },
        "chain": { "id": 7, "height": OBSERVED_HEIGHT, "next_height": OBSERVED_HEIGHT + 1, "mainnet": false },
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

/// A freshly opened channel. A registry activation is only admitted against
/// this exact shape, so the Hub joins the lifecycle here.
fn open_snapshot(binding: &HvmRegistryBindingV2) -> Value {
    let mut snapshot = challenging_snapshot(binding);
    snapshot["channel"]["status"]["value"] = json!(2);
    snapshot["channel"]["serial"]["value"] = json!(0);
    snapshot["channel"]["deadline"]["value"] = json!(0);
    snapshot
}

/// The exact live situation: CHALLENGING, the chain agreeing with the latest
/// fully signed bill, and the challenge deadline already behind the observed
/// height. That is the watchtower's `Finalize` decision.
fn challenging_snapshot(binding: &HvmRegistryBindingV2) -> Value {
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
            "serial": storage_entry(json!(1), live, recover),
            "left_balance": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "hub_balance": storage_entry(json!(0), live, recover),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": storage_entry(json!(OBSERVED_HEIGHT - 8), live, recover),
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

/// How the mock fullnode answers `/submit/transaction/hpay-bound`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubmitOutcome {
    /// The exact refusal `chain/src/check.rs` produces for a future timestamp.
    RefuseFutureTimestamp,
    /// A refusal that says nothing about admissibility: the node was busy.
    RefuseTransient,
    /// Accepted, and the contract executes `finalize()`.
    AcceptAndFinalize,
}

/// What `/query/transaction` reports for the bytes the Hub last submitted.
/// `None` is "transaction not found" — our transaction is nowhere on chain.
#[derive(Clone)]
struct Observation {
    height: u64,
    hash: String,
    confirmations: u64,
}

struct Mock {
    live: Arc<RwLock<Value>>,
    submit: Arc<RwLock<SubmitOutcome>>,
    observation: Arc<RwLock<Option<Observation>>>,
    /// The last bytes offered to the node, recorded even when the node refuses
    /// them, so a test can later pretend those exact bytes were mined.
    offered_body: Arc<RwLock<String>>,
    offered_hash: Arc<RwLock<String>>,
    submits: Arc<AtomicUsize>,
}

struct Harness {
    binding: HvmRegistryBindingV2,
    binding_commitment: String,
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
            "registry abandon",
            self.binding.right_hub_address.clone(),
            self.node_url.clone(),
            None,
            self.state_path.clone(),
            self.hub_secret_hex.clone(),
            &journal_key_hex(),
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

    async fn set_submit(&self, outcome: SubmitOutcome) {
        *self.mock.submit.write().await = outcome;
    }

    async fn set_observation(&self, observation: Option<Observation>) {
        *self.mock.observation.write().await = observation;
    }

    fn journal_phases(&self) -> Vec<JournalPhase> {
        let mut key = [0_u8; 32];
        hex::decode_to_slice(journal_key_hex(), &mut key).unwrap();
        let journal = AuthenticatedJournal::open(
            self.state_path.with_extension("journal.jsonl"),
            &key,
            JournalBinding {
                wallet_scope: format!("hub:{}", self.binding.right_hub_address),
                hub_or_provider_identity: self.binding.right_hub_address.clone(),
                channel_id: None,
            },
        )
        .unwrap();
        journal
            .verify()
            .unwrap()
            .iter()
            .map(|record| record.operation_phase)
            .collect()
    }
}

async fn harness(seed: &str) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x6b; 20])).to_readable();
    let bundle = signed_bundle(&format!("{seed}-left"), &hub_account, &contract);
    let expected_binding = bundle.binding.clone();
    let mock = Mock {
        live: Arc::new(RwLock::new(open_snapshot(&bundle.binding))),
        submit: Arc::new(RwLock::new(SubmitOutcome::AcceptAndFinalize)),
        observation: Arc::new(RwLock::new(None)),
        offered_body: Arc::new(RwLock::new(String::new())),
        offered_hash: Arc::new(RwLock::new(String::new())),
        submits: Arc::new(AtomicUsize::new(0)),
    };

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
                let live = mock.live.clone();
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
                        if !exact {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"ret": 1, "err": "binding mismatch"})),
                            );
                        }
                        (StatusCode::OK, Json(live.read().await.clone()))
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let live = mock.live.clone();
                let submit = mock.submit.clone();
                let offered_body = mock.offered_body.clone();
                let offered_hash = mock.offered_hash.clone();
                let submits = mock.submits.clone();
                move |body: String| {
                    let live = live.clone();
                    let submit = submit.clone();
                    let offered_body = offered_body.clone();
                    let offered_hash = offered_hash.clone();
                    let submits = submits.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        submits.fetch_add(1, Ordering::SeqCst);
                        // Recorded even on refusal: these are the exact bytes
                        // the node was offered, and a later test needs them.
                        *offered_body.write().await = body;
                        *offered_hash.write().await = hash.clone();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        match *submit.read().await {
                            SubmitOutcome::RefuseFutureTimestamp => {
                                // Verbatim shape of chain/src/check.rs:103.
                                let stamp = transaction.timestamp().uint();
                                assert!(stamp > now, "this outcome models the fullnode's own rule");
                                Json(json!({
                                    "ret": 1,
                                    "err": format!("tx timestamp {stamp} cannot exceed now {now}")
                                }))
                            }
                            SubmitOutcome::RefuseTransient => Json(json!({
                                "ret": 1,
                                "err": "fullnode transaction pool is temporarily unavailable"
                            })),
                            SubmitOutcome::AcceptAndFinalize => {
                                // What settle() does: FINAL, the split kept,
                                // the principal credited out of g_locked.
                                let mut current = live.write().await;
                                current["channel"]["status"]["value"] = json!(4);
                                current["registry"]["g_locked"]["value"] = json!(0);
                                current["registry"]["g_left_claimable"]["value"] =
                                    json!(DEPOSIT_ZHU);
                                current["registry"]["g_open_count"]["value"] = json!(0);
                                Json(json!({"ret": 0, "hash": hash}))
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let offered_body = mock.offered_body.clone();
                let offered_hash = mock.offered_hash.clone();
                let observation = mock.observation.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let offered_body = offered_body.clone();
                    let offered_hash = offered_hash.clone();
                    let observation = observation.clone();
                    async move {
                        let body = offered_body.read().await.clone();
                        let hash = offered_hash.read().await.clone();
                        let observation = observation.read().await.clone();
                        let (Some(observation), false) = (observation, body.is_empty()) else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        if query.get("hash") != Some(&hash) {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 1041}, {"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": {
                                "height": observation.height,
                                "hash": observation.hash
                            },
                            "confirm": observation.confirmations
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let harness = Harness {
        binding: bundle.binding.clone(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        node_url: format!("http://{address}"),
        state_path: directory.path().join("registry-abandon-state.json"),
        hub_secret_hex: hex::encode(hub_account.secret_key().serialize()),
        mock,
        server,
        _directory: directory,
    };
    harness
        .hub()
        .activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    // The channel now runs its course and the left party opens a challenge
    // that the Hub answered; the deadline has since passed, so the only thing
    // left to do is finalize.
    *harness.mock.live.write().await = challenging_snapshot(&bundle.binding);
    harness
}

fn monitor(
    binding_commitment: &str,
    suffix: &str,
    timestamp: u64,
) -> HvmRegistryWatchtowerRequestV2 {
    HvmRegistryWatchtowerRequestV2 {
        schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: format!("registry-abandon-{suffix}"),
        idempotency_key: format!("registry-abandon-idempotency-{suffix}"),
        binding_commitment: binding_commitment.into(),
        mode: HvmRegistryWatchtowerModeV2::Monitor,
        network_fee_zhu: 10_000,
        timestamp,
        gas_max: u8::MAX,
        created_unix: timestamp,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Reproduce the live defect exactly: a finalize signed with a timestamp 54
/// days ahead, refused by the node, latching the Hub.
async fn latched_by_a_future_timestamp(harness: &Harness, suffix: &str) -> (HubState, String) {
    harness
        .set_submit(SubmitOutcome::RefuseFutureTimestamp)
        .await;
    let hub = harness.hub();
    let request = monitor(
        &harness.binding_commitment,
        suffix,
        now_unix() + FUTURE_SKEW_SECONDS,
    );
    let operation_id = request.operation_id.clone();
    let response = hub.run_hvm_registry_watchtower(request).await.unwrap();
    assert_eq!(response.action, "finalize");
    assert_eq!(
        response.status, "recovery_required",
        "the node's refusal must leave a durable RecoveryRequired record"
    );
    (hub, operation_id)
}

/// A refusal that says nothing about admissibility. The bytes are perfectly
/// valid; only the node was busy. This is the case abandonment must never
/// touch.
async fn latched_by_a_transient_failure(harness: &Harness, suffix: &str) -> (HubState, String) {
    harness.set_submit(SubmitOutcome::RefuseTransient).await;
    let hub = harness.hub();
    let request = monitor(&harness.binding_commitment, suffix, now_unix());
    let operation_id = request.operation_id.clone();
    let response = hub.run_hvm_registry_watchtower(request).await.unwrap();
    assert_eq!(response.action, "finalize");
    assert_eq!(response.status, "recovery_required");
    (hub, operation_id)
}

fn status_of(hub: &HubState, operation_id: &str) -> String {
    hub.hvm_registry_chain_operation_status(operation_id)
        .unwrap()
        .expect("the durable record exists")
        .status
}

/// The whole reason the gate exists. A transaction whose bytes the chain could
/// still accept has not been proven to be anywhere; abandoning it would let a
/// replacement double-submit. It must be refused, and the durable record must
/// be left exactly as it was.
#[tokio::test]
async fn an_operation_whose_transaction_could_still_be_valid_is_refused_abandonment() {
    let harness = harness("still-valid").await;
    let (hub, operation_id) = latched_by_a_transient_failure(&harness, "still-valid").await;
    let submits_before = harness.submits();

    let error = hub
        .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .expect_err("a transaction that could still be mined must never be abandoned");
    let message = error.to_string();
    assert!(
        message.contains("no consensus rule proves"),
        "the refusal must name the missing proof, got: {message}"
    );

    assert_eq!(
        status_of(&hub, &operation_id),
        "recovery_required",
        "a refused abandonment must not move the durable record"
    );
    assert_eq!(
        harness.submits(),
        submits_before,
        "a refused abandonment must not touch the chain with these bytes"
    );
    // And the Hub is still latched, which is the correct, safe outcome here.
    let blocked = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "blocked", now_unix()))
        .await
        .expect_err("the latch stays up when nothing was proven");
    assert!(blocked.to_string().contains("RecoveryRequired"));
    harness.server.abort();
}

/// The situation the live runs produced. The stored bytes carry a timestamp
/// the fullnode refuses at submission *and* refuses inside a block, so they
/// cannot be in any block; the last chain read confirms they are not. The
/// operation moves to a terminal Abandoned state and the latch is released.
#[tokio::test]
async fn a_provably_future_dated_transaction_is_abandoned_and_releases_the_latch() {
    let harness = harness("future-dated").await;
    let (hub, operation_id) = latched_by_a_future_timestamp(&harness, "future-dated").await;

    // Exactly the dead end the live runs hit: resubmitting the identical bytes
    // cannot help, because they carry the identical impossible timestamp.
    let resubmitted = hub
        .reconcile_hvm_registry_chain_operation(&operation_id, true)
        .await
        .unwrap();
    assert_eq!(resubmitted.status, "recovery_required");

    // And every new operation is refused while the latch is up.
    let blocked = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "blocked", now_unix()))
        .await
        .expect_err("a latched Hub refuses every new chain operation");
    assert!(blocked.to_string().contains("RecoveryRequired"));

    let abandoned = hub
        .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .unwrap();
    assert_eq!(abandoned.status, "abandoned");
    assert_eq!(abandoned.action, "finalize");
    assert_eq!(
        abandoned.confirmed_block_height, None,
        "an abandoned operation owns no block"
    );

    // The transition is journalled like every other durable transition.
    assert!(
        harness
            .journal_phases()
            .contains(&JournalPhase::HvmChainAbandonedInadmissible),
        "the abandon must be recorded in the authenticated journal"
    );
    harness.server.abort();
}

/// The point of the whole capability: after the abandon a correct replacement
/// can be signed, and it carries a timestamp read from the real clock rather
/// than derived from a constant.
#[tokio::test]
async fn a_fresh_operation_succeeds_after_the_abandon_with_a_real_clock_timestamp() {
    let harness = harness("fresh-after").await;
    let (hub, operation_id) = latched_by_a_future_timestamp(&harness, "fresh-after").await;
    hub.abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .unwrap();

    harness.set_submit(SubmitOutcome::AcceptAndFinalize).await;
    harness
        .set_observation(Some(Observation {
            height: OBSERVED_HEIGHT + 1,
            hash: block_anchor(),
            confirmations: 6,
        }))
        .await;

    let before = now_unix();
    let fresh = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "replacement", before))
        .await
        .unwrap();
    let after = now_unix();
    assert_eq!(
        fresh.action, "finalize",
        "the replacement is the same operation the abandoned one was for"
    );
    assert_eq!(fresh.status, "confirmed");

    // The bytes that reached the node carry a real clock reading, and one the
    // fullnode's own rule accepts: not ahead of now.
    let body = harness.mock.offered_body.read().await.clone();
    let raw = hex::decode(&body).unwrap();
    let (transaction, _) = protocol::transaction::transaction_create(&raw).unwrap();
    let stamp = transaction.timestamp().uint();
    assert!(
        (before..=after).contains(&stamp),
        "the replacement timestamp {stamp} must be a real clock reading in [{before}, {after}]"
    );
    harness.server.abort();
}

/// Terminal means terminal. Not across a restart, not under reconciliation,
/// not under `--allow-exact-resubmit`, and not by driving the original request
/// again. The bytes were proven inadmissible once; nothing may ever offer them
/// to a node again.
#[tokio::test]
async fn an_abandoned_record_stays_terminal_and_is_never_resubmitted() {
    let harness = harness("terminal").await;
    let (hub, operation_id) = latched_by_a_future_timestamp(&harness, "terminal").await;
    hub.abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .unwrap();
    let submits_after_abandon = harness.submits();
    drop(hub);

    // Restart: the terminal state is durable, not in-process.
    let hub = harness.hub();
    assert_eq!(status_of(&hub, &operation_id), "abandoned");

    // Reconciliation, including the exact-resubmit escape hatch, must not
    // offer these bytes to the node again.
    let reconciled = hub
        .reconcile_hvm_registry_chain_operation(&operation_id, true)
        .await
        .unwrap();
    assert_eq!(reconciled.status, "abandoned");
    assert_eq!(
        harness.submits(),
        submits_after_abandon,
        "an abandoned transaction must never be resubmitted"
    );

    // Driving the original request again resolves to the terminal record.
    let replayed = hub
        .run_hvm_registry_watchtower(monitor(
            &harness.binding_commitment,
            "terminal",
            now_unix() + FUTURE_SKEW_SECONDS,
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status, "abandoned");
    assert_eq!(harness.submits(), submits_after_abandon);

    // Abandoning again is idempotent and still terminal.
    let again = hub
        .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .unwrap();
    assert_eq!(again.status, "abandoned");
    assert_eq!(status_of(&hub, &operation_id), "abandoned");
    harness.server.abort();
}

/// Belt and braces. The proof says the transaction cannot be in a block. If
/// the chain nevertheless reports it, the proof and the world disagree and the
/// only safe move is to refuse — never to abandon something that is visibly
/// on chain.
#[tokio::test]
async fn a_transaction_that_is_observable_on_chain_is_refused_even_with_a_proof() {
    let harness = harness("observable").await;
    let (hub, operation_id) = latched_by_a_future_timestamp(&harness, "observable").await;

    harness
        .set_observation(Some(Observation {
            height: OBSERVED_HEIGHT + 1,
            hash: block_anchor(),
            confirmations: 6,
        }))
        .await;

    let error = hub
        .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .expect_err("a transaction visible on chain must never be abandoned");
    assert!(
        error.to_string().contains("observable on chain"),
        "the refusal must name the observation, got: {error}"
    );
    assert_eq!(status_of(&hub, &operation_id), "recovery_required");
    harness.server.abort();
}

/// An operation that already reached finality did execute. There is no proof
/// that could make abandoning it safe, so the status check refuses before any
/// proof is even attempted.
#[tokio::test]
async fn a_confirmed_operation_can_never_be_abandoned() {
    let harness = harness("confirmed").await;
    harness
        .set_observation(Some(Observation {
            height: OBSERVED_HEIGHT + 1,
            hash: block_anchor(),
            confirmations: 6,
        }))
        .await;
    let hub = harness.hub();
    let request = monitor(&harness.binding_commitment, "confirmed", now_unix());
    let operation_id = request.operation_id.clone();
    let response = hub.run_hvm_registry_watchtower(request).await.unwrap();
    assert_eq!(response.status, "confirmed");

    let error = hub
        .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
        .await
        .expect_err("a confirmed operation executed; abandoning it is never safe");
    assert!(
        error.to_string().contains("Recovery Required"),
        "got: {error}"
    );
    assert_eq!(status_of(&hub, &operation_id), "confirmed");
    harness.server.abort();
}
