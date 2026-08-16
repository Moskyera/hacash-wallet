//! Action 14 claim: the last step of the chain of custody.
//!
//! `settle()` inside `hpay_channel_registry_v2.fitsh` only rewrites counters —
//! `g_locked`, `g_left_claimable`, `g_hub_claimable`, `g_open_count`,
//! `c_status_`. The coin itself stays inside the contract until an Action 14
//! `HacFromToTrs` whose `from` is the contract reaches the `PermitHAC` hook.
//! These tests drive that final step against a mock fullnode.
//!
//! Claims are permissionless: Action 14 declares `req_sign = [self.from]`, but
//! `TransactionType3::intrinsic_req_sign` only adds an address to the required
//! signer set when it `is_privakey()`, and a contract address is not. The
//! contract therefore never signs — the hook *is* its consent — and anybody
//! willing to pay the fee can trigger the payout. Every test here has to hold
//! when somebody else claims first.

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
    HvmRegistryWatchtowerRequestV2, read_exact_registry_claim_transaction,
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
const DEPOSIT_ZHU: u64 = 1_000_000;
const OBSERVED_HEIGHT: u64 = 900_000;

fn block_anchor() -> String {
    "7e".repeat(32)
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
/// this exact shape, so the Hub joins the lifecycle here and the tests move
/// the contract forward afterwards.
fn open_snapshot(binding: &HvmRegistryBindingV2) -> Value {
    let mut snapshot = settled_snapshot(binding);
    snapshot["registry"]["g_locked"]["value"] = json!(DEPOSIT_ZHU);
    snapshot["registry"]["g_left_claimable"]["value"] = json!(0);
    snapshot["registry"]["g_open_count"]["value"] = json!(1);
    snapshot["channel"]["status"]["value"] = json!(2);
    snapshot["channel"]["serial"]["value"] = json!(0);
    snapshot["channel"]["deadline"]["value"] = json!(0);
    snapshot
}

/// A channel that has already been finalised: FINAL status, the settled
/// balances still recorded, and `c_left_claimed_` still false because nothing
/// has moved the coin yet.
fn settled_snapshot(binding: &HvmRegistryBindingV2) -> Value {
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
            // settle() already moved the deposit out of g_locked and into the
            // left party's claimable credit. Nothing has been paid out.
            "g_locked": storage_entry(json!(0), live, recover),
            "g_left_claimable": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "g_hub_claimable": storage_entry(json!(0), live, recover),
            "g_open_count": storage_entry(json!(0), live, recover)
        },
        "channel": {
            "status": storage_entry(json!(4), live, recover),
            "channel_id": storage_entry(json!(binding.channel_id), live, recover),
            "reuse": storage_entry(json!(binding.reuse_version), live, recover),
            "deposit": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "paid": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "total": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "serial": storage_entry(json!(1), live, recover),
            "left_balance": storage_entry(json!(DEPOSIT_ZHU), live, recover),
            "hub_balance": storage_entry(json!(0), live, recover),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": storage_entry(json!(OBSERVED_HEIGHT - 10), live, recover),
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

/// What the mock fullnode reports for the submitted transaction. `None` means
/// "transaction not found" — our own payout never made it on chain.
#[derive(Clone)]
struct Observation {
    height: u64,
    hash: String,
    confirmations: u64,
}

struct Mock {
    live: Arc<RwLock<Value>>,
    observation: Arc<RwLock<Option<Observation>>>,
    accepted_body: Arc<RwLock<String>>,
    submits: Arc<AtomicUsize>,
    /// Once the registry has been read this many times, every later read
    /// reports `c_left_claimed_` as true. This is the only way to model a
    /// third party claiming *between* the watchtower's decision read and the
    /// resume that follows it, inside a single call. The decision snapshot is
    /// structurally the first registry read, so a value of 1 means "the
    /// decision saw an unclaimed channel, everything afterwards did not".
    flip_claimed_after_reads: Arc<RwLock<Option<usize>>>,
    reads: Arc<AtomicUsize>,
    /// Model the contract executing our own payout when we submit.
    claim_on_submit: Arc<RwLock<bool>>,
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
            "registry claim",
            self.binding.right_hub_address.clone(),
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

    async fn set_claimed(&self, claimed: bool) {
        self.mock.live.write().await["channel"]["left_claimed"]["value"] = json!(claimed);
    }

    fn submits(&self) -> usize {
        self.mock.submits.load(Ordering::SeqCst)
    }
}

async fn harness(seed: &str) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by(&format!("{seed}-hub")).unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x5a; 20])).to_readable();
    let bundle = signed_bundle(&format!("{seed}-left"), &hub_account, &contract);
    let expected_binding = bundle.binding.clone();
    let mock = Mock {
        live: Arc::new(RwLock::new(open_snapshot(&bundle.binding))),
        observation: Arc::new(RwLock::new(None)),
        accepted_body: Arc::new(RwLock::new(String::new())),
        submits: Arc::new(AtomicUsize::new(0)),
        flip_claimed_after_reads: Arc::new(RwLock::new(None)),
        reads: Arc::new(AtomicUsize::new(0)),
        claim_on_submit: Arc::new(RwLock::new(false)),
    };
    let accepted_hash = Arc::new(RwLock::new(String::new()));

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
                let flip = mock.flip_claimed_after_reads.clone();
                let reads = mock.reads.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let flip = flip.clone();
                    let reads = reads.clone();
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
                        let seen = reads.fetch_add(1, Ordering::SeqCst) + 1;
                        let mut snapshot = live.read().await.clone();
                        if let Some(after) = *flip.read().await
                            && seen > after
                        {
                            snapshot["channel"]["left_claimed"]["value"] = json!(true);
                        }
                        (StatusCode::OK, Json(snapshot))
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let live = mock.live.clone();
                let accepted_body = mock.accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                let submits = mock.submits.clone();
                let claim_on_submit = mock.claim_on_submit.clone();
                move |body: String| {
                    let live = live.clone();
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let submits = submits.clone();
                    let claim_on_submit = claim_on_submit.clone();
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
                        if *claim_on_submit.read().await {
                            // What PermitHAC does: mark the single-shot flag.
                            // c_left_balance_ is deliberately left alone, just
                            // as the contract leaves it.
                            live.write().await["channel"]["left_claimed"]["value"] = json!(true);
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
                let accepted_hash = accepted_hash.clone();
                let observation = mock.observation.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let observation = observation.clone();
                    async move {
                        let body = accepted_body.read().await.clone();
                        let hash = accepted_hash.read().await.clone();
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
                            // A claim proves itself with Action 14. There is no
                            // Action 44 anywhere in this transaction.
                            "actions": [{"kind": 1041}, {"kind": 14}],
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
        state_path: directory.path().join("registry-claim-state.json"),
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
    // The channel now runs its course off chain and is finalised: settle() has
    // credited g_left_claimable and set FINAL, and the principal is sitting in
    // the contract with c_left_claimed_ still false.
    *harness.mock.live.write().await = settled_snapshot(&bundle.binding);
    harness.mock.reads.store(0, Ordering::SeqCst);
    harness
}

fn monitor(binding_commitment: &str, suffix: &str, now: u64) -> HvmRegistryWatchtowerRequestV2 {
    HvmRegistryWatchtowerRequestV2 {
        schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: format!("registry-claim-{suffix}"),
        idempotency_key: format!("registry-claim-idempotency-{suffix}"),
        binding_commitment: binding_commitment.into(),
        mode: HvmRegistryWatchtowerModeV2::Monitor,
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

/// The gap this work closes: after finalize the contract has done its
/// accounting and stopped. The watchtower now walks the principal back out
/// with an Action 14 payout, and the bytes it submits are exactly that payout.
#[tokio::test]
async fn a_finalized_registry_channel_walks_its_principal_back_out_with_action_14() {
    let harness = harness("claim-happy").await;
    *harness.mock.claim_on_submit.write().await = true;
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 6,
    });
    let hub = harness.hub();
    let response = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "happy", now_unix()))
        .await
        .unwrap();
    assert_eq!(response.action, "claim");
    assert_eq!(response.status, "confirmed");
    assert_eq!(response.observed_confirmations, 6);
    assert_eq!(harness.submits(), 1);

    // The bytes that actually went to the node are the exact approved payout:
    // Type 3, a chain guard, and one Action 14 drawing from the contract to
    // the left party for exactly c_left_balance_.
    let body = harness.mock.accepted_body.read().await.clone();
    read_exact_registry_claim_transaction(
        &body,
        &harness.binding,
        &harness.binding.left_address,
        DEPOSIT_ZHU,
    )
    .unwrap();
    let raw = hex::decode(&body).unwrap();
    let (transaction, _) = protocol::transaction::transaction_create(&raw).unwrap();
    assert_eq!(transaction.ty(), 3);
    let kinds = transaction
        .actions()
        .iter()
        .map(|action| action.kind())
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec![0x0411, 14], "a claim has no Action 44");

    // A payout of a different amount is not this transaction.
    assert!(
        read_exact_registry_claim_transaction(
            &body,
            &harness.binding,
            &harness.binding.left_address,
            DEPOSIT_ZHU - 1,
        )
        .is_err()
    );
    harness.server.abort();
}

/// Claims are permissionless, so a third party can pay the payee first. When
/// the contract already records the exact payout, this Hub must observe that
/// and resolve — never sign and broadcast a second payout for the same coin.
#[tokio::test]
async fn a_third_party_claim_settles_our_claim_without_signing_a_second_payout() {
    let harness = harness("claim-raced").await;
    // Unclaimed at the decision read; claimed from the very next read on.
    *harness.mock.flip_claimed_after_reads.write().await = Some(1);
    let hub = harness.hub();
    let response = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "raced", now_unix()))
        .await
        .unwrap();
    assert_eq!(response.action, "claim");
    assert_eq!(
        response.status, "confirmed",
        "an already-paid claim resolves; it does not fail into recovery"
    );
    assert_eq!(
        response.transaction_hash, None,
        "no transaction of ours exists, so none is claimed"
    );
    assert_eq!(
        harness.submits(),
        0,
        "the coin already moved; a second payout must never be broadcast"
    );

    // And a fresh monitor pass finds nothing left to do at all.
    harness.set_claimed(true).await;
    *harness.mock.flip_claimed_after_reads.write().await = None;
    let again = hub
        .run_hvm_registry_watchtower(monitor(&harness.binding_commitment, "raced-2", now_unix()))
        .await
        .unwrap();
    assert_eq!(again.status, "no_action");
    assert_eq!(harness.submits(), 0);
    harness.server.abort();
}

/// Our claim was broadcast and then dropped, while somebody else's landed.
/// The chain of custody is complete, so the operation resolves on the
/// contract's own `c_left_claimed_` evidence instead of latching recovery and
/// instead of resubmitting.
#[tokio::test]
async fn a_dropped_claim_settles_on_the_payout_that_did_land() {
    let harness = harness("claim-dropped").await;
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 2,
    });
    let hub = harness.hub();
    let request = monitor(&harness.binding_commitment, "dropped", now_unix());
    let operation_id = request.operation_id.clone();
    let response = hub.run_hvm_registry_watchtower(request).await.unwrap();
    assert_eq!(response.status, "submitted");
    assert_eq!(harness.submits(), 1);

    // Our transaction vanishes; a third party's payout lands instead.
    *harness.mock.observation.write().await = None;
    harness.set_claimed(true).await;
    let reconciled = hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(
        reconciled.status, "confirmed",
        "the payee holds the exact amount; that is not a recovery situation"
    );
    assert_eq!(
        harness.submits(),
        1,
        "the payout already happened, so nothing is resubmitted"
    );

    // Re-reconciling stays put and still never resubmits.
    assert_eq!(
        hub.reconcile_hvm_registry_chain_operation(&operation_id, false)
            .await
            .unwrap()
            .status,
        "confirmed"
    );
    assert_eq!(harness.submits(), 1);
    harness.server.abort();
}

/// A crash between submitting the payout and seeing it confirmed must not
/// produce a second payout. The durable record carries the exact signed bytes
/// across the restart and the reopened Hub reconciles the same transaction.
#[tokio::test]
async fn a_claim_is_recovered_after_a_crash_between_submit_and_confirm() {
    let harness = harness("claim-crash").await;
    *harness.mock.claim_on_submit.write().await = true;
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 2,
    });
    let request = monitor(&harness.binding_commitment, "crash", now_unix());
    let operation_id = request.operation_id.clone();
    let submitted_hash;
    {
        let hub = harness.hub();
        let response = hub.run_hvm_registry_watchtower(request).await.unwrap();
        assert_eq!(response.action, "claim");
        assert_eq!(response.status, "submitted");
        submitted_hash = response.transaction_hash.clone().unwrap();
        assert_eq!(harness.submits(), 1);
        // The process dies here, after the node accepted the payout but
        // before six confirmations were ever observed.
    }

    let reopened = harness.hub();
    assert_eq!(
        reopened
            .hvm_registry_chain_operation_status(&operation_id)
            .unwrap()
            .unwrap()
            .status,
        "submitted",
        "the durable record survives the crash"
    );
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 6,
    });
    let reconciled = reopened
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(reconciled.status, "confirmed");
    assert_eq!(reconciled.transaction_hash, Some(submitted_hash));
    assert_eq!(
        harness.submits(),
        1,
        "recovery reconciles the same payout; it never signs a second one"
    );
    harness.server.abort();
}

/// The claimable amount is read off the contract and never guessed. If the
/// contract stops agreeing that this exact amount was paid to this exact
/// payee, the operation refuses rather than accepting the payout as good.
#[tokio::test]
async fn a_claim_refuses_a_payout_the_contract_does_not_confirm_exactly() {
    let harness = harness("claim-inexact").await;
    *harness.mock.claim_on_submit.write().await = true;
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 2,
    });
    let hub = harness.hub();
    let request = monitor(&harness.binding_commitment, "inexact", now_unix());
    let operation_id = request.operation_id.clone();
    assert_eq!(
        hub.run_hvm_registry_watchtower(request)
            .await
            .unwrap()
            .status,
        "submitted"
    );

    // The contract now reports a different settled split than the one this
    // claim was approved for. The deposit total still adds up, so nothing
    // upstream objects — only the claim's own exactness check can catch that
    // `c_left_balance_` is no longer the amount that was paid out.
    {
        let mut live = harness.mock.live.write().await;
        live["channel"]["left_balance"]["value"] = json!(DEPOSIT_ZHU - 1);
        live["channel"]["hub_balance"]["value"] = json!(1);
    }
    *harness.mock.observation.write().await = Some(Observation {
        height: OBSERVED_HEIGHT + 1,
        hash: block_anchor(),
        confirmations: 6,
    });
    let reconciled = hub
        .reconcile_hvm_registry_chain_operation(&operation_id, false)
        .await
        .unwrap();
    assert_eq!(
        reconciled.status, "recovery_required",
        "an inexact claimable amount is refused, never accepted as close enough"
    );
    harness.server.abort();
}
