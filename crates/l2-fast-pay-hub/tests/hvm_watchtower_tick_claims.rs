//! The v1 watchtower driven by the Hub's own scheduler, end to end, including
//! the durable claim path that nothing automated used to cover.
//!
//! Two separate gaps meet in this file.
//!
//! The first is reachability. `decide_watchtower_action` grew a
//! `ClaimLeftPayout` arm because a finalized channel was measured holding
//! settled principal that no shipped code would release. The arm works — it was
//! proven once, by hand, on chain 7 — but the only caller of
//! `run_hvm_watchtower` outside the test tree was a CLI behind a non-default
//! feature. A Hub daemon compiled the decision and never asked it anything, so
//! an unattended Hub still claimed nothing. `hvm_watchtower_tick` is the
//! driver that closes that, and every test here drives it rather than the
//! decision function underneath it.
//!
//! The second is coverage. Between the pure decision at one end and the pure
//! transaction builder at the other sat the whole durable middle — the claim
//! branch of the signer, both claim preconditions, the postcondition, the
//! third-party settlement path and every claim rule in `validate_hvm_state` —
//! with no automated test touching any of it. These tests run through that
//! middle, and the state file is reopened afterwards so the durable record has
//! to survive validation on load rather than only on write.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
use l2_fast_pay_hub::hvm_scheduler::HvmLeaseSchedulerConfig;
use l2_fast_pay_hub::hvm_watchtower::{
    HVM_WATCHTOWER_REQUEST_SCHEMA, HvmWatchtowerMode, HvmWatchtowerRequestV1,
};
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
/// The exact zhu the finalized contract still holds for the left party. Chosen
/// to match the shape of the live chain-7 case this work came from: a whole
/// deposit sitting behind `left_claimed`.
const DEPOSIT_ZHU: u64 = 1_000_000;
const ACTIVATION_FLOOR_BLOCKS: u64 = 5_000;
const LIVE_BLOCKS: u64 = 20_000;
const RECOVER_BLOCKS: u64 = 20_000;
/// The state file passphrase pair, kept as constants so a test can reopen the
/// same durable state and make `validate_hvm_state` run on load.
const STATE_KEY: &str = "9292929292929292929292929292929292929292929292929292929292929292";
const STATE_SALT: &str = "9393939393939393939393939393939393939393939393939393939393939393";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// The channel exactly as it looks when it was opened and nothing has happened
/// to it. This is what activation has to see.
fn open_snapshot(binding: &HvmChannelBindingV1) -> Value {
    channel_snapshot(
        binding,
        2,
        0,
        binding.left_deposit_zhu,
        0,
        false,
        LIVE_BLOCKS,
    )
}

/// The channel in whatever state the test needs. `status` 4 with
/// `left_claimed` false and a serial matching the durable head bill is the
/// situation the whole file is about: settled, frozen, and still holding the
/// left party's principal.
#[allow(clippy::too_many_arguments)]
fn channel_snapshot(
    binding: &HvmChannelBindingV1,
    status: u8,
    serial: u64,
    left_balance: u64,
    right_balance: u64,
    left_claimed: bool,
    live_blocks: u64,
) -> Value {
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
            "status": storage_entry(json!(status), live_blocks),
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
            "serial": storage_entry(json!(serial), live_blocks),
            "left_balance": storage_entry(json!(left_balance), live_blocks),
            "right_balance": storage_entry(json!(right_balance), live_blocks),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live_blocks),
            "deadline": storage_entry(json!(if status == 2 { 0 } else { OBSERVED_HEIGHT - 1 }), live_blocks),
            "left_claimed": storage_entry(json!(left_claimed), live_blocks),
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
    // Serial 1, the whole deposit still on the left. `decide_watchtower_action`
    // will only claim on a FINAL chain whose split is exactly this bill, so the
    // durable head bill and the finalized contract have to agree here.
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

/// A mock fullnode whose mempool and contract storage are under the test's
/// control, so a claim can be left pending, mined, or made to vanish while a
/// third party's payout appears in the contract instead.
///
/// It also echoes back the action kinds each submitted transaction really
/// carries, read off the bytes at submit. That matters: a claim is judged
/// against an Action 14 proof and every other kind against Action 44, so a mock
/// answering one fixed list for everything would hand a claim a proof it never
/// earned.
struct Chain {
    submits: Arc<AtomicUsize>,
    mempool: Arc<RwLock<HashMap<String, String>>>,
    mined: Arc<RwLock<HashSet<String>>>,
    live: Arc<RwLock<Value>>,
    lease_life: Arc<RwLock<u64>>,
    binding: HvmChannelBindingV1,
}

impl Chain {
    async fn finalize_holding_the_left_share(&self) {
        let life = *self.lease_life.read().await;
        *self.live.write().await = channel_snapshot(
            &self.binding,
            4,
            1,
            self.binding.left_deposit_zhu,
            0,
            false,
            life,
        );
    }

    async fn record_the_payout(&self) {
        let life = *self.lease_life.read().await;
        *self.live.write().await = channel_snapshot(
            &self.binding,
            4,
            1,
            self.binding.left_deposit_zhu,
            0,
            true,
            life,
        );
    }

    /// What a confirmed `renew_all_leases` actually does to the contract: every
    /// lease reports a longer life than it did before the call. The renewal
    /// postcondition demands exactly this and refuses a renewal that bought
    /// nothing, so the mock has to do it rather than assert it.
    async fn extend_every_lease(&self) {
        let mut life = self.lease_life.write().await;
        *life += 10_000;
        let extended = *life;
        drop(life);
        let claimed = self.live.read().await["storage"]["left_claimed"]["value"]
            .as_bool()
            .unwrap_or(false);
        *self.live.write().await = channel_snapshot(
            &self.binding,
            4,
            1,
            self.binding.left_deposit_zhu,
            0,
            claimed,
            extended,
        );
    }

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

    /// Drop everything from the mempool without mining it, so a query answers
    /// "not found" the way a real node does for a transaction that never made
    /// it in.
    async fn drop_the_mempool(&self) {
        self.mempool.write().await.clear();
    }

    fn submitted(&self) -> usize {
        self.submits.load(Ordering::SeqCst)
    }
}

struct Harness {
    /// `None` only while a reopen is in flight. The state file is exclusively
    /// locked by whichever `HubState` holds it, so the live one has to be
    /// dropped before the durable file can be loaded again.
    hub: Option<HubState>,
    chain: Chain,
    node_url: String,
    state_file: std::path::PathBuf,
    hub_address: String,
    hub_secret_hex: String,
    _server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Harness {
    fn hub(&self) -> &HubState {
        self.hub.as_ref().expect("the Hub is open")
    }

    /// Reopen the durable state file. Every claim rule in `validate_hvm_state`
    /// runs on load, so a record that only passes on write does not survive
    /// this.
    fn reopen(&mut self) -> HubState {
        self.hub = None;
        HubState::new_secure_with_policy(
            "v1 watchtower tick",
            self.hub_address.clone(),
            self.node_url.clone(),
            None,
            self.state_file.clone(),
            self.hub_secret_hex.clone(),
            STATE_KEY,
            STATE_SALT,
            "local-pilot",
            0,
            0,
        )
        .unwrap()
    }
}

async fn harness(seed: &str) -> Harness {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let (hub_account, bundle) = signed_bundle(seed);
    let expected = bundle.binding.clone();
    let live = Arc::new(RwLock::new(open_snapshot(&bundle.binding)));
    let submits = Arc::new(AtomicUsize::new(0));
    let mempool: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let actions: Arc<RwLock<HashMap<String, Vec<u16>>>> = Arc::new(RwLock::new(HashMap::new()));
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
                let actions = actions.clone();
                move |body: String| {
                    let mempool = mempool.clone();
                    let submits = submits.clone();
                    let actions = actions.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        let kinds = transaction
                            .actions()
                            .iter()
                            .map(|action| action.kind())
                            .collect::<Vec<_>>();
                        submits.fetch_add(1, Ordering::SeqCst);
                        actions.write().await.insert(hash.clone(), kinds);
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
                let actions = actions.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let mempool = mempool.clone();
                    let mined = mined.clone();
                    let actions = actions.clone();
                    async move {
                        let Some(hash) = query.get("hash").cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        let Some(body) = mempool.read().await.get(&hash).cloned() else {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        };
                        // The kinds this transaction really carries, not a
                        // fixed list: a claim is judged against Action 14 and a
                        // lease renewal against Action 44.
                        let kinds = actions
                            .read()
                            .await
                            .get(&hash)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|kind| json!({"kind": kind}))
                            .collect::<Vec<_>>();
                        if !mined.read().await.contains(&hash) {
                            return Json(json!({
                                "ret": 0,
                                "hash": hash,
                                "tx_type": 3,
                                "body": body,
                                "actions": kinds,
                                "signatures": [{"complete": true}],
                                "pending": true
                            }));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": kinds,
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
    let state_file = directory.path().join("watchtower-tick-state.json");
    let binding = bundle.binding.clone();
    let node_url = format!("http://{address}");
    let hub_address = bundle.binding.right_hub_address.clone();
    let hub_secret_hex = hex::encode(hub_account.secret_key().serialize());
    let hub = HubState::new_secure_with_policy(
        "v1 watchtower tick",
        hub_address.clone(),
        node_url.clone(),
        None,
        state_file.clone(),
        hub_secret_hex.clone(),
        STATE_KEY,
        STATE_SALT,
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    hub.activate_hvm_channel_recovery(bundle, ACTIVATION_FLOOR_BLOCKS, ACTIVATION_FLOOR_BLOCKS)
        .await
        .unwrap();

    Harness {
        hub: Some(hub),
        chain: Chain {
            submits,
            mempool,
            mined,
            live,
            lease_life: Arc::new(RwLock::new(LIVE_BLOCKS)),
            binding,
        },
        node_url,
        state_file,
        hub_address,
        hub_secret_hex,
        _server: server,
        _directory: directory,
    }
}

/// One pass of the shipped scheduler tick over the single activated channel.
async fn one_pass(harness: &Harness) -> (Option<String>, Option<String>) {
    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results.len(), 1, "one activated channel, one result");
    let result = results.into_iter().next().unwrap();
    match result.response {
        Some(response) => (Some(response.status), Some(response.action)),
        None => (None, result.error),
    }
}

/// The whole point: a Hub that nobody is watching claims the money.
///
/// No CLI, no feature flag, no operator. `hvm_watchtower_tick` is the function
/// the shipped scheduler loop calls every interval, and this drives it exactly
/// as the loop does, from a channel that is FINAL and still holding the left
/// party's principal through to the payout being recorded on the contract.
#[tokio::test]
async fn the_watchtower_tick_claims_a_finalized_left_payout_without_an_operator() {
    let mut harness = harness("watchtower-tick-claims").await;
    let commitment = harness
        .chain
        .binding
        .commitment()
        .expect("binding commitment");

    // While the channel is merely open there is nothing to do, and nothing
    // durable is written.
    let (status, action) = one_pass(&harness).await;
    assert_eq!(status.as_deref(), Some("no_action"));
    assert_eq!(action.as_deref(), Some("none"));
    assert_eq!(harness.chain.submitted(), 0);

    // The channel finalizes with the left share still inside the contract.
    // This is the exact shape the live chain-7 contract was found in.
    harness.chain.finalize_holding_the_left_share().await;

    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    let response = results[0].response.clone().expect("a claim was decided");
    assert_eq!(response.action, "claim");
    assert_eq!(
        response.status, "submitted",
        "one submission, still pending"
    );
    assert_eq!(
        response.claim_payee.as_deref(),
        Some(harness.chain.binding.left_address.as_str()),
        "the payee is the contract's own left party and never a request field",
    );
    assert_eq!(response.claim_amount_zhu, Some(DEPOSIT_ZHU));
    assert!(response.claim_settled_elsewhere_height.is_none());
    assert!(response.transaction_hash.is_some());
    assert_eq!(harness.chain.submitted(), 1);
    let claim_operation = response.operation_id.clone();
    assert!(
        claim_operation.starts_with("hvm-watchtower-"),
        "the tick has to name its own work so it can tell it from an operator's: {claim_operation}",
    );

    // A second pass before the transaction is mined resumes the same record
    // rather than opening a second one. This is the wedge the lease tick used
    // to have, and it must not exist here.
    let (status, action) = one_pass(&harness).await;
    assert_eq!(status.as_deref(), Some("submitted"));
    assert_eq!(action.as_deref(), Some("claim"));
    assert_eq!(
        harness.chain.submitted(),
        1,
        "resuming must not rebroadcast",
    );

    // The transaction is mined and the contract records the payout.
    harness.chain.mine_everything_submitted().await;
    harness.chain.record_the_payout().await;

    let (status, action) = one_pass(&harness).await;
    assert_eq!(
        status.as_deref(),
        Some("confirmed"),
        "the postcondition reads `left_claimed` off live evidence and must pass",
    );
    assert_eq!(action.as_deref(), Some("claim"));

    // And once the money has moved the honest answer is nothing to do.
    let (status, action) = one_pass(&harness).await;
    assert_eq!(status.as_deref(), Some("no_action"));
    assert_eq!(action.as_deref(), Some("none"));
    assert_eq!(harness.chain.submitted(), 1, "exactly one payout, ever");

    // The durable record has to survive `validate_hvm_state` on load, which is
    // where the claim descriptor is re-derived from the binding rather than
    // trusted as stored text. Constructing this at all is the assertion: a
    // record that fails any claim rule refuses to load.
    let reopened = harness.reopen();
    assert!(
        reopened.health().settlement_ready,
        "with the claim resolved and nothing outstanding the latch must be down",
    );
    assert_eq!(
        reopened.hvm_latest_bill(&commitment).unwrap().serial,
        1,
        "the claim moves coin, not the ledger",
    );
    let after_restart = reopened
        .hvm_watchtower_request(&claim_operation)
        .unwrap()
        .expect("the confirmed claim rebuilds its exact durable request");
    assert_eq!(after_restart.operation_id, claim_operation);
    let results = reopened
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results[0].response.as_ref().unwrap().status, "no_action");
    assert_eq!(harness.chain.submitted(), 1);
}

/// A permissionless payout by somebody else resolves our claim on the
/// contract's own evidence, and the record keeps its signed bytes.
///
/// Action 14 needs no signature from the contract, so anybody may trigger the
/// payout. When they do, chasing ours would buy a `HPAY_LEFT_ALREADY_CLAIMED`
/// throw and a spent fee, and latching recovery would be the Hub calling
/// somebody else's success a failure.
#[tokio::test]
async fn a_third_party_payout_resolves_the_claim_on_the_contracts_own_evidence() {
    let mut harness = harness("watchtower-tick-settled-elsewhere").await;
    harness.chain.finalize_holding_the_left_share().await;

    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    let response = results[0].response.clone().expect("a claim was decided");
    assert_eq!(response.action, "claim");
    assert_eq!(response.status, "submitted");
    let claim_operation = response.operation_id.clone();
    assert_eq!(harness.chain.submitted(), 1);

    // Our transaction never lands, and meanwhile the payee is paid by someone
    // else: the contract's `left_claimed` is set for the exact amount and the
    // exact payee.
    harness.chain.drop_the_mempool().await;
    harness.chain.record_the_payout().await;

    let (status, action) = one_pass(&harness).await;
    assert_eq!(
        status.as_deref(),
        Some("confirmed"),
        "the payout happened; the record resolves rather than latching recovery",
    );
    assert_eq!(action.as_deref(), Some("claim"));
    assert_eq!(
        harness.chain.submitted(),
        1,
        "nothing is rebroadcast into an already-claimed contract",
    );

    // A settled-elsewhere record keeps its exact signed bytes and owns no
    // block of its own. `validate_hvm_state` runs on load and both of those
    // rules are checked there, so reopening is the assertion.
    let reopened = harness.reopen();
    assert!(
        reopened.health().settlement_ready,
        "a resolved claim releases the latch",
    );
    assert!(
        reopened
            .hvm_watchtower_request(&claim_operation)
            .unwrap()
            .is_some(),
        "the resolved record is still durable and still rebuilds",
    );
}

/// A confirmed claim that did not move `left_claimed` paid nobody, and the
/// postcondition has to say so.
///
/// This is the one that would matter if the contract ever accepted the
/// transaction and did nothing with it: the Hub must not record a payout it
/// cannot see in the contract's own storage.
#[tokio::test]
async fn a_claim_that_did_not_record_the_payout_latches_recovery() {
    let mut harness = harness("watchtower-tick-postcondition").await;
    harness.chain.finalize_holding_the_left_share().await;

    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results[0].response.as_ref().unwrap().action, "claim");

    // Mined and confirmed, but the contract still says the left share is
    // unclaimed.
    harness.chain.mine_everything_submitted().await;

    let (status, action) = one_pass(&harness).await;
    assert_eq!(
        status.as_deref(),
        Some("recovery_required"),
        "a confirmed claim with `left_claimed` still false did not pay anybody",
    );
    assert_eq!(action.as_deref(), Some("claim"));

    let reopened = harness.reopen();
    assert!(
        !reopened.health().settlement_ready,
        "an unresolved operation keeps the latch up until a person clears it",
    );
}

/// The tick names an operation it did not open and leaves it strictly alone.
///
/// An operator's `pilot-watch-…` record on this channel is somebody else's
/// in-flight transaction. Driving it would put it on the wire on their behalf,
/// so the tick refuses by name — which is also strictly more informative than
/// the bare refusal a blocked channel used to produce.
#[tokio::test]
async fn the_watchtower_tick_refuses_to_drive_an_operation_it_did_not_open() {
    let harness = harness("watchtower-tick-ownership").await;
    harness.chain.finalize_holding_the_left_share().await;

    // An operator runs the CLI first. Its claim is submitted and stays pending.
    let now = now_unix();
    let operator = "pilot-watch-0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".to_owned();
    let operator_response = harness
        .hub()
        .run_hvm_watchtower(HvmWatchtowerRequestV1 {
            schema: HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
            operation_id: operator.clone(),
            idempotency_key: format!("{operator}-idem"),
            binding_commitment: harness.chain.binding.commitment().unwrap(),
            mode: HvmWatchtowerMode::Monitor,
            network_fee_zhu: 10_000,
            timestamp: now,
            gas_max: u8::MAX,
            created_unix: now,
        })
        .await
        .unwrap();
    assert_eq!(operator_response.action, "claim");
    assert_eq!(operator_response.status, "submitted");
    assert_eq!(harness.chain.submitted(), 1);

    let (status, error) = one_pass(&harness).await;
    assert!(status.is_none(), "the tick must refuse, not report a pass");
    let error = error.expect("a refusal carries a reason");
    assert!(
        error.contains(&operator) && error.contains("was not opened by the watchtower tick"),
        "the refusal has to name the record and the reason, got: {error}",
    );
    assert_eq!(
        harness.chain.submitted(),
        1,
        "refusing must broadcast nothing",
    );
}

/// A lease renewal in flight is ordinary, not a fault, and must not be
/// reported as one.
///
/// This came out of a live run rather than a hunch. A channel permits exactly
/// one unresolved chain operation, the lease tick runs first on the shared
/// scheduler loop, and a renewal stays outstanding until it reaches six
/// confirmations, which was 29, 83 and 48 passes on the three renewals timed on
/// chain 7. The first version of this tick reported that as a failed-closed
/// channel, which would have put an `error!` line in the log on every one of
/// those passes for a Hub doing exactly what it should. An operator who learns
/// to scroll past this line will scroll past the one that matters.
#[tokio::test]
async fn a_lease_renewal_in_flight_defers_the_watchtower_instead_of_failing_it() {
    let harness = harness("watchtower-tick-defers-to-lease").await;
    harness.chain.finalize_holding_the_left_share().await;

    // A threshold above the reported lease life makes the renewal due, so the
    // lease tick opens and submits one.
    let mut due = scheduler_config();
    due.renew_when_live_blocks_at_or_below = LIVE_BLOCKS + 1;
    let lease = harness
        .hub()
        .hvm_lease_maintenance_tick(&due)
        .await
        .unwrap();
    let lease = lease[0]
        .response
        .clone()
        .expect("the lease tick opened a renewal");
    assert_eq!(lease.action, "renew_all_leases");
    assert_eq!(lease.status, "submitted");
    assert_eq!(harness.chain.submitted(), 1);

    // The channel is FINAL with an unclaimed left share, so the tower has real
    // work here. It still must not touch the renewal's slot.
    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(
        results[0].response.is_none(),
        "the channel was not evaluated this pass",
    );
    assert_eq!(
        results[0].error, None,
        "a renewal this same loop opened is not a failure, and reporting it as one is alarm \
         fatigue by the dozens of passes",
    );
    assert_eq!(
        results[0].deferred_to_lease_operation.as_deref(),
        Some(lease.operation_id.as_str()),
        "the deferral has to name the renewal holding the slot",
    );
    assert_eq!(
        harness.chain.submitted(),
        1,
        "deferring must broadcast nothing",
    );

    // Once the renewal confirms the slot is free and the tower gets the channel
    // back on the very next pass, with its claim intact.
    harness.chain.mine_everything_submitted().await;
    harness.chain.extend_every_lease().await;
    let confirmed = harness
        .hub()
        .hvm_lease_maintenance_tick(&due)
        .await
        .unwrap();
    assert_eq!(
        confirmed[0].response.as_ref().unwrap().status,
        "confirmed",
        "the renewal has to resolve before the slot frees",
    );

    let results = harness
        .hub()
        .hvm_watchtower_tick(&scheduler_config())
        .await
        .unwrap();
    let response = results[0]
        .response
        .clone()
        .expect("the tower is evaluated again once the slot is free");
    assert_eq!(response.action, "claim");
    assert_eq!(response.claim_amount_zhu, Some(DEPOSIT_ZHU));
    assert_eq!(harness.chain.submitted(), 2, "the renewal, then the claim");
}
