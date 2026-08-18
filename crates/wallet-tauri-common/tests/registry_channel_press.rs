//! THE PRESS THAT OPENS A CHANNEL, AND THE SECOND PRESS WITH THE PROVIDER DEAD.
//!
//! # What was missing
//!
//! Opening a usable channel is three hops with a genuine wait in the middle:
//! the provider's countersigned full refund, the deposit, and the adoption that
//! seeds the exit. All three shipped as separate Tauri commands, and the
//! ordering between them lived nowhere in this workspace. Which one is legal
//! when, and what a person presses after the app is closed between any two of
//! them, was left to whatever a renderer would do.
//!
//! That gap has a shape, and it is proven at the bottom of this file: `open` is
//! the only one of the three that carries the channel description, and once a
//! refund is countersigned `begin_hvm_registry_channel_open` refuses it. A
//! screen driving the three commands therefore has **nothing it can press that
//! continues** a half-open channel, and the half-open state is exactly the one
//! a person is in when their money has already left.
//!
//! `wallet_tauri_common::agent_commands::establish_hvm_registry_channel` is
//! that ordering, in Rust, next to the durable state that decides it. This is
//! its proof.
//!
//! # What is real here
//!
//! * The command body a person's press runs, entered exactly as the Tauri
//!   command enters it, and never handed a chain view: it builds its own out of
//!   the `node_url` the wallet was created with.
//! * A real `AgentWalletManager` on disk, a real wallet created and unlocked
//!   through it. The wallet's key never leaves its vault; this test cannot
//!   reach it and does not try.
//! * A real `HubState` behind the real axum router on a real socket, doing the
//!   real countersignature over the real HTTP route, then killed part way
//!   through and asserted dead.
//! * A fullnode on a real socket, so `FullnodeRegistryOpenChain` does the
//!   reqwest, the status codes and the JSON exactly as it would against a
//!   person's own node.
//!
//! # What this file does not claim
//!
//! The funding bytes are not executed by a block executor here. They are, in
//! `agent_wallet_core::service::hvm_registry::exit_on_chain_tests::a_wallet_opens_pays_and_walks_out_with_the_provider_deleted`,
//! against a real deployed `hpay_channel_registry_v2` in real blocks - and that
//! proof cannot live in this crate, because a registry `init` carries
//! `assert check_signature(left)` and the left party's key is inside the Agent
//! Wallet's own vault, which nothing outside `agent-wallet-core` can open. What
//! is proven here is the thing that proof cannot reach: the command, its
//! ordering, its resumability, and the progress a screen renders from it.
//!
//! Nothing is broadcast. Nothing reaches a chain. No money moves anywhere.

#![cfg(feature = "on-chain-exit-proof")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agent_wallet_core::{AgentWalletId, AgentWalletManager, CreateAgentWallet};
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::HvmLocalPilotNetwork;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_deployment;
use l2_fast_pay_hub::node::HvmStorageEntry;
use serde_json::{Value, json};
use sys::Account;
use wallet_tauri_common::agent_commands::{
    establish_hvm_registry_channel, open_hvm_registry_channel, start_hvm_registry_exit,
};

const PASSPHRASE: &str = "agent wallet passphrase 123";
const DEPOSIT_ZHU: u64 = 5_000_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const SETUP_FEE_ZHU: u64 = 500_000;
const CHANNEL_ID: &str = "5151515151515151515151515151515f";
const FUNDED_BLOCK_HEIGHT: u64 = 4_242;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// The fullnode, over real HTTP.
// ---------------------------------------------------------------------------

/// What this node has been told and what it will admit to.
///
/// It corroborates exactly one channel and answers about nothing else, which
/// is the point: the wallet's pre-funding gate is judging this node, and a node
/// that agrees with whatever it is asked would make the gate untestable.
#[derive(Default)]
struct NodeFacts {
    channel: Option<HvmRegistryBindingV2>,
    /// Every transaction hex this node has been handed, keyed by hash.
    submitted: Vec<(String, String)>,
    /// True once the deposit is in a block, which is also the moment the
    /// channel's own storage stops being the unfunded one.
    funded: bool,
}

struct Fullnode {
    network: HvmLocalPilotNetwork,
    facts: Mutex<NodeFacts>,
}

impl Fullnode {
    fn distinct_submissions(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for (hash, _) in self.facts.lock().unwrap().submitted.iter() {
            if !seen.contains(hash) {
                seen.push(hash.clone());
            }
        }
        seen
    }
}

fn entry<T>(value: T) -> HvmStorageEntry<T> {
    HvmStorageEntry {
        value,
        live_blocks: 300_000,
        recover_blocks: 0,
        active: true,
        recoverable: false,
    }
}

/// This channel's storage as a node reports it, before or after the deposit.
///
/// The two states differ in exactly what the contract changes when
/// `PayableHAC` takes the coin: the channel moves from FUNDING to OPEN, `paid`
/// becomes the deposit, and the registry's own locked total and open count take
/// account of it. Everything the binding names is identical in both, because
/// nothing the binding names is allowed to change.
fn snapshot(binding: &HvmRegistryBindingV2, funded: bool) -> HvmRegistryLiveSnapshotV2 {
    let total = binding.left_deposit_zhu + binding.right_hub_deposit_zhu;
    HvmRegistryLiveSnapshotV2 {
        ret: 0,
        schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        chain_id: binding.chain_id,
        network_instance_id: binding.network_instance_id.clone(),
        observed_height: binding.deployment_height + 4,
        evaluation_height: binding.deployment_height + 5,
        contract_address: binding.contract_address.clone(),
        deployment_tx_hash: binding.deployment_tx_hash.clone(),
        deployment_height: binding.deployment_height,
        deployment_action_verified: true,
        bytecode_sha3: binding.bytecode_sha3.clone(),
        hub_address: binding.right_hub_address.clone(),
        left_address: binding.left_address.clone(),
        registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
        channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
        all_keys_active: true,
        minimum_live_blocks: 300_000,
        minimum_recover_blocks: 0,
        registry: HvmRegistryGlobalStorageV2 {
            g_network: entry(binding.network_instance_id.clone()),
            g_hub: entry(binding.right_hub_address.clone()),
            g_locked: entry(if funded { total } else { 0 }),
            g_left_claimable: entry(0),
            g_hub_claimable: entry(0),
            g_open_count: entry(u64::from(funded)),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(if funded { 2 } else { 1 }),
            channel_id: entry(binding.channel_id.clone()),
            reuse: entry(binding.reuse_version),
            deposit: entry(binding.left_deposit_zhu),
            paid: entry(if funded { binding.left_deposit_zhu } else { 0 }),
            total: entry(total),
            serial: entry(0),
            left_balance: entry(binding.left_deposit_zhu),
            hub_balance: entry(0),
            challenge_blocks: entry(binding.challenge_blocks),
            deadline: entry(0),
            left_claimed: entry(false),
        },
    }
}

async fn capabilities_route(State(node): State<Arc<Fullnode>>) -> Json<Value> {
    let network = &node.network;
    Json(json!({
        "ret": 0,
        "api_version": 1,
        "chain": {
            "id": network.chain_id,
            "height": FUNDED_BLOCK_HEIGHT + 10,
            "next_height": FUNDED_BLOCK_HEIGHT + 11,
            "mainnet": false,
        },
        "network": {
            "kind": network.network_kind,
            "node_profile_id": network.node_profile_id,
            "block_1_hash": network.block_1_hash,
            "transaction_format_version": network.transaction_format_version,
            "instance_id": network.network_instance_id,
        },
        "sync": {
            "tip_timestamp_unix": now_unix(),
            "max_tip_age_seconds": 3_600,
            "fresh": true,
        },
        "actions": {
            "registered": [1, 14, 40, 41, 44, 0x0411, 0x0414],
            "enabled": [1, 14, 40, 41, 44, 0x0411, 0x0414],
        },
        "transactions": { "enabled": [2, 3] },
        "api": {
            "transaction_submit_bound": true,
            "hpay_channel_registry_query": true,
        },
    }))
}

async fn registry_route(
    State(node): State<Arc<Fullnode>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let facts = node.facts.lock().unwrap();
    let Some(binding) = facts.channel.as_ref() else {
        return Json(json!({ "ret": 1, "err": "this node holds no such registry channel" }));
    };
    // A node answers about the channel it was asked about and no other.
    if query.get("contract").map(String::as_str) != Some(binding.contract_address.as_str())
        || query.get("left").map(String::as_str) != Some(binding.left_address.as_str())
        || query.get("deployment_tx_hash").map(String::as_str)
            != Some(binding.deployment_tx_hash.as_str())
    {
        return Json(json!({ "ret": 1, "err": "this node holds no such registry channel" }));
    }
    Json(serde_json::to_value(snapshot(binding, facts.funded)).expect("snapshot encodes"))
}

async fn transaction_route(
    State(node): State<Arc<Fullnode>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let facts = node.facts.lock().unwrap();
    let Some(hash) = query.get("hash") else {
        return Json(json!({ "ret": 1, "err": "transaction not found" }));
    };
    let Some((_, body)) = facts.submitted.iter().find(|(known, _)| known == hash) else {
        return Json(json!({ "ret": 1, "err": "transaction not found" }));
    };
    // A registry deposit is a Type 3 carrying an Action 1 transfer and no
    // contract call at all, which is the shape the wallet asks this node for.
    let mut answer = json!({
        "ret": 0,
        "hash": hash,
        "tx_type": 3,
        "actions": [{ "kind": 1 }],
        "signatures": [{ "publickey": "", "signature": "" }],
        "body": body,
    });
    if facts.funded {
        answer["pending"] = json!(false);
        answer["confirm"] = json!(6);
        answer["block"] = json!({
            "height": FUNDED_BLOCK_HEIGHT,
            "hash": "ab".repeat(32),
        });
    } else {
        answer["pending"] = json!(true);
    }
    Json(answer)
}

async fn balance_route(
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    Json(json!({
        "ret": 0,
        "list": [{ "address": address, "hacash": "300.00000000" }],
    }))
}

/// Take exact signed bytes on the bound submit route, the only one this wallet
/// ever uses.
///
/// The transaction's hash is derived here with the chain's own codec rather
/// than echoed from anything the caller said, because the caller checks the
/// answer against the hash it signed: a node that agreed with whatever it was
/// told would make that check meaningless.
async fn submit_route(
    State(node): State<Arc<Fullnode>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    body: String,
) -> Json<Value> {
    let hex_body = body.trim().to_ascii_lowercase();
    let mut facts = node.facts.lock().unwrap();
    let Some(binding) = facts.channel.clone() else {
        return Json(json!({ "ret": 1, "err": "this node holds no such registry channel" }));
    };
    // A bound submit names the chain it is for, and a node on another chain
    // must refuse it rather than take the bytes.
    if query.get("chain_id").map(String::as_str) != Some(binding.chain_id.to_string().as_str())
        || query.get("network_instance_id").map(String::as_str)
            != Some(binding.network_instance_id.as_str())
    {
        return Json(json!({ "ret": 1, "err": "transaction is bound to another chain" }));
    }
    let Ok(raw) = hex::decode(&hex_body) else {
        return Json(json!({ "ret": 1, "err": "submitted body is not hex" }));
    };
    let hash = match protocol::transaction::transaction_create(&raw) {
        Ok((parsed, used)) if used == raw.len() => hex::encode(parsed.hash().as_bytes()),
        _ => return Json(json!({ "ret": 1, "err": "submitted transaction does not parse" })),
    };
    // Idempotent by hash, exactly as a real node is: the wallet is entitled to
    // hand the same bytes over again and must never be told that is a new
    // transaction.
    if !facts.submitted.iter().any(|(known, _)| known == &hash) {
        facts.submitted.push((hash.clone(), hex_body));
    }
    Json(json!({ "ret": 0, "hash": hash }))
}

async fn spawn_fullnode(node: Arc<Fullnode>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/query/capabilities", get(capabilities_route))
        .route("/query/hpay/channel-registry", get(registry_route))
        .route("/query/transaction", get(transaction_route))
        .route("/query/balance", get(balance_route))
        .route("/submit/transaction/hpay-bound", post(submit_route))
        .with_state(node);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{address}")
}

// ---------------------------------------------------------------------------
// The provider.
// ---------------------------------------------------------------------------

async fn spawn_hub(
    hub: &Account,
    directory: &tempfile::TempDir,
) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "registry establish command proof",
            hub.readable().to_owned(),
            "http://127.0.0.1:1".to_owned(),
            None,
            state_path,
            hex::encode(hub.secret_key().serialize()),
            &"92".repeat(32),
            &"93".repeat(32),
            "local-pilot",
            0,
            0,
        )
        .expect("hub state"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = l2_fast_pay_hub::server::build_router(state.clone());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (format!("http://{address}"), state, handle)
}

// ---------------------------------------------------------------------------
// The wallet, and the channel it is offered.
// ---------------------------------------------------------------------------

struct Opened {
    manager: AgentWalletManager,
    wallet_id: AgentWalletId,
    address: String,
    _root: tempfile::TempDir,
}

fn open_wallet(node_url: &str, network: &HvmLocalPilotNetwork) -> Opened {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let now = now_unix();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: node_url.to_owned(),
                block_one_fingerprint: Some(network.block_1_hash.clone()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    let wallet_id: AgentWalletId = created.wallet_id.clone();
    manager.unlock(&wallet_id, PASSPHRASE, now).unwrap();
    Opened {
        manager,
        wallet_id,
        address: created.address,
        _root: root,
    }
}

/// The channel a provider publishes, built from a real deployment transaction
/// so the contract address, the deploying hash and the bytecode digest are the
/// ones the reviewed profile demands rather than plausible-looking strings.
fn channel_for(
    hub: &Account,
    left_address: &str,
    network: &HvmLocalPilotNetwork,
) -> HvmRegistryBindingV2 {
    let deployment =
        build_hvm_registry_pilot_deployment(hub, network, SETUP_FEE_ZHU, 100, u8::MAX).unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height: 100,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: left_address.to_owned(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    };
    binding.validate().expect("a reviewed-profile channel");
    binding
}

// ---------------------------------------------------------------------------
// The proof.
// ---------------------------------------------------------------------------

/// ONE PRESS, FOUR TIMES, AND THE PROVIDER DEAD FOR THREE OF THEM.
///
/// Press one opens the channel with the provider and signs the deposit, then
/// stops at the only wait that exists: the deposit is not in a block. The
/// provider is killed and asserted dead. Press two resumes without asking it
/// anything and signs nothing new. The deposit lands; press three adopts the
/// channel from the chain alone and the exit becomes available. Press four
/// reports a finished channel finished rather than refusing.
///
/// Every hop enters through
/// `wallet_tauri_common::agent_commands::establish_hvm_registry_channel`, which
/// is the Tauri command's body, and none of them is handed a chain view.
#[tokio::test(flavor = "multi_thread")]
async fn one_press_opens_funds_and_adopts_and_a_resumed_press_needs_no_provider() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let network = HvmLocalPilotNetwork::canonical();
    let node = Arc::new(Fullnode {
        network: network.clone(),
        facts: Mutex::new(NodeFacts::default()),
    });
    let node_url = spawn_fullnode(Arc::clone(&node)).await;

    let hub = Account::create_by("establish-command-hub").unwrap();
    let mut wallet = open_wallet(&node_url, &network);
    let binding = channel_for(&hub, &wallet.address, &network);
    node.facts.lock().unwrap().channel = Some(binding.clone());
    let binding_json = serde_json::to_value(&binding).unwrap();
    let now = now_unix();

    // ---- PRESS ONE, with the provider alive ----
    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;

    let first = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("one press gets as far as the chain will take it");
    println!("  PRESS ONE: {first}");
    assert_eq!(first["stage"], "funding");
    assert_eq!(first["refund_guaranteed"], true);
    assert_eq!(first["exit_available"], false);
    assert_eq!(first["funding_confirmed"], false);
    assert_eq!(first["deposit_zhu"], DEPOSIT_ZHU);
    assert_eq!(
        first["at_risk_zhu"], DEPOSIT_ZHU,
        "the moment the transfer is durably signed the deposit stops being safe on the owner's side"
    );
    assert!(
        first["waiting_for"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a screen may never be told to wait without being told what for"
    );
    let network_fee_zhu = first["network_fee_zhu"]
        .as_u64()
        .expect("the fee is a number a screen can render");
    assert!(network_fee_zhu > 0);
    assert_eq!(
        first["spent_zhu"].as_u64(),
        Some(DEPOSIT_ZHU + network_fee_zhu),
        "what has been spent is the deposit and the fee, not one of them"
    );
    let funding_hash = first["funding_transaction_hash"]
        .as_str()
        .expect("the deposit transaction is named")
        .to_owned();
    assert_eq!(
        node.distinct_submissions().len(),
        1,
        "exactly one transaction has been put on the wire"
    );

    // ---- the provider dies ----
    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        reqwest::Client::new()
            .get(format!("{hub_url}/health"))
            .send()
            .await
            .is_err(),
        "this proof is worthless unless the provider is actually dead"
    );

    // ---- PRESS TWO: resume, provider dead, deposit still not in a block ----
    let waiting = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("a resumed press must never go back to a provider that has already signed");
    assert_eq!(waiting["stage"], "funding");
    assert_eq!(
        waiting["funding_transaction_hash"].as_str(),
        Some(funding_hash.as_str()),
        "a resumed press re-submits the stored bytes rather than signing new ones"
    );
    assert_eq!(
        node.distinct_submissions().len(),
        1,
        "pressing again must never sign a second transfer into one channel"
    );

    // ---- the deposit lands ----
    node.facts.lock().unwrap().funded = true;

    // ---- PRESS THREE: adoption, with nothing left to ask ----
    let ready = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("the wallet adopts its own funded channel from the chain alone");
    println!("  PRESS THREE: {ready}");
    assert_eq!(ready["stage"], "ready");
    assert_eq!(ready["waiting_for"], "");
    assert_eq!(ready["next_action"], "");
    assert_eq!(ready["exit_available"], true);
    assert_eq!(ready["funding_confirmed"], true);
    assert_eq!(
        ready["at_risk_zhu"], DEPOSIT_ZHU,
        "a funded channel's deposit comes back through the exit and through nothing else"
    );
    assert_eq!(
        ready["funding_confirmed_block_height"].as_u64(),
        Some(FUNDED_BLOCK_HEIGHT),
        "a confirmation that cannot name its block is not a confirmation"
    );

    // The exit head was seeded in the same journalled transition that wrote
    // the binding, which is the fact `exit_available` reports.
    let kit = wallet
        .manager
        .hvm_registry_exit_kit(&wallet.wallet_id)
        .expect("an adopted channel has an exit kit");
    assert_eq!(kit.latest_bill.serial, 1);
    assert_eq!(
        kit.latest_bill.left_balance_zhu, DEPOSIT_ZHU,
        "the bill this wallet holds returns the entire deposit"
    );

    // ---- PRESS FOUR: a finished channel reports itself finished ----
    let again = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("pressing a ready channel reports it ready rather than refusing");
    assert_eq!(again["stage"], "ready");
    assert_eq!(
        node.distinct_submissions().len(),
        1,
        "no press at any point signed a second transfer"
    );

    // ---- WHY THE COMMAND ABOVE HAD TO EXIST ----
    //
    // `open` is the only one of the three commands that carries the channel
    // description, so it is the only one a screen could press to "start over".
    // Once a refund is countersigned it refuses, which means the three-command
    // sequence has nothing that continues a half-open channel - and half-open
    // is the state a person is in exactly when their money has already left.
    let stuck = open_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        binding_json,
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect_err("the open command cannot be the resume control");
    assert!(!stuck.is_empty());

    // ---- AND WHAT THE OWNER IS TOLD ABOUT WALKING OUT ----
    //
    // The channel is adopted and the exit head is seeded, so everything the
    // exit needs is this wallet's own. Whether the control opens is decided by
    // the project's own measurement and not by this test: the constant a human
    // sets, and the probe that drives the real builders with a real non-Hub
    // key. This asserts whichever answer that measurement gives, so the day it
    // flips this test states the new truth rather than having to be edited.
    let exit = start_hvm_registry_exit(&mut wallet.manager, &wallet.wallet_id, now).await;
    if l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready() {
        let progress = exit.expect("a pass of the owner's own exit");
        assert!(
            progress.get("outcome").is_some(),
            "a driven exit reports what it did"
        );
    } else {
        let refusal = exit.expect_err("the exit gate is the project's own measurement");
        assert!(
            refusal.contains("This wallet cannot yet send a channel exit for you"),
            "the refusal must name this app's own gap rather than blaming the chain: {refusal}"
        );
        println!("  EXIT GATE STILL CLOSED: {refusal}");
    }
}

/// A SECOND PRESS THAT CARRIES A DIFFERENT CHANNEL IS REFUSED, NOT RECONCILED.
///
/// The command continues from durable state, and durable state is what decides
/// which channel is being funded. A press carrying different details would
/// otherwise fund the stored channel while reporting the pasted one, which is
/// the single most expensive sentence a wallet can say wrongly.
#[tokio::test(flavor = "multi_thread")]
async fn a_press_carrying_a_different_channel_continues_nothing() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let network = HvmLocalPilotNetwork::canonical();
    let node = Arc::new(Fullnode {
        network: network.clone(),
        facts: Mutex::new(NodeFacts::default()),
    });
    let node_url = spawn_fullnode(Arc::clone(&node)).await;

    let hub = Account::create_by("establish-command-hub-2").unwrap();
    let mut wallet = open_wallet(&node_url, &network);
    let binding = channel_for(&hub, &wallet.address, &network);
    node.facts.lock().unwrap().channel = Some(binding.clone());
    let now = now_unix();

    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;

    // The owner's typed amount and the pasted channel's amount are two
    // independent statements of the same fact, and this command is one of the
    // two doors where they can be compared.
    let mismatch = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        serde_json::to_value(&binding).unwrap(),
        DEPOSIT_ZHU * 2,
        now,
    )
    .await
    .expect_err("a deposit that is not the one the channel locks up is refused");
    assert!(
        mismatch.contains("nothing was sent to the network and no money has moved"),
        "the refusal has to close down the fear before it explains anything: {mismatch}"
    );
    assert!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .is_none(),
        "a refused press must leave no durable trace at all"
    );

    // Now open for real, then press again with a different channel.
    establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        serde_json::to_value(&binding).unwrap(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("an honest press");

    let mut other = binding.clone();
    other.reuse_version += 1;
    let refusal = establish_hvm_registry_channel(
        &mut wallet.manager,
        &wallet.wallet_id,
        &hub_url,
        serde_json::to_value(&other).unwrap(),
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect_err("a press carrying a different channel continues nothing");
    assert!(
        refusal.contains("different channel details"),
        "the owner has to be told which of the two facts disagreed: {refusal}"
    );

    hub_server.abort();
    drop(hub_state);
}
