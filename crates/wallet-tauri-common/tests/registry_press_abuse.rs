//! ADVERSARIAL DRIVE OF THE ESTABLISH COMMAND. Red-team hop, not a shipped test.
//!
//! Harness lifted from `registry_channel_press.rs` and widened: the node can be
//! killed, can report a balance too small for the deposit, and can refuse the
//! submission the way a real node refuses an unaffordable transfer. The wallet
//! can be dropped and reopened from the same directory, which is what a crash
//! between the countersignature and the funding actually looks like.

#![cfg(feature = "on-chain-exit-proof")]
#![allow(dead_code)]

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
    establish_hvm_registry_channel, fund_hvm_registry_channel, open_hvm_registry_channel,
    start_hvm_registry_exit,
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
struct NodeFacts {
    channel: Option<HvmRegistryBindingV2>,
    /// Every transaction hex this node has been handed, keyed by hash.
    submitted: Vec<(String, String)>,
    /// True once the deposit is in a block, which is also the moment the
    /// channel's own storage stops being the unfunded one.
    funded: bool,
    /// What this node says the owner's address holds, in HAC.
    balance_hac: String,
    /// Set when this node is too poor to take the transfer, the way a real
    /// node refuses one whose sender cannot cover amount plus fee.
    refuse_submit: Option<String>,
}

impl Default for NodeFacts {
    fn default() -> Self {
        Self {
            channel: None,
            submitted: Vec::new(),
            funded: false,
            balance_hac: "300.00000000".to_owned(),
            refuse_submit: None,
        }
    }
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
    State(node): State<Arc<Fullnode>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    let hacash = node.facts.lock().unwrap().balance_hac.clone();
    Json(json!({
        "ret": 0,
        "list": [{ "address": address, "hacash": hacash }],
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
    if let Some(refusal) = facts.refuse_submit.clone() {
        return Json(json!({ "ret": 1, "err": refusal }));
    }
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

async fn spawn_fullnode(node: Arc<Fullnode>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/query/capabilities", get(capabilities_route))
        .route("/query/hpay/channel-registry", get(registry_route))
        .route("/query/transaction", get(transaction_route))
        .route("/query/balance", get(balance_route))
        .route("/submit/transaction/hpay-bound", post(submit_route))
        .with_state(node);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}"), handle)
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
    root: tempfile::TempDir,
}

impl Opened {
    /// Everything a crash destroys, destroyed: the manager and its unlocked
    /// session are dropped and rebuilt from the same directory on disk.
    fn crash_and_reopen(&mut self) {
        // The live manager must be dropped before the directory can be opened
        // again, so a throwaway one is swapped in first.
        let scratch = tempfile::tempdir().unwrap();
        let stand_in = AgentWalletManager::open(scratch.path()).unwrap();
        drop(std::mem::replace(&mut self.manager, stand_in));
        let reopened = AgentWalletManager::open(self.root.path()).unwrap();
        drop(std::mem::replace(&mut self.manager, reopened));
    }

    fn unlock(&mut self) {
        let now = now_unix();
        self.manager
            .unlock(&self.wallet_id, PASSPHRASE, now)
            .unwrap();
    }
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
        root,
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
// The adversarial drives.
// ---------------------------------------------------------------------------

/// A wallet, a node and a channel, all wired together and ready to be pressed.
struct Rig {
    node: Arc<Fullnode>,
    node_url: String,
    node_server: tokio::task::JoinHandle<()>,
    wallet: Opened,
    binding: HvmRegistryBindingV2,
    binding_json: Value,
    hub: Account,
    hub_directory: tempfile::TempDir,
}

async fn rig(seed: &str) -> Rig {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let network = HvmLocalPilotNetwork::canonical();
    let node = Arc::new(Fullnode {
        network: network.clone(),
        facts: Mutex::new(NodeFacts::default()),
    });
    let (node_url, node_server) = spawn_fullnode(Arc::clone(&node)).await;
    let hub = Account::create_by(seed).unwrap();
    let wallet = open_wallet(&node_url, &network);
    let binding = channel_for(&hub, &wallet.address, &network);
    node.facts.lock().unwrap().channel = Some(binding.clone());
    let binding_json = serde_json::to_value(&binding).unwrap();
    Rig {
        node,
        node_url,
        node_server,
        wallet,
        binding,
        binding_json,
        hub,
        hub_directory: tempfile::tempdir().unwrap(),
    }
}

impl Rig {
    async fn hub_up(&self) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
        spawn_hub(&self.hub, &self.hub_directory).await
    }

    async fn press(&mut self, hub_url: &str) -> Result<Value, String> {
        let now = now_unix();
        establish_hvm_registry_channel(
            &mut self.wallet.manager,
            &self.wallet.wallet_id,
            hub_url,
            self.binding_json.clone(),
            DEPOSIT_ZHU,
            now,
        )
        .await
    }

    fn open_record(&mut self) -> Option<OpenRecordSnapshot> {
        let now = now_unix();
        self.wallet
            .manager
            .hvm_registry_channel_open(&self.wallet.wallet_id, now)
            .unwrap()
            .map(|record| {
                (
                    record.countersigned_bundle().is_some(),
                    record.funding().map(|funding| {
                        (
                            funding.transaction_hash().to_owned(),
                            funding.amount_zhu(),
                            funding.network_fee_zhu(),
                            funding.is_confirmed(),
                        )
                    }),
                )
            })
    }
}

/// A funding transaction as this snapshot reports it: hash, deposit, fee, and
/// whether the wallet has seen it in a block.
type FundingSnapshot = (String, u64, u64, bool);

/// What the wallet's durable open record says: whether a countersigned refund
/// is held, and the funding transaction if one has been signed.
type OpenRecordSnapshot = (bool, Option<FundingSnapshot>);

async fn hub_is_dead(hub_url: &str) -> bool {
    reqwest::Client::new()
        .get(format!("{hub_url}/health"))
        .send()
        .await
        .is_err()
}

fn say(tag: &str, what: &str, result: &Result<Value, String>) {
    match result {
        Ok(value) => println!("{tag} {what} OK: {value}"),
        Err(refusal) => println!("{tag} {what} REFUSED: {refusal}"),
    }
}

/// THE WHOLE CIRCLE, ATTEMPTED THROUGH THE COMMAND ONLY.
///
/// Open, fund, adopt, kill the provider, then walk out. Everything up to and
/// including adoption goes through `establish_hvm_registry_channel`; the walk
/// out goes through `start_hvm_registry_exit`, which is the body of the Tauri
/// command an exit control invokes. This test states whatever the commands
/// actually do. It does not assert that the circle closes, because asserting
/// that would only ever prove that somebody edited this file.
#[tokio::test(flavor = "multi_thread")]
async fn the_whole_circle_attempted_through_the_command() {
    let mut rig = rig("abuse-circle-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    let first = rig.press(&hub_url).await;
    say("CIRCLE", "press one", &first);
    assert_eq!(first.as_ref().unwrap()["stage"], "funding");

    rig.node.facts.lock().unwrap().funded = true;
    let ready = rig.press(&hub_url).await;
    say("CIRCLE", "press two", &ready);
    assert_eq!(ready.as_ref().unwrap()["stage"], "ready");

    // The provider dies, which is the only interesting version of this test.
    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        hub_is_dead(&hub_url).await,
        "the provider must really be dead"
    );

    // PAY. There is nothing to enter here: `agent_wallet_execute_approved_hvm`
    // keeps its whole body inside the `#[tauri::command]` attribute, so no
    // caller outside a running shell can reach it, and the operation id it
    // needs is minted by the agent runtime rather than by any control. What
    // this drive can state is what the wallet holds after adoption instead.
    let kit = rig
        .wallet
        .manager
        .hvm_registry_exit_kit(&rig.wallet.wallet_id)
        .expect("an adopted channel has an exit kit");
    println!(
        "CIRCLE bill held: serial={} left_balance_zhu={}",
        kit.latest_bill.serial, kit.latest_bill.left_balance_zhu
    );

    // EXIT.
    let now = now_unix();
    let exit = start_hvm_registry_exit(&mut rig.wallet.manager, &rig.wallet.wallet_id, now).await;
    say("CIRCLE", "exit", &exit);
    println!(
        "CIRCLE readiness measurement: {}",
        l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready()
    );

    rig.node_server.abort();
}

/// PRESS WITH A BALANCE THAT CANNOT COVER THE DEPOSIT AND ITS FEE.
///
/// The node says the owner holds a fraction of the deposit and refuses the
/// transfer the way a real node refuses one whose sender cannot cover amount
/// plus fee. What the command then says about the owner's money is the whole
/// question.
#[tokio::test(flavor = "multi_thread")]
async fn press_with_a_balance_too_small_for_the_deposit_and_its_fee() {
    let mut rig = rig("abuse-poor-hub").await;
    {
        let mut facts = rig.node.facts.lock().unwrap();
        facts.balance_hac = "0.10000000".to_owned();
        facts.refuse_submit = Some("insufficient balance for amount and fee".to_owned());
    }
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    let pressed = rig.press(&hub_url).await;
    say("POOR", "press one", &pressed);
    println!(
        "POOR durable record after press one: {:?}",
        rig.open_record()
    );
    println!(
        "POOR the node accepted {} transactions",
        rig.node.distinct_submissions().len()
    );

    let second = rig.press(&hub_url).await;
    say("POOR", "press two", &second);
    println!(
        "POOR the node accepted {} transactions after two presses",
        rig.node.distinct_submissions().len()
    );

    // Can the owner get out of this at all? The open command is the only
    // control that carries a channel description.
    let now = now_unix();
    let stuck = open_hvm_registry_channel(
        &mut rig.wallet.manager,
        &rig.wallet.wallet_id,
        &hub_url,
        rig.binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await;
    say("POOR", "open again", &stuck);
    println!("POOR record after open again: {:?}", rig.open_record());
    let exit = start_hvm_registry_exit(&mut rig.wallet.manager, &rig.wallet.wallet_id, now).await;
    say("POOR", "exit", &exit);

    // Is any of this recoverable? The owner tops up, so the node stops
    // refusing, and presses again.
    rig.node.facts.lock().unwrap().refuse_submit = None;
    rig.node.facts.lock().unwrap().balance_hac = "300.00000000".to_owned();
    let recovered = rig.press(&hub_url).await;
    say("POOR", "press after topping up", &recovered);
    println!(
        "POOR the node accepted {} transactions after topping up",
        rig.node.distinct_submissions().len()
    );
    rig.node.facts.lock().unwrap().funded = true;
    let finished = rig.press(&hub_url).await;
    say("POOR", "press once the deposit lands", &finished);
    println!(
        "POOR the node accepted {} transactions in total",
        rig.node.distinct_submissions().len()
    );

    hub_server.abort();
    drop(hub_state);
    rig.node_server.abort();
}

/// PRESS WITH NO FULLNODE.
#[tokio::test(flavor = "multi_thread")]
async fn press_with_no_fullnode() {
    let mut rig = rig("abuse-nonode-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    rig.node_server.abort();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let cold = rig.press(&hub_url).await;
    say("NONODE", "cold press", &cold);
    println!(
        "NONODE durable record after a cold press: {:?}",
        rig.open_record()
    );

    hub_server.abort();
    drop(hub_state);
}

/// PRESS WITH NO FULLNODE, HALF WAY THROUGH.
///
/// The provider has countersigned and the deposit has not been signed. The
/// node then disappears. A press must not sign a transfer it cannot check.
#[tokio::test(flavor = "multi_thread")]
async fn press_with_no_fullnode_after_the_refund_is_held() {
    let mut rig = rig("abuse-nonode2-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    let now = now_unix();
    let opened = open_hvm_registry_channel(
        &mut rig.wallet.manager,
        &rig.wallet.wallet_id,
        &hub_url,
        rig.binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await;
    say("NONODE2", "open", &opened);

    rig.node_server.abort();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let pressed = rig.press(&hub_url).await;
    say("NONODE2", "press with no node", &pressed);
    println!("NONODE2 durable record: {:?}", rig.open_record());

    hub_server.abort();
    drop(hub_state);
}

/// PRESS WITH THE VAULT LOCKED.
#[tokio::test(flavor = "multi_thread")]
async fn press_with_the_vault_locked() {
    let mut rig = rig("abuse-locked-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    rig.wallet
        .manager
        .lock(&rig.wallet.wallet_id, now_unix())
        .unwrap();
    let pressed = rig.press(&hub_url).await;
    say("LOCKED", "press", &pressed);
    println!(
        "LOCKED the node accepted {} transactions",
        rig.node.distinct_submissions().len()
    );

    hub_server.abort();
    drop(hub_state);
    rig.node_server.abort();
}

/// A CRASH BETWEEN THE COUNTERSIGNATURE AND THE FUNDING.
///
/// The open command is driven on its own, which is exactly the state a person
/// is in when the app dies after the provider has signed and before the
/// deposit is signed. The manager is then dropped and rebuilt from the same
/// directory on disk, and the establish command is pressed with the provider
/// dead.
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_between_the_countersignature_and_the_funding() {
    let mut rig = rig("abuse-crash-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    let now = now_unix();
    let opened = open_hvm_registry_channel(
        &mut rig.wallet.manager,
        &rig.wallet.wallet_id,
        &hub_url,
        rig.binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await;
    say("CRASH", "open", &opened);

    // The provider dies and so does the app.
    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(hub_is_dead(&hub_url).await);
    rig.wallet.crash_and_reopen();

    // A reopened wallet is locked, which is the first thing a resumed press
    // meets.
    let while_locked = rig.press(&hub_url).await;
    say("CRASH", "press before unlocking", &while_locked);

    rig.wallet.unlock();
    let resumed = rig.press(&hub_url).await;
    say("CRASH", "resumed press", &resumed);
    println!(
        "CRASH the node accepted {} transactions",
        rig.node.distinct_submissions().len()
    );

    // And on to ready, still with no provider anywhere.
    rig.node.facts.lock().unwrap().funded = true;
    let ready = rig.press(&hub_url).await;
    say("CRASH", "final press", &ready);
    println!(
        "CRASH the node accepted {} transactions in total",
        rig.node.distinct_submissions().len()
    );

    rig.node_server.abort();
}

/// PRESSED AGAIN AND AGAIN AS FAST AS THE COMMAND WILL TAKE IT.
///
/// Ten presses back to back with the deposit never confirming, then ten more
/// once it has. What must never change is the number of transactions the node
/// was handed and the fee inside the record.
#[tokio::test(flavor = "multi_thread")]
async fn pressed_ten_times_before_and_after_the_deposit_confirms() {
    let mut rig = rig("abuse-mash-hub").await;
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    for press in 1..=10 {
        let result = rig.press(&hub_url).await;
        if press == 1 || press == 10 {
            say("MASH", &format!("press {press}"), &result);
        }
    }
    println!(
        "MASH after ten presses the node holds {} distinct transactions",
        rig.node.distinct_submissions().len()
    );
    println!("MASH record: {:?}", rig.open_record());

    rig.node.facts.lock().unwrap().funded = true;
    for _ in 1..=10 {
        let _ = rig.press(&hub_url).await;
    }
    println!(
        "MASH after ten more presses the node holds {} distinct transactions",
        rig.node.distinct_submissions().len()
    );
    println!("MASH record after: {:?}", rig.open_record());

    hub_server.abort();
    drop(hub_state);
    rig.node_server.abort();
}

/// THE SAME NODE REFUSAL, THROUGH THE COMMAND THE SCREEN ACTUALLY CALLS.
///
/// `agent_wallet_fund_hvm_registry_channel` is the one wired to a button. This
/// puts the identical failure in front of it, so the two answers can be
/// compared side by side.
#[tokio::test(flavor = "multi_thread")]
async fn the_shipped_funding_command_meets_the_same_refusal() {
    let mut rig = rig("abuse-shipped-hub").await;
    {
        let mut facts = rig.node.facts.lock().unwrap();
        facts.balance_hac = "0.10000000".to_owned();
        facts.refuse_submit = Some("insufficient balance for amount and fee".to_owned());
    }
    let (hub_url, hub_state, hub_server) = rig.hub_up().await;

    let now = now_unix();
    let opened = open_hvm_registry_channel(
        &mut rig.wallet.manager,
        &rig.wallet.wallet_id,
        &hub_url,
        rig.binding_json.clone(),
        DEPOSIT_ZHU,
        now,
    )
    .await;
    println!("SHIPPED open ok: {}", opened.is_ok());

    let funded =
        fund_hvm_registry_channel(&mut rig.wallet.manager, &rig.wallet.wallet_id, now).await;
    say("SHIPPED", "fund command", &funded);
    println!("SHIPPED record: {:?}", rig.open_record());
    println!(
        "SHIPPED the node accepted {} transactions",
        rig.node.distinct_submissions().len()
    );

    // And the establish command, over the very same wallet state.
    let pressed = rig.press(&hub_url).await;
    say("SHIPPED", "establish command over the same state", &pressed);

    hub_server.abort();
    drop(hub_state);
    rig.node_server.abort();
}
