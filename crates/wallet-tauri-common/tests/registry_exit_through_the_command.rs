//! THE OWNER PRESSES THE EXIT, THE PROVIDER IS DEAD, AND THE CHAIN PAYS THEM.
//!
//! # What was missing
//!
//! `agent-wallet-core` proves the *manager's* exit drive against a real
//! deployed `hpay_channel_registry_v2` in real blocks
//! (`service::hvm_registry::exit_on_chain_tests`). `wallet-tauri-common`
//! proves the *command* an owner presses, but against a hand-written fullnode
//! double whose eighteen storage entries are constants
//! (`registry_channel_press.rs`). Neither is the sentence the project needs:
//! **a run that enters at the Tauri command and ends with the owner paid on
//! chain.** The gap between the two proofs is exactly the gap between "the
//! driver works" and "a person can reach it".
//!
//! The two could not be joined because of one transaction. A registry `init`
//! carries `assert check_signature(left)` and `assert check_signature(g_hub)`
//! (`hpay_channel_registry_v2.fitsh:216-217`), so a channel whose left party
//! is an Agent Wallet cannot exist on any chain unless that wallet co-signs
//! the provider's opening transaction - and the wallet's key is inside its own
//! vault, which nothing outside `agent-wallet-core` can open. That is the
//! provider's half of the setup, it is not on the path being proven, and it is
//! now named once, in the crate that already opens the vault, as
//! `AgentWalletManager::provider_side_registry_channel_init` behind the
//! test-only `on-chain-exit-proof` feature.
//!
//! # What is real here
//!
//! * `testkit::sim::memchain::MemChain` on chain id 7 - the fullnode's own
//!   in-process chain, running the real block executor with `fast_sync: false`,
//!   so every signature on every transaction is genuinely verified.
//! * A real deployment of the reviewed registry contract and a real `init`, in
//!   real blocks.
//! * That chain behind a **real HTTP socket**, answering the five routes a
//!   person's own fullnode answers, so `FullnodeRegistryOpenChain` and
//!   `FullnodeRegistryExitChain` do the reqwest, the status codes and the JSON
//!   exactly as they would in the app. Its tip and its storage read are one
//!   height because they are one chain.
//! * A real `AgentWalletManager` on disk with a real unlocked wallet. Every
//!   signature after the setup comes from the wallet's own signing boundary;
//!   nothing below the setup block touches the key.
//! * A real `HubState` behind the real axum router on a real socket, which
//!   countersigns the refund once and is then **aborted and asserted dead**
//!   before the exit begins.
//! * The entry point, and this is the whole point of the file:
//!   `wallet_tauri_common::agent_commands::start_hvm_registry_exit` - the body
//!   of the `#[tauri::command] agent_wallet_start_hvm_registry_exit`, entered
//!   exactly as the command enters it and never handed a chain view. It builds
//!   its own from the `node_url` the wallet was created with.
//!
//! # What this file does not claim
//!
//! Nothing is broadcast, nothing reaches a public chain, and no money moves
//! anywhere. `MemChain` is in-process.

#![cfg(feature = "on-chain-exit-proof")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use agent_wallet_core::{AgentWalletId, AgentWalletManager, CreateAgentWallet};
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use field::Address;
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_deployment,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use serde_json::{Value, json};
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use tokio::sync::{mpsc, oneshot};
use vm::ContractAddress;
use vm::value::Value as VmValue;
use wallet_tauri_common::agent_commands::{
    establish_hvm_registry_channel, start_hvm_registry_exit,
};

const PASSPHRASE: &str = "agent wallet passphrase 123";
const DEPOSIT_ZHU: u64 = 5_000_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const SETUP_FEE_ZHU: u64 = 500_000;
const GAS_MAX: u8 = u8::MAX;
const CHANNEL_ID: &str = "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d";
const MINTED_ZHU: u64 = 30_000_000_000_000;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parameters() -> HvmRegistryPilotChannelParameters {
    HvmRegistryPilotChannelParameters {
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    }
}

// ---------------------------------------------------------------------------
// The chain, on one thread.
// ---------------------------------------------------------------------------
//
// `MemChain` holds a `MutexGuard<'static, ()>` for its whole life and the VM
// setup it needs is stored in *thread-local* state, so the chain is `!Send` and
// has to be driven from the one thread that built it. It is therefore owned by
// a dedicated thread and asked questions over a channel: the HTTP handlers ask,
// the test asks, and one chain answers both. That is not a workaround, it is
// the shape a fullnode already has - one chain, many callers.

/// One transaction as this node remembers it.
#[derive(Clone)]
struct SeenTransaction {
    body_hex: String,
    tx_type: u8,
    action_kinds: Vec<u16>,
    block_height: u64,
    block_hash: String,
}

enum AskKind {
    /// Credit an address directly, the way a chain's own coinbase would.
    Mint {
        address: String,
        zhu: u64,
    },
    /// Setup bytes: submit, mine, and refuse to continue unless the chain
    /// executed them successfully.
    Confirm {
        hex: String,
        contract_address: Option<String>,
    },
    /// Which channel this node will answer registry questions about.
    SetChannel(Box<HvmRegistryBindingV2>),
    Height,
    Snapshot,
    Seen(String),
    /// Wallet bytes, arriving over the wire. Accepted exactly as the chain
    /// accepts them, and mined into the next block.
    Submit(String),
    Balance(String),
    ContractBalance,
    MineEmptyTo(u64),
    /// Any transaction this node accepted that the block executor then failed.
    Failures,
    Settled,
}

enum Reply {
    Height(u64),
    Snapshot(Option<Box<HvmRegistryLiveSnapshotV2>>),
    Seen(Option<SeenTransaction>),
    Submitted(Result<String, String>),
    Zhu(u64),
    Done,
    Failures(Vec<String>),
    Settled(bool),
}

struct Ask {
    kind: AskKind,
    reply: oneshot::Sender<Reply>,
}

#[derive(Clone)]
struct Chain(mpsc::UnboundedSender<Ask>);

impl Chain {
    async fn ask(&self, kind: AskKind) -> Reply {
        let (reply, answer) = oneshot::channel();
        self.0
            .send(Ask { kind, reply })
            .expect("the chain is alive");
        answer.await.expect("the chain answered")
    }

    async fn height(&self) -> u64 {
        match self.ask(AskKind::Height).await {
            Reply::Height(height) => height,
            _ => unreachable!(),
        }
    }

    async fn zhu(&self, kind: AskKind) -> u64 {
        match self.ask(kind).await {
            Reply::Zhu(zhu) => zhu,
            _ => unreachable!(),
        }
    }

    async fn confirm(&self, signed: &HvmPilotSignedTransaction, contract_address: Option<&str>) {
        let reply = self
            .ask(AskKind::Confirm {
                hex: signed.signed_transaction_hex.clone(),
                contract_address: contract_address.map(str::to_owned),
            })
            .await;
        match reply {
            Reply::Submitted(Ok(hash)) => assert_eq!(
                hash, signed.transaction_hash,
                "the chain must agree with the builder about the transaction hash"
            ),
            Reply::Submitted(Err(error)) => panic!("the chain refused setup bytes: {error}"),
            _ => unreachable!(),
        }
    }

    async fn mine_empty_to(&self, height: u64) {
        match self.ask(AskKind::MineEmptyTo(height)).await {
            Reply::Done => {}
            _ => unreachable!(),
        }
    }

    async fn failures(&self) -> Vec<String> {
        match self.ask(AskKind::Failures).await {
            Reply::Failures(failures) => failures,
            _ => unreachable!(),
        }
    }

    async fn settled(&self) -> bool {
        match self.ask(AskKind::Settled).await {
            Reply::Settled(settled) => settled,
            _ => unreachable!(),
        }
    }
}

fn channel_key(prefix: &str, left: &Address) -> VmValue {
    let mut key = prefix.as_bytes().to_vec();
    key.extend_from_slice(left.as_bytes());
    VmValue::bytes(key)
}

fn lease(chain: &MemChain, contract: &ContractAddress, key: &VmValue) -> (u64, u64, bool, bool) {
    let height = chain.height();
    vm::VMStateRead::wrap(chain.state())
        .debug_storage_get(
            &vm::rt::GasExtra::new(height),
            &vm::rt::SpaceCap::new(height),
            height,
            &contract.to_addr(),
            key,
        )
        .expect("storage read")
        .map(|debug| {
            (
                debug.live_blocks,
                debug.recover_blocks,
                debug.active,
                debug.recoverable,
            )
        })
        .expect("a live channel's storage key must exist")
}

fn entry_of<T>(
    chain: &MemChain,
    contract: &ContractAddress,
    key: &VmValue,
    value: T,
) -> HvmStorageEntry<T> {
    let (live_blocks, recover_blocks, active, recoverable) = lease(chain, contract, key);
    HvmStorageEntry {
        value,
        live_blocks,
        recover_blocks,
        active,
        recoverable,
    }
}

fn as_u64(value: VmValue) -> u64 {
    match value {
        VmValue::U64(inner) => inner,
        VmValue::U8(inner) => u64::from(inner),
        VmValue::U16(inner) => u64::from(inner),
        VmValue::U32(inner) => u64::from(inner),
        other => panic!("expected an integer storage value, got {other:?}"),
    }
}

/// The `/query/hpay/channel-registry` answer, read out of contract state.
///
/// Every number here comes from the chain: the values from the eighteen
/// storage keys, the lease figures from the VM's own rent accounting, and the
/// height from the chain's own tip. Nothing in this function is a literal
/// standing in for something the chain would have said.
fn read_snapshot(
    chain: &MemChain,
    contract: &ContractAddress,
    binding: &HvmRegistryBindingV2,
) -> HvmRegistryLiveSnapshotV2 {
    let left = Address::from_readable(&binding.left_address).expect("left address");
    let global = |name: &str| VmValue::bytes(name.as_bytes().to_vec());
    let channel = |prefix: &str| channel_key(prefix, &left);

    let registry = HvmRegistryGlobalStorageV2 {
        g_network: entry_of(
            chain,
            contract,
            &global("g_network"),
            binding.network_instance_id.clone(),
        ),
        g_hub: entry_of(
            chain,
            contract,
            &global("g_hub"),
            binding.right_hub_address.clone(),
        ),
        g_locked: entry_of(
            chain,
            contract,
            &global("g_locked"),
            as_u64(chain.storage(contract, &global("g_locked"))),
        ),
        g_left_claimable: entry_of(
            chain,
            contract,
            &global("g_left_claimable"),
            as_u64(chain.storage(contract, &global("g_left_claimable"))),
        ),
        g_hub_claimable: entry_of(
            chain,
            contract,
            &global("g_hub_claimable"),
            as_u64(chain.storage(contract, &global("g_hub_claimable"))),
        ),
        g_open_count: entry_of(
            chain,
            contract,
            &global("g_open_count"),
            as_u64(chain.storage(contract, &global("g_open_count"))),
        ),
    };

    let left_claimed = matches!(
        chain.storage(contract, &channel("c_left_claimed_")),
        VmValue::Bool(true)
    );
    let channel_storage = HvmRegistryChannelStorageV2 {
        status: entry_of(
            chain,
            contract,
            &channel("c_status_"),
            as_u64(chain.storage(contract, &channel("c_status_"))) as u8,
        ),
        channel_id: entry_of(
            chain,
            contract,
            &channel("c_id_"),
            binding.channel_id.clone(),
        ),
        reuse: entry_of(
            chain,
            contract,
            &channel("c_reuse_"),
            as_u64(chain.storage(contract, &channel("c_reuse_"))) as u32,
        ),
        deposit: entry_of(
            chain,
            contract,
            &channel("c_deposit_"),
            as_u64(chain.storage(contract, &channel("c_deposit_"))),
        ),
        paid: entry_of(
            chain,
            contract,
            &channel("c_paid_"),
            as_u64(chain.storage(contract, &channel("c_paid_"))),
        ),
        total: entry_of(
            chain,
            contract,
            &channel("c_total_"),
            as_u64(chain.storage(contract, &channel("c_total_"))),
        ),
        serial: entry_of(
            chain,
            contract,
            &channel("c_serial_"),
            as_u64(chain.storage(contract, &channel("c_serial_"))),
        ),
        left_balance: entry_of(
            chain,
            contract,
            &channel("c_left_balance_"),
            as_u64(chain.storage(contract, &channel("c_left_balance_"))),
        ),
        hub_balance: entry_of(
            chain,
            contract,
            &channel("c_hub_balance_"),
            as_u64(chain.storage(contract, &channel("c_hub_balance_"))),
        ),
        challenge_blocks: entry_of(
            chain,
            contract,
            &channel("c_challenge_"),
            as_u64(chain.storage(contract, &channel("c_challenge_"))),
        ),
        deadline: entry_of(
            chain,
            contract,
            &channel("c_deadline_"),
            as_u64(chain.storage(contract, &channel("c_deadline_"))),
        ),
        left_claimed: entry_of(chain, contract, &channel("c_left_claimed_"), left_claimed),
    };

    let observed_height = chain.height();
    let mut snapshot = HvmRegistryLiveSnapshotV2 {
        ret: 0,
        schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        chain_id: binding.chain_id,
        network_instance_id: binding.network_instance_id.clone(),
        observed_height,
        evaluation_height: observed_height + 1,
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
        minimum_live_blocks: 0,
        minimum_recover_blocks: 0,
        registry,
        channel: channel_storage,
    };
    let leases: Vec<(u64, u64, bool, bool)> = [
        "g_network",
        "g_hub",
        "g_locked",
        "g_left_claimable",
        "g_hub_claimable",
        "g_open_count",
    ]
    .into_iter()
    .map(|name| lease(chain, contract, &global(name)))
    .chain(
        [
            "c_status_",
            "c_id_",
            "c_reuse_",
            "c_deposit_",
            "c_paid_",
            "c_total_",
            "c_serial_",
            "c_left_balance_",
            "c_hub_balance_",
            "c_challenge_",
            "c_deadline_",
            "c_left_claimed_",
        ]
        .into_iter()
        .map(|prefix| lease(chain, contract, &channel(prefix))),
    )
    .collect();
    assert_eq!(leases.len(), 18);
    snapshot.all_keys_active = leases.iter().all(|entry| entry.2);
    snapshot.minimum_live_blocks = leases.iter().map(|entry| entry.0).min().unwrap_or_default();
    snapshot.minimum_recover_blocks = leases.iter().map(|entry| entry.1).min().unwrap_or_default();
    snapshot
}

/// The chain thread: one `MemChain`, answering everything.
fn run_chain(mut asks: mpsc::UnboundedReceiver<Ask>, network: HvmLocalPilotNetwork, seed: &str) {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let mut chain = MemChain::new();
    testkit::sim::integration::enable_default_vm_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);
    let miner = Address::from(*Account::create_by(seed).unwrap().address());

    let mut block_hashes: HashMap<u64, String> = HashMap::new();
    let mut seen: HashMap<String, SeenTransaction> = HashMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut binding: Option<HvmRegistryBindingV2> = None;
    let mut contract: Option<ContractAddress> = None;

    // A block arrives, carrying whatever was handed in since the last one.
    // Every transaction it carries is remembered with the block it landed in,
    // and every one the executor failed is remembered too, so a node that
    // quietly buried a rejection cannot make this proof look green.
    let mine = |chain: &mut MemChain,
                block_hashes: &mut HashMap<u64, String>,
                seen: &mut HashMap<String, SeenTransaction>,
                failures: &mut Vec<String>| {
        let confirmed = chain
            .confirm_formal_block_observing_failures(miner)
            .expect("the chain executed a block");
        let block_hash = hex::encode(confirmed.block_hash.as_bytes());
        block_hashes.insert(confirmed.height, block_hash.clone());
        for receipt in &confirmed.receipts {
            let hash = hex::encode(receipt.tx_hash.as_bytes());
            if let Some(record) = seen.get_mut(&hash) {
                record.block_height = confirmed.height;
                record.block_hash = block_hash.clone();
            }
            if !receipt.success && seen.contains_key(&hash) {
                failures.push(format!("{hash}: {:?}", receipt.error));
            }
        }
        confirmed.height
    };

    while let Some(Ask { kind, reply }) = asks.blocking_recv() {
        let answer = match kind {
            AskKind::Mint { address, zhu } => {
                let address = Address::from_readable(&address).expect("address");
                chain.mint_hac(&address, zhu);
                Reply::Done
            }
            AskKind::Confirm {
                hex: body,
                contract_address,
            } => {
                let raw = hex::decode(&body).expect("setup bytes are hex");
                let output = match contract_address.as_deref() {
                    Some(address) => TxOutput::ContractAddress(
                        ContractAddress::from_addr(Address::from_readable(address).unwrap())
                            .unwrap(),
                    ),
                    None => TxOutput::None,
                };
                let answer = match chain.submit_signed_transaction_raw(&raw, output) {
                    Ok(hash) => {
                        let hash = hex::encode(hash.as_bytes());
                        seen.insert(
                            hash.clone(),
                            observe_seen(&body, &raw).expect("setup bytes parse"),
                        );
                        mine(&mut chain, &mut block_hashes, &mut seen, &mut failures);
                        match failures.last() {
                            Some(failure) if failure.starts_with(&hash) => Err(failure.clone()),
                            _ => Ok(hash),
                        }
                    }
                    Err(error) => Err(format!("{error:?}")),
                };
                Reply::Submitted(answer)
            }
            AskKind::SetChannel(new_binding) => {
                contract = Some(
                    ContractAddress::from_addr(
                        Address::from_readable(&new_binding.contract_address).unwrap(),
                    )
                    .unwrap(),
                );
                binding = Some(*new_binding);
                Reply::Done
            }
            AskKind::Height => Reply::Height(chain.height()),
            AskKind::Snapshot => Reply::Snapshot(match (&binding, &contract) {
                (Some(binding), Some(contract)) => {
                    Some(Box::new(read_snapshot(&chain, contract, binding)))
                }
                _ => None,
            }),
            AskKind::Seen(hash) => Reply::Seen(seen.get(&hash).cloned()),
            AskKind::Submit(body) => {
                let answer = match hex::decode(&body) {
                    Err(_) => Err("submitted body is not hex".to_owned()),
                    Ok(raw) => match observe(&body, &raw) {
                        None => Err("submitted transaction does not parse".to_owned()),
                        Some(record) => {
                            let hash = record.hash_hex.clone();
                            if seen.contains_key(&hash) {
                                // Idempotent by hash, exactly as a real node
                                // is: the wallet is entitled to hand the same
                                // bytes over again.
                                Ok(hash)
                            } else {
                                match chain.submit_signed_transaction_raw(&raw, TxOutput::None) {
                                    Ok(chain_hash) => {
                                        let chain_hash = hex::encode(chain_hash.as_bytes());
                                        assert_eq!(
                                            chain_hash, hash,
                                            "this node derives a hash with the chain's own codec"
                                        );
                                        seen.insert(hash.clone(), record.seen);
                                        mine(
                                            &mut chain,
                                            &mut block_hashes,
                                            &mut seen,
                                            &mut failures,
                                        );
                                        Ok(hash)
                                    }
                                    Err(error) => Err(format!("{error:?}")),
                                }
                            }
                        }
                    },
                };
                Reply::Submitted(answer)
            }
            AskKind::Balance(address) => {
                let address = Address::from_readable(&address).expect("address");
                Reply::Zhu(chain.balance(&address).to_zhu_u64().unwrap_or_default())
            }
            AskKind::ContractBalance => {
                let contract = contract.as_ref().expect("a channel has been set");
                Reply::Zhu(
                    chain
                        .balance(&contract.to_addr())
                        .to_zhu_u64()
                        .unwrap_or_default(),
                )
            }
            AskKind::MineEmptyTo(height) => {
                if height > chain.height() {
                    chain
                        .confirm_empty_formal_blocks_to_height(miner, height)
                        .expect("age the chain");
                    block_hashes.insert(
                        chain.height(),
                        hex::encode(chain.last_block_hash().as_bytes()),
                    );
                }
                Reply::Done
            }
            AskKind::Failures => Reply::Failures(failures.clone()),
            AskKind::Settled => {
                let settled = match (&binding, &contract) {
                    (Some(binding), Some(contract)) => {
                        let left = Address::from_readable(&binding.left_address).unwrap();
                        chain.storage(contract, &channel_key("c_status_", &left)) == VmValue::U8(4)
                            && chain.storage(contract, &channel_key("c_left_claimed_", &left))
                                == VmValue::Bool(true)
                    }
                    _ => false,
                };
                Reply::Settled(settled)
            }
        };
        let _ = reply.send(answer);
    }
}

struct Observed {
    hash_hex: String,
    seen: SeenTransaction,
}

/// What a node can say about bytes it was handed, derived from the bytes.
///
/// The transaction type and the action kinds are read out of the parsed
/// transaction rather than declared by whoever submitted it, because the
/// wallet's exit asks this node for a *specific* proof - Action 44 for the
/// contract calls, Action 14 for the payout - and a node that echoed back
/// whatever it was told would make that question meaningless.
fn observe(body_hex: &str, raw: &[u8]) -> Option<Observed> {
    let (parsed, used) = protocol::transaction::transaction_create(raw).ok()?;
    if used != raw.len() {
        return None;
    }
    let hash_hex = hex::encode(parsed.hash().as_bytes());
    let seen = SeenTransaction {
        body_hex: body_hex.to_ascii_lowercase(),
        tx_type: parsed.ty(),
        action_kinds: parsed
            .actions()
            .iter()
            .map(|action| action.kind())
            .collect(),
        block_height: 0,
        block_hash: String::new(),
    };
    Some(Observed { hash_hex, seen })
}

fn observe_seen(body_hex: &str, raw: &[u8]) -> Option<SeenTransaction> {
    observe(body_hex, raw).map(|observed| observed.seen)
}

// ---------------------------------------------------------------------------
// The chain, over real HTTP.
// ---------------------------------------------------------------------------

async fn capabilities_route(State(node): State<Arc<Node>>) -> Json<Value> {
    let network = &node.network;
    let height = node.chain.height().await;
    Json(json!({
        "ret": 0,
        "api_version": 1,
        "chain": {
            "id": network.chain_id,
            "height": height,
            "next_height": height + 1,
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
    State(node): State<Arc<Node>>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let Reply::Snapshot(Some(snapshot)) = node.chain.ask(AskKind::Snapshot).await else {
        return Json(json!({ "ret": 1, "err": "this node holds no such registry channel" }));
    };
    // A node answers about the channel it was asked about and no other.
    if query.get("contract").map(String::as_str) != Some(snapshot.contract_address.as_str())
        || query.get("left").map(String::as_str) != Some(snapshot.left_address.as_str())
        || query.get("deployment_tx_hash").map(String::as_str)
            != Some(snapshot.deployment_tx_hash.as_str())
    {
        return Json(json!({ "ret": 1, "err": "this node holds no such registry channel" }));
    }
    Json(serde_json::to_value(&*snapshot).expect("snapshot encodes"))
}

async fn transaction_route(
    State(node): State<Arc<Node>>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let Some(hash) = query.get("hash") else {
        return Json(json!({ "ret": 1, "err": "transaction not found" }));
    };
    let Reply::Seen(Some(seen)) = node.chain.ask(AskKind::Seen(hash.to_owned())).await else {
        return Json(json!({ "ret": 1, "err": "transaction not found" }));
    };
    let mut answer = json!({
        "ret": 0,
        "hash": hash,
        "tx_type": seen.tx_type,
        "actions": seen
            .action_kinds
            .iter()
            .map(|kind| json!({ "kind": kind }))
            .collect::<Vec<Value>>(),
        "signatures": [{ "publickey": "", "signature": "" }],
        "body": seen.body_hex,
    });
    if seen.block_height == 0 {
        answer["pending"] = json!(true);
    } else {
        let tip = node.chain.height().await;
        answer["pending"] = json!(false);
        // Depth, counted rather than asserted.
        answer["confirm"] = json!(tip.saturating_sub(seen.block_height) + 1);
        answer["block"] = json!({
            "height": seen.block_height,
            "hash": seen.block_hash,
        });
    }
    Json(answer)
}

async fn balance_route(
    State(node): State<Arc<Node>>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    let zhu = node.chain.zhu(AskKind::Balance(address.clone())).await;
    Json(json!({
        "ret": 0,
        "list": [{
            "address": address,
            "hacash": format!("{}.{:08}", zhu / 100_000_000, zhu % 100_000_000),
        }],
    }))
}

async fn submit_route(
    State(node): State<Arc<Node>>,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> Json<Value> {
    let network = &node.network;
    // A bound submit names the chain it is for, and a node on another chain
    // must refuse it rather than take the bytes.
    if query.get("chain_id").map(String::as_str) != Some(network.chain_id.to_string().as_str())
        || query.get("network_instance_id").map(String::as_str)
            != Some(network.network_instance_id.as_str())
    {
        return Json(json!({ "ret": 1, "err": "transaction is bound to another chain" }));
    }
    match node
        .chain
        .ask(AskKind::Submit(body.trim().to_ascii_lowercase()))
        .await
    {
        Reply::Submitted(Ok(hash)) => Json(json!({ "ret": 0, "hash": hash })),
        Reply::Submitted(Err(error)) => Json(json!({ "ret": 1, "err": error })),
        _ => unreachable!(),
    }
}

struct Node {
    chain: Chain,
    network: HvmLocalPilotNetwork,
}

async fn spawn_fullnode(node: Arc<Node>) -> String {
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
            "registry exit command proof",
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
// The proof.
// ---------------------------------------------------------------------------

/// THE COMMAND AN OWNER PRESSES, DRIVEN TO A PAYOUT WITH THE PROVIDER DEAD.
///
/// The setup is the provider's half and nothing else: a deployment, an `init`
/// this wallet co-signs because the contract requires it to, and a Hub alive
/// exactly long enough to countersign one full refund. From the moment the Hub
/// is aborted, every hop is a press of
/// `wallet_tauri_common::agent_commands::start_hvm_registry_exit` - the body of
/// the `#[tauri::command]` - and the only thing this test does between presses
/// is let blocks arrive, which is the one thing no amount of pressing shortens.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_an_owner_presses_walks_them_out_with_the_provider_dead() {
    let network = HvmLocalPilotNetwork::canonical();
    let (asks, receiver) = mpsc::unbounded_channel();
    let chain_network = network.clone();
    // Deliberately not joined at the end. The fullnode's router holds a clone
    // of this sender for as long as the server task lives, so the chain's
    // `recv` loop cannot end while the test is still able to ask it anything -
    // joining would hang rather than tidy up. A chain thread that died is
    // reported anyway: the next `ask` finds its reply channel closed.
    std::thread::spawn(move || {
        run_chain(receiver, chain_network, "command-exit-miner");
    });
    let chain = Chain(asks);

    let node_url = spawn_fullnode(Arc::new(Node {
        chain: chain.clone(),
        network: network.clone(),
    }))
    .await;

    // ---- a real Agent Wallet, created and unlocked through the manager ----
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let now = now_unix();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: node_url.clone(),
                block_one_fingerprint: Some(network.block_1_hash.clone()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    let wallet_id: AgentWalletId = created.wallet_id.clone();
    manager.unlock(&wallet_id, PASSPHRASE, now).unwrap();

    let hub = Account::create_by("command-exit-hub").unwrap();
    for address in [hub.readable(), created.address.as_str()] {
        chain
            .ask(AskKind::Mint {
                address: address.to_owned(),
                zhu: MINTED_ZHU,
            })
            .await;
    }

    // ---- the provider's half: a real deployment and a real channel ----
    //
    // `init` is co-signed, so the wallet's key is needed for it and only for
    // it. Nothing on the path being proven opens a registry channel, and
    // nothing below this block touches the key: every signature the exit makes
    // comes from the wallet's own signing boundary.
    let deployment =
        build_hvm_registry_pilot_deployment(&hub, &network, SETUP_FEE_ZHU, 100, GAS_MAX).unwrap();
    chain
        .confirm(&deployment.transaction, Some(&deployment.contract_address))
        .await;
    let deployment_height = chain.height().await;

    let init = manager
        .provider_side_registry_channel_init(
            &wallet_id,
            PASSPHRASE,
            &hub,
            &deployment.contract_address,
            &network,
            &parameters(),
            SETUP_FEE_ZHU,
            101,
            GAS_MAX,
        )
        .expect("the provider opens a channel this wallet co-signs");
    chain.confirm(&init, None).await;

    let binding = HvmRegistryBindingV2 {
        schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: created.address.clone(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    };
    binding.validate().expect("a reviewed-profile channel");
    chain
        .ask(AskKind::SetChannel(Box::new(binding.clone())))
        .await;
    let binding_json = serde_json::to_value(&binding).unwrap();

    // ---- the owner's press: open, fund and adopt, with the provider alive ----
    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;

    let ready = establish_hvm_registry_channel(
        &mut manager,
        &wallet_id,
        &hub_url,
        binding_json,
        DEPOSIT_ZHU,
        now,
    )
    .await
    .expect("one press opens, funds and adopts the channel");
    println!("  ESTABLISH: {ready}");
    assert_eq!(ready["stage"], "ready");
    assert_eq!(ready["funding_confirmed"], true);
    assert_eq!(ready["exit_available"], true);
    assert_eq!(
        chain.zhu(AskKind::ContractBalance).await,
        DEPOSIT_ZHU,
        "the deposit is inside the contract"
    );

    // ---- the provider dies, and stays dead for everything below ----
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

    let before = chain.zhu(AskKind::Balance(created.address.clone())).await;

    // ---- the exit, pressed ----
    let gate_open = l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready();
    if !gate_open {
        // The control is bounded by the project's own measurement, which is a
        // constant a human sets *and* a probe. While it reads false the command
        // must refuse in the owner's own terms rather than half-starting, and
        // that is asserted here so this file states whichever answer the
        // measurement gives rather than having to be edited on the day it
        // flips.
        let refusal = start_hvm_registry_exit(&mut manager, &wallet_id, now)
            .await
            .expect_err("the exit gate is the project's own measurement");
        assert!(
            refusal.contains("This wallet cannot yet send a channel exit for you"),
            "the refusal must name this app's own gap: {refusal}"
        );
        println!("  EXIT GATE CLOSED: {refusal}");
        assert!(!chain.settled().await);

        // WHICH HALF OF THE GATE IS DOWN, MEASURED RATHER THAN ASSUMED.
        //
        // `driver_ready` in the status this command reads is exactly
        // `measure_user_side_unilateral_exit_ready()`
        // (`agent_commands.rs:2831`), which is one human-set constant AND one
        // probe that drives the real builders with a real non-Hub key. Nothing
        // else stands between this run and the loop below: the channel is
        // adopted, the exit head is seeded, the fullnode is the one this
        // wallet is pinned to, and the Hub is dead. So this states which of
        // the two terms is the one refusing, on the day it refuses.
        assert!(
            l2_fast_pay_hub::hvm_registry_watchtower::user_key_can_build_registry_exit_transactions(
            ),
            "the measured half of the exit gate is failing, which is a real regression: this              software can no longer put an exit transaction in a user's hands"
        );
        // Read through `black_box` so the assertion survives: the constant is
        // a literal, so clippy folds it and rejects the assert as constant.
        // The check is not constant in meaning - it is the statement that the
        // refusal came from this term and not from one this test cannot see -
        // so it is kept and made opaque rather than deleted or silenced.
        assert!(
            !std::hint::black_box(
                l2_fast_pay_hub::readiness::USER_SIDE_UNILATERAL_EXIT_DRIVER_READY
            ),
            "the constant is up but the command still refused, which can only mean the gate              grew a term this test does not know about"
        );
        println!(
            "  THE ONLY UNMET TERM IS THE CONSTANT A HUMAN SETS:              USER_SIDE_UNILATERAL_EXIT_DRIVER_READY = false; the builders probe reads true"
        );
        return;
    }

    let mut presses = 0_u32;
    let claimed = loop {
        presses += 1;
        assert!(presses < 30, "the pressed exit did not terminate");
        let progress = start_hvm_registry_exit(&mut manager, &wallet_id, now)
            .await
            .expect("the command drives the owner's own exit");
        println!(
            "  PRESS {presses}: outcome {} step {:?} waiting {:?} status {:?} deadline {:?}",
            progress["outcome"],
            progress["step"],
            progress["waiting_reason"],
            progress["channel_status"],
            progress["deadline_height"],
        );
        match progress["outcome"].as_str().expect("an outcome") {
            "complete" => {
                break progress["claimed_zhu"]
                    .as_u64()
                    .expect("a complete exit names its payout");
            }
            "stepped" => continue,
            "waiting" => {
                let status = progress["channel_status"].as_u64();
                let deadline = progress["deadline_height"].as_u64();
                let height = chain.height().await;
                if status == Some(3)
                    && let Some(deadline) = deadline
                    && deadline > height
                {
                    // A laptop cannot mine blocks. This is the objection window
                    // passing, which is what an exit spends most of its life
                    // waiting for.
                    chain.mine_empty_to(deadline).await;
                    continue;
                }
                panic!("the pressed exit stalled: {progress}");
            }
            other => panic!("unknown outcome {other}"),
        }
    };

    // ---- the owner is paid, on chain, with the provider deleted ----
    assert!(
        chain.settled().await,
        "the channel is FINAL and the payout is made"
    );
    assert_eq!(
        claimed, DEPOSIT_ZHU,
        "the exit pays this wallet its whole settled balance"
    );
    assert_eq!(
        chain.zhu(AskKind::ContractBalance).await,
        0,
        "the deposit left the contract"
    );
    let after = chain.zhu(AskKind::Balance(created.address.clone())).await;
    assert!(
        after > before,
        "the exit has to leave the owner better off than not running it: {before} -> {after}"
    );
    let failed = chain.failures().await;
    assert!(
        failed.is_empty(),
        "the chain failed transactions this node accepted: {failed:?}"
    );
    println!(
        "  OWNER PAID: {} -> {} (+{}) after {presses} presses, contract 0",
        before,
        after,
        after - before
    );
}
