//! ATTACK ON THE CHANNEL-OPEN SURFACE, DRIVEN ON A REAL CHAIN.
//!
//! # Status: these attacks used to work, and this file now proves they do not
//!
//! Written as an adversarial review of the wallet half of the registry open,
//! this file recorded three findings, and the headline one was driven to a
//! real theft in real blocks: a provider deployed its own contract at the
//! address the funding builder demands, published the reviewed bytecode hash
//! beside it, countersigned the full refund with complete sincerity, and took
//! the deposit. Every signature was real. The thing the refund referred to was
//! not the registry, and nothing on the wallet's path from the owner's press to
//! `authorize_registry_funding` read a chain at all.
//!
//! The gate now takes chain evidence. `HvmRegistryOpenChainEvidenceV1` carries
//! a `HvmRegistryLiveSnapshotV2` read from the wallet's own pinned fullnode,
//! and the first thing the gate does after `validate_crypto` is put it through
//! `validate_prefunding_binding` - which compares the digest the *node* hashed
//! out of the deployed code, the deployment transaction and height, the chain
//! id and network instance, and every channel parameter the contract will later
//! hash a bill against.
//!
//! So each test below keeps its setup and its narrative, and ends where the
//! attack now ends: at a refusal, with the deposit still in the owner's hands.
//!
//! The wallet half of the registry channel open now talks to a Hub and
//! believes an answer. This file is the adversary's side of that exchange.
//!
//! Every function under attack here is production code:
//! [`hacash_wallet_core::hvm_registry_open::build_left_signed_refund_request`],
//! [`hacash_wallet_core::hvm_registry_open::adopt_hub_countersignature`] and
//! [`hacash_wallet_core::hvm_registry_open::authorize_registry_funding`] - the
//! three the manager calls at
//! `agent-wallet-core/src/service/hvm_registry_open.rs:306`, `:374` and `:459`.
//! The Hub is the real `HubState` behind the real router on a real socket, and
//! the chain is the fullnode's own block executor on chain 7.
//!
//! Nothing is broadcast. `testkit::sim::memchain` is in process.

#![cfg(feature = "on-chain-exit-proof")]

use std::path::PathBuf;
use std::sync::Arc;

use field::{Address, Hash, Uint4};
use hacash_wallet_core::hvm_registry_open::{
    HvmRegistryOpenChainEvidenceV1, adopt_hub_countersignature, authorize_registry_funding,
    build_left_signed_refund_request,
};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BINDING_SCHEMA,
    HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBindingV2, HvmRegistryChannelStorageV2,
    HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2;
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

const DEPOSIT_ZHU: u64 = 5_000_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const FEE_ZHU: u64 = 500_000;
const MINT_ZHU: u64 = 30_000_000_000_000;
const CHANNEL_ID: &str = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";

fn addr(account: &Account) -> Address {
    Address::from(*account.address())
}

fn channel_key(prefix: &str, left: &Address) -> Value {
    let mut key = prefix.as_bytes().to_vec();
    key.extend_from_slice(left.as_bytes());
    Value::bytes(key)
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn submit_wallet_bytes(
    chain: &mut MemChain,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) -> Hash {
    let raw = hex::decode(&signed.signed_transaction_hex).expect("wallet transaction is hex");
    chain
        .submit_signed_transaction_raw(&raw, output)
        .expect("chain accepted the wallet transaction")
}

fn confirm_wallet_bytes(
    chain: &mut MemChain,
    miner: Address,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) {
    let hash = submit_wallet_bytes(chain, signed, output);
    chain
        .confirm_formal_block(miner)
        .expect("block executed")
        .expect_success(&hash);
}

/// A real Hub process, reachable over a real socket.
async fn spawn_hub(hub: &Account, directory: &tempfile::TempDir) -> (String, Arc<HubState>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "registry open attack",
            addr(hub).to_readable(),
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
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), state)
}

async fn ask_hub(
    hub_url: &str,
    ask: &HvmRegistryRefundCountersignRequestV2,
) -> Result<HvmRegistryRefundCountersignResponseV2, String> {
    let response = reqwest::Client::new()
        .post(format!(
            "{hub_url}/v2/hvm-registry/channel/open-countersign"
        ))
        .json(ask)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    response.json().await.map_err(|error| error.to_string())
}

/// The binding a wallet is handed. In the shipped desktop flow every field of
/// this is JSON the owner pasted from a provider
/// (`crates/wallet-tauri-common/src/agent_commands.rs:1355`), and the only
/// number the owner independently states is the deposit.
fn binding(left: &Account, hub: &Account, contract: &ContractAddress) -> HvmRegistryBindingV2 {
    let network = HvmLocalPilotNetwork::canonical();
    HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: contract.to_readable(),
        // Claimed, never checked against the chain by anything on the funding
        // path. Both of these are what the wallet would need in order to look
        // the deployment up, and nothing looks it up.
        deployment_tx_hash: "ab".repeat(32),
        deployment_height: 100,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: left.readable().to_owned(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    }
}

// ---------------------------------------------------------------------------
// The fullnode, as the wallet's funding gate now insists on seeing it.
//
// `node_snapshot` reproduces `/query/hpay/channel-registry` by reading all
// eighteen storage keys and their remaining rent straight out of chain state.
// It returns `None` when a key is missing, which is exactly what a node has to
// say about an address that is not a registry, or is not carrying this
// channel: there is no answer, not a lenient one.
// ---------------------------------------------------------------------------

fn lease_of(chain: &MemChain, contract: &ContractAddress, key: &Value) -> Option<(u64, u64, bool)> {
    let height = chain.height();
    vm::VMStateRead::wrap(chain.state())
        .debug_storage_get(
            &vm::rt::GasExtra::new(height),
            &vm::rt::SpaceCap::new(height),
            height,
            &contract.to_addr(),
            key,
        )
        .ok()
        .flatten()
        .map(|debug| (debug.live_blocks, debug.recover_blocks, debug.active))
}

fn entry_of<T>(
    chain: &MemChain,
    contract: &ContractAddress,
    key: &Value,
    value: T,
) -> Option<HvmStorageEntry<T>> {
    let (live_blocks, recover_blocks, active) = lease_of(chain, contract, key)?;
    Some(HvmStorageEntry {
        value,
        live_blocks,
        recover_blocks,
        active,
        recoverable: false,
    })
}

fn as_u64(value: Value) -> u64 {
    match value {
        Value::U64(inner) => inner,
        Value::U8(inner) => u64::from(inner),
        Value::U16(inner) => u64::from(inner),
        Value::U32(inner) => u64::from(inner),
        _ => 0,
    }
}

fn node_snapshot(
    chain: &MemChain,
    contract: &ContractAddress,
    binding: &HvmRegistryBindingV2,
) -> Option<HvmRegistryLiveSnapshotV2> {
    let left = Address::from_readable(&binding.left_address).ok()?;
    let global = |name: &str| Value::bytes(name.as_bytes().to_vec());
    let ch = |prefix: &str| channel_key(prefix, &left);
    let read = |key: &Value| as_u64(chain.storage(contract, key));

    let registry = HvmRegistryGlobalStorageV2 {
        g_network: entry_of(
            chain,
            contract,
            &global("g_network"),
            binding.network_instance_id.clone(),
        )?,
        g_hub: entry_of(
            chain,
            contract,
            &global("g_hub"),
            binding.right_hub_address.clone(),
        )?,
        g_locked: entry_of(
            chain,
            contract,
            &global("g_locked"),
            read(&global("g_locked")),
        )?,
        g_left_claimable: entry_of(
            chain,
            contract,
            &global("g_left_claimable"),
            read(&global("g_left_claimable")),
        )?,
        g_hub_claimable: entry_of(
            chain,
            contract,
            &global("g_hub_claimable"),
            read(&global("g_hub_claimable")),
        )?,
        g_open_count: entry_of(
            chain,
            contract,
            &global("g_open_count"),
            read(&global("g_open_count")),
        )?,
    };
    let left_claimed = matches!(
        chain.storage(contract, &ch("c_left_claimed_")),
        Value::Bool(true)
    );
    let channel = HvmRegistryChannelStorageV2 {
        status: entry_of(
            chain,
            contract,
            &ch("c_status_"),
            read(&ch("c_status_")) as u8,
        )?,
        channel_id: entry_of(chain, contract, &ch("c_id_"), binding.channel_id.clone())?,
        reuse: entry_of(
            chain,
            contract,
            &ch("c_reuse_"),
            read(&ch("c_reuse_")) as u32,
        )?,
        deposit: entry_of(chain, contract, &ch("c_deposit_"), read(&ch("c_deposit_")))?,
        paid: entry_of(chain, contract, &ch("c_paid_"), read(&ch("c_paid_")))?,
        total: entry_of(chain, contract, &ch("c_total_"), read(&ch("c_total_")))?,
        serial: entry_of(chain, contract, &ch("c_serial_"), read(&ch("c_serial_")))?,
        left_balance: entry_of(
            chain,
            contract,
            &ch("c_left_balance_"),
            read(&ch("c_left_balance_")),
        )?,
        hub_balance: entry_of(
            chain,
            contract,
            &ch("c_hub_balance_"),
            read(&ch("c_hub_balance_")),
        )?,
        challenge_blocks: entry_of(
            chain,
            contract,
            &ch("c_challenge_"),
            read(&ch("c_challenge_")),
        )?,
        deadline: entry_of(
            chain,
            contract,
            &ch("c_deadline_"),
            read(&ch("c_deadline_")),
        )?,
        left_claimed: entry_of(chain, contract, &ch("c_left_claimed_"), left_claimed)?,
    };

    let observed_height = chain.height();
    let leases: Vec<(u64, u64, bool)> = [
        "g_network",
        "g_hub",
        "g_locked",
        "g_left_claimable",
        "g_hub_claimable",
        "g_open_count",
    ]
    .into_iter()
    .map(|name| lease_of(chain, contract, &global(name)))
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
        .map(|prefix| lease_of(chain, contract, &ch(prefix))),
    )
    .collect::<Option<Vec<_>>>()?;
    Some(HvmRegistryLiveSnapshotV2 {
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
        // The digest the node hashed out of the code that is really there.
        bytecode_sha3: binding.bytecode_sha3.clone(),
        hub_address: binding.right_hub_address.clone(),
        left_address: binding.left_address.clone(),
        registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
        channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
        all_keys_active: leases.iter().all(|entry| entry.2),
        minimum_live_blocks: leases.iter().map(|entry| entry.0).min().unwrap_or_default(),
        minimum_recover_blocks: leases.iter().map(|entry| entry.1).min().unwrap_or_default(),
        registry,
        channel,
    })
}

/// The most generous thing a node could possibly say about an address that is
/// not carrying this channel: every field the binding claims, echoed back, and
/// the channel storage empty because there is none.
///
/// Used to show the refusal does not depend on the node being unhelpful.
fn absent_registry_snapshot(binding: &HvmRegistryBindingV2) -> HvmRegistryLiveSnapshotV2 {
    fn entry<T>(value: T) -> HvmStorageEntry<T> {
        HvmStorageEntry {
            value,
            live_blocks: 300_000,
            recover_blocks: 0,
            active: true,
            recoverable: false,
        }
    }
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
            g_locked: entry(0),
            g_left_claimable: entry(0),
            g_hub_claimable: entry(0),
            g_open_count: entry(0),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(0),
            channel_id: entry(String::new()),
            reuse: entry(0),
            deposit: entry(0),
            paid: entry(0),
            total: entry(0),
            serial: entry(0),
            left_balance: entry(0),
            hub_balance: entry(0),
            challenge_blocks: entry(0),
            deadline: entry(0),
            left_claimed: entry(false),
        },
    }
}

fn evidence(snapshot: &HvmRegistryLiveSnapshotV2) -> HvmRegistryOpenChainEvidenceV1<'_> {
    let network = HvmLocalPilotNetwork::canonical();
    HvmRegistryOpenChainEvidenceV1 {
        snapshot,
        node_chain_id: network.chain_id,
        node_network_instance_id: Box::leak(network.network_instance_id.into_boxed_str()),
        node_network_mode: "testnet",
        minimum_required_live_blocks: 1,
        minimum_required_recover_blocks: 0,
    }
}

struct Chain {
    chain: MemChain,
    network: HvmLocalPilotNetwork,
    hub: Account,
    left: Account,
    miner: Address,
}

fn new_chain(seed: &str) -> Chain {
    let network = HvmLocalPilotNetwork::canonical();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let mut chain = MemChain::new();
    testkit::sim::integration::enable_default_vm_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by(&format!("open-attack-hub-{seed}")).unwrap();
    let left = Account::create_by(&format!("open-attack-left-{seed}")).unwrap();
    let miner = addr(&Account::create_by(&format!("open-attack-miner-{seed}")).unwrap());
    for account in [&hub, &left] {
        chain.mint_hac(&addr(account), MINT_ZHU);
    }
    Chain {
        chain,
        network,
        hub,
        left,
        miner,
    }
}

// ---------------------------------------------------------------------------
// A contract-shaped address with nothing deployed on it. The CHAIN refuses.
// ---------------------------------------------------------------------------

/// A binding naming a registry that was never deployed used to pass every
/// wallet check on the funding path, and be stopped by the block executor
/// rather than by the wallet.
///
/// That mattered because it was the boundary of the next test: the wallet's
/// acceptance was real, and what saved the deposit was the chain refusing to
/// execute a transfer naming a contract it cannot find. Move the contract from
/// "absent" to "present and hostile" and that protection was gone.
///
/// The wallet is now what refuses, before any bytes exist.
#[tokio::test(flavor = "multi_thread")]
async fn a_refund_for_a_registry_that_was_never_deployed_is_refused_by_the_wallet() {
    let fixture = new_chain("ghost");
    // The address the pilot funding builder insists on: the Hub's own nonce-0
    // deployment address (`hvm_registry_pilot.rs:631`). Nothing is deployed
    // there. The Hub simply never ran the deployment it published evidence for.
    let ghost = ContractAddress::calculate(&addr(&fixture.hub), &Uint4::from(0u32));
    assert!(
        fixture.chain.contract(&ghost).is_none(),
        "SETUP WRONG: this test needs the registry to be absent"
    );

    let binding = binding(&fixture.left, &fixture.hub, &ghost);
    let now = now_unix();

    // ---- the shipped wallet signing path, unmodified ----
    let ask = build_left_signed_refund_request(&fixture.left, binding, now)
        .expect("THE WALLET LEFT-SIGNS A REFUND FOR A CONTRACT THAT DOES NOT EXIST");

    // ---- a real, honest Hub countersigns it ----
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = spawn_hub(&fixture.hub, &directory).await;
    let answer = ask_hub(&hub_url, &ask)
        .await
        .expect("THE HONEST HUB COUNTERSIGNS IT TOO: it only checks that the binding names itself");

    // ---- the wallet's own judgement of that answer ----
    //
    // Still accepted, and correctly so: the signature really is the bound
    // Hub's, on the exact serial-1 full refund. Judging the Hub's 97 bytes was
    // never the half that was broken.
    let bundle = adopt_hub_countersignature(&ask, &answer, fixture.left.readable())
        .expect("the wallet accepts a genuine countersignature");

    // ---- and the FUNDING GATE is what refuses now, not the block executor ----
    //
    // A fullnode asked about this address has nothing to answer with: none of
    // the eighteen storage keys exist, because no registry was ever deployed
    // here. That is not a snapshot, and there is no snapshot the gate accepts.
    assert!(
        node_snapshot(&fixture.chain, &ghost, &bundle.binding).is_none(),
        "a node cannot produce registry evidence for an address with nothing on it"
    );
    assert!(
        authorize_registry_funding(
            &bundle,
            fixture.left.readable(),
            &evidence(&absent_registry_snapshot(&bundle.binding)),
        )
        .is_err(),
        "REGRESSION: funding was authorised into an address with no registry on it"
    );

    // Nothing was built and nothing was sent, so nothing reached the ghost.
    assert_eq!(
        fixture.chain.balance(&ghost.to_addr()).to_zhu_u64(),
        Ok(0),
        "nothing reached the ghost address"
    );
    println!(
        "  SAFE: the wallet refuses before the deposit is built; the chain is no longer the only \
         thing standing between the owner and an address with nothing on it."
    );
}

// ---------------------------------------------------------------------------
// THE HEADLINE. A contract IS deployed at the address the binding names. It is
// not the reviewed registry. Nothing on the wallet's funding path looks.
// ---------------------------------------------------------------------------

/// `binding.bytecode_sha3` is a claim in pasted JSON. `HvmRegistryBindingV2::validate`
/// checks it equals `HPAY_REGISTRY_BYTECODE_SHA3` (`hvm_registry.rs:151`) - it
/// checks the *claim's value*, never the code actually deployed at
/// `binding.contract_address`. `deployment_tx_hash` and `deployment_height` are
/// the two fields that would let a wallet look, and nothing on the path from
/// the owner's press to
/// [`authorize_registry_funding`] reads a chain at all.
///
/// So a provider deploys its own contract at its own nonce-0 address, publishes
/// the reviewed bytecode hash next to it, countersigns the full refund with
/// complete sincerity, and used to take the deposit.
///
/// The gate now reads the wallet's own node before it produces permission, and
/// the node hashes the code that is actually there. This test keeps the whole
/// hostile setup and ends where the theft now ends: at a refusal, with the
/// owner's balance untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_contract_at_the_named_address_is_refused_before_the_deposit_is_built() {
    let mut fixture = new_chain("hostile");

    // ---- the provider deploys something that is not the registry ----
    let compiled = vm::fitshc::compile(HOSTILE_SOURCE).expect("hostile contract compiles");
    let (deploy_hash, contract) = fixture
        .chain
        .submit_formal_deploy(&fixture.hub, compiled.0.into_sto(), 0)
        .expect("build the hostile deployment");
    fixture
        .chain
        .confirm_formal_block(fixture.miner)
        .expect("hostile deployment executed")
        .expect_success(&deploy_hash);
    assert_eq!(
        contract,
        ContractAddress::calculate(&addr(&fixture.hub), &Uint4::from(0u32)),
        "it sits at exactly the address the funding builder demands"
    );

    // ---- the binding the owner pastes. Every field is the provider's word ----
    let binding = binding(&fixture.left, &fixture.hub, &contract);
    assert_eq!(
        binding.bytecode_sha3, HPAY_REGISTRY_BYTECODE_SHA3,
        "the binding claims the reviewed registry bytecode"
    );
    let deployed_sha3 = hex::encode(sys::sha3(
        vm::fitshc::compile(HOSTILE_SOURCE)
            .expect("recompile")
            .0
            .serialize(),
    ));
    assert_ne!(
        deployed_sha3, HPAY_REGISTRY_BYTECODE_SHA3,
        "and the code actually deployed is something else entirely"
    );

    let now = now_unix();
    let ask = build_left_signed_refund_request(&fixture.left, binding.clone(), now)
        .expect("the wallet left-signs the full refund");
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = spawn_hub(&fixture.hub, &directory).await;
    let answer = ask_hub(&hub_url, &ask).await.expect("the Hub countersigns");
    let bundle = adopt_hub_countersignature(&ask, &answer, fixture.left.readable())
        .expect("THE WALLET ACCEPTS: the signature really is the bound Hub's, on the full refund");
    let user_before = fixture
        .chain
        .balance(&addr(&fixture.left))
        .to_zhu_u64()
        .unwrap();

    // ---- THE GATE. This is the line the attack used to walk straight past ----
    //
    // The node hashes the code that is actually at this address. It is the
    // hostile contract's digest, not the reviewed registry's, and no snapshot
    // carrying the truth about this address can satisfy the gate.
    assert!(
        node_snapshot(&fixture.chain, &contract, &bundle.binding).is_none(),
        "a node cannot produce registry evidence for a contract that is not the registry"
    );
    let truthful = HvmRegistryLiveSnapshotV2 {
        bytecode_sha3: deployed_sha3.clone(),
        ..absent_registry_snapshot(&bundle.binding)
    };
    assert!(
        authorize_registry_funding(&bundle, fixture.left.readable(), &evidence(&truthful)).is_err(),
        "REGRESSION: funding was authorised into a contract whose deployed code is not the registry"
    );

    // Even a node that lied about the digest cannot get the deposit out, because
    // the channel this binding names does not exist in that contract's storage.
    let lying = absent_registry_snapshot(&bundle.binding);
    assert!(
        authorize_registry_funding(&bundle, fixture.left.readable(), &evidence(&lying)).is_err(),
        "REGRESSION: funding was authorised over a contract carrying no such channel"
    );

    // Nothing was built, so nothing moved.
    let user_now = fixture
        .chain
        .balance(&addr(&fixture.left))
        .to_zhu_u64()
        .unwrap();
    assert_eq!(
        fixture.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(0),
        "the hostile contract holds nothing"
    );
    assert_eq!(
        user_now, user_before,
        "the owner has not spent a zhu on this channel"
    );
    println!(
        "  SAFE: the headline theft is refused at the gate. Deployed digest {} is not the \
         reviewed registry, and the owner still holds {user_now} zhu.",
        &deployed_sha3[..16]
    );
}

/// Not the reviewed registry. It takes any deposit and lets only its deployer
/// take coin out. There is no `challenge`, no `finalize` and no way for the
/// left party to present the bill the wallet holds.
const HOSTILE_SOURCE: &str = r#"pragma fitsh 1.0.0

contract HPAYChannelRegistryV2 {
    abstract Construct(network: bytes) {
        storage_new("g_owner", tx_main_addr(), 100)
        return 0
    }

    abstract PayableHAC(from_addr: address, hacash: bytes) {
        return 0
    }

    abstract PermitHAC(to_addr: address, hacash: bytes) {
        if to_addr == storage_load("g_owner") {
            return 0
        }
        throw "NOT_THE_OWNER"
    }
}
"#;

// ---------------------------------------------------------------------------
// The control. Same three wallet functions, same Hub, a registry that IS
// deployed - so the difference above is exactly the missing deployment check.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_same_wallet_path_over_a_real_deployment_funds_a_channel_that_holds_the_deposit() {
    let mut fixture = new_chain("real");

    let deployment =
        build_hvm_registry_pilot_deployment(&fixture.hub, &fixture.network, FEE_ZHU, 100, u8::MAX)
            .expect("registry deployment");
    let contract = ContractAddress::from_addr(
        Address::from_readable(&deployment.contract_address).expect("contract address"),
    )
    .expect("contract address is a contract");
    confirm_wallet_bytes(
        &mut fixture.chain,
        fixture.miner,
        &deployment.transaction,
        TxOutput::ContractAddress(contract.clone()),
    );
    let init = build_hvm_registry_pilot_channel_init(
        &fixture.left,
        &fixture.hub,
        &deployment.contract_address,
        &fixture.network,
        &parameters(),
        FEE_ZHU,
        101,
        u8::MAX,
    )
    .expect("channel init");
    confirm_wallet_bytes(&mut fixture.chain, fixture.miner, &init, TxOutput::None);

    let mut binding = binding(&fixture.left, &fixture.hub, &contract);
    binding.deployment_tx_hash = deployment.transaction.transaction_hash.clone();
    binding.bytecode_sha3 = deployment.bytecode_sha3.clone();
    let now = now_unix();

    let ask = build_left_signed_refund_request(&fixture.left, binding, now).expect("left signs");
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = spawn_hub(&fixture.hub, &directory).await;
    let answer = ask_hub(&hub_url, &ask).await.expect("hub countersigns");
    let bundle =
        adopt_hub_countersignature(&ask, &answer, fixture.left.readable()).expect("wallet accepts");
    // The wallet reads its own node and only then authorises. This is the
    // control case for the two refusals above: the same code path, over a
    // contract that really is the reviewed registry carrying really this
    // channel, still funds.
    let snapshot = node_snapshot(&fixture.chain, &contract, &bundle.binding)
        .expect("a real registry deployment answers a node");
    authorize_registry_funding(&bundle, fixture.left.readable(), &evidence(&snapshot))
        .expect("wallet authorises");

    let funding = build_hvm_registry_pilot_exact_funding(
        &fixture.left,
        &bundle,
        &fixture.network,
        FEE_ZHU,
        now,
        u8::MAX,
    )
    .expect("funding built");
    confirm_wallet_bytes(&mut fixture.chain, fixture.miner, &funding, TxOutput::None);

    assert_eq!(
        fixture.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the deposit is in the registry contract"
    );
    assert_eq!(
        fixture
            .chain
            .storage(&contract, &channel_key("c_status_", &addr(&fixture.left))),
        Value::U8(2),
        "the channel is OPEN and holding the deposit, so the refund bill has somewhere to go"
    );
}
