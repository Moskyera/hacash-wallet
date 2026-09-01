//! THE DEAD-HUB PROOF.
//!
//! A registry channel is opened, funded and *paid* — the user spends part of
//! their balance, so the amount owed to them is no longer the round deposit
//! they put in. Then the Hub is killed: its HTTP server is aborted, its state
//! is dropped, and the test asserts that a call to it now fails at the socket.
//!
//! From that moment the user has three things and nothing else: their own
//! private key, their own stored bill, and a chain. Every remaining
//! transaction is planned by
//! [`hacash_wallet_core::hvm_registry_exit::plan_user_exit_step`], built by
//! [`hacash_wallet_core::hvm_registry_exit::build_user_exit_transaction`],
//! signed with the *user's* key, and submitted as those exact bytes into the
//! fullnode's real block executor against real HVM contract state.
//!
//! # Why this file exists rather than another unit test
//!
//! The driver already had tests, and they passed while three separate things
//! were wrong in ways only a chain could show: the lease-rescue call asked for
//! more rent periods than the contract's `MAX_RENT_STEP` allows and was thrown
//! out on execution; the snapshot the driver reasons over was hand-built in
//! every test, so no test ever proved the driver could read a *real* one; and
//! nothing anywhere had ever run the four steps in sequence against a contract
//! that was actually holding coin.
//!
//! So nothing here is constructed for the driver's convenience. The contract
//! is deployed from the wallet's own signed bytes, the channel is opened and
//! funded by the wallet's own signed bytes, and the snapshot the driver reads
//! is assembled by reading all eighteen storage keys — values *and* their
//! remaining rent — straight out of chain state, exactly as the fullnode's
//! query endpoint does.
//!
//! Nothing is broadcast anywhere. `testkit::sim::memchain` is an in-process
//! chain; no mainnet is contacted and no real balance moves.

#![cfg(feature = "on-chain-exit-proof")]

use std::path::PathBuf;
use std::sync::Arc;

use field::{Address, Hash, Serialize as _, Sign};
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitPlanV1, HvmRegistryExitStep, build_exit_kit, build_user_exit_transaction,
    channel_lease_blocks, plan_user_exit_step, registry_lease_blocks,
};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2,
    HvmRegistryLiveSnapshotV2, HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA;
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
    build_hvm_registry_pilot_refund_countersign_request,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

const DEPOSIT_ZHU: u64 = 5_000_000_000;
/// What the user spends through the channel before the Hub dies. The exit must
/// settle at `DEPOSIT_ZHU - SPENT_ZHU`, not at the round deposit: an exit that
/// only ever works on an untouched channel is not an exit.
const SPENT_ZHU: u64 = 500_000_000;
const OWED_ZHU: u64 = DEPOSIT_ZHU - SPENT_ZHU;
const CHALLENGE_BLOCKS: u64 = 6;
const FEE_ZHU: u64 = 500_000;
const CHANNEL_ID: &str = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";

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

/// Put the wallet's exact signed bytes into the chain, unmodified.
fn submit_wallet_bytes(
    chain: &mut MemChain,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) -> Hash {
    let raw = hex::decode(&signed.signed_transaction_hex).expect("wallet transaction is hex");
    let hash = chain
        .submit_signed_transaction_raw(&raw, output)
        .expect("chain accepted the wallet transaction");
    assert_eq!(
        hex::encode(hash.as_bytes()),
        signed.transaction_hash,
        "the chain must agree with the wallet about the transaction hash"
    );
    hash
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

/// `(live_blocks, recover_blocks, active, recoverable)` for one storage key,
/// read out of real chain state rather than assumed.
fn lease(chain: &MemChain, contract: &ContractAddress, key: &Value) -> (u64, u64, bool, bool) {
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
    key: &Value,
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

fn as_u64(value: Value) -> u64 {
    match value {
        Value::U64(inner) => inner,
        Value::U8(inner) => u64::from(inner),
        Value::U16(inner) => u64::from(inner),
        Value::U32(inner) => u64::from(inner),
        other => panic!("expected an integer storage value, got {other:?}"),
    }
}

/// Assemble the live snapshot the driver reasons over, by reading all eighteen
/// storage keys and their remaining rent out of chain state.
///
/// This is the fullnode's `/query/hpay/channel-registry` answer reproduced
/// against an in-process chain. Nothing in it is chosen to make a check pass:
/// `minimum_live_blocks` and `minimum_recover_blocks` are the true minima over
/// every key, and `validate_snapshot_identity` re-derives both and refuses the
/// snapshot if they disagree.
fn read_snapshot(
    chain: &MemChain,
    contract: &ContractAddress,
    binding: &HvmRegistryBindingV2,
) -> HvmRegistryLiveSnapshotV2 {
    let left = Address::from_readable(&binding.left_address).expect("left address");
    let global = |name: &str| Value::bytes(name.as_bytes().to_vec());
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
        Value::Bool(true)
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
    // The true minima over all eighteen keys, measured from chain state. The
    // identity check re-derives both from the same entries and refuses the
    // snapshot if they disagree, so writing a convenient number here would
    // only defeat the one lease check the driver has.
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
    assert_eq!(
        leases.len(),
        18,
        "a V2 channel has 6 global and 12 channel keys"
    );
    snapshot.all_keys_active = leases.iter().all(|entry| entry.2);
    snapshot.minimum_live_blocks = leases.iter().map(|entry| entry.0).min().unwrap_or_default();
    snapshot.minimum_recover_blocks = leases.iter().map(|entry| entry.1).min().unwrap_or_default();
    snapshot
}

/// A bill both parties signed, in exactly the shape the shipped ledger mints:
/// the left balance falls by what was spent and the Hub's rises by the same.
fn countersigned_bill(
    binding: &HvmRegistryBindingV2,
    left: &Account,
    hub: &Account,
    serial: u64,
    left_balance_zhu: u64,
) -> HvmRegistryBillV2 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().expect("binding commitment"),
        serial,
        left_balance_zhu,
        hub_balance_zhu: binding.left_deposit_zhu - left_balance_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).expect("bill signing hash");
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    bill.validate_fully_signed(binding)
        .expect("both parties signed this bill");
    bill
}

async fn spawn_hub(
    hub: &Account,
    directory: &tempfile::TempDir,
) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "dead hub exit proof",
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
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (format!("http://{address}"), state, handle)
}

async fn ask_hub(
    hub_url: &str,
    ask: &HvmRegistryRefundCountersignRequestV2,
) -> Result<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2, String> {
    let response = reqwest::Client::new()
        .post(format!(
            "{hub_url}/v2/hvm-registry/channel/open-countersign"
        ))
        .json(ask)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    response.json().await.map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// THE PROOF
// ---------------------------------------------------------------------------

/// Everything up to and including the Hub's death, shared by both proofs.
///
/// Returns a funded, paid channel and the user's own head bill, with the Hub
/// process aborted and verified unreachable.
struct DeadHubChannel {
    chain: MemChain,
    contract: ContractAddress,
    binding: HvmRegistryBindingV2,
    left: Account,
    miner: Address,
    head: HvmRegistryBillV2,
}

async fn funded_channel_with_a_dead_hub(seed: &str) -> DeadHubChannel {
    let network = HvmLocalPilotNetwork::canonical();
    let mut chain = MemChain::new();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    // The wallet's bytes carry a ChainAllow guard naming the private pilot
    // chain, and the guard is checked against exactly this. Chain id 7.
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by(&format!("dead-hub-proof-hub-{seed}")).unwrap();
    let left = Account::create_by(&format!("dead-hub-proof-left-{seed}")).unwrap();
    let miner = addr(&Account::create_by(&format!("dead-hub-proof-miner-{seed}")).unwrap());
    for account in [&hub, &left] {
        chain.mint_hac(&addr(account), 30_000_000_000_000);
    }

    // ---- Deploy the reviewed registry from the wallet's own signed bytes.
    let deployment = build_hvm_registry_pilot_deployment(&hub, &network, FEE_ZHU, 100, u8::MAX)
        .expect("wallet built the registry deployment");
    let contract = ContractAddress::from_addr(
        Address::from_readable(&deployment.contract_address).expect("contract address"),
    )
    .expect("contract address is a contract");
    confirm_wallet_bytes(
        &mut chain,
        miner,
        &deployment.transaction,
        TxOutput::ContractAddress(contract.clone()),
    );
    let deployment_height = chain.height();

    // ---- Open the channel. The contract demands the Hub's co-signature here
    // and this is the last on-chain transaction the Hub takes any part in.
    let init = build_hvm_registry_pilot_channel_init(
        &left,
        &hub,
        &deployment.contract_address,
        &network,
        &parameters(),
        FEE_ZHU,
        101,
        u8::MAX,
    )
    .expect("wallet built the channel init");
    confirm_wallet_bytes(&mut chain, miner, &init, TxOutput::None);

    // ---- The Hub countersigns the serial-1 full refund, over a real socket,
    // before the user parts with anything. This is the gate that makes the
    // serial-0 trap unreachable.
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &directory).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ask = build_hvm_registry_pilot_refund_countersign_request(
        &left,
        hub.readable(),
        &deployment,
        deployment_height,
        &parameters(),
        now,
        now + 300,
    )
    .expect("wallet built the refund countersign ask");
    let answer = ask_hub(&hub_url, &ask).await.expect("Hub countersigned");
    assert_eq!(
        answer.schema,
        HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA
    );
    let bundle: HvmRegistryRecoveryBundleV2 = ask
        .attach_hub_countersignature(&answer.hub_refund_signature_hex)
        .expect("the Hub signature verifies against the wallet's own binding");
    let binding = bundle.binding.clone();

    // ---- Fund it. Now the contract is holding real coin.
    let funding =
        build_hvm_registry_pilot_exact_funding(&left, &bundle, &network, FEE_ZHU, 102, u8::MAX)
            .expect("funding requires a countersigned refund, and there is one");
    confirm_wallet_bytes(&mut chain, miner, &funding, TxOutput::None);
    assert_eq!(
        chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the deposit is inside the contract"
    );

    // ---- The user SPENDS through the channel. The Hub is still alive and
    // countersigns the serial-2 bill. This is the whole reason the exit cannot
    // just refund the deposit: the user is owed less than they put in, and the
    // exit has to settle at the real figure.
    let head = countersigned_bill(&binding, &left, &hub, 2, OWED_ZHU);
    assert_eq!(head.hub_balance_zhu, SPENT_ZHU);

    // =====================================================================
    // THE HUB DIES HERE. Server aborted, state dropped, socket closed.
    // =====================================================================
    hub_server.abort();
    drop(hub_state);
    // Give the aborted task a moment to release the listener, then prove the
    // Hub is genuinely gone rather than merely ignored.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let corpse = ask_hub(&hub_url, &ask).await;
    assert!(
        corpse.is_err(),
        "this proof is worthless unless the Hub is actually dead: {corpse:?}"
    );
    println!("HUB IS DEAD: {}", corpse.unwrap_err());

    DeadHubChannel {
        chain,
        contract,
        binding,
        left,
        miner,
        head,
    }
}

// ---------------------------------------------------------------------------
// THE PROOF
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_hub_is_killed_and_the_user_walks_their_own_money_out_alone() {
    let DeadHubChannel {
        mut chain,
        contract,
        binding,
        left,
        miner,
        head,
    } = funded_channel_with_a_dead_hub("exit").await;

    // ---- Everything from here is the user, their key, their bill, the chain.
    let kit = build_exit_kit(binding.clone(), head.clone()).expect("the user's own exit kit");
    assert!(
        serde_json::to_string(&kit)
            .unwrap()
            .find(&hex::encode(left.secret_key().serialize()))
            .is_none(),
        "the exit kit must never carry a private key"
    );

    let before_exit = chain.balance(&addr(&left)).to_zhu_u64().unwrap();
    let mut declared_fees = 0_u64;
    let mut steps_taken = Vec::new();
    let exit_fee = FEE_ZHU;

    for round in 0..12 {
        let snapshot = read_snapshot(&chain, &contract, &binding);
        let tip = chain.height();
        let plan = plan_user_exit_step(&kit, &snapshot, tip, 0).expect("the driver planned a step");

        match &plan {
            HvmRegistryExitPlanV1::Wait { reason } => {
                // Only legitimate reason to wait here is the objection window.
                assert_eq!(
                    snapshot.channel.status.value, 3,
                    "the driver waited outside the objection window: {reason}"
                );
                println!("WAIT (round {round}): {reason}");
                let deadline = snapshot.channel.deadline.value;
                chain
                    .confirm_empty_formal_blocks_to_height(miner, deadline)
                    .unwrap();
                continue;
            }
            HvmRegistryExitPlanV1::Call { step, .. } => steps_taken.push(format!("{step:?}")),
            HvmRegistryExitPlanV1::Claim {
                amount_zhu, payee, ..
            } => {
                assert_eq!(
                    payee, &binding.left_address,
                    "the payout can only ever be aimed at the channel's own left address"
                );
                steps_taken.push(format!("Claim({amount_zhu})"));
            }
        }

        // Signed with the USER's key. Not the Hub's; the Hub no longer exists.
        let signed = build_user_exit_transaction(
            &left,
            &kit,
            &plan,
            exit_fee,
            1_700_000_000 + round,
            u8::MAX,
        )
        .expect("the user's own key must be able to build their own exit");

        let raw = hex::decode(&signed.signed_transaction_hex).expect("exit transaction is hex");
        let hash = chain
            .submit_signed_transaction_raw(&raw, TxOutput::None)
            .expect("chain accepted the user's exit transaction");
        assert_eq!(
            hex::encode(hash.as_bytes()),
            signed.transaction_hash,
            "the chain must agree with the wallet about the transaction hash"
        );
        chain
            .confirm_formal_block(miner)
            .expect("block executed")
            .expect_success(&hash);
        declared_fees += exit_fee;
        println!(
            "STEP {}: {} mined at height {}",
            steps_taken.len(),
            steps_taken.last().unwrap(),
            chain.height()
        );

        if matches!(plan, HvmRegistryExitPlanV1::Claim { .. }) {
            break;
        }
    }

    // ---- What the chain says afterwards.
    let after_exit = chain.balance(&addr(&left)).to_zhu_u64().unwrap();
    assert_eq!(
        steps_taken,
        vec![
            "Challenge".to_owned(),
            "Finalize".to_owned(),
            format!("Claim({OWED_ZHU})"),
        ],
        "the user must have walked the whole sequence themselves"
    );
    assert_eq!(
        chain.storage(&contract, &channel_key("c_status_", &addr(&left))),
        Value::U8(4),
        "the channel is FINAL"
    );
    assert_eq!(
        chain.storage(&contract, &channel_key("c_left_claimed_", &addr(&left))),
        Value::Bool(true),
        "the user's share is marked claimed"
    );
    assert_eq!(
        chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(SPENT_ZHU),
        "only the Hub's earned share is left inside the contract"
    );
    // The user paid for every one of these transactions themselves, so their
    // balance rose by the payout less the true cost of getting it. That cost is
    // *measured* here rather than assumed: a declared network fee is not the
    // whole price of a Type 3, which also pays for its own HVM gas.
    let measured_cost = (before_exit + OWED_ZHU)
        .checked_sub(after_exit)
        .expect("the payout must have reached the user's own address");
    assert!(
        measured_cost >= declared_fees,
        "the measured cost cannot be below the fees the wallet itself declared"
    );
    // The assertion that makes this an exit rather than a ritual: getting the
    // money out costs less than the money. Worth stating as a test because it
    // is not automatic - at a 1,000,000 zhu deposit these same three
    // transactions cost about fifteen times the balance they recover, and a
    // "proof" run at that size would be a user going backwards.
    assert!(
        measured_cost < OWED_ZHU,
        "recovering {OWED_ZHU} zhu cost {measured_cost} zhu, so this exit is not worth walking"
    );
    assert!(
        after_exit > before_exit,
        "the user must end richer than they started"
    );

    println!(
        "PROOF: Hub dead. User signed {} transactions with their own key and recovered exactly \
         {OWED_ZHU} zhu - the balance they were owed, not the {DEPOSIT_ZHU} zhu deposit they put \
         in. Total cost to them: {measured_cost} zhu. Net: +{} zhu.",
        steps_taken.len(),
        after_exit - before_exit
    );
}

// ---------------------------------------------------------------------------
// THE RESCUE THAT USED TO BE UNEXECUTABLE
// ---------------------------------------------------------------------------

/// The lease is the only clock in this system that destroys a deposit outright:
/// when a channel's storage keys lapse for good, `c_status_` reads Nil, every
/// contract entry point aborts comparing Nil against a number, and the coin
/// stays inside the contract with nobody — not the user, not the Hub, not a
/// stranger — able to reach it.
///
/// So the driver refuses to *start* an exit on a short lease and renews first.
/// That rescue was, until this change, a transaction the chain threw out: the
/// wallet asked for 200 rent periods against a contract asserting
/// `periods <= MAX_RENT_STEP` with `MAX_RENT_STEP = 150`. The one escape from
/// the one irreversible outcome could not execute, and no test noticed because
/// no test had ever put a renewal in a block.
///
/// This one does. It ages the chain until the lease is genuinely short, lets
/// the driver decide what to do about it, signs whatever the driver chose with
/// the user's own key, mines it, and reads the lease back.
#[tokio::test]
async fn the_users_own_lease_rescue_executes_and_buys_real_blocks() {
    let DeadHubChannel {
        mut chain,
        contract,
        binding,
        left,
        miner,
        head,
    } = funded_channel_with_a_dead_hub("lease").await;

    let kit = build_exit_kit(binding.clone(), head.clone()).expect("the user's own exit kit");
    let status_key = channel_key("c_status_", &addr(&left));

    // Age the chain until the lease is below the exit floor but the keys are
    // still live. Aiming a little under the floor rather than at the cliff
    // keeps this a test of the rescue, not of dormancy recovery.
    let floor = hacash_wallet_core::hvm_registry_exit::exit_lease_floor_blocks(&binding);
    let (live_now, _, _, _) = lease(&chain, &contract, &status_key);
    let target = chain.height() + live_now - (floor / 2);
    chain
        .confirm_empty_formal_blocks_to_height(miner, target)
        .expect("age the chain");

    let before = read_snapshot(&chain, &contract, &binding);
    assert!(
        before.minimum_live_blocks < floor,
        "this test is only about the rescue if the lease is actually short: {} vs floor {floor}",
        before.minimum_live_blocks
    );
    println!(
        "LEASE IS SHORT: {} live blocks left, exit floor is {floor}",
        before.minimum_live_blocks
    );

    // The driver must choose to renew rather than to start an exit it cannot
    // finish, and it must choose the half that is actually short. It is asked,
    // not told: the test loops until the driver stops asking for rent, and
    // fails if it never does.
    let mut renewals = Vec::new();
    let mut snapshot = before.clone();
    for round in 0..8 {
        let plan = plan_user_exit_step(&kit, &snapshot, chain.height(), 0)
            .expect("the driver planned a step");
        let step = match &plan {
            HvmRegistryExitPlanV1::Call {
                step:
                    step @ (HvmRegistryExitStep::RenewRegistryLease
                    | HvmRegistryExitStep::RenewChannelLease),
                ..
            } => *step,
            other => {
                assert!(
                    !renewals.is_empty(),
                    "a short lease must be renewed before anything else, got {other:?}"
                );
                break;
            }
        };

        let signed = build_user_exit_transaction(
            &left,
            &kit,
            &plan,
            FEE_ZHU,
            1_700_009_000 + round,
            u8::MAX,
        )
        .expect("the user's own key must be able to buy their own channel more life");
        let raw = hex::decode(&signed.signed_transaction_hex).expect("renewal is hex");
        let hash = chain
            .submit_signed_transaction_raw(&raw, TxOutput::None)
            .expect("chain accepted the renewal");
        chain
            .confirm_formal_block(miner)
            .expect("block executed")
            // THIS is the assertion that was false before the fix. The old
            // constant asked for 200 rent periods against a contract capped at
            // 150, so the transaction mined and then aborted, renewing nothing.
            .expect_success(&hash);

        let after_one = read_snapshot(&chain, &contract, &binding);
        // The other half of the fix, and the reason the two halves are planned
        // separately at all. `renew_channel` touches only the twelve channel
        // keys and `renew_registry` only the six shared globals, while
        // `minimum_live_blocks` spans all eighteen. Renewing the half that is
        // not short executes happily and moves nothing, which is how this used
        // to become an unbounded loop paying a fee per pass while the clock it
        // was trying to beat ran out. So the half the driver *chose* must be
        // the half that moves.
        let (was, now) = match step {
            HvmRegistryExitStep::RenewRegistryLease => (
                registry_lease_blocks(&snapshot),
                registry_lease_blocks(&after_one),
            ),
            _ => (
                channel_lease_blocks(&snapshot),
                channel_lease_blocks(&after_one),
            ),
        };
        assert!(
            now > was,
            "{step:?} executed but the half it targets did not move: {was} -> {now}. Renewing              the half that is not short is a fee spent to stand still"
        );
        println!(
            "RESCUE {step:?}: that half {was} -> {now}; overall minimum {} -> {}",
            snapshot.minimum_live_blocks, after_one.minimum_live_blocks
        );
        renewals.push(step);
        snapshot = after_one;
    }

    assert!(
        !renewals.is_empty(),
        "the driver never rescued a lease that was below its own floor"
    );
    let after = snapshot;
    assert!(
        after.minimum_live_blocks >= floor,
        "the rescue must clear the floor it was triggered by, or the driver loops forever"
    );
    println!(
        "RESCUED with {renewals:?}, signed by the user alone with the Hub dead: {} -> {} live blocks",
        before.minimum_live_blocks, after.minimum_live_blocks
    );

    // And with the lease healthy the driver goes back to the exit it was
    // holding off on, which is the whole reason the rescue exists.
    let next = plan_user_exit_step(&kit, &after, chain.height(), 0).expect("the driver replanned");
    assert!(
        matches!(
            &next,
            HvmRegistryExitPlanV1::Call {
                step: HvmRegistryExitStep::Challenge,
                ..
            }
        ),
        "once the lease is safe the exit proceeds, got {next:?}"
    );
}
