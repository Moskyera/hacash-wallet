//! THE NEW GATE, ATTACKED AS A DENIAL OF SERVICE.
//!
//! Funding now requires a Hub countersignature. That is a veto. These tests ask
//! what the veto costs, whether the user can tell they were vetoed, whether a
//! half-completed open can be finished later, and what happens to a signature
//! that was valid when it was given.
//!
//! Same machinery as `registry_open_countersign_on_chain.rs`: real wallet-built
//! transaction bytes, a real `HubState` behind the real axum router over a real
//! socket, real block execution on `testkit::sim::memchain::MemChain`.

#![cfg(feature = "local-pilot-tools")]

use std::path::PathBuf;
use std::sync::Arc;

use field::{AddrOrPtr, Address, Amount, Field as _, Hash};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::HvmRegistryRefundCountersignRequestV2;
use l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2;
use l2_fast_pay_hub::hvm_registry_pilot::{
    HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU, HvmRegistryPilotChannelParameters,
    build_hvm_registry_pilot_channel_init, build_hvm_registry_pilot_deployment,
    build_hvm_registry_pilot_exact_funding, build_hvm_registry_pilot_refund_countersign_request,
};
use protocol::action::HacToTrs;
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

const DEPOSIT_ZHU: u64 = 1_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const FEE_ZHU: u64 = 500_000;
const CHANNEL_ID: &str = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";

/// The hash this wallet pinned BEFORE the registry contract was fixed. Every
/// binding a previous build signed carries exactly this in `bytecode_sha3`.
const PREVIOUS_PINNED_BYTECODE_SHA3: &str =
    "276d8c205296cc50d06244c84d52c5a9f6f4711e0abae67f416e4fc79c9294be";

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

struct Fixture {
    chain: MemChain,
    hub: Account,
    left: Account,
    miner: Address,
    network: HvmLocalPilotNetwork,
    contract: ContractAddress,
    ask: HvmRegistryRefundCountersignRequestV2,
    /// Everything the user had before they touched this protocol.
    left_balance_at_start: u64,
    prefunded_to_hub: u64,
    deployment: l2_fast_pay_hub::hvm_pilot::HvmPilotDeploymentTransaction,
    deployment_height: u64,
}

/// The pilot's real spending order: the USER prefunds the Hub with the exact
/// deployment protocol cost, the HUB deploys, then the channel is `init`ed and
/// only then is the Hub asked for anything at all.
fn spend_up_to_the_ask(seed: &str, do_init: bool) -> Fixture {
    let network = HvmLocalPilotNetwork::canonical();
    let mut chain = MemChain::new();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by(&format!("dos-hub-{seed}")).unwrap();
    let left = Account::create_by(&format!("dos-left-{seed}")).unwrap();
    let miner = addr(&Account::create_by(&format!("dos-miner-{seed}")).unwrap());
    for account in [&hub, &left] {
        chain.mint_hac(&addr(account), 30_000_000_000_000);
    }
    let left_balance_at_start = chain.balance(&addr(&left)).to_zhu_u64().unwrap();

    // STEP 1. The user sends the Hub the deployment protocol cost. A plain
    // transfer to the Hub's own address: no contract, no escrow, no claim.
    let mut prefund = HacToTrs::new();
    prefund.to = AddrOrPtr::from_addr(addr(&hub));
    prefund.hacash = Amount::zhu(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU);
    let hash = chain
        .submit_formal_actions(
            &left,
            vec![addr(&left), addr(&hub)],
            vec![Box::new(prefund)],
            u8::MAX,
            TxOutput::None,
        )
        .expect("build the Hub prefunding");
    chain
        .confirm_formal_block(miner)
        .unwrap()
        .expect_success(&hash);

    // STEP 2. The Hub deploys, spending what the user just sent it.
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

    if do_init {
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
    }

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

    Fixture {
        chain,
        hub,
        left,
        miner,
        network,
        contract,
        ask,
        left_balance_at_start,
        prefunded_to_hub: HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU,
        deployment,
        deployment_height,
    }
}

async fn spawn_hub(hub: &Account, directory: &tempfile::TempDir) -> (String, Arc<HubState>) {
    spawn_hub_with_profile(hub, directory, "local-pilot").await
}

async fn spawn_hub_with_profile(
    hub: &Account,
    directory: &tempfile::TempDir,
    profile: &str,
) -> (String, Arc<HubState>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "registry open countersign dos",
            addr(hub).to_readable(),
            "http://127.0.0.1:1".to_owned(),
            None,
            state_path,
            hex::encode(hub.secret_key().serialize()),
            &"92".repeat(32),
            &"93".repeat(32),
            profile,
            1_000_000_000,
            1_000_000_000,
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
        .map_err(|error| format!("TRANSPORT: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    response.json().await.map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// DOS 1. THE VETO IS NOT FREE. By the time the Hub can refuse, the user has
// already paid the whole deployment protocol cost INTO THE HUB'S OWN ACCOUNT.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_hub_that_never_answers_keeps_the_deployment_cost_the_user_already_paid_it() {
    let f = spend_up_to_the_ask("silent", false);

    // Nobody is listening. This is the Hub declining, and it is also the Hub
    // being down, and the user cannot tell which.
    let refusal = ask_hub("http://127.0.0.1:1", &f.ask)
        .await
        .expect_err("a Hub that does not answer");
    println!("DOS 1: what the user sees when the Hub declines: {refusal}");

    let hub_balance = f.chain.balance(&addr(&f.hub)).to_zhu_u64().unwrap();
    let left_now = f.chain.balance(&addr(&f.left)).to_zhu_u64().unwrap();
    let lost = f.left_balance_at_start - left_now;
    println!(
        "DOS 1: user is down {lost} zhu ({} of it prefunded straight to the Hub, the rest fees)",
        f.prefunded_to_hub
    );
    println!("DOS 1: Hub account now holds {hub_balance} zhu; contract deployed and useless");
    assert!(
        lost >= f.prefunded_to_hub,
        "the user paid at least the whole protocol cost before the Hub committed to anything"
    );
    assert_eq!(
        f.chain.balance(&f.contract.to_addr()).to_zhu_u64(),
        Ok(0),
        "no deposit is at risk - the loss is the sunk open cost, not the channel"
    );

    // There is no on-chain claim on a plain transfer. Nothing in the contract
    // knows the prefunding happened.
    assert_eq!(
        f.chain
            .storage(&f.contract, &Value::bytes(b"g_locked".to_vec())),
        Value::U64(0)
    );
    println!(
        "DOS 1: the prefunding is a bare HacToTrs to the Hub's address - no escrow, no refund path."
    );
}

// ---------------------------------------------------------------------------
// DOS 2. A REFUSAL LEAVES NO EVIDENCE. Compare the three ways a user fails to
// get a countersignature: nobody home, a Hub that errors, and a Hub that says
// no. None of them is signed, so none of them is attributable to anyone.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_refusal_is_unsigned_and_indistinguishable_from_an_outage() {
    let f = spend_up_to_the_ask("evidence", false);
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _state) = spawn_hub(&f.hub, &directory).await;

    let down = ask_hub("http://127.0.0.1:1", &f.ask)
        .await
        .expect_err("hub down");
    let wrong_route = ask_hub(&format!("{hub_url}/nope"), &f.ask)
        .await
        .expect_err("hub reachable, route gone");
    // A real refusal by the real handler: this ask names a different Hub.
    let mut foreign = f.ask.clone();
    foreign.binding.right_hub_address =
        addr(&Account::create_by("dos-other-hub").unwrap()).to_readable();
    let refused = ask_hub(&hub_url, &foreign)
        .await
        .expect_err("hub refuses an ask bound elsewhere");

    println!("DOS 2: hub down          -> {down}");
    println!("DOS 2: hub up, no route  -> {wrong_route}");
    println!("DOS 2: hub up, refusing  -> {refused}");
    for text in [&down, &wrong_route, &refused] {
        assert!(
            !text.contains("signature") || !text.contains("hub_refusal"),
            "no refusal carries a Hub signature: {text}"
        );
    }
    println!(
        "DOS 2: every failure is an unsigned HTTP string. A user cannot prove they asked, and a \
         third party cannot tell a refusing Hub from a broken one."
    );
}

// ---------------------------------------------------------------------------
// DOS 3. A HALF-COMPLETED OPEN IS RECOVERABLE - the ask is rebuildable and the
// answer is idempotent, so a refusal today is not fatal if the Hub answers
// tomorrow. Driven all the way to a funded, exited channel.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_refusal_today_still_opens_tomorrow_if_the_hub_ever_answers() {
    let mut f = spend_up_to_the_ask("recover", true);

    // Day one: refused.
    assert!(ask_hub("http://127.0.0.1:1", &f.ask).await.is_err());
    assert_eq!(
        f.chain
            .storage(&f.contract, &channel_key("c_status_", &addr(&f.left))),
        Value::U8(1),
        "the channel sits in FUNDING, holding nothing, costing nothing to leave alone"
    );

    // Day two: a Hub appears, and the ORIGINAL ask - unchanged - is answered.
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _state) = spawn_hub(&f.hub, &directory).await;
    let answer = ask_hub(&hub_url, &f.ask)
        .await
        .expect("Hub finally answered");
    let bundle = f
        .ask
        .attach_hub_countersignature(&answer.hub_refund_signature_hex)
        .expect("the late answer is as good as an early one");

    let funding =
        build_hvm_registry_pilot_exact_funding(&f.left, &bundle, &f.network, FEE_ZHU, 102, u8::MAX)
            .expect("funding is buildable now");
    let miner = f.miner;
    confirm_wallet_bytes(&mut f.chain, miner, &funding, TxOutput::None);
    assert_eq!(
        f.chain
            .storage(&f.contract, &channel_key("c_status_", &addr(&f.left))),
        Value::U8(2),
        "the half-completed open completed"
    );
    println!(
        "DOS 3: a refusal is not terminal - the same ask opened the channel later, unchanged."
    );
}

// ---------------------------------------------------------------------------
// DOS 4. THE ASK EXPIRES AGAINST THE HUB'S CLOCK, NOT THE USER'S. A wallet
// whose clock is slow can never open a channel, and the reason it is told is
// the same one a replay attacker is told.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_slow_wallet_clock_is_refused_exactly_like_a_replay() {
    let f = spend_up_to_the_ask("clock", false);
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _state) = spawn_hub(&f.hub, &directory).await;

    let honest_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Six minutes slow: an honest wallet, an honest ask, a lifetime the Hub
    // considers already over because it validates at `now.max(node_now)`.
    let skewed_now = honest_now - 360;
    let deployment_height = f.ask.binding.deployment_height;
    let mut skewed = f.ask.clone();
    skewed.created_unix = skewed_now;
    skewed.expires_unix = skewed_now + 300;
    let error = ask_hub(&hub_url, &skewed)
        .await
        .expect_err("a slow clock is refused");
    println!(
        "DOS 4: wallet clock 6 minutes slow (deployment_height {deployment_height}) -> {error}"
    );
    // The Hub's OWN reason is "request is expired or has an invalid lifetime"
    // (hvm_registry.rs:334). What reaches the user is a 502 about a component
    // that is not involved, because `HubError::Node` is laundered into
    // "upstream full node is unavailable" (server.rs:540).
    assert!(
        error.contains("upstream full node is unavailable"),
        "unexpected refusal: {error}"
    );
    println!(
        "DOS 4: the user is told the FULL NODE is down. Their clock is the fault and nothing in \
         the answer points at it."
    );
}

// ---------------------------------------------------------------------------
// DOS 4b. EVERY DISTINCT REFUSAL ON THIS ROUTE IS LAUNDERED INTO A MESSAGE
// ABOUT SOMETHING ELSE. Three real Hub refusals, three misleading answers.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn no_refusal_on_this_route_tells_the_user_what_is_wrong() {
    let f = spend_up_to_the_ask("messages", false);
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _state) = spawn_hub(&f.hub, &directory).await;

    // (a) HubError::Node - the ask is stale, or the binding does not match the
    // contract hash this build pins.
    let mut stale = f.ask.clone();
    stale.created_unix = 1;
    stale.expires_unix = 2;
    let stale_error = ask_hub(&hub_url, &stale).await.expect_err("stale ask");

    let mut repinned = f.ask.clone();
    repinned.binding.bytecode_sha3 = PREVIOUS_PINNED_BYTECODE_SHA3.into();
    let repinned_error = ask_hub(&hub_url, &repinned)
        .await
        .expect_err("binding from the previous build");

    // (b) HubError::State - the ask names a different Hub.
    let mut foreign = f.ask.clone();
    foreign.binding.right_hub_address =
        addr(&Account::create_by("dos-other-hub-2").unwrap()).to_readable();
    let foreign_error = ask_hub(&hub_url, &foreign).await.expect_err("foreign ask");

    // (c) HubError::Admission - a mainnet-profile Hub, which refuses this route
    // unconditionally and forever.
    let mainnet_directory = tempfile::tempdir().unwrap();
    let (mainnet_url, _mainnet_state) =
        spawn_hub_with_profile(&f.hub, &mainnet_directory, "mainnet-pilot").await;
    let mainnet_error = ask_hub(&mainnet_url, &f.ask)
        .await
        .expect_err("mainnet profile refuses registry opens");

    println!("DOS 4b: stale ask (clock skew)      -> {stale_error}");
    println!("DOS 4b: binding from previous build -> {repinned_error}");
    println!("DOS 4b: ask bound to another Hub    -> {foreign_error}");
    println!("DOS 4b: mainnet-profile Hub         -> {mainnet_error}");
    assert!(stale_error.contains("upstream full node is unavailable"));
    assert!(repinned_error.contains("upstream full node is unavailable"));
    assert!(foreign_error.contains("Fast Pay Hub is unavailable"));
    assert!(mainnet_error.contains("admission limit reached"));
    println!(
        "DOS 4b: four different causes, zero correct diagnoses. The mainnet one even carries \
         Retry-After: 60, inviting a retry that can never succeed."
    );
}

// ---------------------------------------------------------------------------
// DOS 5. A COUNTERSIGNATURE THAT WAS VALID STOPS BEING READABLE WHEN THE WALLET
// RE-PINS THE CONTRACT HASH - which is exactly what shipping the lease fix did.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn an_old_binding_is_unreadable_after_the_wallet_repins_the_contract() {
    let f = spend_up_to_the_ask("repin", false);

    let mut old = f.ask.clone();
    old.binding.bytecode_sha3 = PREVIOUS_PINNED_BYTECODE_SHA3.into();

    let commitment = old
        .binding
        .commitment()
        .expect_err("old binding commitment");
    println!("DOS 5: binding.commitment() on a previously valid binding -> {commitment}");

    let shape = old.validate_shape().expect_err("old ask shape");
    println!("DOS 5: validate_shape() on a previously valid ask -> {shape}");

    println!(
        "DOS 5: `HvmRegistryPilotStore::open` runs `validate_state`, which calls \
         `request.validate_shape()` (hvm_registry_pilot_state.rs:1796). A state file written by \
         the previous build therefore cannot be opened by this one."
    );
}

// ---------------------------------------------------------------------------
// DOS 6. THE ROUTE IS FREE, UNCAPPED, AND RE-VERIFIES ITS WHOLE HISTORY ON
// EVERY WRITE. Nothing on this path touches the chain, so an ask costs the
// asker one signature and costs the Hub a permanent record plus an ECDSA
// verification of every record it has ever kept - on every future state write,
// including ordinary payments.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn asking_is_free_and_the_hubs_cost_grows_with_every_ask_it_ever_answered() {
    let f = spend_up_to_the_ask("flood", false);
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _state) = spawn_hub(&f.hub, &directory).await;
    let state_path = directory.path().join("hub-state.json");

    let rounds = 60_usize;
    let mut first_batch = std::time::Duration::ZERO;
    let mut last_batch = std::time::Duration::ZERO;
    for index in 0..rounds {
        // A throwaway address. It owns nothing, has never been on chain, and
        // has no channel in this registry - the route never asks the chain.
        let stranger = Account::create_by(&format!("dos-flood-{index}")).unwrap();
        let mut parameters = parameters();
        parameters.channel_id = format!("{:032x}", index + 1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ask = build_hvm_registry_pilot_refund_countersign_request(
            &stranger,
            f.hub.readable(),
            &f.deployment,
            f.deployment_height,
            &parameters,
            now,
            now + 300,
        )
        .expect("anybody can build a well-formed ask");
        let started = std::time::Instant::now();
        ask_hub(&hub_url, &ask)
            .await
            .expect("the Hub signs for a stranger it has never heard of");
        let elapsed = started.elapsed();
        if index < 5 {
            first_batch += elapsed;
        }
        if index >= rounds - 5 {
            last_batch += elapsed;
        }
    }

    let size = std::fs::metadata(&state_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "DOS 6: {rounds} asks from {rounds} addresses that own nothing; not one chain read.\n\
         DOS 6: first 5 asks {first_batch:?}, last 5 asks {last_batch:?}\n\
         DOS 6: Hub authenticated state file is now {size} bytes"
    );
    assert!(
        last_batch > first_batch,
        "per-ask cost must be measurably rising: first={first_batch:?} last={last_batch:?}"
    );
    println!(
        "DOS 6: `validate_hvm_registry_open_countersignatures_v2` (storage.rs:1028) re-derives \
         and re-verifies EVERY stored record on every `commit_authenticated_state`, and nothing \
         caps the map. The cost lands on payments too, not just opens."
    );
}
