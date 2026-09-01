//! THE SERIAL-0 TRAP, closed, and driven on a real chain.
//!
//! A Hub that goes silent the instant the channel is funded leaves the user
//! able to recover everything - because the funding never happens without a
//! Hub-countersigned serial-1 full refund, and the user already holds one.
//!
//! Nothing here is asserted about in the abstract. The registry contract is
//! deployed from the wallet's own signed bytes, `init` is the wallet's own
//! signed bytes, the refund countersignature crosses a real HTTP route into a
//! real `HubState` and back, the funding transaction is the wallet's own signed
//! bytes, and the exit is `challenge` -> wait -> `finalize` -> Action 14, every
//! one of them signed and paid for by the USER or by an unrelated stranger.
//! Blocks are executed by the fullnode's real block executor against real HVM
//! contract state.
//!
//! The Hub account signs exactly two things in this whole file: the `init`
//! co-signature the contract itself demands, and the off-chain refund bill.
//! After funding it signs nothing.

#![cfg(feature = "local-pilot-tools")]

use std::path::PathBuf;
use std::sync::Arc;

use field::{AddrOrPtr, Address, Amount, Field as _, Hash, Serialize as _, Sign};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HvmRegistryRecoveryBundleV2,
    HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA, HvmRegistryRefundCountersignResponseV2,
};
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
    build_hvm_registry_pilot_refund_countersign_request,
};
use protocol::action::{HacFromToTrs, HacToTrs};
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

const DEPOSIT_ZHU: u64 = 1_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const FEE_ZHU: u64 = 500_000;
const CHANNEL_ID: &str = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";

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

fn call_source(contract: &ContractAddress, call: &str) -> String {
    format!(
        "lib Registry = 1: {}\nvar result = Registry.{}\nassert result == 0\nend",
        contract.to_readable(),
        call
    )
}

/// One registry call, signed and paid for by ONE account.
fn confirm_solo_call(
    chain: &mut MemChain,
    payer: &Account,
    contract: &ContractAddress,
    call: &str,
    miner: Address,
) {
    let hash = chain
        .submit_formal_main_call_fitsh_with_signers(
            payer,
            &[],
            vec![addr(payer), contract.to_addr()],
            &call_source(contract, call),
            u8::MAX,
        )
        .expect("build solo registry call");
    chain
        .confirm_formal_block(miner)
        .expect("execute solo registry call")
        .expect_success(&hash);
}

fn confirm_solo_call_rejected(
    chain: &mut MemChain,
    payer: &Account,
    contract: &ContractAddress,
    call: &str,
    miner: Address,
) -> String {
    let hash = chain
        .submit_formal_main_call_fitsh_with_signers(
            payer,
            &[],
            vec![addr(payer), contract.to_addr()],
            &call_source(contract, call),
            u8::MAX,
        )
        .expect("build solo registry call");
    let block = chain
        .confirm_formal_block_observing_failures(miner)
        .expect("execute expected-rejection call");
    let receipt = block.receipt(&hash).expect("expected-rejection receipt");
    assert!(
        receipt.is_error(),
        "ESCAPE UNEXPECTEDLY SUCCEEDED, the trap is not where this test thinks it is: {call}"
    );
    format!("{receipt:?}")
}

/// Present a bundle's refund bill to the contract.
fn bill_call(name: &str, bundle: &HvmRegistryRecoveryBundleV2) -> String {
    let bill = &bundle.initial_recovery_bill;
    format!(
        "{}({}, {}, {}, {}, 0x{}, 0x{})",
        name,
        bundle.binding.left_address,
        bill.serial,
        bill.left_balance_zhu,
        bill.hub_balance_zhu,
        bill.left_signature_hex,
        bill.hub_signature_hex,
    )
}

struct Fixture {
    chain: MemChain,
    hub: Account,
    left: Account,
    stranger: Account,
    miner: Address,
    network: HvmLocalPilotNetwork,
    contract: ContractAddress,
    ask: HvmRegistryRefundCountersignRequestV2,
}

/// Deploy the registry and `init` one channel, entirely from wallet-built
/// bytes, and build the left-signed refund ASK. NOTHING is funded here.
fn deploy_and_init(seed: &str) -> Fixture {
    // MemChain installs the process registry AND the VM assigner. The wallet's
    // own `ensure_hacash_protocol_setup` then finds the slot claimed and shares
    // it, which is what lets the wallet's exact bytes run through the real
    // block executor instead of a wallet-shaped imitation of it.
    let network = HvmLocalPilotNetwork::canonical();
    let mut chain = MemChain::new();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    // The wallet's bytes carry a ChainAllow guard naming the private pilot
    // chain, and the guard is checked against exactly this.
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by(&format!("countersign-hub-{seed}")).unwrap();
    let left = Account::create_by(&format!("countersign-left-{seed}")).unwrap();
    let stranger = Account::create_by(&format!("countersign-stranger-{seed}")).unwrap();
    let miner = addr(&Account::create_by(&format!("countersign-miner-{seed}")).unwrap());
    for account in [&hub, &left, &stranger] {
        chain.mint_hac(&addr(account), 30_000_000_000_000);
    }

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

    assert_eq!(
        chain.storage(&contract, &channel_key("c_status_", &addr(&left))),
        Value::U8(1),
        "the channel must be in FUNDING and holding nothing"
    );
    assert_eq!(
        chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(0),
        "init moves no coin"
    );

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
        stranger,
        miner,
        network,
        contract,
        ask,
    }
}

/// A real Hub process, reachable over a real socket.
async fn spawn_hub(hub: &Account, directory: &tempfile::TempDir) -> (String, Arc<HubState>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "registry open countersign",
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

// ---------------------------------------------------------------------------
// THE HEADLINE. The Hub countersigns the refund, the user funds, the Hub goes
// silent forever, and the user still gets everything out alone.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn hub_goes_silent_after_funding_and_the_user_still_recovers_everything() {
    let mut f = deploy_and_init("headline");
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = spawn_hub(&f.hub, &directory).await;

    // ---- STEP 1/2: one round trip, over the wire, into a real Hub.
    let answer = ask_hub(&hub_url, &f.ask).await.expect("Hub countersigned");
    assert_eq!(
        answer.schema, HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA,
        "the answer must be the countersign envelope"
    );
    assert_eq!(
        hex::decode(&answer.hub_refund_signature_hex).unwrap().len(),
        33 + 64,
        "the wallet keeps 97 bytes of what comes back, and nothing else"
    );

    // ---- STEP 3: the wallet DISCARDS everything but the signature and splices
    // it into the bill it built itself.
    let bundle = f
        .ask
        .attach_hub_countersignature(&answer.hub_refund_signature_hex)
        .expect("the Hub signature verifies against the wallet's own binding");
    assert_eq!(bundle.initial_recovery_bill.serial, 1);
    assert_eq!(bundle.initial_recovery_bill.left_balance_zhu, DEPOSIT_ZHU);
    assert_eq!(bundle.initial_recovery_bill.hub_balance_zhu, 0);

    // Idempotent: asking again returns the identical signature, so a wallet
    // that retried after a dropped connection is not handed a second, different
    // refund for the same channel.
    let again = ask_hub(&hub_url, &f.ask).await.expect("Hub answered again");
    assert_eq!(
        again.hub_refund_signature_hex, answer.hub_refund_signature_hex,
        "one binding, one refund signature"
    );

    // ---- STEP 4: funding, built by the ONLY function in this codebase that
    // can build funding bytes - and it demanded the bundle by type.
    let funding =
        build_hvm_registry_pilot_exact_funding(&f.left, &bundle, &f.network, FEE_ZHU, 102, u8::MAX)
            .expect("funding bytes require a countersigned refund, and now there is one");
    let miner = f.miner;
    confirm_wallet_bytes(&mut f.chain, miner, &funding, TxOutput::None);

    let contract = f.contract.clone();
    assert_eq!(
        f.chain
            .storage(&contract, &channel_key("c_status_", &addr(&f.left))),
        Value::U8(2),
        "the channel must be OPEN after funding"
    );
    assert_eq!(
        f.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the coin is inside the contract"
    );

    // ================== THE HUB IS NOW SILENT. FOREVER. ==================
    // Everything below is signed and paid for by the user or by a stranger.

    let left = f.left.clone();
    confirm_solo_call(
        &mut f.chain,
        &left,
        &contract,
        &bill_call("challenge", &bundle),
        miner,
    );
    assert_eq!(
        f.chain
            .storage(&contract, &channel_key("c_status_", &addr(&left))),
        Value::U8(3),
        "the user's own refund bill opened the arbitration window"
    );

    let deadline = match f
        .chain
        .storage(&contract, &channel_key("c_deadline_", &addr(&left)))
    {
        Value::U64(value) => value,
        other => panic!("deadline must be u64, got {other:?}"),
    };
    f.chain
        .confirm_empty_formal_blocks_to_height(miner, deadline)
        .unwrap();

    confirm_solo_call(
        &mut f.chain,
        &left,
        &contract,
        &format!("finalize({})", addr(&left).to_readable()),
        miner,
    );
    assert_eq!(
        f.chain
            .storage(&contract, &channel_key("c_status_", &addr(&left))),
        Value::U8(4),
        "the channel must be FINAL"
    );

    // Fee-neutral: a stranger pays the claim fee, so the user's delta is exactly
    // the coin the contract released.
    let before = f.chain.balance(&addr(&left)).to_zhu_u64().unwrap();
    let mut payout = HacFromToTrs::new();
    payout.from = AddrOrPtr::from_addr(contract.to_addr());
    payout.to = AddrOrPtr::from_addr(addr(&left));
    payout.hacash = Amount::zhu(DEPOSIT_ZHU);
    let claim = f
        .chain
        .submit_formal_actions(
            &f.stranger,
            vec![addr(&f.stranger), contract.to_addr(), addr(&left)],
            vec![Box::new(payout)],
            u8::MAX,
            TxOutput::None,
        )
        .expect("build the payout");
    f.chain
        .confirm_formal_block(miner)
        .unwrap()
        .expect_success(&claim);

    assert_eq!(
        f.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(0),
        "the contract is empty"
    );
    assert_eq!(
        f.chain.balance(&addr(&left)).to_zhu_u64(),
        Ok(before + DEPOSIT_ZHU),
        "the user recovered the entire deposit with zero Hub cooperation"
    );
    println!(
        "HEADLINE: Hub silent from the moment of funding; user recovered all {DEPOSIT_ZHU} zhu alone."
    );
}

// ---------------------------------------------------------------------------
// WHY THE GATE HAS TO EXIST. Without a countersigned refund there is no escape
// on chain at all - so the wallet must refuse to fund, and it does.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn without_the_countersignature_funding_is_unbuildable_and_the_trap_is_real() {
    let mut f = deploy_and_init("trap");
    let miner = f.miner;
    let contract = f.contract.clone();
    let left = f.left.clone();

    // A bundle the user assembled alone: the ask, with the LEFT signature
    // copied into the Hub slot. This is the best a stranded user can do.
    let self_made = HvmRegistryRecoveryBundleV2 {
        schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
        binding: f.ask.binding.clone(),
        initial_recovery_bill: {
            let mut bill = f.ask.left_signed_refund_bill.clone();
            bill.hub_signature_hex = bill.left_signature_hex.clone();
            bill
        },
    };
    assert!(
        self_made.validate_crypto().is_err(),
        "a self-signed refund is not a countersigned refund"
    );
    let error = build_hvm_registry_pilot_exact_funding(
        &f.left,
        &self_made,
        &f.network,
        FEE_ZHU,
        102,
        u8::MAX,
    )
    .expect_err("THE GATE: no countersigned refund, no funding bytes");
    println!("GATE: funding refused without a Hub countersignature: {error}");

    // The unanswered ask itself is equally useless as funding material.
    let unanswered = HvmRegistryRecoveryBundleV2 {
        schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
        binding: f.ask.binding.clone(),
        initial_recovery_bill: f.ask.left_signed_refund_bill.clone(),
    };
    assert!(
        build_hvm_registry_pilot_exact_funding(
            &f.left,
            &unanswered,
            &f.network,
            FEE_ZHU,
            102,
            u8::MAX,
        )
        .is_err(),
        "an unsigned Hub slot is not a Hub signature"
    );

    // Now prove the residual honestly: the chain cannot enforce this. A user who
    // reaches past the wallet with a raw transfer still funds the channel, and
    // is then stranded exactly as the trap describes.
    let mut raw_funding = HacToTrs::new();
    raw_funding.to = AddrOrPtr::from_addr(contract.to_addr());
    raw_funding.hacash = Amount::zhu(DEPOSIT_ZHU);
    let hash = f
        .chain
        .submit_formal_actions(
            &left,
            vec![addr(&left), contract.to_addr()],
            vec![Box::new(raw_funding)],
            u8::MAX,
            TxOutput::None,
        )
        .expect("build a raw funding transfer");
    f.chain
        .confirm_formal_block(miner)
        .unwrap()
        .expect_success(&hash);
    assert_eq!(
        f.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "PayableHAC accepts any correctly sized transfer and cannot see off-chain signatures"
    );

    // And the user is trapped: nothing they can sign alone gets it back.
    let finalize = confirm_solo_call_rejected(
        &mut f.chain,
        &left,
        &contract,
        &format!("finalize({})", addr(&left).to_readable()),
        miner,
    );
    let challenge = confirm_solo_call_rejected(
        &mut f.chain,
        &left,
        &contract,
        &bill_call("challenge", &self_made),
        miner,
    );
    let close = confirm_solo_call_rejected(
        &mut f.chain,
        &left,
        &contract,
        &bill_call("cooperative_close", &self_made),
        miner,
    );
    assert_eq!(
        f.chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "TRAPPED: the whole deposit is still inside the contract"
    );
    println!(
        "RESIDUAL: funding by hand still traps the user. finalize={finalize}\nchallenge={challenge}\nclose={close}"
    );
}

// ---------------------------------------------------------------------------
// A HOSTILE HUB CANNOT SMUGGLE A DIFFERENT CHANNEL BACK.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_hostile_answer_cannot_change_what_was_signed() {
    let f = deploy_and_init("hostile");
    let directory = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = spawn_hub(&f.hub, &directory).await;

    // A signature from another key: well formed, verifies against its own
    // embedded pubkey, and dead here - because the check is against
    // `binding.right_hub_address`.
    let impostor = Account::create_by("countersign-impostor").unwrap();
    let hash = f
        .ask
        .left_signed_refund_bill
        .signing_hash(&f.ask.binding)
        .unwrap();
    assert!(
        f.ask
            .attach_hub_countersignature(&hex::encode(
                Sign::create_by(&impostor, &hash).serialize()
            ))
            .is_err(),
        "a valid signature from the wrong key is not the Hub's signature"
    );

    // A signature over a DIFFERENT channel, made by the real Hub. The wallet
    // never parses a binding out of the response, so the only way to express
    // this substitution is to sign the wrong hash - and that fails.
    let mut other_binding = f.ask.binding.clone();
    other_binding.challenge_blocks = CHALLENGE_BLOCKS + 1;
    let mut other_bill = f.ask.left_signed_refund_bill.clone();
    other_bill.binding_commitment = other_binding.commitment().unwrap();
    let other_hash = other_bill.signing_hash(&other_binding).unwrap();
    assert!(
        f.ask
            .attach_hub_countersignature(&hex::encode(
                Sign::create_by(&f.hub, &other_hash).serialize()
            ))
            .is_err(),
        "a Hub signature over different channel parameters is refused"
    );

    // An expired ask is refused by the Hub, so a captured request cannot be
    // replayed at it later.
    let mut stale = f.ask.clone();
    stale.created_unix = 1;
    stale.expires_unix = 2;
    assert!(
        ask_hub(&hub_url, &stale).await.is_err(),
        "the ASK expires even though the ANSWER never does"
    );

    // A different serial-1 bill for the same binding: the Hub already answered
    // once, and must not be walked into countersigning twice.
    let honest = ask_hub(&hub_url, &f.ask).await.expect("first ask");
    let mut second = f.ask.clone();
    second.left_signed_refund_bill.left_signature_hex = hex::encode(
        Sign::create_by(
            &f.left,
            &second
                .left_signed_refund_bill
                .signing_hash(&second.binding)
                .unwrap(),
        )
        .serialize(),
    );
    second.created_unix += 1;
    second.expires_unix += 1;
    // Same bill, different envelope timing - still the same answer.
    let repeat = ask_hub(&hub_url, &second).await.expect("idempotent re-ask");
    assert_eq!(
        repeat.hub_refund_signature_hex,
        honest.hub_refund_signature_hex
    );

    let mut different = f.ask.clone();
    different.left_signed_refund_bill.left_balance_zhu = DEPOSIT_ZHU - 1;
    different.left_signed_refund_bill.hub_balance_zhu = 1;
    assert!(
        ask_hub(&hub_url, &different).await.is_err(),
        "the Hub refuses a second, different refund for one binding"
    );
    println!("HOSTILE: no substitution survives the response parser or the Hub's own ledger.");
}
