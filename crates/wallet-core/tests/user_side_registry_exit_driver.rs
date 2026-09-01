//! The user drives the whole exit with their own key and their own bill.
//!
//! Four steps, in order, each planned from nothing but the binding, the
//! wallet's own head bill and a live snapshot, and each signed by the channel's
//! left party. The Hub appears nowhere in this file except as an address inside
//! a binding and a signature on a bill it produced while it was still alive.
//! That is the property under test: with the Hub's process deleted, the user
//! still gets from OPEN to paid.

use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::hvm_registry_exit::{
    HVM_REGISTRY_EXIT_KIT_SCHEMA, HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep,
    build_exit_kit, build_user_exit_transaction, exit_lease_floor_blocks, plan_user_exit_step,
};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use vm::ContractAddress;

const DEPOSIT_ZHU: u64 = 1_000_000;
/// The head bill: the user has spent 100_000 and holds 900_000.
const HEAD_SERIAL: u64 = 3;
const HEAD_LEFT_ZHU: u64 = 900_000;
const HEAD_HUB_ZHU: u64 = 100_000;

struct Fixture {
    left: Account,
    hub: Account,
    stranger: Account,
    kit: HvmRegistryExitKitV1,
}

fn fixture() -> Fixture {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let left = Account::create_by("user-side-exit-left").unwrap();
    let hub = Account::create_by("user-side-exit-hub").unwrap();
    let stranger = Account::create_by("user-side-exit-stranger").unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: "11".repeat(32),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: "33".repeat(16),
        reuse_version: 0,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*hub.address()).to_readable(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let bill = sign_bill(
        &binding,
        &left,
        &hub,
        HEAD_SERIAL,
        HEAD_LEFT_ZHU,
        HEAD_HUB_ZHU,
    );
    let kit = build_exit_kit(binding, bill).expect("the exit kit must verify");
    Fixture {
        left,
        hub,
        stranger,
        kit,
    }
}

fn sign_bill(
    binding: &HvmRegistryBindingV2,
    left: &Account,
    hub: &Account,
    serial: u64,
    left_balance_zhu: u64,
    hub_balance_zhu: u64,
) -> HvmRegistryBillV2 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial,
        left_balance_zhu,
        hub_balance_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    bill
}

fn entry<T>(value: T, live_blocks: u64) -> HvmStorageEntry<T> {
    HvmStorageEntry {
        value,
        live_blocks,
        recover_blocks: 100,
        active: true,
        recoverable: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    binding: &HvmRegistryBindingV2,
    status: u8,
    serial: u64,
    left_balance_zhu: u64,
    hub_balance_zhu: u64,
    observed_height: u64,
    deadline: u64,
    minimum_live_blocks: u64,
) -> HvmRegistryLiveSnapshotV2 {
    HvmRegistryLiveSnapshotV2 {
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
        minimum_live_blocks,
        minimum_recover_blocks: 100,
        registry: HvmRegistryGlobalStorageV2 {
            g_network: entry(binding.network_instance_id.clone(), minimum_live_blocks),
            g_hub: entry(binding.right_hub_address.clone(), minimum_live_blocks),
            g_locked: entry(binding.left_deposit_zhu, minimum_live_blocks),
            g_left_claimable: entry(0, minimum_live_blocks),
            g_hub_claimable: entry(0, minimum_live_blocks),
            g_open_count: entry(1, minimum_live_blocks),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(status, minimum_live_blocks),
            channel_id: entry(binding.channel_id.clone(), minimum_live_blocks),
            reuse: entry(binding.reuse_version, minimum_live_blocks),
            deposit: entry(binding.left_deposit_zhu, minimum_live_blocks),
            paid: entry(binding.left_deposit_zhu, minimum_live_blocks),
            total: entry(binding.left_deposit_zhu, minimum_live_blocks),
            serial: entry(serial, minimum_live_blocks),
            left_balance: entry(left_balance_zhu, minimum_live_blocks),
            hub_balance: entry(hub_balance_zhu, minimum_live_blocks),
            challenge_blocks: entry(binding.challenge_blocks, minimum_live_blocks),
            deadline: entry(deadline, minimum_live_blocks),
            left_claimed: entry(false, minimum_live_blocks),
        },
    }
}

/// A healthy OPEN channel: no bill has ever been put on chain, so the
/// contract still shows serial 0 and the whole deposit on the left, and there
/// is plenty of lease left.
fn open_snapshot(binding: &HvmRegistryBindingV2) -> HvmRegistryLiveSnapshotV2 {
    snapshot(binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 400)
}

fn call_source(plan: &HvmRegistryExitPlanV1) -> &str {
    match plan {
        HvmRegistryExitPlanV1::Call { call_source, .. }
        | HvmRegistryExitPlanV1::Claim { call_source, .. } => call_source,
        HvmRegistryExitPlanV1::Wait { reason } => panic!("expected a step, got a wait: {reason}"),
    }
}

/// Step 1. The Hub has gone silent on an OPEN channel. The user starts the
/// settlement themselves, with the receipt the Hub countersigned while it was
/// alive.
#[test]
fn step_one_the_user_opens_the_challenge_with_their_own_key() {
    let f = fixture();
    let snap = open_snapshot(&f.kit.binding);
    let plan = plan_user_exit_step(&f.kit, &snap, 500, 10).unwrap();
    assert_eq!(
        plan,
        HvmRegistryExitPlanV1::Call {
            step: HvmRegistryExitStep::Challenge,
            call_source: call_source(&plan).to_string(),
        }
    );
    // The call carries the head bill's own numbers and both its signatures.
    let source = call_source(&plan);
    assert!(source.contains("Registry.challenge("));
    assert!(source.contains(&f.kit.binding.left_address));
    assert!(source.contains(&format!(
        ", {HEAD_SERIAL}, {HEAD_LEFT_ZHU}, {HEAD_HUB_ZHU}, 0x"
    )));
    assert!(source.contains(&f.kit.latest_bill.hub_signature_hex));

    let signed = build_user_exit_transaction(&f.left, &f.kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the channel left party must be able to sign a challenge");
    let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
    let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(tx.ty(), 3);
    assert_eq!(tx.actions().len(), 2);
    assert_eq!(tx.actions()[0].kind(), 0x0411, "chain guard");
    assert_eq!(tx.actions()[1].kind(), 44, "HVM contract call");
    tx.verify_signature()
        .expect("the user's own signature must verify");
    assert_eq!(
        tx.main().to_readable(),
        f.kit.binding.left_address,
        "the fee payer must be the user, not the Hub"
    );
    assert_eq!(hex::encode(tx.hash()), signed.transaction_hash);
}

/// Step 2. A challenge is standing that pays the user less than their own bill
/// does. The user supersedes it.
///
/// # Why the balances run this way round
///
/// They used to run the other way - a challenge at 950,000 against a head of
/// 900,000 - and the driver dutifully answered it, which handed 50,000 zhu back
/// to the Hub. That is the shape the shipped one-directional ledger actually
/// mints, because every later bill pays the user strictly less, and it is
/// exactly the case a party acting for the left side must now refuse. See
/// `a_response_that_would_cost_the_user_money_is_refused` for that half. So the
/// case that exercises a real response is the one where responding is a
/// defence.
#[test]
fn step_two_the_user_responds_to_a_stale_challenge_and_refuses_a_window_it_cannot_win() {
    let f = fixture();
    // A challenge standing at serial 2 that owes the user only 100_000 against
    // the head bill's 900_000. Deadline 12 blocks out, 9 blocks left.
    let safe = snapshot(&f.kit.binding, 3, 2, 100_000, 900_000, 503, 515, 400);
    let plan = plan_user_exit_step(&f.kit, &safe, 503, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { step, .. } = &plan else {
        panic!("expected a respond, got {plan:?}");
    };
    assert_eq!(*step, HvmRegistryExitStep::Respond);
    assert!(call_source(&plan).contains("Registry.respond("));
    build_user_exit_transaction(&f.left, &f.kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the channel left party must be able to sign a respond");

    // Two blocks left is below the three-block margin: building and paying for
    // a transaction the contract will refuse for being late buys nothing, and
    // the refusal has to say so rather than quietly returning "wait".
    let unsafe_window = snapshot(&f.kit.binding, 3, 2, 100_000, 900_000, 513, 515, 400);
    let refusal = plan_user_exit_step(&f.kit, &unsafe_window, 513, 10)
        .expect_err("a window too short to answer must be refused, not attempted");
    assert!(
        refusal.to_string().contains("too short"),
        "the refusal must name the window: {refusal}"
    );
}

/// Step 3. The window has closed on the user's own split. Lock it in.
#[test]
fn step_three_the_user_finalizes_once_the_deadline_has_passed() {
    let f = fixture();
    let past_deadline = snapshot(
        &f.kit.binding,
        3,
        HEAD_SERIAL,
        HEAD_LEFT_ZHU,
        HEAD_HUB_ZHU,
        520,
        515,
        400,
    );
    let plan = plan_user_exit_step(&f.kit, &past_deadline, 520, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { step, .. } = &plan else {
        panic!("expected a finalize, got {plan:?}");
    };
    assert_eq!(*step, HvmRegistryExitStep::Finalize);
    assert_eq!(
        call_source(&plan),
        format!(
            "lib Registry = 1: {}\nvar result = Registry.finalize({})\nassert result == 0\nend",
            f.kit.binding.contract_address, f.kit.binding.left_address
        )
    );
    build_user_exit_transaction(&f.left, &f.kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the channel left party must be able to sign a finalize");

    // Before the deadline the same state is a wait, not a finalize. The user
    // is told why rather than shown a spinner.
    let before = snapshot(
        &f.kit.binding,
        3,
        HEAD_SERIAL,
        HEAD_LEFT_ZHU,
        HEAD_HUB_ZHU,
        510,
        515,
        400,
    );
    let plan = plan_user_exit_step(&f.kit, &before, 510, 10).unwrap();
    let HvmRegistryExitPlanV1::Wait { reason } = &plan else {
        panic!("expected a wait, got {plan:?}");
    };
    assert!(
        reason.contains("515"),
        "the wait must name the block: {reason}"
    );
}

/// Step 4. The money leaves the contract, by the only door it has.
#[test]
fn step_four_the_user_claims_the_exact_settled_payout_to_their_own_address() {
    let f = fixture();
    let settled = snapshot(
        &f.kit.binding,
        4,
        HEAD_SERIAL,
        HEAD_LEFT_ZHU,
        HEAD_HUB_ZHU,
        600,
        515,
        400,
    );
    let plan = plan_user_exit_step(&f.kit, &settled, 600, 10).unwrap();
    let HvmRegistryExitPlanV1::Claim {
        payee, amount_zhu, ..
    } = &plan
    else {
        panic!("expected a claim, got {plan:?}");
    };
    assert_eq!(payee, &f.kit.binding.left_address);
    assert_eq!(
        *amount_zhu, HEAD_LEFT_ZHU,
        "the payout is the contract's own settled left balance, to the zhu"
    );

    let signed = build_user_exit_transaction(&f.left, &f.kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the channel left party must be able to sign the payout");
    let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
    let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(tx.ty(), 3);
    assert_eq!(tx.actions().len(), 2);
    assert_eq!(tx.actions()[0].kind(), 0x0411, "chain guard");
    assert_eq!(tx.actions()[1].kind(), 14, "Action 14 payout, not a call");
    tx.verify_signature().unwrap();
    assert_eq!(tx.main().to_readable(), f.kit.binding.left_address);
    // The bytes read back as exactly this payout and nothing else.
    l2_fast_pay_hub::hvm_registry_watchtower::read_exact_registry_claim_transaction(
        &signed.signed_transaction_hex,
        &f.kit.binding,
        &f.kit.binding.left_address,
        HEAD_LEFT_ZHU,
    )
    .expect("the claim must read back exactly");
}

/// Widening who may *build* an exit did not widen who may *be paid*.
///
/// The payee restriction and the amount pin were already there. This proves
/// they still are, from the new caller, which is the only reason the new caller
/// is safe.
#[test]
fn the_user_cannot_aim_the_payout_anywhere_but_their_own_address() {
    let f = fixture();
    let stranger_address = Address::from(*f.stranger.address()).to_readable();
    for payee in [&stranger_address, &f.kit.binding.right_hub_address] {
        let tampered = HvmRegistryExitPlanV1::Claim {
            payee: payee.clone(),
            amount_zhu: HEAD_LEFT_ZHU,
            call_source: format!("hpay-hvm-registry-claim/2\nto={payee}"),
        };
        build_user_exit_transaction(&f.left, &f.kit, &tampered, 10_000, 1_700_000_000, 250)
            .expect_err("the payout must never be built for anyone but the channel left party");
    }
    // Nor a different amount to the right address.
    let wrong_amount = HvmRegistryExitPlanV1::Claim {
        payee: f.kit.binding.left_address.clone(),
        amount_zhu: HEAD_LEFT_ZHU + 1,
        call_source: "hpay-hvm-registry-claim/2\ntampered".into(),
    };
    build_user_exit_transaction(&f.left, &f.kit, &wrong_amount, 10_000, 1_700_000_000, 250)
        .expect_err("a call source that is not canonical for its terms must be refused");
}

/// A plan is a durable record. It is re-derived before it is signed, never
/// trusted for having been stored by us.
#[test]
fn a_tampered_plan_is_re_derived_and_refused() {
    let f = fixture();
    let snap = open_snapshot(&f.kit.binding);
    let plan = plan_user_exit_step(&f.kit, &snap, 500, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { call_source, .. } = &plan else {
        panic!("expected a challenge");
    };
    let swapped = HvmRegistryExitPlanV1::Call {
        // Same bytes, different step. The step decides what gets re-derived.
        step: HvmRegistryExitStep::Finalize,
        call_source: call_source.clone(),
    };
    let refusal =
        build_user_exit_transaction(&f.left, &f.kit, &swapped, 10_000, 1_700_000_000, 250)
            .expect_err(
                "a call source that is not the canonical call for its step must be refused",
            );
    assert!(refusal.to_string().contains("canonical"), "{refusal}");
}

/// The Hub keeps its own rule, and nobody else may borrow the user's.
#[test]
fn only_the_channel_left_party_signs_the_user_side_exit() {
    let f = fixture();
    let snap = open_snapshot(&f.kit.binding);
    let plan = plan_user_exit_step(&f.kit, &snap, 500, 10).unwrap();
    for (signer, who) in [(&f.hub, "the Hub"), (&f.stranger, "a stranger")] {
        let refusal =
            build_user_exit_transaction(signer, &f.kit, &plan, 10_000, 1_700_000_000, 250)
                .expect_err("only the channel left party may sign in the left party's role");
        assert!(
            refusal.to_string().contains("signer"),
            "{who}: the refusal must be about the signer: {refusal}"
        );
    }
}

/// The lease is the only clock in this system that destroys money. An exit is
/// not allowed to start inside it.
#[test]
fn a_short_lease_is_renewed_before_an_exit_is_started() {
    let f = fixture();
    let floor = exit_lease_floor_blocks(&f.kit.binding);
    assert_eq!(floor, f.kit.binding.challenge_blocks + 3 + 24);

    let short = snapshot(&f.kit.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, floor - 1);
    let plan = plan_user_exit_step(&f.kit, &short, 500, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { step, .. } = &plan else {
        panic!("expected a renewal, got {plan:?}");
    };
    // The six shared registry globals go first when both halves are short, and
    // in this fixture both are: `snapshot` gives every key the same lease.
    // Order matters because the halves are renewed by two different calls -
    // `renew_registry` touches the globals, `renew_channel` the twelve channel
    // keys - while `minimum_live_blocks` spans all eighteen. Renewing the half
    // that is not short executes happily and moves the minimum not at all,
    // which is an unbounded loop paying a fee per pass. The globals are first
    // because they are shared: if they lapse, every channel in the deployment
    // becomes unreachable, not just this one.
    assert_eq!(
        *step,
        HvmRegistryExitStep::RenewRegistryLease,
        "an exit that could outlive its own storage keys must renew first"
    );
    assert!(call_source(&plan).contains("Registry.renew_registry("));
    // Anyone can pay for it, but the wallet signs it as the user.
    build_user_exit_transaction(&f.left, &f.kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the user must be able to renew their own channel lease");

    // Every renewal the driver builds must be a size the contract accepts.
    // `renew_registry` and `renew_channel` both assert
    // `periods <= MAX_RENT_STEP`, and this driver used to ask for 200 and 400
    // against a cap of 150 - so the one rescue from the one irreversible
    // outcome in this system was a transaction that aborted on execution.
    let cap: u64 =
        include_str!("../../../../hacash-fullnodedev/vm/contracts/hpay_channel_registry_v2.fitsh")
            .lines()
            .find_map(|line| line.trim().strip_prefix("const MAX_RENT_STEP = "))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("the reviewed contract declares MAX_RENT_STEP");
    let asked: u64 = call_source(&plan)
        .rsplit_once('(')
        .and_then(|(_, tail)| tail.split(')').next())
        .and_then(|args| args.rsplit(", ").next())
        .and_then(|value| value.trim().parse().ok())
        .expect("the rescue names a period count");
    assert!(
        asked > 0 && asked <= cap,
        "the rescue asks for {asked} periods against a contract capped at {cap}"
    );

    // One block more and the exit proceeds.
    let just_enough = snapshot(&f.kit.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, floor);
    let plan = plan_user_exit_step(&f.kit, &just_enough, 500, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { step, .. } = &plan else {
        panic!("expected a challenge, got {plan:?}");
    };
    assert_eq!(*step, HvmRegistryExitStep::Challenge);
}

/// A chain ahead of the wallet's own head means the wallet's evidence is not
/// the newest evidence. Challenging with it would be the user attacking
/// themselves, and on this one-directional rail it pays the Hub.
#[test]
fn a_chain_ahead_of_the_wallets_head_latches_instead_of_challenging() {
    let f = fixture();
    let ahead = snapshot(
        &f.kit.binding,
        2,
        HEAD_SERIAL + 1,
        800_000,
        200_000,
        500,
        0,
        400,
    );
    let refusal = plan_user_exit_step(&f.kit, &ahead, 500, 10)
        .expect_err("a chain newer than our own record must latch");
    assert!(
        refusal.to_string().contains("RecoveryRequired"),
        "{refusal}"
    );
}

/// Every deadline in this file is measured against `observed_height`. Evidence
/// that has fallen behind the node's own tip makes all of them fiction.
#[test]
fn stale_evidence_is_refused_before_any_deadline_is_reasoned_about() {
    let f = fixture();
    let snap = open_snapshot(&f.kit.binding);
    plan_user_exit_step(&f.kit, &snap, 502, 10)
        .expect_err("a snapshot two blocks behind the node tip must be refused");
    plan_user_exit_step(&f.kit, &snap, 500, 4_000)
        .expect_err("a node whose own tip is an hour old must be refused");
}

/// The kit is a bearer proof of entitlement, so it is verified on every use
/// rather than trusted for having been stored by us.
#[test]
fn an_exit_kit_that_does_not_verify_is_never_acted_on() {
    let f = fixture();
    let snap = open_snapshot(&f.kit.binding);

    // A bill the Hub never countersigned.
    let mut forged = f.kit.latest_bill.clone();
    forged.left_balance_zhu = DEPOSIT_ZHU;
    forged.hub_balance_zhu = 0;
    let forged_kit = HvmRegistryExitKitV1 {
        schema: HVM_REGISTRY_EXIT_KIT_SCHEMA.into(),
        binding: f.kit.binding.clone(),
        latest_bill: forged,
    };
    plan_user_exit_step(&forged_kit, &snap, 500, 10)
        .expect_err("a bill whose signatures do not verify must never be planned from");
    build_exit_kit(f.kit.binding.clone(), forged_kit.latest_bill)
        .expect_err("an unverifiable kit must never be exported either");

    // A kit whose schema is not the one both sides agree on.
    let wrong_schema = HvmRegistryExitKitV1 {
        schema: "hpay-hvm-registry-exit-kit/99".into(),
        binding: f.kit.binding.clone(),
        latest_bill: f.kit.latest_bill.clone(),
    };
    plan_user_exit_step(&wrong_schema, &snap, 500, 10).expect_err("unknown kit schema");
}

/// The kit carries no key material, which is what makes it handable to a
/// watchtower. Proven by serialising it and looking.
#[test]
fn the_exit_kit_carries_no_private_key() {
    let f = fixture();
    let json = serde_json::to_string(&f.kit).unwrap();
    let left_secret = hex::encode(f.left.secret_key().serialize());
    assert!(
        !json.contains(&left_secret),
        "the exit kit must never carry the user's private key"
    );
    assert!(json.contains(&f.kit.binding.left_address));
    assert!(json.contains(&f.kit.latest_bill.hub_signature_hex));
}
