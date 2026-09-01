//! ADVERSARIAL probe against the new user-side exit driver.
//!
//! The driver is new code that signs transactions on the owner's behalf, which
//! makes it a new place to lose money. Everything here is the WALLET half of an
//! attack; the CHAIN half of each one is in the fullnode repo at
//! `vm/tests/hpay_exit_driver_attack.rs`, driven against a real block executor.
//!
//! Nothing in this file weakens or edits production code. It only asks the
//! shipped functions what they will do.

use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitKitV1, HvmRegistryExitPlanV1, build_exit_kit, build_user_exit_transaction,
    exit_lease_floor_blocks, plan_user_exit_step,
};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    registry_renew_channel_call_source, registry_renew_registry_call_source,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use vm::ContractAddress;

const DEPOSIT_ZHU: u64 = 1_000_000;

/// The exact contract text this workspace compiles and pins. Read here rather
/// than restated, so the attack cannot be closed by editing this test.
/// Same `include_str!` path `crates/l2-fast-pay-hub/src/hvm_registry_pilot.rs:32` uses.
const PINNED_CONTRACT_SOURCE: &str =
    include_str!("../../../../hacash-fullnodedev/vm/contracts/hpay_channel_registry_v2.fitsh");

struct Fixture {
    left: Account,
    hub: Account,
    binding: HvmRegistryBindingV2,
}

fn fixture() -> Fixture {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let left = Account::create_by("adversarial-exit-left").unwrap();
    let hub = Account::create_by("adversarial-exit-hub").unwrap();
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
    Fixture { left, hub, binding }
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

fn kit_at(f: &Fixture, serial: u64, left_zhu: u64, hub_zhu: u64) -> HvmRegistryExitKitV1 {
    let bill = sign_bill(&f.binding, &f.left, &f.hub, serial, left_zhu, hub_zhu);
    build_exit_kit(f.binding.clone(), bill).expect("kit must verify")
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

fn source(plan: &HvmRegistryExitPlanV1) -> String {
    match plan {
        HvmRegistryExitPlanV1::Call { call_source, .. }
        | HvmRegistryExitPlanV1::Claim { call_source, .. } => call_source.clone(),
        HvmRegistryExitPlanV1::Wait { reason } => panic!("expected a step, got wait: {reason}"),
    }
}

// ===========================================================================
// ATTACK 1 - CLOSED. The lease rescue the driver builds is now a call the
// contract accepts, and it renews the half that is actually short.
//
// It used to ask for 200 rent periods against a contract asserting
// `periods <= MAX_RENT_STEP` with `MAX_RENT_STEP = 150`, so the single escape
// from the single irreversible outcome in this system was a transaction that
// aborted on execution. It also always asked for `renew_channel`, while
// `minimum_live_blocks` spans the six shared globals too - so even once the
// size was legal, renewing the wrong half moved nothing and the driver planned
// the identical call again, forever, one fee per pass.
//
// This test keeps reading the cap out of the contract source this workspace
// pins, rather than restating it, so the day the contract moves again the
// failure lands here.
// ===========================================================================
#[test]
fn attack_one_the_lease_rescue_is_a_call_the_contract_actually_accepts() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let floor = exit_lease_floor_blocks(&f.binding);

    // The number the contract will accept, read from the contract itself.
    let cap: u64 = PINNED_CONTRACT_SOURCE
        .lines()
        .find_map(|line| line.trim().strip_prefix("const MAX_RENT_STEP = "))
        .expect("the contract declares MAX_RENT_STEP")
        .trim()
        .parse()
        .expect("MAX_RENT_STEP is a number");
    println!("ATTACK 1: the pinned contract declares MAX_RENT_STEP = {cap}");

    // A channel whose keys are about to lapse: the branch that exists to stop
    // the one outcome where money is destroyed for everybody.
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, floor - 1);
    let plan = plan_user_exit_step(&kit, &snap, 500, 10).unwrap();
    let call = source(&plan);
    println!(
        "ATTACK 1: lease floor is {floor} blocks; snapshot has {}",
        floor - 1
    );
    println!(
        "ATTACK 1: the driver's rescue step is:
{call}"
    );

    // Every period figure in the rescue is within what the contract accepts.
    let asked: u64 = call
        .rsplit_once('(')
        .and_then(|(_, tail)| tail.split(')').next())
        .and_then(|args| args.rsplit(", ").next())
        .and_then(|value| value.trim().parse().ok())
        .expect("the rescue call names a period count");
    println!("ATTACK 1: the rescue asks for {asked} periods");
    assert!(
        asked > 0 && asked <= cap,
        "the rescue asks for {asked} periods against a contract capped at {cap}; it would abort"
    );

    // Both renewal builders are bounded the same way, so neither half can be
    // built at a size the contract refuses.
    for periods in [cap + 1, 200, 400] {
        if periods <= cap {
            continue;
        }
        assert!(
            registry_renew_channel_call_source(&f.binding, periods).is_err(),
            "a channel renewal of {periods} periods must be refused, not signed"
        );
        assert!(
            registry_renew_registry_call_source(&f.binding, periods).is_err(),
            "a registry renewal of {periods} periods must be refused, not signed"
        );
    }

    // And it is still signable, which is the point: the rescue works.
    let signed = build_user_exit_transaction(&f.left, &kit, &plan, 10_000, 1_700_000_000, 250)
        .expect("the user must be able to sign their own lease rescue");
    println!("ATTACK 1: signed, tx {}", signed.transaction_hash);
}

// ===========================================================================
// ATTACK 2 - CLOSED. The driver refuses to pay to exit a channel with nothing
// in it.
//
// The ordinary end state of a one-directional rail is a user who has spent
// their whole balance. Challenging and finalizing there both execute happily,
// `settle()` then marks the zero balance claimed, and the Action 14 payout
// refuses `amount 0` once the fees are already gone. Measured on chain:
// 3,603,000 zhu of fees, 3.6x the deposit, to recover nothing.
// ===========================================================================
#[test]
fn attack_two_an_empty_channel_is_not_worth_a_fee_to_close() {
    let f = fixture();
    let kit = kit_at(&f, 9, 0, DEPOSIT_ZHU);
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);
    let plan = plan_user_exit_step(&kit, &snap, 500, 10).unwrap();
    println!("ATTACK 2: head bill is serial 9 with left_balance 0. The plan is {plan:?}");

    let HvmRegistryExitPlanV1::Wait { reason } = &plan else {
        panic!("an exit that recovers nothing must not be started, got {plan:?}");
    };
    assert!(
        reason.contains("recover zero"),
        "the refusal must say why, not merely refuse: {reason}"
    );

    // Refusing to plan it is not enough on its own - a caller holding a stale
    // plan must not be able to sign it either.
    build_user_exit_transaction(&f.left, &kit, &plan, 10_000, 1_700_000_000, 250)
        .expect_err("there is no step to sign on an empty channel");

    // A settled empty channel says something true rather than claiming a
    // payout was made. `settle()` marks a zero balance claimed without paying
    // anything, and the old wording told this user their money had already
    // arrived.
    let settled = snapshot(&f.binding, 4, 9, 0, DEPOSIT_ZHU, 700, 600, 4_000);
    let after = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    println!("ATTACK 2: at FINAL with a zero left balance the plan is {after:?}");
    let HvmRegistryExitPlanV1::Wait { reason } = &after else {
        panic!("nothing is owed, so nothing should be built: {after:?}");
    };
    assert!(
        reason.contains("nothing owed"),
        "a channel that never owed this wallet anything must not be told its payout was made:          {reason}"
    );
}

// ===========================================================================
// ATTACK 3 - exit on a bill that is not the wallet's latest.
// ===========================================================================
#[test]
fn attack_three_nothing_ties_the_kit_to_the_wallets_own_head() {
    let f = fixture();
    let stale = kit_at(&f, 1, 990_000, 10_000);
    let latest = kit_at(&f, 7, 400_000, 600_000);
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);

    let stale_plan = plan_user_exit_step(&stale, &snap, 500, 10).unwrap();
    let latest_plan = plan_user_exit_step(&latest, &snap, 500, 10).unwrap();
    println!(
        "ATTACK 3: a kit at serial 1 plans: {}",
        source(&stale_plan).lines().nth(1).unwrap()
    );
    println!(
        "ATTACK 3: a kit at serial 7 plans: {}",
        source(&latest_plan).lines().nth(1).unwrap()
    );
    println!(
        "ATTACK 3: both are accepted. plan_user_exit_step's only evidence check is \
         kit.validate_crypto() (hvm_registry_exit.rs:188); it takes no head, no floor, \
         no serial argument."
    );

    assert!(source(&stale_plan).contains(", 1, 990000, 10000, 0x"));
    assert!(source(&latest_plan).contains(", 7, 400000, 600000, 0x"));
    // The direction that decides whether this costs the USER anything: read off
    // the two kits rather than asserted about two literals, so the statement is
    // about the fixtures and not about arithmetic.
    assert!(
        stale.latest_bill.left_balance_zhu > latest.latest_bill.left_balance_zhu,
        "on the one-directional rail an older bill always pays the user MORE"
    );
}

// ===========================================================================
// ATTACK 4 - replay: the driver has no durable per-step record.
// ===========================================================================
#[test]
fn attack_four_the_same_step_signs_twice_into_two_different_transactions() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);
    let plan = plan_user_exit_step(&kit, &snap, 500, 10).unwrap();

    let a = build_user_exit_transaction(&f.left, &kit, &plan, 10_000, 1_700_000_000, 250).unwrap();
    let b = build_user_exit_transaction(&f.left, &kit, &plan, 10_000, 1_700_000_060, 250).unwrap();
    println!(
        "ATTACK 4: same step, timestamp 1700000000 -> tx {}",
        a.transaction_hash
    );
    println!(
        "ATTACK 4: same step, timestamp 1700000060 -> tx {}",
        b.transaction_hash
    );
    assert_ne!(a.transaction_hash, b.transaction_hash);
    assert_ne!(a.signed_transaction_hex, b.signed_transaction_hex);

    // Same for the money-moving step.
    let final_snap = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let claim = plan_user_exit_step(&kit, &final_snap, 700, 10).unwrap();
    let c = build_user_exit_transaction(&f.left, &kit, &claim, 10_000, 1_700_000_000, 250).unwrap();
    let d = build_user_exit_transaction(&f.left, &kit, &claim, 10_000, 1_700_000_060, 250).unwrap();
    println!(
        "ATTACK 4: Action 14 claim signed twice -> {} and {}",
        c.transaction_hash, d.transaction_hash
    );
    assert_ne!(c.transaction_hash, d.transaction_hash);
    println!(
        "ATTACK 4: nothing in wallet-core records that a step was already signed; \
         there is no wallet peer of PersistedHvmRegistryChainOperation (storage.rs:1144)."
    );
}

// ===========================================================================
// ATTACK 5 - race the exit against a settlement the wallet has not seen.
// ===========================================================================
#[test]
fn attack_five_a_plan_outlives_the_snapshot_it_was_made_from() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);

    // The wallet plans a claim for 900_000 from a FINAL snapshot.
    let before = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &before, 700, 10).unwrap();
    let HvmRegistryExitPlanV1::Claim { amount_zhu, .. } = &plan else {
        panic!("expected a claim");
    };
    println!("ATTACK 5: the wallet planned a claim for {amount_zhu} zhu at height 700");

    // The chain moved: a cooperative_close at a newer serial the user also
    // signed settled the channel lower. The plan is still signable as it stands.
    let signed = build_user_exit_transaction(&f.left, &kit, &plan, 10_000, 1_800_000_000, 250)
        .expect("the plan carries no height and no expiry, so it still signs");
    println!(
        "ATTACK 5: signed at a much later timestamp anyway -> {}",
        signed.transaction_hash
    );
    println!(
        "ATTACK 5: HvmRegistryExitPlanV1 (hvm_registry_exit.rs:139-155) carries no \
         observed_height, no snapshot commitment and no expiry, so build_user_exit_transaction \
         cannot tell a fresh plan from a stale one."
    );
    assert_eq!(*amount_zhu, 900_000);
}

// ===========================================================================
// ATTACK 6 - what actually holds. The payee restriction and the role rule.
// ===========================================================================
#[test]
fn attack_six_the_things_that_do_hold() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let final_snap = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &final_snap, 700, 10).unwrap();

    // The payee cannot be moved.
    let HvmRegistryExitPlanV1::Claim {
        payee,
        amount_zhu,
        call_source,
    } = plan.clone()
    else {
        panic!("claim");
    };
    let thief = Account::create_by("adversarial-exit-thief").unwrap();
    let redirected = HvmRegistryExitPlanV1::Claim {
        payee: Address::from(*thief.address()).to_readable(),
        amount_zhu,
        call_source: call_source.clone(),
    };
    let redirect_error =
        build_user_exit_transaction(&f.left, &kit, &redirected, 10_000, 1_700_000_000, 250)
            .expect_err("a redirected payout must be refused");
    println!("ATTACK 6: payout aimed at a stranger -> {redirect_error}");

    let resized = HvmRegistryExitPlanV1::Claim {
        payee: payee.clone(),
        amount_zhu: amount_zhu + 1,
        call_source,
    };
    let resize_error =
        build_user_exit_transaction(&f.left, &kit, &resized, 10_000, 1_700_000_000, 250)
            .expect_err("a resized payout must be refused");
    println!("ATTACK 6: payout resized by one zhu -> {resize_error}");

    // And the Hub's key cannot sign in the left party's role.
    let hub_error = build_user_exit_transaction(&f.hub, &kit, &plan, 10_000, 1_700_000_000, 250)
        .expect_err("the hub is not the left party");
    println!("ATTACK 6: the Hub's own key in the ChannelLeft role -> {hub_error}");

    // registry_claim_payout_source, hvm_registry_watchtower.rs:513-517.
    assert!(
        redirect_error
            .to_string()
            .contains("payee must be the exact channel left address")
    );
    // The re-derivation in build_user_exit_transaction, hvm_registry_exit.rs:330-334.
    assert!(resize_error.to_string().contains("not canonical"));
    assert!(hub_error.to_string().contains("channel left party"));
}
