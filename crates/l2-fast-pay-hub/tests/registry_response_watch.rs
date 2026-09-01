//! Scenario 2, measured: the Hub challenges with a bill older than the user's
//! head while the user is asleep, and the arbitration window expires
//! unanswered.
//!
//! The chain already permits the answer. `respond` carries no signer check,
//! the bill's own two signatures are the authority, and the Action 14 payout
//! is pinned to the channel's left address by the contract's `PermitHAC`
//! hook. What did not exist was any code in this workspace that could put a
//! `respond` in a key that is not the Hub's — so the only party able to
//! defend the user was the Hub, which in this scenario is the attacker.
//!
//! These tests drive the responder end to end as pure computation: real
//! bindings, real fully-signed bills, real Type 3 bytes decoded back through
//! the consensus codec. Nothing here touches a network or a chain.

use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::hvm_registry_response_watch::poll::{
    max_poll_interval_seconds, require_usable_poll_interval,
};
use l2_fast_pay_hub::hvm_registry_response_watch::{
    HVM_REGISTRY_EXIT_KIT_SCHEMA, HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS,
    HvmRegistryExitKitV1, HvmRegistryResponseWatchActionV1, HvmRegistryResponseWatchStepV1,
    build_response_watch_transaction, challenge_window_is_human_answerable,
    decide_response_watch_action, response_watch_coverage, response_watch_startup_notice,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HvmRegistryCallerRole, build_signed_hvm_registry_call_transaction,
    build_signed_hvm_registry_claim_transaction, registry_finalize_call_source,
};
use l2_fast_pay_hub::node::HvmStorageEntry;

use field::{Address, Serialize as _, Sign};
use sys::Account;
use vm::ContractAddress;

fn accounts() -> (Account, Account, Account) {
    (
        Account::create_by("registry-response-watch-left").unwrap(),
        Account::create_by("registry-response-watch-hub").unwrap(),
        Account::create_by("registry-response-watch-watcher").unwrap(),
    )
}

fn binding(left: &Account, hub: &Account) -> HvmRegistryBindingV2 {
    HvmRegistryBindingV2 {
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
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    }
}

/// A bill both parties signed. On this rail every later bill pays the user
/// strictly less and the Hub strictly more, so a *higher* serial is the one
/// the user must be able to install.
fn signed_bill(
    binding: &HvmRegistryBindingV2,
    left: &Account,
    hub: &Account,
    serial: u64,
    left_balance_zhu: u64,
) -> HvmRegistryBillV2 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial,
        left_balance_zhu,
        hub_balance_zhu: binding.left_deposit_zhu - left_balance_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    bill
}

fn kit(binding: &HvmRegistryBindingV2, bill: &HvmRegistryBillV2) -> HvmRegistryExitKitV1 {
    HvmRegistryExitKitV1 {
        schema: HVM_REGISTRY_EXIT_KIT_SCHEMA.into(),
        binding: binding.clone(),
        latest_bill: bill.clone(),
    }
}

fn entry<T>(value: T) -> HvmStorageEntry<T> {
    HvmStorageEntry {
        value,
        live_blocks: 100,
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
    observed_height: u64,
    deadline: u64,
    left_claimed: bool,
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
        minimum_live_blocks: 100,
        minimum_recover_blocks: 100,
        registry: HvmRegistryGlobalStorageV2 {
            g_network: entry(binding.network_instance_id.clone()),
            g_hub: entry(binding.right_hub_address.clone()),
            g_locked: entry(binding.left_deposit_zhu),
            g_left_claimable: entry(0),
            g_hub_claimable: entry(0),
            g_open_count: entry(1),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(status),
            channel_id: entry(binding.channel_id.clone()),
            reuse: entry(binding.reuse_version),
            deposit: entry(binding.left_deposit_zhu),
            paid: entry(binding.left_deposit_zhu),
            total: entry(binding.left_deposit_zhu),
            serial: entry(serial),
            left_balance: entry(left_balance_zhu),
            hub_balance: entry(binding.left_deposit_zhu - left_balance_zhu),
            challenge_blocks: entry(binding.challenge_blocks),
            deadline: entry(deadline),
            left_claimed: entry(left_claimed),
        },
    }
}

/// THE FINDING, and the reason this file exists.
///
/// A challenge is standing that pays the user 100,000. The user's own head
/// bill pays them 900,000. Answering it is worth 800,000 zhu to somebody who
/// is asleep, and the answer has to be buildable by a key that is neither
/// party — because the person it protects is, by construction, not awake.
///
/// Before the change this crate could not build that transaction with any key
/// but the Hub's.
///
/// # Why the amounts run this way round
///
/// They did not, and that was a bug this test used to certify. It was written
/// with the chain at 1,000,000 and the head at 250,000, which is the shape the
/// shipped one-directional rail actually produces — and in that shape the
/// "protective" response takes 750,000 zhu off the very user it is running
/// for. The watcher now refuses that (see
/// `a_response_that_would_cost_the_user_money_is_refused`), so the case that
/// exercises a real response is the one where the response genuinely defends
/// the payout.
#[test]
fn a_watcher_key_that_is_not_the_hub_answers_a_stale_challenge() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 900_000);
    let kit = kit(&binding, &head);
    kit.validate_crypto().expect("the kit must stand alone");

    // The watcher is nobody: not the Hub, not the channel's left party.
    assert_ne!(watcher.readable(), binding.right_hub_address);
    assert_ne!(watcher.readable(), binding.left_address);

    // Chain says CHALLENGING at serial 1 with 9 blocks of window left, and the
    // standing challenge pays the user 100_000 against the head's 900_000.
    let live = snapshot(&binding, 3, 1, 100_000, 1_000, 1_009, false);
    assert!(
        live.channel.left_balance.value < head.left_balance_zhu,
        "this fixture is only a defence if answering it raises the user's payout"
    );
    assert_eq!(
        decide_response_watch_action(&live, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::Respond)
    );

    let signed = build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::Respond,
        &live,
        10_000,
        1_700_000_000,
        250,
    )
    .expect("a watcher key must be able to answer a stale challenge");

    // Real bytes, decoded back through the consensus codec.
    let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(transaction.ty(), 3);
    // The fee payer is the watcher, and only the watcher.
    assert_eq!(
        Address::from(*transaction.main()).to_readable(),
        watcher.readable()
    );
    // Chain guard plus one contract main call, nothing else.
    assert_eq!(transaction.actions().len(), 2);
    assert_eq!(transaction.actions()[0].kind(), 0x0411);
    assert_eq!(transaction.actions()[1].kind(), 44);
    // And the call installs the user's head serial, not the Hub's stale one.
    assert!(signed.call_source.contains("respond("));
    assert!(signed.call_source.contains(&format!("{}", head.serial)));
}

/// After the answer lands the close is somebody else's to finish, and the
/// watcher finishes it: `finalize` is permissionless, and the payout is
/// pinned by the contract to the channel's left address.
#[test]
fn a_watcher_finalises_and_sends_the_money_to_the_user_only() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 250_000);
    let kit = kit(&binding, &head);

    // CHALLENGING at the user's own head, deadline reached.
    let ready_to_finalise = snapshot(&binding, 3, 4, 250_000, 1_010, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&ready_to_finalise, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::Finalize)
    );
    build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::Finalize,
        &ready_to_finalise,
        10_000,
        1_700_000_000,
        250,
    )
    .expect("finalize is permissionless");

    // FINAL, unclaimed. The only door the coin leaves the contract by.
    let final_state = snapshot(&binding, 4, 4, 250_000, 1_020, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&final_state, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::ClaimLeftPayout)
    );
    let claim = build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::ClaimLeftPayout,
        &final_state,
        10_000,
        1_700_000_000,
        250,
    )
    .expect("a watcher may pay the user out");

    let raw = hex::decode(&claim.signed_transaction_hex).unwrap();
    let (transaction, _) = protocol::transaction::transaction_create(&raw).unwrap();
    assert_eq!(transaction.actions().len(), 2);
    assert_eq!(transaction.actions()[1].kind(), 14);
    // The watcher pays the fee and has no say in the destination.
    assert_eq!(
        Address::from(*transaction.main()).to_readable(),
        watcher.readable()
    );
    assert!(
        claim
            .call_source
            .contains(&format!("to={}", binding.left_address))
    );
    assert!(claim.call_source.contains("zhu=250000"));

    // Already claimed is nothing to do, not a second payout.
    let claimed = snapshot(&binding, 4, 4, 250_000, 1_021, 1_009, true);
    assert_eq!(
        decide_response_watch_action(&claimed, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Nothing
    );
}

/// The watcher's whole authority is the bill it was handed. It cannot pay
/// itself, and it cannot pay a different number, because the call source it
/// is allowed to build is derived from the binding rather than supplied.
#[test]
fn a_watcher_cannot_redirect_or_resize_the_payout() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 250_000);
    let kit = kit(&binding, &head);
    let final_state = snapshot(&binding, 4, 4, 250_000, 1_020, 1_009, false);

    let built = build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::ClaimLeftPayout,
        &final_state,
        10_000,
        1_700_000_000,
        250,
    )
    .unwrap();
    // There is no parameter to point this anywhere else: the payee comes from
    // the binding, the amount comes from live contract storage.
    assert!(
        built
            .call_source
            .contains(&format!("to={}", binding.left_address))
    );
    assert!(!built.call_source.contains(watcher.readable()));

    // And the step is re-decided against the chain before anything is signed,
    // so a step that has gone stale is refused rather than paid for.
    let already_paid = snapshot(&binding, 4, 4, 250_000, 1_020, 1_009, true);
    build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::ClaimLeftPayout,
        &already_paid,
        10_000,
        1_700_000_000,
        250,
    )
    .expect_err("a second payout against an already-claimed channel must not be built");
}

/// The watcher answers a close; it never starts one. An OPEN channel is
/// nothing to do, and there is no step that emits a `challenge`.
#[test]
fn the_watcher_never_starts_a_close() {
    let (left, hub, _watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 250_000);
    let kit = kit(&binding, &head);

    let open = snapshot(&binding, 2, 4, 250_000, 1_000, 0, false);
    assert_eq!(
        decide_response_watch_action(&open, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Nothing,
        "an OPEN channel is the user's to close, not the watcher's"
    );
}

/// THE BUG THIS FILE USED TO CERTIFY.
///
/// On the shipped one-directional rail every bill after the first pays the
/// user strictly less: the ledger subtracts from the left balance to credit
/// the Hub, and a non-zero Hub deposit is refused outright. So a Hub that
/// challenges with a *stale* bill is handing money back, and a watcher that
/// dutifully answers with the newest bill takes it away again.
///
/// Measured before the fix, on a 1,000,000 zhu channel: the standing challenge
/// owed the user 950,000, the watcher responded, and the user was paid
/// 300,000. The watcher cost its own user 650,000 zhu and charged a fee for
/// it. An absent watcher was strictly better than a present one — the exact
/// inverse of the guarantee at the top of this module.
///
/// The rule that fixes it is stated on the amount rather than the serial, so
/// it does not assume the rail stays one-directional. The moment a refund or a
/// Hub deposit makes a newer bill pay the user *more*, the response above
/// starts firing again on its own.
#[test]
fn a_response_that_would_cost_the_user_money_is_refused() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);

    // Exactly the shape the shipped ledger mints: serial 4 is the newest bill
    // and it pays the user the least.
    let head = signed_bill(&binding, &left, &hub, 4, 300_000);
    let kit = kit(&binding, &head);

    // A hostile Hub challenges with the stale serial-1 opening bill, which
    // owes the user 950_000, at the moment the user is offline. A full window
    // is open, so nothing but the direction of the money is in question.
    let stale = snapshot(&binding, 3, 1, 950_000, 1_000, 1_009, false);
    assert!(
        l2_fast_pay_hub::hvm_registry_watchtower::registry_response_window_is_safe(&stale),
        "the window must be wide open, so only the direction of the money is in question"
    );

    assert_eq!(
        decide_response_watch_action(&stale, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Nothing,
        "answering here would move 650_000 zhu from the user to the Hub"
    );

    // And the refusal is not advisory. A caller that has the step in hand
    // anyway — from a stale plan, or from insisting — still cannot sign it.
    build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::Respond,
        &stale,
        10_000,
        1_700_000_000,
        250,
    )
    .expect_err("a response that lowers the user's payout must not be signable");

    // The Hub's own chair is untouched: the Hub is entitled to claim what it
    // earned, and its decision function still says so.
    assert_eq!(
        l2_fast_pay_hub::hvm_registry_watchtower::decide_registry_watchtower_action(
            &stale,
            &binding,
            &head,
        )
        .unwrap(),
        l2_fast_pay_hub::hvm_registry_watchtower::HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill,
        "widening nothing and narrowing nothing for the Hub: only the left party's chair changed"
    );
}

/// A window too short to answer is refused rather than paid for. Attempting
/// anyway spends a fee on a transaction the contract will reject for being
/// late, and leaves the stale split standing for anybody to finalise.
#[test]
fn a_window_that_cannot_be_answered_in_time_is_refused_not_attempted() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 900_000);
    let kit = kit(&binding, &head);

    // Two blocks left, below the three-block response margin. The response
    // would be worth 800_000 zhu to the user, so this is the margin refusing,
    // not the payout-direction guard.
    let too_late = snapshot(&binding, 3, 1, 100_000, 1_007, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&too_late, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::RefuseWindowTooShort { blocks_left: 2 }
    );
    build_response_watch_transaction(
        &watcher,
        &kit,
        HvmRegistryResponseWatchStepV1::Respond,
        &too_late,
        10_000,
        1_700_000_000,
        250,
    )
    .expect_err("the builder must refuse a response that cannot land in time");
}

/// A chain serial ahead of the kit means the kit is stale. The watcher never
/// argues with it — but it does not abandon the money either.
///
/// # What changed and why it is not a weakened check
///
/// This used to assert `RecoveryRequired`, which is what the *Hub's* chair
/// says about any chain that disagrees with its own accounting. Taken from the
/// left party's chair it was measured stranding a user: the watcher stopped,
/// the objection window closed with the user's own signed split standing, and
/// `finalize` and the Action 14 payout — both permissionless, both unable to
/// change who is paid — were never pressed by anyone.
///
/// A chain ahead of the kit cannot be a forgery: `challenge` and `respond`
/// both verify *both* signatures, so whatever is standing was signed by this
/// user. Stale kit therefore means "this wallet forgot a payment it made", and
/// the chain is the truth about what it is owed. The watcher's answer is to
/// wait the window out and then finish, which is what it now does.
///
/// What it still must not do is *respond*, because responding with a bill that
/// pays the user less is the one move that costs its own user money.
#[test]
fn a_stale_kit_never_argues_and_still_finishes() {
    let (left, hub, _watcher) = accounts();
    let binding = binding(&left, &hub);
    let stale_head = signed_bill(&binding, &left, &hub, 2, 800_000);
    let kit = kit(&binding, &stale_head);

    // Inside the window: nothing to do. Notably NOT `Respond`.
    let inside = snapshot(&binding, 3, 5, 100_000, 1_000, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&inside, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Nothing
    );

    // Past the deadline: finish what is standing.
    let closed = snapshot(&binding, 3, 5, 100_000, 1_009, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&closed, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::Finalize)
    );

    // Settled: take the payout the contract is holding for the left party.
    let settled = snapshot(&binding, 4, 5, 100_000, 1_010, 1_009, false);
    assert_eq!(
        decide_response_watch_action(&settled, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::ClaimLeftPayout)
    );

    // An OPEN channel whose chain serial this kit cannot beat has no exit path
    // to walk, and that genuinely is a recovery.
    let open_ahead = snapshot(&binding, 2, 5, 100_000, 1_010, 0, false);
    assert_eq!(
        decide_response_watch_action(&open_ahead, &kit).unwrap(),
        HvmRegistryResponseWatchActionV1::RecoveryRequired
    );
}

/// The gap has to be printed, not implied.
///
/// This watcher protects nothing while it is not running, and the notice it
/// prints at startup has to say so in the same words a person would use. It
/// also has to name the two checks the sleeping user's current safety
/// actually rests on, so that a change to either is caught here.
#[test]
fn the_startup_notice_states_the_gap_while_the_user_sleeps() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 250_000);
    let kit = kit(&binding, &head);
    let coverage = response_watch_coverage(&binding, 60).unwrap();

    assert_eq!(coverage.answer_window_blocks, 12);
    assert_eq!(coverage.usable_window_blocks, 9);
    assert_eq!(coverage.usable_window_seconds, 2_700);
    assert_eq!(coverage.polls_inside_the_usable_window, 45);
    assert!(
        !challenge_window_is_human_answerable(&binding),
        "a 12-block window is 45 minutes; that is not a window a person answers"
    );

    let notice = response_watch_startup_notice(&kit, &coverage, "http://127.0.0.1:8080", &watcher);
    for required in [
        "WHAT THIS DOES NOT PROTECT",
        "Nothing at all while this process is not running",
        "45 minutes",
        "It never starts a close",
        "It holds no key of yours",
        "right_hub_deposit_zhu",
        "checked_sub",
        "OWNER DECISION",
    ] {
        assert!(
            notice.contains(required),
            "the startup notice must say {required:?}, and it does not:\n{notice}"
        );
    }
    // The address that pays the fees is named, because somebody has to fund it.
    assert!(notice.contains(watcher.readable()));
    // The user's own address is named, because that is the only place the
    // money can go.
    assert!(notice.contains(&binding.left_address));
}

/// A poll interval longer than the window is not a slow watcher, it is no
/// watcher. It is refused before the process ever claims to be protecting
/// anything.
#[test]
fn an_interval_that_could_step_over_a_whole_window_is_refused() {
    let (left, hub, _) = accounts();
    let binding = binding(&left, &hub);
    assert_eq!(binding.challenge_blocks, 12);

    // 9 usable blocks at the 300s target is 2700s.
    assert_eq!(max_poll_interval_seconds(binding.challenge_blocks), 2_700);
    require_usable_poll_interval(binding.challenge_blocks, 2_700).unwrap();
    require_usable_poll_interval(binding.challenge_blocks, 60).unwrap();

    let too_slow = require_usable_poll_interval(binding.challenge_blocks, 2_701)
        .expect_err("an interval that can step over a whole window must be refused");
    assert!(
        too_slow
            .to_string()
            .contains("open and expire between two looks")
    );
    require_usable_poll_interval(binding.challenge_blocks, 59)
        .expect_err("hammering the node buys no coverage");

    // And the ceiling really is derived from the window, not a constant: a
    // wider window buys a slower, cheaper watcher.
    assert_eq!(
        max_poll_interval_seconds(HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS),
        85_500
    );
}

/// The kit is a file somebody has to be able to hand over, so it has to
/// survive a round trip through JSON with every signature intact.
///
/// It prints itself under `--nocapture` so an operator (or this project's own
/// scripts) can produce a real one to point the watcher at without a running
/// wallet.
#[test]
fn the_kit_is_a_file_a_stranger_can_be_handed() {
    let (left, hub, _) = accounts();
    let binding = binding(&left, &hub);
    let head = signed_bill(&binding, &left, &hub, 4, 250_000);
    let kit = kit(&binding, &head);

    let encoded = serde_json::to_string_pretty(&kit).unwrap();
    let decoded: HvmRegistryExitKitV1 = serde_json::from_str(&encoded).unwrap();
    decoded
        .validate_crypto()
        .expect("a kit must still verify after a round trip through a file");
    assert_eq!(decoded, kit);

    // No private key is in it, and none can be: the struct has three fields.
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("private"));

    println!("---BEGIN EXIT KIT---");
    println!("{encoded}");
    println!("---END EXIT KIT---");
}

/// NO CHECK WEAKENED.
///
/// Adding a third role must not have loosened the two that existed. The Hub
/// role still means exactly `signer == binding.right_hub_address` and the
/// left role still means exactly `signer == binding.left_address`; a key that
/// names the wrong one is refused. The responder is a separate, named rule,
/// not a hole in these.
#[test]
fn the_named_roles_still_refuse_every_other_key() {
    let (left, hub, watcher) = accounts();
    let binding = binding(&left, &hub);
    let finalize = registry_finalize_call_source(&binding).unwrap();

    // Both named roles still work for their own party, so this is measuring
    // the signer and not the input.
    for (role, owner) in [
        (HvmRegistryCallerRole::Hub, &hub),
        (HvmRegistryCallerRole::ChannelLeft, &left),
    ] {
        build_signed_hvm_registry_call_transaction(
            owner,
            &binding,
            role,
            finalize.clone(),
            1,
            1,
            1,
        )
        .expect("each named role's own party is untouched");
    }

    // And every impostor is refused, in both builders.
    for (role, impostors) in [
        (HvmRegistryCallerRole::Hub, [&left, &watcher]),
        (HvmRegistryCallerRole::ChannelLeft, [&hub, &watcher]),
    ] {
        for impostor in impostors {
            let refusal = build_signed_hvm_registry_call_transaction(
                impostor,
                &binding,
                role,
                finalize.clone(),
                1,
                1,
                1,
            )
            .expect_err("a key that names a role it is not must be refused");
            assert!(refusal.to_string().contains("signer"), "{refusal}");

            let claim_refusal = build_signed_hvm_registry_claim_transaction(
                impostor,
                &binding,
                role,
                &binding.left_address,
                binding.left_deposit_zhu,
                1,
                1,
                1,
            )
            .expect_err("a key that names a role it is not must be refused");
            assert!(
                claim_refusal.to_string().contains("signer"),
                "{claim_refusal}"
            );
        }
    }
}

/// The two checks the sleeping user's safety currently rests on.
///
/// Scenario 2 is dormant on this rail because every bill the user signs pays
/// the user less than the one before it, so a stale challenge from the Hub
/// hands money back. That is not a property of the exit code; it is a
/// property of these two refusals. If either ever changes, a sleeping user
/// starts losing real money to an unanswered stale challenge and this test is
/// where that is supposed to be noticed.
#[test]
fn the_one_directional_rail_is_what_makes_a_sleeping_user_safe_today() {
    let (left, hub, _) = accounts();
    let mut two_sided = binding(&left, &hub);
    two_sided.right_hub_deposit_zhu = 1;
    assert!(
        two_sided.validate().is_err(),
        "crates/l2-fast-pay-hub/src/hvm_registry.rs: a non-zero Hub deposit must stay refused. \
         The moment the Hub has principal in the channel, a stale challenge can pay the Hub \
         and an unanswered window becomes a real theft."
    );

    // And a bill that moves value back towards the user cannot be minted:
    // `left_balance = previous.left_balance.checked_sub(amount)` only ever
    // subtracts (crates/l2-fast-pay-hub/src/hvm_registry_ledger.rs).
    let binding = binding(&left, &hub);
    let earlier = signed_bill(&binding, &left, &hub, 2, 800_000);
    let later = signed_bill(&binding, &left, &hub, 4, 250_000);
    assert!(
        later.left_balance_zhu < earlier.left_balance_zhu,
        "a later serial must pay the user less, or a stale challenge stops being harmless"
    );
}
