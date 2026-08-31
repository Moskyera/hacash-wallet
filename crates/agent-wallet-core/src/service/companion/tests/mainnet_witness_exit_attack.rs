//! ATTACKING THE TWO MAINNET EXITS, RATHER THAN DEMONSTRATING THEM.
//!
//! `mainnet_witness_exit.rs` shows the exits working. This file tries to make
//! them wrong, and it exists because the two commands stopped consulting the
//! network and now rest entirely on the status admission. If that admission is
//! the whole safety argument then it has to be executed over EVERY status, not
//! the two or three the happy path passes through.
//!
//! It also executes the two node conditions the safety bar names - a node that
//! cannot be reached, and a node that is holding the transaction - and records
//! what actually happens rather than what the design intends.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    DeviceRole, SoftwareDeviceIdentity, WitnessRotationMode, WitnessRotationReason,
};

use super::desktop_witness_flow::desktop_approved_operation;
use super::fixtures::*;
use super::pilot_node::signed_receipt;
use super::*;
use crate::journal::AgentJournalEventKind;

/// Every variant of `OperationStatus`, listed here rather than derived, with an
/// exhaustive `match` below that fails to compile if a variant is ever added
/// without being added here too. An admission set is only proved by the states
/// it turns away.
const EVERY_STATUS: [OperationStatus; 18] = [
    OperationStatus::PaymentIntentCreated,
    OperationStatus::FundsReserved,
    OperationStatus::UnsignedTransactionPersisted,
    OperationStatus::ApprovalRequested,
    OperationStatus::Approved,
    OperationStatus::Rejected,
    OperationStatus::Signed,
    OperationStatus::SignedAwaitingWitness,
    OperationStatus::WitnessedAwaitingBroadcast,
    OperationStatus::BroadcastSubmitted,
    OperationStatus::BroadcastUncertain,
    OperationStatus::SubmittedAwaitingFinalWitness,
    OperationStatus::ReconciliationRequired,
    OperationStatus::ReconciledAwaitingFinalWitness,
    OperationStatus::Committed,
    OperationStatus::Failed,
    OperationStatus::Cancelled,
    OperationStatus::RecoveryRequired,
];

#[test]
fn every_status_is_listed_once() {
    for status in EVERY_STATUS {
        // Exhaustive on purpose: adding a variant without adding it above is a
        // compile error here, not a silently unattacked status.
        match status {
            OperationStatus::PaymentIntentCreated
            | OperationStatus::FundsReserved
            | OperationStatus::UnsignedTransactionPersisted
            | OperationStatus::ApprovalRequested
            | OperationStatus::Approved
            | OperationStatus::Rejected
            | OperationStatus::Signed
            | OperationStatus::SignedAwaitingWitness
            | OperationStatus::WitnessedAwaitingBroadcast
            | OperationStatus::BroadcastSubmitted
            | OperationStatus::BroadcastUncertain
            | OperationStatus::SubmittedAwaitingFinalWitness
            | OperationStatus::ReconciliationRequired
            | OperationStatus::ReconciledAwaitingFinalWitness
            | OperationStatus::Committed
            | OperationStatus::Failed
            | OperationStatus::Cancelled
            | OperationStatus::RecoveryRequired => {}
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for status in EVERY_STATUS {
        assert!(
            seen.insert(format!("{status:?}")),
            "{status:?} listed twice"
        );
    }
    assert_eq!(seen.len(), 18);
}

fn move_wallet_to_mainnet(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId, now: u64) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state.network_mode = "mainnet".to_owned();
    state.block_one_fingerprint =
        crate::node_binding::anchor_for_new_wallet("mainnet", None).unwrap();
    state.trusted_mainnet_fast_pay_pilot = true;
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            now,
        )
        .unwrap();
}

/// Rewrites one operation's status in the durable store and nothing else.
///
/// The lifecycle cannot legitimately reach most of these eighteen from a single
/// fixture, and the thing under attack is the ADMISSION PREDICATE, not the
/// lifecycle. So the status is written through the same serde shape the store
/// round-trips anyway, leaving the signed hex, the hash and the reservation
/// exactly where the real signing put them - which is what makes each refusal
/// below a refusal about the status and about nothing else.
fn force_status(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    status: OperationStatus,
    now: u64,
) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let mut value =
        serde_json::to_value(state.operations.get(operation_id.as_str()).unwrap()).unwrap();
    value["status"] = serde_json::to_value(status).unwrap();
    let patched: AgentOperation = serde_json::from_value(value).unwrap();
    state
        .operations
        .insert(operation_id.as_str().to_owned(), patched);
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            now,
        )
        .unwrap();
}

fn status_now(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
) -> OperationStatus {
    let (state_master, journal_key) = keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .operations
        .get(operation_id.as_str())
        .unwrap()
        .status()
}

/// GIVING UP IS ADMITTED BY EXACTLY ONE STATUS OUT OF EIGHTEEN, ON MAINNET.
///
/// This is the whole of the safety argument now that the network comparison is
/// gone: the claim "nothing was sent" is true of `SignedAwaitingWitness` and of
/// no other status, so the admission has to be that single status and every
/// other one has to be turned away. Seventeen refusals, each executed, each with
/// the operation checked to be exactly where it was afterwards.
#[tokio::test]
async fn giving_up_is_refused_by_all_seventeen_other_statuses_on_mainnet() {
    let (root, mut manager, wallet_id, _mobile, operation_id, node, _authorization) =
        desktop_approved_operation(51_000).await;
    move_wallet_to_mainnet(&mut manager, &wallet_id, 51_010);
    let mut now = 51_020;

    for status in EVERY_STATUS {
        if status == OperationStatus::SignedAwaitingWitness {
            continue;
        }
        now += 1;
        force_status(&mut manager, &wallet_id, &operation_id, status, now);
        now += 1;
        let refusal = manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, now)
            .expect_err(&format!(
                "{status:?} must not be able to give the payment up"
            ));
        let expected = if status.awaits_mobile_witness() {
            AgentWalletError::StrandedPaymentAlreadySent
        } else {
            AgentWalletError::NotWaitingOnWitnessPhone
        };
        assert_eq!(refusal, expected, "wrong reason given for {status:?}");
        assert_eq!(
            status_now(&mut manager, &wallet_id, &operation_id),
            status,
            "{status:?} was refused but the payment moved anyway"
        );
    }

    // AND THE ONE THAT IS ADMITTED, LAST, SO THE CONTRAST IS IN THE SAME RUN.
    now += 1;
    force_status(
        &mut manager,
        &wallet_id,
        &operation_id,
        OperationStatus::SignedAwaitingWitness,
        now,
    );
    now += 1;
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, now)
            .unwrap()
            .status,
        OperationStatus::Cancelled
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "not one of the eighteen presses put anything on a network"
    );
    drop(root);
}

/// CLEARING A WINDOW IS ADMITTED BY EXACTLY THE FOUR WITNESS-AWAITING STATUSES,
/// ON MAINNET, AND TURNS THE OTHER FOURTEEN AWAY.
///
/// The window is minted honestly on testnet, because that forward step is still
/// mainnet-shut, and the wallet is then moved onto mainnet carrying the slot -
/// the exact shape a restored or re-pointed wallet has, and the shape the old
/// gate could not answer at all.
#[tokio::test]
async fn clearing_a_window_admits_only_the_four_witness_statuses_on_mainnet() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(52_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 52_020)
        .await
        .unwrap();
    move_wallet_to_mainnet(&mut manager, &wallet_id, 52_021);
    let dead = anchor.anchor.expires_at + 1;

    // The seeded state, kept so the pending slot can be put back after each
    // press that legitimately consumes it.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let seeded = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();

    let mut now = dead;
    for status in EVERY_STATUS {
        now += 1;
        // Re-seed the slot, then set the status under test.
        let mut state = seeded.clone();
        let mut value =
            serde_json::to_value(state.operations.get(operation_id.as_str()).unwrap()).unwrap();
        value["status"] = serde_json::to_value(status).unwrap();
        let patched: AgentOperation = serde_json::from_value(value).unwrap();
        state
            .operations
            .insert(operation_id.as_str().to_owned(), patched);
        state.journal_sequence = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap()
            .journal_sequence;
        state.journal_head_hash = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap()
            .journal_head_hash;
        state.updated_at = now;
        manager
            .persist_event(
                &mut state,
                &state_master,
                &journal_key,
                AgentJournalEventKind::PolicyChanged,
                None,
                None,
                now,
            )
            .unwrap();

        now += 1;
        let outcome = manager.release_dead_witness_anchor(&wallet_id, &operation_id, now);
        if status.awaits_mobile_witness() {
            let released = outcome
                .unwrap_or_else(|error| panic!("{status:?} should clear the window: {error:?}"));
            assert_eq!(
                released.status, status,
                "clearing must return the payment untouched, and that includes {status:?}"
            );
        } else {
            assert_eq!(
                outcome.unwrap_err(),
                AgentWalletError::NotWaitingOnWitnessPhone,
                "{status:?} must not be able to clear a window"
            );
            assert_eq!(status_now(&mut manager, &wallet_id, &operation_id), status);
        }
    }
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// A NODE THAT CANNOT BE REACHED DOES NOT TAKE THE EXIT AWAY.
///
/// The bar says "not knowing is not evidence: an unreachable node releases
/// nothing", and that is the right rule when the proof has to COME from the
/// node - `retire_unmined_channel_opens` genuinely handed a transaction to one.
/// It does not apply here, and this test is the demonstration of why: nothing
/// was ever handed to a node, so there is no question to ask it, so there is
/// nothing an unreachable node could withhold. The exit works with the node
/// dead, which is the property the owner needs, since a stranded payment and an
/// unreachable node are exactly the pair a bad night produces.
#[tokio::test]
async fn an_unreachable_node_does_not_take_the_give_up_away() {
    let (root, mut manager, wallet_id, _mobile, operation_id, node, _authorization) =
        desktop_approved_operation(53_000).await;
    move_wallet_to_mainnet(&mut manager, &wallet_id, 53_010);
    assert_eq!(
        status_now(&mut manager, &wallet_id, &operation_id),
        OperationStatus::SignedAwaitingWitness
    );

    // The node goes away entirely: the listener is aborted and the socket is
    // gone, so every call against `node_url` now fails at connect.
    let submit_count = node.submit_count.clone();
    drop(node);

    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 53_020)
            .unwrap()
            .status,
        OperationStatus::Cancelled,
        "the way out of a stranded payment must not depend on a node being up"
    );
    assert_eq!(submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// A NODE THAT IS HOLDING THE TRANSACTION IS NOT ASKED, AND THE PAYMENT IS
/// FORGOTTEN ANYWAY.
///
/// This is the attack the safety bar names - "never release something that might
/// have been broadcast and might still be mined" - and it is recorded here as
/// what the code actually does rather than as what it intends.
///
/// The transaction is genuinely broadcast: the mock node holds the bytes and
/// `submit_count` is 1. The operation's status is then rolled back to
/// `SignedAwaitingWitness` on disk, which is what a restore of the wallet
/// directory to a pre-broadcast point looks like from inside the process, and
/// the give-up is pressed. It succeeds, the reservation comes back, and the
/// wallet now says a transaction the node is holding never happened.
///
/// The lifecycle cannot produce this on its own - see
/// `no_window_exists_between_the_broadcast_and_the_status_leaving_the_releasable_one`
/// - so this is not a live path. It is the residual: the ONLY thing standing
/// between the owner and this outcome is that the durable status is truthful,
/// and unlike the channel-open sweep nothing here re-checks that against a
/// chain.
#[tokio::test]
async fn a_node_holding_the_transaction_is_never_asked_before_the_payment_is_forgotten() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(54_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 54_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 54_021).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 54_022)
        .await
        .unwrap();
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the bytes really did go to the node"
    );
    let held = node.submitted_bodies.read().await.clone();
    assert_eq!(held.len(), 1, "and the node is holding them");

    move_wallet_to_mainnet(&mut manager, &wallet_id, 54_030);
    // The state is rolled back to a pre-broadcast status while the node keeps
    // the transaction. This is a restore, not a lifecycle transition.
    force_status(
        &mut manager,
        &wallet_id,
        &operation_id,
        OperationStatus::SignedAwaitingWitness,
        54_031,
    );

    let outcome = manager.abandon_stranded_witness_operation(&wallet_id, &operation_id, 54_032);
    assert!(
        outcome.is_ok(),
        "RECORDED, NOT ENDORSED: the give-up consults no node, so a transaction the \
         node is holding does not stop it. The status is the entire proof."
    );
    assert_eq!(outcome.unwrap().status, OperationStatus::Cancelled);
    assert_eq!(
        node.submitted_bodies.read().await.len(),
        1,
        "and the transaction the wallet just forgot is still sitting on the node"
    );
    drop(root);
}

/// THERE IS NO WINDOW IN WHICH THE TRANSACTION IS ON A NETWORK AND THE DURABLE
/// STATUS STILL READS THE ONE THAT MAY BE GIVEN UP.
///
/// Two independent durable writes close it, and this executes both boundaries
/// with the crash injected at each, then presses the give-up.
///
/// 1. `apply_mobile_witness_and_broadcast` persists `RollbackWitnessAccepted`
///    AFTER `mark_witnessed` has already moved the status to
///    `WitnessedAwaitingBroadcast`, and BEFORE `resume_payment` is called at
///    all. A crash on that boundary leaves a status the give-up refuses.
/// 2. `resume_payment` persists `TransactionBroadcast` - status
///    `BroadcastSubmitted` - BEFORE `node.submit_tx_hex`. A crash on that
///    boundary also leaves a status the give-up refuses.
///
/// And `resume_payment` itself refuses `SignedAwaitingWitness` outright, so
/// there is no third route from the releasable status to a submit.
#[tokio::test]
async fn no_window_exists_between_the_broadcast_and_the_status_leaving_the_releasable_one() {
    // BOUNDARY 1. Witness accepted, nothing broadcast yet.
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(55_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 55_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 55_021).await;
    manager.crash_after_witness_accepted = true;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 55_022)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    manager.crash_after_witness_accepted = false;
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "nothing was submitted at this boundary"
    );
    assert_eq!(
        status_now(&mut manager, &wallet_id, &operation_id),
        OperationStatus::WitnessedAwaitingBroadcast,
        "and the status had already left the releasable one before the broadcast could start"
    );
    move_wallet_to_mainnet(&mut manager, &wallet_id, 55_030);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 55_031)
            .unwrap_err(),
        AgentWalletError::NotWaitingOnWitnessPhone
    );
    drop(root);

    // BOUNDARY 2. Broadcast persisted, bytes provably still inside the process.
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(56_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 56_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 56_021).await;
    manager.crash_after_broadcast_persisted = true;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 56_022)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    manager.crash_after_broadcast_persisted = false;
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "the durable write happens strictly before the first network call"
    );
    assert_eq!(
        status_now(&mut manager, &wallet_id, &operation_id),
        OperationStatus::BroadcastSubmitted
    );
    move_wallet_to_mainnet(&mut manager, &wallet_id, 56_030);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 56_031)
            .unwrap_err(),
        AgentWalletError::NotWaitingOnWitnessPhone,
        "a payment whose bytes may be on a network cannot be given up, at either boundary"
    );

    // AND THE THIRD ROUTE DOES NOT EXIST: the broadcast entry point refuses the
    // releasable status by name.
    let (second_root, mut second, second_wallet, _mobile, second_operation, second_node, _auth) =
        desktop_approved_operation(57_000).await;
    assert_eq!(
        status_now(&mut second, &second_wallet, &second_operation),
        OperationStatus::SignedAwaitingWitness
    );
    assert_eq!(
        second
            .resume_payment(&second_wallet, &second_operation, 57_020)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackWitnessRequired,
        "the only submit path refuses the one status the give-up admits"
    );
    assert_eq!(second_node.submit_count.load(Ordering::SeqCst), 0);
    drop(second_root);
    drop(root);
}

/// THE WITNESS REQUIREMENT DID NOT MOVE. A PAYMENT STILL CANNOT BE MADE WITHOUT
/// A PAIRED PHONE, ON MAINNET.
///
/// This is the one that would be unforgivable. The rollback witness is a second
/// device standing between an AI agent and the owner's money, and an exit pass
/// that quietly widened the approval gate would have bought a safety net by
/// selling the thing it protects.
///
/// The approval refusal is asserted on MAINNET specifically, because mainnet is
/// where the two commands changed, and with the wallet in the state the exits
/// now leave behind - reservation returned, no operation outstanding - because
/// that is the state an owner reaches by pressing the new control.
#[tokio::test]
async fn no_phone_still_means_no_payment_on_mainnet_after_the_exit_is_taken() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(58_000).await;
    let testnet_anchor = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap()
            .block_one_fingerprint
    };
    move_wallet_to_mainnet(&mut manager, &wallet_id, 58_010);
    manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, 58_011)
        .unwrap();

    // The phone is revoked, which is this owner's situation: no device that
    // could witness anything.
    //
    // The wallet is put back on testnet for the approval attempt for one
    // uninteresting reason - the mock node in this fixture is a testnet node, so
    // a mainnet wallet cannot get past `verified_agent_node` to reach the
    // approval gate at all. It costs the test nothing:
    // `pinned_witness_phone_can_sign` reads `rollback_witness` and
    // `companion_security` and never looks at `network_mode`, and this pass did
    // not touch it or its two call sites.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.trusted_mainnet_fast_pay_pilot = false;
    state.network_mode = "testnet".to_owned();
    state.block_one_fingerprint = testnet_anchor;
    state.companion_security = None;
    state.updated_at = 58_012;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            58_012,
        )
        .unwrap();

    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request("post-exit", 58_400),
            58_020,
        )
        .await
        .unwrap();
    let next = created.operation_id.clone();
    assert_eq!(created.status, OperationStatus::ApprovalRequested);

    let approval = manager.pending_approval(&wallet_id, &next, 58_021).unwrap();
    let refusal = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, 58_022)
        .await
        .unwrap_err();
    assert_eq!(
        refusal,
        AgentWalletError::WitnessPhoneRequiredForApproval,
        "an agent must not be able to spend without a phone that can witness it"
    );
    assert_eq!(
        status_now(&mut manager, &wallet_id, &next),
        OperationStatus::ApprovalRequested,
        "and the refusal left the payment unapproved and unsigned"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "nothing reached a network at any point in this test"
    );
    let _ = mobile;
    drop(root);
}

/// THE PANEL STILL ADVERTISES THE PHONE REPLACEMENT ON MAINNET, AND THE CORE
/// STILL REFUSES IT.
///
/// `retryable` was corrected in this pass to mirror the network predicate its
/// command enforces. `phone_replacement_unblocked` was NOT, and it is the same
/// defect on the same struct: `witness_dead_end` asks only about operations and
/// the pending slot, never about the network, while
/// `prepare_witness_rotation` refuses on mainnet outright.
///
/// The sequence below is the one the desktop copy itself walks the owner
/// through - clear the dead window, then replace the phone - and it ends on a
/// refusal.
#[tokio::test]
async fn the_phone_replacement_is_still_offered_on_mainnet_and_still_refused() {
    let (root, mut manager, wallet_id, mobile, operation_id, _node, _authorization) =
        desktop_approved_operation(59_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 59_020)
        .await
        .unwrap();
    move_wallet_to_mainnet(&mut manager, &wallet_id, 59_021);
    let dead = anchor.anchor.expires_at + 1;

    // What the owner is told before they clear the window.
    let before = manager
        .stranded_witness_recovery(&wallet_id, dead)
        .unwrap()
        .unwrap();
    assert!(before.anchor_releasable);
    assert!(
        !before.phone_replacement_unblocked,
        "not offered yet, because the window is still in the slot"
    );

    manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, dead)
        .unwrap();

    let after = manager
        .stranded_witness_recovery(&wallet_id, dead + 1)
        .unwrap()
        .unwrap();
    assert!(
        after.phone_replacement_unblocked,
        "THE FINDING: on mainnet the panel now says replacing the phone is available"
    );

    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "attack-rotation".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                dead + 2,
            )
            .await
            .unwrap_err(),
        AgentWalletError::WitnessRotationNetworkUnsupported,
        "and pressing it is refused: the surface advertises a control the core will not honour"
    );
    drop(root);
}

/// TWO OF THE NEW SENTENCES CLAIM THINGS THE CODE CANNOT KNOW, ON STATUSES THAT
/// REACH THEM.
///
/// Every one of these strings is `error.to_string()`, which `public_error`
/// passes through verbatim and `readableError` returns unchanged into the
/// desktop's error banner. They ARE the screen, so a clause in one is a claim
/// the wallet is making to the owner about their money.
///
/// Each is asserted here the same way: reach the refusal from a real operation
/// in a real status, then read the sentence it produced.
#[tokio::test]
async fn two_new_refusals_overclaim_on_statuses_that_reach_them() {
    // ONE. `WitnessAnchorNetworkUnsupported` ends "Nothing was sent to the
    // network and no money has moved." `pending_rollback_anchor` checks the
    // status FIRST and the network SECOND, and the status it admits is all four
    // of `awaits_mobile_witness`, three of which are past the node. So this
    // sentence is produced for a payment that was sent.
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(60_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 60_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 60_021).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 60_022)
        .await
        .unwrap();
    assert_eq!(
        status_now(&mut manager, &wallet_id, &operation_id),
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the money really did move"
    );
    move_wallet_to_mainnet(&mut manager, &wallet_id, 60_030);

    let refusal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 60_031)
        .await
        .unwrap_err();
    assert_eq!(refusal, AgentWalletError::WitnessAnchorNetworkUnsupported);
    assert!(
        refusal
            .to_string()
            .contains("Nothing was sent to the network and no money has moved"),
        "RECORDED: this is the sentence a submitted payment produces"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 60_032)
            .unwrap()
            .unwrap()
            .submitted,
        "and the same wallet, in the same breath, reports the payment as submitted"
    );

    // TWO. `StrandedPaymentAlreadySent` states "the transaction is on the
    // chain". `BroadcastUncertain` is the status that exists precisely because
    // that is not known: the bytes went out and the acknowledgement could not be
    // tied to them.
    force_status(
        &mut manager,
        &wallet_id,
        &operation_id,
        OperationStatus::BroadcastUncertain,
        60_040,
    );
    let refusal = manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, 60_041)
        .unwrap_err();
    assert_eq!(refusal, AgentWalletError::StrandedPaymentAlreadySent);
    assert!(
        refusal
            .to_string()
            .contains("the transaction is on the chain"),
        "RECORDED: stated as fact to an owner whose payment is in the one status \
         that means the wallet does not know it"
    );
    drop(root);
}
