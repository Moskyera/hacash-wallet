//! THE WAY OUT OF A STRANDED PAYMENT, ON THE NETWORK THE OWNER IS ACTUALLY ON.
//!
//! `OperationStatus::SignedAwaitingWitness` is ENTERED on a compile-time check -
//! `AgentOperation::record_signed` keys off
//! `cfg!(feature = "agent-wallet-testnet-pilot")` and nothing on the signing
//! path looks at the network - and both ways out of it USED to be gated on a
//! runtime string, `state.network_mode != "testnet"`, tested before the
//! operation was so much as looked up. The two disagreed, and mainnet is where
//! they disagreed.
//!
//! What that cost is not one payment. `SignedAwaitingWitness` satisfies
//! `retains_reservation()` and fails `is_terminal()`, and the guards on new
//! payments, on `prepare_l2_channel_setup`, on `verify_and_bind_l2_channel`, on
//! `prepare_witness_rotation` and on `prepare_l2_channel_close` all read exactly
//! that pair. The last one is the one that matters: the channel exit proven on
//! mainnet at block 778065 is refused while a payment that never left this
//! desktop sits in this status, so the deposit is locked in behind it.
//!
//! Every test here reaches that status the honest way, through
//! `desktop_approved_operation`: a real agent proposal, a real owner approval, a
//! real signature over a real consensus transaction. Nothing writes a status
//! into state by hand. Only the network name is moved, the way
//! `lifecycle.rs` moves it, because that is the one thing the fixture cannot
//! reach and the exact thing that was gating the exits.
//!
//! WHAT IS DELIBERATELY STILL SHUT, AND IS EXECUTED HERE RATHER THAN ASSUMED:
//! the FORWARD step. `pending_rollback_anchor` mints the anchor the phone signs
//! and an accepted receipt broadcasts immediately, so admitting it on mainnet is
//! a decision about moving real money, not about unsticking a payment. It stays
//! testnet only, it now says so in words the owner can act on, and
//! `stranded_witness_recovery` stops advertising a retry it will refuse.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    DeviceRole, SoftwareDeviceIdentity, WitnessRotationMode, WitnessRotationReason,
};

use super::desktop_witness_flow::{AMOUNT_UNITS, desktop_approved_operation};
use super::fixtures::*;
use super::pilot_node::signed_receipt;
use super::*;
use crate::journal::AgentJournalEventKind;

/// Moves an existing wallet onto mainnet, leaving everything else exactly as it
/// stands.
///
/// This is the one thing the desktop fixture cannot do for itself, and it is
/// precisely the difference the defect lived in. `trusted_mainnet_fast_pay_pilot`
/// is set because that is this owner's wallet: they accepted the trusted voucher
/// and their agent spending is live on mainnet.
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
    assert_eq!(
        manager
            .load_verified_state(wallet_id, &state_master, &journal_key)
            .unwrap()
            .network_mode,
        "mainnet"
    );
}

/// The exact pair of facts every wedging guard in this codebase reads:
/// `active_reservations(state) != 0`, and any operation that is not terminal.
///
/// Quoted rather than described, because "the wallet is stuck" is the claim and
/// this is the thing that makes it true.
fn wallet_is_wedged_by_an_operation(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> bool {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    crate::service::state::active_reservations(&state).unwrap() != HacUnits::ZERO
        || state
            .operations
            .values()
            .any(|operation| !operation.status().is_terminal())
}

fn operation_view(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    now: u64,
) -> PaymentOperationView {
    manager
        .list_operations_admin(wallet_id, now)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == *operation_id)
        .unwrap()
}

/// THE HEADLINE. A MAINNET OWNER WHOSE PHONE CANNOT WITNESS CAN GIVE THE
/// PAYMENT UP, AND GETS THEIR CHANNEL BACK.
///
/// No anchor was ever minted here, which is this owner's real situation: their
/// journal holds no pairing, witness, companion or device event at all. A phone
/// that is lost, broken or never paired strands a signed payment exactly as
/// thoroughly as an expired anchor does.
///
/// The give-up is safe because of what the STATUS is, not because of which chain
/// the wallet points at. `record_signed` stores the signed hex and a hash and
/// sets a field; it takes no node handle and submits nothing, and the only route
/// from here towards a broadcast is `mark_witnessed`, reachable only through a
/// receipt that verifies against a pending anchor. The transaction exists solely
/// as hex inside this wallet's own encrypted state, so there is no question to
/// put to a node and no unreachable node that can take this exit away.
#[tokio::test]
async fn a_mainnet_owner_can_give_up_a_payment_no_phone_can_witness() {
    let (root, mut manager, wallet_id, _mobile, operation_id, node, _authorization) =
        desktop_approved_operation(41_000).await;
    move_wallet_to_mainnet(&mut manager, &wallet_id, 41_010);

    let before = operation_view(&mut manager, &wallet_id, &operation_id, 41_011);
    assert_eq!(before.status, OperationStatus::SignedAwaitingWitness);
    assert!(
        before.tx_hash.is_some(),
        "signed, so there is a hash - which is not the same as sent"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "and nothing was handed to the node, which is what makes the exit honest"
    );
    assert!(wallet_is_wedged_by_an_operation(&mut manager, &wallet_id));

    // THE DOOR THAT MATTERS MOST IS SHUT. The channel exit refuses while this
    // sits, so the deposit in an already open channel cannot be brought home.
    //
    // Asked only in the build the owner actually runs. Off the bounded mainnet
    // pilot the close is refused one gate earlier, by
    // `require_agent_spending_network`, and would prove nothing about this
    // payment either way.
    if cfg!(feature = "agent-wallet-bounded-mainnet-pilot") {
        assert_eq!(
            manager
                .prepare_l2_channel_close(&wallet_id, 41_012)
                .await
                .unwrap_err(),
            AgentWalletError::RecoveryRequired,
            "the stranded payment, not the channel, is what refuses the exit"
        );
    }

    // WHAT THE DESKTOP PUTS IN FRONT OF THE OWNER BEFORE THE PRESS.
    let stranded = manager
        .stranded_witness_recovery(&wallet_id, 41_013)
        .unwrap()
        .unwrap();
    assert_eq!(stranded.operation_id, operation_id.to_string());
    assert_eq!(stranded.amount_units, HacUnits::new(AMOUNT_UNITS));
    assert!(!stranded.submitted, "nothing was sent, and it says so");
    assert!(
        stranded.abandonable,
        "the control the panel draws must be one the core will honour"
    );

    // THE PRESS. This used to answer `NodeNetworkMismatch` - "configured node
    // does not match the Agent Wallet network" - about a node that had opened
    // and closed a real mainnet channel hours earlier.
    let abandoned = manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, 41_014)
        .unwrap();
    assert_eq!(abandoned.status, OperationStatus::Cancelled);
    assert_eq!(
        abandoned.reserved_units,
        HacUnits::ZERO,
        "the money comes back"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "and giving it up moved nothing on any network"
    );

    // AND EVERY DOOR IS OPEN AGAIN. The channel exit no longer refuses because
    // of this payment; it refuses only because this wallet has no channel bound,
    // which is a different sentence and a different remedy.
    assert!(!wallet_is_wedged_by_an_operation(&mut manager, &wallet_id));
    if cfg!(feature = "agent-wallet-bounded-mainnet-pilot") {
        assert_eq!(
            manager
                .prepare_l2_channel_close(&wallet_id, 41_015)
                .await
                .unwrap_err(),
            AgentWalletError::SigningBlocked,
            "no channel bound: the refusal that is left is a different one, with a different remedy"
        );
    }
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 41_016)
            .unwrap()
            .is_none()
    );

    // AND THE ONE CONTROL THAT COULD NOT HAVE WORKED WAS NEVER OFFERED. Asking
    // the phone again is still testnet only, so the panel the owner read before
    // the press did not invite it.
    assert!(!stranded.retryable);
    assert!(
        !stranded.network_supports_witness_retry,
        "and the desktop is told which of the two reasons it is, so it prints the dead end rather than 'your phone is already confirming it'"
    );
    drop(root);
}

/// A DEAD CONFIRMATION WINDOW CAN BE CLEARED ON MAINNET, AND CLEARING IT STILL
/// TOUCHES NOTHING.
///
/// The anchor has to be minted while the wallet is on testnet, because that
/// forward step is deliberately still shut on mainnet - a wallet restored or
/// re-pointed onto mainnet carries the slot with it. That is exactly the case
/// the old gate could not answer: the slot is what refuses the phone
/// replacement, and there was no way to empty it.
///
/// What makes this safe on any network is that it ASSERTS NOTHING. It drops one
/// dead anchor and returns the operation untouched, so there is no claim for a
/// chain to contradict and no node to ask.
#[tokio::test]
async fn a_mainnet_owner_can_clear_a_dead_confirmation_window() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(42_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 42_020)
        .await
        .unwrap();
    let dead = anchor.anchor.expires_at + 1;
    move_wallet_to_mainnet(&mut manager, &wallet_id, dead);

    let shown = manager
        .stranded_witness_recovery(&wallet_id, dead)
        .unwrap()
        .unwrap();
    assert!(shown.anchor_issued);
    assert!(shown.anchor_releasable);

    let before = operation_view(&mut manager, &wallet_id, &operation_id, dead);
    let released = manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, dead)
        .unwrap();
    assert_eq!(
        released, before,
        "the payment is returned untouched: status, hash and reservation"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    assert!(
        !manager
            .stranded_witness_recovery(&wallet_id, dead + 1)
            .unwrap()
            .unwrap()
            .anchor_issued,
        "the slot is empty, which is the whole point of the control"
    );

    // AND THE PAYMENT STILL HAS ITS OWN EXIT AFTERWARDS.
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, dead + 2)
            .unwrap()
            .status,
        OperationStatus::Cancelled
    );
    drop(root);
}

/// NOTHING ABOUT A LIVE WINDOW CHANGED WHEN THE NETWORK GATE CAME OFF.
///
/// The admission that carries the safety is the one that was always there: a
/// phone may be signing this second, so neither control is honoured while
/// anything is still outstanding that could become a witness. Removing the
/// network comparison must not have widened that by one second, on either
/// network.
#[tokio::test]
async fn a_live_confirmation_window_still_refuses_both_controls_on_mainnet() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(43_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 43_020)
        .await
        .unwrap();
    move_wallet_to_mainnet(&mut manager, &wallet_id, 43_021);

    let live = anchor.anchor.expires_at - 1;
    assert!(
        !manager
            .stranded_witness_recovery(&wallet_id, live)
            .unwrap()
            .unwrap()
            .abandonable
    );
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, live)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable,
        "nothing races a phone that may be signing, on any network"
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, live)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, live).status,
        OperationStatus::SignedAwaitingWitness,
        "and the refusals changed nothing"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// EVERY REFUSAL ON THESE TWO CONTROLS SAYS SOMETHING TRUE.
///
/// `public_error` is `error.to_string()` verbatim, `readableError` returns it
/// unchanged and the desktop puts it straight in the error banner, so these
/// sentences ARE the screen. Not one of them may name the node, because the node
/// is not what is wrong in any of these cases, and each has to say what did not
/// happen: a refusal here never signs, never sends and never spends.
#[tokio::test]
async fn every_refusal_on_the_stranded_payment_controls_says_what_is_true() {
    let (root, mut manager, wallet_id, _mobile, operation_id, node, _authorization) =
        desktop_approved_operation(44_000).await;
    move_wallet_to_mainnet(&mut manager, &wallet_id, 44_010);

    // AN OPERATION THAT DOES NOT EXIST IS NOT A NETWORK PROBLEM. The old gate
    // answered before it had looked, so it blamed the network for a payment it
    // had never read.
    let stranger = OperationId::new();
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &stranger, 44_011)
            .unwrap_err(),
        AgentWalletError::OperationNotFound
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &stranger, 44_012)
            .unwrap_err(),
        AgentWalletError::OperationNotFound
    );

    // NO WINDOW WAS EVER OPENED, SO THERE IS NOTHING TO CLEAR. This used to be
    // `RollbackWitnessRequired` - "mobile rollback witness receipt is required
    // before broadcast" - which describes a different thing entirely.
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, 44_013)
            .unwrap_err(),
        AgentWalletError::WitnessConfirmationWindowNotFound
    );

    // ONCE GIVEN UP, THE PAYMENT IS NOT WAITING ON A PHONE ANY MORE.
    manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, 44_014)
        .unwrap();
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 44_015)
            .unwrap_err(),
        AgentWalletError::NotWaitingOnWitnessPhone
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, 44_016)
            .unwrap_err(),
        AgentWalletError::NotWaitingOnWitnessPhone
    );

    // THE FORWARD STEP IS STILL SHUT ON MAINNET, AND NOW SAYS SO. It used to
    // answer `InvalidOperationState`, which reads as though the payment were the
    // thing that was wrong.
    let (second_root, mut second, second_wallet, second_mobile, second_operation, _node, _auth) =
        desktop_approved_operation(45_000).await;
    move_wallet_to_mainnet(&mut second, &second_wallet, 45_010);
    assert_eq!(
        second
            .pending_rollback_anchor(
                &second_wallet,
                &second_operation,
                second_mobile.device_id(),
                45_011,
            )
            .await
            .unwrap_err(),
        AgentWalletError::WitnessAnchorNetworkUnsupported
    );
    // AND THE PANEL STOPS OFFERING IT. `retryable` promised a retry the core
    // refused, and the desktop rendered that as "it is safe to try more than
    // once" over a button that could not work.
    let shown = second
        .stranded_witness_recovery(&second_wallet, 45_012)
        .unwrap()
        .unwrap();
    assert!(
        !shown.retryable,
        "no control is offered that will be refused"
    );
    assert!(
        !shown.network_supports_witness_retry,
        "and the desktop is told which of the two reasons it is, so it prints the dead end rather than 'your phone is already confirming it'"
    );
    assert!(
        shown.abandonable,
        "and the exit that does work is the one left standing"
    );

    // THE PHONE REPLACEMENT IS ALSO STILL MAINNET-SHUT, AND SAYS THAT INSTEAD OF
    // BLAMING THE NODE. It is not an exit from a stranded payment: it revokes
    // the owner's current phone and burns a witness epoch partway through.
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        second
            .prepare_witness_rotation(
                &second_wallet,
                "mainnet-rotation".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                45_013,
            )
            .await
            .unwrap_err(),
        AgentWalletError::WitnessRotationNetworkUnsupported
    );

    for message in [
        AgentWalletError::WitnessRecoveryNotAvailable.to_string(),
        AgentWalletError::StrandedPaymentAlreadySent.to_string(),
        AgentWalletError::NotWaitingOnWitnessPhone.to_string(),
        AgentWalletError::WitnessConfirmationWindowNotFound.to_string(),
        AgentWalletError::WitnessConfirmationWindowBelongsToAnotherPayment.to_string(),
        AgentWalletError::WitnessAnchorNetworkUnsupported.to_string(),
        AgentWalletError::WitnessRotationNetworkUnsupported.to_string(),
    ] {
        assert!(
            !message.contains("configured node"),
            "the node is not what is wrong here: {message}"
        );
        assert!(
            message.contains("Nothing was") || message.contains("no money has moved"),
            "a refusal on stuck money must say what did not happen: {message}"
        );
    }
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(second_root);
    drop(root);
}

/// A PAYMENT THAT REALLY WAS SENT IS STILL REFUSED, AND NOW THE OWNER IS TOLD
/// WHY.
///
/// This is the one refusal that must never soften. Giving up a submitted payment
/// would hand the reservation back and mark it `Cancelled`, which is a claim
/// that a transaction on the chain never happened. The network gate coming off
/// must not have reached this, and `abandonable` must stay false.
#[tokio::test]
async fn a_submitted_payment_is_still_refused_and_the_reason_is_the_true_one() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(46_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 46_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 46_021).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 46_022)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    move_wallet_to_mainnet(&mut manager, &wallet_id, 46_030);

    let shown = manager
        .stranded_witness_recovery(&wallet_id, 46_031)
        .unwrap()
        .unwrap();
    assert!(shown.submitted, "the owner is told their money moved");
    assert!(!shown.abandonable);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 46_032)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent,
        "refused, and no longer for a reason about the node"
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 46_033).status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "and the payment is exactly where it was"
    );
    drop(root);
}
