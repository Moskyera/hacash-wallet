//! THE PROCESS DIES BETWEEN THE DURABLE RECEIPT WRITE AND THE ARCHIVE.
//!
//! `apply_mobile_witness_and_broadcast` does two durable writes, not one. The
//! first records the phone's receipt in the single pending slot, advances the
//! witness chain position, and - pre-broadcast - marks the payment witnessed.
//! Only after that does it broadcast and archive. Between those two writes is a
//! window, and a wallet that dies in it comes back holding a receipt that
//! nothing left in the wallet could consume:
//!
//!   * `pending_rollback_anchor` re-serves the dead anchor until it expires and
//!     then refuses forever, because re-issue is deliberately refused once a
//!     receipt sits against the anchor;
//!   * `release_dead_witness_anchor` refuses while a receipt sits there;
//!   * `abandon_stranded_witness_operation` refuses post-submit, and must;
//!   * `prepare_witness_rotation` refuses while the slot is occupied;
//!   * `create_payment_intent` refuses while the payment is unresolved.
//!
//! Every control the owner has returns false at once. Post-submit the money is
//! already on the network when that happens.
//!
//! Nothing here writes a status into state by hand and nothing here fakes a
//! receipt. The crash is injected at the exact instant `persist_event` returns,
//! the manager is dropped, and the wallet is reopened from the same directory -
//! so what the recovery reads is the real on-disk residue of a real interrupted
//! call.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    DeviceRole, RollbackOperationPhase, SoftwareDeviceIdentity, WitnessRotationMode,
    WitnessRotationReason,
};

use super::desktop_witness_flow::{
    desktop_approved_operation, pair_desktop_agent, payment_request, settle_with_witness,
};
use super::fixtures::*;
use super::pilot_node::*;
use super::*;

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

/// `(operation_id, anchor_id, expires_at, has_receipt)` for whatever occupies
/// the single pending slot.
fn pending_slot(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> Option<(String, String, u64, bool)> {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state
        .rollback_witness
        .as_ref()
        .and_then(|witness| witness.pending.as_ref())
        .map(|pending| {
            (
                pending.operation_id.clone(),
                pending.proposal.anchor.anchor_id.clone(),
                pending.proposal.anchor.expires_at,
                pending.receipt.is_some(),
            )
        })
}

fn chain_position(manager: &AgentWalletManager, wallet_id: &AgentWalletId) -> (u64, String) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state.rollback_witness.as_ref().map_or_else(
        || {
            (
                0,
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            )
        },
        |witness| {
            (
                witness.last_anchor_sequence,
                witness.last_anchor_hash.clone(),
            )
        },
    )
}

fn archived_witness_count(manager: &AgentWalletManager, wallet_id: &AgentWalletId) -> usize {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state
        .rollback_witness
        .as_ref()
        .map_or(0, |witness| witness.history.len())
}

/// Drives a fresh wallet to `SubmittedAwaitingFinalWitness` through the real
/// path - desktop approval, real anchor, real phone signature, real submission
/// to the mock node - and hands back the post-submit anchor and the receipt the
/// phone signed for it.
///
/// This is the state in which the money has already moved and the wallet is
/// waiting on the second witness.
async fn post_submit_anchor_and_receipt(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    MockPilotNode,
    crate::service::AgentAuthorization,
    hpay_companion_protocol::SignedRollbackAnchor,
    hpay_companion_protocol::SignedWitnessReceipt,
) {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(now).await;
    let first = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 20)
        .await
        .unwrap();
    let receipt = signed_receipt(&first, &mobile, now + 30).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, now + 40)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 50)
        .await
        .unwrap();
    assert_eq!(
        post_submit.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    let post_receipt = signed_receipt(&post_submit, &mobile, now + 60).await;
    (
        root,
        manager,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        post_submit,
        post_receipt,
    )
}

/// EXECUTION 1: THE NAMED DEFECT. POST-SUBMIT, NO EXIT AT ALL.
///
/// The money is on the network, the phone has signed the post-submit witness,
/// the desktop has written that receipt to disk - and then the process dies
/// before `archive_completed_witness` runs.
///
/// The whole of the owner's recovery surface is exercised on the reopened
/// wallet, at the instant of the crash and again once the anchor is long dead.
#[tokio::test]
async fn the_post_submit_crash_between_the_receipt_write_and_the_archive_recovers_on_unlock() {
    let (
        root,
        mut manager,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        post_submit,
        post_receipt,
    ) = post_submit_anchor_and_receipt(30_000).await;
    let before_crash = operation_view(&mut manager, &wallet_id, &operation_id, 30_069);
    let tx_hash = before_crash.tx_hash.clone().unwrap();

    // ---- THE CRASH. The receipt reaches the desktop, the desktop writes it,
    // and the process dies with the archive still to run.
    manager.crash_after_witness_accepted = true;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, post_receipt.clone(), 30_070)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "the injected crash returns without running anything below the boundary"
    );
    drop(manager);

    // ---- THE OWNER REOPENS THE WALLET. Nothing is in memory; everything below
    // is read back off disk.
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 30_080).unwrap();

    // WHAT WAS WRITTEN BEFORE THE CRASH IS INTACT, and it is exactly the half
    // of the sequence that ran: the receipt is in the slot and the chain
    // position has moved onto the post-submit anchor.
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the crash submitted nothing and un-submitted nothing"
    );

    // ---- THE RECOVERY. Unlock finished the archive from what was already on
    // disk. No phone was contacted, no owner pressed anything, and the receipt
    // that did the work is the one the phone really signed.
    let recovered = operation_view(&mut manager, &wallet_id, &operation_id, 30_081);
    assert_eq!(
        recovered.status,
        OperationStatus::ReconciliationRequired,
        "the interrupted post-submit witness is completed on unlock, which is \
         exactly where the uninterrupted call would have left it"
    );
    assert_eq!(
        recovered.tx_hash.as_deref(),
        Some(tx_hash.as_str()),
        "and the record of which transaction moved the money is unchanged"
    );
    assert!(
        pending_slot(&manager, &wallet_id).is_none(),
        "the slot that nothing could clear is clear"
    );
    assert_eq!(
        chain_position(&manager, &wallet_id).0,
        post_submit.anchor.anchor_sequence,
        "the chain position is the one the accepted receipt wrote, not a new one"
    );
    assert_eq!(
        archived_witness_count(&manager, &wallet_id),
        2,
        "both witnesses are archived: the pre-broadcast one and this one"
    );

    // ---- AND THE WALLET IS ALIVE AGAIN. Every control that returned false
    // while the receipt was parked now behaves as it does on the ordinary path.
    let tx = recovered.tx_hash.clone().unwrap();
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx, 30_090)
        .unwrap();
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 30_100)
        .await
        .unwrap();
    let receipt = signed_receipt(&final_anchor, &mobile, 30_110).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 30_120)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "one payment, one submission, across a crash and a restart"
    );
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-crash-recovery", 30_500),
                30_130,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "and the agent-payment feature is not dead forever"
    );
    drop(root);
}

/// EXECUTION 2: THE SAME CRASH, AND THE ANCHOR IS LONG DEAD BEFORE THE OWNER
/// COMES BACK.
///
/// This is the version with no exit at all. While the anchor is alive the phone
/// could in principle re-send the identical receipt, and `RecoverPendingWitness`
/// would carry it. Once the five minutes are up, re-issue is refused because a
/// receipt sits against the anchor, and every other control is refused too.
///
/// The recovery must not depend on the anchor being alive, because a wallet
/// that crashed is by definition not going to be reopened inside five minutes.
#[tokio::test]
async fn the_post_submit_crash_recovers_when_the_anchor_died_long_before_the_owner_returned() {
    let (
        root,
        mut manager,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        post_submit,
        post_receipt,
    ) = post_submit_anchor_and_receipt(31_000).await;
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 31_069)
        .tx_hash
        .unwrap();

    manager.crash_after_witness_accepted = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, post_receipt, 31_070)
            .await
            .is_err()
    );
    drop(manager);

    // A YEAR LATER. The anchor died 365 days ago.
    let much_later = post_submit.anchor.expires_at + 365 * 24 * 60 * 60;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();

    let recovered = operation_view(&mut manager, &wallet_id, &operation_id, much_later + 1);
    assert_eq!(
        recovered.status,
        OperationStatus::ReconciliationRequired,
        "expiry is irrelevant to a receipt that was already accepted and \
         already advanced the chain; nothing is being re-verified against a \
         clock here, it is being finished"
    );
    assert_eq!(recovered.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert!(pending_slot(&manager, &wallet_id).is_none());
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // AND THE LIFECYCLE RUNS ON FROM THERE, WITH THE SAME PHONE, TO Committed.
    // `ReconciliationRequired` still blocks a new payment, and must: this one
    // has not finished. What matters is that it can now finish at all.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("still-blocked-until-committed", much_later + 500),
                much_later + 2,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "a payment awaiting external reconciliation still blocks the next one"
    );
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, much_later + 3)
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(
            &wallet_id,
            &operation_id,
            mobile.device_id(),
            much_later + 4,
        )
        .await
        .unwrap();
    let receipt = signed_receipt(&final_anchor, &mobile, much_later + 5).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, much_later + 6)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-year-late-recovery", much_later + 900),
                much_later + 7,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "and the wallet takes payments again"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 3: THE SECOND DEFECT. PRE-BROADCAST, AND THE DESKTOP SHOWS
/// NOTHING AT ALL.
///
/// Same window, one phase earlier. The first durable write marks the payment
/// `WitnessedAwaitingBroadcast`, and that status is not in
/// `OperationStatus::awaits_mobile_witness`, so `stranded_witness_recovery` -
/// the whole of the owner's recovery surface - answers `None`. The desktop
/// shows an owner whose wallet refuses every further payment precisely nothing.
///
/// It is also the one window where the interrupted step is a BROADCAST, so the
/// recovery has to finish the payment the owner approved rather than only tidy
/// state.
#[tokio::test]
async fn the_pre_broadcast_crash_before_the_broadcast_finishes_the_payment_on_unlock() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(32_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 32_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 32_030).await;

    // ---- THE CRASH, one instant after the receipt is durable and before the
    // signed transaction has gone anywhere.
    manager.crash_after_witness_accepted = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 32_040)
            .await
            .is_err()
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "nothing reached the node before the crash"
    );
    drop(manager);

    // ---- REOPEN. This is the residue the desktop was blind to: a status that
    // is not in `awaits_mobile_witness`, so the whole recovery surface answered
    // nothing while the wallet refused every further payment.
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 32_050).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 32_050).status,
        OperationStatus::WitnessedAwaitingBroadcast,
        "the unlock archive alone cannot finish this one: the interrupted step \
         is a broadcast, and unlock does not reach the network"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 32_050)
            .unwrap()
            .is_none(),
        "and this is exactly why the desktop showed the owner nothing"
    );

    // The witnessed payment is resumed from disk: the same signed bytes, the
    // same approval, the same receipt. This is what the desktop runs straight
    // after every unlock.
    let resumed = manager
        .resume_interrupted_witness(&wallet_id, 32_051)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed.status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "the payment the owner approved and the phone witnessed is carried \
         through, not stranded in a status with no control on it"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "exactly one submission, and only after the real phone signature"
    );
    assert!(pending_slot(&manager, &wallet_id).is_none());
    assert_eq!(archived_witness_count(&manager, &wallet_id), 1);

    // The owner-facing surface answers again, and truthfully.
    let shown = manager
        .stranded_witness_recovery(&wallet_id, 32_052)
        .unwrap()
        .unwrap();
    assert_eq!(shown.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert!(shown.submitted);
    assert!(shown.transaction_id.is_some());
    assert!(!shown.abandonable);

    // Resuming again is a nothing, and it does not submit twice.
    assert!(
        manager
            .resume_interrupted_witness(&wallet_id, 32_053)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 4: THE THIRD WINDOW. THE MONEY WENT OUT AND THEN THE PROCESS DIED.
///
/// Pre-broadcast phase, crash AFTER `resume_payment` put the transaction on the
/// network and persisted `BroadcastSubmitted`, and before the archive.
///
/// `BroadcastSubmitted` is in nobody's admitted set: it is not in
/// `awaits_mobile_witness`, `confirm_broadcast` refuses it in the pilot,
/// `resume_payment` answers `BroadcastUncertain` without changing anything, and
/// the pending receipt keeps the slot occupied. The owner's money is on the
/// network and their wallet is a brick.
#[tokio::test]
async fn the_crash_after_the_broadcast_and_before_the_archive_recovers_on_unlock() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(33_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 33_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 33_030).await;

    manager.crash_before_witness_archive = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 33_040)
            .await
            .is_err()
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the money really did go out before the process died"
    );
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 33_041)
        .tx_hash
        .unwrap();
    drop(manager);

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 33_050).unwrap();

    let recovered = operation_view(&mut manager, &wallet_id, &operation_id, 33_051);
    assert_eq!(
        recovered.status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "the archive that was interrupted is completed from disk, and it moves \
         the payment exactly one step - the step the uninterrupted call takes"
    );
    assert_eq!(recovered.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert!(pending_slot(&manager, &wallet_id).is_none());
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "recovering an archive rebroadcasts nothing"
    );

    // And the lifecycle carries on to Committed with the same phone.
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 33_060)
        .await
        .unwrap();
    let receipt = signed_receipt(&post_submit, &mobile, 33_070).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 33_080)
            .await
            .unwrap()
            .status,
        OperationStatus::ReconciliationRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 5: THE FINAL-WITNESS WINDOW, WHERE THE CHAIN HAS ALREADY CONFIRMED
/// THE PAYMENT.
///
/// Same shape, the last phase: `ReconciledAwaitingFinalWitness` one signature
/// short of `Committed`, receipt written, archive interrupted.
#[tokio::test]
async fn the_final_witness_crash_recovers_on_unlock() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(34_000).await;
    let first = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 34_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&first, &mobile, 34_030).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 34_040)
        .await
        .unwrap();
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 34_050)
        .await
        .unwrap();
    let receipt = signed_receipt(&post_submit, &mobile, 34_060).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 34_070)
        .await
        .unwrap();
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 34_075)
        .tx_hash
        .unwrap();
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 34_080)
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 34_090)
        .await
        .unwrap();
    let final_receipt = signed_receipt(&final_anchor, &mobile, 34_100).await;

    manager.crash_after_witness_accepted = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, final_receipt, 34_110)
            .await
            .is_err()
    );
    drop(manager);

    let much_later = final_anchor.anchor.expires_at + 90 * 24 * 60 * 60;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();

    let recovered = operation_view(&mut manager, &wallet_id, &operation_id, much_later + 1);
    assert_eq!(
        recovered.status,
        OperationStatus::Committed,
        "the last witness is finished from disk"
    );
    assert_eq!(recovered.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert!(pending_slot(&manager, &wallet_id).is_none());
    assert_eq!(archived_witness_count(&manager, &wallet_id), 3);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, much_later + 2)
            .unwrap()
            .is_none()
    );
    drop(root);
}

/// PROVE-THE-TEST, PART ONE: THE CRASH REALLY IS A DEAD END WITHOUT THE
/// RECOVERY.
///
/// The recovery on unlock is what the four tests above rest on. This one turns
/// it off - by reading the residue with the recovery skipped - and walks every
/// control the owner has, so that "no exit at all" is a fact this suite
/// executes rather than a claim it inherits from a report.
#[tokio::test]
async fn without_the_recovery_the_post_submit_crash_has_no_exit_at_all() {
    let (
        root,
        mut manager,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        post_submit,
        post_receipt,
    ) = post_submit_anchor_and_receipt(35_000).await;

    manager.crash_after_witness_accepted = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, post_receipt.clone(), 35_070)
            .await
            .is_err()
    );
    drop(manager);

    // Reopen WITHOUT the unlock recovery, which is exactly the wallet as it
    // stood before this change.
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager
        .unlock_without_witness_recovery_for_test(&wallet_id, PASSPHRASE, 35_080)
        .unwrap();

    let parked = pending_slot(&manager, &wallet_id).unwrap();
    assert_eq!(parked.0, operation_id.to_string());
    assert_eq!(parked.1, post_submit.anchor.anchor_id);
    assert!(
        parked.3,
        "the receipt is on disk and the archive never ran: this is the window"
    );

    let dead = post_submit.anchor.expires_at + 1;

    // 1. RE-ISSUE. Refused, and rightly: a receipt already sits against this
    //    anchor, so handing out a second one for the same phase would be a
    //    second witness for one signature.
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );

    // 2. RELEASE THE DEAD ANCHOR. Refused: it would discard a witness that
    //    really arrived.
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, dead)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable
    );

    // 3. ABANDON. Refused, and must be: the money moved.
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, dead)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent
    );

    // 4. REPLACE THE PHONE. Refused while the slot is occupied.
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation-after-crash".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                dead,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );

    // 5. THE PHONE SENDS THE SAME RECEIPT AGAIN. This is the one thing that
    //    still worked, and only because the anchor had not expired; the
    //    lifecycle re-enters at the archive. It is not an exit the owner has:
    //    it needs the handset back on the LAN with the identical receipt.
    //    Every control below is what they are left with when it is not.
    //
    // 6. THE DESKTOP'S RECOVERY SURFACE. Every flag false at once.
    let shown = manager
        .stranded_witness_recovery(&wallet_id, dead)
        .unwrap()
        .unwrap();
    assert_eq!(shown.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert!(shown.submitted, "the money moved and it still says so");
    assert!(!shown.retryable, "asking the phone again is refused");
    assert!(!shown.abandonable);
    assert!(!shown.anchor_releasable);
    assert!(!shown.phone_replacement_unblocked);

    // 7. AND NO FURTHER PAYMENT, EVER.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("blocked-by-crash", dead + 400),
                dead + 1,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // AND THE RECOVERY IS WHAT LIFTS IT. Same wallet, same disk, one unlock.
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, dead + 2).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, dead + 3).status,
        OperationStatus::ReconciliationRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// PROVE-THE-TEST, PART TWO: THE RECOVERY IS NOT A WAY PAST THE PHONE.
///
/// The recovery finishes a witness that a real phone really signed and that was
/// already written to disk. It must never manufacture one. Four ways of having
/// no such receipt are executed against it, and it declines every one, leaving
/// the payment exactly where the ordinary rules leave it.
#[tokio::test]
async fn the_crash_recovery_never_witnesses_anything_the_phone_did_not_sign() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(36_000).await;

    // 1. A SIGNED PAYMENT WITH NO ANCHOR AT ALL. Nothing to resume.
    assert!(
        manager
            .resume_interrupted_witness(&wallet_id, 36_010)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 36_011).status,
        OperationStatus::SignedAwaitingWitness
    );

    // 2. AN ANCHOR OUTSTANDING AND NO RECEIPT. Still nothing to resume: an
    //    anchor is a question, not an answer.
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 36_020)
        .await
        .unwrap();
    assert!(
        manager
            .resume_interrupted_witness(&wallet_id, 36_021)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 36_022).status,
        OperationStatus::SignedAwaitingWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // 3. THE ANCHOR DIES UNWITNESSED. A restart is not a witness either: unlock
    //    runs the recovery and the payment is still waiting for the phone.
    let dead = anchor.anchor.expires_at + 1;
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, dead).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, dead + 1).status,
        OperationStatus::SignedAwaitingWitness,
        "an unlock must never move a payment that no phone has signed for"
    );
    assert!(
        manager
            .resume_interrupted_witness(&wallet_id, dead + 2)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    let parked = pending_slot(&manager, &wallet_id).unwrap();
    assert!(!parked.3, "no receipt, and the recovery did not invent one");

    // 4. A RECEIPT THAT IS NOT A WITNESS. The phone signs the dead anchor too
    //    late; the desktop refuses it, so nothing is written; the recovery has
    //    nothing to find and unlocking again changes nothing.
    let late = signed_receipt(&anchor, &mobile, dead + 3).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, late, dead + 4)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected
    );
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, dead + 5).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, dead + 6).status,
        OperationStatus::SignedAwaitingWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // AND THE REAL SIGNATURE IS STILL THE ONLY THING THAT MOVES IT.
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 7)
        .await
        .unwrap();
    let receipt = signed_receipt(&replacement, &mobile, dead + 8).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 9)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// AN OWNER WHO CHANGES NOTHING SEES NOTHING CHANGE.
///
/// The recovery only ever has work when a receipt is parked in the pending slot
/// with no archive against it, and the uninterrupted path never leaves one
/// there. Every step of the ordinary lifecycle is unlocked across here, and the
/// status after each unlock is the status the uninterrupted path produces.
#[tokio::test]
async fn unlocking_at_every_step_of_the_ordinary_path_changes_nothing() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(37_000).await;
    let mut now = 37_020;

    let relock = |manager: AgentWalletManager, at: u64| {
        drop(manager);
        let mut reopened = AgentWalletManager::open(root.path()).unwrap();
        reopened.unlock(&wallet_id, PASSPHRASE, at).unwrap();
        reopened
    };

    manager = relock(manager, now);
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, now).status,
        OperationStatus::SignedAwaitingWitness
    );

    for expected in [
        OperationStatus::SubmittedAwaitingFinalWitness,
        OperationStatus::ReconciliationRequired,
    ] {
        let anchor = manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 1)
            .await
            .unwrap();
        manager = relock(manager, now + 2);
        let receipt = signed_receipt(&anchor, &mobile, now + 3).await;
        assert_eq!(
            manager
                .apply_mobile_witness_and_broadcast(&wallet_id, receipt, now + 4)
                .await
                .unwrap()
                .status,
            expected
        );
        manager = relock(manager, now + 5);
        assert_eq!(
            operation_view(&mut manager, &wallet_id, &operation_id, now + 6).status,
            expected,
            "an unlock after a completed witness is a nothing"
        );
        assert!(pending_slot(&manager, &wallet_id).is_none());
        now += 20;
    }

    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, now)
        .tx_hash
        .unwrap();
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, now + 1)
        .unwrap();
    manager = relock(manager, now + 2);
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, now + 3).status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 4)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, now + 5).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, now + 6)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    manager = relock(manager, now + 7);
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, now + 8).status,
        OperationStatus::Committed
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "seven unlocks and exactly one submission"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, now + 9)
            .unwrap()
            .is_none()
    );
    drop(manager);
}

/// THE SWEEP, EXECUTED: THE OTHER PLACES A DURABLE WRITE HAS A SECOND STEP
/// AFTER IT.
///
/// `persist_event` is called at thirty-one places across the witness, rotation
/// and payment paths. At all but four of them it is the last act of its
/// function, so a crash after it is indistinguishable from a crash after the
/// call returned. The four that are not are:
///
///   1. `apply_mobile_witness_and_broadcast` - the two defects above;
///   2. `resume_payment`, which persists `BroadcastSubmitted` before the
///      network call ON PURPOSE, so a restart reconciles rather than
///      rebroadcasts. In the pilot every operation that reaches that status
///      also has a witness receipt parked against it, so the unlock recovery
///      finishes it - executed in
///      `the_crash_after_the_broadcast_and_before_the_archive_recovers_on_unlock`;
///   3. `approve_desktop_and_broadcast`, which journals `ApprovalGranted` and
///      then signs and broadcasts - this test;
///   4. `accept_witness_rotation_baseline`, which journals the baseline and
///      then revokes the old phone - the test below.
///
/// This one drives 3. A crash there leaves the payment `Approved`, which is a
/// pre-signing status: nothing was signed, nothing reached the node, and the
/// ordinary expiry sweep returns the reservation. That is an exit, and the
/// evidence for it is the reservation coming back rather than the reading.
#[tokio::test]
async fn the_crash_between_the_approval_and_the_signature_gives_the_reservation_back() {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 38_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 38_003);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        38_004,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("approval-crash", 38_300),
            38_005,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let reserved = created.reserved_units;
    assert!(reserved > HacUnits::ZERO);
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, 38_006)
        .unwrap();

    manager.crash_after_approval_granted = true;
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 38_007)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    drop(manager);

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 38_008).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 38_009).status,
        OperationStatus::Approved,
        "the approval is durable and the signature never happened"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "and nothing reached the node"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 38_010)
            .unwrap()
            .is_none(),
        "nothing is stranded on a phone here: no anchor was ever issued"
    );

    // THE EXIT. `Approved` is pre-signing, so the ordinary expiry sweep takes
    // it and the reserved funds come back. Nothing here is a new control.
    let after_expiry = 38_400;
    let next = manager
        .create_payment_intent(
            &authorization,
            payment_request("after-approval-crash", after_expiry + 300),
            after_expiry,
        )
        .await
        .unwrap();
    assert_eq!(next.status, OperationStatus::ApprovalRequested);
    // The interrupted approval is gone as a live payment: either swept to
    // `Cancelled` or pruned outright once terminal. Either way it holds nothing.
    let residue = manager
        .list_operations_admin(&wallet_id, after_expiry + 1)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == operation_id);
    match residue {
        None => {}
        Some(view) => {
            assert_eq!(
                view.status,
                OperationStatus::Cancelled,
                "the interrupted approval was swept by its own expiry"
            );
            assert_eq!(
                view.reserved_units,
                HacUnits::ZERO,
                "and the reservation came back"
            );
        }
    }
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// THE SWEEP, PART TWO: THE ROTATION BASELINE BOUNDARY - AND THE THIRD DEFECT
/// OF THE SAME FAMILY, FOUND BY THE SWEEP.
///
/// `accept_witness_rotation_baseline` journals the new phone's baseline receipt
/// and then, as a second write, revokes the old phone and advances the witness
/// epoch. A crash between them leaves the baseline durable, the phase still
/// `CandidatePairedRestricted`, and the old phone still registered.
///
/// The sweep expected that to be benign and it is not. Both rotation controls
/// go false at once - `cancel_witness_rotation` refuses because a baseline
/// exists, `retarget_witness_rotation` refuses because nothing has been revoked
/// yet - and the only remaining route, the candidate handset re-sending the
/// identical baseline, is re-verified against the rotation record and therefore
/// EXPIRES. After that the wallet can never issue another rollback anchor,
/// because `pending_rollback_anchor` refuses while a rotation is unfinished.
///
/// Same medicine: finish the second write on unlock from the baseline that is
/// already on disk.
#[tokio::test]
async fn the_crash_inside_the_rotation_baseline_recovers_on_unlock() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(39_000).await;
    let mut now =
        settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, 39_020).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation-baseline-crash".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            now,
        )
        .await
        .unwrap();
    let rotation_authorization =
        hpay_companion_protocol::SignedWitnessRotationAuthorization::sign(record.clone(), &mobile)
            .await
            .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, rotation_authorization, now + 1)
        .unwrap();
    super::witness::pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        now + 2,
    )
    .await;
    now += 20;
    let baseline = hpay_companion_protocol::WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        now,
    )
    .unwrap();
    let baseline =
        hpay_companion_protocol::SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
            .await
            .unwrap();

    // ---- THE CRASH, between the baseline write and the revoke.
    manager.crash_after_rotation_baseline = true;
    assert_eq!(
        manager
            .accept_witness_rotation_baseline(&wallet_id, baseline.clone(), now + 1)
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    drop(manager);

    // ---- FIRST, WHAT THE RESIDUE IS WITHOUT THE RECOVERY. This is the wallet
    // exactly as it stood before this change.
    let expired = record.expires_at + 1;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager
        .unlock_without_witness_recovery_for_test(&wallet_id, PASSPHRASE, expired)
        .unwrap();
    let controls = manager
        .witness_rotation_controls(&wallet_id, expired)
        .unwrap();
    assert!(
        !controls.cancellable,
        "cancel is refused: a baseline is on disk"
    );
    assert!(
        !controls.retargetable,
        "and re-target is refused: nothing has been revoked yet"
    );
    assert_eq!(
        manager
            .accept_witness_rotation_baseline(&wallet_id, baseline.clone(), expired)
            .unwrap_err(),
        AgentWalletError::RotationBaselineReceiptInvalid,
        "and the candidate re-sending the identical receipt no longer works \
         either: it is re-verified against a rotation record that has expired"
    );
    // AND THE WALLET CAN NEVER WITNESS ANOTHER PAYMENT.
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), expired)
            .await
            .unwrap_err(),
        AgentWalletError::InvalidOperationState,
        "this payment is settled; the block below is the general one"
    );
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let phase = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap()
        .witness_rotation
        .as_ref()
        .map(|rotation| rotation.phase);
    assert_eq!(
        phase,
        Some(hpay_companion_protocol::WitnessRotationPhase::CandidatePairedRestricted),
        "the rotation is parked one write short of done, with no control on it"
    );
    drop(manager);

    // ---- THE RECOVERY. One unlock, off the baseline already on disk, with the
    // rotation record long expired and the candidate handset never contacted.
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, expired + 1).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let rotation = state.witness_rotation.as_ref().unwrap();
    assert_eq!(
        rotation.phase,
        hpay_companion_protocol::WitnessRotationPhase::AwaitingCompletionAnchor,
        "the second write is finished from disk"
    );
    assert_eq!(
        state.rollback_witness.as_ref().unwrap().witness_epoch,
        record.new_witness_epoch,
        "the witness epoch advanced exactly as the uninterrupted call advances it"
    );
    assert!(
        state
            .companion_security
            .as_ref()
            .unwrap()
            .device_registry
            .records()
            .find(|device| device.device_id == record.old_mobile_device_id)
            .unwrap()
            .is_revoked(),
        "and the old phone is revoked, which is what the second write is for"
    );
    drop(state);

    // AND THE ROTATION FINISHES, WITH A REAL SIGNATURE FROM THE NEW PHONE.
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, expired + 2)
        .await
        .unwrap();
    let completion_receipt = signed_receipt(&completion, &candidate, expired + 3).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt, expired + 3)
        .unwrap();
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "a rotation moves no money, crashed or not"
    );

    // The old phone cannot witness for this wallet any more, and the new one
    // still has to sign for real. Neither is softened by the recovery.
    assert_eq!(
        manager
            .stranded_witness_recovery(&wallet_id, expired + 4)
            .unwrap()
            .map(|stranded| stranded.operation_id),
        None
    );
    drop(root);
}
