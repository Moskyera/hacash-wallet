//! EVERY PHASE IN WHICH A ROLLBACK ANCHOR IS ISSUED, DRIVEN TO EXPIRY.
//!
//! Four statuses issue an anchor - `SignedAwaitingWitness`,
//! `SubmittedAwaitingFinalWitness`, `BroadcastUncertain` and
//! `ReconciledAwaitingFinalWitness` - and three of them are past the node. This
//! file walks the whole witness lifecycle through the real public entry points -
//! real signing, real submission to the mock node, real receipts, real handset
//! state - and lets the anchor die unwitnessed in each phase that has one,
//! recording exactly what the owner is left holding and exactly which way out
//! they have.
//!
//! WHAT IS CLOSED HERE, BY EXECUTION:
//!   * re-issue is phase-generic: a dead anchor is replaced at the same chain
//!     position in every phase, and an old receipt never satisfies the
//!     replacement;
//!   * the owner-facing surface answers in every phase, and says where the
//!     money is rather than showing nothing;
//!   * a dead anchor can be dropped out of the single pending slot without
//!     touching the payment;
//!   * the residue re-issue cannot reach - a phone that durably accepted the
//!     dead anchor - is rescued PRE-BROADCAST by replacing the phone, keeping
//!     the payment rather than giving it up.
//!
//! WHAT IS NOT, AND IS EXECUTED RATHER THAN ASSUMED: that same residue
//! POST-SUBMIT. See
//! `a_phone_that_already_accepted_the_dead_post_submit_anchor_refuses_the_replacement`.
//!
//! Nothing here writes a status into state by hand.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    CompanionError, MobileWitnessState, RollbackOperationPhase, SoftwareDeviceIdentity,
    WitnessReconciliationStatus, WitnessRotationMode, WitnessRotationReason,
    WitnessSubmissionStatus,
};

use super::super::session::composite_registry;
use super::desktop_witness_flow::{
    desktop_approved_operation, payment_request, witness_pending_activity,
};
use super::fixtures::*;
use super::pilot_node::*;
use super::*;

/// The durable witness chain position, read straight out of authenticated
/// state. This is the thing the first-phase fix turned on: issuing an anchor
/// must not move it.
fn chain_position(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId) -> (u64, String) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    // Before the first anchor is ever asked for there is no witness state at
    // all. That is the zero position, not a missing one.
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

/// Whether an anchor is parked in the single pending slot, and for which
/// operation. A slot nothing can clear is the shape of every trap in this
/// family.
fn pending_slot(
    manager: &mut AgentWalletManager,
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

/// EXECUTION 1: THE FULL LIFECYCLE, EVERY ANCHOR IT ISSUES, IN ORDER.
///
/// One payment, from the agent's proposal to `Committed`. Every anchor is
/// captured as it is handed out, and the chain position is read before and
/// after every issue and every accepted receipt.
///
/// What this establishes, by execution:
///   * exactly which statuses issue an anchor, and with which phase;
///   * that ISSUING never advances `last_anchor_sequence` or `last_anchor_hash`
///     in ANY phase, not just the first - which is the fact the first-phase
///     re-issue fix rests on;
///   * that only an ACCEPTED RECEIPT advances them.
#[tokio::test]
async fn every_anchor_issuing_phase_is_executed_in_order() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(20_000).await;

    // ---- PHASE 1: SignedAwaitingWitness -> RollbackOperationPhase::SignedPreBroadcast
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 20_019).status,
        OperationStatus::SignedAwaitingWitness
    );
    let before = chain_position(&mut manager, &wallet_id);
    assert_eq!(
        before,
        (
            0,
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
        )
    );
    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 20_020)
        .await
        .unwrap();
    assert_eq!(
        anchor_one.anchor.operation_phase,
        RollbackOperationPhase::SignedPreBroadcast
    );
    assert_eq!(anchor_one.anchor.anchor_sequence, 1);
    assert_eq!(
        anchor_one
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::NotSubmitted
    );
    assert_eq!(
        chain_position(&mut manager, &wallet_id),
        before,
        "issuing the pre-broadcast anchor moves no chain position"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    let receipt_one = signed_receipt(&anchor_one, &mobile, 20_030).await;
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 20_040)
        .await
        .unwrap();
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    let after_one = chain_position(&mut manager, &wallet_id);
    assert_eq!(
        after_one.0, 1,
        "an accepted receipt is the only thing that advances the chain"
    );
    assert_eq!(
        after_one.1,
        anchor_one.anchor.canonical_sha256_hex().unwrap()
    );
    assert!(
        pending_slot(&mut manager, &wallet_id).is_none(),
        "the archived witness vacates the slot"
    );

    // ---- PHASE 2: SubmittedAwaitingFinalWitness -> RollbackOperationPhase::Submitted
    // THE MONEY HAS ALREADY GONE. submit_count is 1 from here on.
    let anchor_two = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 20_050)
        .await
        .unwrap();
    assert_eq!(
        anchor_two.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    assert_eq!(anchor_two.anchor.anchor_sequence, 2);
    assert_eq!(
        anchor_two.anchor.previous_anchor_hash, after_one.1,
        "the post-submit anchor chains onto the accepted pre-broadcast one"
    );
    assert_eq!(
        anchor_two
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::Submitted
    );
    assert_eq!(
        chain_position(&mut manager, &wallet_id),
        after_one,
        "issuing the POST-SUBMIT anchor moves no chain position either"
    );

    let receipt_two = signed_receipt(&anchor_two, &mobile, 20_060).await;
    let reconciling = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_two, 20_070)
        .await
        .unwrap();
    assert_eq!(reconciling.status, OperationStatus::ReconciliationRequired);
    let after_two = chain_position(&mut manager, &wallet_id);
    assert_eq!(after_two.0, 2);

    // ---- ReconciliationRequired issues NO anchor. It is not in
    // `awaits_mobile_witness`, and the desktop refuses to hand one out.
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 20_075)
            .await
            .unwrap_err(),
        AgentWalletError::InvalidOperationState,
        "a payment waiting on external reconciliation has no anchor to expire"
    );

    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 20_076)
        .tx_hash
        .unwrap();
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 20_080)
        .unwrap();
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );

    // ---- PHASE 3: ReconciledAwaitingFinalWitness -> RollbackOperationPhase::ReconciledFinal
    let anchor_three = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 20_090)
        .await
        .unwrap();
    assert_eq!(
        anchor_three.anchor.operation_phase,
        RollbackOperationPhase::ReconciledFinal
    );
    assert_eq!(anchor_three.anchor.anchor_sequence, 3);
    assert_eq!(
        anchor_three
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .reconciliation_status,
        WitnessReconciliationStatus::Confirmed
    );
    assert_eq!(
        chain_position(&mut manager, &wallet_id),
        after_two,
        "issuing the final anchor moves no chain position either"
    );

    let receipt_three = signed_receipt(&anchor_three, &mobile, 20_100).await;
    let committed = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_three, 20_110)
        .await
        .unwrap();
    assert_eq!(committed.status, OperationStatus::Committed);
    assert_eq!(chain_position(&mut manager, &wallet_id).0, 3);
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "three anchors, three receipts, exactly one submission"
    );
    drop(root);
}

/// EXECUTION 2: THE POST-SUBMIT ANCHOR DIES, WITH THE MONEY ALREADY GONE.
///
/// The transaction is on the network. `submit_count` is 1 before the anchor is
/// ever issued. This is the phase the last adversarial pass called
/// "no exit at all", and this test records exactly what the owner is left with.
#[tokio::test]
async fn the_post_submit_anchor_expiry_is_executed_with_the_payment_already_on_the_network() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(21_000).await;
    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 21_020)
        .await
        .unwrap();
    let receipt_one = signed_receipt(&anchor_one, &mobile, 21_030).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 21_040)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 21_050)
        .await
        .unwrap();
    let before = chain_position(&mut manager, &wallet_id);

    // THE ANCHOR DIES UNWITNESSED. The phone was away for the five minutes.
    let dead = post_submit.anchor.expires_at + 1;

    // WHAT THE OWNER STILL HAS. None of this may be lost by any recovery.
    let view = operation_view(&mut manager, &wallet_id, &operation_id, dead);
    assert_eq!(view.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert!(
        view.tx_hash.is_some(),
        "the hash that tells the owner what to look for on chain"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the payment happened; nothing about expiry may suggest otherwise"
    );

    // THE RECEIPT THE PHONE SIGNED TOO LATE IS NOT A WITNESS. Anchor expiry is
    // enforced on the receipt path, so a late receipt cannot rescue this.
    let late_receipt = signed_receipt(&post_submit, &mobile, dead).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, late_receipt, dead + 1)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected,
        "a receipt over a dead anchor is refused, exactly as pre-broadcast"
    );

    // THE PHONE CAN STILL FIND IT. The least-privilege disclosure covers every
    // status in `awaits_mobile_witness`, so a phone that reconnects after the
    // window is still handed this operation id to ask about.
    let snapshot = manager
        .companion_status_snapshot(&wallet_id, dead + 2)
        .await
        .unwrap();
    assert_eq!(
        witness_pending_activity(&snapshot),
        vec![(
            operation_id.to_string(),
            "submitted_awaiting_final_witness".to_owned()
        )],
        "the phone rediscovers the post-submit operation after the anchor died"
    );

    // THE OWNER-FACING RECOVERY SURFACE ANSWERS HERE. It used to look for
    // `SignedAwaitingWitness` and nothing else, so post-submit the desktop
    // showed the owner nothing at all while their money was already gone.
    let shown = manager
        .stranded_witness_recovery(&wallet_id, dead + 2)
        .unwrap()
        .unwrap();
    assert_eq!(shown.operation_id, operation_id.to_string());
    assert_eq!(shown.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert!(shown.submitted, "the owner is told the money moved");
    assert_eq!(
        shown.transaction_id,
        operation_view(&mut manager, &wallet_id, &operation_id, dead + 2).tx_hash,
        "and given the id to look it up with, not asked to take this on trust"
    );
    assert_eq!(shown.anchor_expires_at, Some(post_submit.anchor.expires_at));
    assert!(shown.retryable, "the phone is still the first thing to try");
    assert!(
        !shown.abandonable,
        "and giving up is not offered, because the money already moved"
    );
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, dead + 3)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent,
        "and abandoning is refused - correctly: the money already moved, and the refusal now says that instead of naming a state machine"
    );

    // THE WALLET IS WEDGED WHILE THIS SITS. One pending slot, one lifecycle.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("blocked-by-post-submit", dead + 400),
                dead + 4,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "no further payment can be proposed while this one is unresolved"
    );

    // THE PHONE-DRIVEN EXIT. `RecoverPendingWitness` runs exactly this.
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 5)
        .await
        .unwrap();
    assert_eq!(
        replacement.anchor.anchor_sequence, post_submit.anchor.anchor_sequence,
        "a post-submit replacement consumes no chain position"
    );
    assert_eq!(
        replacement.anchor.previous_anchor_hash, post_submit.anchor.previous_anchor_hash,
        "and does not re-link the chain"
    );
    assert_ne!(replacement.anchor.anchor_id, post_submit.anchor.anchor_id);
    assert_eq!(
        replacement.anchor.operation_phase,
        RollbackOperationPhase::Submitted,
        "the replacement is still the POST-SUBMIT phase, not a rewind to pre-broadcast"
    );
    assert_eq!(
        replacement
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::Submitted,
        "the replacement still says the payment was submitted"
    );
    assert_eq!(
        replacement
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .transaction_id,
        view.tx_hash,
        "and still names the exact transaction the owner would look for"
    );
    assert_eq!(chain_position(&mut manager, &wallet_id), before);
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "re-issuing a post-submit anchor submits nothing a second time"
    );

    // THE OLD RECEIPT STILL CANNOT REPLAY AGAINST THE NEW ANCHOR.
    let stale = signed_receipt(&post_submit, &mobile, post_submit.anchor.expires_at - 1).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, stale, dead + 6)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected
    );

    // AND THE PAYMENT FINISHES, WITH THE SUBMISSION RECORD INTACT.
    let receipt = signed_receipt(&replacement, &mobile, dead + 7).await;
    let resolved = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 8)
        .await
        .unwrap();
    assert_eq!(resolved.status, OperationStatus::ReconciliationRequired);
    assert_eq!(resolved.tx_hash, view.tx_hash);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 3: THE FINAL, POST-RECONCILIATION ANCHOR DIES.
///
/// The transaction is not merely submitted here, it is confirmed. The owner's
/// money is gone and the chain says so.
#[tokio::test]
async fn the_reconciled_final_anchor_expiry_is_executed() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(22_000).await;
    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 22_020)
        .await
        .unwrap();
    let receipt_one = signed_receipt(&anchor_one, &mobile, 22_030).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 22_040)
        .await
        .unwrap();
    let anchor_two = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 22_050)
        .await
        .unwrap();
    let receipt_two = signed_receipt(&anchor_two, &mobile, 22_060).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_two, 22_070)
        .await
        .unwrap();
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 22_075)
        .tx_hash
        .unwrap();
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 22_080)
        .unwrap();

    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 22_090)
        .await
        .unwrap();
    let before = chain_position(&mut manager, &wallet_id);
    let dead = final_anchor.anchor.expires_at + 1;

    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, dead).status,
        OperationStatus::ReconciledAwaitingFinalWitness,
        "the payment is confirmed on chain and stuck one signature short of Committed"
    );
    let snapshot = manager
        .companion_status_snapshot(&wallet_id, dead)
        .await
        .unwrap();
    assert_eq!(
        witness_pending_activity(&snapshot),
        vec![(
            operation_id.to_string(),
            "reconciled_awaiting_final_witness".to_owned()
        )],
        "the phone rediscovers the confirmed-but-unwitnessed operation"
    );
    let shown = manager
        .stranded_witness_recovery(&wallet_id, dead)
        .unwrap()
        .unwrap();
    assert_eq!(
        shown.status,
        OperationStatus::ReconciledAwaitingFinalWitness,
        "the owner-facing surface answers in this phase too"
    );
    assert!(shown.submitted);
    assert!(
        shown.transaction_id.is_some(),
        "confirmed on chain, and the owner is given the id that proves it"
    );
    assert!(!shown.abandonable);
    assert!(
        shown.anchor_releasable,
        "the anchor is dead, so it can be dropped out of the way"
    );
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, dead)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent
    );

    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 1)
        .await
        .unwrap();
    assert_eq!(
        replacement.anchor.anchor_sequence,
        final_anchor.anchor.anchor_sequence
    );
    assert_eq!(
        replacement.anchor.previous_anchor_hash,
        final_anchor.anchor.previous_anchor_hash
    );
    assert_eq!(
        replacement.anchor.operation_phase,
        RollbackOperationPhase::ReconciledFinal
    );
    assert_eq!(
        replacement
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .reconciliation_status,
        WitnessReconciliationStatus::Confirmed,
        "the replacement still records that the chain confirmed this transaction"
    );
    assert_eq!(chain_position(&mut manager, &wallet_id), before);

    let receipt = signed_receipt(&replacement, &mobile, dead + 2).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 3)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 4: THE ANCHOR ISSUED OVER A SUBMISSION NOBODY CAN VOUCH FOR.
///
/// The node acknowledged a submission with the wrong transaction hash, so the
/// wallet cannot say whether the bytes it signed are on the network. The
/// operation lands in `BroadcastUncertain`, which also issues an anchor, which
/// can also expire.
#[tokio::test]
async fn the_broadcast_uncertain_anchor_expiry_is_executed() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(23_000).await;
    node.submit_hash_mismatch.store(true, Ordering::SeqCst);

    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 23_020)
        .await
        .unwrap();
    let receipt_one = signed_receipt(&anchor_one, &mobile, 23_030).await;
    let uncertain = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 23_040)
        .await
        .unwrap();
    assert_eq!(
        uncertain.status,
        OperationStatus::BroadcastUncertain,
        "the bytes went out and the acknowledgement did not match them"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "uncertain means submitted-and-unverifiable, not not-submitted"
    );

    let anchor_two = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 23_050)
        .await
        .unwrap();
    assert_eq!(
        anchor_two.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    assert_eq!(
        anchor_two
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::Uncertain
    );
    let before = chain_position(&mut manager, &wallet_id);
    let dead = anchor_two.anchor.expires_at + 1;

    let snapshot = manager
        .companion_status_snapshot(&wallet_id, dead)
        .await
        .unwrap();
    assert_eq!(
        witness_pending_activity(&snapshot),
        vec![(operation_id.to_string(), "broadcast_uncertain".to_owned())],
        "the phone rediscovers the uncertain submission"
    );
    let shown = manager
        .stranded_witness_recovery(&wallet_id, dead)
        .unwrap()
        .unwrap();
    assert_eq!(shown.status, OperationStatus::BroadcastUncertain);
    assert!(
        shown.submitted,
        "the bytes went out; an unverifiable acknowledgement is not a non-payment"
    );
    assert!(!shown.abandonable);
    assert!(shown.anchor_releasable);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, dead)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent,
        "abandoning an uncertain submission would be a lie about where the money is"
    );

    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 1)
        .await
        .unwrap();
    assert_eq!(
        replacement
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::Uncertain,
        "the replacement still says the submission is unverifiable"
    );
    assert_eq!(
        replacement.anchor.anchor_sequence,
        anchor_two.anchor.anchor_sequence
    );
    assert_eq!(chain_position(&mut manager, &wallet_id), before);

    let receipt = signed_receipt(&replacement, &mobile, dead + 2).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 3)
            .await
            .unwrap()
            .status,
        OperationStatus::ReconciliationRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 5: THE RESIDUE RE-ISSUE CANNOT RESCUE, POST-SUBMIT.
///
/// If the phone durably accepted the anchor before the exchange broke, its own
/// monotonic witness state has already consumed that sequence number. The
/// replacement the desktop hands out sits at the SAME sequence, so this exact
/// phone refuses it - correctly, that is the anti-rollback rule.
///
/// Pre-broadcast the owner's exit is `abandon_stranded_witness_operation`, and
/// it costs no money. Post-submit that exit does not exist and must not: the
/// money already moved. This test executes the refusal so the gap is a fact and
/// not a reading.
#[tokio::test]
async fn a_phone_that_already_accepted_the_dead_post_submit_anchor_refuses_the_replacement() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(24_000).await;

    let registry = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        let signer = manager
            .session(&wallet_id)
            .unwrap()
            .desktop_companion_signer
            .clone();
        composite_registry(&state, &signer, 24_010).unwrap()
    };
    let desktop_device_id = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        hpay_companion_protocol::DeviceId::parse(state.primary_signing_device_id.clone()).unwrap()
    };

    // The phone's own durable anti-rollback state, the real type the handset
    // persists.
    let mut phone = MobileWitnessState::new(
        wallet_id.to_string(),
        desktop_device_id,
        mobile.device_id().clone(),
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND.to_owned(),
        TESTNET_ANCHOR.to_owned(),
        1,
        1,
        1,
    )
    .unwrap();

    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 24_020)
        .await
        .unwrap();
    phone.accept_anchor(&anchor_one, &registry, 24_021).unwrap();
    let receipt_one = signed_receipt(&anchor_one, &mobile, 24_022).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 24_030)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // The post-submit anchor reaches the phone, the phone durably accepts it,
    // and then the connection dies before the receipt gets back.
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 24_040)
        .await
        .unwrap();
    phone
        .accept_anchor(&post_submit, &registry, 24_041)
        .unwrap();
    assert_eq!(
        phone.last_anchor_sequence,
        post_submit.anchor.anchor_sequence
    );

    let dead = post_submit.anchor.expires_at + 1;
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead)
        .await
        .unwrap();

    // THE REFUSAL. The desktop's replacement is honest and the phone is right
    // to refuse it. Nobody is misbehaving and the payment cannot finish.
    assert_eq!(
        phone
            .accept_anchor(&replacement, &registry, dead + 1)
            .unwrap_err(),
        CompanionError::RollbackDetected,
        "the phone has consumed that sequence; the replacement sits on it"
    );

    // And the receipt it already holds is no use either: it is bound to an
    // anchor id that is now dead, and expiry is checked on the receipt path.
    let held = phone.last_receipt.clone().unwrap();
    let signed = hpay_companion_protocol::SignedWitnessReceipt::sign(held, &mobile)
        .await
        .unwrap();
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, signed, dead + 2)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected
    );

    // WHERE THE OWNER STANDS: a real payment on the network, a phone that can
    // never sign for it again, and a wallet that will take no further payment.
    let view = operation_view(&mut manager, &wallet_id, &operation_id, dead + 3);
    assert_eq!(view.status, OperationStatus::SubmittedAwaitingFinalWitness);
    let tx_hash = view.tx_hash.clone().unwrap();
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-post-submit-residue", dead + 400),
                dead + 4,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );

    // AND WHAT THE DESKTOP SHOWS THEM. Not nothing, which is what it used to
    // show: the payment, the fact that the money moved, and the id to check it
    // with. The pre-broadcast exit is refused and is not offered, because taking
    // it would assert the payment did not happen when it did.
    //
    // The replacement anchor handed out above is still live for its five
    // minutes, and nothing may be dropped or rotated while it is: this desktop
    // cannot know the phone will refuse it. So the escape opens only once that
    // window has run out too, exactly like every other control in this family.
    assert!(
        !manager
            .stranded_witness_recovery(&wallet_id, dead + 5)
            .unwrap()
            .unwrap()
            .anchor_releasable,
        "nothing races a live anchor, not even a replacement nobody can use"
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, dead + 5)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable
    );
    let clear = replacement.anchor.expires_at + 1;
    let shown = manager
        .stranded_witness_recovery(&wallet_id, clear + 5)
        .unwrap()
        .unwrap();
    assert_eq!(shown.operation_id, operation_id.to_string());
    assert_eq!(shown.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert!(shown.submitted);
    assert_eq!(shown.transaction_id.as_deref(), Some(tx_hash.as_str()));
    assert!(!shown.abandonable);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, clear + 5)
            .unwrap_err(),
        AgentWalletError::StrandedPaymentAlreadySent,
        "the pre-broadcast exit is refused, and must be: the money moved"
    );
    assert!(shown.anchor_releasable, "the dead anchor can be dropped");
    assert!(
        !shown.phone_replacement_unblocked,
        "but not while it still occupies the one pending slot"
    );

    // ---- STEP ONE OF THE EXIT WORKS HERE TOO: DROP THE DEAD ANCHOR. It
    // changes nothing about the payment, and the returned view is the proof.
    let released = manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, clear + 6)
        .unwrap();
    assert_eq!(
        released.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(released.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert_eq!(released.reserved_units, view.reserved_units);
    assert_eq!(released.total_debit_units, view.total_debit_units);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    assert!(pending_slot(&mut manager, &wallet_id).is_none());
    assert_eq!(
        chain_position(&mut manager, &wallet_id),
        (1, anchor_one.anchor.canonical_sha256_hex().unwrap()),
        "releasing consumes no chain position"
    );

    // ---- AND STEP TWO DOES NOT. THIS IS THE RESIDUE, EXECUTED.
    //
    // Replacing the phone is what rescues the same dead end pre-broadcast, and
    // it is refused here. Not as an oversight - as the only honest answer. A
    // rotated-in phone baselines with no transaction state at all, because
    // `WitnessRotationRecord` carries a chain position and not a transaction,
    // and a phone with no transaction state refuses every anchor whose phase is
    // not `SignedPreBroadcast`.
    //
    // That refusal is the rule that stops a desktop handing a freshly paired
    // handset a "this was already submitted, sign here" claim it has no way to
    // check, so it must not be weakened to make this case work. Executed here
    // against a real `MobileWitnessState` with no transaction state - which is
    // exactly what any replacement phone would be:
    let mut replacement_phone = MobileWitnessState::new(
        wallet_id.to_string(),
        anchor_one.anchor.desktop_device_id.clone(),
        mobile.device_id().clone(),
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND.to_owned(),
        TESTNET_ANCHOR.to_owned(),
        1,
        1,
        1,
    )
    .unwrap();
    let post_submit_again = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), clear + 7)
        .await
        .unwrap();
    assert_eq!(
        post_submit_again.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    assert_eq!(
        replacement_phone
            .accept_anchor(&post_submit_again, &registry, clear + 8)
            .unwrap_err(),
        CompanionError::AnchorChainMismatch,
        "no phone that has not seen this payment pre-broadcast can witness it now"
    );

    // So the desktop does not offer the replacement here, and the core refuses
    // it, rather than burning the owner's old phone for a rotation that would
    // leave the payment exactly as stuck.
    let after_release = manager
        .stranded_witness_recovery(&wallet_id, clear + 9)
        .unwrap()
        .unwrap();
    assert!(after_release.submitted);
    assert_eq!(
        after_release.transaction_id.as_deref(),
        Some(tx_hash.as_str()),
        "and it keeps telling the owner exactly where to look for their money"
    );
    assert!(!after_release.abandonable);
    assert!(!after_release.phone_replacement_unblocked);
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation-after-post-submit-residue".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                clear + 10,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );

    // WHAT IS TRUE THROUGHOUT: no money moved, nothing was marked witnessed,
    // and the record that the payment WAS submitted is intact.
    let end = operation_view(&mut manager, &wallet_id, &operation_id, clear + 11);
    assert_eq!(end.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(end.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 5b: THE SAME DEAD END BEFORE THE BROADCAST, RESCUED IN FULL.
///
/// Same residue - a phone that durably accepted the anchor and then went away,
/// so no honest replacement can ever be signed by it - but caught before the
/// payment reached the node. The exit is the same two steps, and it does
/// something the old exit could not: the payment SURVIVES. Abandoning gives the
/// payment up; replacing the phone keeps it and lets the new handset witness it
/// through to `Committed`.
///
/// Executed end to end, with real handset state on both phones: release the
/// dead anchor, replace the phone, and a real signature from the NEW paired
/// phone over a real anchor is still the only thing that puts anything on the
/// network.
#[tokio::test]
async fn a_pre_broadcast_dead_end_is_rescued_by_replacing_the_phone_and_keeps_the_payment() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(26_000).await;

    let registry = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        let signer = manager
            .session(&wallet_id)
            .unwrap()
            .desktop_companion_signer
            .clone();
        composite_registry(&state, &signer, 26_010).unwrap()
    };
    let desktop_device_id = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        hpay_companion_protocol::DeviceId::parse(state.primary_signing_device_id.clone()).unwrap()
    };
    let mut phone = MobileWitnessState::new(
        wallet_id.to_string(),
        desktop_device_id,
        mobile.device_id().clone(),
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND.to_owned(),
        TESTNET_ANCHOR.to_owned(),
        1,
        1,
        1,
    )
    .unwrap();

    // The phone accepts the anchor durably and then the connection dies.
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 26_020)
        .await
        .unwrap();
    phone.accept_anchor(&anchor, &registry, 26_021).unwrap();
    let dead = anchor.anchor.expires_at + 1;

    // Re-issue is offered first, in this phase as in every other, and it is
    // right to offer it: only THIS phone cannot take it.
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead)
        .await
        .unwrap();
    assert_eq!(
        replacement.anchor.anchor_sequence,
        anchor.anchor.anchor_sequence
    );
    assert_eq!(
        phone
            .accept_anchor(&replacement, &registry, dead + 1)
            .unwrap_err(),
        CompanionError::RollbackDetected
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    let clear = replacement.anchor.expires_at + 1;
    let shown = manager
        .stranded_witness_recovery(&wallet_id, clear)
        .unwrap()
        .unwrap();
    assert!(
        !shown.submitted,
        "nothing has reached the network, and the desktop says so"
    );
    assert!(
        shown.abandonable,
        "giving the payment up is honest here, and stays on offer"
    );
    assert!(shown.anchor_releasable);

    // ---- STEP ONE: DROP THE DEAD ANCHOR, KEEPING THE PAYMENT.
    let released = manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, clear + 1)
        .unwrap();
    assert_eq!(released.status, OperationStatus::SignedAwaitingWitness);
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, clear + 2)
            .unwrap()
            .unwrap()
            .phone_replacement_unblocked
    );

    // ---- STEP TWO: REPLACE THE PHONE, WITHOUT ABANDONING ANYTHING.
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation-after-pre-broadcast-residue".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            clear + 3,
        )
        .await
        .unwrap();
    let rotation_authorization =
        hpay_companion_protocol::SignedWitnessRotationAuthorization::sign(record.clone(), &mobile)
            .await
            .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, rotation_authorization, clear + 4)
        .unwrap();
    super::witness::pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        clear + 5,
    )
    .await;
    let baseline = hpay_companion_protocol::WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        clear + 15,
    )
    .unwrap();
    let baseline =
        hpay_companion_protocol::SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
            .await
            .unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, baseline.clone(), clear + 15)
        .unwrap();

    // NOTHING REACHED THE NETWORK ANYWHERE IN THE ESCAPE.
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, clear + 16).status,
        OperationStatus::SignedAwaitingWitness,
        "the payment is kept, not cancelled, and it is still unwitnessed"
    );

    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, clear + 16)
        .await
        .unwrap();
    let completion_receipt = signed_receipt(&completion, &candidate, clear + 17).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt, clear + 17)
        .unwrap();

    // ---- STEP THREE: THE NEW PHONE WITNESSES THE PAYMENT THE OLD ONE COULD
    // NOT. Real handset state, built from the real rotation baseline.
    let registry = {
        let (state_master, journal_key) = keys(&manager, &wallet_id);
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        let signer = manager
            .session(&wallet_id)
            .unwrap()
            .desktop_companion_signer
            .clone();
        composite_registry(&state, &signer, clear + 18).unwrap()
    };
    let mut new_phone =
        MobileWitnessState::from_rotation_baseline(&record, &baseline, &registry, clear + 18)
            .unwrap();
    new_phone
        .accept_anchor(&completion, &registry, clear + 19)
        .unwrap();
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    let fresh = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, candidate.device_id(), clear + 20)
        .await
        .unwrap();
    assert_eq!(
        fresh.anchor.operation_phase,
        RollbackOperationPhase::SignedPreBroadcast
    );
    assert_eq!(
        fresh
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .submission_status,
        WitnessSubmissionStatus::NotSubmitted,
        "and it still says, truthfully, that nothing was submitted"
    );

    // THE OLD PHONE'S RECEIPT PAYS NOBODY, before or after the replacement.
    let stale = hpay_companion_protocol::SignedWitnessReceipt::sign(
        phone.last_receipt.clone().unwrap(),
        &mobile,
    )
    .await
    .unwrap();
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, stale, clear + 21)
            .await
            .is_err()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // A REAL SIGNATURE FROM THE NEWLY PAIRED PHONE IS WHAT SUBMITS IT.
    let receipt = new_phone
        .accept_anchor(&fresh, &registry, clear + 22)
        .unwrap();
    let receipt = hpay_companion_protocol::SignedWitnessReceipt::sign(receipt, &candidate)
        .await
        .unwrap();
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, clear + 23)
        .await
        .unwrap();
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "exactly one submission, and only after a real phone signature"
    );

    // AND ON TO Committed THROUGH THE ORDINARY PATH, WITH THE NEW PHONE.
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, candidate.device_id(), clear + 24)
        .await
        .unwrap();
    let receipt = new_phone
        .accept_anchor(&post_submit, &registry, clear + 25)
        .unwrap();
    let receipt = hpay_companion_protocol::SignedWitnessReceipt::sign(receipt, &candidate)
        .await
        .unwrap();
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, clear + 26)
            .await
            .unwrap()
            .status,
        OperationStatus::ReconciliationRequired
    );
    manager
        .confirm_broadcast(
            &wallet_id,
            &operation_id,
            submitted.tx_hash.as_deref().unwrap(),
            clear + 27,
        )
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, candidate.device_id(), clear + 28)
        .await
        .unwrap();
    let receipt = new_phone
        .accept_anchor(&final_anchor, &registry, clear + 29)
        .unwrap();
    let receipt = hpay_companion_protocol::SignedWitnessReceipt::sign(receipt, &candidate)
        .await
        .unwrap();
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, clear + 30)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, clear + 31)
            .unwrap()
            .is_none(),
        "and nothing is stranded any more"
    );
    drop(root);
}

/// EXECUTION 6: THE POST-SUBMIT TRAP SURVIVES A RESTART, AND SO MUST THE EXIT.
///
/// The pending slot is durable, so a post-submit anchor that died is still
/// sitting there after a lock, an unlock and a process restart - and the money
/// is still gone. A phone that comes back a year later must still be able to
/// finish the witness, and the record that the payment was submitted must read
/// back exactly as it was written.
#[tokio::test]
async fn the_post_submit_exit_survives_a_restart_a_year_later() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(25_000).await;
    let anchor_one = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 25_020)
        .await
        .unwrap();
    let receipt_one = signed_receipt(&anchor_one, &mobile, 25_030).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt_one, 25_040)
        .await
        .unwrap();
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 25_050)
        .await
        .unwrap();
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 25_051)
        .tx_hash
        .unwrap();

    let much_later = post_submit.anchor.expires_at + 365 * 24 * 60 * 60;
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();

    // THE RECORD THAT THE MONEY MOVED IS INTACT ACROSS THE RESTART.
    let view = operation_view(&mut manager, &wallet_id, &operation_id, much_later);
    assert_eq!(view.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(view.tx_hash.as_deref(), Some(tx_hash.as_str()));
    let parked = pending_slot(&mut manager, &wallet_id).unwrap();
    assert_eq!(parked.0, operation_id.to_string());
    assert_eq!(parked.1, post_submit.anchor.anchor_id);
    assert!(!parked.3, "no receipt ever arrived for it");

    let replacement = manager
        .pending_rollback_anchor(
            &wallet_id,
            &operation_id,
            mobile.device_id(),
            much_later + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        replacement.anchor.anchor_sequence,
        post_submit.anchor.anchor_sequence
    );
    assert_eq!(
        replacement.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    assert_eq!(
        replacement
            .anchor
            .transaction_state
            .as_ref()
            .unwrap()
            .transaction_id
            .as_deref(),
        Some(tx_hash.as_str())
    );
    let receipt = signed_receipt(&replacement, &mobile, much_later + 2).await;
    let resolved = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, much_later + 3)
        .await
        .unwrap();
    assert_eq!(resolved.status, OperationStatus::ReconciliationRequired);
    assert_eq!(resolved.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// EXECUTION 7: PROVE-THE-TEST ON THE RELEASE ITSELF.
///
/// `release_dead_witness_anchor` is the step that unwedges the single pending
/// slot without touching the payment. Everything it is allowed to do rests on
/// its refusals, so each one is executed: it never races a phone that may be
/// signing, it never discards a witness that really arrived, it never reaches
/// past the operation it was asked about, and it never moves the payment.
#[tokio::test]
async fn the_dead_anchor_release_refuses_everything_it_must() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(27_000).await;

    // NOTHING TO RELEASE. No anchor was ever handed out.
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, 27_019)
            .unwrap_err(),
        AgentWalletError::WitnessConfirmationWindowNotFound,
        "and it says there is no window rather than asking for a witness receipt"
    );

    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 27_020)
        .await
        .unwrap();

    // A LIVE ANCHOR IS NEVER DROPPED. The phone may be signing it this second,
    // and the desktop has no way to know that it is not.
    assert!(
        !manager
            .stranded_witness_recovery(&wallet_id, 27_021)
            .unwrap()
            .unwrap()
            .anchor_releasable
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, 27_021)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, anchor.anchor.expires_at - 1)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable,
        "refused on the last instant the anchor is still live, and the boundary \
         is the protocol's own: `expires_at <= now` is expired"
    );

    // AN UNKNOWN OPERATION IS NOT A WAY IN.
    let stranger = OperationId::new();
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &stranger, anchor.anchor.expires_at + 1)
            .unwrap_err(),
        AgentWalletError::OperationNotFound
    );

    // ONCE DEAD IT GOES, AND THE PAYMENT DOES NOT MOVE.
    let dead = anchor.anchor.expires_at + 1;
    let before = operation_view(&mut manager, &wallet_id, &operation_id, dead);
    let released = manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, dead)
        .unwrap();
    assert_eq!(released, before, "the operation is returned untouched");
    assert!(pending_slot(&mut manager, &wallet_id).is_none());
    assert_eq!(
        chain_position(&mut manager, &wallet_id),
        (
            0,
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
        ),
        "and no chain position was consumed by issuing it or by dropping it"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // IT IS NOT A SECOND ANCHOR. The receipt the phone signed for the anchor
    // that was dropped still pays nobody.
    let genuine = signed_receipt(&anchor, &mobile, anchor.anchor.created_at + 1).await;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, genuine, dead + 1)
            .await
            .is_err()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // AND A REAL WITNESS IS NEVER DISCARDED BY IT. Once a receipt sits against
    // the pending anchor the lifecycle owns it, expired or not.
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 2)
        .await
        .unwrap();
    assert_eq!(
        replacement.anchor.anchor_sequence, anchor.anchor.anchor_sequence,
        "the replacement still sits at the same chain position after a release"
    );
    let receipt = signed_receipt(&replacement, &mobile, dead + 3).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 4)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // Post-submit, with no anchor outstanding at all, there is nothing to
    // release and the refusal says so rather than inventing one.
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, dead + 5)
            .unwrap_err(),
        AgentWalletError::WitnessConfirmationWindowNotFound
    );

    // AND A COMMITTED PAYMENT IS NOT A WITNESS CANDIDATE AT ALL.
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead + 6)
        .await
        .unwrap();
    let receipt = signed_receipt(&post_submit, &mobile, dead + 7).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead + 8)
        .await
        .unwrap();
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, dead + 9)
            .unwrap_err(),
        AgentWalletError::NotWaitingOnWitnessPhone,
        "ReconciliationRequired awaits no phone, so it has no anchor to release"
    );
    drop(root);
}
