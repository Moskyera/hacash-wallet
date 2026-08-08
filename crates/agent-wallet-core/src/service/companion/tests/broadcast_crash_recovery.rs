//! THE TWO WINDOWS OF THE SAME FAMILY THE FIRST SWEEP READ PAST.
//!
//! The first sweep enumerated `persist_event` and named four boundaries where a
//! durable write has a second step after it. It missed two, and it dismissed one
//! of the four on a claim that does not survive being run:
//!
//!   1. `resume_payment` persists `BroadcastSubmitted` BEFORE it posts the
//!      signed bytes to the node, deliberately, so a restart may not assume the
//!      transaction went out - and may not assume it did not. The sweep said the
//!      unlock recovery "finishes it". It does, by promoting the payment to
//!      `SubmittedAwaitingFinalWitness`, which asserts the money moved. Executed
//!      below, with the node's own submission counter at zero, that assertion is
//!      made on a payment the network never saw, and every control the owner has
//!      then refuses at once.
//!
//!   2. `apply_mobile_approval_and_broadcast` journals the phone's approval AND
//!      the replay-guard snapshot that consumes it, in one durable write, and
//!      then signs. The sweep listed the desktop twin of this boundary and never
//!      mentioned the phone one. It is the worse of the two: a crash there
//!      leaves the payment durably `Approved`, and the owner cannot repeat the
//!      press, because the identical signed decision is now refused for ever.
//!
//! Nothing here writes a status into state by hand and nothing here fakes a
//! receipt or a decision. Each crash is injected at the exact instant
//! `persist_event` returns, the manager is dropped, and the wallet is reopened
//! from the same directory - so what the recovery reads is the real on-disk
//! residue of a real interrupted call.
//!
//! The last three tests execute the three remaining boundaries the sweep did not
//! name, so that "benign" is a fact this suite runs rather than a claim it
//! inherits from a report.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    ApprovalDecision, DeviceRole, RollbackOperationPhase, SoftwareDeviceIdentity,
    WitnessReconciliationStatus, WitnessRotationMode, WitnessRotationReason,
    WitnessSubmissionStatus,
};

use super::desktop_witness_flow::{
    desktop_approved_operation, pair_desktop_agent, payment_request,
};
use super::fixtures::*;
use super::pilot_node::*;
use super::*;

fn operation_view(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    now: u64,
) -> Option<PaymentOperationView> {
    manager
        .list_operations_admin(wallet_id, now)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == *operation_id)
}

fn pending_slot(manager: &AgentWalletManager, wallet_id: &AgentWalletId) -> Option<(String, bool)> {
    let (state_master, journal_key) = keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .rollback_witness
        .as_ref()
        .and_then(|witness| witness.pending.as_ref())
        .map(|pending| (pending.operation_id.clone(), pending.receipt.is_some()))
}

/// A witness phone that may also approve payments, which the mobile-approval
/// path needs and `register_witness_mobile` deliberately does not grant.
fn register_approving_witness_mobile(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) {
    let record = mobile
        .public_record(
            wallet_id.as_str(),
            BTreeSet::from([
                DevicePermission::WitnessRollbackAnchor,
                DevicePermission::ApprovePayment,
                DevicePermission::RejectPayment,
            ]),
            now,
        )
        .unwrap();
    manager
        .register_verified_companion_device(wallet_id, record, now)
        .unwrap();
}

/// Drives a fresh wallet to the exact instant before the node call, through the
/// real path - agent intent, desktop approval, real signing, real anchor, real
/// phone signature - and then kills the process one instruction after
/// `BroadcastSubmitted` is durable.
///
/// The node's own counter is the evidence that nothing was sent.
async fn crash_between_the_broadcast_write_and_the_node(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    MockPilotNode,
    crate::service::AgentAuthorization,
    String,
) {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(now).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 20)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, now + 30).await;
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, now + 35)
        .unwrap()
        .tx_hash
        .unwrap();

    manager.crash_after_broadcast_persisted = true;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, now + 40)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "the injected crash returns without running anything below the boundary"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "the process died with the signed bytes still inside it: the network \
         never saw this transaction"
    );
    drop(manager);
    (
        root,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        tx_hash,
    )
}

/// EXECUTION 1: THE FIRST NEW DEFECT, AND THE ONE THE SWEEP DISMISSED.
///
/// The crash lands between the durable `BroadcastSubmitted` and the post to the
/// node. On disk that is byte-for-byte what a crash one instant AFTER a
/// successful post leaves, and it must be - persisting first is exactly what
/// buys the wallet the right not to guess.
///
/// The unlock recovery was guessing. It archived the parked receipt and, in
/// doing so, promoted the payment to `SubmittedAwaitingFinalWitness`: the money
/// moved, here is the transaction id, go and look. This test pins the honest
/// answer instead.
#[tokio::test]
async fn the_crash_between_the_broadcast_write_and_the_node_is_reconciled_not_asserted() {
    let (root, wallet_id, mobile, operation_id, node, _authorization, tx_hash) =
        crash_between_the_broadcast_write_and_the_node(60_000).await;

    // ---- THE OWNER REOPENS THE WALLET. Nothing is in memory.
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 60_050).unwrap();

    let recovered = operation_view(&mut manager, &wallet_id, &operation_id, 60_051).unwrap();
    assert_eq!(
        recovered.status,
        OperationStatus::BroadcastUncertain,
        "the one statement this wallet can support about a crash inside the \
         submission window is that the outcome is unknown - never that the \
         payment was submitted"
    );
    assert_eq!(
        recovered.tx_hash.as_deref(),
        Some(tx_hash.as_str()),
        "and the record of which transaction it is, is unchanged"
    );
    assert!(
        pending_slot(&manager, &wallet_id).is_none(),
        "the receipt that nothing could clear is archived, from disk"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "recovering an archive rebroadcasts nothing"
    );

    // ---- AND THE DESKTOP TELLS THE OWNER THE TRUTH. `BroadcastUncertain` is
    // in `awaits_mobile_witness`, so the surface answers at all - and it says
    // the money may have moved, which is why nothing here is abandonable.
    let shown = manager
        .stranded_witness_recovery(&wallet_id, 60_052)
        .unwrap()
        .unwrap();
    assert_eq!(shown.status, OperationStatus::BroadcastUncertain);
    assert!(
        shown.submitted,
        "an unknown outcome is treated as money that may have moved, and is \
         never handed back"
    );
    assert!(!shown.abandonable);
    assert_eq!(shown.transaction_id.as_deref(), Some(tx_hash.as_str()));

    // ---- AND THE PHONE IS TOLD THE SAME THING. The post-submit anchor carries
    // `Uncertain`, not `Submitted`, so the handset is never asked to counter-
    // sign a claim the desktop cannot make.
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 60_060)
        .await
        .unwrap();
    assert_eq!(
        post_submit.anchor.operation_phase,
        RollbackOperationPhase::Submitted
    );
    let transaction_state = post_submit.anchor.transaction_state.as_ref().unwrap();
    assert_eq!(
        transaction_state.submission_status,
        WitnessSubmissionStatus::Uncertain,
        "the phone is told the submission is uncertain, because it is"
    );
    assert_eq!(
        transaction_state.reconciliation_status,
        WitnessReconciliationStatus::Unknown
    );

    // ---- AND THE LIFECYCLE RUNS ON, THROUGH THE ONE DOOR THAT IS CORRECT FOR
    // AN UNKNOWN OUTCOME: an external reconciliation of the exact hash.
    let receipt = signed_receipt(&post_submit, &mobile, 60_070).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 60_080)
            .await
            .unwrap()
            .status,
        OperationStatus::ReconciliationRequired
    );
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 60_090)
        .unwrap();
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 60_100)
        .await
        .unwrap();
    let receipt = signed_receipt(&final_anchor, &mobile, 60_110).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 60_120)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "and the recovery never turned into a broadcast of its own"
    );
    drop(root);
}

/// EXECUTION 2: THE SAME CRASH, AND THE ANCHOR IS LONG DEAD BEFORE THE OWNER
/// COMES BACK.
///
/// A wallet that crashed is not going to be reopened inside the anchor's five
/// minutes, so the reconciliation must not depend on the anchor being alive.
#[tokio::test]
async fn the_broadcast_write_crash_is_reconciled_a_year_later() {
    let (root, wallet_id, mobile, operation_id, node, authorization, tx_hash) =
        crash_between_the_broadcast_write_and_the_node(61_000).await;
    let much_later = 61_000 + 365 * 24 * 60 * 60;

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();
    let recovered =
        operation_view(&mut manager, &wallet_id, &operation_id, much_later + 1).unwrap();
    assert_eq!(recovered.status, OperationStatus::BroadcastUncertain);
    assert_eq!(recovered.tx_hash.as_deref(), Some(tx_hash.as_str()));
    assert!(pending_slot(&manager, &wallet_id).is_none());
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // An unresolved payment still blocks the next one, and must. What matters
    // is that it can now be resolved at all.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("blocked-until-reconciled", much_later + 500),
                much_later + 2,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    let post_submit = manager
        .pending_rollback_anchor(
            &wallet_id,
            &operation_id,
            mobile.device_id(),
            much_later + 3,
        )
        .await
        .unwrap();
    let receipt = signed_receipt(&post_submit, &mobile, much_later + 4).await;
    manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, much_later + 5)
        .await
        .unwrap();
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, much_later + 6)
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(
            &wallet_id,
            &operation_id,
            mobile.device_id(),
            much_later + 7,
        )
        .await
        .unwrap();
    let receipt = signed_receipt(&final_anchor, &mobile, much_later + 8).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, much_later + 9)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-reconciliation", much_later + 900),
                much_later + 10,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "and the wallet takes payments again"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// PROVE-THE-TEST, PART ONE: WITHOUT THE RECOVERY THE RESIDUE HAS NO EXIT AT
/// ALL, AND WITH THE OLD ONE IT HAD THE WRONG EXIT.
///
/// The wallet is reopened with the unlock recovery skipped, which is exactly how
/// it stood before this change, and every control the owner has is walked.
#[tokio::test]
async fn without_the_recovery_the_broadcast_write_crash_has_no_exit_at_all() {
    let (root, wallet_id, mobile, operation_id, node, authorization, _tx_hash) =
        crash_between_the_broadcast_write_and_the_node(62_000).await;

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager
        .unlock_without_witness_recovery_for_test(&wallet_id, PASSPHRASE, 62_050)
        .unwrap();

    let parked = pending_slot(&manager, &wallet_id).unwrap();
    assert_eq!(parked.0, operation_id.to_string());
    assert!(parked.1, "the receipt is on disk and nothing archived it");
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 62_051)
            .unwrap()
            .status,
        OperationStatus::BroadcastSubmitted,
        "this is the residue: a status that says submitted, on a transaction \
         the node's own counter says it never received"
    );

    // 1. THE DESKTOP'S RECOVERY SURFACE. `BroadcastSubmitted` is not in
    //    `awaits_mobile_witness`, so the owner is shown nothing at all.
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 62_052)
            .unwrap()
            .is_none()
    );

    // 2. RESUME. Refused, and rightly: from `BroadcastSubmitted` this wallet
    //    never auto-rebroadcasts.
    assert_eq!(
        manager
            .resume_payment(&wallet_id, &operation_id, 62_053)
            .await
            .unwrap_err(),
        AgentWalletError::BroadcastUncertain
    );

    // 3. RECONCILE. Refused: `confirm_broadcast` admits only
    //    `ReconciliationRequired` in the pilot, and nothing can reach it.
    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 62_054)
        .unwrap()
        .tx_hash
        .unwrap();
    assert_eq!(
        manager
            .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 62_055)
            .unwrap_err(),
        AgentWalletError::ApprovalCommitmentMismatch
    );

    // 4. ASK THE PHONE AGAIN. Refused: `BroadcastSubmitted` is not an anchor
    //    phase this wallet issues.
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 62_056)
            .await
            .unwrap_err(),
        AgentWalletError::InvalidOperationState
    );

    // 5. ABANDON. Refused, and must be: the wallet cannot prove the money did
    //    not move.
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 62_057)
            .unwrap_err(),
        AgentWalletError::InvalidOperationState
    );

    // 6. RELEASE THE ANCHOR. Refused twice over: `BroadcastSubmitted` is not a
    //    status this wallet admits to the witness recovery surface at all, and
    //    a receipt sits against the anchor anyway.
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, 62_058)
            .unwrap_err(),
        AgentWalletError::InvalidOperationState
    );

    // 7. REPLACE THE PHONE. Refused while the slot is occupied.
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation-after-broadcast-crash".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                62_059,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );

    // 8. AND NO FURTHER PAYMENT, EVER.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("blocked-by-broadcast-crash", 62_500),
                62_060,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // AND THE RECOVERY IS WHAT LIFTS IT. Same wallet, same disk, one unlock -
    // and it lifts it to `BroadcastUncertain`, not to a claim that the payment
    // was submitted.
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 62_070).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 62_071)
            .unwrap()
            .status,
        OperationStatus::BroadcastUncertain
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 62_072)
            .unwrap()
            .is_some()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// A CRASH ON THE FAR SIDE OF THE SAME WINDOW IS STILL REPORTED AS SUBMITTED.
///
/// The reconciliation must not turn every interrupted archive into "unknown".
/// When the crash lands after the node acknowledged the exact hash,
/// `resume_payment` has already persisted `SubmittedAwaitingFinalWitness`, and
/// the recovery must leave that statement alone: the money did move, and the
/// owner is entitled to be told so.
#[tokio::test]
async fn the_crash_after_the_node_acknowledged_still_says_the_money_moved() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(63_000).await;
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 63_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 63_030).await;

    manager.crash_before_witness_archive = true;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 63_040)
            .await
            .is_err()
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the money really did go out before the process died"
    );
    drop(manager);

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 63_050).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 63_051)
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "a submission the node acknowledged is never downgraded to uncertain"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// Drives the phone-approval path to the instant after the decision and its
/// replay token are durable, and kills the process there.
async fn crash_after_the_phone_said_yes(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    MockPilotNode,
    crate::service::AgentAuthorization,
    hpay_companion_protocol::SignedApprovalDecision,
    HacUnits,
) {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_approving_witness_mobile(&mut manager, &wallet_id, &mobile, now + 3);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::MobileManual,
        now + 4,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("mobile-approval-crash", now + 300),
            now + 5,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let reserved = created.reserved_units;
    assert!(reserved > HacUnits::ZERO);
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 6)
        .unwrap();
    let signed =
        signed_decision(&approval, ApprovalDecision::Approve, &mobile, 1, 1, now + 7).await;

    manager.crash_after_mobile_approval_granted = true;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, signed.clone(), now + 8)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(manager);
    (
        root,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
        signed,
        reserved,
    )
}

/// EXECUTION 3: THE SECOND NEW DEFECT. THE OWNER SAID YES ON THEIR PHONE AND
/// THE WALLET THREW IT AWAY.
#[tokio::test]
async fn the_mobile_approval_crash_is_finished_on_unlock() {
    let (root, wallet_id, mobile, operation_id, node, _authorization, _signed, _reserved) =
        crash_after_the_phone_said_yes(64_000).await;

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 64_050).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 64_051)
            .unwrap()
            .status,
        OperationStatus::Approved,
        "the approval is durable and the signature never happened; the unlock \
         itself cannot finish this one, because signing needs the node"
    );

    // This is what the desktop runs straight after every unlock.
    let resumed = manager
        .resume_interrupted_approval(&wallet_id, 64_052)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed.operation_id, operation_id,
        "the payment resumed is the one the phone approved"
    );
    assert_eq!(
        resumed.status,
        OperationStatus::SignedAwaitingWitness,
        "the approval the owner really gave is carried through to exactly \
         where the uninterrupted call leaves it"
    );
    assert!(resumed.tx_hash.is_some());
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "signing is not broadcasting"
    );

    // Resuming again is a nothing.
    assert!(
        manager
            .resume_interrupted_approval(&wallet_id, 64_053)
            .await
            .unwrap()
            .is_none()
    );

    // AND THE PAYMENT COMPLETES, WITH A REAL SIGNATURE FROM THE REAL PHONE.
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 64_060)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 64_070).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 64_080)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "one payment, one submission, across a crash and a restart"
    );
    drop(root);
}

/// PROVE-THE-TEST, PART TWO: WITHOUT THE RESUME THE PHONE'S YES IS GONE.
#[tokio::test]
async fn without_the_resume_the_mobile_approval_crash_destroys_the_owners_yes() {
    let (root, wallet_id, _mobile, operation_id, node, authorization, signed, reserved) =
        crash_after_the_phone_said_yes(65_000).await;

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 65_050).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 65_051)
            .unwrap()
            .status,
        OperationStatus::Approved
    );

    // 1. THE PHONE PRESSES YES AGAIN, WITH THE IDENTICAL SIGNED DECISION. This
    //    is the whole difference from the desktop twin of this boundary: the
    //    replay token went out with the same durable write that recorded the
    //    decision, so the owner cannot repeat their own press.
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, signed, 65_052)
            .await
            .unwrap_err(),
        AgentWalletError::CompanionReplayRejected
    );

    // 2. THE DESKTOP CANNOT APPROVE IT EITHER: this agent's approval device is
    //    the phone.
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, 65_053)
        .unwrap_err();
    assert_eq!(
        approval,
        AgentWalletError::InvalidOperationState,
        "and the desktop is not even offered the commitment, because the \
         payment is no longer awaiting an approval"
    );

    // 3. THE DESKTOP'S RECOVERY SURFACE SHOWS NOTHING: `Approved` is not in
    //    `awaits_mobile_witness`.
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, 65_054)
            .unwrap()
            .is_none()
    );

    // 4. SO THE ONLY THING THAT EVER HAPPENS TO IT IS THE EXPIRY SWEEP: the
    //    payment the owner approved is cancelled and the reservation comes
    //    back, with nothing anywhere having told them why.
    assert!(reserved > HacUnits::ZERO);
    let after_expiry = 65_400;
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-lost-yes", after_expiry + 300),
                after_expiry,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    match operation_view(&mut manager, &wallet_id, &operation_id, after_expiry + 1) {
        None => {}
        Some(view) => {
            assert_eq!(view.status, OperationStatus::Cancelled);
            assert_eq!(view.reserved_units, HacUnits::ZERO);
        }
    }
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// THE APPROVAL RESUME NEVER SIGNS ANYTHING THE OWNER DID NOT APPROVE, AND
/// NEVER SIGNS ANYTHING IT CANNOT SEE THROUGH.
///
/// Four ways of having no resumable approval are executed against it, and it
/// declines every one, leaving the payment exactly where the ordinary rules
/// leave it.
#[tokio::test]
async fn the_approval_resume_declines_everything_it_cannot_reason_about() {
    // 1. NOTHING APPROVED AT ALL. A payment still awaiting its decision is not
    //    an interrupted approval.
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 66_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_approving_witness_mobile(&mut manager, &wallet_id, &mobile, 66_003);
    let authorization =
        pair_desktop_agent(&mut manager, &wallet_id, ApprovalMode::MobileManual, 66_004);
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("never-approved", 66_300),
            66_005,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    assert!(
        manager
            .resume_interrupted_approval(&wallet_id, 66_006)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 66_007)
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(manager);
    drop(root);

    // 2. AN APPROVAL THAT EXPIRED WHILE THE WALLET WAS SHUT. It is swept and
    //    the reservation comes back; it is never signed late.
    let (root, wallet_id, _mobile, operation_id, node, _authorization, _signed, _reserved) =
        crash_after_the_phone_said_yes(67_000).await;
    let after_expiry = 67_500;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager
        .unlock(&wallet_id, PASSPHRASE, after_expiry)
        .unwrap();
    assert!(
        manager
            .resume_interrupted_approval(&wallet_id, after_expiry + 1)
            .await
            .unwrap()
            .is_none(),
        "an expired approval is not resumed"
    );
    // And the ordinary sweep - not this recovery - is what cancels it and hands
    // the reservation back, exactly as it does for an approval nothing crashed.
    manager
        .create_payment_intent(
            &_authorization,
            payment_request("after-expired-approval", after_expiry + 400),
            after_expiry + 2,
        )
        .await
        .unwrap();
    match operation_view(&mut manager, &wallet_id, &operation_id, after_expiry + 2) {
        None => {}
        Some(view) => {
            assert_eq!(view.status, OperationStatus::Cancelled);
            assert_eq!(view.reserved_units, HacUnits::ZERO);
        }
    }
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(manager);
    drop(root);

    // 3. THE WITNESS PHONE IS GONE. Signing would land the payment in
    //    `SignedAwaitingWitness`, which no sweep expires and no phone can move,
    //    so the resume declines for the same reason the approval itself would
    //    have been refused.
    let (root, wallet_id, mobile, operation_id, node, _authorization, _signed, _reserved) =
        crash_after_the_phone_said_yes(68_000).await;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 68_050).unwrap();
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 68_051)
        .unwrap();
    assert!(
        manager
            .resume_interrupted_approval(&wallet_id, 68_052)
            .await
            .unwrap()
            .is_none(),
        "no witness phone, no signature"
    );
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 68_053)
            .unwrap()
            .status,
        OperationStatus::Approved,
        "and the approval is left exactly as it was, to expire on its own terms"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(manager);
    drop(root);

    // 4. A PAYMENT ALREADY IN THE WITNESS LIFECYCLE. Signing a second one would
    //    strand both.
    let (root, mut manager, wallet_id, _mobile, operation_id, node, _authorization) =
        desktop_approved_operation(69_000).await;
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 69_020)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness
    );
    assert!(
        manager
            .resume_interrupted_approval(&wallet_id, 69_021)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// AN OWNER WHO CHANGES NOTHING SEES NOTHING CHANGE.
///
/// The ordinary phone-approval lifecycle is run end to end with an unlock, and
/// the two new recoveries, at every step. Both are a no-op at every one of them,
/// because the uninterrupted path never leaves the residue either of them looks
/// for.
#[tokio::test]
async fn the_uninterrupted_path_is_untouched_by_either_recovery() {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 70_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_approving_witness_mobile(&mut manager, &wallet_id, &mobile, 70_003);
    let authorization =
        pair_desktop_agent(&mut manager, &wallet_id, ApprovalMode::MobileManual, 70_004);

    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("uninterrupted", 70_600),
            70_005,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();

    macro_rules! relock_and_recover {
        ($manager:ident, $at:expr, $expected:expr) => {{
            drop($manager);
            let mut reopened = AgentWalletManager::open(root.path()).unwrap();
            reopened.unlock(&wallet_id, PASSPHRASE, $at).unwrap();
            assert!(
                reopened
                    .resume_interrupted_witness(&wallet_id, $at + 1)
                    .await
                    .unwrap()
                    .is_none(),
                "the witness resume has nothing to do on an uninterrupted wallet"
            );
            assert!(
                reopened
                    .resume_interrupted_approval(&wallet_id, $at + 2)
                    .await
                    .unwrap()
                    .is_none(),
                "and neither has the approval resume"
            );
            assert_eq!(
                operation_view(&mut reopened, &wallet_id, &operation_id, $at + 3)
                    .unwrap()
                    .status,
                $expected
            );
            reopened
        }};
    }

    manager = relock_and_recover!(manager, 70_010, OperationStatus::ApprovalRequested);
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, 70_020)
        .unwrap();
    let signed = signed_decision(&approval, ApprovalDecision::Approve, &mobile, 1, 1, 70_021).await;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, signed, 70_022)
            .await
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness
    );
    manager = relock_and_recover!(manager, 70_030, OperationStatus::SignedAwaitingWitness);

    for expected in [
        OperationStatus::SubmittedAwaitingFinalWitness,
        OperationStatus::ReconciliationRequired,
    ] {
        let anchor = manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 70_040)
            .await
            .unwrap();
        let receipt = signed_receipt(&anchor, &mobile, 70_041).await;
        assert_eq!(
            manager
                .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 70_042)
                .await
                .unwrap()
                .status,
            expected
        );
        manager = relock_and_recover!(manager, 70_050, expected);
    }

    let tx_hash = operation_view(&mut manager, &wallet_id, &operation_id, 70_060)
        .unwrap()
        .tx_hash
        .unwrap();
    manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, 70_061)
        .unwrap();
    manager = relock_and_recover!(
        manager,
        70_070,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 70_080)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 70_081).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 70_082)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
    manager = relock_and_recover!(manager, 70_090, OperationStatus::Committed);
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "seven unlocks, two recoveries at each, and exactly one submission"
    );
    drop(manager);
    drop(root);
}

/// THE SWEEP, RE-RUN AND EXECUTED: THE THREE REMAINING BOUNDARIES.
///
/// After the two above, three `persist_event` calls in these files still have a
/// second step after them. Each is driven here rather than argued about.
///
///   * `pending_rollback_anchor` journals `RollbackWitnessInitialized` and then
///     mints the anchor;
///   * `create_payment_intent` journals `FundsReserved` and then asks the node
///     to build the transaction;
///   * `resume_payment` journals `TransactionSigned` and then reloads and, off
///     the pilot, broadcasts.
#[tokio::test]
async fn the_three_remaining_boundaries_strand_nothing() {
    // 1. THE WITNESS RECORD IS CREATED AND THE ANCHOR IS NOT. The record is a
    //    pin and an epoch, not a proposal, so the phone simply asks again.
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(71_000).await;
    manager.crash_after_witness_state_initialized = true;
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 71_020)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 71_030).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 71_031)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness,
        "which is where the payment was before the call"
    );
    assert!(pending_slot(&manager, &wallet_id).is_none());
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 71_032)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 71_033).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 71_034)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);

    // 2. THE RESERVATION IS DURABLE AND THE APPROVAL IS NEVER REQUESTED.
    //    `FundsReserved` is pre-signing, so the ordinary expiry sweep takes it
    //    and the reserved funds come back.
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 72_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 72_003);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        72_004,
    );
    manager.crash_after_funds_reserved = true;
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("funds-reserved-crash", 72_300),
                72_005,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 72_006).unwrap();
    let residue: Vec<_> = manager
        .list_operations_admin(&wallet_id, 72_007)
        .unwrap()
        .into_iter()
        .map(|view| view.status)
        .collect();
    assert_eq!(residue, vec![OperationStatus::FundsReserved]);
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("a-different-payment", 72_400),
                72_008,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "a half-created intent blocks nothing"
    );
    let after_expiry = 72_500;
    manager
        .create_payment_intent(
            &authorization,
            payment_request("after-expiry", after_expiry + 300),
            after_expiry,
        )
        .await
        .unwrap();
    assert!(
        manager
            .list_operations_admin(&wallet_id, after_expiry + 1)
            .unwrap()
            .iter()
            .all(|view| view.status != OperationStatus::FundsReserved),
        "the interrupted intent is swept by its own expiry and the reservation \
         comes back"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);

    // 3. THE SIGNATURE IS DURABLE AND THE CALL NEVER RETURNED. Under the pilot
    //    the uninterrupted call stops at exactly this status anyway, so there is
    //    no residue to speak of.
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 73_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 73_003);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        73_004,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("signed-crash", 73_300),
            73_005,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, 73_006)
        .unwrap();
    manager.crash_after_transaction_signed = true;
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 73_007)
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 73_008).unwrap();
    assert_eq!(
        operation_view(&mut manager, &wallet_id, &operation_id, 73_009)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness
    );
    let shown = manager
        .stranded_witness_recovery(&wallet_id, 73_010)
        .unwrap()
        .unwrap();
    assert!(!shown.submitted);
    assert!(shown.retryable);
    assert!(shown.abandonable, "and it can still be given up for free");
    let anchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 73_011)
        .await
        .unwrap();
    let receipt = signed_receipt(&anchor, &mobile, 73_012).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 73_013)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}
