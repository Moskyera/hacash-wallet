//! Where an exact payment can actually be approved, and what happens to an
//! owner who approves nowhere.
//!
//! The Testnet Pilot used to refuse every desktop approval. That refusal was
//! never a statement about which device is trusted - the approval-mode gate in
//! `approve_desktop_and_broadcast` has always admitted `DesktopManual` - it was
//! a fail-closed stub standing in for a phone that could not yet witness an
//! operation it had not itself approved. The phone can now discover and witness
//! exactly such an operation, the whole path is executed in
//! `desktop_witness_flow.rs`, and the stub is gone.
//!
//! These tests pin what decides an approval now: the agent's approval mode, and
//! the exactness of the commitment. Nothing about the build.

use super::fixtures::*;
use super::*;

/// The owner's yes is durably recorded before the signer or the node is ever
/// reached, and a valid desktop approval is not refused.
///
/// The manager in this fixture points at a node that is not running, which is
/// precisely what makes the assertion sharp: the approval is journaled as
/// `Approved` and survives, and the failure that follows is the node's, not a
/// refusal of the approval. An owner who says yes and then loses the node has
/// not lost their decision, and nothing was signed on the way.
///
/// Before the stub was removed this call returned
/// `DesktopApprovalUnavailableInPilot` for this exact input.
#[tokio::test]
async fn a_valid_desktop_approval_is_recorded_before_any_signer_or_node_call() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    // A paired phone that can witness. Approving signs, and under the pilot a
    // signed payment goes nowhere without one; see
    // `a_desktop_approval_with_no_phone_that_can_witness_is_refused_unsigned`.
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let before_view = before.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(before_view.status, OperationStatus::ApprovalRequested);

    let outcome = manager
        .approve_desktop_and_broadcast(&wallet_id, approval.clone(), 104)
        .await;
    assert_ne!(
        outcome.as_ref().err(),
        Some(&AgentWalletError::AgentPermissionDenied),
        "the desktop must not be refused for an agent whose Approval device is \
         Desktop only"
    );
    assert_ne!(
        outcome.as_ref().err(),
        Some(&AgentWalletError::ApprovalRequired),
        "an owner who has just supplied an approval must never be told that \
         approval is required"
    );

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let after_view = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(
        after_view.status,
        OperationStatus::Approved,
        "the decision is durable before the signer is called; only the node \
         call after it failed"
    );
    assert_eq!(after_view.approval_mode, Some(ApprovalMode::DesktopManual));
    assert_eq!(
        after_view.tx_hash, None,
        "an unreachable node must leave nothing signed"
    );
    assert!(
        after.journal_sequence > before.journal_sequence,
        "the granted approval is journaled"
    );
    drop(root);
}

/// An approval that is wrong gets its own specific error, and writes nothing.
///
/// This is what the throwaway probe clone buys, and it is why the clone was
/// kept when the blanket refusal was removed: the wallet in this test has no
/// paired phone, so a VALID approval here is refused with
/// `WitnessPhoneRequiredForApproval`. Each of the three below is refused with
/// its own reason instead, which is only possible because the approval is
/// validated before that refusal is reached. Without the probe an owner could
/// not tell "these are not the bytes you approved" from "pair a phone first".
#[tokio::test]
async fn a_tampered_or_expired_desktop_approval_gets_its_own_error_and_writes_nothing() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();

    let mut tampered = approval.clone();
    tampered.amount_units += 1;
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, tampered, 104)
            .await
            .unwrap_err(),
        AgentWalletError::ApprovalCommitmentMismatch,
        "an approval that does not match the stored commitment must say so"
    );

    let mut expired = approval.clone();
    expired.expires_at = 103;
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, expired, 104)
            .await
            .unwrap_err(),
        AgentWalletError::ApprovalExpired,
        "an expired approval must say so"
    );

    let mut malformed = approval.clone();
    malformed.wallet_fee_units = 1;
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, malformed, 104)
            .await
            .unwrap_err(),
        AgentWalletError::ApprovalCommitmentMismatch,
        "an approval carrying a wallet fee must be refused as malformed"
    );

    // Not one of the three wrote anything: not the status, not the decision,
    // not the reservation, not the journal.
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let after_view = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(after_view.status, OperationStatus::ApprovalRequested);
    assert_eq!(after_view.approval_mode, None);
    assert_eq!(after_view.tx_hash, None);
    assert_eq!(
        after.journal_sequence, before.journal_sequence,
        "a refused approval must journal nothing"
    );
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(
        after
            .operations
            .get(operation_id.as_str())
            .unwrap()
            .stored_approval()
            .unwrap(),
        &approval,
        "the stored commitment must survive a refused attempt"
    );
    drop(root);
}

/// THE ONE PART OF THE OLD BLANKET REFUSAL THAT STILL HAS A REASON.
///
/// Under the pilot, approving signs the transaction into
/// `SignedAwaitingWitness` and stops there. Only a phone holding
/// `WitnessRollbackAnchor` can move it: that is the permission
/// `pending_rollback_anchor` requires. With no such phone the payment would sign
/// into a status no sweep can expire, holding its reservation, refusing every
/// later payment an anchor - the exact stranding the blanket refusal existed to
/// prevent, and the only part of it that survived removing the stub.
///
/// So a wallet with no witness phone is refused, before signing, with a reason
/// that names the control that fixes it, and the same approval is accepted once
/// a phone is paired. That second half is what makes this a prerequisite rather
/// than a new prohibition.
#[cfg(feature = "agent-wallet-testnet-pilot")]
#[tokio::test]
async fn a_desktop_approval_with_no_phone_that_can_witness_is_refused_unsigned() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();

    let error = manager
        .approve_desktop_and_broadcast(&wallet_id, approval.clone(), 104)
        .await
        .unwrap_err();
    assert_eq!(error, AgentWalletError::WitnessPhoneRequiredForApproval);

    // The message is shown verbatim to the owner. It has to name the reason,
    // name a control that really exists and really works, and promise the thing
    // the code above it guarantees.
    let message = error.to_string();
    assert!(
        message.contains("witness"),
        "the refusal must say why this cannot complete: {message}"
    );
    assert!(
        message.contains("Pair a phone"),
        "the refusal must name the control that resolves it: {message}"
    );
    assert!(
        message.contains("Nothing was signed"),
        "the refusal must state that no transaction was produced: {message}"
    );

    // Nothing was written. Not the status, not the decision, not the journal.
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let after_view = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(after_view.status, OperationStatus::ApprovalRequested);
    assert_eq!(after_view.approval_mode, None);
    assert_eq!(after_view.tx_hash, None);
    assert_eq!(after.journal_sequence, before.journal_sequence);
    assert_eq!(after.updated_at, before.updated_at);

    // Pair a phone that can witness, and the identical approval is admitted.
    // (No node is running here, so what is asserted is the gate and the durable
    // decision; the full path is executed in `desktop_witness_flow.rs`.)
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 105);
    let outcome = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, 106)
        .await;
    assert_ne!(
        outcome.as_ref().err(),
        Some(&AgentWalletError::WitnessPhoneRequiredForApproval),
        "pairing a witness phone must clear this refusal"
    );
    let paired = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        paired
            .operations
            .get(operation_id.as_str())
            .unwrap()
            .view()
            .status,
        OperationStatus::Approved
    );
    drop(root);
}

/// THE APPROVAL MODE IS THE ONLY THING THAT DECIDES WHICH DEVICE MAY APPROVE.
///
/// `ApprovalMode::DesktopManual` is the only mode the desktop can produce: the
/// pairing screen writes `approval_mode: "desktop_manual"`
/// (apps/desktop/src/agent/AgentWalletApp.tsx), the Rules page renders "Approval
/// device" as a read-only disabled input, and `draftToPolicy`
/// (apps/desktop/src/agent/AgentAdminPages.tsx) refuses to save any policy whose
/// mode is not `desktop_manual`. `AgentPolicy::default` and the pairing outbox
/// agree.
///
/// Under that mode exactly one device may approve, and it is the desktop:
///
///   * the desktop is admitted, and its decision is durably recorded;
///   * the phone is refused, because `apply_mobile_approval_and_broadcast`
///     admits only `MobileManual` or `EitherTrustedDevice` and returns
///     `AgentPermissionDenied` for `DesktopManual`.
///
/// This test used to assert that NEITHER device could approve. That was the
/// state of the pilot while the desktop refusal existed, and it is what made the
/// owner headline path unreachable.
#[tokio::test]
async fn the_shipping_desktop_manual_policy_is_approved_by_the_desktop_and_not_the_phone() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 103);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 104);

    let signed = signed_decision(
        &approval,
        ApprovalDecision::Approve,
        &mobile,
        record.authorization_epoch,
        1,
        105,
    )
    .await;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, signed, 106)
            .await
            .unwrap_err(),
        AgentWalletError::AgentPermissionDenied,
        "the phone is refused by the approval mode the desktop wrote"
    );

    // The desktop is not. No node is running in this test, so what is asserted
    // is the gate and the durable decision, not the broadcast.
    let outcome = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, 107)
        .await;
    assert_ne!(
        outcome.as_ref().err(),
        Some(&AgentWalletError::AgentPermissionDenied),
        "the desktop must be able to approve under the only mode it can write"
    );

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let view = state.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(view.status, OperationStatus::Approved);
    assert_eq!(view.approval_mode, Some(ApprovalMode::DesktopManual));
    assert_eq!(view.tx_hash, None);
    drop(root);
}

/// The setting still moves the decision to the phone.
///
/// The same operation, the same phone, the same signed decision: only the
/// agent's approval mode differs, and the phone's approval is accepted and
/// durably recorded. Unchanged by the removal of the desktop refusal, and
/// pinned so that giving the desktop back its Approve control cannot quietly
/// take the mobile modes away.
#[tokio::test]
async fn a_mobile_approval_mode_is_what_lets_the_phone_decide_the_same_payment() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 103);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 104);

    let signed = signed_decision(
        &approval,
        ApprovalDecision::Approve,
        &mobile,
        record.authorization_epoch,
        1,
        106,
    )
    .await;
    // No node is running in this test, so the signing step that follows cannot
    // complete. What matters is the gate: the decision is admitted, not refused.
    let outcome = manager
        .apply_mobile_approval_and_broadcast(&wallet_id, signed, 107)
        .await;
    assert_ne!(
        outcome.as_ref().err(),
        Some(&AgentWalletError::AgentPermissionDenied),
        "a mobile approval mode must let the phone decide"
    );

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let view = state.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(
        view.status,
        OperationStatus::Approved,
        "the phone's approval is durably recorded before any signer call"
    );
    assert_eq!(view.approval_mode, Some(ApprovalMode::MobileManual));
    assert_eq!(view.tx_hash, None);
    drop(root);
}

/// An owner who does nothing sees no change.
///
/// The owner opens the exact-transaction review, reads it, and decides nothing.
/// That path reads state; it must never write any. The payment stays exactly as
/// the agent left it, still waiting and still reserved.
///
/// The second half pins the passive ending: an approval nobody ever answers
/// expires and is swept, releasing its reservation. Nothing here changed when
/// the desktop refusal was removed, which is the point of keeping it.
#[tokio::test]
async fn an_owner_who_decides_nothing_leaves_the_payment_exactly_as_it_was() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let before_view = before.operations.get(operation_id.as_str()).unwrap().view();

    // Reviewing the exact transaction, repeatedly, well inside the window.
    for now in [104, 150, 300] {
        let reviewed = manager
            .pending_approval(&wallet_id, &operation_id, now)
            .unwrap();
        assert_eq!(
            reviewed, approval,
            "reviewing a payment must return the exact stored commitment"
        );
    }

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let after_view = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(after_view.status, OperationStatus::ApprovalRequested);
    assert_eq!(after_view.reserved_units, before_view.reserved_units);
    assert_eq!(after_view.total_debit_units, before_view.total_debit_units);
    assert_eq!(after_view.final_result, None);
    assert_eq!(after_view.tx_hash, None);
    assert_eq!(
        after.journal_sequence, before.journal_sequence,
        "reading a pending approval must journal nothing"
    );
    assert_eq!(after.updated_at, before.updated_at);

    // The unchanged ending for an owner who never answers: the approval expires
    // and the sweep releases the reservation. `prepare_pending` sets the window
    // to 300 seconds from 103.
    let expired = manager
        .pending_approval(&wallet_id, &operation_id, 404)
        .unwrap_err();
    assert_eq!(expired, AgentWalletError::InvalidOperationState);
    let swept = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let swept_view = swept.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(swept_view.status, OperationStatus::Cancelled);
    assert_eq!(swept_view.reserved_units, HacUnits::ZERO);
    drop(root);
}
