#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    ApprovalNetworkBinding, DeviceRole, SignedWitnessReceipt, WitnessReceipt,
};
use serde_json::json;

use super::fixtures::*;
use super::pilot_node::*;
use super::*;
use crate::node_binding::verified_agent_node;

pub(super) const TX_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

async fn prepare_signed_operation(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    node_url: &str,
    now: u64,
) -> OperationId {
    let node = verified_agent_node(node_url, "testnet", TESTNET_ANCHOR)
        .await
        .unwrap();
    let (mut approval, operation_id) =
        prepare_pending(manager, wallet_id, ApprovalMode::MobileManual, now);
    approval.approval_version = 3;
    approval.network_binding = Some(ApprovalNetworkBinding {
        network_id: node.network_kind().to_owned(),
        chain_id: node.chain_id(),
        genesis_identifier: TESTNET_ANCHOR.to_owned(),
        node_profile_id: node.node_profile_id().to_owned(),
        transaction_format_version: node.transaction_format_version(),
    });

    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = state.operations.get(operation_id.as_str()).unwrap().clone();
    let mut encoded = serde_json::to_value(operation).unwrap();
    encoded["approval_commitment"] = serde_json::to_value(approval).unwrap();
    encoded["status"] = json!("signed_awaiting_witness");
    encoded["signed_tx_hex"] = json!("00");
    encoded["tx_hash"] = json!(TX_HASH);
    state.operations.insert(
        operation_id.to_string(),
        serde_json::from_value(encoded).unwrap(),
    );
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::TransactionSigned,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )
        .unwrap();
    operation_id
}

async fn prepared_witness_flow(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    hpay_companion_protocol::SignedRollbackAnchor,
    SignedWitnessReceipt,
    MockPilotNode,
) {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 2);
    let operation_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, now + 3).await;
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 4)
        .await
        .unwrap();
    let receipt = signed_receipt(&proposal, &mobile, now + 5).await;
    (
        root,
        manager,
        wallet_id,
        mobile,
        operation_id,
        proposal,
        receipt,
        node,
    )
}

fn persist_test_state(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    state: &mut AgentWalletState,
    event: AgentJournalEventKind,
    now: u64,
) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    state.updated_at = now;
    manager
        .persist_event(state, &state_master, &journal_key, event, None, None, now)
        .unwrap();
}

fn write_unvalidated_current_state(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    state: &AgentWalletState,
) {
    let (state_master, _journal_key) = keys(manager, wallet_id);
    manager
        .storage
        .write_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            state,
        )
        .unwrap();
}
/// Nothing added for the dead-end escapes may make a broadcast reachable
/// without a real signature from the paired phone over the exact anchor.
///
/// This is the invariant every escape in this change is measured against, so it
/// is asserted directly rather than inferred: a receipt from another device, a
/// receipt over a different anchor, and a receipt whose hash has been edited are
/// all refused, the operation stays `SignedAwaitingWitness`, and the node is
/// never asked to submit anything until the genuine receipt arrives.
#[tokio::test]
async fn broadcast_still_requires_a_real_witness_signature_over_the_exact_anchor() {
    let (_root, mut manager, wallet_id, mobile, operation_id, proposal, receipt, node) =
        prepared_witness_flow(2_600).await;
    let submits = node.submit_count.clone();
    assert_eq!(submits.load(Ordering::SeqCst), 0);

    // A different registered phone cannot even produce a receipt for this
    // anchor: the receipt is scoped to the device the anchor names.
    let impostor = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &impostor, 2_601);
    let anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    let honest = WitnessReceipt::for_anchor(&proposal.anchor, anchor_hash.clone(), 2_602).unwrap();
    assert!(
        SignedWitnessReceipt::sign(honest.clone(), &impostor)
            .await
            .is_err(),
        "only the phone the anchor names may witness it"
    );
    // Nor by re-scoping the receipt to itself and signing that honestly.
    let mut rescoped = honest;
    rescoped.mobile_device_id = impostor.device_id().clone();
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(
                &wallet_id,
                SignedWitnessReceipt::sign(rescoped, &impostor)
                    .await
                    .unwrap(),
                2_602,
            )
            .await
            .is_err()
    );

    // The right phone, but the hash it attests to is edited after signing.
    let mut tampered = receipt.clone();
    tampered.receipt.anchor_hash = "22".repeat(32);
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, tampered, 2_603)
            .await
            .is_err()
    );

    // The right phone, signing honestly, but over an anchor for a rotation
    // rather than this operation.
    let mut wrong_anchor = receipt.clone();
    wrong_anchor.receipt.anchor_id = "anchor_not_this_one".to_owned();
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, wrong_anchor, 2_604)
            .await
            .is_err()
    );

    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, 2_605)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_id)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness,
        "a refused witness must leave the operation exactly where it was"
    );
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "nothing may reach the node without a genuine witness"
    );

    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 2_606)
        .await
        .unwrap();
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(submits.load(Ordering::SeqCst), 1);
    let _ = mobile;
}

#[tokio::test]
async fn malformed_authenticated_checkpoint_is_rejected_on_load() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, _proposal, _receipt, _node) =
        prepared_witness_flow(100).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.rollback_witness.as_mut().unwrap().last_anchor_hash = "malformed".to_owned();
    write_unvalidated_current_state(&manager, &wallet_id, &state);

    assert_eq!(
        manager.unlocked_status(&wallet_id, 111),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn decreasing_authenticated_checkpoint_is_rejected_on_load() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, proposal, _receipt, _node) =
        prepared_witness_flow(200).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let witness = state.rollback_witness.as_mut().unwrap();
    witness.last_anchor_sequence = proposal.anchor.anchor_sequence;
    witness.last_anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    write_unvalidated_current_state(&manager, &wallet_id, &state);

    assert_eq!(
        manager.unlocked_status(&wallet_id, 211),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn exact_receipt_retry_after_witnessed_state_submits_once() {
    let (_root, mut manager, wallet_id, _mobile, operation_id, proposal, receipt, node) =
        prepared_witness_flow(300).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let witness = state.rollback_witness.as_mut().unwrap();
    witness.last_anchor_sequence = proposal.anchor.anchor_sequence;
    witness.last_anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    witness.pending.as_mut().unwrap().receipt = Some(receipt.clone());
    state
        .operations
        .get_mut(operation_id.as_str())
        .unwrap()
        .mark_witnessed()
        .unwrap();
    persist_test_state(
        &mut manager,
        &wallet_id,
        &mut state,
        AgentJournalEventKind::RollbackWitnessAccepted,
        306,
    );

    let result = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 307)
        .await
        .unwrap();
    assert_eq!(
        result.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lost_ack_after_broadcast_submitted_returns_status_without_second_submit() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, _proposal, receipt, node) =
        prepared_witness_flow(400).await;

    let first = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt.clone(), 406)
        .await
        .unwrap();
    let retry = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 407)
        .await
        .unwrap();

    assert_eq!(first.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(retry.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn final_witness_releases_reservation_and_allows_a_second_operation() {
    let (_root, mut manager, wallet_id, mobile, _first_id, first_proposal, first_receipt, node) =
        prepared_witness_flow(500).await;
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, first_receipt, 506)
        .await
        .unwrap();
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &submitted.operation_id, mobile.device_id(), 507)
        .await
        .unwrap();
    assert_eq!(
        post_submit.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::Submitted
    );
    let post_receipt = signed_receipt(&post_submit, &mobile, 508).await;
    let reconciliation = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, post_receipt, 509)
        .await
        .unwrap();
    assert_eq!(
        reconciliation.status,
        OperationStatus::ReconciliationRequired
    );
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &submitted.operation_id, TX_HASH, 510)
        .unwrap();
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &submitted.operation_id, mobile.device_id(), 511)
        .await
        .unwrap();
    assert_eq!(
        final_anchor.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::ReconciledFinal
    );
    let final_receipt = signed_receipt(&final_anchor, &mobile, 512).await;
    let committed = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, final_receipt, 513)
        .await
        .unwrap();
    assert_eq!(committed.status, OperationStatus::Committed);
    assert_eq!(committed.reserved_units, HacUnits::ZERO);

    let second_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, 514).await;
    let second_proposal = manager
        .pending_rollback_anchor(&wallet_id, &second_id, mobile.device_id(), 515)
        .await
        .unwrap();

    assert_eq!(
        second_proposal.anchor.anchor_sequence,
        first_proposal.anchor.anchor_sequence + 3
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

/// This test used to assert `RecoveryRequired`, and that assertion was the
/// codified form of the trap: an anchor that expired before its receipt arrived
/// left the pending slot occupied forever, and with it the payment, every future
/// agent payment, every witness rotation and the reservation.
///
/// The expiry itself is protective and is untouched. What is asserted now is
/// that it is recoverable: the dead anchor is replaced at the same chain
/// position, and the receipt signed over the dead one is still worthless.
#[tokio::test]
async fn an_expired_pending_proposal_is_replaced_at_the_same_chain_position() {
    let (_root, mut manager, wallet_id, mobile, operation_id, proposal, receipt, node) =
        prepared_witness_flow(600).await;
    let dead_at = proposal.anchor.expires_at;
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), dead_at)
        .await
        .unwrap();

    assert_ne!(replacement.anchor.anchor_id, proposal.anchor.anchor_id);
    assert!(replacement.anchor.expires_at > dead_at);
    assert_eq!(
        replacement.anchor.anchor_sequence,
        proposal.anchor.anchor_sequence
    );
    assert_eq!(
        replacement.anchor.previous_anchor_hash,
        proposal.anchor.previous_anchor_hash
    );
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, dead_at + 1)
            .await,
        Err(AgentWalletError::RollbackDetected),
        "a receipt over the replaced anchor is not a witness for the replacement"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn node_profile_change_between_approval_and_anchor_is_rejected() {
    let node = spawn_pilot_node().await;
    let (_root, mut manager, wallet_id) = create_manager_for_node(&node.url, 700);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 702);
    let operation_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, 703).await;
    let mut changed = official_capabilities();
    changed["actions"]["registered"] = json!([1, 2]);
    changed["actions"]["enabled"] = json!([1, 2]);
    node.set_capabilities(changed).await;

    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 704)
            .await,
        Err(AgentWalletError::ApprovalCommitmentMismatch)
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
}

async fn complete_prepared_operation(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    operation_id: &OperationId,
    first_receipt: SignedWitnessReceipt,
    now: u64,
) {
    let submitted = manager
        .apply_mobile_witness_and_broadcast(wallet_id, first_receipt, now)
        .await
        .unwrap();
    let submitted_anchor = manager
        .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now + 1)
        .await
        .unwrap();
    let submitted_receipt = signed_receipt(&submitted_anchor, mobile, now + 2).await;
    let reconciliation = manager
        .apply_mobile_witness_and_broadcast(wallet_id, submitted_receipt, now + 3)
        .await
        .unwrap();
    assert_eq!(
        reconciliation.status,
        OperationStatus::ReconciliationRequired
    );
    manager
        .confirm_broadcast(
            wallet_id,
            operation_id,
            submitted.tx_hash.as_deref().unwrap(),
            now + 4,
        )
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now + 5)
        .await
        .unwrap();
    let final_receipt = signed_receipt(&final_anchor, mobile, now + 6).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(wallet_id, final_receipt, now + 7)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
}

pub(super) async fn pair_unregistered_rotation_candidate(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    rotation_id: &str,
    candidate: &SoftwareDeviceIdentity,
    now: u64,
) {
    use hpay_companion_protocol::{
        LanEndpoint, MobilePairingAttempt, RotationCandidateAcceptance,
        SignedRotationCandidateAcceptance,
    };

    let endpoint = LanEndpoint::parse("hpay-lan://192.168.1.9:42492").unwrap();
    let mut desktop_attempt = manager
        .start_rotation_candidate_pairing(wallet_id, rotation_id, vec![endpoint], now, 240)
        .unwrap();
    let mobile_attempt =
        MobilePairingAttempt::start(desktop_attempt.offer().clone(), candidate, now + 1)
            .await
            .unwrap();
    let request = mobile_attempt.request().clone();
    let (confirmation, ticket) = manager
        .accept_rotation_candidate_pairing_request(
            wallet_id,
            &mut desktop_attempt,
            request,
            now + 2,
        )
        .await
        .unwrap();
    let acceptance = RotationCandidateAcceptance::for_ticket(&ticket.ticket, now + 3).unwrap();
    let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, candidate)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, candidate, now + 3)
        .await
        .unwrap();
    drop(mobile_result);
    manager
        .accept_companion_pairing_ack(wallet_id, &mut desktop_attempt, &ack, now + 4)
        .unwrap();
    manager
        .complete_rotation_candidate_pairing_code(
            wallet_id,
            &mut desktop_attempt,
            &code,
            signed_acceptance,
            now + 4,
        )
        .unwrap();
}

#[tokio::test]
async fn normal_rotation_requires_old_authorization_new_baseline_and_completion_anchor() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(800).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        806,
    )
    .await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_normal_one".to_owned(),
            new_mobile.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            821,
        )
        .await
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 822)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingOldWitnessAuthorization)
    );
    let authorization = SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, authorization, 823)
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &new_mobile,
        824,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        829,
    )
    .unwrap();
    let baseline = SignedWitnessRotationBaselineReceipt::sign(baseline, &new_mobile)
        .await
        .unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, baseline, 829)
        .unwrap();
    let devices = manager.list_companion_devices(&wallet_id, 830).unwrap();
    assert!(
        devices
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        devices
            .iter()
            .all(|device| device.device_id != *new_mobile.device_id()),
        "candidate must not enter the active registry before final completion"
    );
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, 831)
        .await
        .unwrap();
    let completion_receipt = signed_receipt(&completion, &new_mobile, 832).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt.clone(), 832)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 833)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
    assert_eq!(
        manager
            .complete_witness_rotation(&wallet_id, completion_receipt, 833)
            .unwrap(),
        record
    );
    assert!(
        manager
            .start_companion_desktop_session(&wallet_id, old_mobile.device_id(), 834, 60,)
            .await
            .is_err(),
        "the revoked old witness phone must never authenticate after rotation"
    );
    let third_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let second_record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_normal_two".to_owned(),
            third_mobile.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            835,
        )
        .await
        .unwrap();
    assert_eq!(second_record.old_mobile_device_id, *new_mobile.device_id());
    assert_eq!(second_record.old_witness_epoch, record.new_witness_epoch);
}

#[tokio::test]
async fn restricted_candidate_survives_restart_and_can_be_safely_cancelled_before_baseline() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_100).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_106,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_cancel_before_baseline".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_121,
        )
        .await
        .unwrap();
    let authorization = SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, authorization, 1_122)
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_123,
    )
    .await;
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_128)
            .unwrap()
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_128)
            .unwrap()
            .iter()
            .all(|device| device.device_id != *candidate.device_id())
    );

    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 1_129).unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_130)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::CandidatePairedRestricted)
    );
    manager
        .cancel_witness_rotation(&wallet_id, &record.rotation_id, 1_131)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_132)
            .await
            .unwrap()
            .witness_rotation_phase,
        None
    );
    let devices = manager.list_companion_devices(&wallet_id, 1_132).unwrap();
    assert!(
        !devices
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        devices
            .iter()
            .all(|device| device.device_id != *candidate.device_id()),
        "cancelled candidate must never enter the general registry"
    );
    let retry_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_after_cancel".to_owned(),
            retry_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_133,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn cancellation_is_blocked_after_baseline_authority_transition() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_200).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_206,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_cancel_blocked".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_221,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_222,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_223,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        1_228,
    )
    .unwrap();
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
                .await
                .unwrap(),
            1_228,
        )
        .unwrap();
    assert_eq!(
        manager.cancel_witness_rotation(&wallet_id, &record.rotation_id, 1_229),
        Err(AgentWalletError::InvalidOperationState)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_230)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked(),
        "old authority remains revoked after the transition"
    );
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_230)
            .unwrap(),
        "candidate remains restricted until the completion receipt"
    );
}

/// Dead end 1: `AwaitingCompletionAnchor` with the replacement phone gone.
///
/// Before the re-target this state had no exit at all. `cancel_witness_rotation`
/// refuses twice over, the desktop hides the start form while a rotation is
/// active, and `create_payment_intent` refuses every agent write meanwhile, so
/// the wallet is stopped for good on a phone that will never come back.
#[tokio::test]
async fn stranded_completion_anchor_can_be_retargeted_to_another_replacement_phone() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(2_400).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        2_406,
    )
    .await;
    let lost_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_stranded".to_owned(),
            lost_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            2_421,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            2_422,
        )
        .unwrap();
    let controls = manager
        .witness_rotation_controls(&wallet_id, 2_422)
        .unwrap();
    assert!(
        controls.cancellable && !controls.retargetable,
        "a rotation that can still be cancelled must not offer the re-target"
    );
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &lost_candidate,
        2_423,
    )
    .await;
    let controls = manager
        .witness_rotation_controls(&wallet_id, 2_423)
        .unwrap();
    assert!(
        controls.cancellable && !controls.retargetable,
        "CandidatePairedRestricted still has cancel, so it is not stranded"
    );
    let abandoned_baseline = SignedWitnessRotationBaselineReceipt::sign(
        WitnessRotationBaselineReceipt::for_rotation(
            &record,
            record.canonical_sha256_hex().unwrap(),
            2_428,
        )
        .unwrap(),
        &lost_candidate,
    )
    .await
    .unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, abandoned_baseline.clone(), 2_428)
        .unwrap();

    // The exact dead end: past the authority transition there is no cancel and
    // no other desktop control.
    assert_eq!(
        manager.cancel_witness_rotation(&wallet_id, &record.rotation_id, 2_429),
        Err(AgentWalletError::InvalidOperationState)
    );
    let controls = manager
        .witness_rotation_controls(&wallet_id, 2_429)
        .unwrap();
    assert!(
        !controls.cancellable && controls.retargetable,
        "the stranded phase has no cancel and is exactly where the re-target is offered"
    );

    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let retargeted = manager
        .retarget_witness_rotation(
            &wallet_id,
            &record.rotation_id,
            "rotation_stranded_retarget".to_owned(),
            replacement.device_id(),
            2_430,
        )
        .unwrap();
    assert_eq!(
        manager
            .retarget_witness_rotation(
                &wallet_id,
                &record.rotation_id,
                "rotation_stranded_retarget".to_owned(),
                replacement.device_id(),
                2_431,
            )
            .unwrap(),
        retargeted,
        "an exact re-target retry is idempotent"
    );
    assert_eq!(
        manager
            .overview(&wallet_id, 2_431)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingCandidatePairing)
    );
    // The epoch is never rolled back, so the abandoned candidate's epoch is
    // burned rather than reusable.
    assert_eq!(retargeted.old_witness_epoch, record.new_witness_epoch);
    assert_eq!(
        retargeted.new_witness_epoch,
        record.new_witness_epoch.checked_add(1).unwrap()
    );
    assert_eq!(retargeted.old_mobile_device_id, *old_mobile.device_id());
    assert!(
        manager
            .list_companion_devices(&wallet_id, 2_431)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked(),
        "the re-target never un-revokes the old phone"
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 2_431)
            .unwrap()
            .iter()
            .all(|device| device.device_id != *lost_candidate.device_id()),
        "the abandoned candidate is discarded and never registered"
    );
    assert_eq!(
        manager.accept_witness_rotation_baseline(&wallet_id, abandoned_baseline.clone(), 2_432),
        Err(AgentWalletError::InvalidOperationState),
        "the abandoned candidate's baseline is refused while a new candidate is being paired"
    );

    // The replacement finishes the rotation exactly as any candidate would: a
    // real baseline receipt and a real witness receipt over the exact anchor.
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &retargeted.rotation_id,
        &replacement,
        2_433,
    )
    .await;
    assert_eq!(
        manager.accept_witness_rotation_baseline(&wallet_id, abandoned_baseline, 2_434),
        Err(AgentWalletError::RotationBaselineReceiptInvalid),
        "the abandoned candidate's baseline can never be replayed onto the new attempt"
    );
    let baseline = SignedWitnessRotationBaselineReceipt::sign(
        WitnessRotationBaselineReceipt::for_rotation(
            &retargeted,
            retargeted.canonical_sha256_hex().unwrap(),
            2_438,
        )
        .unwrap(),
        &replacement,
    )
    .await
    .unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, baseline, 2_438)
        .unwrap();
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &retargeted.rotation_id, 2_439)
        .await
        .unwrap();
    assert_eq!(completion.anchor.mobile_device_id, *replacement.device_id());
    assert_eq!(
        completion.anchor.witness_epoch,
        retargeted.new_witness_epoch
    );
    let completion_receipt = signed_receipt(&completion, &replacement, 2_440).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt, 2_440)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 2_441)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
    // The wallet is usable again: a further rotation can be prepared, which is
    // only reachable from a phase that permits agent writes.
    let fourth = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let next = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_after_retarget".to_owned(),
            fourth.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            2_442,
        )
        .await
        .unwrap();
    assert_eq!(next.old_mobile_device_id, *replacement.device_id());
    assert_eq!(next.old_witness_epoch, retargeted.new_witness_epoch);
}

/// A completion receipt already exists, so nothing is stranded and the escape
/// that discards a candidate must not be offered.
#[tokio::test]
async fn completed_rotation_is_never_retargetable() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(2_500).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        2_506,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_completed_no_retarget".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            2_521,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            2_522,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        2_523,
    )
    .await;
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(
                WitnessRotationBaselineReceipt::for_rotation(
                    &record,
                    record.canonical_sha256_hex().unwrap(),
                    2_528,
                )
                .unwrap(),
                &candidate,
            )
            .await
            .unwrap(),
            2_528,
        )
        .unwrap();
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, 2_529)
        .await
        .unwrap();
    manager
        .complete_witness_rotation(
            &wallet_id,
            signed_receipt(&completion, &candidate, 2_530).await,
            2_530,
        )
        .unwrap();
    let controls = manager
        .witness_rotation_controls(&wallet_id, 2_531)
        .unwrap();
    assert!(!controls.cancellable && !controls.retargetable);
    let other = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        manager.retarget_witness_rotation(
            &wallet_id,
            &record.rotation_id,
            "rotation_completed_retarget_attempt".to_owned(),
            other.device_id(),
            2_531,
        ),
        Err(AgentWalletError::InvalidOperationState)
    );
}

#[tokio::test]
async fn restart_after_durable_baseline_completes_old_device_revocation_once() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_240).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_246,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_restart_after_baseline".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_261,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_262,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_263,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        1_268,
    )
    .unwrap();
    let signed_baseline = SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
        .await
        .unwrap();

    // Simulate a process loss after the baseline checkpoint was durably
    // authenticated but before the old-device revocation checkpoint.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.witness_rotation.as_mut().unwrap().new_mobile_baseline = Some(signed_baseline.clone());
    state.updated_at = 1_268;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::WitnessRotationBaselineAccepted,
            None,
            Some(candidate.device_id().as_str().as_bytes()),
            1_268,
        )
        .unwrap();
    drop(manager);

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 1_269).unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, signed_baseline.clone(), 1_270)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_271)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingCompletionAnchor)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_271)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_271)
            .unwrap()
    );
    assert_eq!(
        manager
            .accept_witness_rotation_baseline(&wallet_id, signed_baseline, 1_272)
            .unwrap(),
        record,
        "replaying the same durable baseline must be idempotent"
    );
}

#[tokio::test]
async fn rotation_ticket_is_single_use_and_blocks_concurrent_candidate_scan() {
    use hpay_companion_protocol::{
        LanEndpoint, MobilePairingAttempt, RotationCandidateAcceptance,
        SignedRotationCandidateAcceptance, SignedWitnessRotationAuthorization, WitnessRotationMode,
        WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_300).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_306,
    )
    .await;
    let first_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let second_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_single_use".to_owned(),
            first_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_321,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_322,
        )
        .unwrap();

    let endpoint = LanEndpoint::parse("hpay-lan://192.168.1.9:42492").unwrap();
    let mut desktop_attempt = manager
        .start_rotation_candidate_pairing(
            &wallet_id,
            &record.rotation_id,
            vec![endpoint.clone()],
            1_323,
            240,
        )
        .unwrap();
    let mobile_attempt =
        MobilePairingAttempt::start(desktop_attempt.offer().clone(), &first_candidate, 1_324)
            .await
            .unwrap();
    let (confirmation, ticket) = manager
        .accept_rotation_candidate_pairing_request(
            &wallet_id,
            &mut desktop_attempt,
            mobile_attempt.request().clone(),
            1_325,
        )
        .await
        .unwrap();
    assert!(
        manager
            .start_rotation_candidate_pairing(
                &wallet_id,
                &record.rotation_id,
                vec![endpoint],
                1_326,
                240,
            )
            .is_err(),
        "a second candidate cannot race an already-issued ticket"
    );
    let acceptance = RotationCandidateAcceptance::for_ticket(&ticket.ticket, 1_326).unwrap();
    let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, &first_candidate)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (ack, result) = mobile_attempt
        .confirm(&confirmation, &code, &first_candidate, 1_326)
        .await
        .unwrap();
    let candidate_record = result.mobile_device_record.clone();
    drop(result);
    manager
        .accept_companion_pairing_ack(&wallet_id, &mut desktop_attempt, &ack, 1_327)
        .unwrap();
    manager
        .complete_rotation_candidate_pairing_code(
            &wallet_id,
            &mut desktop_attempt,
            &code,
            signed_acceptance.clone(),
            1_327,
        )
        .unwrap();
    // THE SAME DELIVERY ARRIVING TWICE IS NOT A REPLAY, AND IS NOT AN ERROR.
    //
    // The candidate handset persists this exact acceptance BEFORE it hands it
    // over, so a crash on either side - or the desktop scanning the QR twice,
    // which is the ordinary case - presents it again. Nothing is consumed and
    // nothing is journalled the second time; the durable state already says this.
    assert_eq!(
        manager.accept_rotation_candidate(
            &wallet_id,
            &record.rotation_id,
            candidate_record.clone(),
            signed_acceptance.clone(),
            1_328,
        ),
        Ok(()),
        "the acceptance already durable here is accepted again unchanged"
    );

    // A DIFFERENT ACCEPTANCE FOR THE SAME CONSUMED TICKET IS STILL REFUSED.
    let other = RotationCandidateAcceptance::for_ticket(&ticket.ticket, 1_329).unwrap();
    let other_signed = SignedRotationCandidateAcceptance::sign(other, &first_candidate)
        .await
        .unwrap();
    assert_ne!(other_signed, signed_acceptance);
    assert_eq!(
        manager.accept_rotation_candidate(
            &wallet_id,
            &record.rotation_id,
            candidate_record,
            other_signed,
            1_330,
        ),
        Err(AgentWalletError::InvalidOperationState),
        "the consumed ticket cannot be replayed with a second acceptance"
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_329)
            .unwrap()
            .iter()
            .all(|device| device.device_id != *second_candidate.device_id())
    );
}

#[tokio::test]
async fn lost_phone_rotation_is_blocked_by_unresolved_financial_state() {
    use hpay_companion_protocol::{WitnessRotationMode, WitnessRotationReason};

    let (_root, mut manager, wallet_id, _old_mobile, _operation_id, _proposal, _receipt, _node) =
        prepared_witness_flow(900).await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &new_mobile, 906);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation_blocked".to_owned(),
                new_mobile.device_id(),
                WitnessRotationMode::LostPhoneRecovery,
                WitnessRotationReason::LostPhone,
                907,
            )
            .await,
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn lost_phone_rotation_requires_clean_state_live_node_and_new_baseline() {
    use hpay_companion_protocol::{
        SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationMode,
        WitnessRotationPhase, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(940).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        946,
    )
    .await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_lost_phone_one".to_owned(),
            new_mobile.device_id(),
            WitnessRotationMode::LostPhoneRecovery,
            WitnessRotationReason::LostPhone,
            961,
        )
        .await
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 962)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingCandidatePairing)
    );
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &new_mobile,
        963,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        968,
    )
    .unwrap();
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(baseline, &new_mobile)
                .await
                .unwrap(),
            968,
        )
        .unwrap();
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, 969)
        .await
        .unwrap();
    manager
        .complete_witness_rotation(
            &wallet_id,
            signed_receipt(&completion, &new_mobile, 970).await,
            970,
        )
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 971)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 971)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
}

/// The escape must not create a second dead end one step past the first.
///
/// `retarget_witness_rotation` leaves the rotation in AwaitingCandidatePairing
/// with the old phone already revoked, so `cancel_witness_rotation` refuses at
/// every later phase. Once a candidate is bound the pairing ticket cannot be
/// re-issued either (`require_rotation_candidate_pairing` refuses while a
/// candidate is present), so if the second replacement handset fails at the
/// pairing step - a lapsed five-minute ticket is enough - the owner used to have
/// no control at all. The re-target is offered again there, and it is a real
/// exit: this drives the rotation to a genuine completion afterwards.
#[tokio::test]
async fn a_retargeted_rotation_that_fails_at_the_pairing_step_still_has_a_way_out() {
    use hpay_companion_protocol::{
        LanEndpoint, MobilePairingAttempt, SignedWitnessRotationAuthorization,
        SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationMode,
        WitnessRotationPhase, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(5_400).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        5_406,
    )
    .await;
    let lost_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_second_strand".to_owned(),
            lost_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            5_421,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            5_422,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &lost_candidate,
        5_423,
    )
    .await;
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(
                WitnessRotationBaselineReceipt::for_rotation(
                    &record,
                    record.canonical_sha256_hex().unwrap(),
                    5_428,
                )
                .unwrap(),
                &lost_candidate,
            )
            .await
            .unwrap(),
            5_428,
        )
        .unwrap();

    let second = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let retargeted = manager
        .retarget_witness_rotation(
            &wallet_id,
            &record.rotation_id,
            "rotation_second_strand_retarget".to_owned(),
            second.device_id(),
            5_430,
        )
        .unwrap();

    // The owner starts pairing the second replacement phone. Issuing the ticket
    // is enough to bind a candidate; nothing after it has to succeed.
    let mut desktop_attempt = manager
        .start_rotation_candidate_pairing(
            &wallet_id,
            &retargeted.rotation_id,
            vec![LanEndpoint::parse("hpay-lan://192.168.1.9:42492").unwrap()],
            5_433,
            240,
        )
        .unwrap();
    let mobile_attempt =
        MobilePairingAttempt::start(desktop_attempt.offer().clone(), &second, 5_434)
            .await
            .unwrap();
    let request = mobile_attempt.request().clone();
    manager
        .accept_rotation_candidate_pairing_request(&wallet_id, &mut desktop_attempt, request, 5_435)
        .await
        .unwrap();
    drop(mobile_attempt);
    drop(desktop_attempt);

    // That phone is now gone, and its ticket has lapsed.
    assert_eq!(
        manager
            .overview(&wallet_id, 5_900)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::RotationTicketIssued)
    );
    assert_eq!(
        manager.cancel_witness_rotation(&wallet_id, &retargeted.rotation_id, 5_901),
        Err(AgentWalletError::RecoveryRequired),
        "the old phone is already revoked, so the cancel is refused for good"
    );
    assert_eq!(
        manager.require_rotation_candidate_pairing(&wallet_id, &retargeted.rotation_id, 5_902),
        Err(AgentWalletError::InvalidOperationState),
        "and the pairing ticket cannot be re-issued while a candidate is bound"
    );
    let controls = manager
        .witness_rotation_controls(&wallet_id, 5_903)
        .unwrap();
    assert!(
        !controls.cancellable && controls.retargetable,
        "so the re-target must be offered here, or the escape has built a second dead end"
    );

    // And it is a real exit, not just a live button: the third handset signs a
    // real baseline and a real completion receipt over the exact anchor.
    let third = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let again = manager
        .retarget_witness_rotation(
            &wallet_id,
            &retargeted.rotation_id,
            "rotation_second_strand_retarget_two".to_owned(),
            third.device_id(),
            5_904,
        )
        .unwrap();
    // No witness epoch is consumed by a handset that never signed a baseline.
    assert_eq!(again.old_witness_epoch, retargeted.old_witness_epoch);
    assert_eq!(again.new_witness_epoch, retargeted.new_witness_epoch);
    assert_eq!(again.old_mobile_device_id, *old_mobile.device_id());
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &again.rotation_id,
        &third,
        5_905,
    )
    .await;
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(
                WitnessRotationBaselineReceipt::for_rotation(
                    &again,
                    again.canonical_sha256_hex().unwrap(),
                    5_912,
                )
                .unwrap(),
                &third,
            )
            .await
            .unwrap(),
            5_912,
        )
        .unwrap();
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &again.rotation_id, 5_913)
        .await
        .unwrap();
    assert_eq!(completion.anchor.mobile_device_id, *third.device_id());
    let completion_receipt = signed_receipt(&completion, &third, 5_914).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt, 5_914)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 5_915)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
}

/// A rotation whose old phone is still active keeps the ordinary cancel and is
/// never offered the destructive escape. This is the "changed nothing, sees
/// nothing new" case for the phases the re-target now also covers.
#[tokio::test]
async fn a_healthy_rotation_is_never_offered_the_retarget_at_the_pairing_phases() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, WitnessRotationMode, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(6_400).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        6_406,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_healthy".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            6_421,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            6_422,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        6_423,
    )
    .await;
    let controls = manager
        .witness_rotation_controls(&wallet_id, 6_430)
        .unwrap();
    assert!(
        controls.cancellable && !controls.retargetable,
        "the old phone is still active, so the ordinary cancel is the way out"
    );
    manager
        .cancel_witness_rotation(&wallet_id, &record.rotation_id, 6_431)
        .unwrap();
}
