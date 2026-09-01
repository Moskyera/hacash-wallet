//! THE OWNER'S DECISION, EXECUTED: a payment that completes with no phone
//! anywhere in the picture, and a witness path that is untouched for an owner
//! who asks for one.
//!
//! `desktop_witness_flow.rs` proves the phone path end to end. This file proves
//! the other half, on the same rails, through the same public entry points and
//! against the same mock node: agent intent, desktop approval, real signing of a
//! consensus Type 2 transaction, one submission, and a commit - with no
//! companion device registered, no rollback witness record, and no anchor ever
//! minted.
//!
//! It also holds the refusals that make the setting safe to change: the flip is
//! the owner's, it needs their passphrase, and it is refused while a payment is
//! mid-flight, because a payment is pinned to the answer that was current when
//! it was created and moving the answer under it is how a payment reaches a
//! status with no exit.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{DeviceRole, SoftwareDeviceIdentity};

use super::desktop_witness_flow::{AMOUNT_UNITS, pair_desktop_agent, payment_request};
use super::fixtures::{PASSPHRASE, keys};
use super::pilot_node::*;
use super::*;

/// A PAYMENT COMPLETES WITH NO PHONE.
///
/// Every hop is the real one. Nothing is written into state by hand, no status
/// is forced, and the assertions that matter are the negative ones: no companion
/// device is ever registered, `rollback_witness` stays `None` from first line to
/// last, and the payment still reaches `Committed`.
///
/// Fails without the change at the first hop that touches the witness. Under the
/// old build-time requirement `approve_desktop_and_broadcast` returned
/// `WitnessPhoneRequiredForApproval` at hop 3, before anything was signed,
/// because no phone was paired.
#[tokio::test]
async fn a_payment_completes_end_to_end_with_no_phone_paired() {
    let now = 1_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);

    // The default. Nobody has been asked anything and no phone exists.
    let overview = manager.overview(&wallet_id, now + 3).await.unwrap();
    assert!(
        !overview.rollback_witness_required,
        "a new Agent Wallet must not require a phone"
    );
    assert!(
        !overview.mobile_witness_ready,
        "no companion device is registered on this wallet"
    );

    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 4,
    );

    // HOP 1. The agent proposes. It supplies no bytes, no fee and no actions,
    // and it still stops at the owner.
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("no-phone-e2e", now + 300),
            now + 5,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    assert_eq!(
        created.status,
        OperationStatus::ApprovalRequested,
        "an agent proposal must stop at the owner whatever the witness setting says"
    );

    // HOP 2. The owner opens the exact-transaction review.
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 6)
        .unwrap();
    assert_eq!(approval.amount_units, AMOUNT_UNITS);
    assert_eq!(
        approval.approval_version, 3,
        "the approval wire format is the build's, not the setting's: a phone \
         paired to this wallet for status must still be able to read it"
    );
    assert!(
        approval.network_binding.is_some(),
        "the node binding is checked again before signing whether or not a \
         phone is involved"
    );

    // HOP 3. The owner says yes. This is the line that used to refuse.
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 7)
        .await
        .unwrap();
    assert_eq!(
        approved.status,
        OperationStatus::BroadcastSubmitted,
        "with no witness asked for, the owner's yes signs and submits in one go"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "exactly one submission"
    );
    let tx_hash = approved.tx_hash.clone().expect("a real transaction hash");

    // The submitted bytes are the wallet's own signed transaction, not a stub.
    {
        let bodies = node.submitted_bodies.read().await;
        assert_eq!(bodies.len(), 1);
        assert!(!bodies[0].is_empty());
    }

    // HOP 4. Reconciliation commits it, with no receipt from anyone.
    let committed = manager
        .confirm_broadcast(&wallet_id, &operation_id, &tx_hash, now + 8)
        .unwrap();
    assert_eq!(committed.status, OperationStatus::Committed);
    assert_eq!(committed.reserved_units, HacUnits::ZERO);

    // THE NEGATIVE ASSERTIONS. No phone was involved at any point.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(
        state.rollback_witness.is_none(),
        "no rollback witness record may be created by a payment that needs none"
    );
    assert!(
        state
            .companion_security
            .as_ref()
            .is_none_or(|companion| !companion.has_active_witness_device()),
        "no witness-capable device exists on this wallet"
    );
    drop(root);
}

/// AN OWNER WHO OPTS IN GETS EXACTLY WHAT THEY GOT BEFORE.
///
/// The same wallet, the same node, the same agent, with the setting turned on by
/// the owner and a phone paired: the approval stops at `SignedAwaitingWitness`,
/// nothing reaches the node, and an unwitnessed resume is refused. This is the
/// guarantee the default-off change must not have cost anyone.
#[tokio::test]
async fn opting_in_restores_the_witness_gate_exactly() {
    let now = 2_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);
    manager
        .set_rollback_witness_requirement(&wallet_id, PASSPHRASE, true, now + 3)
        .unwrap();
    assert!(
        manager
            .overview(&wallet_id, now + 4)
            .await
            .unwrap()
            .rollback_witness_required
    );

    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 5,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("opt-in-e2e", now + 300),
            now + 6,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 7)
        .unwrap();

    // With the setting on and no phone yet, the old refusal is back, unchanged,
    // and it still writes nothing.
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval.clone(), now + 8)
            .await
            .unwrap_err(),
        AgentWalletError::WitnessPhoneRequiredForApproval,
    );
    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, now + 9)
            .unwrap()
            .into_iter()
            .find(|operation| operation.operation_id == operation_id)
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "the refusal signs nothing and leaves the payment awaiting a decision"
    );

    // Pair the phone and the same approval goes through, and stops for it.
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 10);
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 11)
        .await
        .unwrap();
    assert_eq!(approved.status, OperationStatus::SignedAwaitingWitness);
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "an opted-in wallet still broadcasts nothing before the phone signs"
    );
    assert_eq!(
        manager
            .resume_payment(&wallet_id, &operation_id, now + 12)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackWitnessRequired,
        "there is still no self-service broadcast of an unwitnessed payment"
    );
    drop(root);
}

/// THE PINNED PHONE IS STILL THE ONLY PHONE, AFTER OPTING IN.
///
/// A second registered witness device cannot take the pinned one's place, and
/// the refusal is still `RollbackDetected`. Nothing about making the requirement
/// a setting loosened who may witness once it is on.
#[tokio::test]
async fn a_second_phone_still_cannot_witness_for_the_pinned_one() {
    let now = 3_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);
    manager
        .set_rollback_witness_requirement(&wallet_id, PASSPHRASE, true, now + 3)
        .unwrap();
    let pinned = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &pinned, now + 4);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 5,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("pin-e2e", now + 300),
            now + 6,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 7)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 8)
        .await
        .unwrap();
    // The pin is taken by the first anchor.
    manager
        .pending_rollback_anchor(&wallet_id, &operation_id, pinned.device_id(), now + 9)
        .await
        .unwrap();

    let other = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &other, now + 10);
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, other.device_id(), now + 11)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected,
        "a second paired phone is still not the pinned witness"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "nothing reached the node while the pin was being tested"
    );
    drop(root);
}

/// THE SETTING NEEDS THE OWNER'S PASSPHRASE, NOT JUST A CALL.
///
/// The command above this method is behind `require_wallet_shell`, which no
/// agent and no companion device can reach. This asserts the second, independent
/// guard: the passphrase is re-verified against the vault here, so reaching the
/// method is not enough to change what the wallet checks before it spends.
#[tokio::test]
async fn the_setting_refuses_a_wrong_passphrase_and_changes_nothing() {
    let now = 4_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);
    assert!(
        manager
            .set_rollback_witness_requirement(&wallet_id, "not the passphrase", true, now + 3)
            .is_err(),
        "the passphrase is the authority and it is checked, not taken on trust"
    );
    assert!(
        !manager
            .overview(&wallet_id, now + 4)
            .await
            .unwrap()
            .rollback_witness_required,
        "a refused change leaves the setting exactly as it was"
    );
    drop(root);
}

/// THE FLIP IS REFUSED WHILE A PAYMENT IS IN FLIGHT, AND THAT IS THE WHOLE
/// POINT.
///
/// Turning the requirement ON while a payment sits between approval and
/// broadcast is the one transition with no exit. This asserts the refusal, and
/// then asserts the property the refusal exists to protect: the in-flight
/// payment keeps the answer it was created with and still completes.
#[tokio::test]
async fn the_setting_cannot_be_moved_under_a_payment_in_flight() {
    let now = 5_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 4,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("in-flight", now + 300),
            now + 5,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();

    assert_eq!(
        manager
            .set_rollback_witness_requirement(&wallet_id, PASSPHRASE, true, now + 6)
            .unwrap_err(),
        AgentWalletError::InvalidOperationState,
        "a payment already pinned to the old answer must not have it moved"
    );

    // And the payment it protected finishes on the answer it started with.
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 7)
        .unwrap();
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 8)
        .await
        .unwrap();
    assert_eq!(approved.status, OperationStatus::BroadcastSubmitted);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// A WALLET THAT PREDATES THE SETTING, WITH A PHONE ALREADY PAIRED.
///
/// The upgrade path, and the one this nearly got wrong. `rollback_witness` is
/// written by the FIRST ANCHOR, not by pairing, so an owner who deliberately
/// paired a witness phone and has not paid yet carries the legacy shape with the
/// record still absent. Reading only that record would have derived "not
/// required" and silently switched the phone off - for an owner whose single
/// visible action was pairing it.
///
/// On the previous build that wallet required the phone, through the very
/// registry question `pinned_witness_phone_can_sign` falls back to, so that is
/// the question an undecided wallet is still asked here.
///
/// Fails without the second arm of the `None` fallback: the overview reports
/// false and the payment walks to `BroadcastSubmitted` with the phone never
/// consulted.
#[tokio::test]
async fn a_legacy_wallet_with_a_paired_phone_keeps_its_witness() {
    let now = 6_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);

    // The owner's one action: pair a phone that may witness. No anchor has ever
    // been minted, so `rollback_witness` is still absent.
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 2);

    // The legacy shape: nobody ever answered the question, because on that build
    // there was no question to answer.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.rollback_witness_required = None;
    state.updated_at = now + 3;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            now + 3,
        )
        .unwrap();
    assert!(
        state.rollback_witness.is_none(),
        "pairing alone mints no anchor, which is the whole trap"
    );

    assert!(
        manager
            .overview(&wallet_id, now + 4)
            .await
            .unwrap()
            .rollback_witness_required,
        "an undecided wallet holding a witness phone keeps the phone"
    );

    // And the payment path agrees with the overview: it stops for the phone.
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 5,
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("legacy-paired-phone", now + 300),
            now + 6,
        )
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &created.operation_id, now + 7)
        .unwrap();
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 8)
        .await
        .unwrap();
    assert_eq!(
        approved.status,
        OperationStatus::SignedAwaitingWitness,
        "the phone this owner paired is still asked before anything is broadcast"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "nothing reaches the node while the witness is outstanding"
    );
    drop(root);
}

/// A MAINNET WALLET IS NEVER ASKED FOR A WITNESS IT CANNOT GET.
///
/// The regression the paired-phone fallback nearly shipped, and the house
/// defect: a predicate written for the pilot rail applied unchanged to a
/// mainnet path.
///
/// Anchors exist on testnet only - `pending_rollback_anchor` refuses every
/// other network with `WitnessAnchorNetworkUnsupported`. Reading
/// `rollback_witness.is_some()` was accidentally safe because of that: a
/// mainnet wallet can hold no witness record, since minting one is the very
/// thing refused. Asking "is a witness phone paired" instead removed the
/// accident, and a mainnet wallet with a phone and no stored decision would
/// have derived "required", signed into `SignedAwaitingWitness`, and found the
/// anchor refused for the network - leaving the stranded-witness exit as the
/// only door out of a payment that should never have gone through it.
///
/// Fails without the network check: the overview reports true and the approval
/// stops at `SignedAwaitingWitness` instead of submitting.
#[tokio::test]
async fn a_mainnet_wallet_with_a_paired_phone_is_not_asked_for_an_anchor() {
    let now = 7_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node_without_witness(&node.url, now);

    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 2);

    // The legacy shape, on mainnet: nobody ever answered, and the network
    // cannot carry an anchor whatever the answer would have been.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.rollback_witness_required = None;
    // Moved the way `move_live_wallet_to_mainnet` does it in the live-chain
    // tests: the anchor has to move with the network, or the state stops
    // agreeing with itself and the reload refuses.
    state.network_mode = "mainnet".to_owned();
    state.block_one_fingerprint =
        crate::node_binding::anchor_for_new_wallet("mainnet", None).unwrap();
    state.trusted_mainnet_fast_pay_pilot = true;
    state.updated_at = now + 3;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            now + 3,
        )
        .unwrap();
    assert!(
        !super::super::witness_anchor_available_on_network(&state.network_mode),
        "the premise: this network mints no anchors"
    );

    assert!(
        !manager
            .overview(&wallet_id, now + 4)
            .await
            .unwrap()
            .rollback_witness_required,
        "a wallet that cannot mint an anchor must not be told it needs one"
    );

    // STOPS HERE, DELIBERATELY. Carrying this to a submitted payment would need
    // a node that reports mainnet, and this harness runs a private pilot chain -
    // `create_payment_intent` refuses it with `NodeNetworkMismatch`, correctly.
    // Asserting a mainnet submission against a node that is not on mainnet would
    // be a fiction, and the derived answer above is the whole of what regressed.
    // The submitting half is covered on the pilot rail by
    // `a_payment_completes_end_to_end_with_no_phone_paired`.
    drop(root);
}
