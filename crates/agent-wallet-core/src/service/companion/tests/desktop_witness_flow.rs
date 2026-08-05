//! THE OWNER HEADLINE PATH, EXECUTED: yes on the desktop, witnessed by the
//! phone, submitted to the node.
//!
//! Every other test in this crate that reaches `SignedAwaitingWitness` gets
//! there by writing that status into state by hand. Nothing does that here. The
//! agent really calls `create_payment_intent`, the node really builds the
//! unsigned body, the desktop really approves it, the wallet's own signer really
//! signs a consensus Type 2 transaction with the wallet's own key, the phone
//! really discovers the operation through the least-privilege disclosure, really
//! fetches the anchor, really signs a receipt over it, and the node really
//! receives exactly one submission.
//!
//! That matters because the desktop refusal that used to sit in
//! `approve_desktop_and_broadcast` was justified entirely by what would happen
//! after it. Removing it on the strength of reading the downstream code would
//! repeat the mistake it was written to prevent. This file is the execution.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{
    CompanionPayload, DeviceRole, SignedRollbackAnchor, SignedWitnessReceipt,
    SoftwareDeviceIdentity, WitnessReceipt, WitnessRotationMode, WitnessRotationReason,
};

use super::fixtures::*;
use super::pilot_node::*;
use super::*;
use crate::WITNESS_PENDING_OPERATION_STATUS_NAMES;
use crate::service::AgentAuthorization;

/// The amount the agent asks for, in exact units. 10,000 units is 0.01 HAC.
pub(super) const AMOUNT_UNITS: u64 = 10_000;

/// Pairs one agent whose Approval device is the value this desktop actually
/// writes, and hands back the authorization the connector would have built for
/// it after authenticating a request.
///
/// The recipient is on the agent's allowlist, because that is the ordinary case
/// this path is for: an address the owner has already vetted. The unlisted-
/// recipient proposal path has its own tests and is not what is under test here.
fn pair_desktop_agent(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    approval_mode: ApprovalMode,
    now: u64,
) -> AgentAuthorization {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(state.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(wallet_id),
        name: "Desktop approval end-to-end agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
        identity_fingerprint: identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: now,
        authorization_epoch: 1,
        server_identity: server_identity.clone(),
    };
    let identity_key_sha256 = paired.identity_key_sha256().unwrap();
    let record = AgentRecord {
        agent_id: agent_id.clone(),
        wallet_scope: paired.wallet_scope.clone(),
        name: paired.name,
        version: paired.version,
        identity_public_key_sec1: paired.identity_public_key_sec1_hex,
        identity_fingerprint: paired.identity_fingerprint,
        identity_key_sha256: identity_key_sha256.clone(),
        server_identity,
        status: AgentStatus::Active,
        authorization_epoch: 1,
        policy: AgentPolicy {
            permissions,
            max_per_payment_units: HacUnits::new(1_000_000),
            max_daily_units: HacUnits::new(10_000_000),
            max_pending_operations: 4,
            allowed_recipients: BTreeSet::from([RECIPIENT.to_owned()]),
            blocked_recipients: BTreeSet::new(),
            allow_unlisted_recipient_with_approval: false,
            approval_mode,
            policy_epoch: state.policy_epoch,
        },
        paired_at: now,
    };
    state.agents.insert(agent_id.as_str().to_owned(), record);
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::AgentPaired,
            None,
            Some(agent_id.as_str().as_bytes()),
            now,
        )
        .unwrap();

    AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(wallet_id),
        agent_id,
        authorization_epoch: 1,
        identity_key_sha256,
        capability: AgentPermission::CreatePaymentIntent,
    }
}

pub(super) fn payment_request(idempotency_key: &str, expires_at: u64) -> AgentPaymentRequest {
    AgentPaymentRequest {
        idempotency_key: idempotency_key.to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(AMOUNT_UNITS),
        recipient: RECIPIENT.to_owned(),
        reason: "desktop approval end-to-end".to_owned(),
        expires_at,
    }
}

/// Everything up to and including the desktop's yes, executed through the real
/// public entry points and nothing else.
///
/// Returns the wallet, the witness phone and the operation the desktop signed.
pub(super) async fn desktop_approved_operation(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    MockPilotNode,
    AgentAuthorization,
) {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 3);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 4,
    );

    // HOP 1. The agent proposes. It supplies no bytes, no fee and no actions.
    let created = manager
        .create_payment_intent(
            &authorization,
            payment_request("desktop-e2e", now + 300),
            now + 5,
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    assert_eq!(
        created.status,
        OperationStatus::ApprovalRequested,
        "an agent proposal must stop at the owner"
    );
    assert_eq!(created.tx_hash, None);

    // HOP 2. The owner opens the exact-transaction review and gets back the one
    // stored commitment. This is the byte-for-byte object the Approve control
    // sends back.
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, now + 6)
        .unwrap();
    assert_eq!(approval.operation_id, operation_id.to_string());
    assert_eq!(approval.amount_units, AMOUNT_UNITS);
    assert_eq!(approval.wallet_fee_units, 0);

    // HOP 3. The owner says yes on the desktop.
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, now + 7)
        .await
        .unwrap();
    assert_eq!(
        approved.status,
        OperationStatus::SignedAwaitingWitness,
        "a desktop approval in the pilot must sign and then stop for the phone"
    );
    assert!(
        approved.tx_hash.is_some(),
        "the signer produced a real transaction hash"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "signing is not broadcasting: nothing may reach the node yet"
    );

    (
        root,
        manager,
        wallet_id,
        mobile,
        operation_id,
        node,
        authorization,
    )
}

/// What the phone is allowed to see about an operation it did not approve, read
/// off the real snapshot the desktop would answer a sync request with.
///
/// The filter itself lives in `wallet-tauri-common`
/// (`witness_pending_disclosure`), which cannot be reached from this crate. What
/// this asserts is its exact input: that the real snapshot carries one, and only
/// one, entry the filter will admit, and that the entry carries the operation id
/// `RecoverPendingWitness` needs. The permission gate and the redaction are
/// asserted on the other side, in that crate's own tests.
pub(super) fn witness_pending_activity(payload: &CompanionPayload) -> Vec<(String, String)> {
    let CompanionPayload::StatusSnapshot { activity, .. } = payload else {
        panic!("expected a status snapshot");
    };
    activity
        .iter()
        .filter(|item| WITNESS_PENDING_OPERATION_STATUS_NAMES.contains(&item.status.as_str()))
        .map(|item| (item.activity_id.clone(), item.status.clone()))
        .collect()
}

/// THE WHOLE SEQUENCE, IN ONE TEST, WITH NO STEP FAKED.
///
/// This is the test that had to pass before the desktop refusal could be
/// removed, and it is the test that fails if any hop of the path regresses.
#[tokio::test]
async fn a_desktop_approval_is_discovered_witnessed_and_submitted() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(1_000).await;

    // HOP 4. The phone discovers an operation it never approved. Before the
    // disclosure existed this list was empty and the phone had no id to ask for.
    let snapshot = manager
        .companion_status_snapshot(&wallet_id, 1_010)
        .await
        .unwrap();
    assert_eq!(
        witness_pending_activity(&snapshot),
        vec![(
            operation_id.to_string(),
            "signed_awaiting_witness".to_owned()
        )],
        "the phone must be told exactly one operation id, and only this one"
    );
    let CompanionPayload::StatusSnapshot {
        policies,
        approvals,
        ..
    } = &snapshot
    else {
        panic!("expected a status snapshot");
    };
    assert!(
        approvals.is_empty(),
        "an approved payment is no longer waiting for anyone's approval"
    );
    assert!(
        !policies.is_empty(),
        "policies are present in the unfiltered snapshot and blanked by the \
         per-device filter, not by this snapshot"
    );

    // HOP 5. The phone asks for the anchor by that id. This is exactly what the
    // desktop runs when it receives `CompanionPayload::RecoverPendingWitness`.
    let proposal: SignedRollbackAnchor = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 1_020)
        .await
        .unwrap();
    assert_eq!(
        proposal.anchor.last_operation_id.as_deref(),
        Some(operation_id.as_str())
    );
    assert_eq!(
        proposal.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::SignedPreBroadcast
    );
    assert_eq!(proposal.anchor.mobile_device_id, *mobile.device_id());
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "fetching an anchor is not a broadcast"
    );

    // HOP 6. The phone signs a real receipt over that exact anchor.
    let receipt: SignedWitnessReceipt = signed_receipt(&proposal, &mobile, 1_030).await;

    // HOP 7. The desktop accepts it and the payment proceeds.
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 1_040)
        .await
        .unwrap();
    assert_eq!(submitted.operation_id, operation_id);
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "the witnessed payment reaches the network and then waits for the \
         post-submit witness, exactly as a phone-approved one does"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "exactly one submission, after the witness and not before"
    );

    // And it is durable: a restart reads back the same operation in the same
    // place, not a payment that has to be rediscovered.
    drop(manager);
    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 1_050).unwrap();
    let persisted = restarted
        .list_operations_admin(&wallet_id, 1_051)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == operation_id)
        .unwrap();
    assert_eq!(
        persisted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(persisted.approval_mode, Some(ApprovalMode::DesktopManual));
    drop(root);
}

/// THE WITNESS REQUIREMENT IS UNCHANGED FOR A DESKTOP-APPROVED PAYMENT.
///
/// The refusal that was removed was the only thing standing between a desktop
/// approval and a signed transaction, so the guarantee that a signed transaction
/// still cannot reach the network without a real signature from the paired phone
/// over the exact anchor has to be re-proved on this path specifically, not
/// inherited from the phone-approved one.
///
/// Four ways to not be that signature are tried, on the real operation the
/// desktop just signed, and the node is asked to submit nothing until the
/// genuine receipt arrives.
#[tokio::test]
async fn a_desktop_approved_payment_still_reaches_no_node_without_a_real_phone_witness() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(2_000).await;
    let submits = node.submit_count.clone();

    // Not witnessed at all: resuming the payment on its own is refused.
    assert_eq!(
        manager
            .resume_payment(&wallet_id, &operation_id, 2_010)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackWitnessRequired,
        "a signed, unwitnessed payment must not be resumable into a broadcast"
    );
    assert_eq!(submits.load(Ordering::SeqCst), 0);

    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 2_020)
        .await
        .unwrap();
    let anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();

    // Another registered phone cannot produce a receipt for this anchor at all,
    // and cannot get one accepted by re-scoping it to itself and signing that.
    let impostor = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &impostor, 2_021);
    let honest = WitnessReceipt::for_anchor(&proposal.anchor, anchor_hash.clone(), 2_022).unwrap();
    assert!(
        SignedWitnessReceipt::sign(honest.clone(), &impostor)
            .await
            .is_err(),
        "only the phone the anchor names may witness it"
    );
    let mut rescoped = honest;
    rescoped.mobile_device_id = impostor.device_id().clone();
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(
                &wallet_id,
                SignedWitnessReceipt::sign(rescoped, &impostor)
                    .await
                    .unwrap(),
                2_023,
            )
            .await
            .is_err()
    );

    let genuine = signed_receipt(&proposal, &mobile, 2_024).await;

    // The right phone, but the hash it attests to is edited after signing.
    let mut tampered = genuine.clone();
    tampered.receipt.anchor_hash = "22".repeat(32);
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, tampered, 2_025)
            .await
            .is_err()
    );

    // The right phone, signing honestly, but over some other anchor.
    let mut wrong_anchor = genuine.clone();
    wrong_anchor.receipt.anchor_id = "anchor_not_this_one".to_owned();
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, wrong_anchor, 2_026)
            .await
            .is_err()
    );

    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, 2_027)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_id)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness,
        "a refused witness must leave the payment exactly where it was"
    );
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "nothing may reach the node without a genuine witness"
    );

    // Only the genuine receipt moves it.
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, genuine, 2_028)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(submits.load(Ordering::SeqCst), 1);
    drop(root);
}

/// A REVOKED phone must not satisfy the witness prerequisite.
///
/// `has_active_witness_device` reads the registry through the accessor that
/// still sees the revocation flag. Nothing pinned the `!is_revoked()` clause:
/// deleting it leaves every other test in this crate green while an owner whose
/// only phone has been revoked is allowed to sign a payment that nothing can
/// then witness - the precise stranding the prerequisite exists to prevent.
#[tokio::test]
async fn a_revoked_phone_does_not_satisfy_the_witness_prerequisite() {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 4_000);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 4_003);

    let (state_master, journal_key) = keys(&mut manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state
        .companion_security
        .as_mut()
        .unwrap()
        .device_registry
        .revoke(mobile.device_id(), 4_004)
        .unwrap();
    state.updated_at = 4_004;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::CompanionDeviceRevoked,
            None,
            Some(mobile.device_id().as_str().as_bytes()),
            4_004,
        )
        .unwrap();

    let authorization =
        pair_desktop_agent(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 4_005);
    let created = manager
        .create_payment_intent(&authorization, payment_request("revoked", 4_300), 4_006)
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &created.operation_id, 4_007)
        .unwrap();
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 4_008)
            .await
            .unwrap_err(),
        AgentWalletError::WitnessPhoneRequiredForApproval,
        "a revoked phone cannot witness, so it must not unlock the approval"
    );
    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, 4_009)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == created.operation_id)
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// Drives an operation out of the witness lifecycle the ordinary way, so the
/// wallet is clean and `rollback_witness` is pinned to `mobile` by a healthy
/// run rather than by hand.
async fn settle_with_witness(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    mobile: &SoftwareDeviceIdentity,
    mut now: u64,
) -> u64 {
    for _ in 0..8 {
        let view = manager
            .list_operations_admin(wallet_id, now)
            .unwrap()
            .into_iter()
            .find(|view| &view.operation_id == operation_id)
            .unwrap();
        if view.status == OperationStatus::ReconciliationRequired {
            let hash = view.tx_hash.clone().unwrap();
            manager
                .confirm_broadcast(wallet_id, operation_id, &hash, now)
                .unwrap();
            now += 2;
            continue;
        }
        if !view.status.awaits_mobile_witness() {
            return now;
        }
        let proposal = manager
            .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now)
            .await
            .unwrap();
        let receipt = signed_receipt(&proposal, mobile, now + 1).await;
        manager
            .apply_mobile_witness_and_broadcast(wallet_id, receipt, now + 2)
            .await
            .unwrap();
        now += 5;
    }
    panic!("the operation never left the witness lifecycle");
}

/// A NEWLY PAIRED PHONE DOES NOT INHERIT THE WITNESS ROLE, AND THE APPROVAL
/// MUST NOT PRETEND OTHERWISE.
///
/// `rollback_witness.mobile_device_id` is pinned to the first phone that ever
/// fetched an anchor, and only `complete_witness_rotation` moves it. An
/// ordinary revoke-and-re-pair therefore leaves a registry full of a perfectly
/// good witness phone that `pending_rollback_anchor` will refuse with
/// `RollbackDetected`.
///
/// If the approval prerequisite asked only "is some active phone in the
/// registry able to witness", it would say yes here and sign into
/// `SignedAwaitingWitness` - a status with no exit at all: no sweep expires it,
/// `prepare_witness_rotation` refuses while it exists, `create_payment_intent`
/// refuses while it exists, `reject_payment` refuses it and `resume_payment`
/// refuses it. So the prerequisite asks about the exact device that would have
/// to produce the anchor, and refuses before anything is signed.
#[tokio::test]
async fn a_phone_paired_after_the_witness_was_bound_does_not_unlock_the_approval() {
    let (root, mut manager, wallet_id, first, operation_id, node, _authorization) =
        desktop_approved_operation(7_000).await;
    let now = settle_with_witness(&mut manager, &wallet_id, &operation_id, &first, 7_020).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // The owner loses that phone, revokes it, and pairs a replacement the
    // ordinary way.
    let (state_master, journal_key) = keys(&mut manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state
        .companion_security
        .as_mut()
        .unwrap()
        .device_registry
        .revoke(first.device_id(), now)
        .unwrap();
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::CompanionDeviceRevoked,
            None,
            Some(first.device_id().as_str().as_bytes()),
            now,
        )
        .unwrap();
    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &replacement, now + 1);

    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 2,
    );
    let second = manager
        .create_payment_intent(
            &authorization,
            payment_request("re-paired", now + 400),
            now + 3,
        )
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &second.operation_id, now + 4)
        .unwrap();
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, now + 5)
            .await
            .unwrap_err(),
        AgentWalletError::WitnessPhoneRequiredForApproval,
        "a phone the anchor pin does not name cannot witness, so it must not \
         unlock the approval"
    );
    // Refused before signing, and the replacement really cannot witness.
    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, now + 6)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == second.operation_id)
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "the refused approval submits nothing"
    );
    drop(root);
}

/// THE PHONE WAS OFF WHEN THE OWNER SAID YES, AND CAME BACK A DAY LATER.
///
/// A day is past the payment's own `expires_at` and past every anchor lifetime,
/// and the desktop session has timed out and been unlocked again. None of that
/// may lose the payment: the sweep must not take a signed operation, the
/// disclosure must still name it, and the witness must still land it.
#[tokio::test]
async fn a_phone_that_reconnects_a_day_late_can_still_discover_and_witness() {
    let (root, manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(5_000).await;

    let late = 5_000 + 24 * 60 * 60;
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, late).unwrap();
    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, late)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_id)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness,
        "a signed payment awaiting witness must never be swept by its own expiry"
    );
    let snapshot = manager
        .companion_status_snapshot(&wallet_id, late + 1)
        .await
        .unwrap();
    assert_eq!(
        witness_pending_activity(&snapshot),
        vec![(
            operation_id.to_string(),
            "signed_awaiting_witness".to_owned()
        )],
        "a phone that was away must still be told which id to ask for"
    );
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), late + 2)
        .await
        .unwrap();
    let receipt = signed_receipt(&proposal, &mobile, late + 3).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, late + 4)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// THE DESKTOP DIED BETWEEN HANDING OUT THE ANCHOR AND GETTING THE RECEIPT.
///
/// The pending anchor is durable, so the same receipt is accepted after a
/// restart. And replaying that receipt afterwards must never submit twice.
#[tokio::test]
async fn the_desktop_dying_between_anchor_and_receipt_submits_once_and_only_once() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(6_000).await;
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 6_020)
        .await
        .unwrap();
    let receipt = signed_receipt(&proposal, &mobile, 6_030).await;

    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 6_040).unwrap();

    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt.clone(), 6_050)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    let _ = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 6_060)
        .await;
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        1,
        "a replayed receipt must never cause a second submission"
    );
    drop(root);
}

/// The approval mode still decides which device may approve. Removing the pilot
/// refusal did not remove the gate above it.
///
/// `MobileManual` is a mode the desktop is refused under, and it is refused with
/// `AgentPermissionDenied`, the error that has always meant "this caller may not
/// do that" - never with a message about the build.
#[tokio::test]
async fn a_mobile_only_agent_still_refuses_the_desktop() {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, 3_000);
    let authorization =
        pair_desktop_agent(&mut manager, &wallet_id, ApprovalMode::MobileManual, 3_004);
    let created = manager
        .create_payment_intent(&authorization, payment_request("mobile-only", 3_300), 3_005)
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &created.operation_id, 3_006)
        .unwrap();

    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 3_007)
            .await
            .unwrap_err(),
        AgentWalletError::AgentPermissionDenied,
        "an agent whose Approval device is a mobile mode must refuse the desktop"
    );
    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, 3_008)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == created.operation_id)
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested,
        "a refused approval writes nothing"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// THE ANCHOR DIED BEFORE THE RECEIPT CAME BACK.
///
/// A rollback anchor lives five minutes. A phone that reconnects after that -
/// a slow LAN, a locked handset, an owner who walked away - used to leave the
/// pending slot occupied by an object nothing could ever clear, and that one
/// slot then refused this payment, every future agent payment, every witness
/// rotation, and held the reservation for good.
///
/// The window is unchanged. What changed is that it is no longer one-shot: the
/// dead anchor is replaced, at the same chain position, by one built fresh from
/// current state. Everything the replacement must not do is asserted here.
#[tokio::test]
async fn an_expired_anchor_is_replaced_and_the_payment_still_lands() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(10_000).await;

    let first = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 10_020)
        .await
        .unwrap();

    // TWO LIVE ANCHORS FOR ONE OPERATION CANNOT EXIST. While the first is alive
    // it is re-served byte for byte; asking again does not mint a second.
    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 10_021)
            .await
            .unwrap(),
        first,
        "a live anchor is re-served, never replaced"
    );

    // The phone was away for the whole window and comes back after it.
    let late = first.anchor.expires_at + 1;
    let replacement = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), late)
        .await
        .unwrap();

    // THE CHAIN IS UNTOUCHED. Issuing an anchor never advanced the high-water
    // mark, so the replacement sits exactly where the dead one sat.
    assert_eq!(
        replacement.anchor.anchor_sequence, first.anchor.anchor_sequence,
        "a replacement consumes no chain position"
    );
    assert_eq!(
        replacement.anchor.previous_anchor_hash, first.anchor.previous_anchor_hash,
        "a replacement does not re-link the chain"
    );
    assert_eq!(
        replacement.anchor.witness_epoch, first.anchor.witness_epoch,
        "a replacement is not a rotation"
    );
    // And it is a different anchor, freshly dated, for the same operation and
    // the same phase.
    assert_ne!(replacement.anchor.anchor_id, first.anchor.anchor_id);
    assert!(replacement.anchor.expires_at > late);
    assert_eq!(replacement.anchor.created_at, late);
    assert_eq!(
        replacement.anchor.last_operation_id.as_deref(),
        Some(operation_id.as_str())
    );
    assert_eq!(
        replacement.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::SignedPreBroadcast
    );
    assert_eq!(
        replacement.anchor.mobile_device_id,
        *mobile.device_id(),
        "the replacement is still pinned to the same phone"
    );

    // A WITNESS IS STILL REQUIRED. Handing out a replacement is not one.
    assert_eq!(
        manager
            .resume_payment(&wallet_id, &operation_id, late + 1)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackWitnessRequired
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // AN OLD RECEIPT CANNOT BE REPLAYED AGAINST A NEW ANCHOR. This one is
    // genuine - the phone really signed it, really inside the old window - and
    // it is still not a witness for the anchor that is now outstanding.
    let stale = signed_receipt(&first, &mobile, first.anchor.expires_at - 1).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, stale, late + 2)
            .await
            .unwrap_err(),
        AgentWalletError::RollbackDetected
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "a receipt for a dead anchor must never reach the node"
    );

    // The real one lands, and the payment the owner already approved is not lost.
    let receipt = signed_receipt(&replacement, &mobile, late + 3).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, late + 4)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// THE SAME THING ACROSS A RESTART, AND WITHOUT THE OWNER TOUCHING ANYTHING.
///
/// The pending anchor is durable, so the trap survived lock, unlock and process
/// restart. So must the recovery: the phone that comes back fifteen months
/// later is handed a live anchor and the payment finishes.
#[tokio::test]
async fn a_wallet_restarted_long_after_the_anchor_died_still_recovers_itself() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(13_000).await;
    let dead = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 13_020)
        .await
        .unwrap();

    let much_later = dead.anchor.expires_at + 15 * 30 * 24 * 60 * 60;
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();

    assert_eq!(
        manager
            .list_operations_admin(&wallet_id, much_later)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_id)
            .unwrap()
            .status,
        OperationStatus::SignedAwaitingWitness
    );
    let proposal = manager
        .pending_rollback_anchor(
            &wallet_id,
            &operation_id,
            mobile.device_id(),
            much_later + 1,
        )
        .await
        .unwrap();
    assert_eq!(proposal.anchor.anchor_sequence, dead.anchor.anchor_sequence);
    let receipt = signed_receipt(&proposal, &mobile, much_later + 2).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, much_later + 3)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(root);
}

/// THE RESIDUE THE REPLACEMENT CANNOT RESCUE, AND THE OWNER WAY OUT OF IT.
///
/// If the phone durably accepted the dead anchor before the reply was lost, its
/// own anti-rollback state has moved past this operation pre-broadcast phase
/// and no anchor the desktop can honestly build will ever be signed for it
/// again. That is correct behaviour on the phone side and must stay. What must
/// not stay is the owner having no way to give the payment up.
///
/// The control costs one payment and no money: `SignedAwaitingWitness` provably
/// never reached the node.
#[tokio::test]
async fn an_owner_can_abandon_a_payment_no_phone_can_witness_any_more() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(11_000).await;
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 11_020)
        .await
        .unwrap();

    // WHILE THE ANCHOR IS ALIVE THERE IS NOTHING TO ABANDON. A phone may be
    // signing it this second, so the control is not offered and not honoured.
    let live = manager
        .stranded_witness_recovery(&wallet_id, 11_021)
        .unwrap()
        .unwrap();
    assert_eq!(live.operation_id, operation_id.to_string());
    assert!(live.retryable);
    assert!(!live.abandonable);
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, 11_021)
            .unwrap_err(),
        AgentWalletError::WitnessRecoveryNotAvailable
    );

    let late = proposal.anchor.expires_at + 24 * 60 * 60;
    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, late).unwrap();

    // What the desktop puts in front of the owner before the press.
    let stranded = manager
        .stranded_witness_recovery(&wallet_id, late)
        .unwrap()
        .unwrap();
    assert_eq!(stranded.operation_id, operation_id.to_string());
    assert_eq!(stranded.amount_units, HacUnits::new(AMOUNT_UNITS));
    assert_eq!(stranded.recipient, RECIPIENT);
    assert!(stranded.anchor_issued);
    assert_eq!(stranded.anchor_expires_at, Some(proposal.anchor.expires_at));
    assert!(stranded.abandonable);
    assert!(
        stranded.retryable,
        "the phone is still worth asking first; abandoning is the second choice"
    );

    let abandoned = manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, late + 1)
        .unwrap();
    assert_eq!(abandoned.status, OperationStatus::Cancelled);
    assert_eq!(
        abandoned.reserved_units,
        HacUnits::ZERO,
        "the reservation comes back"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        0,
        "abandoning a signed payment moves no money"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, late + 2)
            .unwrap()
            .is_none()
    );

    // AN ABANDONED PAYMENT MUST NEVER LOOK WITNESSED. The receipt the phone
    // really signed for that anchor still pays nobody.
    let genuine = signed_receipt(&proposal, &mobile, proposal.anchor.created_at + 1).await;
    assert!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, genuine, late + 3)
            .await
            .is_err()
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);

    // And the agent-payment feature is alive again rather than dead forever.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-abandon", late + 400),
                late + 4,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    drop(root);
}

/// A STRANDED PAYMENT MUST NOT COST THE OWNER THEIR PHONE SLOT.
///
/// `prepare_witness_rotation` refuses while a payment is stranded, and it is
/// right to: the witness must not be rotated out from under an operation that
/// depends on it. It becomes a trap only when that operation can never resolve.
///
/// Rotation is also the only cure for a phone whose own witness state has run
/// ahead of this desktop, because the phone transaction-state progression has
/// no abandon transition and only a new witness epoch resets it. So this exit
/// has to be reachable.
#[tokio::test]
async fn abandoning_a_stranded_payment_re_opens_witness_rotation() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(12_000).await;
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 12_020)
        .await
        .unwrap();
    let late = proposal.anchor.expires_at + 1;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);

    // PAIRING A PHONE IS NEVER BLOCKED BY THIS, before or after. What a
    // stranded payment blocks is the rotation that moves the witness pin, and
    // that distinction is worth pinning: an owner told "you cannot pair a
    // phone" would go looking for the wrong escape.
    let attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), late, 60)
        .unwrap();
    manager
        .cancel_companion_pairing(&wallet_id, attempt)
        .unwrap();

    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation_after_stranded_payment".to_owned(),
                candidate.device_id(),
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone,
                late,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "the stranded payment blocks the replacement, and must not block it forever"
    );

    manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, late + 1)
        .unwrap();

    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_after_stranded_payment".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            late + 2,
        )
        .await
        .unwrap();
    assert_eq!(record.new_mobile_device_id, *candidate.device_id());
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
    drop(root);
}

/// AN OWNER WHO CHANGES NOTHING SEES NOTHING CHANGE.
///
/// The ordinary path never reaches expiry, so every status along it, and the
/// single submission at the end of it, must be exactly what the headline path
/// already asserts. The recovery query is a read: it starts a nothing and ends
/// a nothing.
///
/// It does report a payment that is waiting with no anchor outstanding as
/// abandonable, and that is deliberate rather than an accident of the
/// predicate. A phone that is lost or broken before it is ever asked strands the
/// payment exactly as thoroughly as an expired anchor does, and the owner needs
/// the same way out. Nothing is outstanding that could still become a witness,
/// so giving it up is safe; the desktop says what it costs before the press.
#[tokio::test]
async fn the_ordinary_witness_path_is_unchanged_end_to_end() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(14_000).await;

    let waiting = manager
        .stranded_witness_recovery(&wallet_id, 14_020)
        .unwrap()
        .unwrap();
    assert!(!waiting.anchor_issued);
    assert_eq!(waiting.anchor_expires_at, None);
    assert!(waiting.retryable);
    assert!(
        waiting.abandonable,
        "a phone lost before it was ever asked strands the payment just as hard"
    );

    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 14_021)
        .await
        .unwrap();
    let receipt = signed_receipt(&proposal, &mobile, 14_022).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 14_023)
            .await
            .unwrap()
            .status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);

    // A payment past the pre-broadcast witness is still waiting on the phone,
    // and the desktop now says so rather than showing nothing. What it must
    // never do is describe a submitted payment the way it describes an
    // unsubmitted one.
    let post_submit = manager
        .stranded_witness_recovery(&wallet_id, 14_024)
        .unwrap()
        .unwrap();
    assert_eq!(
        post_submit.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert!(post_submit.submitted, "the money moved and it says so");
    assert!(
        post_submit.transaction_id.is_some(),
        "and it hands over the id the owner can check on chain"
    );
    assert!(
        !post_submit.abandonable,
        "giving it up would assert the payment did not happen"
    );
    assert!(
        post_submit.retryable,
        "the phone is still the way out, and it is offered"
    );
    assert!(
        !post_submit.anchor_releasable,
        "the anchor is live; nothing may race a phone that is signing"
    );
    assert!(!post_submit.phone_replacement_unblocked);
    drop(root);
}
