use std::collections::BTreeSet;

use super::*;
use crate::identity::SoftwareDeviceIdentity;

const GENESIS: &str = "11b008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
const NODE_PROFILE: &str = "22b008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

type Fixture = (
    SoftwareDeviceIdentity,
    SoftwareDeviceIdentity,
    DeviceRegistry,
    MobileWitnessState,
    RollbackAnchor,
);

fn fixture(now: u64) -> Fixture {
    let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let wallet_id = "wallet_testnet_one";
    let mut registry = DeviceRegistry::new();
    registry
        .register(
            desktop
                .public_record(wallet_id, BTreeSet::new(), now - 10)
                .unwrap(),
        )
        .unwrap();
    registry
        .register(
            mobile
                .public_record(
                    wallet_id,
                    BTreeSet::from([DevicePermission::WitnessRollbackAnchor]),
                    now - 10,
                )
                .unwrap(),
        )
        .unwrap();
    let state = MobileWitnessState::new(
        wallet_id.to_owned(),
        desktop.device_id().clone(),
        mobile.device_id().clone(),
        "testnet".to_owned(),
        GENESIS.to_owned(),
        1,
        1,
        1,
    )
    .unwrap();
    let anchor = RollbackAnchor {
        anchor_version: 1,
        anchor_id: "anchor_one".to_owned(),
        agent_wallet_id: wallet_id.to_owned(),
        desktop_device_id: desktop.device_id().clone(),
        mobile_device_id: mobile.device_id().clone(),
        desktop_authorization_epoch: 1,
        mobile_authorization_epoch: 1,
        network_id: "testnet".to_owned(),
        genesis_identifier: GENESIS.to_owned(),
        node_profile_id: NODE_PROFILE.to_owned(),
        transaction_format_version: 2,
        signer_epoch: 1,
        journal_epoch: 1,
        witness_epoch: 1,
        anchor_sequence: 1,
        previous_anchor_hash: ZERO_HASH.to_owned(),
        journal_sequence: 7,
        journal_head_hash: "33".repeat(32),
        materialized_state_commitment: "44".repeat(32),
        last_operation_id: Some("operation_one".to_owned()),
        operation_phase: RollbackOperationPhase::SignedAwaitingWitness,
        transaction_state: None,
        policy_epoch: 1,
        capability_epoch: 1,
        created_at: now - 1,
        expires_at: now + 60,
    };
    (desktop, mobile, registry, state, anchor)
}

#[tokio::test]
async fn canonical_anchor_and_receipt_round_trip_deterministically() {
    let (desktop, mobile, registry, mut state, anchor) = fixture(100);
    let bytes = anchor.canonical_bytes().unwrap();
    assert_eq!(
        RollbackAnchor::from_canonical_bytes(&bytes).unwrap(),
        anchor
    );
    assert_eq!(anchor.canonical_bytes().unwrap(), bytes);
    let signed = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    let receipt = state.accept_anchor(&signed, &registry, 100).unwrap();
    let receipt_bytes = receipt.canonical_bytes().unwrap();
    assert_eq!(
        WitnessReceipt::from_canonical_bytes(&receipt_bytes).unwrap(),
        receipt
    );
    let signed_receipt = SignedWitnessReceipt::sign(receipt, &mobile).await.unwrap();
    signed_receipt.verify(&signed, &registry, 100).unwrap();
}

#[tokio::test]
async fn invalid_desktop_and_mobile_signatures_fail_closed() {
    let (desktop, mobile, registry, mut state, anchor) = fixture(100);
    let other_desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
    assert!(matches!(
        SignedRollbackAnchor::sign(anchor.clone(), &other_desktop).await,
        Err(CompanionError::WalletScopeMismatch)
    ));
    let signed = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    let receipt = state.accept_anchor(&signed, &registry, 100).unwrap();
    let other_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert!(matches!(
        SignedWitnessReceipt::sign(receipt.clone(), &other_mobile).await,
        Err(CompanionError::WalletScopeMismatch)
    ));
    let mut invalid = SignedWitnessReceipt::sign(receipt, &mobile).await.unwrap();
    // Guaranteed to differ: a fixed "00" leaves a signature that already starts
    // with those digits untouched, and it then verifies.
    let replacement = if invalid.signature_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    invalid.signature_hex.replace_range(0..2, replacement);
    assert_eq!(
        invalid.verify(&signed, &registry, 100),
        Err(CompanionError::InvalidSignature)
    );
}

#[tokio::test]
async fn every_critical_anchor_field_is_signature_bound() {
    let (desktop, _, registry, _, anchor) = fixture(100);
    let signed = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    let mut changed = signed.clone();
    changed.anchor.network_id = "mainnet".to_owned();
    assert!(changed.verify(&registry, 100).is_err());
    let mut changed = signed.clone();
    changed.anchor.agent_wallet_id = "wallet_other".to_owned();
    assert!(changed.verify(&registry, 100).is_err());
    let mut changed = signed.clone();
    changed.anchor.journal_head_hash = "55".repeat(32);
    assert!(changed.verify(&registry, 100).is_err());
    let mut changed = signed;
    changed.anchor.materialized_state_commitment = "66".repeat(32);
    assert!(changed.verify(&registry, 100).is_err());
}

#[tokio::test]
async fn duplicate_decreasing_gap_and_wrong_previous_hash_are_rejected() {
    let (desktop, _, registry, mut state, anchor) = fixture(100);
    let first = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    state.accept_anchor(&first, &registry, 100).unwrap();
    assert_eq!(
        state.accept_anchor(&first, &registry, 100),
        Err(CompanionError::SequenceReplay)
    );

    let mut stale = first.anchor.clone();
    stale.anchor_id = "anchor_stale".to_owned();
    assert_eq!(
        state.accept_anchor(
            &SignedRollbackAnchor::sign(stale, &desktop).await.unwrap(),
            &registry,
            100
        ),
        Err(CompanionError::RollbackDetected)
    );

    let mut gap = first.anchor.clone();
    gap.anchor_id = "anchor_gap".to_owned();
    gap.anchor_sequence = 3;
    gap.previous_anchor_hash = state.last_anchor_hash.clone();
    gap.journal_sequence = 8;
    gap.journal_head_hash = "77".repeat(32);
    assert_eq!(
        state.accept_anchor(
            &SignedRollbackAnchor::sign(gap, &desktop).await.unwrap(),
            &registry,
            100
        ),
        Err(CompanionError::AnchorChainMismatch)
    );

    let mut wrong_previous = first.anchor;
    wrong_previous.anchor_id = "anchor_two".to_owned();
    wrong_previous.anchor_sequence = 2;
    wrong_previous.previous_anchor_hash = "88".repeat(32);
    wrong_previous.journal_sequence = 8;
    wrong_previous.journal_head_hash = "77".repeat(32);
    assert_eq!(
        state.accept_anchor(
            &SignedRollbackAnchor::sign(wrong_previous, &desktop)
                .await
                .unwrap(),
            &registry,
            100
        ),
        Err(CompanionError::AnchorChainMismatch)
    );
}

#[tokio::test]
async fn expired_epoch_mismatch_and_revoked_desktop_are_rejected() {
    let (desktop, _, mut registry, mut state, mut anchor) = fixture(100);
    anchor.expires_at = 100;
    let expired = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    assert_eq!(
        state.accept_anchor(&expired, &registry, 100),
        Err(CompanionError::Expired)
    );

    anchor.expires_at = 160;
    anchor.signer_epoch = 2;
    let wrong_epoch = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    assert_eq!(
        state.accept_anchor(&wrong_epoch, &registry, 100),
        Err(CompanionError::AuthorizationEpochMismatch)
    );

    registry.revoke(desktop.device_id(), 101).unwrap();
    let revoked = SignedRollbackAnchor::sign(
        RollbackAnchor {
            signer_epoch: 1,
            ..anchor
        },
        &desktop,
    )
    .await
    .unwrap();
    assert!(state.accept_anchor(&revoked, &registry, 100).is_err());
}

#[tokio::test]
async fn revoked_mobile_or_changed_receipt_cannot_authorize_witness() {
    let (desktop, mobile, mut registry, mut state, anchor) = fixture(100);
    let signed = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    let receipt = state.accept_anchor(&signed, &registry, 100).unwrap();
    let mut changed = SignedWitnessReceipt::sign(receipt, &mobile).await.unwrap();
    changed.receipt.anchor_hash = "aa".repeat(32);
    assert_eq!(
        changed.verify(&signed, &registry, 100),
        Err(CompanionError::AnchorCommitmentMismatch)
    );
    registry.revoke(mobile.device_id(), 101).unwrap();
    assert!(changed.verify(&signed, &registry, 100).is_err());
}

#[test]
fn witness_state_has_no_silent_reset_shape() {
    let (_, _, _, mut state, _) = fixture(100);
    state.last_anchor_sequence = 4;
    state.last_anchor_hash = "aa".repeat(32);
    state.last_journal_sequence = 9;
    state.last_journal_head_hash = "bb".repeat(32);
    assert_eq!(state.validate(), Err(CompanionError::MalformedMessage));
}
#[tokio::test]
async fn persisted_witness_retry_after_biometric_failure_is_idempotent() {
    let (desktop, _, registry, mut state, anchor) = fixture(100);
    let proposal = SignedRollbackAnchor::sign(anchor, &desktop).await.unwrap();
    let receipt = state.accept_anchor(&proposal, &registry, 100).unwrap();
    let persisted = serde_json::to_vec(&state).unwrap();
    let restarted: MobileWitnessState = serde_json::from_slice(&persisted).unwrap();
    let before_retry = restarted.clone();

    let retry = restarted
        .receipt_for_accepted_anchor(&proposal, &registry, 100)
        .unwrap();
    assert_eq!(retry, receipt);
    assert_eq!(restarted, before_retry);

    let mut replayed = restarted;
    assert_eq!(
        replayed.accept_anchor(&proposal, &registry, 100),
        Err(CompanionError::SequenceReplay)
    );
}

#[tokio::test]
async fn one_sided_mobile_reset_rejects_an_advanced_desktop_anchor() {
    let (desktop, _, registry, mut progressed, first_anchor) = fixture(100);
    let mut reset_mobile = progressed.clone();
    let first = SignedRollbackAnchor::sign(first_anchor, &desktop)
        .await
        .unwrap();
    progressed.accept_anchor(&first, &registry, 100).unwrap();

    let mut second_anchor = first.anchor;
    second_anchor.anchor_id = "anchor_two".to_owned();
    second_anchor.anchor_sequence = 2;
    second_anchor.previous_anchor_hash = progressed.last_anchor_hash;
    second_anchor.journal_sequence = 8;
    second_anchor.journal_head_hash = "77".repeat(32);
    second_anchor.last_operation_id = Some("operation_two".to_owned());
    let second = SignedRollbackAnchor::sign(second_anchor, &desktop)
        .await
        .unwrap();

    assert_eq!(
        reset_mobile.accept_anchor(&second, &registry, 100),
        Err(CompanionError::AnchorChainMismatch)
    );
}

/// The first anchor a phone accepts pins the node profile and transaction
/// format; every later anchor is measured against that durable pin rather than
/// against a value the desktop supplied in the same exchange.
///
/// This is what replaces the network-binding half of the pending-approval check
/// for a payment the owner approved on the desktop instead of on the phone.
#[tokio::test]
async fn node_profile_and_transaction_format_are_pinned_on_first_use() {
    let (desktop, _, registry, mut state, anchor) = fixture(100);
    assert_eq!(state.node_profile_id, None);
    assert_eq!(state.transaction_format_version, None);
    assert_eq!(state.last_policy_epoch, None);

    let first = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    let first_hash = state
        .accept_anchor(&first, &registry, 100)
        .unwrap()
        .anchor_hash;
    assert_eq!(state.node_profile_id.as_deref(), Some(NODE_PROFILE));
    assert_eq!(state.transaction_format_version, Some(2));
    assert_eq!(state.last_policy_epoch, Some(1));

    let next = |mutate: fn(&mut RollbackAnchor)| {
        let mut next = anchor.clone();
        next.anchor_id = "anchor_two".to_owned();
        next.anchor_sequence = 2;
        next.previous_anchor_hash = first_hash.clone();
        next.journal_sequence = 8;
        next.last_operation_id = Some("operation_two".to_owned());
        mutate(&mut next);
        next
    };

    // A changed node profile is refused by the phone's own pin.
    let signed = SignedRollbackAnchor::sign(
        next(|anchor| anchor.node_profile_id = "55".repeat(32)),
        &desktop,
    )
    .await
    .unwrap();
    assert_eq!(
        state.clone().accept_anchor(&signed, &registry, 100),
        Err(CompanionError::WalletScopeMismatch)
    );

    // So is a changed transaction format version.
    let signed = SignedRollbackAnchor::sign(
        next(|anchor| anchor.transaction_format_version = 3),
        &desktop,
    )
    .await
    .unwrap();
    assert_eq!(
        state.clone().accept_anchor(&signed, &registry, 100),
        Err(CompanionError::WalletScopeMismatch)
    );

    // A policy epoch that moves backwards is a rollback.
    let mut rolled_back = state.clone();
    rolled_back.last_policy_epoch = Some(5);
    let signed = SignedRollbackAnchor::sign(next(|_| {}), &desktop)
        .await
        .unwrap();
    assert_eq!(
        rolled_back.accept_anchor(&signed, &registry, 100),
        Err(CompanionError::RollbackDetected)
    );

    // A policy epoch that moves forwards is accepted, and must be. An owner who
    // edits a spending rule while a payment is awaiting witness bumps the wallet
    // policy epoch, and `update_agent_policy_admin` cancels only pre-signing
    // operations - so refusing a higher epoch here would strand that payment for
    // good. The floor is anti-rollback, not a freeze.
    let signed = SignedRollbackAnchor::sign(next(|anchor| anchor.policy_epoch = 9), &desktop)
        .await
        .unwrap();
    state
        .clone()
        .accept_anchor(&signed, &registry, 100)
        .expect("a newer policy epoch must not strand a payment awaiting witness");

    // The unmodified continuation is still accepted.
    let signed = SignedRollbackAnchor::sign(next(|_| {}), &desktop)
        .await
        .unwrap();
    state.accept_anchor(&signed, &registry, 100).unwrap();
    assert_eq!(state.last_anchor_sequence, 2);
}

/// A phone restored from a document written before the pins existed adopts them
/// on its next anchor rather than refusing. Nothing an owner already has stops
/// working.
#[test]
fn a_witness_document_without_the_pins_still_decodes() {
    let (_, _, _, state, _) = fixture(100);
    let mut document = serde_json::to_value(&state).unwrap();
    let object = document.as_object_mut().unwrap();
    assert!(!object.contains_key("node_profile_id"));
    assert!(!object.contains_key("transaction_format_version"));
    assert!(!object.contains_key("last_policy_epoch"));
    let restored: MobileWitnessState = serde_json::from_value(document).unwrap();
    assert_eq!(restored, state);
    restored.validate().unwrap();
}

/// A phone witnessing a payment it never approved binds every field that
/// matters, against its own durable state rather than against anything the
/// desktop resupplies.
///
/// This is the replacement for the pending-approval comparison, tested the way
/// that comparison deserved: not "a tampered anchor fails signature check",
/// which is trivially true, but "the desktop itself, legitimately re-signing,
/// cannot move any of these". Each mutation below is a fresh, validly signed
/// anchor from the real desktop key.
#[tokio::test]
async fn a_phone_that_never_approved_still_rejects_every_altered_anchor_field() {
    let (desktop, _, registry, mut state, anchor) = fixture(100);

    // The phone's first anchor. Nothing here came from an approval on this
    // handset; the pins are adopted from this anchor and enforced from now on.
    let first = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    let first_hash = state
        .accept_anchor(&first, &registry, 100)
        .unwrap()
        .anchor_hash;

    let continuation = {
        let mut next = anchor.clone();
        next.anchor_id = "anchor_two".to_owned();
        next.anchor_sequence = 2;
        next.previous_anchor_hash = first_hash.clone();
        next.journal_sequence = 8;
        next.last_operation_id = Some("operation_two".to_owned());
        next
    };

    // Sanity: the honest continuation is accepted, so every refusal below is
    // caused by the one field it changes and nothing else.
    let signed = SignedRollbackAnchor::sign(continuation.clone(), &desktop)
        .await
        .unwrap();
    state
        .clone()
        .accept_anchor(&signed, &registry, 100)
        .expect("the unmodified continuation must be accepted");

    #[allow(clippy::type_complexity)]
    let mutations: Vec<(&str, fn(&mut RollbackAnchor))> = vec![
        ("agent_wallet_id", |anchor| {
            anchor.agent_wallet_id = "wallet_other".to_owned()
        }),
        ("network_id", |anchor| {
            anchor.network_id = crate::HPAY_LOCAL_PILOT_NETWORK_ID.to_owned()
        }),
        ("genesis_identifier", |anchor| {
            anchor.genesis_identifier = "66".repeat(32)
        }),
        ("node_profile_id", |anchor| {
            anchor.node_profile_id = "55".repeat(32)
        }),
        ("transaction_format_version", |anchor| {
            anchor.transaction_format_version = 3
        }),
        ("signer_epoch", |anchor| anchor.signer_epoch = 2),
        ("journal_epoch", |anchor| anchor.journal_epoch = 2),
        ("witness_epoch", |anchor| anchor.witness_epoch = 2),
        ("anchor_sequence", |anchor| anchor.anchor_sequence = 3),
        ("previous_anchor_hash", |anchor| {
            anchor.previous_anchor_hash = "77".repeat(32)
        }),
        ("journal_sequence", |anchor| anchor.journal_sequence = 6),
    ];

    for (name, mutate) in mutations {
        let mut altered = continuation.clone();
        mutate(&mut altered);
        let signed = SignedRollbackAnchor::sign(altered, &desktop).await.unwrap();
        // Genuinely signed by the paired desktop key, so no refusal below is a
        // signature failure. Wallet and device scope are caught by the
        // registry-bound `verify`; everything else is caught by state this
        // phone holds and the desktop cannot reach.
        assert!(
            state
                .clone()
                .accept_anchor(&signed, &registry, 100)
                .is_err(),
            "a changed {name} must be refused by the phone's durable witness state"
        );
    }

    // A journal head that changes without the sequence moving is a rewrite of
    // history the phone has already seen.
    let mut rewritten = continuation.clone();
    rewritten.journal_sequence = 7;
    rewritten.journal_head_hash = "88".repeat(32);
    let signed = SignedRollbackAnchor::sign(rewritten, &desktop)
        .await
        .unwrap();
    assert_eq!(
        state.clone().accept_anchor(&signed, &registry, 100),
        Err(CompanionError::RollbackDetected)
    );

    // And the same anchor twice is a replay.
    assert_eq!(
        state.accept_anchor(&first, &registry, 100),
        Err(CompanionError::SequenceReplay)
    );
}

/// A REPLACEMENT FOR A DEAD ANCHOR IS AN ORDINARY ANCHOR TO THE PHONE.
///
/// When an anchor expires before its receipt comes back, the desktop rebuilds it
/// at the same chain position with a new id and a new window. To a phone that
/// never durably accepted the dead one, that is simply the first anchor it has
/// seen, and every check it has always made still applies: a field altered after
/// signing is refused, a field altered and re-signed off this phone's own
/// durable pins is refused, and the receipt it does sign is bound to the
/// replacement and to nothing else.
#[tokio::test]
async fn a_replacement_for_a_dead_anchor_is_accepted_and_still_fully_checked() {
    let (desktop, mobile, registry, mut state, anchor) = fixture(100);
    let dead = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    let expired_at = anchor.expires_at;
    assert!(matches!(
        dead.verify(&registry, expired_at),
        Err(CompanionError::Expired)
    ));

    let mut replacement = anchor.clone();
    replacement.anchor_id = "anchor_two".to_owned();
    replacement.created_at = expired_at;
    replacement.expires_at = expired_at + 300;

    // Altered after signing: the desktop signature no longer covers it.
    let mut forged = SignedRollbackAnchor::sign(replacement.clone(), &desktop)
        .await
        .unwrap();
    forged.anchor.materialized_state_commitment = "55".repeat(32);
    assert!(
        state
            .clone()
            .accept_anchor(&forged, &registry, expired_at)
            .is_err()
    );

    // Altered and honestly re-signed, but off this phone's own durable chain: a
    // replacement that quietly took the next chain position instead of the one
    // it replaced. The phone is still at zero and will not follow it.
    let mut wrong_chain = replacement.clone();
    wrong_chain.anchor_sequence = anchor.anchor_sequence + 1;
    wrong_chain.previous_anchor_hash = "66".repeat(32);
    let wrong_chain = SignedRollbackAnchor::sign(wrong_chain, &desktop)
        .await
        .unwrap();
    assert!(matches!(
        state
            .clone()
            .accept_anchor(&wrong_chain, &registry, expired_at),
        Err(CompanionError::AnchorChainMismatch)
    ));

    // Altered and honestly re-signed, but off this phone's own wallet scope.
    let mut wrong_wallet = replacement.clone();
    wrong_wallet.genesis_identifier = "77".repeat(32);
    let wrong_wallet = SignedRollbackAnchor::sign(wrong_wallet, &desktop)
        .await
        .unwrap();
    assert!(matches!(
        state
            .clone()
            .accept_anchor(&wrong_wallet, &registry, expired_at),
        Err(CompanionError::WalletScopeMismatch)
    ));

    // The genuine replacement is ordinary work, at the same chain position.
    let fresh = SignedRollbackAnchor::sign(replacement, &desktop)
        .await
        .unwrap();
    let receipt = state.accept_anchor(&fresh, &registry, expired_at).unwrap();
    assert_eq!(state.last_anchor_sequence, anchor.anchor_sequence);
    let fresh_hash = fresh.anchor.canonical_sha256_hex().unwrap();
    let dead_hash = dead.anchor.canonical_sha256_hex().unwrap();
    assert!(receipt.matches_anchor(&fresh.anchor, &fresh_hash));
    assert!(
        !receipt.matches_anchor(&dead.anchor, &dead_hash),
        "a receipt for the replacement is not a receipt for the anchor it replaced"
    );
    SignedWitnessReceipt::sign(receipt, &mobile).await.unwrap();
}

/// THE PHONE THAT ALREADY CONSUMED THE DEAD ANCHOR REFUSES EVERY REPLACEMENT.
///
/// This is the residue, executed: a phone that durably accepted an anchor and
/// then lost the reply on the way back has moved its own anti-rollback state
/// past this operation's pre-broadcast phase. A replacement at the same chain
/// position is a rollback; one chained forward re-witnesses a phase that has
/// already been witnessed. Both refusals are correct and must stay.
///
/// So no fresh pre-broadcast witness for that operation is obtainable, ever,
/// and lengthening the anchor lifetime would change none of it - the phone's
/// state advanced regardless of how wide the window was. That is why the owner
/// needs a way to give the payment up, and why the only cure for the divergence
/// itself is a witness rotation, which burns the witness epoch and resets this
/// state from a fresh baseline.
#[tokio::test]
async fn a_phone_that_already_consumed_the_dead_anchor_refuses_every_replacement() {
    let (desktop, _mobile, registry, mut state, base) = fixture(100);
    let mut anchor = base.clone();
    anchor.anchor_version = 2;
    anchor.operation_phase = RollbackOperationPhase::SignedPreBroadcast;
    anchor.transaction_state = Some(WitnessTransactionState {
        operation_id: "operation_one".to_owned(),
        agent_id: "agent_one".to_owned(),
        signed_transaction_commitment: "88".repeat(32),
        transaction_id: Some("99".repeat(32)),
        submission_status: WitnessSubmissionStatus::NotSubmitted,
        reconciliation_status: WitnessReconciliationStatus::NotStarted,
        block_height: None,
        block_hash: None,
        reservation_state: WitnessReservationState::Held,
    });
    let dead = SignedRollbackAnchor::sign(anchor.clone(), &desktop)
        .await
        .unwrap();
    let dead_hash = state
        .accept_anchor(&dead, &registry, 100)
        .unwrap()
        .anchor_hash;
    let expired_at = anchor.expires_at;

    // It cannot re-emit its own stored receipt for the dead anchor either.
    assert!(matches!(
        state.receipt_for_accepted_anchor(&dead, &registry, expired_at),
        Err(CompanionError::Expired)
    ));

    // A replacement at the same chain position is a rollback.
    let mut same_position = anchor.clone();
    same_position.anchor_id = "anchor_two".to_owned();
    same_position.created_at = expired_at;
    same_position.expires_at = expired_at + 300;
    let same_position = SignedRollbackAnchor::sign(same_position, &desktop)
        .await
        .unwrap();
    assert!(matches!(
        state
            .clone()
            .accept_anchor(&same_position, &registry, expired_at),
        Err(CompanionError::RollbackDetected)
    ));

    // Chained forward, it re-witnesses a phase that was already witnessed.
    let mut chained = anchor.clone();
    chained.anchor_id = "anchor_three".to_owned();
    chained.anchor_sequence = anchor.anchor_sequence + 1;
    chained.previous_anchor_hash = dead_hash;
    chained.created_at = expired_at;
    chained.expires_at = expired_at + 300;
    let chained = SignedRollbackAnchor::sign(chained, &desktop).await.unwrap();
    assert!(matches!(
        state.clone().accept_anchor(&chained, &registry, expired_at),
        Err(CompanionError::AnchorCommitmentMismatch)
    ));
}
