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
