use std::fs;

use hpay_companion_protocol::{
    EncryptedCompanionFrame, FRAME_VERSION, LanEndpoint, MobilePairingAttempt, PairingRequest,
};

use super::fixtures::*;
use super::*;
use crate::AgentCompanionPairingAttempt;

fn enabled_manager(now: u64) -> (tempfile::TempDir, AgentWalletManager, AgentWalletId) {
    let (root, mut manager, wallet_id) = create_manager(now);
    manager
        .enable_agent_payments_locally(&wallet_id, now + 2)
        .unwrap();
    (root, manager, wallet_id)
}

async fn request_for(
    attempt: &AgentCompanionPairingAttempt,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> MobilePairingAttempt {
    MobilePairingAttempt::start(attempt.offer().clone(), mobile, now)
        .await
        .unwrap()
}

async fn acknowledged_pairing(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> (AgentCompanionPairingAttempt, String) {
    let mut attempt = manager
        .start_companion_pairing(
            wallet_id,
            vec![LanEndpoint::parse("hpay-lan://192.168.1.7:7443").unwrap()],
            now,
            60,
        )
        .unwrap();
    let mobile_attempt = request_for(&attempt, mobile, now + 1).await;
    let confirmation = manager
        .accept_companion_pairing_request(
            wallet_id,
            &mut attempt,
            mobile_attempt.request().clone(),
            now + 2,
        )
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, mobile, now + 3)
        .await
        .unwrap();
    let mobile_cipher = mobile_result.into_mobile_cipher().unwrap();
    drop(mobile_cipher);
    manager
        .accept_companion_pairing_ack(wallet_id, &mut attempt, &ack, now + 3)
        .unwrap();
    (attempt, code)
}

#[tokio::test]
async fn successful_pairing_is_durable_before_desktop_cipher_is_released() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut attempt, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    let pairing_id = attempt.offer().pairing_id.clone();

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(!serde_json::to_string(&state).unwrap().contains(&pairing_id));

    let completed = manager
        .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 107)
        .unwrap();
    assert_eq!(
        completed.mobile_device_record().device_id,
        *mobile.device_id()
    );
    assert_eq!(
        manager.list_companion_devices(&wallet_id, 108).unwrap(),
        vec![completed.mobile_device_record().clone()]
    );
    assert!(completed.into_desktop_cipher().is_ok());
}

#[tokio::test]
async fn default_suspended_wallet_can_pair_read_only_until_explicit_pause() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    assert!(
        manager
            .unlocked_status(&wallet_id, 102)
            .unwrap()
            .payments_suspended
    );
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut attempt, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    let completed = manager
        .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 107)
        .unwrap();
    assert_eq!(
        completed.mobile_device_record().device_id,
        *mobile.device_id()
    );
    drop(completed);

    manager.disable_all_agent_payments(&wallet_id, 108).unwrap();
    assert_eq!(
        manager
            .start_companion_pairing(&wallet_id, Vec::new(), 109, 60)
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );
}
#[tokio::test]
async fn restart_and_lock_invalidate_memory_only_pairing_authority() {
    let (root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut restart_attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
        .unwrap();
    let restart_mobile = request_for(&restart_attempt, &mobile, 104).await;
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 105).unwrap();
    assert_eq!(
        restarted
            .accept_companion_pairing_request(
                &wallet_id,
                &mut restart_attempt,
                restart_mobile.request().clone(),
                106,
            )
            .await
            .unwrap_err(),
        AgentWalletError::PairingSignerAuthorityChanged
    );

    let mut lock_attempt = restarted
        .start_companion_pairing(&wallet_id, Vec::new(), 107, 60)
        .unwrap();
    let lock_mobile = request_for(&lock_attempt, &mobile, 108).await;
    restarted.lock(&wallet_id, 109).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 110).unwrap();
    assert_eq!(
        restarted
            .accept_companion_pairing_request(
                &wallet_id,
                &mut lock_attempt,
                lock_mobile.request().clone(),
                111,
            )
            .await
            .unwrap_err(),
        AgentWalletError::PairingSignerAuthorityChanged
    );
}

#[tokio::test]
async fn emergency_epoch_cross_wallet_and_expiry_fail_closed() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut emergency_attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
        .unwrap();
    let emergency_mobile = request_for(&emergency_attempt, &mobile, 104).await;
    manager.disable_all_agent_payments(&wallet_id, 105).unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, 106)
        .unwrap();
    assert_eq!(
        manager
            .accept_companion_pairing_request(
                &wallet_id,
                &mut emergency_attempt,
                emergency_mobile.request().clone(),
                107,
            )
            .await
            .unwrap_err(),
        AgentWalletError::PairingStateChangedSinceStart
    );

    let mut cross_attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 108, 60)
        .unwrap();
    let cross_mobile = request_for(&cross_attempt, &mobile, 109).await;
    let other = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: "http://127.0.0.1:18081".to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
            },
            110,
        )
        .unwrap();
    manager.unlock(&other.wallet_id, PASSPHRASE, 111).unwrap();
    manager
        .enable_agent_payments_locally(&other.wallet_id, 112)
        .unwrap();
    assert_eq!(
        manager
            .accept_companion_pairing_request(
                &other.wallet_id,
                &mut cross_attempt,
                cross_mobile.request().clone(),
                113,
            )
            .await
            .unwrap_err(),
        AgentWalletError::InvalidWalletScope
    );

    let mut expired = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 114, 5)
        .unwrap();
    let expired_mobile = request_for(&expired, &mobile, 115).await;
    assert_eq!(
        manager
            .accept_companion_pairing_request(
                &wallet_id,
                &mut expired,
                expired_mobile.request().clone(),
                119,
            )
            .await
            .unwrap_err(),
        AgentWalletError::RequestExpired
    );
}

#[tokio::test]
async fn invalid_requests_consume_a_bounded_attempt_budget() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
        .unwrap();
    let mobile_attempt = request_for(&attempt, &mobile, 104).await;
    let valid = mobile_attempt.request().clone();
    let mut invalid: PairingRequest = valid.clone();
    invalid.pairing_nonce = "00".repeat(32);

    for now in 105..110 {
        assert_eq!(
            manager
                .accept_companion_pairing_request(&wallet_id, &mut attempt, invalid.clone(), now,)
                .await
                .unwrap_err(),
            AgentWalletError::PairingTranscriptMismatch
        );
    }
    assert_eq!(
        manager
            .accept_companion_pairing_request(&wallet_id, &mut attempt, valid, 110)
            .await
            .unwrap_err(),
        AgentWalletError::PairingAttemptsExhausted
    );
    assert!(
        manager
            .start_companion_pairing(&wallet_id, Vec::new(), 111, 60)
            .is_ok()
    );
}

#[tokio::test]
async fn encrypted_ack_rejects_plaintext_shape_without_consuming_valid_ack() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
        .unwrap();
    let mobile_attempt = request_for(&attempt, &mobile, 104).await;
    let confirmation = manager
        .accept_companion_pairing_request(
            &wallet_id,
            &mut attempt,
            mobile_attempt.request().clone(),
            105,
        )
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (valid_ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, &mobile, 106)
        .await
        .unwrap();
    drop(mobile_result);
    let downgraded = EncryptedCompanionFrame {
        frame_version: FRAME_VERSION,
        session_id: confirmation.session_id.clone(),
        sender_device_id: mobile.device_id().clone(),
        recipient_device_id: confirmation.desktop_device_id.clone(),
        sequence: 1,
        issued_at: 106,
        expires_at: confirmation.expires_at,
        nonce_hex: "00".repeat(12),
        ciphertext_hex: hex::encode(b"plaintext pairing proof"),
    };
    assert_eq!(
        manager
            .accept_companion_pairing_ack(&wallet_id, &mut attempt, &downgraded, 106)
            .unwrap_err(),
        AgentWalletError::PairingTranscriptMismatch
    );
    manager
        .accept_companion_pairing_ack(&wallet_id, &mut attempt, &valid_ack, 107)
        .unwrap();
    assert!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 108)
            .is_ok()
    );
}

#[tokio::test]
async fn wrong_code_can_retry_but_revoked_identity_cannot_repair() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut attempt, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut attempt, "999999", 107)
            .unwrap_err(),
        AgentWalletError::PairingVerificationCodeMismatch
    );
    let completed = manager
        .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 108)
        .unwrap();
    drop(completed);
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 109)
        .unwrap();

    let (mut replay, replay_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &mobile, 110).await;
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut replay, &replay_code, 114)
            .unwrap_err(),
        AgentWalletError::PairingDeviceRevoked
    );
    assert!(manager.list_companion_devices(&wallet_id, 115).unwrap()[0].is_revoked());
}

/// The exact sequence the owner performed on real hardware: a phone that has
/// already been paired once is paired again after "resetting both sides".
///
/// Android deliberately keeps the hardware companion identity across an app
/// reset (`hardware_identity_retained_on_reset: true`), so the second pairing
/// presents the same `device_id` and the same identity fingerprint, and only
/// `paired_at` differs. Everything up to and including the local code
/// confirmation succeeds; the durable registration is the only step left.
#[tokio::test]
async fn a_phone_that_already_paired_can_pair_again_after_the_owner_resets_both_sides() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);

    // Earlier tonight: the first pairing of this phone.
    let (mut first, first_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    manager
        .complete_companion_pairing_code(&wallet_id, &mut first, &first_code, 107)
        .unwrap();
    drop(first);

    // Control: a phone this wallet has never seen still pairs, at the same
    // timestamps and through the same calls. Whatever breaks below is not the
    // sequence, the clock, or the attempt bookkeeping.
    let never_seen = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut control, control_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &never_seen, 200).await;
    manager
        .complete_companion_pairing_code(&wallet_id, &mut control, &control_code, 204)
        .unwrap();
    drop(control);

    // The owner resets the phone app and restarts pairing on the desktop. This
    // is a first, fresh attempt with the correct code, pressed once.
    let (mut second, second_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &mobile, 300).await;
    let pairing_id = second.offer().pairing_id.clone();
    let outcome =
        manager.complete_companion_pairing_code(&wallet_id, &mut second, &second_code, 304);

    // Proof of the raising line. `complete_companion_pairing_code` releases the
    // in-memory registration slot at pairing.rs:334, which happens only after
    // `validate_pairing_attempt` (pairing.rs:426 / :439) and `confirm_code`
    // (pairing.rs:331) have both passed. If the slot is gone, execution reached
    // the `register_verified_companion_device` call at pairing.rs:339, and that
    // is the only remaining site below it that can return
    // CompanionAuthorizationFailed.
    assert!(
        !manager
            .unlocked
            .get(wallet_id.as_str())
            .unwrap()
            .active_companion_pairings
            .contains_key(&pairing_id),
        "the attempt must have passed validate_pairing_attempt and confirm_code"
    );
    let completed = outcome.unwrap_or_else(|error| {
        panic!("re-pairing a known phone failed at the durable registration step: {error:?}")
    });
    assert_eq!(
        completed.mobile_device_record().device_id,
        *mobile.device_id()
    );
}

/// Pins the origin of the error the test above hits: the durable registry
/// refuses the second record purely because `paired_at` moved, even though the
/// device identity is byte-for-byte the same one it already trusts.
#[test]
fn the_device_registry_refuses_a_second_pairing_of_the_same_hardware_identity() {
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let first = mobile
        .public_record("agw_one", mobile_permissions(), 103)
        .unwrap();
    let mut second = first.clone();
    second.paired_at = 300;

    let mut registry = DeviceRegistry::new();
    registry.register(first.clone()).unwrap();
    // Same device_id, same fingerprint, same role, same wallet, same
    // authorization epoch, same permissions. Only `paired_at` differs.
    assert_eq!(first.device_id, second.device_id);
    assert_eq!(first.identity_fingerprint, second.identity_fingerprint);
    assert_eq!(first.authorization_epoch, second.authorization_epoch);
    assert_eq!(first.permissions, second.permissions);
    assert_eq!(
        registry.register(second).unwrap_err(),
        CompanionError::DeviceAlreadyRegistered
    );
}

/// The re-pair path must not become a way around the emergency gate. A real
/// emergency stop landing between `start_companion_pairing` and the code
/// confirmation refuses the completion for a first-time phone AND for a phone
/// the wallet already trusts, and it leaves the stored record untouched.
#[tokio::test]
async fn a_real_emergency_stop_between_start_and_completion_still_refuses_the_pairing() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);

    // A phone this wallet already trusts, so the completion below takes the
    // re-pair branch rather than the first-registration branch.
    let known = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut first, first_code) = acknowledged_pairing(&mut manager, &wallet_id, &known, 103).await;
    manager
        .complete_companion_pairing_code(&wallet_id, &mut first, &first_code, 107)
        .unwrap();
    drop(first);
    let stored = manager.list_companion_devices(&wallet_id, 108).unwrap();
    assert_eq!(stored.len(), 1);

    // First-time phone: stop lands mid-pairing.
    let fresh = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut fresh_attempt, fresh_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &fresh, 200).await;
    // Re-pair of the already trusted phone: same stop, other branch.
    let (mut repair, repair_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &known, 210).await;

    manager.disable_all_agent_payments(&wallet_id, 220).unwrap();

    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut fresh_attempt, &fresh_code, 221)
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut repair, &repair_code, 222)
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );

    // Clearing the stop advances the emergency generation, so an attempt that
    // was created before it can never be completed afterwards either.
    manager
        .enable_agent_payments_locally(&wallet_id, 223)
        .unwrap();
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut fresh_attempt, &fresh_code, 224)
            .unwrap_err(),
        AgentWalletError::PairingStateChangedSinceStart
    );
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut repair, &repair_code, 225)
            .unwrap_err(),
        AgentWalletError::PairingStateChangedSinceStart
    );

    // Nothing was admitted and nothing was refreshed across the stop.
    assert_eq!(
        manager.list_companion_devices(&wallet_id, 226).unwrap(),
        stored
    );
}

/// The dedicated re-pair transition admits nothing on its own: it refuses an
/// unknown device, a revoked device, and any delta other than a forward
/// `paired_at`.
#[test]
fn the_repair_transition_refuses_admission_revival_and_every_other_delta() {
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let original = mobile
        .public_record("agw_one", mobile_permissions(), 103)
        .unwrap();

    let mut empty = DeviceRegistry::new();
    assert_eq!(
        empty
            .refresh_verified_pairing(original.clone())
            .unwrap_err(),
        CompanionError::UnknownDevice
    );

    let mut registry = DeviceRegistry::new();
    registry.register(original.clone()).unwrap();

    let mut escalated = original.clone();
    escalated.paired_at = 300;
    assert!(escalated.permissions.insert(DevicePermission::RevokeAgent));
    assert_eq!(
        registry.refresh_verified_pairing(escalated).unwrap_err(),
        CompanionError::DeviceAlreadyRegistered
    );

    let mut cross_wallet = mobile
        .public_record("agw_two", mobile_permissions(), 300)
        .unwrap();
    cross_wallet.device_id = original.device_id.clone();
    assert_eq!(
        registry.refresh_verified_pairing(cross_wallet).unwrap_err(),
        CompanionError::WalletScopeMismatch
    );

    let mut rewound = original.clone();
    rewound.paired_at = 1;
    assert_eq!(
        registry.refresh_verified_pairing(rewound).unwrap_err(),
        CompanionError::MalformedMessage
    );

    let mut epoch_moved = original.clone();
    epoch_moved.paired_at = 300;
    epoch_moved.authorization_epoch = 2;
    assert_eq!(
        registry.refresh_verified_pairing(epoch_moved).unwrap_err(),
        CompanionError::AuthorizationEpochMismatch
    );

    // Only the pairing timestamp may move, and it does.
    let mut refreshed = original.clone();
    refreshed.paired_at = 300;
    registry.refresh_verified_pairing(refreshed).unwrap();
    assert_eq!(
        registry
            .records()
            .find(|record| record.device_id == original.device_id)
            .unwrap()
            .paired_at,
        300
    );

    // A revoked device is never revived by this path.
    registry.revoke(mobile.device_id(), 400).unwrap();
    let mut revival = original.clone();
    revival.paired_at = 500;
    assert_eq!(
        registry.refresh_verified_pairing(revival).unwrap_err(),
        CompanionError::DeviceRevoked
    );
}

#[tokio::test]
async fn persistence_failure_releases_no_cipher_or_device_record() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut attempt, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    let pending_path = manager
        .storage
        .paths(&wallet_id)
        .unwrap()
        .encrypted_state_path(PENDING_STATE_NAME)
        .unwrap();
    if pending_path.exists() {
        fs::remove_file(&pending_path).unwrap();
    }
    fs::create_dir(&pending_path).unwrap();

    assert!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 107)
            .is_err()
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 108)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn active_pairing_attempts_are_bounded_and_cancel_releases_a_slot() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mut attempts = Vec::new();
    for _ in 0..4 {
        attempts.push(
            manager
                .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
                .unwrap(),
        );
    }
    assert_eq!(
        manager
            .start_companion_pairing(&wallet_id, Vec::new(), 103, 60)
            .unwrap_err(),
        AgentWalletError::RateLimited
    );
    let cancelled = attempts.remove(0);
    manager
        .cancel_companion_pairing(&wallet_id, cancelled)
        .unwrap();
    assert!(
        manager
            .start_companion_pairing(&wallet_id, Vec::new(), 104, 60)
            .is_ok()
    );
}

/// Four times in one evening the code knew exactly why a pairing was refused
/// and the owner was shown "companion device authorization failed". Each real
/// cause below now arrives as its own variant, so the panel can say what
/// happened and what to do about it.
#[tokio::test]
async fn every_pairing_refusal_arrives_as_its_own_named_reason() {
    let (root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut seen: Vec<AgentWalletError> = Vec::new();

    // 1. The owner typed, or the phone showed, a different six digit code.
    let (mut wrong_code, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    seen.push(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut wrong_code, "999999", 107)
            .unwrap_err(),
    );
    assert_eq!(seen[0], AgentWalletError::PairingVerificationCodeMismatch);

    // 2. The same attempt, completed and therefore no longer held here. The
    //    button that used to look dead now says so.
    manager
        .complete_companion_pairing_code(&wallet_id, &mut wrong_code, &code, 108)
        .unwrap();
    seen.push(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut wrong_code, &code, 109)
            .unwrap_err(),
    );
    assert_eq!(seen[1], AgentWalletError::PairingUnknownToSession);

    // 3. The phone was revoked here, so its identity cannot be re-admitted.
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 110)
        .unwrap();
    let (mut revoked, revoked_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &mobile, 111).await;
    seen.push(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut revoked, &revoked_code, 115)
            .unwrap_err(),
    );
    assert_eq!(seen[2], AgentWalletError::PairingDeviceRevoked);

    // 4. The phone answered a different pairing transcript.
    let fresh = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut transcript = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 120, 300)
        .unwrap();
    let honest = request_for(&transcript, &fresh, 121).await;
    let mut tampered = honest.request().clone();
    tampered.pairing_nonce = "00".repeat(32);
    seen.push(
        manager
            .accept_companion_pairing_request(&wallet_id, &mut transcript, tampered.clone(), 122)
            .await
            .unwrap_err(),
    );
    assert_eq!(seen[3], AgentWalletError::PairingTranscriptMismatch);

    // 5. The same attempt after its bounded budget is gone.
    for now in 123..127 {
        manager
            .accept_companion_pairing_request(&wallet_id, &mut transcript, tampered.clone(), now)
            .await
            .unwrap_err();
    }
    seen.push(
        manager
            .accept_companion_pairing_request(&wallet_id, &mut transcript, tampered, 127)
            .await
            .unwrap_err(),
    );
    assert_eq!(seen[4], AgentWalletError::PairingAttemptsExhausted);

    // 6. An emergency stop and resume between start and completion.
    let (mut across_stop, across_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &fresh, 130).await;
    manager.disable_all_agent_payments(&wallet_id, 140).unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, 141)
        .unwrap();
    seen.push(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut across_stop, &across_code, 142)
            .unwrap_err(),
    );
    assert_eq!(seen[5], AgentWalletError::PairingStateChangedSinceStart);

    // 7. A desktop restart replaces the signer authority the offer was bound to.
    let mut over_restart = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 150, 300)
        .unwrap();
    let over_restart_mobile = request_for(&over_restart, &fresh, 151).await;
    drop(manager);
    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 152).unwrap();
    seen.push(
        restarted
            .accept_companion_pairing_request(
                &wallet_id,
                &mut over_restart,
                over_restart_mobile.request().clone(),
                153,
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(seen[6], AgentWalletError::PairingSignerAuthorityChanged);

    // The whole point: seven real causes, seven different things to read.
    for (index, error) in seen.iter().enumerate() {
        assert_ne!(
            *error,
            AgentWalletError::CompanionAuthorizationFailed,
            "cause {index} is still opaque"
        );
        for (other_index, other) in seen.iter().enumerate() {
            if index != other_index {
                assert_ne!(error, other, "causes {index} and {other_index} collide");
            }
        }
    }
}

/// Every companion refusal message is read by an owner mid-pairing, so it has
/// to name an action and must never carry a code, nonce, key or fingerprint.
#[test]
fn pairing_refusal_messages_are_actionable_and_carry_no_secret() {
    // Every refusal has to end on something the owner can actually do, so the
    // last sentence must open with one of these imperatives.
    const OWNER_ACTIONS: [&str; 17] = [
        "Approve ",
        "Cancel ",
        "Choose ",
        "Compare ",
        "Finish ",
        "Make sure ",
        "Open ",
        "Reconnect ",
        "Refresh ",
        "Repeat ",
        "Reset ",
        "Restart ",
        "Revoke ",
        "Run ",
        "Start ",
        "Use ",
        "Wait ",
    ];
    let refusals = [
        AgentWalletError::PairingAlreadyRegistered,
        AgentWalletError::PairingPurposeMismatch,
        AgentWalletError::PairingPhoneRecordMissing,
        AgentWalletError::PairingAttemptsExhausted,
        AgentWalletError::PairingSignerAuthorityChanged,
        AgentWalletError::PairingUnknownToSession,
        AgentWalletError::PairingStateChangedSinceStart,
        AgentWalletError::PairingOfferBindingMismatch,
        AgentWalletError::PairingVerificationCodeMismatch,
        AgentWalletError::PairingIdentityMismatch,
        AgentWalletError::PairingTranscriptMismatch,
        AgentWalletError::PairingAlreadyUsed,
        AgentWalletError::PairingDeviceAlreadyRegistered,
        AgentWalletError::PairingDeviceRevoked,
        AgentWalletError::PairingDeviceRecordRejected,
        AgentWalletError::RotationDeviceNotInRotation,
        AgentWalletError::RotationOldDeviceNotRegistered,
        AgentWalletError::RotationOldDeviceNotAuthorized,
        AgentWalletError::RotationOldDeviceRevokeFailed,
        AgentWalletError::RotationOldDeviceApprovalMissing,
        AgentWalletError::RotationAuthorizationMismatch,
        AgentWalletError::RotationAuthorizationSignatureInvalid,
        AgentWalletError::RotationCandidateIsCurrentDevice,
        AgentWalletError::RotationCandidateRecordInvalid,
        AgentWalletError::RotationCandidateNotEligible,
        AgentWalletError::RotationCandidateAlreadyRegistered,
        AgentWalletError::RotationCandidateNotAuthorized,
        AgentWalletError::RotationCandidateAcceptanceInvalid,
        AgentWalletError::RotationCandidateRegistrationFailed,
        AgentWalletError::RotationTicketInvalid,
        AgentWalletError::RotationBaselineReceiptInvalid,
        AgentWalletError::RotationBaselineAlreadyRecorded,
    ];

    let mut messages: Vec<String> = Vec::new();
    for refusal in refusals {
        let message = refusal.to_string();
        let closing = message.trim_end_matches('.').rsplit(". ").next().unwrap();
        assert!(
            OWNER_ACTIONS
                .iter()
                .any(|action| closing.starts_with(action)),
            "{refusal:?} does not end on something the owner can do: {message}"
        );
        // The old copy explained the internals and not the next step.
        assert!(
            !message.contains("authorization failed"),
            "{refusal:?} is still internal jargon: {message}"
        );
        assert!(
            message.starts_with(|first: char| first.is_ascii_uppercase()),
            "{refusal:?} is not a sentence: {message}"
        );
        // No verification code, nonce, fingerprint or key may reach the screen.
        let digit_run = longest_run(&message, |character| character.is_ascii_digit());
        let hex_run = longest_run(&message, |character| character.is_ascii_hexdigit());
        assert!(
            digit_run <= 1,
            "{refusal:?} leaks a numeric secret: {message}"
        );
        assert!(
            hex_run <= 4,
            "{refusal:?} leaks encoded material: {message}"
        );
        assert!(!messages.contains(&message), "duplicate copy: {message}");
        messages.push(message);
    }
}

fn longest_run(value: &str, predicate: impl Fn(char) -> bool) -> usize {
    let mut longest = 0_usize;
    let mut current = 0_usize;
    for character in value.chars() {
        current = if predicate(character) { current + 1 } else { 0 };
        longest = longest.max(current);
    }
    longest
}

/// The retry budget used to be invisible: five silent tries, then a pairing
/// that simply stopped answering. The trusted UI polls this, so it must be able
/// to say "Attempt 2 of 5" before the last one is spent.
#[tokio::test]
async fn the_bounded_attempt_budget_is_visible_before_the_last_try_is_spent() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut attempt = manager
        .start_companion_pairing(&wallet_id, Vec::new(), 103, 300)
        .unwrap();

    assert_eq!(MAX_PAIRING_REQUEST_ATTEMPTS, 5);
    let fresh = attempt.attempt_budget();
    assert_eq!(fresh.used(), 0);
    assert_eq!(fresh.max(), MAX_PAIRING_REQUEST_ATTEMPTS);
    assert_eq!(fresh.remaining(), MAX_PAIRING_REQUEST_ATTEMPTS);
    assert_eq!(fresh.next_attempt(), 1, "the first press is attempt 1 of 5");

    let honest = request_for(&attempt, &mobile, 104).await;
    let mut tampered = honest.request().clone();
    tampered.pairing_nonce = "00".repeat(32);

    // Each refused request spends exactly one try, and the count is readable
    // between presses instead of only after the budget is gone.
    for (spent, now) in (105..109).enumerate() {
        manager
            .accept_companion_pairing_request(&wallet_id, &mut attempt, tampered.clone(), now)
            .await
            .unwrap_err();
        let budget = attempt.attempt_budget();
        let spent = u8::try_from(spent + 1).unwrap();
        assert_eq!(budget.used(), spent);
        assert_eq!(budget.remaining(), MAX_PAIRING_REQUEST_ATTEMPTS - spent);
        assert_eq!(
            budget.next_attempt(),
            (spent + 1).min(MAX_PAIRING_REQUEST_ATTEMPTS)
        );
    }
    assert_eq!(attempt.attempt_budget().used(), 4);
    assert_eq!(attempt.attempt_budget().remaining(), 1, "one try left");

    // The last try, and then the refusal that names the exhausted budget.
    manager
        .accept_companion_pairing_request(&wallet_id, &mut attempt, tampered.clone(), 109)
        .await
        .unwrap_err();
    let spent = attempt.attempt_budget();
    assert_eq!(spent.used(), MAX_PAIRING_REQUEST_ATTEMPTS);
    assert_eq!(spent.remaining(), 0);
    assert_eq!(spent.next_attempt(), MAX_PAIRING_REQUEST_ATTEMPTS);
    assert_eq!(
        manager
            .accept_companion_pairing_request(&wallet_id, &mut attempt, tampered, 110)
            .await
            .unwrap_err(),
        AgentWalletError::PairingAttemptsExhausted
    );
    // Counters never wrap past the bound, whatever the caller does next.
    assert_eq!(attempt.attempt_budget().remaining(), 0);
    assert_eq!(
        attempt.attempt_budget().used(),
        MAX_PAIRING_REQUEST_ATTEMPTS
    );
}

/// A revoked phone is a permanent dead end, and the refusal the owner reads
/// says exactly that instead of sending them on an impossible errand.
///
/// The handset keeps its hardware companion identity across a phone-side reset,
/// so the same device id, key and fingerprint come back unchanged. Every route
/// that could readmit it must stay closed, and the message must name the two
/// routes that actually work: a new mobile identity on the phone, or a
/// different phone.
#[tokio::test]
async fn a_revoked_phone_is_never_readmitted_and_the_refusal_names_the_real_options() {
    let (_root, mut manager, wallet_id) = enabled_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut attempt, code) = acknowledged_pairing(&mut manager, &wallet_id, &mobile, 103).await;
    manager
        .complete_companion_pairing_code(&wallet_id, &mut attempt, &code, 107)
        .unwrap();
    drop(attempt);
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 110)
        .unwrap();
    let revoked = manager.list_companion_devices(&wallet_id, 111).unwrap();
    assert_eq!(revoked.len(), 1);
    assert!(revoked[0].is_revoked());

    // The owner resets the companion app and pairs again. The transcript and
    // the six digits verify; only the durable registry refuses, and it names
    // revocation rather than a generic authorization failure.
    let (mut repair, repair_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &mobile, 200).await;
    assert_eq!(
        manager
            .complete_companion_pairing_code(&wallet_id, &mut repair, &repair_code, 205)
            .unwrap_err(),
        AgentWalletError::PairingDeviceRevoked
    );
    drop(repair);

    // No implicit path revives it: not a fully verified re-pair, and not a
    // freshly minted record for the same identity with a newer `paired_at`.
    let fresh = mobile
        .public_record(wallet_id.as_str(), mobile_permissions(), 300)
        .unwrap();
    assert_eq!(
        manager
            .register_verified_companion_device(&wallet_id, fresh, 300)
            .unwrap_err(),
        AgentWalletError::PairingDeviceRevoked
    );
    assert_eq!(
        manager.list_companion_devices(&wallet_id, 301).unwrap(),
        revoked
    );

    // A genuinely new identity on the same phone is admitted through the
    // ordinary first-pairing path, and the revoked record stays revoked.
    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let (mut replaced, replaced_code) =
        acknowledged_pairing(&mut manager, &wallet_id, &replacement, 400).await;
    manager
        .complete_companion_pairing_code(&wallet_id, &mut replaced, &replaced_code, 405)
        .unwrap();
    drop(replaced);
    let devices = manager.list_companion_devices(&wallet_id, 406).unwrap();
    assert_eq!(devices.len(), 2);
    assert!(
        devices
            .iter()
            .find(|record| record.device_id == *mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        !devices
            .iter()
            .find(|record| record.device_id == *replacement.device_id())
            .unwrap()
            .is_revoked()
    );

    // The copy the owner reads. A reset cannot help, so it must not be offered.
    let refusal = AgentWalletError::PairingDeviceRevoked.to_string();
    assert!(!refusal.contains("Reset the companion app on the phone, then pair it again"));
    assert!(refusal.contains("Revocation is permanent"));
    assert!(refusal.contains("create a new mobile identity"));
    assert!(refusal.contains("pair a different phone"));

    // And the already-registered refusal must never send an owner to Revoke,
    // which is how a working phone becomes a permanently unpairable one.
    let already = AgentWalletError::PairingDeviceAlreadyRegistered.to_string();
    assert!(!already.contains("Revoke it under Authorized mobile devices"));
    assert!(already.contains("never revoke a working phone"));
}
