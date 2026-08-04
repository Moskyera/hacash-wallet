use std::collections::BTreeSet;
use std::fs;

use hpay_companion_protocol::{DeviceRegistry, MobileSessionAttempt, ReplayGuard};

use super::fixtures::*;
use super::*;
use crate::AgentDesktopSessionAttempt;
use crate::service::AgentAuthorization;

fn enabled_manager(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    DevicePublicRecord,
) {
    let (root, mut manager, wallet_id) = create_manager(now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, now + 2);
    manager
        .enable_agent_payments_locally(&wallet_id, now + 3)
        .unwrap();
    (root, manager, wallet_id, mobile, record)
}

fn current_registry(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> DeviceRegistry {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let signer = manager
        .session(wallet_id)
        .unwrap()
        .desktop_companion_signer
        .clone();
    super::super::session::composite_registry(&state, &signer, now).unwrap()
}

async fn mobile_response(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    attempt: &AgentDesktopSessionAttempt,
    mobile: &SoftwareDeviceIdentity,
    sequence: u64,
    now: u64,
) -> MobileSessionAttempt {
    MobileSessionAttempt::respond(
        attempt.challenge().clone(),
        mobile,
        &current_registry(manager, wallet_id, now),
        &mut ReplayGuard::new(),
        sequence,
        now,
    )
    .await
    .unwrap()
}

/// The unauthenticated challenge phase still writes nothing durable, and every
/// challenge still carries a fresh session id and a fresh 32-byte nonce.
///
/// What it must ALSO do is hand out a strictly increasing `challenge_sequence`.
/// The phone feeds that field into its durable replay guard as the sequence of
/// the `companion_session_challenge` scope, which accepts only values above the
/// last one it accepted. An independent random draw per handshake cannot satisfy
/// that: it fails with probability `S / u64::MAX` after a handshake that landed
/// on `S`, which is how a correctly paired phone ended up refusing its own
/// desktop with "companion backend rejected the operation". Over 32 starts a
/// random source is strictly increasing with probability 1/32!, so this
/// assertion is a reproduction, not a style preference.
#[tokio::test]
async fn unauthenticated_challenge_starts_are_memory_only_and_strictly_increasing() {
    let (_root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let paths = manager.storage.paths(&wallet_id).unwrap();
    let state_path = paths.encrypted_state_path(STATE_NAME).unwrap();
    let journal_path = crate::service::journal_path(&paths);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let before_state = serde_json::to_vec(&before).unwrap();
    let before_state_file = fs::read(&state_path).unwrap();
    let before_journal_file = fs::read(&journal_path).unwrap();
    let before_challenge_sequence = before
        .companion_security
        .as_ref()
        .unwrap()
        .desktop_challenge_sequence;

    let mut challenge_sequences = BTreeSet::new();
    let mut session_ids = BTreeSet::new();
    let mut challenge_nonces = BTreeSet::new();
    let mut previous_sequence = 0;
    for _ in 0..32 {
        let attempt = manager
            .start_companion_desktop_session(&wallet_id, mobile.device_id(), 104, 60)
            .await
            .unwrap();
        let challenge = attempt.challenge();
        assert_ne!(challenge.challenge_sequence, 0);
        assert!(
            challenge.challenge_sequence > previous_sequence,
            "challenge_sequence {} did not exceed the previous {previous_sequence}; the phone's \
             replay guard refuses anything that is not strictly increasing",
            challenge.challenge_sequence,
        );
        previous_sequence = challenge.challenge_sequence;
        assert_eq!(
            hex::decode(challenge.session_id.strip_prefix("session_").unwrap())
                .unwrap()
                .len(),
            16
        );
        assert_eq!(hex::decode(&challenge.challenge_nonce).unwrap().len(), 32);
        assert!(challenge_sequences.insert(challenge.challenge_sequence));
        assert!(session_ids.insert(challenge.session_id.clone()));
        assert!(challenge_nonces.insert(challenge.challenge_nonce.clone()));
    }

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(serde_json::to_vec(&after).unwrap(), before_state);
    assert_eq!(fs::read(&state_path).unwrap(), before_state_file);
    assert_eq!(fs::read(&journal_path).unwrap(), before_journal_file);
    assert_eq!(after.journal_sequence, before.journal_sequence);
    assert_eq!(after.journal_head_hash, before.journal_head_hash);
    assert_eq!(
        after
            .companion_security
            .as_ref()
            .unwrap()
            .desktop_challenge_sequence,
        before_challenge_sequence
    );
}

/// The live failure, end to end, against the real manager.
///
/// A phone that is paired, whose desktop record is active and whose pending
/// pairing flag is cleared must be able to reconnect over and over. The phone
/// keeps its replay guard in durable storage and rebuilds it on every handshake,
/// so the second challenge is checked against the mark the first one left. With
/// an independently drawn challenge sequence this reconnect failed roughly five
/// times out of six and surfaced on the phone as
/// "companion backend rejected the operation".
#[tokio::test]
async fn a_paired_phone_reconnects_against_its_own_durable_replay_guard() {
    let (root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let (state_master, journal_key) = keys(&manager, &wallet_id);

    // The phone's guard, persisted and restored exactly as the handset does it.
    let mut phone_replay = ReplayGuard::new();
    let mut accepted_sequences = Vec::new();
    for (index, (start_at, respond_at, accept_at)) in
        [(104_u64, 105_u64, 106_u64), (107, 108, 109), (110, 111, 112)]
            .into_iter()
            .enumerate()
    {
        let attempt = manager
            .start_companion_desktop_session(&wallet_id, mobile.device_id(), start_at, 60)
            .await
            .unwrap();
        let sequence = attempt.challenge().challenge_sequence;
        if let Some(previous) = accepted_sequences.last() {
            assert!(
                sequence > *previous,
                "reconnect {index} offered {sequence}, which the phone must refuse after \
                 {previous}",
            );
        }
        let response = MobileSessionAttempt::respond(
            attempt.challenge().clone(),
            &mobile,
            &current_registry(&manager, &wallet_id, respond_at),
            &mut phone_replay,
            u64::try_from(index).unwrap() + 1,
            respond_at,
        )
        .await
        .unwrap_or_else(|error| {
            panic!("reconnect {index} was refused by the phone's replay guard: {error}")
        });
        // Round-trip the phone's durable snapshot between handshakes.
        phone_replay =
            ReplayGuard::from_snapshot(phone_replay.snapshot(respond_at).unwrap(), respond_at)
                .unwrap();
        manager
            .accept_companion_desktop_response(&wallet_id, attempt, response.response(), accept_at)
            .await
            .unwrap();
        accepted_sequences.push(sequence);
    }

    // The accepted mark is durable, so a restarted desktop cannot rewind it.
    let persisted = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap()
        .companion_security
        .unwrap()
        .desktop_challenge_sequence;
    assert_eq!(persisted, *accepted_sequences.last().unwrap());

    drop(manager);
    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 113).unwrap();
    let after_restart = restarted
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 114, 60)
        .await
        .unwrap();
    assert!(
        after_restart.challenge().challenge_sequence > persisted,
        "a restarted desktop reissued a sequence the phone has already accepted",
    );
    MobileSessionAttempt::respond(
        after_restart.challenge().clone(),
        &mobile,
        &current_registry(&restarted, &wallet_id, 115),
        &mut phone_replay,
        4,
        115,
    )
    .await
    .expect("the phone must accept the first challenge after a desktop restart");
}

/// The guard itself is untouched: a challenge sequence that really has been
/// consumed is still refused, and refused as a replay.
#[tokio::test]
async fn a_reissued_challenge_sequence_is_still_refused_as_a_replay() {
    let (_root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let attempt = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 104, 60)
        .await
        .unwrap();
    let mut phone_replay = ReplayGuard::new();
    MobileSessionAttempt::respond(
        attempt.challenge().clone(),
        &mobile,
        &current_registry(&manager, &wallet_id, 105),
        &mut phone_replay,
        1,
        105,
    )
    .await
    .unwrap();
    // A rogue or rolled-back desktop reoffering a counter value it already used.
    assert_eq!(
        MobileSessionAttempt::respond(
            attempt.challenge().clone(),
            &mobile,
            &current_registry(&manager, &wallet_id, 106),
            &mut phone_replay,
            2,
            106,
        )
        .await
        .unwrap_err(),
        hpay_companion_protocol::CompanionError::SequenceReplay,
    );
}

#[tokio::test]
async fn accepted_replay_is_durable_and_sessions_remain_memory_only() {
    let (root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let paths = manager.storage.paths(&wallet_id).unwrap();
    let state_path = paths.encrypted_state_path(STATE_NAME).unwrap();
    let journal_path = crate::service::journal_path(&paths);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let state_file_before = fs::read(&state_path).unwrap();
    let journal_before = fs::read(&journal_path).unwrap();
    let first = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 104, 60)
        .await
        .unwrap();
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
    let mobile_first = mobile_response(&manager, &wallet_id, &first, &mobile, 1, 105).await;
    let first_session_id = first.challenge().session_id.clone();
    let (confirmation, established) = manager
        .accept_companion_desktop_response(&wallet_id, first, mobile_first.response(), 106)
        .await
        .unwrap();
    assert_eq!(confirmation.session_id, first_session_id);
    assert_eq!(established.session_id, first_session_id);

    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(state.journal_sequence, before.journal_sequence + 1);
    assert_ne!(
        state.companion_security.as_ref().unwrap().replay_guard,
        before.companion_security.as_ref().unwrap().replay_guard
    );
    let serialized = serde_json::to_string(&state).unwrap();
    assert!(!serialized.contains(&first_session_id));
    assert!(!serialized.contains("session_key"));
    let state_after_accept = fs::read(&state_path).unwrap();
    let journal_after_accept = fs::read(&journal_path).unwrap();
    assert_ne!(state_after_accept, state_file_before);
    assert_ne!(journal_after_accept, journal_before);
    drop(established);
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 107).unwrap();
    let (state_master, journal_key) = keys(&restarted, &wallet_id);
    let before_replay = restarted
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        before_replay
            .companion_security
            .as_ref()
            .unwrap()
            .replay_guard,
        state.companion_security.as_ref().unwrap().replay_guard
    );
    let state_file_before_replay = fs::read(&state_path).unwrap();
    let journal_before_replay = fs::read(&journal_path).unwrap();
    let replayed = restarted
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 108, 60)
        .await
        .unwrap();
    let replayed_mobile = mobile_response(&restarted, &wallet_id, &replayed, &mobile, 1, 109).await;
    assert_eq!(
        restarted
            .accept_companion_desktop_response(
                &wallet_id,
                replayed,
                replayed_mobile.response(),
                110,
            )
            .await
            .unwrap_err(),
        AgentWalletError::CompanionReplayRejected
    );
    let after_replay = restarted
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        after_replay.journal_sequence,
        before_replay.journal_sequence
    );
    assert_eq!(
        after_replay
            .companion_security
            .as_ref()
            .unwrap()
            .replay_guard,
        before_replay
            .companion_security
            .as_ref()
            .unwrap()
            .replay_guard
    );
    assert_eq!(fs::read(&state_path).unwrap(), state_file_before_replay);
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before_replay);
}
#[tokio::test]
async fn default_suspended_wallet_reconnects_read_only_but_cannot_pay_or_sign() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    assert!(
        manager
            .unlocked_status(&wallet_id, 102)
            .unwrap()
            .payments_suspended
    );
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);

    let attempt = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 103, 60)
        .await
        .unwrap();
    let mobile_attempt = mobile_response(&manager, &wallet_id, &attempt, &mobile, 1, 104).await;
    let (_, established) = manager
        .accept_companion_desktop_response(&wallet_id, attempt, mobile_attempt.response(), 105)
        .await
        .unwrap();
    drop(established);

    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 106);
    assert_eq!(approval.wallet_fee_units, 0);
    let agent_id = AgentId::parse(approval.agent_id.clone()).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let agent = before.agents.get(agent_id.as_str()).unwrap();
    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: agent.wallet_scope.clone(),
        agent_id,
        authorization_epoch: agent.authorization_epoch,
        identity_key_sha256: agent.identity_key_sha256.clone(),
        capability: AgentPermission::CreatePaymentIntent,
    };
    let request = AgentPaymentRequest {
        idempotency_key: "suspended-read-only-payment-denial".to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(10_000),
        recipient: RECIPIENT.to_owned(),
        reason: "must remain read only".to_owned(),
        expires_at: 300,
    };
    assert_eq!(
        manager
            .create_payment_intent(&authorization, request, 107)
            .await
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 108)
            .await
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(operation.status, OperationStatus::ApprovalRequested);
    assert_eq!(operation.wallet_fee_units, HacUnits::ZERO);

    manager.disable_all_agent_payments(&wallet_id, 109).unwrap();
    assert_eq!(
        manager
            .start_companion_desktop_session(&wallet_id, mobile.device_id(), 110, 60)
            .await
            .unwrap_err(),
        AgentWalletError::AgentPaymentsSuspended
    );
}
#[tokio::test]
async fn lock_revocation_emergency_epoch_and_cross_wallet_fail_closed() {
    let (_root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let locked_attempt = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 104, 60)
        .await
        .unwrap();
    let locked_mobile =
        mobile_response(&manager, &wallet_id, &locked_attempt, &mobile, 1, 105).await;
    manager.lock(&wallet_id, 106).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 107).unwrap();
    assert_eq!(
        manager
            .accept_companion_desktop_response(
                &wallet_id,
                locked_attempt,
                locked_mobile.response(),
                108,
            )
            .await
            .unwrap_err(),
        AgentWalletError::CompanionAuthorizationFailed
    );

    let revoked_attempt = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 109, 60)
        .await
        .unwrap();
    let revoked_mobile =
        mobile_response(&manager, &wallet_id, &revoked_attempt, &mobile, 1, 110).await;
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 111)
        .unwrap();
    assert_eq!(
        manager
            .accept_companion_desktop_response(
                &wallet_id,
                revoked_attempt,
                revoked_mobile.response(),
                112,
            )
            .await
            .unwrap_err(),
        AgentWalletError::CompanionAuthorizationFailed
    );

    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &replacement, 113);
    let emergency_attempt = manager
        .start_companion_desktop_session(&wallet_id, replacement.device_id(), 114, 60)
        .await
        .unwrap();
    let emergency_mobile = mobile_response(
        &manager,
        &wallet_id,
        &emergency_attempt,
        &replacement,
        1,
        115,
    )
    .await;
    manager.disable_all_agent_payments(&wallet_id, 116).unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, 117)
        .unwrap();
    assert_eq!(
        manager
            .accept_companion_desktop_response(
                &wallet_id,
                emergency_attempt,
                emergency_mobile.response(),
                118,
            )
            .await
            .unwrap_err(),
        AgentWalletError::CompanionAuthorizationFailed
    );

    let cross_attempt = manager
        .start_companion_desktop_session(&wallet_id, replacement.device_id(), 119, 60)
        .await
        .unwrap();
    let cross_mobile =
        mobile_response(&manager, &wallet_id, &cross_attempt, &replacement, 2, 120).await;
    let other = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: "http://127.0.0.1:18081".to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
            },
            121,
        )
        .unwrap();
    manager.unlock(&other.wallet_id, PASSPHRASE, 122).unwrap();
    assert_eq!(
        manager
            .accept_companion_desktop_response(
                &other.wallet_id,
                cross_attempt,
                cross_mobile.response(),
                123,
            )
            .await
            .unwrap_err(),
        AgentWalletError::InvalidWalletScope
    );
    manager
        .enable_agent_payments_locally(&other.wallet_id, 124)
        .unwrap();
    assert_eq!(
        manager
            .start_companion_desktop_session(&other.wallet_id, replacement.device_id(), 125, 60)
            .await
            .unwrap_err(),
        AgentWalletError::CompanionAuthorizationFailed
    );
}

#[tokio::test]
async fn persistence_failure_returns_no_session_and_does_not_consume_replay() {
    let (_root, mut manager, wallet_id, mobile, _) = enabled_manager(100);
    let attempt = manager
        .start_companion_desktop_session(&wallet_id, mobile.device_id(), 104, 60)
        .await
        .unwrap();
    let mobile_attempt = mobile_response(&manager, &wallet_id, &attempt, &mobile, 1, 105).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap()
        .companion_security
        .unwrap()
        .replay_guard;
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
            .accept_companion_desktop_response(&wallet_id, attempt, mobile_attempt.response(), 106,)
            .await
            .is_err()
    );
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap()
        .companion_security
        .unwrap()
        .replay_guard;
    assert_eq!(after, before);
}
