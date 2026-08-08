use hpay_companion_protocol::{DeviceId, DeviceRole, ReplayMetadata, SoftwareDeviceIdentity};

use super::fixtures::*;
use super::*;

fn frame_metadata(
    mobile_device_id: &DeviceId,
    session_id: &str,
    sequence: u64,
    nonce: &str,
    now: u64,
) -> ReplayMetadata {
    ReplayMetadata {
        context: format!("encrypted_frame:{session_id}"),
        sender_device_id: mobile_device_id.clone(),
        sequence,
        nonce: nonce.to_owned(),
        issued_at: now,
        expires_at: now + 60,
    }
}

#[test]
fn encrypted_transport_replay_is_durable_across_restart() {
    let (root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
    let accepted = frame_metadata(
        mobile.device_id(),
        "session-one",
        1,
        "0123456789abcdef01234567",
        103,
    );
    manager
        .consume_companion_transport_replay(&wallet_id, mobile.device_id(), &accepted, 103)
        .unwrap();
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 104).unwrap();
    let duplicate_sequence = frame_metadata(
        mobile.device_id(),
        "session-one",
        1,
        "1123456789abcdef01234567",
        105,
    );
    assert_eq!(
        restarted.consume_companion_transport_replay(
            &wallet_id,
            mobile.device_id(),
            &duplicate_sequence,
            105,
        ),
        Err(AgentWalletError::CompanionReplayRejected)
    );
    let duplicate_nonce = frame_metadata(
        mobile.device_id(),
        "session-one",
        2,
        "0123456789abcdef01234567",
        105,
    );
    assert_eq!(
        restarted.consume_companion_transport_replay(
            &wallet_id,
            mobile.device_id(),
            &duplicate_nonce,
            105,
        ),
        Err(AgentWalletError::CompanionReplayRejected)
    );
}

#[test]
fn transport_replay_requires_exact_active_mobile_and_encrypted_session_context() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
    let other = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let valid = frame_metadata(
        mobile.device_id(),
        "session-two",
        1,
        "2123456789abcdef01234567",
        103,
    );
    assert_eq!(
        manager.consume_companion_transport_replay(&wallet_id, other.device_id(), &valid, 103),
        Err(AgentWalletError::CompanionAuthorizationFailed)
    );

    for context in ["", "encrypted_frame:", "signed_approval:session-two"] {
        let mut invalid = valid.clone();
        invalid.context = context.to_owned();
        assert_eq!(
            manager.consume_companion_transport_replay(
                &wallet_id,
                mobile.device_id(),
                &invalid,
                103,
            ),
            Err(AgentWalletError::CompanionAuthorizationFailed)
        );
    }

    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 104)
        .unwrap();
    assert_eq!(
        manager.consume_companion_transport_replay(&wallet_id, mobile.device_id(), &valid, 105),
        Err(AgentWalletError::CompanionAuthorizationFailed)
    );
}

#[test]
fn persistence_failure_returns_no_transport_replay_success() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
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
    let metadata = frame_metadata(
        mobile.device_id(),
        "session-three",
        1,
        "3123456789abcdef01234567",
        103,
    );
    assert_eq!(
        manager.consume_companion_transport_replay(&wallet_id, mobile.device_id(), &metadata, 103,),
        Err(AgentWalletError::PersistenceFailed)
    );
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap()
        .companion_security
        .unwrap()
        .replay_guard;
    assert_eq!(after, before);
}

#[test]
fn locked_or_emergency_stopped_wallet_rejects_transport_replay() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
    let metadata = frame_metadata(
        mobile.device_id(),
        "session-four",
        1,
        "4123456789abcdef01234567",
        104,
    );

    manager.lock(&wallet_id, 105).unwrap();
    assert_eq!(
        manager.consume_companion_transport_replay(&wallet_id, mobile.device_id(), &metadata, 106,),
        Err(AgentWalletError::AgentWalletLocked)
    );

    manager.unlock(&wallet_id, PASSPHRASE, 107).unwrap();
    manager.disable_all_agent_payments(&wallet_id, 108).unwrap();
    assert_eq!(
        manager.consume_companion_transport_replay(&wallet_id, mobile.device_id(), &metadata, 109,),
        Err(AgentWalletError::AgentPaymentsSuspended)
    );
}
