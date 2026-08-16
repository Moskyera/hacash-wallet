use super::fixtures::*;
use super::*;

#[tokio::test]
async fn retained_desktop_companion_signer_is_disabled_on_wallet_lock() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let signer = manager
        .session(&wallet_id)
        .unwrap()
        .desktop_companion_signer
        .clone();
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut pairing = hpay_companion_protocol::PairingSession::new(
        &signer,
        wallet_id.to_string(),
        Vec::new(),
        103,
        60,
    )
    .unwrap();
    let attempt =
        hpay_companion_protocol::MobilePairingAttempt::start(pairing.offer().clone(), &mobile, 104)
            .await
            .unwrap();
    manager.lock(&wallet_id, 105).unwrap();
    assert!(matches!(
        pairing
            .accept_request(attempt.request().clone(), &signer, 106)
            .await,
        Err(hpay_companion_protocol::CompanionError::PlatformSignerUnavailable)
    ));
}

#[tokio::test]
async fn mobile_rejection_consumes_replay_durably_and_never_signs() {
    let (root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 110);
    let signed = signed_decision(
        &approval,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        1,
        111,
    )
    .await;
    let rejected = manager
        .apply_mobile_approval_and_broadcast(&wallet_id, signed.clone(), 112)
        .await
        .unwrap();
    assert_eq!(rejected.status, OperationStatus::Rejected);
    assert_eq!(rejected.approval_mode, Some(ApprovalMode::MobileManual));
    assert_eq!(rejected.wallet_fee_units, HacUnits::ZERO);
    assert!(rejected.tx_hash.is_none());
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 113).unwrap();
    assert_eq!(
        restarted
            .apply_mobile_approval_and_broadcast(&wallet_id, signed, 114)
            .await,
        Err(AgentWalletError::CompanionReplayRejected)
    );
    let persisted = restarted
        .list_operations_admin(&wallet_id, 115)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == operation_id)
        .unwrap();
    assert_eq!(persisted.status, OperationStatus::Rejected);
    assert!(persisted.tx_hash.is_none());
}

#[tokio::test]
async fn mobile_approval_is_persisted_before_resume_can_reach_the_signer() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    let (approval, operation_id) = prepare_pending(
        &mut manager,
        &wallet_id,
        ApprovalMode::EitherTrustedDevice,
        110,
    );
    let signed = signed_decision(
        &approval,
        ApprovalDecision::Approve,
        &mobile,
        record.authorization_epoch,
        1,
        111,
    )
    .await;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, signed, 112)
            .await,
        Err(AgentWalletError::AgentPaymentsSuspended)
    );
    let persisted = manager
        .list_operations_admin(&wallet_id, 113)
        .unwrap()
        .into_iter()
        .find(|view| view.operation_id == operation_id)
        .unwrap();
    assert_eq!(persisted.status, OperationStatus::Approved);
    assert_eq!(persisted.approval_mode, Some(ApprovalMode::MobileManual));
    assert!(persisted.tx_hash.is_none());
}

#[tokio::test]
async fn stale_revoked_cross_device_and_nonzero_wallet_fee_decisions_fail_closed() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let other_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    register_mobile(&mut manager, &wallet_id, &other_mobile, 103);

    let (approval_epoch, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 104);
    let stale_epoch = signed_decision(
        &approval_epoch,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch + 1,
        1,
        105,
    )
    .await;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, stale_epoch, 106)
            .await,
        Err(AgentWalletError::CompanionAuthorizationFailed)
    );

    let (approval_fee, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 110);
    let mut nonzero_fee = signed_decision(
        &approval_fee,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        1,
        111,
    )
    .await;
    nonzero_fee.decision.wallet_fee_units = 1;
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, nonzero_fee, 112)
            .await,
        Err(AgentWalletError::ApprovalCommitmentMismatch)
    );

    let (approval_device, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 120);
    let mut cross_device = signed_decision(
        &approval_device,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        2,
        121,
    )
    .await;
    cross_device.decision.mobile_device_id = other_mobile.device_id().clone();
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, cross_device, 122)
            .await,
        Err(AgentWalletError::CompanionAuthorizationFailed)
    );

    let (approval_stale, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 130);
    let stale = signed_decision(
        &approval_stale,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        3,
        131,
    )
    .await;
    manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 132)
        .unwrap();
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, stale, 133)
            .await,
        Err(AgentWalletError::CompanionAuthorizationFailed)
    );
}

#[tokio::test]
async fn desktop_and_mobile_decisions_are_atomic_first_wins() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);

    let (mobile_first_approval, mobile_first_id) = prepare_pending(
        &mut manager,
        &wallet_id,
        ApprovalMode::EitherTrustedDevice,
        110,
    );
    let mobile_first = signed_decision(
        &mobile_first_approval,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        1,
        111,
    )
    .await;
    manager
        .apply_mobile_approval_and_broadcast(&wallet_id, mobile_first, 112)
        .await
        .unwrap();
    let still_mobile = manager
        .reject_payment(
            &wallet_id,
            &mobile_first_id,
            ApprovalMode::DesktopManual,
            113,
        )
        .unwrap();
    assert_eq!(still_mobile.approval_mode, Some(ApprovalMode::MobileManual));

    let (desktop_first_approval, desktop_first_id) = prepare_pending(
        &mut manager,
        &wallet_id,
        ApprovalMode::EitherTrustedDevice,
        120,
    );
    let mobile_loses = signed_decision(
        &desktop_first_approval,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        2,
        121,
    )
    .await;
    let desktop_winner = manager
        .reject_payment(
            &wallet_id,
            &desktop_first_id,
            ApprovalMode::DesktopManual,
            122,
        )
        .unwrap();
    assert_eq!(
        desktop_winner.approval_mode,
        Some(ApprovalMode::DesktopManual)
    );
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, mobile_loses, 123)
            .await,
        Err(AgentWalletError::InvalidOperationState)
    );
}

#[tokio::test]
async fn desktop_only_policy_expired_and_cross_wallet_decisions_are_rejected() {
    let (_first_root, mut first, first_wallet) = create_manager(100);
    let (_second_root, mut second, second_wallet) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut first, &first_wallet, &mobile, 102);
    let cross_wallet_record = mobile
        .public_record(first_wallet.as_str(), mobile_permissions(), 102)
        .unwrap();
    assert_eq!(
        second.register_verified_companion_device(&second_wallet, cross_wallet_record, 103),
        Err(AgentWalletError::PairingDeviceRecordRejected)
    );

    let (desktop_only, _) =
        prepare_pending(&mut first, &first_wallet, ApprovalMode::DesktopManual, 110);
    let signed_desktop_only = signed_decision(
        &desktop_only,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        1,
        111,
    )
    .await;
    assert_eq!(
        first
            .apply_mobile_approval_and_broadcast(&first_wallet, signed_desktop_only, 112)
            .await,
        Err(AgentWalletError::AgentPermissionDenied)
    );

    let (expired, _) = prepare_pending(&mut first, &first_wallet, ApprovalMode::MobileManual, 120);
    let signed_expired = signed_decision(
        &expired,
        ApprovalDecision::Reject,
        &mobile,
        record.authorization_epoch,
        2,
        121,
    )
    .await;
    assert_eq!(
        first
            .apply_mobile_approval_and_broadcast(&first_wallet, signed_expired, 421)
            .await,
        Err(AgentWalletError::ApprovalExpired)
    );
}

#[tokio::test]
async fn mobile_emergency_is_marker_first_restart_safe_and_wallet_scoped() {
    let (root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
    let command = admin_command(
        &manager,
        &wallet_id,
        &mobile,
        record.authorization_epoch,
        1,
        104,
    );
    let signed = SignedAdminCommand::sign(command, &mobile).await.unwrap();
    manager
        .apply_mobile_admin_command(&wallet_id, signed.clone(), 105)
        .unwrap();
    assert!(
        manager
            .emergency_controller(&wallet_id)
            .unwrap()
            .status(false)
            .stopped
    );
    assert!(
        manager
            .unlocked_status(&wallet_id, 106)
            .unwrap()
            .payments_suspended
    );
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 107).unwrap();
    assert_eq!(
        restarted.apply_mobile_admin_command(&wallet_id, signed, 108),
        Err(AgentWalletError::CompanionReplayRejected)
    );
    assert!(
        restarted
            .unlocked_status(&wallet_id, 109)
            .unwrap()
            .payments_suspended
    );
}

#[tokio::test]
async fn emergency_marker_remains_stopped_when_state_persistence_fails() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    manager
        .enable_agent_payments_locally(&wallet_id, 103)
        .unwrap();
    let command = admin_command(
        &manager,
        &wallet_id,
        &mobile,
        record.authorization_epoch,
        1,
        104,
    );
    let signed = SignedAdminCommand::sign(command, &mobile).await.unwrap();
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
            .apply_mobile_admin_command(&wallet_id, signed, 105)
            .is_err()
    );
    assert!(
        manager
            .emergency_controller(&wallet_id)
            .unwrap()
            .status(false)
            .stopped
    );
}

#[test]
fn companion_state_is_bound_to_only_its_agent_wallet() {
    let (parent, mut manager, first_wallet) = create_manager(100);
    let second = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: "http://127.0.0.1:18081".to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
                mainnet_pilot_acknowledgement: None,
            },
            101,
        )
        .unwrap();
    manager.unlock(&second.wallet_id, PASSPHRASE, 102).unwrap();
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &first_wallet, &mobile, 103);
    assert!(
        manager
            .list_companion_devices(&second.wallet_id, 104)
            .unwrap()
            .is_empty()
    );
    drop(manager);
    assert!(parent.path().exists());
}

#[test]
fn corrupt_cross_wallet_registry_fails_closed_during_authenticated_state_load() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &mobile, 102);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state: AgentWalletState = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let other_wallet = AgentWalletId::new();
    let wrong = mobile
        .public_record(other_wallet.as_str(), mobile_permissions(), 103)
        .unwrap();
    let companion = state.companion_security.as_mut().unwrap();
    companion.device_registry = DeviceRegistry::new();
    companion.device_registry.register(wrong).unwrap();
    state.updated_at = 103;
    manager
        .storage
        .write_encrypted(
            &wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            &state,
        )
        .unwrap();
    assert_eq!(
        manager.unlocked_status(&wallet_id, 104),
        Err(AgentWalletError::RecoveryRequired)
    );
    let _ = journal_key;
}
