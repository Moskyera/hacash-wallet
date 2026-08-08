use super::fixtures::*;
use super::*;

#[test]
fn companion_registry_is_encrypted_journal_state_and_survives_restart_and_revocation() {
    let (root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let original = register_mobile(&mut manager, &wallet_id, &mobile, 102);
    let current_path = manager
        .storage
        .paths(&wallet_id)
        .unwrap()
        .encrypted_state_path(STATE_NAME)
        .unwrap();
    let encrypted = fs::read(&current_path).unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains(mobile.device_id().as_str()));
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 103).unwrap();
    assert_eq!(
        restarted.list_companion_devices(&wallet_id, 104).unwrap(),
        vec![original.clone()]
    );
    let revoked = restarted
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), 105)
        .unwrap();
    assert_eq!(
        revoked.authorization_epoch,
        original.authorization_epoch + 1
    );
    assert_eq!(revoked.revoked_at, Some(105));
    drop(restarted);

    let mut twice = AgentWalletManager::open(root.path()).unwrap();
    twice.unlock(&wallet_id, PASSPHRASE, 106).unwrap();
    assert!(twice.list_companion_devices(&wallet_id, 107).unwrap()[0].is_revoked());
    assert_eq!(
        twice.register_verified_companion_device(&wallet_id, original, 108),
        Err(AgentWalletError::PairingDeviceRevoked)
    );
}

#[test]
fn revoked_tombstones_do_not_consume_the_active_device_capacity() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mut mobiles = Vec::new();
    for offset in 0..MAX_ACTIVE_MOBILE_DEVICES {
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        register_mobile(&mut manager, &wallet_id, &mobile, 102 + offset as u64);
        mobiles.push(mobile);
    }
    manager
        .revoke_companion_device_locally(&wallet_id, mobiles[0].device_id(), 130)
        .unwrap();
    assert_eq!(
        manager.register_verified_companion_device(
            &wallet_id,
            mobiles[0]
                .public_record(wallet_id.as_str(), mobile_permissions(), 131)
                .unwrap(),
            131,
        ),
        Err(AgentWalletError::PairingDeviceRevoked)
    );

    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_mobile(&mut manager, &wallet_id, &replacement, 132);
    let overflow = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let overflow_record = overflow
        .public_record(wallet_id.as_str(), mobile_permissions(), 133)
        .unwrap();
    assert_eq!(
        manager.register_verified_companion_device(&wallet_id, overflow_record, 133),
        Err(AgentWalletError::TooManyCompanionDevices)
    );
    let records = manager.list_companion_devices(&wallet_id, 134).unwrap();
    assert_eq!(records.len(), MAX_ACTIVE_MOBILE_DEVICES + 1);
    assert_eq!(
        records.iter().filter(|record| !record.is_revoked()).count(),
        MAX_ACTIVE_MOBILE_DEVICES
    );
}
