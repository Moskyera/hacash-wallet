use super::*;
use crate::identity::{
    DeviceSignaturePurpose, SoftwareDeviceIdentity as DeviceIdentity, sign_with_platform,
};
use crate::message::{CompanionMessage, CompanionPayload, PROTOCOL_VERSION};
use zeroize::Zeroizing;

fn identities() -> (DeviceIdentity, DeviceIdentity) {
    (
        DeviceIdentity::generate(DeviceRole::Desktop),
        DeviceIdentity::generate(DeviceRole::Mobile),
    )
}

fn endpoint() -> LanEndpoint {
    LanEndpoint::parse("hpay-lan://192.168.1.2:443").unwrap()
}

#[tokio::test]
async fn valid_pairing_derives_same_key_exposes_exact_record_and_is_single_use() {
    let (desktop, mobile) = identities();
    let mut desktop_session =
        PairingSession::new(&desktop, "aw_one", vec![endpoint()], 100, 60).unwrap();
    let mobile_attempt = MobilePairingAttempt::start(desktop_session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = desktop_session
        .accept_request(mobile_attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (encrypted_ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, &mobile, 103)
        .await
        .unwrap();
    desktop_session
        .accept_encrypted_mobile_ack(&encrypted_ack, 103)
        .unwrap();
    let desktop_result = desktop_session.confirm_code(&code, 103).unwrap();

    assert_eq!(
        desktop_result.desktop_device_record,
        mobile_result.desktop_device_record
    );
    assert_eq!(
        desktop_result.desktop_device_record.device_id,
        *desktop.identity().device_id()
    );
    assert_eq!(
        desktop_result.desktop_device_record.role,
        DeviceRole::Desktop
    );
    assert_eq!(
        desktop_result.desktop_device_record.agent_wallet_id,
        "aw_one"
    );
    assert_eq!(desktop_result.desktop_device_record.authorization_epoch, 1);
    assert_eq!(desktop_result.desktop_device_record.paired_at, 100);
    assert!(desktop_result.desktop_device_record.revoked_at.is_none());
    assert!(desktop_result.desktop_device_record.permissions.is_empty());
    assert_eq!(
        desktop_result.mobile_device_record,
        mobile_result.mobile_device_record
    );
    assert_eq!(
        desktop_result.mobile_device_record.device_id,
        *mobile.identity().device_id()
    );
    assert_eq!(desktop_result.mobile_device_record.role, DeviceRole::Mobile);
    assert_eq!(
        desktop_result.mobile_device_record.agent_wallet_id,
        "aw_one"
    );
    assert_eq!(desktop_result.mobile_device_record.authorization_epoch, 1);
    assert_eq!(desktop_result.mobile_device_record.paired_at, 102);
    assert!(desktop_result.mobile_device_record.revoked_at.is_none());
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    let expected_permissions = BTreeSet::from([
        DevicePermission::ViewAgentWalletStatus,
        DevicePermission::ViewPendingApprovals,
        DevicePermission::ViewAgents,
    ]);
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    let expected_permissions = BTreeSet::from([
        DevicePermission::ViewAgentWalletStatus,
        DevicePermission::ViewPendingApprovals,
        DevicePermission::ViewAgents,
        DevicePermission::ApprovePayment,
        DevicePermission::RejectPayment,
        DevicePermission::WitnessRollbackAnchor,
    ]);
    assert_eq!(
        desktop_result.mobile_device_record.permissions,
        expected_permissions
    );
    assert_eq!(
        desktop_result
            .mobile_device_record
            .permissions
            .contains(&DevicePermission::ApprovePayment),
        cfg!(feature = "agent-wallet-testnet-pilot")
    );
    assert!(
        !desktop_result
            .mobile_device_record
            .permissions
            .contains(&DevicePermission::EmergencyStop)
    );
    assert!(matches!(
        desktop_session.confirm_code(&code, 104),
        Err(CompanionError::PairingAlreadyUsed)
    ));

    let desktop_cipher = desktop_result.into_desktop_cipher().unwrap();
    let mobile_cipher = mobile_result.into_mobile_cipher().unwrap();
    let message = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: "pairing_key_check".to_owned(),
        session_id: confirmation.session_id.clone(),
        sender_device_id: desktop.identity().device_id().clone(),
        recipient_device_id: mobile.identity().device_id().clone(),
        sequence: 1,
        issued_at: 103,
        expires_at: confirmation.expires_at,
        payload: CompanionPayload::Ping,
    };
    let frame = desktop_cipher.encrypt(&message, 103).unwrap();
    assert_eq!(mobile_cipher.decrypt(&frame, 103).unwrap().0, message);
}

#[tokio::test]
async fn invalid_proof_or_local_code_does_not_consume_desktop_pairing() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", Vec::new(), 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (encrypted_ack, _) = attempt
        .confirm(&confirmation, &code, &mobile, 103)
        .await
        .unwrap();

    let mut tampered = encrypted_ack.clone();
    tampered.ciphertext_hex.replace_range(0..2, "00");
    if tampered.ciphertext_hex == encrypted_ack.ciphertext_hex {
        tampered.ciphertext_hex.replace_range(0..2, "01");
    }
    assert_eq!(
        session.accept_encrypted_mobile_ack(&tampered, 103),
        Err(CompanionError::Crypto)
    );
    session
        .accept_encrypted_mobile_ack(&encrypted_ack, 103)
        .unwrap();
    assert!(matches!(
        session.confirm_code("999999", 103),
        Err(CompanionError::VerificationCodeMismatch)
    ));
    session.confirm_code(&code, 103).unwrap();
}

#[tokio::test]
async fn pairing_rejects_expiry_and_wrong_mobile_code() {
    let (desktop, mobile) = identities();
    let expired = PairingSession::new(&desktop, "aw_one", Vec::new(), 100, 1).unwrap();
    assert!(matches!(
        MobilePairingAttempt::start(expired.offer().clone(), &mobile, 101).await,
        Err(CompanionError::PairingExpired)
    ));

    let mut session = PairingSession::new(&desktop, "aw_one", Vec::new(), 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    assert!(matches!(
        attempt.confirm(&confirmation, "999999", &mobile, 103).await,
        Err(CompanionError::VerificationCodeMismatch)
    ));
}

#[tokio::test]
async fn pairing_confirmation_rejects_forged_desktop_fingerprint() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", Vec::new(), 100, 60).unwrap();
    let mut changed_offer = session.offer().clone();
    changed_offer.desktop_identity_fingerprint = "00".repeat(32);
    let attempt = MobilePairingAttempt::start(changed_offer, &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    assert!(matches!(
        attempt.confirm(&confirmation, &code, &mobile, 103).await,
        Err(CompanionError::FingerprintMismatch)
    ));
}

#[tokio::test]
async fn pairing_request_signature_binds_ephemeral_key_and_rejects_zero_shared_secret() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", Vec::new(), 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let mut tampered = attempt.request().clone();
    tampered.mobile_ephemeral_public_key = "11".repeat(32);
    assert_eq!(
        session.accept_request(tampered, &desktop, 102).await,
        Err(CompanionError::InvalidSignature)
    );

    let mut zero_key = attempt.request().clone();
    zero_key.mobile_ephemeral_public_key = "00".repeat(32);
    zero_key.identity_signature = sign_with_platform(
        &mobile,
        DeviceSignaturePurpose::PairingRequest,
        &zero_key.unsigned_bytes().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        session.accept_request(zero_key, &desktop, 102).await,
        Err(CompanionError::Crypto)
    );
}

#[tokio::test]
async fn encrypted_mobile_ack_is_single_use_and_required_before_local_confirmation() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", vec![endpoint()], 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (encrypted_ack, _) = attempt
        .confirm(&confirmation, &code, &mobile, 103)
        .await
        .unwrap();

    assert!(matches!(
        session.confirm_code(&code, 103),
        Err(CompanionError::PairingMismatch)
    ));
    session
        .accept_encrypted_mobile_ack(&encrypted_ack, 103)
        .unwrap();
    assert_eq!(
        session.accept_encrypted_mobile_ack(&encrypted_ack, 103),
        Err(CompanionError::PairingAlreadyUsed)
    );
    session.confirm_code(&code, 103).unwrap();
}

#[tokio::test]
async fn encrypted_ack_rejects_wrong_key_plaintext_and_expiry() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", vec![endpoint()], 100, 5).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (encrypted_ack, mobile_result) = attempt
        .confirm(&confirmation, &code, &mobile, 103)
        .await
        .unwrap();

    assert_eq!(
        ack::decrypt(
            &encrypted_ack,
            &confirmation.session_id,
            desktop.identity().device_id(),
            &mobile_result.mobile_device_record,
            Zeroizing::new([42_u8; 32]),
            confirmation.expires_at,
            103,
        ),
        Err(CompanionError::Crypto)
    );

    let mut plaintext = encrypted_ack.clone();
    plaintext.ciphertext_hex = hex::encode(b"pairing_mobile_proof");
    assert_eq!(
        session.accept_encrypted_mobile_ack(&plaintext, 103),
        Err(CompanionError::Crypto)
    );
    assert_eq!(
        session.accept_encrypted_mobile_ack(&encrypted_ack, 106),
        Err(CompanionError::PairingExpired)
    );
}

#[tokio::test]
async fn local_confirmation_attempts_are_bounded_and_fail_closed() {
    let (desktop, mobile) = identities();
    let mut session = PairingSession::new(&desktop, "aw_one", vec![endpoint()], 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (encrypted_ack, _) = attempt
        .confirm(&confirmation, &code, &mobile, 103)
        .await
        .unwrap();
    session
        .accept_encrypted_mobile_ack(&encrypted_ack, 103)
        .unwrap();

    for _ in 0..MAX_LOCAL_CONFIRMATION_ATTEMPTS {
        assert!(matches!(
            session.confirm_code("999999", 103),
            Err(CompanionError::VerificationCodeMismatch)
        ));
    }
    assert!(matches!(
        session.confirm_code("999999", 103),
        Err(CompanionError::PairingCancelled)
    ));
    assert!(matches!(
        session.confirm_code(&code, 103),
        Err(CompanionError::PairingCancelled)
    ));
}

#[test]
fn pairing_offer_caps_typed_endpoint_count_and_commits_to_endpoints() {
    let (desktop, _) = identities();
    let endpoints = (0..MAX_LAN_ENDPOINTS)
        .map(|index| {
            LanEndpoint::parse(&format!("hpay-lan://192.168.1.{}:443", index + 1)).unwrap()
        })
        .collect::<Vec<_>>();
    let session = PairingSession::new(&desktop, "aw_one", endpoints.clone(), 100, 60).unwrap();
    let original = session.offer().canonical_bytes().unwrap();

    let mut changed = session.offer().clone();
    changed.lan_endpoints[0] = LanEndpoint::parse("hpay-lan://10.0.0.1:443").unwrap();
    assert_ne!(changed.canonical_bytes().unwrap(), original);

    let mut too_many = endpoints;
    too_many.push(LanEndpoint::parse("hpay-lan://192.168.1.9:443").unwrap());
    assert!(matches!(
        PairingSession::new(&desktop, "aw_one", too_many, 100, 60),
        Err(CompanionError::PairingMismatch)
    ));
}
