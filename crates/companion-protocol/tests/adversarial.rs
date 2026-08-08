use std::collections::BTreeSet;

#[cfg(feature = "dev-software-identity")]
use hpay_companion_protocol::SessionCipher;
use hpay_companion_protocol::{
    AdminCommand, AdminCommandKind, ApprovalCommitment, ApprovalDecision, CompanionError,
    CompanionMessage, CompanionPayload, DeviceId, DevicePermission, DeviceRegistry, DeviceRole,
    DeviceSigningRequest, MobileApprovalDecision, MobilePairingAttempt, PROTOCOL_VERSION,
    PairingSession, PlatformDeviceIdentity, PlatformDeviceSigner, PlatformP256Signature,
    PlatformSignFuture, ReplayGuard, SignedAdminCommand, SignedApprovalDecision,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;

struct TestDeviceIdentity {
    identity: PlatformDeviceIdentity,
    signing_key: SigningKey,
}

impl TestDeviceIdentity {
    fn generate(role: DeviceRole) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let identity = PlatformDeviceIdentity::new(
            DeviceId::random(role),
            role,
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
        Self {
            identity,
            signing_key,
        }
    }

    fn device_id(&self) -> &DeviceId {
        self.identity.device_id()
    }

    fn public_record(
        &self,
        wallet_id: &str,
        permissions: BTreeSet<DevicePermission>,
        paired_at: u64,
    ) -> hpay_companion_protocol::CompanionResult<hpay_companion_protocol::DevicePublicRecord> {
        self.identity
            .public_record(wallet_id, permissions, paired_at)
    }
}

impl PlatformDeviceSigner for TestDeviceIdentity {
    fn identity(&self) -> &PlatformDeviceIdentity {
        &self.identity
    }

    fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a> {
        Box::pin(async move {
            let signature: Signature = self.signing_key.sign(request.canonical_payload());
            let fixed: [u8; 64] = signature.to_bytes().into();
            PlatformP256Signature::from_fixed_bytes(&fixed)
        })
    }
}

fn approval_fixture() -> (
    TestDeviceIdentity,
    DeviceRegistry,
    ApprovalCommitment,
    MobileApprovalDecision,
) {
    let desktop = TestDeviceIdentity::generate(DeviceRole::Desktop);
    let mobile = TestDeviceIdentity::generate(DeviceRole::Mobile);
    let mut registry = DeviceRegistry::new();
    registry
        .register(
            mobile
                .public_record(
                    "wallet_one",
                    BTreeSet::from([
                        DevicePermission::ApprovePayment,
                        DevicePermission::RejectPayment,
                        DevicePermission::EmergencyStop,
                        DevicePermission::RevokeAgent,
                        DevicePermission::RevokeMobileDevice,
                    ]),
                    90,
                )
                .unwrap(),
        )
        .unwrap();
    let commitment = ApprovalCommitment {
        approval_version: 2,
        approval_id: "approval_one".to_owned(),
        operation_id: "operation_one".to_owned(),
        agent_wallet_id: "wallet_one".to_owned(),
        agent_id: "agent_one".to_owned(),
        desktop_device_id: desktop.device_id().clone(),
        transaction_commitment: "ab".repeat(32),
        amount_units: 50_000,
        fee_units: 150,
        wallet_fee_units: 0,
        total_debit_units: 50_150,
        recipient: "1Recipient".to_owned(),
        policy_epoch: 9,
        network_binding: None,
        challenge_nonce: "cd".repeat(16),
        issued_at: 100,
        expires_at: 200,
    };
    let decision = MobileApprovalDecision::from_commitment(
        &commitment,
        ApprovalDecision::Approve,
        mobile.device_id().clone(),
        1,
        1,
        101,
    );
    (mobile, registry, commitment, decision)
}

#[tokio::test]
async fn every_approval_envelope_field_is_fail_closed_when_mutated() {
    let (mobile, registry, expected, decision) = approval_fixture();
    let original = SignedApprovalDecision::sign(decision, &mobile)
        .await
        .unwrap();
    let mut mutations = Vec::new();

    macro_rules! mutated {
        ($body:expr) => {{
            let mut candidate = original.clone();
            $body(&mut candidate.decision);
            mutations.push(candidate);
        }};
    }

    mutated!(|v: &mut MobileApprovalDecision| v.decision_version += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.approval_id.push('x'));
    mutated!(|v: &mut MobileApprovalDecision| v.decision = ApprovalDecision::Reject);
    mutated!(|v: &mut MobileApprovalDecision| v.operation_id.push('x'));
    mutated!(|v: &mut MobileApprovalDecision| v.agent_wallet_id.push('x'));
    mutated!(|v: &mut MobileApprovalDecision| v.agent_id.push('x'));
    mutated!(|v: &mut MobileApprovalDecision| {
        v.desktop_device_id = DeviceId::parse("desktop_other").unwrap()
    });
    mutated!(|v: &mut MobileApprovalDecision| {
        v.mobile_device_id = DeviceId::parse("mobile_other").unwrap()
    });
    mutated!(|v: &mut MobileApprovalDecision| v.device_authorization_epoch += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.transaction_commitment = "ef".repeat(32));
    mutated!(|v: &mut MobileApprovalDecision| v.amount_units += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.fee_units += 1);
    mutated!(|v: &mut MobileApprovalDecision| {
        v.wallet_fee_units = 1;
        v.total_debit_units += 1;
    });
    mutated!(|v: &mut MobileApprovalDecision| v.total_debit_units += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.recipient.push('x'));
    mutated!(|v: &mut MobileApprovalDecision| v.policy_epoch += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.challenge_nonce = "ef".repeat(16));
    mutated!(|v: &mut MobileApprovalDecision| v.approval_sequence += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.issued_at += 1);
    mutated!(|v: &mut MobileApprovalDecision| v.expires_at -= 1);

    for candidate in mutations {
        assert!(
            candidate
                .verify(&expected, &registry, &ReplayGuard::new(), 102)
                .is_err()
        );
    }

    let mut signature_mutation = original;
    // The replacement must be guaranteed to differ from what is already there.
    // A fixed "00" is a no-op for the ~1-in-256 signatures that already carry
    // those two hex digits, and the untouched signature then verifies, so this
    // fail-closed assertion failed at random rather than on a real regression.
    let replacement = if &signature_mutation.signature_hex[2..4] == "00" {
        "01"
    } else {
        "00"
    };
    signature_mutation
        .signature_hex
        .replace_range(2..4, replacement);
    assert_eq!(
        signature_mutation.verify(&expected, &registry, &ReplayGuard::new(), 102),
        Err(CompanionError::InvalidSignature)
    );
}

#[tokio::test]
async fn admin_envelope_binds_targets_devices_policy_and_expiry() {
    let (mobile, registry, _, _) = approval_fixture();
    let desktop_id = DeviceId::parse("desktop_admin").unwrap();
    let command = AdminCommand {
        command_version: 2,
        command_id: "command_one".to_owned(),
        command_type: AdminCommandKind::RevokeAgent {
            agent_id: "agent_one".to_owned(),
        },
        agent_wallet_id: "wallet_one".to_owned(),
        mobile_device_id: mobile.device_id().clone(),
        device_authorization_epoch: 1,
        desktop_device_id: desktop_id.clone(),
        policy_epoch: 9,
        command_sequence: 1,
        nonce: "ab".repeat(16),
        issued_at: 100,
        expires_at: 200,
    };
    let original = SignedAdminCommand::sign(command, &mobile).await.unwrap();
    let mut mutations = Vec::new();

    let mut value = original.clone();
    value.command.command_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.command.command_type = AdminCommandKind::SuspendAgentPayments;
    mutations.push(value);
    let mut value = original.clone();
    value.command.device_authorization_epoch += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.command.command_sequence += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.command.nonce = "cd".repeat(16);
    mutations.push(value);
    let mut value = original.clone();
    value.command.issued_at += 1;
    mutations.push(value);

    for value in mutations {
        assert!(
            value
                .verify(
                    "wallet_one",
                    &desktop_id,
                    9,
                    &registry,
                    &ReplayGuard::new(),
                    102,
                )
                .is_err()
        );
    }

    assert_eq!(
        original.verify(
            "wallet_one",
            &desktop_id,
            9,
            &registry,
            &ReplayGuard::new(),
            200,
        ),
        Err(CompanionError::Expired)
    );

    let mut cross_device_revoke = original;
    cross_device_revoke.command.command_type = AdminCommandKind::RevokeMobileDevice {
        device_id: DeviceId::parse("mobile_other").unwrap(),
    };
    assert_eq!(
        cross_device_revoke.verify(
            "wallet_one",
            &desktop_id,
            9,
            &registry,
            &ReplayGuard::new(),
            102,
        ),
        Err(CompanionError::AdminCommandNotAllowed)
    );
}

#[tokio::test]
async fn approval_rejects_cross_wallet_registry_and_any_wallet_fee() {
    let (mobile, _, commitment, decision) = approval_fixture();
    let mut other_wallet_registry = DeviceRegistry::new();
    other_wallet_registry
        .register(
            mobile
                .public_record(
                    "wallet_two",
                    BTreeSet::from([DevicePermission::ApprovePayment]),
                    90,
                )
                .unwrap(),
        )
        .unwrap();
    let signed = SignedApprovalDecision::sign(decision.clone(), &mobile)
        .await
        .unwrap();
    assert_eq!(
        signed.verify(
            &commitment,
            &other_wallet_registry,
            &ReplayGuard::new(),
            102,
        ),
        Err(CompanionError::WalletScopeMismatch)
    );

    let mut charged_commitment = commitment.clone();
    charged_commitment.wallet_fee_units = 1;
    charged_commitment.total_debit_units += 1;
    assert_eq!(
        charged_commitment.canonical_bytes(),
        Err(CompanionError::MalformedMessage)
    );
    let mut charged_decision = decision;
    charged_decision.wallet_fee_units = 1;
    charged_decision.total_debit_units += 1;
    assert_eq!(
        charged_decision.canonical_bytes(),
        Err(CompanionError::MalformedMessage)
    );
}

#[tokio::test]
async fn pairing_confirmation_expires_and_cancelled_pairing_cannot_resume() {
    let desktop = TestDeviceIdentity::generate(DeviceRole::Desktop);
    let mobile = TestDeviceIdentity::generate(DeviceRole::Mobile);
    let mut session = PairingSession::new(
        &desktop,
        "wallet_one",
        vec!["hpay-lan://192.168.1.2:443".parse().unwrap()],
        100,
        60,
    )
    .unwrap();
    let attempt = MobilePairingAttempt::start(session.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    let confirmation = session
        .accept_request(attempt.request().clone(), &desktop, 102)
        .await
        .unwrap();
    assert!(matches!(
        attempt
            .confirm(&confirmation, &confirmation.verification_code, &mobile, 160,)
            .await,
        Err(CompanionError::PairingExpired)
    ));

    let mut cancelled = PairingSession::new(&desktop, "wallet_one", Vec::new(), 100, 60).unwrap();
    let attempt = MobilePairingAttempt::start(cancelled.offer().clone(), &mobile, 101)
        .await
        .unwrap();
    cancelled.cancel();
    assert!(matches!(
        cancelled
            .accept_request(attempt.request().clone(), &desktop, 102)
            .await,
        Err(CompanionError::PairingCancelled)
    ));
}

#[test]
fn canonical_message_rejects_every_truncation() {
    let message = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: "message_one".to_owned(),
        session_id: "session_one".to_owned(),
        sender_device_id: DeviceId::parse("desktop_one").unwrap(),
        recipient_device_id: DeviceId::parse("mobile_one").unwrap(),
        sequence: 1,
        issued_at: 100,
        expires_at: 200,
        payload: CompanionPayload::Ping,
    };
    let bytes = message.to_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(CompanionMessage::from_bytes(&bytes[..end]).is_err());
    }
    assert_eq!(CompanionMessage::from_bytes(&bytes).unwrap(), message);
}

#[cfg(feature = "dev-software-identity")]
#[test]
fn authenticated_frame_rejects_sampled_ciphertext_and_nonce_mutations() {
    let desktop_id = DeviceId::parse("desktop_one").unwrap();
    let mobile_id = DeviceId::parse("mobile_one").unwrap();
    let key = [42_u8; 32];
    let desktop = SessionCipher::new_for_testing(
        "session_one",
        desktop_id.clone(),
        mobile_id.clone(),
        key,
        300,
    )
    .unwrap();
    let mobile = SessionCipher::new_for_testing(
        "session_one",
        mobile_id.clone(),
        desktop_id.clone(),
        key,
        300,
    )
    .unwrap();
    let message = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: "message_one".to_owned(),
        session_id: "session_one".to_owned(),
        sender_device_id: desktop_id,
        recipient_device_id: mobile_id,
        sequence: 1,
        issued_at: 100,
        expires_at: 200,
        payload: CompanionPayload::Ping,
    };
    let frame = desktop.encrypt(&message, 101).unwrap();

    for offset in (0..frame.ciphertext_hex.len()).step_by(8) {
        let mut changed = frame.clone();
        let replacement = if &changed.ciphertext_hex[offset..offset + 1] == "0" {
            "1"
        } else {
            "0"
        };
        changed
            .ciphertext_hex
            .replace_range(offset..offset + 1, replacement);
        assert!(mobile.decrypt(&changed, 102).is_err());
    }

    for offset in 0..frame.nonce_hex.len() {
        let mut changed = frame.clone();
        let replacement = if &changed.nonce_hex[offset..offset + 1] == "0" {
            "1"
        } else {
            "0"
        };
        changed
            .nonce_hex
            .replace_range(offset..offset + 1, replacement);
        assert!(mobile.decrypt(&changed, 102).is_err());
    }
}
