use super::*;

pub(super) const PASSPHRASE: &str = "agent companion passphrase 123";
pub(super) const TESTNET_ANCHOR: &str =
    "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
pub(super) const RECIPIENT: &str = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";

pub(super) fn create_manager(now: u64) -> (tempfile::TempDir, AgentWalletManager, AgentWalletId) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: "http://127.0.0.1:18081".to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
            },
            now,
        )
        .unwrap();
    manager
        .unlock(&created.wallet_id, PASSPHRASE, now + 1)
        .unwrap();
    (root, manager, created.wallet_id)
}

pub(super) fn mobile_permissions() -> BTreeSet<DevicePermission> {
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    let permissions = BTreeSet::from([
        DevicePermission::ApprovePayment,
        DevicePermission::RejectPayment,
        DevicePermission::EmergencyStop,
    ]);
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    let permissions = BTreeSet::from([
        DevicePermission::ApprovePayment,
        DevicePermission::RejectPayment,
        DevicePermission::EmergencyStop,
        DevicePermission::WitnessRollbackAnchor,
    ]);
    permissions
}

pub(super) fn register_mobile(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> DevicePublicRecord {
    let record = mobile
        .public_record(wallet_id.as_str(), mobile_permissions(), now)
        .unwrap();
    manager
        .register_verified_companion_device(wallet_id, record.clone(), now)
        .unwrap()
}

pub(super) fn keys(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> ([u8; 32], [u8; 32]) {
    let session = manager.session(wallet_id).unwrap();
    (*session.state_master, *session.journal_key)
}

pub(super) fn prepare_pending(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    approval_mode: ApprovalMode,
    now: u64,
) -> (ApprovalCommitment, OperationId) {
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
        name: "Companion test agent".to_owned(),
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
        wallet_scope: paired.wallet_scope,
        name: paired.name,
        version: paired.version,
        identity_public_key_sec1: paired.identity_public_key_sec1_hex,
        identity_fingerprint: paired.identity_fingerprint,
        identity_key_sha256,
        server_identity,
        status: AgentStatus::Active,
        authorization_epoch: 1,
        policy: AgentPolicy {
            permissions,
            max_per_payment_units: HacUnits::new(1_000_000),
            max_daily_units: HacUnits::new(10_000_000),
            max_pending_operations: 4,
            allowed_recipients: BTreeSet::new(),
            blocked_recipients: BTreeSet::new(),
            approval_mode,
            policy_epoch: state.policy_epoch,
        },
        paired_at: now,
    };
    state.agents.insert(agent_id.as_str().to_owned(), record);

    let operation_id = OperationId::new();
    let mut operation = AgentOperation::new(
        operation_id.clone(),
        agent_id.clone(),
        wallet_id.clone(),
        AgentPaymentRequest {
            idempotency_key: format!("test-{}", operation_id.as_str()),
            asset: "HAC".to_owned(),
            amount_units: HacUnits::new(10_000),
            recipient: RECIPIENT.to_owned(),
            reason: "companion security test".to_owned(),
            expires_at: now + 300,
        },
        now,
    )
    .unwrap();
    operation.reserve(HacUnits::MIN_NETWORK_FEE).unwrap();
    operation
        .persist_unsigned_transaction("00".to_owned())
        .unwrap();
    let view = operation.view();
    let approval = ApprovalCommitment {
        approval_version: 2,
        approval_id: format!("approval_{}", operation_id.as_str()),
        operation_id: operation_id.to_string(),
        agent_wallet_id: wallet_id.to_string(),
        agent_id: agent_id.to_string(),
        desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone()).unwrap(),
        transaction_commitment: view.transaction_commitment.unwrap(),
        amount_units: view.amount_units.get(),
        fee_units: HacUnits::MIN_NETWORK_FEE.get(),
        wallet_fee_units: 0,
        total_debit_units: view.total_debit_units.get(),
        recipient: view.recipient,
        policy_epoch: state.policy_epoch,
        challenge_nonce: operation_id
            .as_str()
            .strip_prefix("op_")
            .unwrap()
            .to_owned(),
        issued_at: now,
        expires_at: now + 300,
        network_binding: None,
    };
    operation
        .request_approval(approval.clone(), state.policy_epoch, now)
        .unwrap();
    state
        .operations
        .insert(operation_id.as_str().to_owned(), operation);
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ApprovalRequested,
            Some(operation_id.as_str().as_bytes()),
            Some(agent_id.as_str().as_bytes()),
            now,
        )
        .unwrap();
    (approval, operation_id)
}

pub(super) async fn signed_decision(
    approval: &ApprovalCommitment,
    decision: ApprovalDecision,
    mobile: &SoftwareDeviceIdentity,
    authorization_epoch: u64,
    sequence: u64,
    now: u64,
) -> SignedApprovalDecision {
    SignedApprovalDecision::sign(
        MobileApprovalDecision::from_commitment(
            approval,
            decision,
            mobile.device_id().clone(),
            authorization_epoch,
            sequence,
            now,
        ),
        mobile,
    )
    .await
    .unwrap()
}

pub(super) fn admin_command(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    authorization_epoch: u64,
    sequence: u64,
    now: u64,
) -> AdminCommand {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    AdminCommand {
        command_version: 2,
        command_id: format!("stop-{sequence}"),
        command_type: AdminCommandKind::SuspendAgentPayments,
        agent_wallet_id: wallet_id.to_string(),
        mobile_device_id: mobile.device_id().clone(),
        device_authorization_epoch: authorization_epoch,
        desktop_device_id: DeviceId::parse(state.primary_signing_device_id).unwrap(),
        policy_epoch: state.policy_epoch,
        command_sequence: sequence,
        nonce: "stopnonce0123456789abcdef01234567".to_owned(),
        issued_at: now,
        expires_at: now + 120,
    }
}
