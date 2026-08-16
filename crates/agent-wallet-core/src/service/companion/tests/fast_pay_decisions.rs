use super::*;
use crate::fast_pay_operation::{AgentFastPayRequest, AgentFastPayStatus};
use crate::service::payment::revalidate_approved_payment_policy;
use crate::service::{AgentAuthorization, AgentL2Binding};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::channel::{
    CHANNEL_STATUS_OPENING, ChannelInfo, ChannelPartyBalance, derive_channel_id,
};
use hacash_wallet_core::l2_safety::ClientL2Safety;
use hpay_companion_protocol::{
    AgentFastPayApprovalCommitment, AgentFastPayApprovalDecision, AgentFastPayNetworkBinding,
    DeviceRole, SignedAgentFastPayApprovalDecision,
};
use l2_fast_pay_hub::{HubState, build_router};
use std::sync::Arc;
use sys::Account;

struct FastPayFixture {
    root: tempfile::TempDir,
    manager: AgentWalletManager,
    wallet_id: AgentWalletId,
    mobile: SoftwareDeviceIdentity,
    mobile_authorization_epoch: u64,
    operation_id: OperationId,
    approval: AgentFastPayApprovalCommitment,
}

fn prepare_fast_pay(now: u64) -> FastPayFixture {
    let (root, mut manager, wallet_id) = fixtures::create_manager(now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mobile_record = fixtures::register_mobile(&mut manager, &wallet_id, &mobile, now + 2);
    let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();

    let hub = WalletAccount::create_random().unwrap();
    let reuse_version = 1;
    let channel = ChannelInfo {
        ret: 0,
        id: derive_channel_id(&state.address, &hub.address(), reuse_version),
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: state.address.clone(),
            hacash: "1".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let binding = AgentL2Binding::from_verified_channel(
        wallet_id.clone(),
        "testnet",
        AgentFastPayNetworkBinding {
            network_mode: "testnet".to_owned(),
            chain_id: 7,
            genesis_identifier: fixtures::TESTNET_ANCHOR.to_owned(),
            node_profile_id: "77".repeat(32),
            network_instance_id: "agent-fast-pay-decision-tests".to_owned(),
            transaction_format_version: 2,
        },
        &state.address,
        "https://hub.example",
        &hub.address(),
        &channel,
        105,
        now + 3,
    )
    .unwrap();

    let recipient = WalletAccount::create_random().unwrap().address();
    let agent_identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(state.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        name: "Fast Pay decision test agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: agent_identity.public_key_sec1_hex(),
        identity_fingerprint: agent_identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: now + 3,
        authorization_epoch: 1,
        server_identity: server_identity.clone(),
    };
    let identity_key_sha256 = paired.identity_key_sha256().unwrap();
    state.agents.insert(
        agent_id.as_str().to_owned(),
        AgentRecord {
            agent_id: agent_id.clone(),
            wallet_scope: paired.wallet_scope,
            name: paired.name,
            version: paired.version,
            identity_public_key_sec1: paired.identity_public_key_sec1_hex,
            identity_fingerprint: paired.identity_fingerprint,
            identity_key_sha256: identity_key_sha256.clone(),
            server_identity,
            status: AgentStatus::Active,
            authorization_epoch: 1,
            policy: AgentPolicy {
                permissions,
                max_per_payment_units: HacUnits::new(1_000_000),
                max_daily_units: HacUnits::new(10_000_000),
                max_pending_operations: 4,
                allowed_recipients: BTreeSet::from([recipient.clone()]),
                blocked_recipients: BTreeSet::new(),
                allow_unlisted_recipient_with_approval: false,
                approval_mode: ApprovalMode::MobileManual,
                policy_epoch: state.policy_epoch,
            },
            paired_at: now + 3,
        },
    );
    state.l2_binding = Some(binding);
    state.updated_at = now + 3;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::L2BindingVerified,
            None,
            None,
            now + 3,
        )
        .unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, now + 4)
        .unwrap();

    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        agent_id,
        authorization_epoch: 1,
        identity_key_sha256,
        capability: AgentPermission::CreatePaymentIntent,
    };
    let view = manager
        .request_fast_pay_intent(
            &authorization,
            AgentFastPayRequest {
                idempotency_key: "signed-fast-pay-decision-0001".to_owned(),
                amount_units: HacUnits::new(8_000),
                recipient,
                reason: "exact owner-approved testnet compute".to_owned(),
                expires_at: now + 300,
            },
            now + 5,
        )
        .unwrap();
    let approval = manager
        .pending_fast_pay_approval(
            &wallet_id,
            Some(&view.operation_id),
            mobile.device_id(),
            now + 6,
        )
        .unwrap()
        .unwrap();
    let discovered = manager
        .pending_fast_pay_approval(&wallet_id, None, mobile.device_id(), now + 6)
        .unwrap()
        .unwrap();
    assert_eq!(discovered, approval);
    FastPayFixture {
        root,
        manager,
        wallet_id,
        mobile,
        mobile_authorization_epoch: mobile_record.authorization_epoch,
        operation_id: view.operation_id,
        approval,
    }
}

async fn sign_decision(
    fixture: &FastPayFixture,
    decision: ApprovalDecision,
    sequence: u64,
    now: u64,
) -> SignedAgentFastPayApprovalDecision {
    let decision = AgentFastPayApprovalDecision::from_commitment(
        fixture.approval.clone(),
        decision,
        fixture.mobile.device_id().clone(),
        fixture.mobile_authorization_epoch,
        sequence,
        now,
    )
    .unwrap();
    SignedAgentFastPayApprovalDecision::sign(decision, &fixture.mobile)
        .await
        .unwrap()
}

#[tokio::test]
async fn approved_agent_fast_pay_signs_submits_and_survives_restart_without_l1_fallback() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let node = pilot_node::spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = pilot_node::create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mobile_record = fixtures::register_mobile(&mut manager, &wallet_id, &mobile, now + 3);
    let hub_account = Account::create_by("agent-fast-pay-live-hub").unwrap();
    let hub_address = hub_account.readable().to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_url = format!("http://{}", listener.local_addr().unwrap());

    let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let channel_id = derive_channel_id(&state.address, &hub_address, 1);
    let channel = ChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 5,
        close_height: 0,
        reuse_version: 1,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: state.address.clone(),
            hacash: "1".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub_address.clone(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    node.set_channel(channel_id.clone(), serde_json::to_value(&channel).unwrap())
        .await;
    let verified_node =
        crate::node_binding::verified_agent_node(&node.url, "testnet", fixtures::TESTNET_ANCHOR)
            .await
            .unwrap();
    let snapshot = verified_node.snapshot();
    let binding = AgentL2Binding::from_verified_channel(
        wallet_id.clone(),
        "testnet",
        AgentFastPayNetworkBinding {
            network_mode: "testnet".to_owned(),
            chain_id: snapshot.chain_id,
            genesis_identifier: snapshot.block_one_fingerprint.clone(),
            node_profile_id: snapshot.node_profile_commitment.clone(),
            network_instance_id: snapshot.network_instance_id.clone(),
            transaction_format_version: snapshot.transaction_format_version,
        },
        &state.address,
        &hub_url,
        &hub_address,
        &channel,
        snapshot.current_height,
        now + 4,
    )
    .unwrap();
    let agent_identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(state.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        name: "Fast Pay live execution agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: agent_identity.public_key_sec1_hex(),
        identity_fingerprint: agent_identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: now + 4,
        authorization_epoch: 1,
        server_identity: server_identity.clone(),
    };
    let identity_key_sha256 = paired.identity_key_sha256().unwrap();
    state.agents.insert(
        agent_id.as_str().to_owned(),
        AgentRecord {
            agent_id: agent_id.clone(),
            wallet_scope: paired.wallet_scope,
            name: paired.name,
            version: paired.version,
            identity_public_key_sec1: paired.identity_public_key_sec1_hex,
            identity_fingerprint: paired.identity_fingerprint,
            identity_key_sha256: identity_key_sha256.clone(),
            server_identity,
            status: AgentStatus::Active,
            authorization_epoch: 1,
            policy: AgentPolicy {
                permissions,
                max_per_payment_units: HacUnits::new(1_000_000),
                max_daily_units: HacUnits::new(10_000_000),
                max_pending_operations: 4,
                allowed_recipients: BTreeSet::from([hub_address.clone()]),
                blocked_recipients: BTreeSet::new(),
                allow_unlisted_recipient_with_approval: false,
                approval_mode: ApprovalMode::MobileManual,
                policy_epoch: state.policy_epoch,
            },
            paired_at: now + 4,
        },
    );
    state.l2_binding = Some(binding);
    state.updated_at = now + 4;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::L2BindingVerified,
            None,
            None,
            now + 4,
        )
        .unwrap();

    let hub_dir = tempfile::tempdir().unwrap();
    let hub = Arc::new(
        HubState::new_secure_with_policy(
            "Agent Fast Pay execution test",
            hub_address.clone(),
            node.url.clone(),
            None,
            hub_dir.path().join("hub-state.json"),
            hex::encode(hub_account.secret_key().serialize()),
            &"62".repeat(32),
            &"63".repeat(32),
            "testnet",
            0,
            0,
        )
        .unwrap(),
    );
    let hub_task = tokio::spawn(async move {
        axum::serve(listener, build_router(hub)).await.unwrap();
    });

    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        agent_id,
        authorization_epoch: 1,
        identity_key_sha256,
        capability: AgentPermission::CreatePaymentIntent,
    };
    let requested = manager
        .request_fast_pay_intent(
            &authorization,
            AgentFastPayRequest {
                idempotency_key: "agent-live-fast-pay-0001".to_owned(),
                amount_units: HacUnits::new(8_000),
                recipient: hub_address,
                reason: "exact live Agent Fast Pay test".to_owned(),
                expires_at: now + 300,
            },
            now + 5,
        )
        .unwrap();
    let approval = manager
        .pending_fast_pay_approval(
            &wallet_id,
            Some(&requested.operation_id),
            mobile.device_id(),
            now + 6,
        )
        .unwrap()
        .unwrap();
    let decision = AgentFastPayApprovalDecision::from_commitment(
        approval,
        ApprovalDecision::Approve,
        mobile.device_id().clone(),
        mobile_record.authorization_epoch,
        1,
        now + 7,
    )
    .unwrap();
    let signed_decision = SignedAgentFastPayApprovalDecision::sign(decision, &mobile)
        .await
        .unwrap();
    manager
        .apply_mobile_fast_pay_approval(&wallet_id, signed_decision, now + 8)
        .unwrap();
    let signed = manager
        .sign_prepared_approved_fast_pay_bill(&wallet_id, &requested.operation_id, now + 9)
        .await
        .unwrap();
    assert_eq!(signed.status, AgentFastPayStatus::Signed);
    assert_eq!(signed.wallet_fee_units, HacUnits::ZERO);
    assert_eq!(signed.network_fee_units, HacUnits::ZERO);
    let committed = manager
        .submit_signed_approved_fast_pay_bill(&wallet_id, &requested.operation_id, now + 10)
        .await
        .unwrap();
    assert_eq!(committed.status, AgentFastPayStatus::Committed);
    assert_eq!(committed.total_debit_units, committed.amount_units);
    assert_eq!(
        node.submit_count.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let root_path = root.path().to_owned();
    drop(manager);
    let mut restarted = AgentWalletManager::open(root_path).unwrap();
    restarted
        .unlock(&wallet_id, fixtures::PASSPHRASE, now + 11)
        .unwrap();
    let activity = restarted
        .list_fast_pay_operations_admin(&wallet_id, now + 12)
        .unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].status, AgentFastPayStatus::Committed);
    hub_task.abort();
}

#[tokio::test]
async fn pre_hub_execution_is_mirrored_durable_and_not_pre_sign_cancellable() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut fixture = prepare_fast_pay(now);
    let signed = sign_decision(&fixture, ApprovalDecision::Approve, 1, now + 7).await;
    fixture
        .manager
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed, now + 8)
        .unwrap();
    let prepared = fixture
        .manager
        .test_persist_approved_fast_pay_execution_journals(
            &fixture.wallet_id,
            &fixture.operation_id,
            now + 9,
        )
        .unwrap();
    assert_eq!(prepared.status, AgentFastPayStatus::ExecutionPrepared);
    let owner_authority = prepared.owner_authority_commitment.clone().unwrap();
    let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
    let mut state = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(
        !state
            .fast_pay_operations
            .get_mut(fixture.operation_id.as_str())
            .unwrap()
            .cancel_pre_signing()
    );
    let signer_binding = state
        .fast_pay_operations
        .get(fixture.operation_id.as_str())
        .unwrap()
        .signer_binding()
        .unwrap();
    let expected_restricted_authority = signer_binding.restricted_sender_authority.clone();
    let mut exact_limit_agent = state
        .agents
        .get(prepared.agent_id.as_str())
        .unwrap()
        .clone();
    exact_limit_agent.policy.max_pending_operations = 1;
    exact_limit_agent.policy.max_daily_units = prepared.total_debit_units;
    revalidate_approved_payment_policy(
        &state,
        &exact_limit_agent,
        &prepared.recipient,
        prepared.total_debit_units,
        now + 9,
    )
    .unwrap();
    exact_limit_agent.policy.max_pending_operations = 0;
    assert_eq!(
        revalidate_approved_payment_policy(
            &state,
            &exact_limit_agent,
            &prepared.recipient,
            prepared.total_debit_units,
            now + 9,
        ),
        Err(AgentWalletError::TooManyPendingOperations)
    );
    exact_limit_agent.policy.max_pending_operations = 1;
    exact_limit_agent.policy.max_daily_units = HacUnits::new(7_999);
    assert_eq!(
        revalidate_approved_payment_policy(
            &state,
            &exact_limit_agent,
            &prepared.recipient,
            prepared.total_debit_units,
            now + 9,
        ),
        Err(AgentWalletError::DailyLimitExceeded)
    );
    let binding = state.l2_binding.clone().unwrap();
    let policy_epoch = state.policy_epoch;
    let signer_epoch = state.signer_epoch;
    let emergency_epoch = state.emergency_epoch;
    let transition_probe = state
        .fast_pay_operations
        .get_mut(fixture.operation_id.as_str())
        .unwrap();
    let mut unsigned_recovery = transition_probe.clone();
    unsigned_recovery.mark_recovery_required().unwrap();
    unsigned_recovery
        .mark_reconciled_unsigned_prepared()
        .unwrap();
    assert_eq!(
        unsigned_recovery.status(),
        AgentFastPayStatus::ExecutionPrepared
    );
    let mut expired_unsigned = transition_probe.clone();
    expired_unsigned.mark_recovery_required().unwrap();
    expired_unsigned
        .mark_reconciled_unsigned_cancelled()
        .unwrap();
    assert_eq!(expired_unsigned.status(), AgentFastPayStatus::Cancelled);
    assert_eq!(expired_unsigned.view().reserved_units, HacUnits::ZERO);
    transition_probe.mark_signed().unwrap();
    assert_eq!(transition_probe.status(), AgentFastPayStatus::Signed);
    assert!(!transition_probe.cancel_pre_signing());
    transition_probe
        .signed_submission_view(
            &binding,
            prepared.agent_authorization_epoch,
            policy_epoch,
            signer_epoch,
            emergency_epoch,
        )
        .unwrap();
    let mut recovery_probe = transition_probe.clone();
    recovery_probe.mark_recovery_required().unwrap();
    assert_eq!(
        recovery_probe.status(),
        AgentFastPayStatus::RecoveryRequired
    );
    recovery_probe.mark_exact_retry_ready().unwrap();
    assert_eq!(recovery_probe.status(), AgentFastPayStatus::ExactRetryReady);
    recovery_probe.mark_exact_retry_ready().unwrap();
    assert_eq!(recovery_probe.status(), AgentFastPayStatus::ExactRetryReady);
    recovery_probe
        .post_sign_recovery_view(
            &binding,
            prepared.agent_authorization_epoch,
            policy_epoch,
            signer_epoch,
            emergency_epoch,
        )
        .unwrap();
    recovery_probe.mark_reconciled_submitted().unwrap();
    assert_eq!(recovery_probe.status(), AgentFastPayStatus::Submitted);
    transition_probe.mark_submitted().unwrap();
    assert_eq!(transition_probe.status(), AgentFastPayStatus::Submitted);
    assert_eq!(transition_probe.view().reserved_units, HacUnits::new(8_000));
    transition_probe.mark_awaiting_recipient().unwrap();
    assert_eq!(
        transition_probe.status(),
        AgentFastPayStatus::AwaitingRecipient
    );
    assert_eq!(transition_probe.view().reserved_units, HacUnits::new(8_000));
    transition_probe.mark_committed(now + 400).unwrap();
    assert_eq!(transition_probe.status(), AgentFastPayStatus::Committed);
    assert_eq!(transition_probe.view().reserved_units, HacUnits::ZERO);
    assert_eq!(transition_probe.view().settled_at, Some(now + 400));
    drop(state);

    let fast_pay_permit = fixture
        .manager
        .emergency_controller(&fixture.wallet_id)
        .unwrap()
        .issue_safety_permit(false)
        .unwrap();
    let session = fixture.manager.session(&fixture.wallet_id).unwrap();
    let restricted = session
        .signer
        .restrict_fast_pay(signer_binding.clone(), &fast_pay_permit, now + 9)
        .unwrap();
    drop(restricted);
    let mut wrong_epoch = signer_binding.clone();
    wrong_epoch.signer_epoch += 1;
    assert!(
        session
            .signer
            .restrict_fast_pay(wrong_epoch, &fast_pay_permit, now + 9)
            .is_err()
    );
    let mut expired = signer_binding.clone();
    expired.approval_expires_at = now + 9;
    assert!(
        session
            .signer
            .restrict_fast_pay(expired, &fast_pay_permit, now + 9)
            .is_err()
    );
    let mut wrong_scope = signer_binding;
    wrong_scope.wallet_scope = WalletScope::for_agent_wallet(&AgentWalletId::new());
    assert!(
        session
            .signer
            .restrict_fast_pay(wrong_scope, &fast_pay_permit, now + 9)
            .is_err()
    );

    let l2_root = fixture
        .manager
        .storage
        .paths(&fixture.wallet_id)
        .unwrap()
        .l2_dir();
    let session = fixture.manager.session(&fixture.wallet_id).unwrap();
    let safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
        &session.signer,
        l2_root,
        binding.wallet_scope().as_str(),
        binding.network_mode(),
        binding.hub_address(),
        binding.channel_id(),
    )
    .unwrap();
    let mirrored = safety.operation(&prepared.hub_operation_id).unwrap();
    assert_eq!(
        mirrored.owner_authority_commitment.as_deref(),
        Some(owner_authority.as_str())
    );
    assert_eq!(
        mirrored.amount_units,
        prepared.amount_units.to_millimeis_exact().unwrap()
    );
    assert_eq!(
        mirrored.restricted_sender_authority.as_ref(),
        Some(&expected_restricted_authority)
    );
    drop(safety);

    let root_path = fixture.root.path().to_owned();
    drop(fixture.manager);
    let mut restarted = AgentWalletManager::open(root_path).unwrap();
    restarted
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, now + 10)
        .unwrap();
    let (state_master, journal_key) = fixtures::keys(&restarted, &fixture.wallet_id);
    let recovered = restarted
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        recovered
            .fast_pay_operations
            .get(fixture.operation_id.as_str())
            .unwrap()
            .status(),
        AgentFastPayStatus::ExecutionPrepared
    );
}

#[tokio::test]
async fn rejection_is_atomic_and_exact_retry_is_idempotent_after_restart() {
    let now = 1_000;
    let mut fixture = prepare_fast_pay(now);
    let signed = sign_decision(&fixture, ApprovalDecision::Reject, 1, now + 7).await;
    let conflicting = sign_decision(&fixture, ApprovalDecision::Approve, 2, now + 7).await;
    let rejected = fixture
        .manager
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed.clone(), now + 8)
        .unwrap();
    assert_eq!(rejected.status, AgentFastPayStatus::Rejected);
    assert_eq!(rejected.reserved_units, HacUnits::ZERO);
    assert_eq!(rejected.network_fee_units, HacUnits::ZERO);
    assert_eq!(rejected.wallet_fee_units, HacUnits::ZERO);

    let root_path = fixture.root.path().to_owned();
    drop(fixture.manager);
    let mut restarted = AgentWalletManager::open(&root_path).unwrap();
    restarted
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, now + 400)
        .unwrap();
    let (state_master, journal_key) = fixtures::keys(&restarted, &fixture.wallet_id);
    let before_retry = restarted
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    let replayed = restarted
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed, now + 401)
        .unwrap();
    assert_eq!(replayed.status, AgentFastPayStatus::Rejected);
    let after_retry = restarted
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(after_retry.journal_sequence, before_retry.journal_sequence);
    assert_eq!(after_retry.updated_at, before_retry.updated_at);
    assert_eq!(
        restarted
            .pending_fast_pay_approval(
                &fixture.wallet_id,
                None,
                fixture.mobile.device_id(),
                now + 401,
            )
            .unwrap(),
        None
    );
    assert_eq!(
        restarted.apply_mobile_fast_pay_approval(&fixture.wallet_id, conflicting, now + 402,),
        Err(AgentWalletError::InvalidOperationState)
    );
}

#[tokio::test]
async fn tampering_writes_nothing_and_exact_approval_retry_survives_restart_and_expiry() {
    let now = 2_000;
    let mut fixture = prepare_fast_pay(now);
    let signed = sign_decision(&fixture, ApprovalDecision::Approve, 1, now + 7).await;
    let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
    let before = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();

    let mut tampered = signed.clone();
    tampered.decision.commitment.amount_units += 1_000;
    assert_eq!(
        fixture
            .manager
            .apply_mobile_fast_pay_approval(&fixture.wallet_id, tampered, now + 8,),
        Err(AgentWalletError::ApprovalCommitmentMismatch)
    );
    let unchanged = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(unchanged.journal_sequence, before.journal_sequence);
    assert_eq!(
        unchanged
            .fast_pay_operations
            .get(fixture.operation_id.as_str())
            .unwrap()
            .status(),
        AgentFastPayStatus::ApprovalRequested
    );

    let conflicting = sign_decision(&fixture, ApprovalDecision::Reject, 2, now + 7).await;
    let approved = fixture
        .manager
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed.clone(), now + 9)
        .unwrap();
    assert_eq!(approved.status, AgentFastPayStatus::Approved);
    assert_eq!(approved.reserved_units, HacUnits::new(8_000));
    assert_eq!(approved.total_debit_units, HacUnits::new(8_000));
    assert_eq!(approved.network_fee_units, HacUnits::ZERO);
    assert_eq!(approved.wallet_fee_units, HacUnits::ZERO);
    assert!(approved.agent_authorization_epoch > 0);
    assert_eq!(
        approved
            .owner_authority_commitment
            .as_ref()
            .map(String::len),
        Some(64)
    );
    let approved_state = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    let binding = approved_state.l2_binding.as_ref().unwrap();
    let operation = approved_state
        .fast_pay_operations
        .get(fixture.operation_id.as_str())
        .unwrap();
    assert_eq!(
        operation
            .approved_signing_view(
                binding,
                approved.agent_authorization_epoch,
                approved_state.policy_epoch,
                approved_state.signer_epoch,
                approved_state.emergency_epoch,
                now + 10,
            )
            .unwrap(),
        approved
    );
    assert_eq!(
        operation.approved_signing_view(
            binding,
            approved.agent_authorization_epoch + 1,
            approved_state.policy_epoch,
            approved_state.signer_epoch,
            approved_state.emergency_epoch,
            now + 10,
        ),
        Err(AgentWalletError::ApprovalCommitmentMismatch)
    );
    assert_eq!(
        operation.approved_signing_view(
            binding,
            approved.agent_authorization_epoch,
            approved_state.policy_epoch,
            approved_state.signer_epoch,
            approved_state.emergency_epoch,
            now + 400,
        ),
        Err(AgentWalletError::ApprovalExpired)
    );

    let root_path = fixture.root.path().to_owned();
    drop(fixture.manager);
    let mut restarted = AgentWalletManager::open(&root_path).unwrap();
    restarted
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, now + 400)
        .unwrap();
    let (state_master, journal_key) = fixtures::keys(&restarted, &fixture.wallet_id);
    let before_retry = restarted
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    let replayed = restarted
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed, now + 401)
        .unwrap();
    assert_eq!(replayed.status, AgentFastPayStatus::Approved);
    let after_retry = restarted
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(after_retry.journal_sequence, before_retry.journal_sequence);
    assert_eq!(after_retry.updated_at, before_retry.updated_at);
    assert_eq!(
        restarted.apply_mobile_fast_pay_approval(&fixture.wallet_id, conflicting, now + 402,),
        Err(AgentWalletError::InvalidOperationState)
    );
}

#[tokio::test]
async fn a_first_decision_arriving_after_expiry_writes_nothing() {
    let now = 3_000;
    let mut fixture = prepare_fast_pay(now);
    let signed = sign_decision(&fixture, ApprovalDecision::Approve, 1, now + 7).await;
    let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
    let before = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(
        fixture
            .manager
            .apply_mobile_fast_pay_approval(&fixture.wallet_id, signed, now + 400)
            .is_err()
    );
    let after = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(after.journal_sequence, before.journal_sequence);
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(
        after
            .fast_pay_operations
            .get(fixture.operation_id.as_str())
            .unwrap()
            .status(),
        AgentFastPayStatus::ApprovalRequested
    );
}

#[tokio::test]
async fn emergency_marker_blocks_approval_but_still_allows_exact_rejection() {
    let now = 4_000;
    let mut fixture = prepare_fast_pay(now);
    let approve = sign_decision(&fixture, ApprovalDecision::Approve, 1, now + 7).await;
    let reject = sign_decision(&fixture, ApprovalDecision::Reject, 2, now + 7).await;
    let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
    let before = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();

    fixture
        .manager
        .emergency_controller(&fixture.wallet_id)
        .unwrap()
        .request_stop()
        .unwrap();
    assert_eq!(
        fixture
            .manager
            .apply_mobile_fast_pay_approval(&fixture.wallet_id, approve, now + 8,),
        Err(AgentWalletError::AgentPaymentsSuspended)
    );
    let unchanged = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(unchanged.journal_sequence, before.journal_sequence);
    assert_eq!(unchanged.updated_at, before.updated_at);

    let rejected = fixture
        .manager
        .apply_mobile_fast_pay_approval(&fixture.wallet_id, reject, now + 9)
        .unwrap();
    assert_eq!(rejected.status, AgentFastPayStatus::Rejected);
    assert_eq!(rejected.reserved_units, HacUnits::ZERO);
}
