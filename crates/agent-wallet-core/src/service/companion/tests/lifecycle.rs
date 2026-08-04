use hpay_agent_connector::PairingSubmissionCommitment;
use hpay_companion_protocol::CompanionPayload;

use super::fixtures::*;
use super::*;
use crate::service::{AgentAuthorization, active_reservations, validate_policy_for_request};

fn persist_desktop_approval(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    approval: &ApprovalCommitment,
    now: u64,
) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let policy_epoch = state.policy_epoch;
    state
        .operations
        .get_mut(operation_id.as_str())
        .unwrap()
        .record_approval(
            approval.clone(),
            ApprovalMode::DesktopManual,
            policy_epoch,
            now,
        )
        .unwrap();
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ApprovalGranted,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )
        .unwrap();
}
#[tokio::test]
async fn global_policy_change_cancels_stale_approval_before_signing() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let agent_id = AgentId::parse(approval.agent_id.clone()).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();

    let mut changed = manager
        .agent_policy_admin(&wallet_id, &agent_id, 104)
        .unwrap();
    changed.max_pending_operations = 1;
    let updated = manager
        .update_agent_policy_admin(&wallet_id, &agent_id, changed, 104)
        .unwrap();
    assert_eq!(updated.policy_epoch, before.policy_epoch + 1);

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(after.journal_sequence, before.journal_sequence + 1);
    assert_eq!(operation.status, OperationStatus::Cancelled);
    assert_eq!(operation.reserved_units, HacUnits::ZERO);
    assert_eq!(operation.final_result.as_deref(), Some("policy_changed"));
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, approval, 105)
            .await
            .unwrap_err(),
        AgentWalletError::InvalidOperationState
    );

    let payload = manager
        .companion_status_snapshot(&wallet_id, 106)
        .await
        .unwrap();
    let CompanionPayload::StatusSnapshot { approvals, .. } = payload else {
        panic!("expected status snapshot");
    };
    assert!(approvals.is_empty());
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 107).unwrap();
    let persisted = restarted
        .list_operations_admin(&wallet_id, 108)
        .unwrap()
        .into_iter()
        .find(|operation| operation.operation_id == operation_id)
        .unwrap();
    assert_eq!(persisted.status, OperationStatus::Cancelled);
    assert_eq!(persisted.final_result.as_deref(), Some("policy_changed"));
}

#[tokio::test]
async fn expired_pre_signing_sweep_is_durable_and_recovers_budget_after_restart() {
    let (root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let agent_id = AgentId::parse(approval.agent_id).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(active_reservations(&before).unwrap() > HacUnits::ZERO);

    let persisted_agent = before.agents.get(agent_id.as_str()).unwrap();
    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: persisted_agent.wallet_scope.clone(),
        agent_id: agent_id.clone(),
        authorization_epoch: persisted_agent.authorization_epoch,
        identity_key_sha256: persisted_agent.identity_key_sha256.clone(),
        capability: AgentPermission::CreatePaymentIntent,
    };
    let new_request = AgentPaymentRequest {
        idempotency_key: "after-expiry-budget-recovery".to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(10_000),
        recipient: RECIPIENT.to_owned(),
        reason: "prove expired reservation is released".to_owned(),
        expires_at: 500,
    };
    assert!(
        manager
            .create_payment_intent(&authorization, new_request.clone(), 403)
            .await
            .is_err()
    );

    let after_sweep = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(after_sweep.journal_sequence, before.journal_sequence + 2);
    assert!(!after_sweep.operations.contains_key(operation_id.as_str()));
    assert_eq!(active_reservations(&after_sweep).unwrap(), HacUnits::ZERO);

    let listed = manager.list_operations_admin(&wallet_id, 404).unwrap();
    assert!(
        listed
            .iter()
            .all(|operation| operation.operation_id != operation_id)
    );
    let after_second_entry = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        after_second_entry.journal_sequence,
        after_sweep.journal_sequence
    );
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 405).unwrap();
    let (state_master, journal_key) = keys(&restarted, &wallet_id);
    let recovered = restarted
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(!recovered.operations.contains_key(operation_id.as_str()));

    let mut budget_agent = recovered.agents.get(agent_id.as_str()).unwrap().clone();
    budget_agent.policy.max_pending_operations = 1;
    budget_agent
        .policy
        .allowed_recipients
        .insert(RECIPIENT.to_owned());
    let total_debit = new_request
        .amount_units
        .checked_add(HacUnits::MIN_NETWORK_FEE)
        .unwrap();
    assert!(
        validate_policy_for_request(&recovered, &budget_agent, &new_request, total_debit, 406)
            .is_ok()
    );
}

#[test]
fn pairing_epoch_change_cancels_approved_operations_and_releases_reservations() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    assert_eq!(approval.wallet_fee_units, 0);
    persist_desktop_approval(&mut manager, &wallet_id, &operation_id, &approval, 104);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(
        before
            .operations
            .get(operation_id.as_str())
            .unwrap()
            .status(),
        OperationStatus::Approved
    );
    assert!(active_reservations(&before).unwrap() > HacUnits::ZERO);

    let identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(before.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        name: "Policy epoch transition agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
        identity_fingerprint: identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: 105,
        authorization_epoch: 1,
        server_identity,
    };
    let policy = AgentPolicy {
        permissions,
        max_per_payment_units: HacUnits::new(1_000_000),
        max_daily_units: HacUnits::new(10_000_000),
        max_pending_operations: 4,
        allowed_recipients: BTreeSet::new(),
        blocked_recipients: BTreeSet::new(),
        approval_mode: ApprovalMode::DesktopManual,
        policy_epoch: before.policy_epoch,
    };
    let paired_record = manager
        .commit_paired_agent(
            paired,
            policy,
            &format!("pair_{}", "12".repeat(32)),
            PairingSubmissionCommitment::parse("ab".repeat(32)).unwrap(),
            200,
            105,
        )
        .unwrap();

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = after.operations.get(operation_id.as_str()).unwrap().view();
    assert_eq!(after.policy_epoch, before.policy_epoch + 1);
    assert_eq!(paired_record.policy.policy_epoch, after.policy_epoch);
    assert_eq!(operation.status, OperationStatus::Cancelled);
    assert_eq!(operation.reserved_units, HacUnits::ZERO);
    assert_eq!(operation.final_result.as_deref(), Some("policy_changed"));
    assert_eq!(active_reservations(&after).unwrap(), HacUnits::ZERO);
}

#[test]
fn payment_reenable_epoch_change_cancels_approved_operations() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    assert_eq!(approval.wallet_fee_units, 0);
    persist_desktop_approval(&mut manager, &wallet_id, &operation_id, &approval, 104);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(before.payments_suspended);
    assert_eq!(
        before
            .operations
            .get(operation_id.as_str())
            .unwrap()
            .status(),
        OperationStatus::Approved
    );

    manager
        .enable_agent_payments_locally(&wallet_id, 105)
        .unwrap();
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = after.operations.get(operation_id.as_str()).unwrap().view();
    assert!(!after.payments_suspended);
    assert_eq!(after.policy_epoch, before.policy_epoch + 1);
    assert_eq!(after.journal_sequence, before.journal_sequence + 1);
    assert_eq!(operation.status, OperationStatus::Cancelled);
    assert_eq!(operation.reserved_units, HacUnits::ZERO);
    assert_eq!(operation.final_result.as_deref(), Some("policy_changed"));
    assert_eq!(active_reservations(&after).unwrap(), HacUnits::ZERO);
}

#[test]
fn recipient_policy_is_default_deny_exact_allow_and_blocked_precedence() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let (approval, _) = prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let agent_id = AgentId::parse(approval.agent_id).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let mut agent = state.agents.get(agent_id.as_str()).unwrap().clone();
    let request = AgentPaymentRequest {
        idempotency_key: "recipient-default-deny".to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(10_000),
        recipient: RECIPIENT.to_owned(),
        reason: "recipient policy invariant".to_owned(),
        expires_at: 300,
    };
    let total = request
        .amount_units
        .checked_add(HacUnits::MIN_NETWORK_FEE)
        .unwrap();

    agent.policy.allowed_recipients.clear();
    agent.policy.blocked_recipients.clear();
    assert_eq!(
        validate_policy_for_request(&state, &agent, &request, total, 104),
        Err(AgentWalletError::RecipientNotAllowed)
    );
    agent.policy.allowed_recipients.insert(RECIPIENT.to_owned());
    assert!(validate_policy_for_request(&state, &agent, &request, total, 104).is_ok());
    agent.policy.blocked_recipients.insert(RECIPIENT.to_owned());
    assert_eq!(
        validate_policy_for_request(&state, &agent, &request, total, 104),
        Err(AgentWalletError::RecipientNotAllowed)
    );
}

#[test]
fn revocation_immediately_prunes_agents_terminal_pre_signing_rows_and_idempotency() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let (approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let agent_id = AgentId::parse(approval.agent_id).unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let view = state.operations.get(operation_id.as_str()).unwrap().view();
    let scoped_key = crate::service::scoped_idempotency_key(&agent_id, &view.idempotency_key);
    state.idempotency.insert(
        scoped_key.clone(),
        crate::service::IdempotencyRecord {
            request_commitment: view.request_commitment,
            operation_id: operation_id.clone(),
        },
    );
    state.updated_at = 104;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            104,
        )
        .unwrap();

    manager.revoke_agent(&wallet_id, &agent_id, 105).unwrap();
    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(!after.operations.contains_key(operation_id.as_str()));
    assert!(!after.idempotency.contains_key(&scoped_key));
    assert_eq!(
        after.agents.get(agent_id.as_str()).unwrap().status,
        AgentStatus::Revoked
    );
}
#[tokio::test]
async fn legacy_mainnet_anchor_ready_remains_read_only_across_every_payment_path() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mobile_record = register_mobile(&mut manager, &wallet_id, &mobile, 102);

    let (create_approval, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 110);
    let (desktop_approval, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 111);
    let (approved_approval, approved_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 112);
    persist_desktop_approval(
        &mut manager,
        &wallet_id,
        &approved_id,
        &approved_approval,
        113,
    );
    let (signed_approval, signed_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 114);
    persist_desktop_approval(&mut manager, &wallet_id, &signed_id, &signed_approval, 115);
    let (submitted_approval, submitted_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 116);
    persist_desktop_approval(
        &mut manager,
        &wallet_id,
        &submitted_id,
        &submitted_approval,
        117,
    );
    let (mobile_approval, _) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 118);
    let mobile_decision = signed_decision(
        &mobile_approval,
        ApprovalDecision::Approve,
        &mobile,
        mobile_record.authorization_epoch,
        1,
        119,
    )
    .await;

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let create_agent_id = AgentId::parse(create_approval.agent_id.clone()).unwrap();
    let create_agent = state.agents.get(create_agent_id.as_str()).unwrap();
    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: create_agent.wallet_scope.clone(),
        agent_id: create_agent_id,
        authorization_epoch: create_agent.authorization_epoch,
        identity_key_sha256: create_agent.identity_key_sha256.clone(),
        capability: AgentPermission::CreatePaymentIntent,
    };
    let tx_hash = "ab".repeat(32);
    for (operation_id, status) in [
        (&signed_id, OperationStatus::Signed),
        (&submitted_id, OperationStatus::BroadcastSubmitted),
    ] {
        let operation = state.operations.get_mut(operation_id.as_str()).unwrap();
        let mut encoded = serde_json::to_value(&*operation).unwrap();
        encoded["status"] = serde_json::to_value(status).unwrap();
        encoded["signed_tx_hex"] = serde_json::Value::String("00".to_owned());
        encoded["tx_hash"] = serde_json::Value::String(tx_hash.clone());
        *operation = serde_json::from_value(encoded).unwrap();
    }
    state.network_mode = "mainnet".to_owned();
    state.block_one_fingerprint =
        crate::node_binding::anchor_for_new_wallet("mainnet", None).unwrap();
    state.external_rollback_anchor_ready = true;
    state.updated_at = 120;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            120,
        )
        .unwrap();

    let baseline = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let baseline_bytes = serde_json::to_vec(&baseline).unwrap();
    assert_eq!(baseline.network_mode, "mainnet");
    assert!(baseline.external_rollback_anchor_ready);
    assert!(!crate::service::agent_spending_ready("mainnet"));

    let request = AgentPaymentRequest {
        idempotency_key: "legacy-mainnet-create-is-blocked".to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(10_000),
        recipient: RECIPIENT.to_owned(),
        reason: "mainnet foundation must remain read only".to_owned(),
        expires_at: 400,
    };
    assert_eq!(
        manager
            .create_payment_intent(&authorization, request, 121)
            .await,
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager
            .approve_desktop_and_broadcast(&wallet_id, desktop_approval, 122)
            .await,
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager.resume_payment(&wallet_id, &approved_id, 123).await,
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager.resume_payment(&wallet_id, &signed_id, 124).await,
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager.resume_payment(&wallet_id, &submitted_id, 125).await,
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager.confirm_broadcast(&wallet_id, &submitted_id, &tx_hash, 126),
        Err(AgentWalletError::SigningBlocked)
    );
    assert_eq!(
        manager
            .apply_mobile_approval_and_broadcast(&wallet_id, mobile_decision, 127)
            .await,
        Err(AgentWalletError::SigningBlocked)
    );

    let after = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(serde_json::to_vec(&after).unwrap(), baseline_bytes);
}
