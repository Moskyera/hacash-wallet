use hpay_companion_protocol::{AgentAuthorizationState, CompanionPayload};

use super::fixtures::*;
use super::*;
use crate::amount::HacUnits;
use crate::node_binding::AgentNodeStatus;
use crate::operation::{ApprovalMode, OperationStatus};
use crate::service::{AgentWalletOverview, AgentWalletState};

fn verified_state(manager: &AgentWalletManager, wallet_id: &AgentWalletId) -> AgentWalletState {
    let (state_master, journal_key) = keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
}

fn deterministic_overview(
    state: &AgentWalletState,
    node_status: AgentNodeStatus,
    available_units: Option<HacUnits>,
) -> AgentWalletOverview {
    let reserved_units = state
        .operations
        .values()
        .try_fold(HacUnits::ZERO, |total, operation| {
            total.checked_add(operation.view().reserved_units)
        })
        .unwrap();
    AgentWalletOverview {
        wallet_id: state.wallet_id.clone(),
        address: state.address.clone(),
        network_mode: state.network_mode.clone(),
        node_url: Some(state.node_url.clone()),
        block_one_fingerprint: Some(state.block_one_fingerprint.clone()),
        node: None,
        node_status,
        node_error: (node_status != AgentNodeStatus::Verified)
            .then(|| "deterministic unavailable node".to_owned()),
        unlocked: true,
        payments_suspended: state.payments_suspended,
        mainnet_spending_ready: state.network_mode != "mainnet",
        trusted_mainnet_fast_pay_pilot: state.trusted_mainnet_fast_pay_pilot,
        l2_binding: state.l2_binding.clone(),
        l2_channel_setup: state
            .l2_channel_setup
            .as_ref()
            .map(|operation| operation.review.clone()),
        l2_channel_close: state
            .l2_channel_close
            .as_ref()
            .map(|operation| operation.review.clone()),
        hvm_channel_binding: state.hvm_channel_binding.clone(),
        hvm_registry_binding: state.hvm_registry_binding.clone(),
        confirmed_balance_units: available_units.map(|available| {
            available
                .checked_add(reserved_units)
                .expect("test balance must fit")
        }),
        reserved_units,
        available_units,
        fast_pay_deposit_units: None,
        fast_pay_reserved_units: HacUnits::ZERO,
        fast_pay_available_units: None,
        spent_today_units: HacUnits::ZERO,
        spent_this_month_units: HacUnits::ZERO,
        authorized_agents: state
            .agents
            .values()
            .filter(|agent| agent.status == AgentStatus::Active)
            .count()
            .try_into()
            .unwrap(),
        pending_approvals: state
            .operations
            .values()
            .filter(|operation| operation.status() == OperationStatus::ApprovalRequested)
            .count()
            .try_into()
            .unwrap(),
        pilot_enabled: cfg!(feature = "agent-wallet-testnet-pilot"),
        mobile_witness_ready: state.rollback_witness.is_some(),
        mobile_witness_synchronized: state
            .rollback_witness
            .as_ref()
            .is_some_and(|witness| witness.pending.is_none()),
        latest_anchor_sequence: state
            .rollback_witness
            .as_ref()
            .map_or(0, |witness| witness.last_anchor_sequence),
        witness_rotation_phase: state
            .witness_rotation
            .as_ref()
            .map(|rotation| rotation.phase),
        unresolved_signed_operations: 0,
        stale: available_units.is_none(),
    }
}

#[test]
fn unavailable_balance_stays_none_and_identity_comes_from_verified_state() {
    let (_root, manager, wallet_id) = create_manager(100);
    let state = verified_state(&manager, &wallet_id);
    let overview = deterministic_overview(&state, AgentNodeStatus::BalanceError, None);
    let payload =
        super::super::snapshot::build_companion_status_snapshot(overview.clone(), &state, 102)
            .unwrap();
    assert!(payload.validate_for_wallet(wallet_id.as_str()).is_ok());

    let json = serde_json::to_string(&payload).unwrap();
    assert!(!json.contains("provider"));
    assert!(!json.contains("connected"));
    let CompanionPayload::StatusSnapshot { status, .. } = payload else {
        panic!("expected status snapshot");
    };
    assert_eq!(status.agent_wallet_id, wallet_id.to_string());
    assert_eq!(status.address, state.address);
    assert_eq!(status.node_status, "balance_error");
    assert_eq!(status.available_units, None);

    let mut mismatched = overview;
    mismatched.address = RECIPIENT.to_owned();
    assert_eq!(
        super::super::snapshot::build_companion_status_snapshot(mismatched, &state, 102,),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[test]
fn snapshot_uses_persisted_authorization_policy_approval_and_activity() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    let (expected_approval, operation_id) =
        prepare_pending(&mut manager, &wallet_id, ApprovalMode::MobileManual, 103);
    let state = verified_state(&manager, &wallet_id);
    let operation = state.operations.get(operation_id.as_str()).unwrap().view();
    let source_agent = state.agents.values().next().unwrap();
    let payload = super::super::snapshot::build_companion_status_snapshot(
        deterministic_overview(&state, AgentNodeStatus::Offline, None),
        &state,
        104,
    )
    .unwrap();
    assert!(payload.validate_for_wallet(wallet_id.as_str()).is_ok());

    let CompanionPayload::StatusSnapshot {
        status,
        agents,
        policies,
        approvals,
        activity,
    } = payload
    else {
        panic!("expected status snapshot");
    };
    assert_eq!(status.reserved_units, operation.reserved_units.get());
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_id, source_agent.agent_id.to_string());
    assert_eq!(agents[0].display_name, source_agent.name);
    assert_eq!(agents[0].authorization, AgentAuthorizationState::Authorized);

    assert_eq!(policies.len(), 1);
    let policy = &policies[0];
    assert_eq!(policy.agent_id, source_agent.agent_id.to_string());
    assert_eq!(
        policy.max_per_payment_units,
        source_agent.policy.max_per_payment_units.get()
    );
    assert_eq!(
        policy.max_daily_units,
        source_agent.policy.max_daily_units.get()
    );
    assert_eq!(
        policy.max_pending_operations,
        source_agent.policy.max_pending_operations
    );
    assert_eq!(policy.approval_mode, "mobile_manual");
    assert_eq!(policy.permissions, vec!["create_payment_intent"]);
    assert_eq!(
        policy.allowed_recipients,
        source_agent
            .policy
            .allowed_recipients
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    );
    assert_eq!(
        policy.blocked_recipients,
        source_agent
            .policy
            .blocked_recipients
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    );
    assert_eq!(policy.policy_epoch, source_agent.policy.policy_epoch);

    assert_eq!(approvals, vec![expected_approval.clone()]);
    assert_eq!(approvals[0].wallet_fee_units, 0);
    assert_eq!(
        approvals[0].total_debit_units,
        approvals[0]
            .amount_units
            .checked_add(approvals[0].fee_units)
            .unwrap()
    );
    assert_eq!(
        approvals[0].total_debit_units,
        operation.total_debit_units.get()
    );

    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].activity_id, operation.operation_id.to_string());
    assert_eq!(activity[0].description, operation.reason);
    assert_eq!(activity[0].asset, operation.asset);
    assert_eq!(activity[0].recipient, operation.recipient);
    assert_eq!(activity[0].amount_units, operation.amount_units.get());
    assert_eq!(activity[0].occurred_at, operation.created_at);
    assert_eq!(activity[0].status, "approval_requested");
}

#[test]
fn canonical_payload_validation_rejects_invalid_activity_and_scope() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    prepare_pending(&mut manager, &wallet_id, ApprovalMode::DesktopManual, 103);
    let state = verified_state(&manager, &wallet_id);
    let payload = super::super::snapshot::build_companion_status_snapshot(
        deterministic_overview(&state, AgentNodeStatus::Unchecked, None),
        &state,
        104,
    )
    .unwrap();

    let mut invalid_activity = payload.clone();
    let CompanionPayload::StatusSnapshot { activity, .. } = &mut invalid_activity else {
        panic!("expected status snapshot");
    };
    activity[0].recipient.clear();
    assert!(
        invalid_activity
            .validate_for_wallet(wallet_id.as_str())
            .is_err()
    );

    let mut wrong_scope = payload;
    let CompanionPayload::StatusSnapshot { status, .. } = &mut wrong_scope else {
        panic!("expected status snapshot");
    };
    status.agent_wallet_id = AgentWalletId::new().to_string();
    assert!(wrong_scope.validate_for_wallet(wallet_id.as_str()).is_err());
}

/// Every `OperationStatus`, listed once.
///
/// The exhaustive `match` in
/// `every_operation_status_appears_exactly_once_in_the_status_inventory` has no
/// wildcard arm, so adding a variant to `OperationStatus` fails to compile until
/// it is listed here. That is what makes the set-equality test below a proof
/// over the whole enum rather than over a hand-picked sample.
const ALL_OPERATION_STATUSES: [OperationStatus; 18] = [
    OperationStatus::PaymentIntentCreated,
    OperationStatus::FundsReserved,
    OperationStatus::UnsignedTransactionPersisted,
    OperationStatus::ApprovalRequested,
    OperationStatus::Approved,
    OperationStatus::Rejected,
    OperationStatus::Signed,
    OperationStatus::SignedAwaitingWitness,
    OperationStatus::WitnessedAwaitingBroadcast,
    OperationStatus::BroadcastSubmitted,
    OperationStatus::BroadcastUncertain,
    OperationStatus::SubmittedAwaitingFinalWitness,
    OperationStatus::ReconciliationRequired,
    OperationStatus::ReconciledAwaitingFinalWitness,
    OperationStatus::Committed,
    OperationStatus::Failed,
    OperationStatus::Cancelled,
    OperationStatus::RecoveryRequired,
];

#[test]
fn every_operation_status_appears_exactly_once_in_the_status_inventory() {
    use super::super::snapshot::operation_status_name;

    let mut seen = BTreeSet::new();
    for status in ALL_OPERATION_STATUSES {
        assert!(
            seen.insert(operation_status_name(status)),
            "{status:?} is listed twice"
        );
        #[allow(clippy::match_same_arms)]
        match status {
            OperationStatus::PaymentIntentCreated => {}
            OperationStatus::FundsReserved => {}
            OperationStatus::UnsignedTransactionPersisted => {}
            OperationStatus::ApprovalRequested => {}
            OperationStatus::Approved => {}
            OperationStatus::Rejected => {}
            OperationStatus::Signed => {}
            OperationStatus::SignedAwaitingWitness => {}
            OperationStatus::WitnessedAwaitingBroadcast => {}
            OperationStatus::BroadcastSubmitted => {}
            OperationStatus::BroadcastUncertain => {}
            OperationStatus::SubmittedAwaitingFinalWitness => {}
            OperationStatus::ReconciliationRequired => {}
            OperationStatus::ReconciledAwaitingFinalWitness => {}
            OperationStatus::Committed => {}
            OperationStatus::Failed => {}
            OperationStatus::Cancelled => {}
            OperationStatus::RecoveryRequired => {}
        }
    }
    assert_eq!(seen.len(), ALL_OPERATION_STATUSES.len());
}

/// The proof obligation for the witness-discovery disclosure.
///
/// `WITNESS_PENDING_OPERATION_STATUS_NAMES` is the exact set of wire status
/// names for which the companion snapshot filter will disclose an operation id
/// to a phone holding `WitnessRollbackAnchor`. `pending_rollback_anchor` admits
/// exactly `OperationStatus::awaits_mobile_witness`. If the disclosure set were
/// wider the phone would receive a pointer it could not act on - a leak with no
/// purpose. If it were narrower an operation would strand with no way for the
/// phone to find it. Equality is checked over every variant.
#[test]
fn witness_pending_status_names_equal_the_anchor_admission_set() {
    use super::super::snapshot::operation_status_name;

    for status in ALL_OPERATION_STATUSES {
        let name = operation_status_name(status);
        assert_eq!(
            status.awaits_mobile_witness(),
            crate::WITNESS_PENDING_OPERATION_STATUS_NAMES.contains(&name),
            "{status:?} ({name}) is admitted by exactly one of the anchor gate and the disclosure filter"
        );
    }
    assert_eq!(
        crate::WITNESS_PENDING_OPERATION_STATUS_NAMES.len(),
        ALL_OPERATION_STATUSES
            .into_iter()
            .filter(|status| status.awaits_mobile_witness())
            .count(),
        "the disclosure list must not carry a name that no status produces"
    );
    // The phone matches against the protocol's copy of this vocabulary, because
    // it has no access to the desktop's operation state machine. The two must
    // name the same set or the phone would offer the owner a confirmation for
    // an operation the desktop will not hand it an anchor for.
    assert_eq!(
        crate::WITNESS_PENDING_OPERATION_STATUS_NAMES
            .into_iter()
            .collect::<BTreeSet<_>>(),
        hpay_companion_protocol::WITNESS_PENDING_ACTIVITY_STATUSES
            .into_iter()
            .collect::<BTreeSet<_>>(),
    );
}
