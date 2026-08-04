//! Canonical read-only snapshot for an authenticated mobile companion.
//!
//! Every value comes from the verified Agent Wallet state. Unsupported
//! provider, service, asset and live-connection claims are intentionally absent.

use hpay_companion_protocol::{
    ActivitySummary, AgentAuthorizationState, AgentPolicySummary, AgentSummary, CompanionPayload,
    CompanionStatus,
};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::node_binding::AgentNodeStatus;
use crate::operation::{ApprovalMode, OperationStatus};
use crate::policy::{AgentPermission, AgentStatus};
use crate::service::{AgentWalletOverview, AgentWalletState};
use crate::types::AgentWalletId;

use super::super::AgentWalletManager;

const MAX_COMPANION_ACTIVITY: usize = 256;

impl AgentWalletManager {
    /// Builds a read-only, wallet-scoped snapshot after transport replay has
    /// been durably consumed. An unavailable node balance remains `None`; it is
    /// never converted to a misleading zero.
    pub async fn companion_status_snapshot(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<CompanionPayload> {
        self.ensure_session_active(wallet_id, now)?;
        let overview = self.overview(wallet_id, now).await?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        build_companion_status_snapshot(overview, &state, now)
    }
}

/// Converts already verified state plus one typed node overview into the wire
/// snapshot. Keeping this pure makes security assertions deterministic.
pub(super) fn build_companion_status_snapshot(
    overview: AgentWalletOverview,
    state: &AgentWalletState,
    now: u64,
) -> AgentWalletResult<CompanionPayload> {
    if overview.wallet_id != state.wallet_id
        || overview.address != state.address
        || overview.network_mode != state.network_mode
    {
        return Err(AgentWalletError::RecoveryRequired);
    }

    let status = CompanionStatus {
        agent_wallet_id: state.wallet_id.to_string(),
        address: state.address.clone(),
        available_units: overview.available_units.map(|value| value.get()),
        node_status: node_status_name(overview.node_status).to_owned(),
        reserved_units: overview.reserved_units.get(),
        spent_today_units: overview.spent_today_units.get(),
        spent_month_units: overview.spent_this_month_units.get(),
        paused: overview.payments_suspended,
        policy_epoch: state.policy_epoch,
    };

    let agents = state
        .agents
        .values()
        .map(|agent| AgentSummary {
            agent_id: agent.agent_id.to_string(),
            display_name: agent.name.clone(),
            authorization: match agent.status {
                AgentStatus::Active => AgentAuthorizationState::Authorized,
                AgentStatus::Disabled => AgentAuthorizationState::Disabled,
                AgentStatus::Revoked => AgentAuthorizationState::Revoked,
            },
        })
        .collect();

    let policies = state
        .agents
        .values()
        .map(|agent| AgentPolicySummary {
            agent_id: agent.agent_id.to_string(),
            max_per_payment_units: agent.policy.max_per_payment_units.get(),
            max_daily_units: agent.policy.max_daily_units.get(),
            max_pending_operations: agent.policy.max_pending_operations,
            approval_mode: approval_mode_name(agent.policy.approval_mode).to_owned(),
            permissions: agent
                .policy
                .permissions
                .iter()
                .copied()
                .map(permission_name)
                .map(str::to_owned)
                .collect(),
            allowed_recipients: agent.policy.allowed_recipients.iter().cloned().collect(),
            blocked_recipients: agent.policy.blocked_recipients.iter().cloned().collect(),
            policy_epoch: agent.policy.policy_epoch,
        })
        .collect();

    let approvals = state
        .operations
        .values()
        .filter(|operation| {
            operation.status() == OperationStatus::ApprovalRequested
                && operation.view().expires_at > now
        })
        .filter_map(|operation| operation.stored_approval().ok().cloned())
        .collect();

    let mut operation_views: Vec<_> = state
        .operations
        .values()
        .map(super::super::AgentOperation::view)
        .collect();
    operation_views.sort_by_key(|view| {
        (
            std::cmp::Reverse(view.created_at),
            view.operation_id.clone(),
        )
    });
    let activity = operation_views
        .into_iter()
        .take(MAX_COMPANION_ACTIVITY)
        .map(|view| ActivitySummary {
            activity_id: view.operation_id.to_string(),
            description: view.reason,
            asset: view.asset,
            recipient: view.recipient,
            amount_units: view.amount_units.get(),
            occurred_at: view.created_at,
            status: operation_status_name(view.status).to_owned(),
        })
        .collect();

    let payload = CompanionPayload::StatusSnapshot {
        status,
        agents,
        policies,
        approvals,
        activity,
    };
    payload
        .validate_for_wallet(state.wallet_id.as_str())
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
    Ok(payload)
}

fn node_status_name(status: AgentNodeStatus) -> &'static str {
    match status {
        AgentNodeStatus::Unchecked => "unchecked",
        AgentNodeStatus::Verified => "verified",
        AgentNodeStatus::Offline => "offline",
        AgentNodeStatus::NetworkMismatch => "network_mismatch",
        AgentNodeStatus::CapabilityMismatch => "capability_mismatch",
        AgentNodeStatus::BalanceError => "balance_error",
    }
}

fn approval_mode_name(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::DesktopManual => "desktop_manual",
        ApprovalMode::MobileManual => "mobile_manual",
        ApprovalMode::EitherTrustedDevice => "either_trusted_device",
    }
}

fn permission_name(permission: AgentPermission) -> &'static str {
    match permission {
        AgentPermission::ReadWalletInfo => "read_wallet_info",
        AgentPermission::ReadBalance => "read_balance",
        AgentPermission::CreatePaymentIntent => "create_payment_intent",
        AgentPermission::ReadOwnOperationStatus => "read_own_operation_status",
        AgentPermission::ListOwnOperations => "list_own_operations",
        AgentPermission::CancelOwnUnsignedOperation => "cancel_own_unsigned_operation",
    }
}

fn operation_status_name(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::PaymentIntentCreated => "payment_intent_created",
        OperationStatus::FundsReserved => "funds_reserved",
        OperationStatus::UnsignedTransactionPersisted => "unsigned_transaction_persisted",
        OperationStatus::ApprovalRequested => "approval_requested",
        OperationStatus::Approved => "approved",
        OperationStatus::Rejected => "rejected",
        OperationStatus::Signed => "signed",
        OperationStatus::SignedAwaitingWitness => "signed_awaiting_witness",
        OperationStatus::WitnessedAwaitingBroadcast => "witnessed_awaiting_broadcast",
        OperationStatus::BroadcastSubmitted => "broadcast_submitted",
        OperationStatus::BroadcastUncertain => "broadcast_uncertain",
        OperationStatus::SubmittedAwaitingFinalWitness => "submitted_awaiting_final_witness",
        OperationStatus::ReconciliationRequired => "reconciliation_required",
        OperationStatus::ReconciledAwaitingFinalWitness => "reconciled_awaiting_final_witness",
        OperationStatus::Committed => "committed",
        OperationStatus::Failed => "failed",
        OperationStatus::Cancelled => "cancelled",
        OperationStatus::RecoveryRequired => "recovery_required",
    }
}
