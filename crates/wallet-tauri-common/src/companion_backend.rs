//! Narrow adapter between the private-LAN companion runtime and Agent Wallet.
//!
//! The adapter deliberately exposes only authenticated read-only status sync.
//! It rejects approval decisions and admin commands, and has no
//! Personal Wallet, generic send, key export, settings, provider or L2 surface.

use std::collections::BTreeSet;
use std::sync::Arc;

use agent_wallet_core::{AgentDesktopSessionAttempt, AgentWalletId, AgentWalletManager};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use agent_wallet_core::{OperationId, OperationStatus};
use hpay_companion_lan_runtime::{
    DesktopHandshake, DesktopSessionBackend, HandleMessageResult, LanRuntimeError, RuntimeFuture,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::WitnessRotationPhase;
use hpay_companion_protocol::{
    CompanionConnection, CompanionMessage, CompanionPayload, DeviceId, DevicePermission,
    EstablishedSession, MAX_REQUESTED_SESSION_LIFETIME_SECS, PROTOCOL_VERSION, ReplayMetadata,
    SessionChallenge, SessionConfirmation, SessionResponse,
};
use tokio::sync::Mutex;

/// Taken from the protocol rather than restated, so it cannot drift back up
/// against the verification cap. It used to be `5 * 60`, the cap itself, which
/// left the phone's derived response no room for a clock offset of even one
/// second. See `MAX_REQUESTED_SESSION_LIFETIME_SECS`.
const SESSION_LIFETIME_SECS: u64 = MAX_REQUESTED_SESSION_LIFETIME_SECS;
const RESPONSE_LIFETIME_SECS: u64 = 60;
// Encrypted-frame JSON hex-encodes ciphertext, so keep plaintext well below 256 KiB.
const MAX_SYNC_MESSAGE_BYTES: usize = 96 * 1024;

/// Production backend for one explicit Agent Wallet. The wallet scope cannot
/// be selected by a message sent over the network.
pub struct AgentCompanionBackend {
    wallet_id: AgentWalletId,
    manager: Arc<Mutex<AgentWalletManager>>,
}

impl AgentCompanionBackend {
    pub fn new(wallet_id: AgentWalletId, manager: Arc<Mutex<AgentWalletManager>>) -> Self {
        Self { wallet_id, manager }
    }
}

struct ManagerOwnedDesktopHandshake {
    wallet_id: AgentWalletId,
    manager: Arc<Mutex<AgentWalletManager>>,
    attempt: AgentDesktopSessionAttempt,
}

impl DesktopHandshake for ManagerOwnedDesktopHandshake {
    fn challenge(&self) -> &SessionChallenge {
        self.attempt.challenge()
    }

    fn accept(
        self: Box<Self>,
        response: SessionResponse,
        now: u64,
    ) -> RuntimeFuture<'static, (SessionConfirmation, EstablishedSession)> {
        let Self {
            wallet_id,
            manager,
            attempt,
        } = *self;
        Box::pin(async move {
            manager
                .lock()
                .await
                .accept_companion_desktop_response(&wallet_id, attempt, &response, now)
                .await
                .map_err(|_| LanRuntimeError::Backend)
        })
    }
}

impl DesktopSessionBackend for AgentCompanionBackend {
    fn begin<'a>(
        &'a self,
        mobile_device_id: DeviceId,
        now: u64,
    ) -> RuntimeFuture<'a, Box<dyn DesktopHandshake>> {
        Box::pin(async move {
            let attempt = self
                .manager
                .lock()
                .await
                .start_companion_desktop_session(
                    &self.wallet_id,
                    &mobile_device_id,
                    now,
                    SESSION_LIFETIME_SECS,
                )
                .await
                .map_err(|_| LanRuntimeError::Backend)?;
            Ok(Box::new(ManagerOwnedDesktopHandshake {
                wallet_id: self.wallet_id.clone(),
                manager: Arc::clone(&self.manager),
                attempt,
            }) as Box<dyn DesktopHandshake>)
        })
    }

    fn handle_message<'a>(
        &'a self,
        connection: &'a CompanionConnection,
        message: CompanionMessage,
        replay: ReplayMetadata,
        now: u64,
    ) -> RuntimeFuture<'a, HandleMessageResult> {
        Box::pin(async move {
            validate_inbound(connection, &message, now)?;

            let mut manager = self.manager.lock().await;
            // Commit the authenticated outer encrypted-frame replay marker
            // before dispatching any action, including read-only sync.
            manager
                .consume_companion_transport_replay(
                    &self.wallet_id,
                    &connection.remote_device_id,
                    &replay,
                    now,
                )
                .map_err(|_| LanRuntimeError::Backend)?;

            #[cfg(feature = "agent-wallet-testnet-pilot")]
            let restricted_rotation_candidate = manager
                .is_restricted_rotation_candidate(
                    &self.wallet_id,
                    &connection.remote_device_id,
                    now,
                )
                .map_err(|_| LanRuntimeError::Backend)?;
            #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
            let restricted_rotation_candidate = false;
            if restricted_rotation_candidate
                && !restricted_rotation_candidate_payload_allowed(&message.payload)
            {
                return Err(LanRuntimeError::Backend);
            }

            let response_payload = match message.payload.clone() {
                CompanionPayload::Ping => Some(CompanionPayload::Pong),
                CompanionPayload::SyncRequest { .. } => {
                    let permissions = manager
                        .list_companion_devices(&self.wallet_id, now)
                        .map_err(|_| LanRuntimeError::Backend)?
                        .into_iter()
                        .find(|record| {
                            record.device_id == connection.remote_device_id && !record.is_revoked()
                        })
                        .map(|record| record.permissions)
                        .ok_or(LanRuntimeError::Backend)?;
                    if !permissions.contains(&DevicePermission::ViewAgentWalletStatus) {
                        return Err(LanRuntimeError::Backend);
                    }
                    let snapshot = manager
                        .companion_status_snapshot(&self.wallet_id, now)
                        .await
                        .map_err(|_| LanRuntimeError::Backend)?;
                    Some(filter_snapshot_for_permissions(snapshot, &permissions)?)
                }
                CompanionPayload::ApprovalDecision(signed) => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        let approval_id = signed.decision.approval_id.clone();
                        let operation_id = OperationId::parse(signed.decision.operation_id.clone())
                            .map_err(|_| LanRuntimeError::Backend)?;
                        let approved = signed.decision.decision
                            == hpay_companion_protocol::ApprovalDecision::Approve;
                        let view = manager
                            .apply_mobile_approval_and_broadcast(&self.wallet_id, signed, now)
                            .await
                            .map_err(|_| LanRuntimeError::Backend)?;
                        if !approved {
                            Some(CompanionPayload::AdminAck {
                                command_id: approval_id,
                                accepted: true,
                                detail: "payment_rejected".to_owned(),
                            })
                        } else {
                            if view.status != OperationStatus::SignedAwaitingWitness {
                                return Err(LanRuntimeError::Backend);
                            }
                            let proposal = manager
                                .pending_rollback_anchor(
                                    &self.wallet_id,
                                    &operation_id,
                                    &connection.remote_device_id,
                                    now,
                                )
                                .await
                                .map_err(|_| LanRuntimeError::Backend)?;
                            Some(CompanionPayload::RollbackAnchorProposal(proposal))
                        }
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = signed;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::WitnessReceipt(signed) => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        let anchor_id = signed.receipt.anchor_id.clone();
                        if manager
                            .is_pending_witness_rotation_receipt(&self.wallet_id, &signed, now)
                            .map_err(|_| LanRuntimeError::Backend)?
                        {
                            manager
                                .complete_witness_rotation(&self.wallet_id, signed, now)
                                .map_err(|_| LanRuntimeError::Backend)?;
                            Some(CompanionPayload::WitnessAck {
                                anchor_id,
                                accepted: true,
                                detail: "witness_rotation_completed".to_owned(),
                            })
                        } else {
                            if restricted_rotation_candidate {
                                return Err(LanRuntimeError::Backend);
                            }
                            let view = manager
                                .apply_mobile_witness_and_broadcast(&self.wallet_id, signed, now)
                                .await
                                .map_err(|_| LanRuntimeError::Backend)?;
                            match view.status {
                                OperationStatus::SubmittedAwaitingFinalWitness
                                | OperationStatus::BroadcastUncertain
                                | OperationStatus::ReconciledAwaitingFinalWitness => {
                                    let operation_id =
                                        OperationId::parse(view.operation_id.to_string())
                                            .map_err(|_| LanRuntimeError::Backend)?;
                                    let proposal = manager
                                        .pending_rollback_anchor(
                                            &self.wallet_id,
                                            &operation_id,
                                            &connection.remote_device_id,
                                            now,
                                        )
                                        .await
                                        .map_err(|_| LanRuntimeError::Backend)?;
                                    Some(CompanionPayload::RollbackAnchorProposal(proposal))
                                }
                                OperationStatus::ReconciliationRequired => {
                                    Some(CompanionPayload::WitnessAck {
                                        anchor_id,
                                        accepted: true,
                                        detail:
                                            "submitted_witness_accepted_reconciliation_required"
                                                .to_owned(),
                                    })
                                }
                                OperationStatus::Committed => Some(CompanionPayload::WitnessAck {
                                    anchor_id,
                                    accepted: true,
                                    detail: "final_witness_accepted_committed".to_owned(),
                                }),
                                _ => return Err(LanRuntimeError::Backend),
                            }
                        }
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = signed;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::RecoverPendingWitness { operation_id } => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        let operation_id = OperationId::parse(operation_id)
                            .map_err(|_| LanRuntimeError::Backend)?;
                        let proposal = manager
                            .pending_rollback_anchor(
                                &self.wallet_id,
                                &operation_id,
                                &connection.remote_device_id,
                                now,
                            )
                            .await
                            .map_err(|_| LanRuntimeError::Backend)?;
                        Some(CompanionPayload::RollbackAnchorProposal(proposal))
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = operation_id;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::WitnessRotationPoll { rotation_id } => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        let (phase, record) = manager
                            .witness_rotation_step_for_device(
                                &self.wallet_id,
                                &connection.remote_device_id,
                                rotation_id.as_deref(),
                                now,
                            )
                            .map_err(|_| LanRuntimeError::Backend)?;
                        match phase {
                            WitnessRotationPhase::AwaitingOldWitnessAuthorization
                                if connection.remote_device_id == record.old_mobile_device_id =>
                            {
                                Some(CompanionPayload::WitnessRotationProposal(record))
                            }
                            WitnessRotationPhase::CandidatePairedRestricted
                                if connection.remote_device_id == record.new_mobile_device_id =>
                            {
                                Some(CompanionPayload::WitnessRotationProposal(record))
                            }
                            WitnessRotationPhase::AwaitingCandidatePairing
                                if connection.remote_device_id == record.old_mobile_device_id =>
                            {
                                Some(CompanionPayload::AdminAck {
                                    command_id: record.rotation_id,
                                    accepted: true,
                                    detail: "old_witness_authorization_accepted".to_owned(),
                                })
                            }
                            WitnessRotationPhase::AwaitingCompletionAnchor
                            | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                                if connection.remote_device_id == record.new_mobile_device_id =>
                            {
                                Some(CompanionPayload::RollbackAnchorProposal(
                                    manager
                                        .pending_witness_rotation_completion_anchor(
                                            &self.wallet_id,
                                            &record.rotation_id,
                                            now,
                                        )
                                        .await
                                        .map_err(|_| LanRuntimeError::Backend)?,
                                ))
                            }
                            WitnessRotationPhase::Completed
                                if connection.remote_device_id == record.new_mobile_device_id =>
                            {
                                Some(CompanionPayload::AdminAck {
                                    command_id: record.rotation_id,
                                    accepted: true,
                                    detail: "witness_rotation_completed".to_owned(),
                                })
                            }
                            _ => return Err(LanRuntimeError::Backend),
                        }
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = rotation_id;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::WitnessRotationAuthorization(signed) => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        if connection.remote_device_id != signed.rotation.old_mobile_device_id {
                            return Err(LanRuntimeError::Backend);
                        }
                        let rotation_id = signed.rotation.rotation_id.clone();
                        manager
                            .authorize_witness_rotation(&self.wallet_id, signed, now)
                            .map_err(|_| LanRuntimeError::Backend)?;
                        Some(CompanionPayload::AdminAck {
                            command_id: rotation_id,
                            accepted: true,
                            detail: "old_witness_authorization_accepted".to_owned(),
                        })
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = signed;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::WitnessRotationBaseline(signed) => {
                    #[cfg(feature = "agent-wallet-testnet-pilot")]
                    {
                        if connection.remote_device_id != signed.receipt.new_mobile_device_id {
                            return Err(LanRuntimeError::Backend);
                        }
                        let rotation_id = signed.receipt.rotation_id.clone();
                        manager
                            .accept_witness_rotation_baseline(&self.wallet_id, signed, now)
                            .map_err(|_| LanRuntimeError::Backend)?;
                        Some(CompanionPayload::RollbackAnchorProposal(
                            manager
                                .pending_witness_rotation_completion_anchor(
                                    &self.wallet_id,
                                    &rotation_id,
                                    now,
                                )
                                .await
                                .map_err(|_| LanRuntimeError::Backend)?,
                        ))
                    }
                    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
                    {
                        let _ = signed;
                        return Err(LanRuntimeError::Backend);
                    }
                }
                CompanionPayload::Disconnect { .. } => None,
                CompanionPayload::ApprovalRequest(_)
                | CompanionPayload::RollbackAnchorProposal(_)
                | CompanionPayload::WitnessRotationProposal(_)
                | CompanionPayload::WitnessAck { .. }
                | CompanionPayload::StatusSnapshot { .. }
                | CompanionPayload::AdminCommand(_)
                | CompanionPayload::AdminAck { .. }
                | CompanionPayload::Pong
                | CompanionPayload::PairingMobileProof(_) => {
                    return Err(LanRuntimeError::Backend);
                }
            };

            let response = response_payload
                .map(|payload| build_response(connection, &message, payload, now))
                .transpose()?;
            Ok(HandleMessageResult { response })
        })
    }
}

fn restricted_rotation_candidate_payload_allowed(payload: &CompanionPayload) -> bool {
    matches!(
        payload,
        CompanionPayload::WitnessRotationPoll { .. }
            | CompanionPayload::WitnessRotationBaseline(_)
            | CompanionPayload::WitnessReceipt(_)
            | CompanionPayload::Disconnect { .. }
    )
}

fn filter_snapshot_for_permissions(
    payload: CompanionPayload,
    permissions: &BTreeSet<DevicePermission>,
) -> Result<CompanionPayload, LanRuntimeError> {
    let CompanionPayload::StatusSnapshot {
        status,
        mut agents,
        mut approvals,
        activity,
        ..
    } = payload
    else {
        return Err(LanRuntimeError::Backend);
    };
    if !permissions.contains(&DevicePermission::ViewAgents) {
        agents.clear();
    }
    if !permissions.contains(&DevicePermission::ViewPendingApprovals) {
        approvals.clear();
    }
    // The current protocol defines no ViewPolicies or ViewActivity permissions.
    // Keep those private until explicit least-privilege capabilities exist.
    Ok(CompanionPayload::StatusSnapshot {
        status,
        agents,
        policies: Vec::new(),
        approvals,
        activity: witness_pending_disclosure(activity, permissions),
    })
}

/// The wallet's activity list is never sent to a phone. The single exception is
/// the one operation that is waiting on that phone's own rollback witness.
///
/// Without this the phone cannot discover an operation it did not itself
/// approve: `RecoverPendingWitness` takes an operation id and nothing else on
/// the wire carries one. So a desktop-approved payment signs, lands in
/// `SignedAwaitingWitness` and strands, because no phone is ever told which id
/// to ask for.
///
/// The disclosure is deliberately the smallest thing that closes that gap:
///
/// * gated on `WitnessRollbackAnchor`, the permission that already authorizes
///   the strictly stronger act of producing the anchor. A phone that never
///   received it - every non-pilot pairing - keeps getting an empty list, byte
///   for byte as before.
/// * restricted to `WITNESS_PENDING_OPERATION_STATUS_NAMES`, which is exactly
///   the set `pending_rollback_anchor` will act on. Committed, failed,
///   cancelled, rejected and every pre-signing operation stay private, so this
///   is never wallet history.
/// * at most one entry. Two operations cannot legitimately await witness at
///   once: `create_payment_intent` refuses while any operation sits in the
///   witness lifecycle, and `pending_rollback_anchor` refuses under the same
///   condition. If a second one is somehow present, neither could be witnessed
///   anyway, so this discloses nothing rather than an id the phone cannot use.
/// * redacted down to the fields the witness flow actually consumes. The
///   vehicle has to be an `ActivitySummary`, because changing the wire shape is
///   a protocol change, and `validate_for_wallet` rejects an empty
///   `description` or a zero `occurred_at`. So those two are overwritten with
///   constants rather than carried: `description` is `AgentOperationView::reason`,
///   the agent's free-text reason for the payment, which is the most sensitive
///   string in the record and which nothing on the phone reads; `occurred_at`
///   is rendered only by the recent-activity list, which filters this entry out
///   by id. What survives is what the confirmation screen shows the owner and
///   what `RecoverPendingWitness` needs: the id, the status, the amount, the
///   asset and the recipient.
///
/// `policies` is still blanked unconditionally, for every device.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn witness_pending_disclosure(
    activity: Vec<hpay_companion_protocol::ActivitySummary>,
    permissions: &BTreeSet<DevicePermission>,
) -> Vec<hpay_companion_protocol::ActivitySummary> {
    if !permissions.contains(&DevicePermission::WitnessRollbackAnchor) {
        return Vec::new();
    }
    let mut pending: Vec<_> = activity
        .into_iter()
        .filter(|item| {
            agent_wallet_core::WITNESS_PENDING_OPERATION_STATUS_NAMES
                .contains(&item.status.as_str())
        })
        .collect();
    if pending.len() == 1 {
        for item in &mut pending {
            item.description = WITNESS_PENDING_REDACTED_DESCRIPTION.to_owned();
            item.occurred_at = WITNESS_PENDING_REDACTED_OCCURRED_AT;
        }
        pending
    } else {
        Vec::new()
    }
}

/// Placeholders for the two `ActivitySummary` fields the witness disclosure has
/// no use for and cannot omit. Both are only as non-empty/non-zero as
/// `CompanionPayload::validate_for_wallet` and the phone's own
/// `validateActivity` demand.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const WITNESS_PENDING_REDACTED_DESCRIPTION: &str = "Awaiting your rollback witness";
#[cfg(feature = "agent-wallet-testnet-pilot")]
const WITNESS_PENDING_REDACTED_OCCURRED_AT: u64 = 1;

#[cfg(not(feature = "agent-wallet-testnet-pilot"))]
fn witness_pending_disclosure(
    _activity: Vec<hpay_companion_protocol::ActivitySummary>,
    _permissions: &BTreeSet<DevicePermission>,
) -> Vec<hpay_companion_protocol::ActivitySummary> {
    Vec::new()
}
fn validate_inbound(
    connection: &CompanionConnection,
    message: &CompanionMessage,
    now: u64,
) -> Result<(), LanRuntimeError> {
    connection.validate_at(now)?;
    message.validate_at(now)?;
    if message.session_id != connection.session_id
        || message.sender_device_id != connection.remote_device_id
        || message.recipient_device_id != connection.local_device_id
    {
        return Err(LanRuntimeError::Backend);
    }
    Ok(())
}

fn build_response(
    connection: &CompanionConnection,
    request: &CompanionMessage,
    payload: CompanionPayload,
    now: u64,
) -> Result<CompanionMessage, LanRuntimeError> {
    let expires_at = connection
        .expires_at
        .min(now.saturating_add(RESPONSE_LIFETIME_SECS));
    if expires_at <= now {
        return Err(LanRuntimeError::Backend);
    }
    let mut response = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: format!("reply_{}", request.sequence),
        session_id: connection.session_id.clone(),
        sender_device_id: connection.local_device_id.clone(),
        recipient_device_id: connection.remote_device_id.clone(),
        sequence: request.sequence,
        issued_at: now,
        expires_at,
        payload,
    };
    fit_status_snapshot_to_wire_budget(&mut response)?;
    response.validate_at(now)?;
    Ok(response)
}
fn fit_status_snapshot_to_wire_budget(
    message: &mut CompanionMessage,
) -> Result<(), LanRuntimeError> {
    let mut truncated = false;
    loop {
        let encoded_len = message
            .to_bytes()
            .map_err(|_| LanRuntimeError::Backend)?
            .len();
        if encoded_len <= MAX_SYNC_MESSAGE_BYTES {
            if truncated {
                let CompanionPayload::StatusSnapshot { status, .. } = &mut message.payload else {
                    return Err(LanRuntimeError::Backend);
                };
                status.node_status = format!("{}; companion_snapshot_limited", status.node_status);
            }
            return Ok(());
        }
        let CompanionPayload::StatusSnapshot {
            agents, approvals, ..
        } = &mut message.payload
        else {
            return Err(LanRuntimeError::Backend);
        };
        if approvals.pop().is_some() || agents.pop().is_some() {
            truncated = true;
            continue;
        }
        return Err(LanRuntimeError::Backend);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> CompanionConnection {
        CompanionConnection {
            connection_version: 1,
            session_id: "session_one".to_owned(),
            local_device_id: DeviceId::parse("desktop_one").unwrap(),
            remote_device_id: DeviceId::parse("mobile_one").unwrap(),
            established_at: 100,
            expires_at: 500,
        }
    }

    fn inbound() -> CompanionMessage {
        let connection = connection();
        CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "request_one".to_owned(),
            session_id: connection.session_id,
            sender_device_id: connection.remote_device_id,
            recipient_device_id: connection.local_device_id,
            sequence: 7,
            issued_at: 110,
            expires_at: 200,
            payload: CompanionPayload::Ping,
        }
    }

    #[test]
    fn inbound_scope_is_exact_and_response_reverses_authenticated_devices() {
        let connection = connection();
        let request = inbound();
        validate_inbound(&connection, &request, 120).unwrap();
        let response = build_response(&connection, &request, CompanionPayload::Pong, 120).unwrap();
        assert_eq!(response.session_id, connection.session_id);
        assert_eq!(response.sender_device_id, connection.local_device_id);
        assert_eq!(response.recipient_device_id, connection.remote_device_id);
        assert_eq!(response.sequence, request.sequence);
        assert_eq!(response.expires_at, 180);
    }

    #[test]
    fn snapshot_sections_are_filtered_by_explicit_device_permissions() {
        use hpay_companion_protocol::{
            ActivitySummary, AgentAuthorizationState, AgentPolicySummary, AgentSummary,
            CompanionStatus,
        };

        let payload = CompanionPayload::StatusSnapshot {
            status: CompanionStatus {
                agent_wallet_id: "wallet_one".to_owned(),
                address: "1Agent".to_owned(),
                available_units: Some(1),
                node_status: "verified".to_owned(),
                reserved_units: 0,
                spent_today_units: 0,
                spent_month_units: 0,
                paused: false,
                policy_epoch: 1,
            },
            agents: vec![AgentSummary {
                agent_id: "agent_one".to_owned(),
                display_name: "Agent one".to_owned(),
                authorization: AgentAuthorizationState::Authorized,
            }],
            policies: vec![AgentPolicySummary {
                agent_id: "agent_one".to_owned(),
                max_per_payment_units: 1,
                max_daily_units: 1,
                max_pending_operations: 1,
                approval_mode: "desktop_manual".to_owned(),
                permissions: vec!["create_payment_intent".to_owned()],
                allowed_recipients: vec!["1PrivateRecipient".to_owned()],
                blocked_recipients: Vec::new(),
                policy_epoch: 1,
            }],
            approvals: Vec::new(),
            activity: vec![ActivitySummary {
                activity_id: "activity_one".to_owned(),
                description: "Private reason".to_owned(),
                asset: "HAC".to_owned(),
                recipient: "1PrivateRecipient".to_owned(),
                amount_units: 1,
                occurred_at: 100,
                status: "completed".to_owned(),
            }],
        };
        let status_only = BTreeSet::from([DevicePermission::ViewAgentWalletStatus]);
        let filtered = filter_snapshot_for_permissions(payload.clone(), &status_only).unwrap();
        let CompanionPayload::StatusSnapshot {
            agents,
            policies,
            approvals,
            activity,
            ..
        } = filtered
        else {
            panic!("expected status snapshot");
        };
        assert!(agents.is_empty());
        assert!(policies.is_empty());
        assert!(approvals.is_empty());
        assert!(activity.is_empty());

        let with_agents = BTreeSet::from([
            DevicePermission::ViewAgentWalletStatus,
            DevicePermission::ViewAgents,
        ]);
        let filtered = filter_snapshot_for_permissions(payload, &with_agents).unwrap();
        let CompanionPayload::StatusSnapshot {
            agents,
            policies,
            activity,
            ..
        } = filtered
        else {
            panic!("expected status snapshot");
        };
        assert_eq!(agents.len(), 1);
        assert!(policies.is_empty());
        assert!(activity.is_empty());
    }
    fn activity(activity_id: &str, status: &str) -> hpay_companion_protocol::ActivitySummary {
        hpay_companion_protocol::ActivitySummary {
            activity_id: activity_id.to_owned(),
            description: "Private reason".to_owned(),
            asset: "HAC".to_owned(),
            recipient: "1PrivateRecipient".to_owned(),
            amount_units: 5_000_000_000,
            occurred_at: 100,
            status: status.to_owned(),
        }
    }

    fn snapshot_with_activity(
        activity: Vec<hpay_companion_protocol::ActivitySummary>,
    ) -> CompanionPayload {
        use hpay_companion_protocol::{
            AgentAuthorizationState, AgentPolicySummary, AgentSummary, CompanionStatus,
        };

        CompanionPayload::StatusSnapshot {
            status: CompanionStatus {
                agent_wallet_id: "wallet_one".to_owned(),
                address: "1Agent".to_owned(),
                available_units: Some(1),
                node_status: "verified".to_owned(),
                reserved_units: 0,
                spent_today_units: 0,
                spent_month_units: 0,
                paused: false,
                policy_epoch: 1,
            },
            agents: vec![AgentSummary {
                agent_id: "agent_one".to_owned(),
                display_name: "Agent one".to_owned(),
                authorization: AgentAuthorizationState::Authorized,
            }],
            policies: vec![AgentPolicySummary {
                agent_id: "agent_one".to_owned(),
                max_per_payment_units: 1,
                max_daily_units: 1,
                max_pending_operations: 1,
                approval_mode: "desktop_manual".to_owned(),
                permissions: vec!["create_payment_intent".to_owned()],
                allowed_recipients: vec!["1PrivateRecipient".to_owned()],
                blocked_recipients: Vec::new(),
                policy_epoch: 1,
            }],
            approvals: Vec::new(),
            activity,
        }
    }

    fn filtered_activity(
        payload: CompanionPayload,
        permissions: &BTreeSet<DevicePermission>,
    ) -> Vec<hpay_companion_protocol::ActivitySummary> {
        let CompanionPayload::StatusSnapshot {
            policies, activity, ..
        } = filter_snapshot_for_permissions(payload, permissions).unwrap()
        else {
            panic!("expected status snapshot");
        };
        assert!(
            policies.is_empty(),
            "agent policies stay private on every device"
        );
        activity
    }

    /// A phone that never received `WitnessRollbackAnchor` - every non-pilot
    /// pairing - must see exactly the bytes it saw before witness discovery
    /// existed. Not "an empty activity list", but the identical encoded message.
    #[test]
    fn a_phone_without_the_witness_permission_sees_byte_identical_snapshot_bytes() {
        let payload = snapshot_with_activity(vec![
            activity("operation_awaiting_witness", "signed_awaiting_witness"),
            activity("operation_committed", "committed"),
        ]);
        // Every permission a paired device can hold except the witness one.
        let without_witness = BTreeSet::from([
            DevicePermission::ViewAgentWalletStatus,
            DevicePermission::ViewPendingApprovals,
            DevicePermission::ViewAgents,
            DevicePermission::ApprovePayment,
            DevicePermission::RejectPayment,
            DevicePermission::EmergencyStop,
            DevicePermission::RevokeAgent,
            DevicePermission::RevokeMobileDevice,
            DevicePermission::LowerSpendingLimits,
        ]);
        assert!(!without_witness.contains(&DevicePermission::WitnessRollbackAnchor));

        let filtered = filter_snapshot_for_permissions(payload, &without_witness).unwrap();
        // The pre-change behaviour, restated independently: agents survive,
        // policies and activity are blanked outright.
        let expected = {
            let CompanionPayload::StatusSnapshot { status, agents, .. } =
                snapshot_with_activity(Vec::new())
            else {
                panic!("expected status snapshot");
            };
            CompanionPayload::StatusSnapshot {
                status,
                agents,
                policies: Vec::new(),
                approvals: Vec::new(),
                activity: Vec::new(),
            }
        };
        assert_eq!(filtered, expected);

        let actual_bytes = build_response(&connection(), &inbound(), filtered, 120)
            .unwrap()
            .to_bytes()
            .unwrap();
        let expected_bytes = build_response(&connection(), &inbound(), expected, 120)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(actual_bytes, expected_bytes);
    }

    /// A witness phone learns the id of the one operation waiting on its own
    /// signature, and nothing else. Not the rest of the activity list, not the
    /// policies, not an operation in any status it could not witness.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn a_witness_phone_sees_only_the_operation_awaiting_its_own_witness() {
        let with_witness = BTreeSet::from([
            DevicePermission::ViewAgentWalletStatus,
            DevicePermission::WitnessRollbackAnchor,
        ]);

        for status in agent_wallet_core::WITNESS_PENDING_OPERATION_STATUS_NAMES {
            let payload = snapshot_with_activity(vec![
                activity("operation_committed", "committed"),
                activity("operation_awaiting_witness", status),
                activity("operation_cancelled", "cancelled"),
                activity("operation_rejected", "rejected"),
                activity("operation_approval_requested", "approval_requested"),
                activity("operation_signed", "signed"),
            ]);
            let disclosed = filtered_activity(payload, &with_witness);
            assert_eq!(disclosed.len(), 1, "{status} must disclose exactly one id");
            assert_eq!(disclosed[0].activity_id, "operation_awaiting_witness");
            assert_eq!(disclosed[0].status, status);
        }

        // Nothing pending: byte-identical to a phone with no witness authority.
        let quiet = snapshot_with_activity(vec![
            activity("operation_committed", "committed"),
            activity("operation_witnessed", "witnessed_awaiting_broadcast"),
            activity("operation_broadcast", "broadcast_submitted"),
            activity("operation_reconciliation", "reconciliation_required"),
            activity("operation_recovery", "recovery_required"),
        ]);
        assert!(filtered_activity(quiet, &with_witness).is_empty());

        // Two operations cannot legitimately await witness at once, and neither
        // could be witnessed if they did. Fail closed rather than hand over an
        // id the phone cannot act on.
        let ambiguous = snapshot_with_activity(vec![
            activity("operation_one", "signed_awaiting_witness"),
            activity("operation_two", "broadcast_uncertain"),
        ]);
        assert!(filtered_activity(ambiguous, &with_witness).is_empty());
    }

    /// The disclosure carries the witness flow's inputs and nothing else.
    ///
    /// `ActivitySummary` is the only vehicle available without a protocol
    /// change, and it has two fields the flow never reads. `description` is the
    /// agent's free-text reason for the payment - the single most revealing
    /// string in an operation record - and `occurred_at` is history the witness
    /// card never shows. Neither may be empty or zero on the wire, so both are
    /// overwritten with constants instead of forwarded. If a future edit drops
    /// the redaction, the phone starts receiving the payment reason and this
    /// test fails.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn the_disclosed_entry_carries_no_payment_reason_and_no_history_timestamp() {
        let with_witness = BTreeSet::from([
            DevicePermission::ViewAgentWalletStatus,
            DevicePermission::WitnessRollbackAnchor,
        ]);
        let private = activity("operation_awaiting_witness", "signed_awaiting_witness");
        let payload = snapshot_with_activity(vec![private.clone()]);

        let disclosed = filtered_activity(payload, &with_witness);
        assert_eq!(disclosed.len(), 1);
        let disclosed = &disclosed[0];

        // Carried, because the owner reads them or the recovery needs them.
        assert_eq!(disclosed.activity_id, private.activity_id);
        assert_eq!(disclosed.status, private.status);
        assert_eq!(disclosed.amount_units, private.amount_units);
        assert_eq!(disclosed.recipient, private.recipient);
        assert_eq!(disclosed.asset, private.asset);

        // Withheld.
        assert_ne!(
            disclosed.description, private.description,
            "the agent's stated reason for the payment must never reach a phone"
        );
        assert_eq!(disclosed.description, WITNESS_PENDING_REDACTED_DESCRIPTION);
        assert_ne!(disclosed.occurred_at, private.occurred_at);
        assert_eq!(disclosed.occurred_at, WITNESS_PENDING_REDACTED_OCCURRED_AT);

        // The redaction must still be a legal snapshot on the wire, and still
        // pass the phone's own `validateActivity` preconditions.
        assert!(!disclosed.description.is_empty());
        assert_ne!(disclosed.occurred_at, 0);
        build_response(
            &connection(),
            &inbound(),
            snapshot_with_activity(vec![disclosed.clone()]),
            120,
        )
        .unwrap()
        .to_bytes()
        .unwrap();
    }

    #[test]
    fn oversized_valid_snapshot_is_deterministically_bounded_for_encrypted_wire() {
        use hpay_companion_protocol::{AgentAuthorizationState, AgentSummary, CompanionStatus};

        let payload = CompanionPayload::StatusSnapshot {
            status: CompanionStatus {
                agent_wallet_id: "wallet_one".to_owned(),
                address: "1Agent".to_owned(),
                available_units: Some(1),
                node_status: "verified".to_owned(),
                reserved_units: 0,
                spent_today_units: 0,
                spent_month_units: 0,
                paused: false,
                policy_epoch: 1,
            },
            agents: (0..10)
                .map(|index| AgentSummary {
                    agent_id: format!("agent_{index}"),
                    display_name: "x".repeat(16 * 1024),
                    authorization: AgentAuthorizationState::Authorized,
                })
                .collect(),
            policies: Vec::new(),
            approvals: Vec::new(),
            activity: Vec::new(),
        };
        let response = build_response(&connection(), &inbound(), payload, 120).unwrap();
        assert!(response.to_bytes().unwrap().len() <= MAX_SYNC_MESSAGE_BYTES);
        let CompanionPayload::StatusSnapshot { status, agents, .. } = response.payload else {
            panic!("expected status snapshot");
        };
        assert!(agents.len() < 10);
        assert!(status.node_status.contains("companion_snapshot_limited"));
    }
    #[test]
    fn cross_session_and_cross_device_messages_fail_closed() {
        let connection = connection();
        let mut request = inbound();
        request.session_id = "other_session".to_owned();
        assert!(validate_inbound(&connection, &request, 120).is_err());

        let mut request = inbound();
        request.sender_device_id = DeviceId::parse("mobile_other").unwrap();
        assert!(validate_inbound(&connection, &request, 120).is_err());
    }

    #[test]
    fn rotation_candidate_acl_is_an_explicit_rotation_only_allowlist() {
        assert!(restricted_rotation_candidate_payload_allowed(
            &CompanionPayload::WitnessRotationPoll {
                rotation_id: Some("rotation_one".to_owned()),
            },
        ));
        assert!(restricted_rotation_candidate_payload_allowed(
            &CompanionPayload::Disconnect {
                reason: "user_cancelled".to_owned(),
            },
        ));
        for denied in [
            CompanionPayload::Ping,
            CompanionPayload::SyncRequest { since_sequence: 0 },
            CompanionPayload::RecoverPendingWitness {
                operation_id: "operation_one".to_owned(),
            },
            CompanionPayload::AdminAck {
                command_id: "emergency_one".to_owned(),
                accepted: true,
                detail: "must_not_be_reachable".to_owned(),
            },
        ] {
            assert!(
                !restricted_rotation_candidate_payload_allowed(&denied),
                "general, financial recovery and administrative payloads stay denied"
            );
        }
    }
}
