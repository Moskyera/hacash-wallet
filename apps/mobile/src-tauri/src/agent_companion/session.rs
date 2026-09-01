#[cfg(any(target_os = "android", test))]
use hpay_companion_protocol::{CompanionMessage, CompanionPayload};

#[cfg(any(target_os = "android", test))]
use super::network::agent_fast_pay_network_allowed;
#[cfg(any(target_os = "android", test))]
use super::storage::MobileCompanionDurableState;

#[cfg(any(target_os = "android", test))]
const OUTER_CONNECT_TIMEOUT_SECS: u64 = 75;

#[cfg(any(target_os = "android", test))]
const AGENT_NETWORK_FEE_UNITS: u64 = 1_000;

#[cfg(any(target_os = "android", test))]
pub(super) fn inbound_payload_allowed(payload: &CompanionPayload) -> bool {
    matches!(
        payload,
        CompanionPayload::StatusSnapshot { .. }
            | CompanionPayload::Pong
            | CompanionPayload::AdminAck { .. }
            | CompanionPayload::Disconnect { .. }
            // A rotation proposal is a desktop-signed record describing this
            // phone's own replacement. Reading it authorizes nothing and can
            // move no money. It is admitted in every build so that a handset
            // which was left mid-rotation by a pilot build, and then updated to
            // a read-only one, can still hand its authority over instead of
            // being stuck at "Controlled witness rotation required" for good.
            | CompanionPayload::WitnessRotationProposal(_)
    ) || (cfg!(feature = "agent-wallet-testnet-pilot")
        && matches!(
            payload,
            CompanionPayload::RollbackAnchorProposal(_)
                | CompanionPayload::WitnessAck { .. }
                | CompanionPayload::AgentFastPayApprovalRequest(_)
                | CompanionPayload::AgentHvmApprovalRequest(_)
        ))
}

#[cfg(any(target_os = "android", test))]
pub(super) fn outbound_payload_allowed(payload: &CompanionPayload) -> bool {
    matches!(
        payload,
        CompanionPayload::SyncRequest { .. }
            | CompanionPayload::Ping
            | CompanionPayload::Disconnect { .. }
            // The old phone's half of a controlled rotation: ask what rotation
            // the desktop has prepared, and sign an authorization for this
            // handset's own replacement. Neither is an approval and neither is
            // a payment witness; both are desktop-initiated and desktop-
            // verified, and the wallet keeps refusing every payment until the
            // replacement phone signs a real baseline and a real completion
            // receipt. Withholding them from a read-only build left such a
            // handset with no way to hand over at all.
            | CompanionPayload::WitnessRotationPoll { .. }
            | CompanionPayload::WitnessRotationAuthorization(_)
    ) || (cfg!(feature = "agent-wallet-testnet-pilot")
        && matches!(
            payload,
            CompanionPayload::ApprovalDecision(_)
                | CompanionPayload::AgentFastPayApprovalPoll { .. }
                | CompanionPayload::AgentFastPayApprovalDecision(_)
                | CompanionPayload::AgentHvmApprovalPoll { .. }
                | CompanionPayload::AgentHvmApprovalDecision(_)
                | CompanionPayload::RecoverPendingWitness { .. }
                | CompanionPayload::WitnessReceipt(_)
                // The replacement phone's half stays pilot-only: it ends in a
                // witness receipt over a rollback anchor.
                | CompanionPayload::WitnessRotationBaseline(_)
        ))
}

#[cfg(any(target_os = "android", test))]
fn validate_inbound_message(
    message: &CompanionMessage,
    connection: &hpay_companion_protocol::CompanionConnection,
    state: &MobileCompanionDurableState,
    now: u64,
) -> Result<(), String> {
    message
        .validate_at(now)
        .map_err(|error| error.to_string())?;
    if message.session_id != connection.session_id
        || message.sender_device_id != state.desktop_device_id
        || message.recipient_device_id != state.mobile_device_id
        || !inbound_payload_allowed(&message.payload)
    {
        return Err("Inbound companion message scope is not allowed".to_owned());
    }
    if let CompanionPayload::RollbackAnchorProposal(proposal) = &message.payload {
        proposal
            .verify(&state.registry, now)
            .map_err(|error| error.to_string())?;
        if proposal.anchor.agent_wallet_id != state.agent_wallet_id
            || proposal.anchor.desktop_device_id != state.desktop_device_id
            || proposal.anchor.mobile_device_id != state.mobile_device_id
        {
            return Err("Inbound rollback anchor scope is invalid".to_owned());
        }
    }
    if let CompanionPayload::WitnessAck { anchor_id, .. } = &message.payload
        && anchor_id.is_empty()
    {
        return Err("Inbound witness acknowledgement is invalid".to_owned());
    }
    if let CompanionPayload::WitnessRotationProposal(rotation) = &message.payload {
        rotation
            .validate_at(now)
            .map_err(|error| error.to_string())?;
        if rotation.agent_wallet_id != state.agent_wallet_id
            || rotation.desktop_device_id != state.desktop_device_id
            || (rotation.old_mobile_device_id != state.mobile_device_id
                && rotation.new_mobile_device_id != state.mobile_device_id)
        {
            return Err("Inbound witness rotation scope is invalid".to_owned());
        }
    }
    if let CompanionPayload::AgentFastPayApprovalRequest(approval) = &message.payload {
        approval
            .validate_at(now)
            .map_err(|error| error.to_string())?;
        if approval.agent_wallet_id != state.agent_wallet_id
            || approval.desktop_device_id != state.desktop_device_id
            || !agent_fast_pay_network_allowed(&approval.network_binding)
        {
            return Err("Inbound Agent Fast Pay approval scope is invalid".to_owned());
        }
    }
    if let CompanionPayload::AgentHvmApprovalRequest(approval) = &message.payload {
        approval
            .validate_at(now)
            .map_err(|error| error.to_string())?;
        if approval.agent_wallet_id != state.agent_wallet_id
            || approval.desktop_device_id != state.desktop_device_id
            || !agent_fast_pay_network_allowed(&approval.network_binding)
            || approval.network_fee_zhu != 0
            || approval.wallet_fee_zhu != 0
            || approval.hub_fee_zhu != 0
            || approval.total_debit_zhu != approval.amount_zhu
        {
            return Err("Inbound Agent HVM approval scope is invalid".to_owned());
        }
    }
    if let CompanionPayload::StatusSnapshot {
        status, approvals, ..
    } = &message.payload
    {
        if status.agent_wallet_id != state.agent_wallet_id
            || status.address.is_empty()
            || status.node_status.is_empty()
        {
            return Err("Inbound companion status scope is invalid".to_owned());
        }
        for approval in approvals {
            approval
                .validate_at(now)
                .map_err(|error| error.to_string())?;
            let binding_is_exact =
                if cfg!(feature = "agent-wallet-testnet-pilot") {
                    approval.approval_version == 3
                        && approval.network_binding.as_ref().is_some_and(|binding| {
                            binding.network_id == "testnet"
                                && binding.chain_id > 0
                                && binding.genesis_identifier.len() == 64
                                && binding.genesis_identifier.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                                && binding.node_profile_id.len() == 64
                                && binding.node_profile_id.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                                && binding.transaction_format_version == 2
                        })
                } else {
                    approval.approval_version == 2 && approval.network_binding.is_none()
                };
            if approval.agent_wallet_id != state.agent_wallet_id
                || approval.desktop_device_id != state.desktop_device_id
                || approval.fee_units != AGENT_NETWORK_FEE_UNITS
                || approval.wallet_fee_units != 0
                || !binding_is_exact
            {
                return Err("Inbound approval summary scope is invalid".to_owned());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn validate_connection_scope(
    connection: &hpay_companion_protocol::CompanionConnection,
    state: &MobileCompanionDurableState,
) -> Result<(), String> {
    if connection.local_device_id != state.mobile_device_id
        || connection.remote_device_id != state.desktop_device_id
    {
        return Err("Companion connection device scope mismatch".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "android")]
mod android {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use hpay_companion_lan_runtime::{
        LanRuntimeError, MobileHandshake, MobileLanSession, MobileSessionBackend, RuntimeFuture,
    };
    use hpay_companion_protocol::{
        CompanionMessage, CompanionPayload, EstablishedSession, MobileSessionAttempt,
        PROTOCOL_VERSION, ReplayGuard, ReplayMetadata, SessionChallenge, SessionConfirmation,
        SessionResponse, SignedApprovalDecision, SignedWitnessReceipt, WitnessRotationPhase,
    };
    use tauri::AppHandle;
    use tokio::time::timeout;

    use crate::agent_companion_identity;

    use super::{
        OUTER_CONNECT_TIMEOUT_SECS, outbound_payload_allowed, validate_connection_scope,
        validate_inbound_message,
    };
    use crate::agent_companion::commands::CompanionSessionView;
    use crate::agent_companion::storage::SharedCompanionState;
    use crate::agent_companion::{AgentCompanionMobileState, unix_now};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(OUTER_CONNECT_TIMEOUT_SECS);
    const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
    const MESSAGE_LIFETIME_SECS: u64 = 60;

    pub(in crate::agent_companion) struct ActiveSession {
        session: MobileLanSession,
        next_sequence: u64,
        last_received_sequence: u64,
    }

    #[derive(Clone)]
    pub(in crate::agent_companion) enum OutboundKind {
        Sync,
        Ping,
        Approval(SignedApprovalDecision),
        AgentFastPayApprovalPoll {
            agent_wallet_id: String,
            operation_id: Option<String>,
        },
        AgentFastPayApprovalDecision(hpay_companion_protocol::SignedAgentFastPayApprovalDecision),
        AgentHvmApprovalPoll {
            agent_wallet_id: String,
            operation_id: Option<String>,
        },
        AgentHvmApprovalDecision(hpay_companion_protocol::SignedAgentHvmApprovalDecision),
        RecoverPendingWitness(String),
        Witness(SignedWitnessReceipt),
        RotationPoll(Option<String>),
        RotationAuthorization(hpay_companion_protocol::SignedWitnessRotationAuthorization),
        RotationBaseline(hpay_companion_protocol::SignedWitnessRotationBaselineReceipt),
    }

    struct AndroidMobileBackend {
        app: AppHandle,
        shared: Arc<SharedCompanionState>,
    }

    struct AndroidMobileHandshake {
        attempt: MobileSessionAttempt,
        registry: hpay_companion_protocol::DeviceRegistry,
    }

    impl MobileHandshake for AndroidMobileHandshake {
        fn response(&self) -> &SessionResponse {
            self.attempt.response()
        }

        fn verify(
            self: Box<Self>,
            confirmation: SessionConfirmation,
            now: u64,
        ) -> RuntimeFuture<'static, EstablishedSession> {
            Box::pin(async move {
                self.attempt
                    .verify_confirmation(&confirmation, &self.registry, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)
            })
        }
    }

    impl MobileSessionBackend for AndroidMobileBackend {
        // Every refusal below used to be `.map_err(|_| LanRuntimeError::Backend)`,
        // so twenty-one distinct causes reached the owner as one sentence that
        // named none of them: "companion backend rejected the operation". The
        // decisions here are unchanged and still fail closed; only the reason
        // now survives the return.
        fn respond<'a>(
            &'a self,
            challenge: SessionChallenge,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn MobileHandshake>> {
            Box::pin(async move {
                self.shared
                    .require_available()
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let mut slot = self.shared.state.lock().await;
                let current = slot
                    .as_ref()
                    .ok_or(LanRuntimeError::CompanionNotPaired)?
                    .clone();
                current
                    .validate_at(now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                if challenge.agent_wallet_id != current.agent_wallet_id
                    || challenge.desktop_device_id != current.desktop_device_id
                    || challenge.mobile_device_id != current.mobile_device_id
                {
                    return Err(LanRuntimeError::CompanionScopeMismatch);
                }
                let signer = agent_companion_identity::open(&self.app)
                    .await
                    .map_err(|_| LanRuntimeError::CompanionIdentityUnavailable)?
                    .ok_or(LanRuntimeError::CompanionIdentityUnavailable)?;
                let mut replay = ReplayGuard::from_snapshot(current.replay.clone(), now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let response_sequence = current
                    .response_sequence
                    .checked_add(1)
                    .ok_or(LanRuntimeError::CompanionStateUnavailable)?;
                let attempt = MobileSessionAttempt::respond(
                    challenge,
                    &signer,
                    &current.registry,
                    &mut replay,
                    response_sequence,
                    now,
                )
                .await
                .map_err(LanRuntimeError::from_challenge_refusal)?;
                let mut next = current.clone();
                next.replay = replay
                    .snapshot(now)
                    .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?;
                next.response_sequence = response_sequence;
                // Replay and response sequence are durable before the signed response
                // is released to the transport.
                self.shared
                    .persist_locked(&next)
                    .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?;
                *slot = Some(next);
                Ok(Box::new(AndroidMobileHandshake {
                    attempt,
                    registry: current.registry,
                }) as Box<dyn MobileHandshake>)
            })
        }

        fn accept_message<'a>(
            &'a self,
            connection: &'a hpay_companion_protocol::CompanionConnection,
            message: CompanionMessage,
            replay: ReplayMetadata,
            now: u64,
        ) -> RuntimeFuture<'a, CompanionMessage> {
            Box::pin(async move {
                self.shared
                    .require_available()
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let mut slot = self.shared.state.lock().await;
                let current = slot
                    .as_ref()
                    .ok_or(LanRuntimeError::CompanionNotPaired)?
                    .clone();
                current
                    .validate_at(now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                validate_connection_scope(connection, &current)
                    .map_err(|_| LanRuntimeError::CompanionScopeMismatch)?;
                validate_inbound_message(&message, connection, &current, now)
                    .map_err(|_| LanRuntimeError::CompanionScopeMismatch)?;
                let mut guard = ReplayGuard::from_snapshot(current.replay.clone(), now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let permit = guard
                    .check(&replay, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)?;
                guard
                    .commit(permit, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)?;
                let mut next = current;
                next.replay = guard
                    .snapshot(now)
                    .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?;
                // Durable replay commit happens before the plaintext message is
                // released to the command/UI layer.
                self.shared
                    .persist_locked(&next)
                    .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?;
                *slot = Some(next);
                Ok(message)
            })
        }
    }

    impl AgentCompanionMobileState {
        pub(in crate::agent_companion) async fn connect(
            &self,
            app: AppHandle,
        ) -> Result<CompanionSessionView, String> {
            self.run_guarded(CONNECT_TIMEOUT, "Private-LAN reconnect timed out", async {
                let state = self
                    .shared
                    .current()
                    .await?
                    .ok_or_else(|| "Pair this phone before connecting".to_owned())?;
                let mut active = self.active.lock().await;
                if let Some(existing) = active.as_ref() {
                    existing
                        .session
                        .connection()
                        .validate_at(unix_now()?)
                        .map_err(|error| error.to_string())?;
                    let view =
                        CompanionSessionView::from_connection(existing.session.connection(), true);
                    drop(active);
                    self.renew_session_lease().await;
                    return Ok(view);
                }
                let backend: Arc<dyn MobileSessionBackend> = Arc::new(AndroidMobileBackend {
                    app,
                    shared: Arc::clone(&self.shared),
                });
                let mut last_error = "No private-LAN endpoint was available".to_owned();
                let mut connected = None;
                for endpoint in state.endpoints.clone() {
                    let address = SocketAddr::new(endpoint.ip(), endpoint.port());
                    match MobileLanSession::connect(
                        address,
                        state.mobile_device_id.clone(),
                        Arc::clone(&backend),
                    )
                    .await
                    {
                        Ok(session) => {
                            connected = Some(session);
                            break;
                        }
                        Err(error) => last_error = error.to_string(),
                    }
                }
                let session = connected.ok_or(last_error)?;
                validate_connection_scope(session.connection(), &state)?;
                self.shared.clear_pending_pairing_ack().await?;
                let view = CompanionSessionView::from_connection(session.connection(), true);
                *active = Some(ActiveSession {
                    session,
                    next_sequence: 1,
                    last_received_sequence: 0,
                });
                drop(active);
                self.renew_session_lease().await;
                Ok(view)
            })
            .await
        }

        async fn exchange_once(&self, kind: OutboundKind) -> Result<CompanionMessage, String> {
            let restricted_candidate = self.shared.current().await?.is_some_and(|state| {
                state.rotation_candidate_acceptance.is_some()
                    && state.rotation_phase != WitnessRotationPhase::Completed
            });
            if restricted_candidate
                && !matches!(
                    kind,
                    OutboundKind::RotationPoll(_)
                        | OutboundKind::RotationBaseline(_)
                        | OutboundKind::Witness(_)
                )
            {
                return Err(
                    "Rotation candidate session cannot access general companion actions".to_owned(),
                );
            }
            let result = self
                .run_guarded(EXCHANGE_TIMEOUT, "Companion exchange timed out", async {
                    let mut slot = self.active.lock().await;
                    let active = slot
                        .as_mut()
                        .ok_or_else(|| "Mobile companion is not connected".to_owned())?;
                    let payload = match &kind {
                        OutboundKind::Sync => CompanionPayload::SyncRequest {
                            since_sequence: active.last_received_sequence,
                        },
                        OutboundKind::Ping => CompanionPayload::Ping,
                        OutboundKind::Approval(decision) => {
                            CompanionPayload::ApprovalDecision(decision.clone())
                        }
                        OutboundKind::AgentFastPayApprovalPoll {
                            agent_wallet_id,
                            operation_id,
                        } => CompanionPayload::AgentFastPayApprovalPoll {
                            agent_wallet_id: agent_wallet_id.clone(),
                            operation_id: operation_id.clone(),
                        },
                        OutboundKind::AgentFastPayApprovalDecision(signed) => {
                            CompanionPayload::AgentFastPayApprovalDecision(signed.clone())
                        }
                        OutboundKind::AgentHvmApprovalPoll {
                            agent_wallet_id,
                            operation_id,
                        } => CompanionPayload::AgentHvmApprovalPoll {
                            agent_wallet_id: agent_wallet_id.clone(),
                            operation_id: operation_id.clone(),
                        },
                        OutboundKind::AgentHvmApprovalDecision(signed) => {
                            CompanionPayload::AgentHvmApprovalDecision(signed.clone())
                        }
                        OutboundKind::RecoverPendingWitness(operation_id) => {
                            CompanionPayload::RecoverPendingWitness {
                                operation_id: operation_id.clone(),
                            }
                        }
                        OutboundKind::Witness(receipt) => {
                            CompanionPayload::WitnessReceipt(receipt.clone())
                        }
                        OutboundKind::RotationPoll(rotation_id) => {
                            CompanionPayload::WitnessRotationPoll {
                                rotation_id: rotation_id.clone(),
                            }
                        }
                        OutboundKind::RotationAuthorization(signed) => {
                            CompanionPayload::WitnessRotationAuthorization(signed.clone())
                        }
                        OutboundKind::RotationBaseline(signed) => {
                            CompanionPayload::WitnessRotationBaseline(signed.clone())
                        }
                    };
                    let message = build_outbound_message(active, payload)?;
                    active
                        .session
                        .send(&message)
                        .await
                        .map_err(|error| error.to_string())?;
                    let response = active
                        .session
                        .receive()
                        .await
                        .map_err(|error| error.to_string())?;
                    match &kind {
                        OutboundKind::Ping
                            if !matches!(response.payload, CompanionPayload::Pong) =>
                        {
                            return Err("Desktop returned an unexpected ping response".to_owned());
                        }
                        OutboundKind::Sync
                            if !matches!(
                                response.payload,
                                CompanionPayload::StatusSnapshot { .. }
                            ) =>
                        {
                            return Err("Desktop returned an unexpected sync response".to_owned());
                        }
                        OutboundKind::Approval(_)
                            if !matches!(
                                response.payload,
                                CompanionPayload::RollbackAnchorProposal(_)
                                    | CompanionPayload::AdminAck { .. }
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected approval response".to_owned()
                            );
                        }
                        OutboundKind::AgentFastPayApprovalPoll { .. }
                            if !matches!(
                                response.payload,
                                CompanionPayload::AgentFastPayApprovalRequest(_)
                                    | CompanionPayload::AdminAck { .. }
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected Agent Fast Pay approval response"
                                    .to_owned(),
                            );
                        }
                        OutboundKind::AgentFastPayApprovalDecision(_)
                            if !matches!(response.payload, CompanionPayload::AdminAck { .. }) =>
                        {
                            return Err(
                                "Desktop returned an unexpected Agent Fast Pay decision response"
                                    .to_owned(),
                            );
                        }
                        OutboundKind::AgentHvmApprovalPoll { .. }
                            if !matches!(
                                response.payload,
                                CompanionPayload::AgentHvmApprovalRequest(_)
                                    | CompanionPayload::AdminAck { .. }
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected Agent HVM approval response"
                                    .to_owned(),
                            );
                        }
                        OutboundKind::AgentHvmApprovalDecision(_)
                            if !matches!(response.payload, CompanionPayload::AdminAck { .. }) =>
                        {
                            return Err(
                                "Desktop returned an unexpected Agent HVM decision response"
                                    .to_owned(),
                            );
                        }
                        OutboundKind::RecoverPendingWitness(_)
                            if !matches!(
                                response.payload,
                                CompanionPayload::RollbackAnchorProposal(_)
                            ) =>
                        {
                            return Err("Desktop returned an unexpected pending witness response"
                                .to_owned());
                        }
                        OutboundKind::Witness(_)
                            if !matches!(
                                response.payload,
                                CompanionPayload::WitnessAck { .. }
                                    | CompanionPayload::RollbackAnchorProposal(_)
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected witness response".to_owned()
                            );
                        }
                        OutboundKind::RotationPoll(_)
                            if !matches!(
                                response.payload,
                                CompanionPayload::WitnessRotationProposal(_)
                                    | CompanionPayload::RollbackAnchorProposal(_)
                                    | CompanionPayload::AdminAck { .. }
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected rotation response".to_owned()
                            );
                        }
                        OutboundKind::RotationAuthorization(_)
                            if !matches!(response.payload, CompanionPayload::AdminAck { .. }) =>
                        {
                            return Err(
                                "Desktop returned an unexpected rotation authorization response"
                                    .to_owned(),
                            );
                        }
                        OutboundKind::RotationBaseline(_)
                            if !matches!(
                                response.payload,
                                CompanionPayload::RollbackAnchorProposal(_)
                            ) =>
                        {
                            return Err(
                                "Desktop returned an unexpected rotation baseline response"
                                    .to_owned(),
                            );
                        }
                        _ => {}
                    }
                    active.last_received_sequence =
                        active.last_received_sequence.max(response.sequence);
                    Ok(response)
                })
                .await;
            if result.is_err() {
                self.active.lock().await.take();
            } else {
                self.renew_session_lease().await;
            }
            result
        }

        pub(in crate::agent_companion) async fn exchange_with_reconnect(
            &self,
            app: AppHandle,
            kind: OutboundKind,
        ) -> Result<CompanionMessage, String> {
            let retry_safe = matches!(
                &kind,
                OutboundKind::Sync
                    | OutboundKind::Ping
                    | OutboundKind::AgentFastPayApprovalPoll { .. }
                    | OutboundKind::AgentHvmApprovalPoll { .. }
                    | OutboundKind::RecoverPendingWitness(_)
                    | OutboundKind::RotationPoll(_)
            );
            self.connect(app.clone()).await?;
            match self.exchange_once(kind.clone()).await {
                Ok(message) => Ok(message),
                Err(error) if error.contains("cancelled by lifecycle transition") => Err(error),
                Err(error) if !retry_safe => Err(error),
                Err(_) => {
                    self.connect(app).await?;
                    self.exchange_once(kind).await
                }
            }
        }

        pub(in crate::agent_companion) async fn disconnect(&self) -> Result<(), String> {
            self.signal_lifecycle_cancel();
            let _lifecycle = self.lifecycle.lock().await;
            *self.lease_deadline.lock().await = None;
            let Some(mut active) = self.active.lock().await.take() else {
                return Ok(());
            };
            let message = build_outbound_message(
                &mut active,
                CompanionPayload::Disconnect {
                    reason: "mobile_user_disconnect".to_owned(),
                },
            )?;
            let _ = timeout(EXCHANGE_TIMEOUT, active.session.send(&message)).await;
            active
                .session
                .disconnect()
                .await
                .map_err(|error| error.to_string())
        }
    }

    fn build_outbound_message(
        active: &mut ActiveSession,
        payload: CompanionPayload,
    ) -> Result<CompanionMessage, String> {
        if !outbound_payload_allowed(&payload) {
            return Err("Outbound companion payload is disabled".to_owned());
        }
        let now = unix_now()?;
        let connection = active.session.connection();
        connection
            .validate_at(now)
            .map_err(|error| error.to_string())?;
        let expires_at = now
            .checked_add(MESSAGE_LIFETIME_SECS)
            .ok_or_else(|| "Companion message time overflow".to_owned())?
            .min(connection.expires_at);
        if expires_at <= now {
            return Err("Companion session has expired".to_owned());
        }
        let sequence = active.next_sequence;
        active.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "Companion message sequence exhausted".to_owned())?;
        Ok(CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: format!("mobile_{}_{}", connection.session_id, sequence),
            session_id: connection.session_id.clone(),
            sender_device_id: connection.local_device_id.clone(),
            recipient_device_id: connection.remote_device_id.clone(),
            sequence,
            issued_at: now,
            expires_at,
            payload,
        })
    }
}

#[cfg(target_os = "android")]
pub(super) use android::{ActiveSession, OutboundKind};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hpay_companion_protocol::{
        ApprovalCommitment, ApprovalNetworkBinding, CompanionConnection, CompanionStatus,
        DevicePermission, DeviceRegistry, DeviceRole, LanEndpoint, PROTOCOL_VERSION, ReplayGuard,
        SoftwareDeviceIdentity,
    };

    use super::*;
    use crate::agent_companion::STATE_VERSION;
    use crate::agent_companion::storage::MobileCompanionDurableState;

    fn fixture(now: u64) -> (MobileCompanionDurableState, CompanionConnection) {
        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), now)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                mobile
                    .public_record(
                        "wallet_one",
                        BTreeSet::from([DevicePermission::ViewAgentWalletStatus]),
                        now,
                    )
                    .unwrap(),
            )
            .unwrap();
        let state = MobileCompanionDurableState {
            state_version: STATE_VERSION,
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            mobile_device_id: mobile.device_id().clone(),
            endpoints: vec![LanEndpoint::parse("hpay-lan://192.168.1.8:42492").unwrap()],
            registry,
            replay: ReplayGuard::new().snapshot(now).unwrap(),
            response_sequence: 0,
            approval_sequence: 0,
            pending_pairing_ack: None,
            pending_approval: None,
            pending_agent_fast_pay_approval: None,
            pending_agent_hvm_approval: None,
            pending_witness: None,
            discarded_consents: Vec::new(),
            discarded_consents_dropped: 0,
            witness: None,
            rotation_phase: hpay_companion_protocol::WitnessRotationPhase::Stable,
            pending_rotation_authorization: None,
            pending_rotation_baseline: None,
            rotation_ticket: None,
            rotation_candidate_acceptance: None,
        };
        let connection = CompanionConnection {
            connection_version: 1,
            session_id: "session_one".to_owned(),
            local_device_id: state.mobile_device_id.clone(),
            remote_device_id: state.desktop_device_id.clone(),
            established_at: now,
            expires_at: now + 120,
        };
        (state, connection)
    }

    fn status_message(
        state: &MobileCompanionDurableState,
        connection: &CompanionConnection,
        now: u64,
    ) -> CompanionMessage {
        CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "message_one".to_owned(),
            session_id: connection.session_id.clone(),
            sender_device_id: state.desktop_device_id.clone(),
            recipient_device_id: state.mobile_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: now + 60,
            payload: CompanionPayload::StatusSnapshot {
                status: CompanionStatus {
                    agent_wallet_id: state.agent_wallet_id.clone(),
                    address: "1AgentWallet".to_owned(),
                    available_units: Some(10),
                    node_status: "online".to_owned(),
                    reserved_units: 0,
                    spent_today_units: 0,
                    spent_month_units: 0,
                    paused: false,
                    policy_epoch: 1,
                },
                agents: Vec::new(),
                policies: Vec::new(),
                approvals: Vec::new(),
                activity: Vec::new(),
            },
        }
    }

    #[test]
    fn outer_connect_timeout_covers_human_biometric_handshake_window() {
        let configured = std::hint::black_box(OUTER_CONNECT_TIMEOUT_SECS);
        assert!(configured >= 65);
    }

    #[test]
    fn payload_allowlists_are_read_only_and_directional() {
        assert!(inbound_payload_allowed(&CompanionPayload::Pong));
        assert!(inbound_payload_allowed(&CompanionPayload::AdminAck {
            command_id: "cmd_one".to_owned(),
            accepted: true,
            detail: "paused".to_owned(),
        }));
        assert!(!inbound_payload_allowed(&CompanionPayload::Ping));
        assert!(!inbound_payload_allowed(&CompanionPayload::SyncRequest {
            since_sequence: 0,
        }));
        assert!(outbound_payload_allowed(&CompanionPayload::Ping));
        assert!(outbound_payload_allowed(&CompanionPayload::SyncRequest {
            since_sequence: 0,
        }));
        assert_eq!(
            outbound_payload_allowed(&CompanionPayload::RecoverPendingWitness {
                operation_id: "operation_one".to_owned(),
            }),
            cfg!(feature = "agent-wallet-testnet-pilot")
        );
        let fast_pay_poll = CompanionPayload::AgentFastPayApprovalPoll {
            agent_wallet_id: "wallet_one".to_owned(),
            operation_id: Some("operation_fast_pay_one".to_owned()),
        };
        assert!(!inbound_payload_allowed(&fast_pay_poll));
        assert_eq!(
            outbound_payload_allowed(&fast_pay_poll),
            cfg!(feature = "agent-wallet-testnet-pilot")
        );
        let hvm_poll = CompanionPayload::AgentHvmApprovalPoll {
            agent_wallet_id: "wallet_one".to_owned(),
            operation_id: Some("operation_hvm_one".to_owned()),
        };
        assert!(!inbound_payload_allowed(&hvm_poll));
        assert_eq!(
            outbound_payload_allowed(&hvm_poll),
            cfg!(feature = "agent-wallet-testnet-pilot")
        );
        assert!(!outbound_payload_allowed(&CompanionPayload::Pong));
        assert!(!outbound_payload_allowed(&CompanionPayload::AdminAck {
            command_id: "cmd_one".to_owned(),
            accepted: true,
            detail: "paused".to_owned(),
        }));
        // Dead end 3: a read-only build that had been marked as needing a
        // controlled rotation could not even ask the desktop what rotation was
        // prepared, so it could never run its half and the reset stayed blocked
        // forever. The old-phone half is admitted in every build; everything
        // that ends in a witness receipt is still pilot-only.
        assert!(outbound_payload_allowed(
            &CompanionPayload::WitnessRotationPoll {
                rotation_id: Some("rotation_one".to_owned()),
            }
        ));
        assert_eq!(
            outbound_payload_allowed(&CompanionPayload::WitnessReceipt(witness_receipt_fixture())),
            cfg!(feature = "agent-wallet-testnet-pilot")
        );
    }

    fn witness_receipt_fixture() -> hpay_companion_protocol::SignedWitnessReceipt {
        hpay_companion_protocol::SignedWitnessReceipt {
            receipt: hpay_companion_protocol::WitnessReceipt {
                receipt_version: 1,
                anchor_id: "anchor_one".to_owned(),
                anchor_hash: "11".repeat(32),
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: hpay_companion_protocol::DeviceId::parse(
                    "desktop_".to_owned() + &"b".repeat(32),
                )
                .unwrap(),
                mobile_device_id: hpay_companion_protocol::DeviceId::parse(
                    "mobile_".to_owned() + &"a".repeat(32),
                )
                .unwrap(),
                mobile_authorization_epoch: 1,
                witness_epoch: 1,
                anchor_sequence: 1,
                accepted_at: 1_000,
            },
            signature_hex: "11".repeat(64),
        }
    }

    #[test]
    fn status_snapshot_enforces_time_session_device_and_wallet_scope() {
        let now = 1_000;
        let (state, connection) = fixture(now);
        let valid = status_message(&state, &connection, now);
        assert!(validate_inbound_message(&valid, &connection, &state, now).is_ok());

        let mut expired = valid.clone();
        expired.expires_at = now;
        assert!(validate_inbound_message(&expired, &connection, &state, now).is_err());

        let mut wrong_session = valid.clone();
        wrong_session.session_id = "session_two".to_owned();
        assert!(validate_inbound_message(&wrong_session, &connection, &state, now).is_err());

        let mut wrong_device = valid.clone();
        wrong_device.recipient_device_id = state.desktop_device_id.clone();
        assert!(validate_inbound_message(&wrong_device, &connection, &state, now).is_err());

        let mut exact_fee = valid.clone();
        if let CompanionPayload::StatusSnapshot { approvals, .. } = &mut exact_fee.payload {
            approvals.push(ApprovalCommitment {
                approval_version: if cfg!(feature = "agent-wallet-testnet-pilot") {
                    3
                } else {
                    2
                },
                approval_id: "approval_one".to_owned(),
                operation_id: "operation_one".to_owned(),
                agent_wallet_id: state.agent_wallet_id.clone(),
                agent_id: "agent_one".to_owned(),
                desktop_device_id: state.desktop_device_id.clone(),
                transaction_commitment: "ab".repeat(32),
                amount_units: 10_000,
                fee_units: AGENT_NETWORK_FEE_UNITS,
                wallet_fee_units: 0,
                total_debit_units: 11_000,
                recipient: "1Recipient".to_owned(),
                policy_epoch: 1,
                challenge_nonce: "cd".repeat(16),
                issued_at: now,
                expires_at: now + 60,
                network_binding: cfg!(feature = "agent-wallet-testnet-pilot").then_some(
                    ApprovalNetworkBinding {
                        network_id: "testnet".to_owned(),
                        chain_id: 1,
                        genesis_identifier: "11".repeat(32),
                        node_profile_id: "22".repeat(32),
                        transaction_format_version: 2,
                    },
                ),
            });
        }
        assert!(validate_inbound_message(&exact_fee, &connection, &state, now).is_ok());

        let mut wrong_fee = exact_fee.clone();
        if let CompanionPayload::StatusSnapshot { approvals, .. } = &mut wrong_fee.payload {
            approvals[0].fee_units = 999;
            approvals[0].total_debit_units = 10_999;
        }
        assert!(validate_inbound_message(&wrong_fee, &connection, &state, now).is_err());

        if cfg!(feature = "agent-wallet-testnet-pilot") {
            let mut wrong_binding = exact_fee.clone();
            if let CompanionPayload::StatusSnapshot { approvals, .. } = &mut wrong_binding.payload {
                approvals[0].network_binding.as_mut().unwrap().network_id = "mainnet".to_owned();
            }
            assert!(validate_inbound_message(&wrong_binding, &connection, &state, now).is_err());
        }

        let mut wrong_wallet = valid;
        if let CompanionPayload::StatusSnapshot { status, .. } = &mut wrong_wallet.payload {
            status.agent_wallet_id = "wallet_two".to_owned();
        }
        assert!(validate_inbound_message(&wrong_wallet, &connection, &state, now).is_err());
    }
}
