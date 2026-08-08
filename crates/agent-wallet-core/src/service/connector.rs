use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hpay_agent_connector::{
    AgentBackend, AgentOperationStatus, AgentRequest, AgentResponse, ConnectorError,
    ConnectorResult, PAIRING_COMPLETION_TTL_SECS, PairedAgent, PairedAgentStatus,
    PairingCompletionRequest, PairingSubmissionCommitment, VerifiedAgentRequest,
};

use super::{
    AgentAuthorization, AgentOperation, AgentPermission, AgentPolicy, AgentRecord, AgentStatus,
    AgentWalletManager, AgentWalletResult, HacUnits, OperationStatus, PaymentOperationView,
    active_reservations, validate_authorization, validate_text,
};
use crate::pairing_outbox::{
    MAX_PAIRING_COMPLETION_OUTBOX_ENTRIES, PairingCompletionOutboxEntry, pairing_id_sha256,
};

impl AgentWalletManager {
    /// Persist the exact identity approved by the connector pairing flow.
    ///
    /// The connector and wallet core deliberately share one `AgentId`; there
    /// is no second registration record that could drift.
    pub fn commit_paired_agent(
        &mut self,
        paired: PairedAgent,
        mut policy: AgentPolicy,
        pairing_id: &str,
        submission_commitment: PairingSubmissionCommitment,
        completion_expires_at_unix: u64,
        now: u64,
    ) -> AgentWalletResult<AgentRecord> {
        paired
            .ensure_active()
            .map_err(|_| super::AgentWalletError::AgentAuthenticationFailed)?;
        let identity_key_sha256 = paired
            .identity_key_sha256()
            .map_err(|_| super::AgentWalletError::AgentAuthenticationFailed)?;
        validate_text(&paired.name, super::MAX_AGENT_NAME_BYTES)?;
        validate_text(&paired.version, super::MAX_AGENT_VERSION_BYTES)?;
        submission_commitment
            .validate()
            .map_err(|_| super::AgentWalletError::AgentAuthenticationFailed)?;
        let pairing_id_sha256 = pairing_id_sha256(pairing_id)?;
        if completion_expires_at_unix <= now
            || completion_expires_at_unix - now > PAIRING_COMPLETION_TTL_SECS
        {
            return Err(super::AgentWalletError::RequestExpired);
        }
        if policy.permissions.is_empty()
            || !policy.permissions.is_subset(&paired.capabilities)
            || paired.server_identity.desktop_instance_id.is_empty()
        {
            return Err(super::AgentWalletError::AgentPermissionDenied);
        }

        self.ensure_session_active(&paired.wallet_id, now)?;
        let session = self.session(&paired.wallet_id)?;
        let mut state = self.load_verified_state(
            &paired.wallet_id,
            &session.state_master,
            &session.journal_key,
        )?;
        state
            .pairing_completion_outbox
            .retain(|_, completion| now < completion.expires_at_unix());
        if state.pairing_completion_outbox.len() >= MAX_PAIRING_COMPLETION_OUTBOX_ENTRIES
            || state
                .pairing_completion_outbox
                .contains_key(&pairing_id_sha256)
            || paired.server_identity.desktop_instance_id != state.primary_signing_device_id
            || state.agents.contains_key(paired.agent_id.as_str())
            || state.agents.values().any(|agent| {
                agent.identity_key_sha256 == identity_key_sha256
                    || agent.identity_public_key_sec1 == paired.identity_public_key_sec1_hex
            })
        {
            return Err(super::AgentWalletError::IdempotencyConflict);
        }

        policy.policy_epoch = state
            .policy_epoch
            .checked_add(1)
            .ok_or(super::AgentWalletError::IntegerOverflow)?;
        super::cancel_pre_signing_operations(&mut state, None, "policy_changed")?;
        state.policy_epoch = policy.policy_epoch;
        let record = AgentRecord {
            agent_id: paired.agent_id,
            wallet_scope: paired.wallet_scope,
            name: paired.name,
            version: paired.version,
            identity_public_key_sec1: paired.identity_public_key_sec1_hex,
            identity_fingerprint: paired.identity_fingerprint,
            identity_key_sha256,
            server_identity: paired.server_identity,
            status: AgentStatus::Active,
            authorization_epoch: paired.authorization_epoch,
            policy,
            paired_at: paired.paired_at_unix,
        };
        let completion = PairingCompletionOutboxEntry::new(
            pairing_id,
            submission_commitment,
            record.clone(),
            completion_expires_at_unix,
        )?;
        state
            .agents
            .insert(record.agent_id.as_str().to_owned(), record.clone());
        if state
            .pairing_completion_outbox
            .insert(pairing_id_sha256, completion)
            .is_some()
        {
            return Err(super::AgentWalletError::IdempotencyConflict);
        }
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            super::AgentJournalEventKind::AgentPaired,
            None,
            Some(record.agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }

    /// Load an approved completion from the encrypted, journal-committed
    /// outbox. The request must prove possession of the exact approved agent
    /// identity; the raw bearer pairing id is hashed before state lookup.
    pub fn pairing_completion(
        &mut self,
        wallet_id: &super::AgentWalletId,
        request: &PairingCompletionRequest,
        now: u64,
    ) -> AgentWalletResult<PairingCompletionOutboxEntry> {
        request
            .verify_identity_proof()
            .map_err(|_| super::AgentWalletError::AgentAuthenticationFailed)?;
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let key = pairing_id_sha256(request.pairing_id())?;
        let completion = state
            .pairing_completion_outbox
            .get(&key)
            .ok_or(super::AgentWalletError::AgentAuthenticationFailed)?;
        completion.matches_request(request, now)?;
        Ok(completion.clone())
    }

    fn paired_agent_snapshot(
        &mut self,
        wallet_id: &super::AgentWalletId,
        agent_id: &super::AgentId,
        now: u64,
    ) -> AgentWalletResult<PairedAgent> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let agent = state
            .agents
            .get(agent_id.as_str())
            .ok_or(super::AgentWalletError::AgentNotPaired)?;
        Ok(PairedAgent {
            agent_id: agent.agent_id.clone(),
            wallet_id: wallet_id.clone(),
            wallet_scope: agent.wallet_scope.clone(),
            name: agent.name.clone(),
            version: agent.version.clone(),
            identity_public_key_sec1_hex: agent.identity_public_key_sec1.clone(),
            identity_fingerprint: agent.identity_fingerprint.clone(),
            capabilities: agent.policy.permissions.clone(),
            status: match agent.status {
                AgentStatus::Active => PairedAgentStatus::Active,
                AgentStatus::Disabled => PairedAgentStatus::Disabled,
                AgentStatus::Revoked => PairedAgentStatus::Revoked,
            },
            paired_at_unix: agent.paired_at,
            authorization_epoch: agent.authorization_epoch,
            server_identity: agent.server_identity.clone(),
        })
    }

    async fn dispatch_verified(
        &mut self,
        verified: VerifiedAgentRequest,
        now: u64,
    ) -> AgentWalletResult<AgentResponse> {
        let request = verified.request().clone();
        let authorization = AgentAuthorization {
            wallet_id: verified.wallet_id().clone(),
            wallet_scope: super::WalletScope::for_agent_wallet(verified.wallet_id()),
            agent_id: verified.agent_id().clone(),
            authorization_epoch: verified.authorization_epoch(),
            identity_key_sha256: verified.identity_key_sha256().to_owned(),
            capability: capability_for(&request),
        };

        match request {
            AgentRequest::GetStatus => {
                let state = self.state_for_verified(&authorization, now)?;
                Ok(AgentResponse::Status {
                    paused: state.payments_suspended,
                    paired: true,
                })
            }
            AgentRequest::GetBalance => {
                let (available_units, reserved_units) =
                    self.balance_for_verified(&authorization, now).await?;
                Ok(AgentResponse::Balance {
                    available_units,
                    reserved_units,
                })
            }
            AgentRequest::CreatePaymentIntent(intent) => {
                let operation = self
                    .create_payment_intent(
                        &authorization,
                        super::AgentPaymentRequest {
                            idempotency_key: intent.idempotency_key,
                            asset: intent.asset,
                            amount_units: HacUnits::new(intent.amount_units),
                            recipient: intent.recipient,
                            reason: intent.reason,
                            expires_at: intent.expires_at_unix,
                        },
                        now,
                    )
                    .await?;
                Ok(AgentResponse::IntentCreated {
                    operation_id: operation.operation_id,
                })
            }
            AgentRequest::GetOwnOperationStatus { operation_id } => {
                let operation = self.operation_for_verified(&authorization, &operation_id, now)?;
                Ok(AgentResponse::OperationStatus {
                    operation_id,
                    status: connector_status(operation.status),
                })
            }
            AgentRequest::ListOwnOperations { limit, cursor } => {
                let operations = self.list_operations_for_agent(&authorization, now)?;
                let mut matching = operations
                    .into_iter()
                    .filter(|operation| {
                        cursor
                            .as_deref()
                            .is_none_or(|cursor| operation.operation_id.as_str() > cursor)
                    })
                    .map(|operation| operation.operation_id);
                let mut operation_ids = matching
                    .by_ref()
                    .take(usize::from(limit) + 1)
                    .collect::<Vec<_>>();
                let has_more = operation_ids.len() > usize::from(limit);
                if has_more {
                    operation_ids.pop();
                }
                let next_cursor = has_more
                    .then(|| operation_ids.last().map(ToString::to_string))
                    .flatten();
                Ok(AgentResponse::Operations {
                    operation_ids,
                    next_cursor,
                })
            }
            AgentRequest::CancelOwnUnsigned { operation_id } => {
                self.cancel_own_unsigned(&authorization, &operation_id, now)?;
                Ok(AgentResponse::Cancelled { operation_id })
            }
        }
    }

    fn state_for_verified(
        &mut self,
        authorization: &AgentAuthorization,
        now: u64,
    ) -> AgentWalletResult<super::AgentWalletState> {
        self.ensure_session_active(&authorization.wallet_id, now)?;
        let session = self.session(&authorization.wallet_id)?;
        let mut state = self.load_verified_state(
            &authorization.wallet_id,
            &session.state_master,
            &session.journal_key,
        )?;
        validate_authorization(&state, authorization)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        Ok(state)
    }

    async fn balance_for_verified(
        &mut self,
        authorization: &AgentAuthorization,
        now: u64,
    ) -> AgentWalletResult<(u64, u64)> {
        let state = self.state_for_verified(authorization, now)?;
        let reserved = active_reservations(&state)?;
        let node = crate::node_binding::verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        let balance = node
            .query_balance_entry(&state.address, false)
            .await
            .map_err(|_| super::AgentWalletError::NodeRejected)
            .and_then(|entry| HacUnits::from_decimal(entry.hacash_decimal()))?;
        let available = balance
            .checked_sub(reserved)
            .map_err(|_| super::AgentWalletError::InsufficientAgentBalance)?;
        Ok((available.get(), reserved.get()))
    }

    fn operation_for_verified(
        &mut self,
        authorization: &AgentAuthorization,
        operation_id: &super::OperationId,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        let state = self.state_for_verified(authorization, now)?;
        let operation = state
            .operations
            .get(operation_id.as_str())
            .ok_or(super::AgentWalletError::OperationNotFound)?;
        if operation.agent_id() != authorization.agent_id() {
            return Err(super::AgentWalletError::AgentPermissionDenied);
        }
        Ok(AgentOperation::view(operation))
    }
}

#[async_trait]
impl AgentBackend for AgentWalletManager {
    async fn paired_agent(
        &mut self,
        agent_id: &super::AgentId,
        wallet_id: &super::AgentWalletId,
    ) -> ConnectorResult<PairedAgent> {
        self.paired_agent_snapshot(wallet_id, agent_id, unix_now()?)
            .map_err(map_core_error)
    }

    async fn dispatch(&mut self, request: VerifiedAgentRequest) -> ConnectorResult<AgentResponse> {
        self.dispatch_verified(request, unix_now()?)
            .await
            .map_err(map_core_error)
    }
}

pub(super) fn validate_agent_record(
    agent: &AgentRecord,
    wallet_id: &super::AgentWalletId,
    primary_signing_device_id: &str,
) -> AgentWalletResult<()> {
    agent.agent_id.validate()?;
    agent.wallet_scope.validate_for(wallet_id)?;
    agent
        .server_identity
        .validate()
        .map_err(|_| super::AgentWalletError::RecoveryRequired)?;
    let candidate = PairedAgent {
        agent_id: agent.agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: agent.wallet_scope.clone(),
        name: agent.name.clone(),
        version: agent.version.clone(),
        identity_public_key_sec1_hex: agent.identity_public_key_sec1.clone(),
        identity_fingerprint: agent.identity_fingerprint.clone(),
        capabilities: agent.policy.permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: agent.paired_at,
        authorization_epoch: agent.authorization_epoch,
        server_identity: agent.server_identity.clone(),
    };
    let actual_digest = candidate
        .identity_key_sha256()
        .map_err(|_| super::AgentWalletError::RecoveryRequired)?;
    if agent.authorization_epoch == 0
        || agent.policy.policy_epoch == 0
        || agent.policy.permissions.is_empty()
        || agent.identity_key_sha256 != actual_digest
        || agent.server_identity.desktop_instance_id != primary_signing_device_id
    {
        return Err(super::AgentWalletError::RecoveryRequired);
    }
    Ok(())
}

fn capability_for(request: &AgentRequest) -> AgentPermission {
    match request {
        AgentRequest::GetStatus => AgentPermission::ReadWalletInfo,
        AgentRequest::GetBalance => AgentPermission::ReadBalance,
        AgentRequest::CreatePaymentIntent(_) => AgentPermission::CreatePaymentIntent,
        AgentRequest::GetOwnOperationStatus { .. } => AgentPermission::ReadOwnOperationStatus,
        AgentRequest::ListOwnOperations { .. } => AgentPermission::ListOwnOperations,
        AgentRequest::CancelOwnUnsigned { .. } => AgentPermission::CancelOwnUnsignedOperation,
    }
}

fn connector_status(status: OperationStatus) -> AgentOperationStatus {
    match status {
        OperationStatus::PaymentIntentCreated => AgentOperationStatus::PaymentIntentCreated,
        OperationStatus::FundsReserved => AgentOperationStatus::FundsReserved,
        OperationStatus::UnsignedTransactionPersisted => {
            AgentOperationStatus::UnsignedTransactionPersisted
        }
        OperationStatus::ApprovalRequested => AgentOperationStatus::ApprovalRequested,
        OperationStatus::Approved => AgentOperationStatus::Approved,
        OperationStatus::Rejected => AgentOperationStatus::Rejected,
        OperationStatus::Signed
        | OperationStatus::SignedAwaitingWitness
        | OperationStatus::WitnessedAwaitingBroadcast => AgentOperationStatus::Signed,
        OperationStatus::BroadcastSubmitted => AgentOperationStatus::BroadcastSubmitted,
        OperationStatus::BroadcastUncertain => AgentOperationStatus::BroadcastUncertain,
        OperationStatus::SubmittedAwaitingFinalWitness => {
            AgentOperationStatus::SubmittedAwaitingFinalWitness
        }
        OperationStatus::ReconciliationRequired => AgentOperationStatus::ReconciliationRequired,
        OperationStatus::ReconciledAwaitingFinalWitness => {
            AgentOperationStatus::ReconciledAwaitingFinalWitness
        }
        OperationStatus::Committed => AgentOperationStatus::Committed,
        OperationStatus::Failed => AgentOperationStatus::Failed,
        OperationStatus::Cancelled => AgentOperationStatus::Cancelled,
        OperationStatus::RecoveryRequired => AgentOperationStatus::RecoveryRequired,
    }
}

fn unix_now() -> ConnectorResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ConnectorError::InvalidTimeWindow)
}

fn map_core_error(error: super::AgentWalletError) -> ConnectorError {
    match error {
        super::AgentWalletError::AgentNotPaired
        | super::AgentWalletError::AgentAuthenticationFailed => {
            ConnectorError::AuthenticationFailed
        }
        super::AgentWalletError::AgentRevoked => ConnectorError::Revoked,
        super::AgentWalletError::AgentSessionExpired
        | super::AgentWalletError::AgentWalletLocked => ConnectorError::SessionExpired,
        super::AgentWalletError::AgentPermissionDenied
        | super::AgentWalletError::AgentPaymentsSuspended
        | super::AgentWalletError::PaymentLimitExceeded
        | super::AgentWalletError::DailyLimitExceeded
        | super::AgentWalletError::RecipientNotAllowed
        | super::AgentWalletError::SigningBlocked
        | super::AgentWalletError::ApprovalRequired
        // No agent can reach the desktop approval command, but classify its
        // refusals with the other "this caller may not do that" outcomes rather
        // than letting the catch-all report them as malformed messages.
        | super::AgentWalletError::WitnessPhoneRequiredForApproval => {
            ConnectorError::CapabilityDenied
        }
        super::AgentWalletError::InvalidIdentifier => ConnectorError::InvalidIdentifier,
        super::AgentWalletError::InvalidWalletScope => ConnectorError::SessionMismatch,
        super::AgentWalletError::RequestExpired | super::AgentWalletError::ApprovalExpired => {
            ConnectorError::Expired
        }
        super::AgentWalletError::RateLimited
        | super::AgentWalletError::TooManyPendingOperations
        | super::AgentWalletError::NodeRejected
        | super::AgentWalletError::PersistenceFailed
        | super::AgentWalletError::JournalAuthenticationFailed
        | super::AgentWalletError::RecoveryRequired
        | super::AgentWalletError::BroadcastUncertain => ConnectorError::Io,
        _ => ConnectorError::InvalidMessage,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hpay_agent_connector::{
        AgentIdentityKey, AuthenticationStart, Capability, ClientEnvelope, ClientMessage,
        ConnectionPhase, ConnectionServer, ErrorCode, FrameCodec, Nonce, PairingBearer,
        PairingRequest, PairingSession, ProtocolEnvelope, RequestId, ServerEnvelope,
        ServerIdentityKey, ServerMessage, TransportBinding, WalletScope, verify_server_challenge,
    };

    use super::*;
    use crate::{ApprovalMode, CreateAgentWallet};

    const PASSPHRASE: &str = "agent connector integration password";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn transport_binding() -> TransportBinding {
        TransportBinding {
            binding_version: 1,
            transport_kind: "local_ipc".to_owned(),
            connection_id: Nonce::random(),
            peer_identity_sha256: "ab".repeat(32),
            transport_transcript_sha256: "cd".repeat(32),
        }
    }

    fn frame(codec: &FrameCodec, message: ClientMessage) -> Vec<u8> {
        ClientEnvelope::new(RequestId::new(), message)
            .to_frame(codec)
            .unwrap()
    }

    fn create_manager(
        capabilities: BTreeSet<Capability>,
    ) -> (
        tempfile::TempDir,
        AgentWalletManager,
        crate::AgentWalletId,
        String,
        AgentIdentityKey,
        ServerIdentityKey,
        PairedAgent,
        String,
        PairingSubmissionCommitment,
    ) {
        let root = tempfile::tempdir().unwrap();
        let mut manager = AgentWalletManager::open(root.path()).unwrap();
        let timestamp = now();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: PASSPHRASE.into(),
                    network_mode: "testnet".into(),
                    node_url: "http://127.0.0.1:18081".into(),
                    block_one_fingerprint: Some(
                        "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff".into(),
                    ),
                },
                timestamp,
            )
            .unwrap();
        manager
            .unlock(&created.wallet_id, PASSPHRASE, timestamp)
            .unwrap();

        let (desktop_id, server_key) = manager
            .connector_server_identity(&created.wallet_id, timestamp)
            .unwrap();
        let pinned = server_key.pinned_identity(desktop_id.clone()).unwrap();
        let agent_key = AgentIdentityKey::generate();
        let mut pairing =
            PairingSession::activate(created.wallet_id.clone(), pinned, timestamp, 60, 2).unwrap();
        let pairing_id = pairing.pairing_id().to_owned();
        let pending = pairing
            .submit(
                timestamp,
                PairingRequest {
                    pairing_id: PairingBearer::parse(pairing.pairing_id().to_owned()).unwrap(),
                    agent_name: "Core Integration Agent".into(),
                    agent_version: "1.0.0".into(),
                    identity_public_key_sec1_hex: agent_key.public_key_sec1_hex(),
                    requested_capabilities: capabilities.clone(),
                },
            )
            .unwrap();
        let paired = pairing
            .approve(
                timestamp,
                &pending.submission_commitment,
                capabilities.clone(),
            )
            .unwrap();
        let policy = AgentPolicy {
            permissions: capabilities,
            max_per_payment_units: HacUnits::ZERO,
            max_daily_units: HacUnits::ZERO,
            max_pending_operations: 0,
            allowed_recipients: Default::default(),
            blocked_recipients: Default::default(),
            allow_unlisted_recipient_with_approval: false,
            approval_mode: ApprovalMode::DesktopManual,
            policy_epoch: 1,
        };
        let persisted = manager
            .commit_paired_agent(
                paired.clone(),
                policy,
                &pairing_id,
                pending.submission_commitment.clone(),
                timestamp + PAIRING_COMPLETION_TTL_SECS,
                timestamp,
            )
            .unwrap();
        assert_eq!(persisted.agent_id, paired.agent_id);
        assert_eq!(
            persisted.identity_key_sha256,
            paired.identity_key_sha256().unwrap()
        );
        (
            root,
            manager,
            created.wallet_id,
            desktop_id,
            agent_key,
            server_key,
            paired,
            pairing_id,
            pending.submission_commitment,
        )
    }

    async fn authenticate(
        server: &mut ConnectionServer<'_>,
        manager: &mut AgentWalletManager,
        agent_key: &AgentIdentityKey,
        paired: &PairedAgent,
        timestamp: u64,
    ) -> hpay_agent_connector::SessionId {
        let capabilities = paired.capabilities.clone();
        let start = AuthenticationStart {
            agent_id: paired.agent_id.clone(),
            wallet_id: paired.wallet_id.clone(),
            wallet_scope: WalletScope::for_agent_wallet(&paired.wallet_id),
            sequence: 1,
            nonce: Nonce::random(),
            issued_at_unix: timestamp,
            expires_at_unix: timestamp + 30,
            requested_capabilities: capabilities,
        };
        let start_hash = start.canonical_sha256_hex().unwrap();
        let output = server
            .handle_frame(
                &frame(server.codec(), ClientMessage::AuthenticationStart(start)),
                timestamp,
                manager,
            )
            .await;
        assert!(!output.close_connection);
        let challenge = match ServerEnvelope::from_frame(server.codec(), &output.frame)
            .unwrap()
            .message
        {
            ServerMessage::AuthenticationChallenge(challenge) => challenge,
            other => panic!("unexpected auth challenge response: {other:?}"),
        };
        let verified = verify_server_challenge(
            &challenge,
            &paired.server_identity,
            server.transport_binding(),
            &start_hash,
            timestamp,
        )
        .unwrap();
        let response = agent_key.sign_verified_challenge(&verified).unwrap();
        let session_id = response.session_id.clone();
        let output = server
            .handle_frame(
                &frame(
                    server.codec(),
                    ClientMessage::AuthenticationResponse(response),
                ),
                timestamp,
                manager,
            )
            .await;
        assert!(!output.close_connection);
        assert_eq!(server.phase(), ConnectionPhase::Authenticated);
        session_id
    }

    #[tokio::test]
    async fn connector_v2_uses_one_durable_identity_and_revocation_authority() {
        let (
            _root,
            mut manager,
            wallet_id,
            desktop_id,
            agent_key,
            server_key,
            paired,
            pairing_id,
            submission_commitment,
        ) = create_manager([Capability::ReadWalletInfo].into_iter().collect());
        let timestamp = now();
        let mut server =
            ConnectionServer::new(desktop_id, &server_key, transport_binding(), 64 * 1024).unwrap();
        let session_id =
            authenticate(&mut server, &mut manager, &agent_key, &paired, timestamp).await;

        let request = ProtocolEnvelope::request(
            paired.agent_id.clone(),
            wallet_id.clone(),
            session_id.clone(),
            1,
            timestamp,
            timestamp + 30,
            AgentRequest::GetStatus,
        )
        .unwrap();
        let output = server
            .handle_frame(
                &frame(server.codec(), ClientMessage::Request(Box::new(request))),
                timestamp,
                &mut manager,
            )
            .await;
        assert!(!output.close_connection);
        assert!(matches!(
            ServerEnvelope::from_frame(server.codec(), &output.frame)
                .unwrap()
                .message,
            ServerMessage::Response(AgentResponse::Status {
                paused: true,
                paired: true
            })
        ));

        let completion_request = PairingCompletionRequest::new(
            PairingBearer::parse(pairing_id).unwrap(),
            submission_commitment,
            &agent_key,
        )
        .unwrap();
        assert!(
            manager
                .pairing_completion(&wallet_id, &completion_request, timestamp)
                .is_ok()
        );
        manager
            .revoke_agent(&wallet_id, &paired.agent_id, timestamp)
            .unwrap();
        assert_eq!(
            manager
                .pairing_completion(&wallet_id, &completion_request, timestamp)
                .unwrap_err(),
            crate::AgentWalletError::AgentAuthenticationFailed
        );
        let after_revoke = ProtocolEnvelope::request(
            paired.agent_id.clone(),
            wallet_id,
            session_id,
            2,
            timestamp,
            timestamp + 30,
            AgentRequest::GetStatus,
        )
        .unwrap();
        let output = server
            .handle_frame(
                &frame(
                    server.codec(),
                    ClientMessage::Request(Box::new(after_revoke)),
                ),
                timestamp,
                &mut manager,
            )
            .await;
        assert!(output.close_connection);
        assert!(matches!(
            ServerEnvelope::from_frame(server.codec(), &output.frame)
                .unwrap()
                .message,
            ServerMessage::Error(error) if error.code == ErrorCode::Revoked
        ));
    }

    #[tokio::test]
    async fn policy_epoch_change_invalidates_an_existing_connector_session() {
        let (
            _root,
            mut manager,
            wallet_id,
            desktop_id,
            agent_key,
            server_key,
            paired,
            pairing_id,
            submission_commitment,
        ) = create_manager([Capability::ReadWalletInfo].into_iter().collect());
        let timestamp = now();
        let mut server =
            ConnectionServer::new(desktop_id, &server_key, transport_binding(), 64 * 1024).unwrap();
        let session_id =
            authenticate(&mut server, &mut manager, &agent_key, &paired, timestamp).await;
        let completion_request = PairingCompletionRequest::new(
            PairingBearer::parse(pairing_id).unwrap(),
            submission_commitment,
            &agent_key,
        )
        .unwrap();
        assert!(
            manager
                .pairing_completion(&wallet_id, &completion_request, timestamp)
                .is_ok()
        );
        let mut changed = manager
            .agent_policy_admin(&wallet_id, &paired.agent_id, timestamp)
            .unwrap();
        changed.max_pending_operations = 1;
        manager
            .update_agent_policy_admin(&wallet_id, &paired.agent_id, changed, timestamp)
            .unwrap();
        assert_eq!(
            manager
                .pairing_completion(&wallet_id, &completion_request, timestamp)
                .unwrap_err(),
            crate::AgentWalletError::AgentAuthenticationFailed
        );

        let request = ProtocolEnvelope::request(
            paired.agent_id,
            wallet_id,
            session_id,
            1,
            timestamp,
            timestamp + 30,
            AgentRequest::GetStatus,
        )
        .unwrap();
        let output = server
            .handle_frame(
                &frame(server.codec(), ClientMessage::Request(Box::new(request))),
                timestamp,
                &mut manager,
            )
            .await;
        assert!(output.close_connection);
        assert!(matches!(
            ServerEnvelope::from_frame(server.codec(), &output.frame)
                .unwrap()
                .message,
            ServerMessage::Error(error) if error.code == ErrorCode::Revoked
        ));
    }

    #[tokio::test]
    async fn emergency_stop_after_auth_rejects_payment_before_any_operation_is_created() {
        let capabilities = [Capability::CreatePaymentIntent].into_iter().collect();
        let (
            _root,
            mut manager,
            wallet_id,
            desktop_id,
            agent_key,
            server_key,
            paired,
            _pairing_id,
            _submission_commitment,
        ) = create_manager(capabilities);
        let timestamp = now();
        let mut server =
            ConnectionServer::new(desktop_id, &server_key, transport_binding(), 64 * 1024).unwrap();
        let session_id =
            authenticate(&mut server, &mut manager, &agent_key, &paired, timestamp).await;
        manager
            .disable_all_agent_payments(&wallet_id, timestamp)
            .unwrap();

        let request = ProtocolEnvelope::request(
            paired.agent_id,
            wallet_id.clone(),
            session_id,
            1,
            timestamp,
            timestamp + 30,
            AgentRequest::CreatePaymentIntent(
                hpay_agent_connector::protocol::CreatePaymentIntent {
                    idempotency_key: "emergency-stop-test-0001".into(),
                    asset: "HAC".into(),
                    amount_units: 1,
                    recipient: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into(),
                    reason: "must never reach the node".into(),
                    expires_at_unix: timestamp + 30,
                },
            ),
        )
        .unwrap();
        let output = server
            .handle_frame(
                &frame(server.codec(), ClientMessage::Request(Box::new(request))),
                timestamp,
                &mut manager,
            )
            .await;
        assert!(output.close_connection);
        assert!(matches!(
            ServerEnvelope::from_frame(server.codec(), &output.frame)
                .unwrap()
                .message,
            ServerMessage::Error(error) if error.code == ErrorCode::CapabilityDenied
        ));
        assert!(
            manager
                .list_operations_admin(&wallet_id, timestamp)
                .unwrap()
                .is_empty()
        );
    }
}
