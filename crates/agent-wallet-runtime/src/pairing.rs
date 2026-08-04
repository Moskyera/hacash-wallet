use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_wallet_core::{
    AgentPolicy, AgentRecord, AgentWalletError, AgentWalletId, AgentWalletManager,
};
use hpay_agent_connector::{
    Capability, ConnectorError, PairedAgent, PairingBearer, PairingClientEnvelope,
    PairingClientMessage, PairingRequest, PairingServerEnvelope, PairingSession,
    PairingSubmissionCommitment, PendingPairing, PinnedServerIdentity, ServerIdentityKey,
};

use crate::error::{RuntimeError, RuntimeResult};
use crate::pairing_completion::ApprovedPairingCompletion;

pub(crate) type SharedPairingState = Arc<Mutex<PairingRuntimeState>>;

pub struct PairingActivation {
    pairing_id: PairingBearer,
    wallet_id: AgentWalletId,
    expires_at_unix: u64,
    server_identity: PinnedServerIdentity,
}

impl PairingActivation {
    pub fn pairing_id(&self) -> &str {
        self.pairing_id.expose_for_activation()
    }

    pub fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn server_identity(&self) -> &PinnedServerIdentity {
        &self.server_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairingView {
    pub wallet_id: AgentWalletId,
    pub agent_name: String,
    pub agent_version: String,
    pub identity_fingerprint: String,
    pub requested_capabilities: BTreeSet<Capability>,
    pub submission_commitment: PairingSubmissionCommitment,
    pub expires_at_unix: u64,
}

struct ActivePairing {
    wallet_id: AgentWalletId,
    session: PairingSession,
    pending: Option<PendingPairingView>,
}

#[derive(Default)]
pub(crate) struct PairingRuntimeState {
    accepting: bool,
    active: Option<ActivePairing>,
}

impl PairingRuntimeState {
    pub(crate) fn enable(&mut self) {
        self.accepting = true;
    }

    pub(crate) fn disable_and_clear(&mut self) {
        self.accepting = false;
        self.active = None;
    }

    pub(crate) fn activate(
        &mut self,
        wallet_id: AgentWalletId,
        server_identity: PinnedServerIdentity,
        now_unix: u64,
        ttl_secs: u64,
        max_attempts: u8,
    ) -> RuntimeResult<PairingActivation> {
        self.clear_expired(now_unix);
        if !self.accepting {
            return Err(RuntimeError::NotRunning);
        }
        if self.active.is_some() {
            return Err(RuntimeError::PairingAlreadyActive);
        }
        let session = PairingSession::activate(
            wallet_id.clone(),
            server_identity.clone(),
            now_unix,
            ttl_secs,
            max_attempts,
        )?;
        let activation = PairingActivation {
            pairing_id: session.pairing_bearer_for_activation(),
            wallet_id: wallet_id.clone(),
            expires_at_unix: session.expires_at_unix(),
            server_identity,
        };
        self.active = Some(ActivePairing {
            wallet_id,
            session,
            pending: None,
        });
        Ok(activation)
    }

    pub(crate) fn submit(
        &mut self,
        now_unix: u64,
        request: PairingRequest,
    ) -> Result<PendingPairing, ConnectorError> {
        self.clear_expired(now_unix);
        if !self.accepting {
            return Err(ConnectorError::PairingInactive);
        }
        let result = self
            .active
            .as_mut()
            .ok_or(ConnectorError::PairingInactive)?
            .session
            .submit(now_unix, request);
        match result {
            Ok(pending) => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or(ConnectorError::PairingInactive)?;
                active.pending = Some(PendingPairingView {
                    wallet_id: active.wallet_id.clone(),
                    agent_name: pending.request.agent_name.clone(),
                    agent_version: pending.request.agent_version.clone(),
                    identity_fingerprint: pending.identity_fingerprint.clone(),
                    requested_capabilities: pending.request.requested_capabilities.clone(),
                    submission_commitment: pending.submission_commitment.clone(),
                    expires_at_unix: active.session.expires_at_unix(),
                });
                Ok(pending)
            }
            Err(error) => {
                if matches!(
                    error,
                    ConnectorError::Expired
                        | ConnectorError::PairingConsumed
                        | ConnectorError::PairingAttemptsExceeded
                ) {
                    self.active = None;
                }
                Err(error)
            }
        }
    }

    pub(crate) fn pending(&mut self, now_unix: u64) -> Option<PendingPairingView> {
        self.clear_expired(now_unix);
        if !self.accepting {
            return None;
        }
        self.active
            .as_ref()
            .and_then(|active| active.pending.clone())
    }

    pub(crate) fn take(
        &mut self,
        pairing_id: &str,
        expected_submission_commitment: &PairingSubmissionCommitment,
        now_unix: u64,
    ) -> RuntimeResult<PairingSession> {
        self.clear_expired(now_unix);
        if !self.accepting {
            return Err(RuntimeError::NotRunning);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(ConnectorError::PairingInactive)?;
        let pending = active
            .pending
            .as_ref()
            .ok_or(ConnectorError::PairingInactive)?;
        if active.session.pairing_id() != pairing_id
            || &pending.submission_commitment != expected_submission_commitment
        {
            return Err(ConnectorError::AuthenticationFailed.into());
        }
        self.active
            .take()
            .map(|active| active.session)
            .ok_or(ConnectorError::PairingInactive.into())
    }

    fn clear_expired(&mut self, now_unix: u64) {
        if self
            .active
            .as_ref()
            .is_some_and(|active| now_unix >= active.session.expires_at_unix())
        {
            self.active = None;
        }
    }

    pub(crate) const fn is_accepting(&self) -> bool {
        self.accepting
    }
}

pub(crate) async fn process_pairing_envelope(
    state: &SharedPairingState,
    manager: &tokio::sync::Mutex<AgentWalletManager>,
    wallet_id: &AgentWalletId,
    envelope: PairingClientEnvelope,
    server_identity_key: &ServerIdentityKey,
    now_unix: u64,
) -> RuntimeResult<PairingServerEnvelope> {
    let request_id = envelope.request_id;
    match envelope.payload {
        PairingClientMessage::Submit(request) => {
            let result = state
                .lock()
                .map_err(|_| RuntimeError::WorkerPanicked)?
                .submit(now_unix, request);
            match result {
                Ok(pending) => {
                    PairingServerEnvelope::pending(request_id, &pending).map_err(Into::into)
                }
                Err(error) => Ok(PairingServerEnvelope::error(request_id, &error)),
            }
        }
        PairingClientMessage::Completion(request) => {
            if !state
                .lock()
                .map_err(|_| RuntimeError::WorkerPanicked)?
                .is_accepting()
            {
                return Ok(PairingServerEnvelope::error(
                    request_id,
                    &ConnectorError::PairingInactive,
                ));
            }
            let persisted = manager
                .lock()
                .await
                .pairing_completion(wallet_id, &request, now_unix)
                .map_err(map_completion_error);
            let result = persisted.and_then(|completion| {
                ApprovedPairingCompletion::new(completion).complete(
                    &request,
                    wallet_id,
                    server_identity_key,
                    now_unix,
                )
            });
            match result {
                Ok(receipt) => {
                    PairingServerEnvelope::completed(request_id, receipt).map_err(Into::into)
                }
                Err(RuntimeError::Connector(error)) => {
                    Ok(PairingServerEnvelope::error(request_id, &error))
                }
                Err(error) => Err(error),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_approved_pairing(
    manager: &tokio::sync::Mutex<AgentWalletManager>,
    paired: PairedAgent,
    policy: AgentPolicy,
    pairing_id: &str,
    submission_commitment: PairingSubmissionCommitment,
    completion_expires_at_unix: u64,
    now_unix: u64,
) -> RuntimeResult<AgentRecord> {
    manager
        .lock()
        .await
        .commit_paired_agent(
            paired,
            policy,
            pairing_id,
            submission_commitment,
            completion_expires_at_unix,
            now_unix,
        )
        .map_err(|_| RuntimeError::PairingCommitFailed)
}

fn map_completion_error(error: AgentWalletError) -> RuntimeError {
    let connector = match error {
        AgentWalletError::RequestExpired => ConnectorError::Expired,
        AgentWalletError::AgentAuthenticationFailed | AgentWalletError::InvalidIdentifier => {
            ConnectorError::AuthenticationFailed
        }
        AgentWalletError::AgentWalletLocked | AgentWalletError::AgentSessionExpired => {
            ConnectorError::PairingInactive
        }
        AgentWalletError::RecoveryRequired
        | AgentWalletError::PersistenceFailed
        | AgentWalletError::JournalAuthenticationFailed => ConnectorError::Io,
        _ => ConnectorError::InvalidMessage,
    };
    connector.into()
}

pub(crate) fn unix_now() -> RuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RuntimeError::InvalidConfiguration)
}
