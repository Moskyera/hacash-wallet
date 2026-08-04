use std::collections::BTreeSet;

pub(crate) use hpay_agent_types::Capability;

use crate::error::{ConnectorError, ConnectorResult};
use crate::protocol::{
    AgentId, AgentRequest, AgentWalletId, MAX_CLOCK_SKEW_SECS, Nonce, ProtocolEnvelope, SessionId,
    WalletScope, WireMessage,
};

pub const MAX_SESSION_MESSAGES: usize = 4096;
pub const MAX_SESSION_LIFETIME_SECS: u64 = 60 * 60;

fn required_capability(request: &AgentRequest) -> Capability {
    match request {
        AgentRequest::GetStatus => Capability::ReadWalletInfo,
        AgentRequest::GetBalance => Capability::ReadBalance,
        AgentRequest::CreatePaymentIntent(_) => Capability::CreatePaymentIntent,
        AgentRequest::GetOwnOperationStatus { .. } => Capability::ReadOwnOperationStatus,
        AgentRequest::ListOwnOperations { .. } => Capability::ListOwnOperations,
        AgentRequest::CancelOwnUnsigned { .. } => Capability::CancelOwnUnsignedOperation,
    }
}
#[derive(Debug)]
pub(crate) struct ReplayGuard {
    next_sequence: u64,
    used_nonces: BTreeSet<Nonce>,
}

impl ReplayGuard {
    fn new(first_sequence: u64) -> ConnectorResult<Self> {
        if first_sequence == 0 {
            return Err(ConnectorError::SequenceViolation);
        }
        Ok(Self {
            next_sequence: first_sequence,
            used_nonces: BTreeSet::new(),
        })
    }

    fn accept(&mut self, sequence: u64, nonce: &Nonce) -> ConnectorResult<()> {
        nonce.validate()?;
        if sequence != self.next_sequence {
            return Err(ConnectorError::SequenceViolation);
        }
        if self.used_nonces.len() >= MAX_SESSION_MESSAGES {
            return Err(ConnectorError::SessionExpired);
        }
        if !self.used_nonces.insert(nonce.clone()) {
            return Err(ConnectorError::ReplayDetected);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ConnectorError::SessionExpired)?;
        Ok(())
    }
}

/// An authenticated capability session owned by one local IPC connection.
///
/// This type is intentionally not `Clone`: embedders must keep it attached to
/// the connection that completed challenge-response authentication. Every
/// request also supplies the registry's current authorization epoch so revoke
/// and capability changes invalidate an existing connection immediately.
pub struct CapabilitySession {
    agent_id: AgentId,
    wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    session_id: SessionId,
    capabilities: BTreeSet<Capability>,
    authorization_epoch: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
    replay: ReplayGuard,
}

impl CapabilitySession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        agent_id: AgentId,
        wallet_id: AgentWalletId,
        desktop_instance_id: String,
        session_id: SessionId,
        capabilities: BTreeSet<Capability>,
        authorization_epoch: u64,
        issued_at_unix: u64,
        expires_at_unix: u64,
        first_sequence: u64,
    ) -> ConnectorResult<Self> {
        agent_id.validate()?;
        wallet_id.validate()?;
        session_id.validate()?;
        validate_desktop_instance_id(&desktop_instance_id)?;
        if capabilities.is_empty()
            || authorization_epoch == 0
            || expires_at_unix <= issued_at_unix
            || expires_at_unix - issued_at_unix > MAX_SESSION_LIFETIME_SECS
        {
            return Err(ConnectorError::InvalidTimeWindow);
        }
        Ok(Self {
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            agent_id,
            wallet_id,
            session_id,
            capabilities,
            authorization_epoch,
            issued_at_unix,
            expires_at_unix,
            replay: ReplayGuard::new(first_sequence)?,
        })
    }

    pub(crate) fn authorize(
        &mut self,
        envelope: ProtocolEnvelope,
        now_unix: u64,
        current_authorization_epoch: u64,
    ) -> ConnectorResult<AgentRequest> {
        envelope.validate_shape()?;
        if envelope.agent_id != self.agent_id
            || envelope.wallet_id != self.wallet_id
            || envelope.wallet_scope != self.wallet_scope
            || envelope.session_id != self.session_id
        {
            return Err(ConnectorError::SessionMismatch);
        }
        if current_authorization_epoch != self.authorization_epoch {
            return Err(ConnectorError::Revoked);
        }
        if now_unix < self.issued_at_unix
            || now_unix >= self.expires_at_unix
            || envelope.issued_at_unix < self.issued_at_unix
            || envelope.expires_at_unix > self.expires_at_unix
            || envelope.issued_at_unix > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS)
            || envelope.expires_at_unix <= now_unix
        {
            return Err(ConnectorError::SessionExpired);
        }
        let WireMessage::Request(request) = envelope.payload else {
            return Err(ConnectorError::InvalidMessage);
        };
        let capability = required_capability(&request);
        if !self.capabilities.contains(&capability) {
            return Err(ConnectorError::CapabilityDenied);
        }
        self.replay.accept(envelope.sequence, &envelope.nonce)?;
        Ok(request)
    }

    pub(crate) fn disconnect(self) {}

    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    pub(crate) const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }
}

pub(crate) fn validate_desktop_instance_id(value: &str) -> ConnectorResult<()> {
    let suffix = value
        .strip_prefix("desktop_")
        .ok_or(ConnectorError::InvalidIdentifier)?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConnectorError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProtocolEnvelope;

    const EPOCH: u64 = 7;

    fn session() -> (CapabilitySession, AgentId, AgentWalletId, SessionId) {
        let agent = AgentId::new();
        let wallet = AgentWalletId::new();
        let id = SessionId::new();
        let session = CapabilitySession::new(
            agent.clone(),
            wallet.clone(),
            format!("desktop_{}", uuid::Uuid::new_v4().simple()),
            id.clone(),
            [Capability::ReadBalance].into_iter().collect(),
            EPOCH,
            100,
            500,
            1,
        )
        .unwrap();
        (session, agent, wallet, id)
    }

    #[test]
    fn exact_capability_sequence_and_epoch_are_required() {
        let (mut session, agent, wallet, id) = session();
        let balance = ProtocolEnvelope::request(
            agent.clone(),
            wallet.clone(),
            id.clone(),
            1,
            110,
            120,
            AgentRequest::GetBalance,
        )
        .unwrap();
        assert!(session.authorize(balance.clone(), 115, EPOCH).is_ok());
        assert_eq!(
            session.authorize(balance, 115, EPOCH),
            Err(ConnectorError::SequenceViolation)
        );

        let denied =
            ProtocolEnvelope::request(agent, wallet, id, 2, 115, 125, AgentRequest::GetStatus)
                .unwrap();
        assert_eq!(
            session.authorize(denied.clone(), 120, EPOCH),
            Err(ConnectorError::CapabilityDenied)
        );
        assert_eq!(
            session.authorize(denied, 120, EPOCH + 1),
            Err(ConnectorError::Revoked)
        );
    }

    #[test]
    fn sequence_cross_wallet_and_session_time_escape_fail() {
        let (mut session, agent, wallet, id) = session();
        let out_of_order = ProtocolEnvelope::request(
            agent.clone(),
            wallet,
            id.clone(),
            2,
            110,
            120,
            AgentRequest::GetBalance,
        )
        .unwrap();
        assert_eq!(
            session.authorize(out_of_order, 115, EPOCH),
            Err(ConnectorError::SequenceViolation)
        );
        let cross_wallet = ProtocolEnvelope::request(
            agent.clone(),
            AgentWalletId::new(),
            id.clone(),
            1,
            110,
            120,
            AgentRequest::GetBalance,
        )
        .unwrap();
        assert_eq!(
            session.authorize(cross_wallet, 115, EPOCH),
            Err(ConnectorError::SessionMismatch)
        );
        let before_session = ProtocolEnvelope::request(
            agent.clone(),
            AgentWalletId::parse(session.wallet_id.as_str()).unwrap(),
            id.clone(),
            1,
            90,
            120,
            AgentRequest::GetBalance,
        )
        .unwrap();
        assert_eq!(
            session.authorize(before_session, 115, EPOCH),
            Err(ConnectorError::SessionExpired)
        );
        let after_session = ProtocolEnvelope::request(
            agent,
            AgentWalletId::parse(session.wallet_id.as_str()).unwrap(),
            id,
            1,
            250,
            501,
            AgentRequest::GetBalance,
        )
        .unwrap();
        assert_eq!(
            session.authorize(after_session, 260, EPOCH),
            Err(ConnectorError::SessionExpired)
        );
    }

    #[test]
    fn capability_deserialization_has_no_privileged_variants() {
        for denied in [
            "export_private_key",
            "export_seed",
            "sign_arbitrary_bytes",
            "sign_arbitrary_transaction",
            "access_personal_wallet",
            "change_settings",
            "change_own_permissions",
            "increase_own_limits",
            "pair_new_agent",
            "manage_devices",
            "open_channel",
            "close_channel",
            "disable_security",
        ] {
            assert!(serde_json::from_str::<Capability>(&format!("\"{denied}\"")).is_err());
        }
        assert_eq!(Capability::ALL.len(), 6);
    }
}
