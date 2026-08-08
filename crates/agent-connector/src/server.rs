use std::collections::BTreeSet;

use async_trait::async_trait;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authentication::{
    AuthenticationChallenge, AuthenticationChallengeContext, AuthenticationResponse,
    ChallengePayload, TransportBinding, authenticate_response,
};
use crate::error::{ConnectorError, ConnectorResult, ErrorResponse};
use crate::framing::FrameCodec;
use crate::pairing::{PairedAgent, ServerIdentityKey};
use crate::protocol::{
    AgentId, AgentRequest, AgentResponse, AgentWalletId, Nonce, PROTOCOL_VERSION, ProtocolEnvelope,
    RequestId, SessionId, WalletScope, validate_time_window,
};
use crate::session::{Capability, CapabilitySession};

pub const MAX_AUTHENTICATION_START_TTL_SECS: u64 = 60;
pub const MIN_CONNECTION_FRAME_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    AwaitingAuthenticationStart,
    ChallengeIssued,
    Authenticated,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationStart {
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub wallet_scope: WalletScope,
    pub sequence: u64,
    pub nonce: Nonce,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub requested_capabilities: BTreeSet<Capability>,
}

impl AuthenticationStart {
    pub fn validate_at(&self, now_unix: u64) -> ConnectorResult<()> {
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        self.nonce.validate()?;
        validate_time_window(self.issued_at_unix, self.expires_at_unix)?;
        if self.sequence != 1
            || self.requested_capabilities.is_empty()
            || self.expires_at_unix - self.issued_at_unix > MAX_AUTHENTICATION_START_TTL_SECS
        {
            return Err(ConnectorError::InvalidMessage);
        }
        if now_unix < self.issued_at_unix || now_unix >= self.expires_at_unix {
            return Err(ConnectorError::Expired);
        }
        Ok(())
    }
    pub fn canonical_sha256_hex(&self) -> ConnectorResult<String> {
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        self.nonce.validate()?;
        let mut bytes = Vec::with_capacity(512);
        append_start_field(&mut bytes, b"HPAY/AGENT-AUTH/START/V1")?;
        append_start_field(&mut bytes, self.agent_id.as_str().as_bytes())?;
        append_start_field(&mut bytes, self.wallet_id.as_str().as_bytes())?;
        append_start_field(&mut bytes, self.wallet_scope.as_str().as_bytes())?;
        append_start_field(&mut bytes, &self.sequence.to_be_bytes())?;
        append_start_field(&mut bytes, self.nonce.as_str().as_bytes())?;
        append_start_field(&mut bytes, &self.issued_at_unix.to_be_bytes())?;
        append_start_field(&mut bytes, &self.expires_at_unix.to_be_bytes())?;
        for capability in &self.requested_capabilities {
            append_start_field(&mut bytes, capability_wire_name(*capability))?;
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientMessage {
    AuthenticationStart(AuthenticationStart),
    AuthenticationResponse(AuthenticationResponse),
    Request(Box<ProtocolEnvelope>),
    Disconnect,
}

impl ClientMessage {
    fn validate_at(&self, now_unix: u64) -> ConnectorResult<()> {
        match self {
            Self::AuthenticationStart(start) => start.validate_at(now_unix),
            Self::AuthenticationResponse(response) => response.validate_shape(),
            Self::Request(envelope) => envelope.validate_shape(),
            Self::Disconnect => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub message: ClientMessage,
}

impl ClientEnvelope {
    pub fn new(request_id: RequestId, message: ClientMessage) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            message,
        }
    }

    pub fn to_frame(&self, codec: &FrameCodec) -> ConnectorResult<Vec<u8>> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.request_id.validate()?;
        let payload = serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)?;
        codec.encode(&payload)
    }

    pub fn from_frame(codec: &FrameCodec, frame: &[u8], now_unix: u64) -> ConnectorResult<Self> {
        let payload = codec.decode_exact(frame)?;
        let envelope: Self =
            serde_json::from_slice(&payload).map_err(|_| ConnectorError::InvalidMessage)?;
        if envelope.protocol_version != PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        envelope.request_id.validate()?;
        envelope.message.validate_at(now_unix)?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServerMessage {
    AuthenticationChallenge(Box<ChallengePayload>),
    Authenticated {
        session_id: SessionId,
        authorization_epoch: u64,
        capabilities: BTreeSet<Capability>,
    },
    Response(AgentResponse),
    Error(ErrorResponse),
    Disconnected,
}

impl ServerMessage {
    fn validate(&self) -> ConnectorResult<()> {
        match self {
            Self::AuthenticationChallenge(challenge) => challenge.validate_shape(),
            Self::Authenticated {
                session_id,
                authorization_epoch,
                capabilities,
            } => {
                session_id.validate()?;
                if *authorization_epoch == 0 || capabilities.is_empty() {
                    return Err(ConnectorError::InvalidMessage);
                }
                Ok(())
            }
            Self::Response(response) => response.validate(),
            Self::Error(error) if error.message.len() <= 512 => Ok(()),
            Self::Error(_) => Err(ConnectorError::InvalidMessage),
            Self::Disconnected => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub message: ServerMessage,
}

impl ServerEnvelope {
    pub fn from_frame(codec: &FrameCodec, frame: &[u8]) -> ConnectorResult<Self> {
        let payload = codec.decode_exact(frame)?;
        let envelope: Self =
            serde_json::from_slice(&payload).map_err(|_| ConnectorError::InvalidMessage)?;
        if envelope.protocol_version != PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        envelope.request_id.validate()?;
        envelope.message.validate()?;
        Ok(envelope)
    }

    fn to_frame(&self, codec: &FrameCodec) -> ConnectorResult<Vec<u8>> {
        self.message.validate()?;
        let payload = serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)?;
        codec.encode(&payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOutput {
    pub frame: Vec<u8>,
    pub close_connection: bool,
}

/// An authorization proof consumed by the business backend.
///
/// It cannot be constructed, cloned, serialized, or deserialized outside this
/// crate. The exact typed request is owned by the proof, preventing callers
/// from authorizing one request and dispatching another.
///
/// ```compile_fail
/// use hpay_agent_connector::VerifiedAgentRequest;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedAgentRequest>();
/// ```
///
/// ```compile_fail
/// use hpay_agent_connector::VerifiedAgentRequest;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<VerifiedAgentRequest>();
/// ```
///
/// ```compile_fail
/// use hpay_agent_connector::VerifiedAgentRequest;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<VerifiedAgentRequest>();
/// ```
pub struct VerifiedAgentRequest {
    connection_request_id: RequestId,
    protocol_request_id: RequestId,
    agent_id: AgentId,
    wallet_id: AgentWalletId,
    session_id: SessionId,
    authorization_epoch: u64,
    identity_key_sha256: String,
    request: AgentRequest,
}

impl VerifiedAgentRequest {
    pub fn connection_request_id(&self) -> &RequestId {
        &self.connection_request_id
    }

    pub fn protocol_request_id(&self) -> &RequestId {
        &self.protocol_request_id
    }

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }

    pub fn identity_key_sha256(&self) -> &str {
        &self.identity_key_sha256
    }

    pub const fn request(&self) -> &AgentRequest {
        &self.request
    }
}

/// Async typed business dispatch boundary. There is no generic command,
/// arbitrary signer, Personal Wallet handle, or synchronous `block_on` bridge.
///
/// ```compile_fail
/// use hpay_agent_connector::PairedAgentRegistry;
/// ```
#[async_trait]
pub trait AgentBackend: Send {
    /// Reads the current durable pairing and authorization state. Implementors
    /// must not satisfy this from a stale connection-local snapshot.
    async fn paired_agent(
        &mut self,
        agent_id: &AgentId,
        wallet_id: &AgentWalletId,
    ) -> ConnectorResult<PairedAgent>;

    async fn dispatch(&mut self, request: VerifiedAgentRequest) -> ConnectorResult<AgentResponse>;
}

struct IssuedChallenge {
    challenge: AuthenticationChallenge,
    paired: PairedAgent,
}

struct AuthenticatedConnection {
    session: CapabilitySession,
    identity_key_sha256: String,
}

enum ConnectionState {
    AwaitingAuthenticationStart,
    ChallengeIssued(Box<IssuedChallenge>),
    Authenticated(Box<AuthenticatedConnection>),
    Closed,
}

/// A single-connection, transport-agnostic server.
///
/// Callers supply one complete length-prefixed frame at a time. This type does
/// not bind, listen, connect, spawn threads, or perform any network/IPC I/O.
pub struct ConnectionServer<'a> {
    codec: FrameCodec,
    desktop_instance_id: String,
    server_identity_key: &'a ServerIdentityKey,
    transport_binding: TransportBinding,
    state: ConnectionState,
}

impl<'a> ConnectionServer<'a> {
    pub fn new(
        desktop_instance_id: String,
        server_identity_key: &'a ServerIdentityKey,
        transport_binding: TransportBinding,
        max_frame_bytes: usize,
    ) -> ConnectorResult<Self> {
        crate::session::validate_desktop_instance_id(&desktop_instance_id)?;
        transport_binding.validate()?;
        server_identity_key.pinned_identity(desktop_instance_id.clone())?;
        if !(MIN_CONNECTION_FRAME_BYTES..=crate::framing::MAX_FRAME_BYTES)
            .contains(&max_frame_bytes)
        {
            return Err(ConnectorError::InvalidFrame);
        }
        Ok(Self {
            codec: FrameCodec::new(max_frame_bytes)?,
            desktop_instance_id,
            server_identity_key,
            transport_binding,
            state: ConnectionState::AwaitingAuthenticationStart,
        })
    }

    pub const fn phase(&self) -> ConnectionPhase {
        match &self.state {
            ConnectionState::AwaitingAuthenticationStart => {
                ConnectionPhase::AwaitingAuthenticationStart
            }
            ConnectionState::ChallengeIssued(_) => ConnectionPhase::ChallengeIssued,
            ConnectionState::Authenticated(_) => ConnectionPhase::Authenticated,
            ConnectionState::Closed => ConnectionPhase::Closed,
        }
    }

    pub const fn codec(&self) -> &FrameCodec {
        &self.codec
    }

    pub const fn transport_binding(&self) -> &TransportBinding {
        &self.transport_binding
    }

    pub async fn handle_frame<B>(
        &mut self,
        frame: &[u8],
        now_unix: u64,
        backend: &mut B,
    ) -> ServerOutput
    where
        B: AgentBackend,
    {
        if self.phase() == ConnectionPhase::Closed {
            return self.error_output(RequestId::new(), ConnectorError::SessionExpired, true);
        }
        let envelope = match ClientEnvelope::from_frame(&self.codec, frame, now_unix) {
            Ok(envelope) => envelope,
            Err(error) => return self.error_output(RequestId::new(), error, true),
        };
        let request_id = envelope.request_id.clone();
        match self.route(envelope, now_unix, backend).await {
            Ok(message) => {
                let close_connection = self.phase() == ConnectionPhase::Closed;
                self.message_output(request_id, message, close_connection)
            }
            Err(error) => self.error_output(request_id, error, true),
        }
    }

    async fn route<B>(
        &mut self,
        envelope: ClientEnvelope,
        now_unix: u64,
        backend: &mut B,
    ) -> ConnectorResult<ServerMessage>
    where
        B: AgentBackend,
    {
        let state = std::mem::replace(&mut self.state, ConnectionState::Closed);
        match (state, envelope.message) {
            (
                ConnectionState::AwaitingAuthenticationStart,
                ClientMessage::AuthenticationStart(start),
            ) => {
                let authentication_start_sha256 = start.canonical_sha256_hex()?;
                let paired = backend
                    .paired_agent(&start.agent_id, &start.wallet_id)
                    .await?;
                paired.ensure_active()?;
                if paired.wallet_scope != start.wallet_scope
                    || !start.requested_capabilities.is_subset(&paired.capabilities)
                {
                    return Err(ConnectorError::CapabilityDenied);
                }
                let challenge_ttl = start
                    .expires_at_unix
                    .saturating_sub(now_unix)
                    .min(crate::authentication::MAX_CHALLENGE_TTL_SECS);
                if challenge_ttl == 0 {
                    return Err(ConnectorError::Expired);
                }
                let challenge = AuthenticationChallenge::issue(
                    &paired,
                    AuthenticationChallengeContext {
                        server_identity_key: self.server_identity_key,
                        desktop_instance_id: self.desktop_instance_id.clone(),
                        transport_binding: self.transport_binding.clone(),
                        authentication_start_sha256,
                        now_unix,
                        ttl_secs: challenge_ttl,
                    },
                    start.requested_capabilities,
                )?;
                let payload = challenge.payload().clone();
                self.state = ConnectionState::ChallengeIssued(Box::new(IssuedChallenge {
                    challenge,
                    paired,
                }));
                Ok(ServerMessage::AuthenticationChallenge(Box::new(payload)))
            }
            (
                ConnectionState::ChallengeIssued(issued),
                ClientMessage::AuthenticationResponse(response),
            ) => {
                let IssuedChallenge {
                    mut challenge,
                    paired,
                } = *issued;
                let session = authenticate_response(&mut challenge, &response, &paired, now_unix)?;
                let authenticated = ServerMessage::Authenticated {
                    session_id: session.session_id().clone(),
                    authorization_epoch: session.authorization_epoch(),
                    capabilities: session.capabilities().clone(),
                };
                self.state = ConnectionState::Authenticated(Box::new(AuthenticatedConnection {
                    session,
                    identity_key_sha256: paired.identity_key_sha256()?,
                }));
                Ok(authenticated)
            }
            (
                ConnectionState::Authenticated(authenticated),
                ClientMessage::Request(request_envelope),
            ) => {
                let AuthenticatedConnection {
                    mut session,
                    identity_key_sha256,
                } = *authenticated;
                let current = backend
                    .paired_agent(&request_envelope.agent_id, &request_envelope.wallet_id)
                    .await?;
                current.ensure_active()?;
                let current_identity_key_sha256 = current.identity_key_sha256()?;
                if current_identity_key_sha256 != identity_key_sha256 {
                    return Err(ConnectorError::Revoked);
                }
                let protocol_request_id = request_envelope.request_id.clone();
                let request =
                    session.authorize(*request_envelope, now_unix, current.authorization_epoch)?;
                let verified = VerifiedAgentRequest {
                    connection_request_id: envelope.request_id,
                    protocol_request_id,
                    agent_id: current.agent_id,
                    wallet_id: current.wallet_id,
                    session_id: session.session_id().clone(),
                    authorization_epoch: current.authorization_epoch,
                    identity_key_sha256: current_identity_key_sha256,
                    request,
                };
                let response = backend.dispatch(verified).await?;
                response.validate()?;
                self.state = ConnectionState::Authenticated(Box::new(AuthenticatedConnection {
                    session,
                    identity_key_sha256,
                }));
                Ok(ServerMessage::Response(response))
            }
            (ConnectionState::Authenticated(authenticated), ClientMessage::Disconnect) => {
                authenticated.session.disconnect();
                self.state = ConnectionState::Closed;
                Ok(ServerMessage::Disconnected)
            }
            _ => Err(ConnectorError::InvalidMessage),
        }
    }

    fn message_output(
        &mut self,
        request_id: RequestId,
        message: ServerMessage,
        close_connection: bool,
    ) -> ServerOutput {
        let envelope = ServerEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            message,
        };
        match envelope.to_frame(&self.codec) {
            Ok(frame) => ServerOutput {
                frame,
                close_connection,
            },
            Err(error) => self.error_output(RequestId::new(), error, true),
        }
    }

    fn error_output(
        &mut self,
        request_id: RequestId,
        error: ConnectorError,
        close_connection: bool,
    ) -> ServerOutput {
        if close_connection {
            self.state = ConnectionState::Closed;
        }
        let envelope = ServerEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            message: ServerMessage::Error(ErrorResponse::from_error(&error)),
        };
        let frame = envelope
            .to_frame(&self.codec)
            .unwrap_or_else(|_| Vec::new());
        ServerOutput {
            frame,
            close_connection,
        }
    }
}

fn append_start_field(output: &mut Vec<u8>, field: &[u8]) -> ConnectorResult<()> {
    let length = u32::try_from(field.len()).map_err(|_| ConnectorError::InvalidMessage)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

const fn capability_wire_name(capability: Capability) -> &'static [u8] {
    match capability {
        Capability::ReadWalletInfo => b"read_wallet_info",
        Capability::ReadBalance => b"read_balance",
        Capability::CreatePaymentIntent => b"create_payment_intent",
        Capability::ReadOwnOperationStatus => b"read_own_operation_status",
        Capability::ListOwnOperations => b"list_own_operations",
        Capability::CancelOwnUnsignedOperation => b"cancel_own_unsigned_operation",
    }
}
