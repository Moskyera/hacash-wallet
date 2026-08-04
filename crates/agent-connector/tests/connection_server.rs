use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;

use hpay_agent_connector::{
    AgentBackend, AgentId, AgentIdentityKey, AgentRequest, AgentResponse, AgentWalletId,
    AuthenticationStart, Capability, ClientEnvelope, ClientMessage, ConnectionPhase,
    ConnectionServer, ConnectorError, ConnectorResult, FrameCodec, PairedAgent, PairingBearer,
    PairingRequest, PairingSession, ProtocolEnvelope, RequestId, ServerEnvelope, ServerIdentityKey,
    ServerMessage, TransportBinding, VerifiedAgentRequest, WalletScope, verify_server_challenge,
};

#[derive(Default)]
struct Registry {
    agents: BTreeMap<(AgentId, AgentWalletId), PairedAgent>,
}

impl Registry {
    fn insert(&mut self, paired: PairedAgent) {
        self.agents
            .insert((paired.agent_id.clone(), paired.wallet_id.clone()), paired);
    }

    fn get_mut(&mut self, agent_id: &AgentId, wallet_id: &AgentWalletId) -> &mut PairedAgent {
        self.agents
            .get_mut(&(agent_id.clone(), wallet_id.clone()))
            .unwrap()
    }
}

struct DispatchSnapshot {
    connection_request_id: RequestId,
    protocol_request_id: RequestId,
    agent_id: AgentId,
    wallet_id: AgentWalletId,
    identity_key_sha256: String,
    request: AgentRequest,
}

#[derive(Default)]
struct TestBackend {
    registry: Registry,
    calls: Cell<usize>,
    last_verified: Option<DispatchSnapshot>,
}

#[async_trait]
impl AgentBackend for TestBackend {
    async fn paired_agent(
        &mut self,
        agent_id: &AgentId,
        wallet_id: &AgentWalletId,
    ) -> ConnectorResult<PairedAgent> {
        tokio::task::yield_now().await;
        self.registry
            .agents
            .get(&(agent_id.clone(), wallet_id.clone()))
            .cloned()
            .ok_or(ConnectorError::AuthenticationFailed)
    }

    async fn dispatch(&mut self, verified: VerifiedAgentRequest) -> ConnectorResult<AgentResponse> {
        tokio::task::yield_now().await;
        self.calls.set(self.calls.get() + 1);
        self.last_verified = Some(DispatchSnapshot {
            connection_request_id: verified.connection_request_id().clone(),
            protocol_request_id: verified.protocol_request_id().clone(),
            agent_id: verified.agent_id().clone(),
            wallet_id: verified.wallet_id().clone(),
            identity_key_sha256: verified.identity_key_sha256().to_owned(),
            request: verified.request().clone(),
        });
        match verified.request() {
            AgentRequest::GetBalance => Ok(AgentResponse::Balance {
                available_units: 500,
                reserved_units: 25,
            }),
            _ => Err(ConnectorError::CapabilityDenied),
        }
    }
}

fn paired_fixture(
    capabilities: BTreeSet<Capability>,
) -> (AgentIdentityKey, ServerIdentityKey, PairedAgent) {
    let key = AgentIdentityKey::generate();
    let server_key = ServerIdentityKey::generate();
    let pinned = server_key
        .pinned_identity(format!("desktop_{}", uuid::Uuid::new_v4().simple()))
        .unwrap();
    let wallet_id = AgentWalletId::new();
    let mut pairing = PairingSession::activate(wallet_id, pinned, 100, 60, 2).unwrap();
    let request = PairingRequest {
        pairing_id: PairingBearer::parse(pairing.pairing_id().to_owned()).unwrap(),
        agent_name: "Test Agent".to_owned(),
        agent_version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: key.public_key_sec1_hex(),
        requested_capabilities: capabilities.clone(),
    };
    let pending = pairing.submit(101, request).unwrap();
    let paired = pairing
        .approve(102, &pending.submission_commitment, capabilities)
        .unwrap();
    (key, server_key, paired)
}

fn transport_binding() -> TransportBinding {
    TransportBinding {
        binding_version: 1,
        transport_kind: "local_ipc".to_owned(),
        connection_id: hpay_agent_connector::Nonce::random(),
        peer_identity_sha256: "ab".repeat(32),
        transport_transcript_sha256: "cd".repeat(32),
    }
}
fn start(paired: &PairedAgent, capabilities: BTreeSet<Capability>) -> AuthenticationStart {
    AuthenticationStart {
        agent_id: paired.agent_id.clone(),
        wallet_id: paired.wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&paired.wallet_id),
        sequence: 1,
        nonce: hpay_agent_connector::Nonce::random(),
        issued_at_unix: 200,
        expires_at_unix: 230,
        requested_capabilities: capabilities,
    }
}

fn frame(codec: &FrameCodec, message: ClientMessage) -> Vec<u8> {
    ClientEnvelope::new(RequestId::new(), message)
        .to_frame(codec)
        .unwrap()
}

async fn authenticate(
    server: &mut ConnectionServer<'_>,
    key: &AgentIdentityKey,
    paired: &PairedAgent,
    backend: &mut TestBackend,
) -> hpay_agent_connector::SessionId {
    let capabilities = [Capability::ReadBalance].into_iter().collect();
    let authentication_start = start(paired, capabilities);
    let start_hash = authentication_start.canonical_sha256_hex().unwrap();
    let request = frame(
        server.codec(),
        ClientMessage::AuthenticationStart(authentication_start),
    );
    let output = server.handle_frame(&request, 201, backend).await;
    assert!(!output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::ChallengeIssued);
    let challenge = match ServerEnvelope::from_frame(server.codec(), &output.frame)
        .unwrap()
        .message
    {
        ServerMessage::AuthenticationChallenge(challenge) => challenge,
        other => panic!("unexpected challenge response: {other:?}"),
    };
    let verified = verify_server_challenge(
        &challenge,
        &paired.server_identity,
        server.transport_binding(),
        &start_hash,
        202,
    )
    .unwrap();
    let response = key.sign_verified_challenge(&verified).unwrap();
    let session_id = response.session_id.clone();
    let request = frame(
        server.codec(),
        ClientMessage::AuthenticationResponse(response),
    );
    let output = server.handle_frame(&request, 202, backend).await;
    assert!(!output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Authenticated);
    session_id
}

#[tokio::test]
async fn full_connection_flow_dispatches_only_typed_authorized_request() {
    let (key, server_key, paired) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let mut backend = TestBackend::default();
    backend.registry.insert(paired.clone());
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let session_id = authenticate(&mut server, &key, &paired, &mut backend).await;

    let request = ProtocolEnvelope::request(
        paired.agent_id.clone(),
        paired.wallet_id.clone(),
        session_id,
        1,
        203,
        220,
        AgentRequest::GetBalance,
    )
    .unwrap();
    let request_id = RequestId::new();
    let output = server
        .handle_frame(
            &ClientEnvelope::new(
                request_id.clone(),
                ClientMessage::Request(Box::new(request)),
            )
            .to_frame(server.codec())
            .unwrap(),
            204,
            &mut backend,
        )
        .await;
    assert!(!output.close_connection);
    assert_eq!(backend.calls.get(), 1);
    let response = ServerEnvelope::from_frame(server.codec(), &output.frame).unwrap();
    assert_eq!(response.request_id, request_id);
    assert!(matches!(
        response.message,
        ServerMessage::Response(AgentResponse::Balance {
            available_units: 500,
            reserved_units: 25
        })
    ));
    let verified = backend.last_verified.as_ref().unwrap();
    assert_eq!(verified.connection_request_id, request_id);
    assert_eq!(verified.agent_id, paired.agent_id);
    assert_eq!(verified.wallet_id, paired.wallet_id);
    assert_eq!(
        verified.identity_key_sha256,
        paired.identity_key_sha256().unwrap()
    );
    assert_eq!(verified.identity_key_sha256.len(), 64);
    assert!(
        verified
            .identity_key_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert!(matches!(verified.request, AgentRequest::GetBalance));
    assert_ne!(verified.connection_request_id, verified.protocol_request_id);
}

#[tokio::test]
async fn request_before_authentication_closes_connection() {
    let (_, server_key, paired) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let mut backend = TestBackend::default();
    backend.registry.insert(paired.clone());
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let unauthenticated = ProtocolEnvelope::request(
        paired.agent_id,
        paired.wallet_id,
        hpay_agent_connector::SessionId::new(),
        1,
        200,
        220,
        AgentRequest::GetBalance,
    )
    .unwrap();
    let output = server
        .handle_frame(
            &frame(
                server.codec(),
                ClientMessage::Request(Box::new(unauthenticated)),
            ),
            201,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Closed);
    assert_eq!(backend.calls.get(), 0);
}

#[tokio::test]
async fn wrong_signature_and_expired_start_are_single_attempt_failures() {
    let (_, server_key, paired) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let (wrong_key, _, _) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let mut backend = TestBackend::default();
    backend.registry.insert(paired.clone());
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let authentication_start = start(&paired, [Capability::ReadBalance].into_iter().collect());
    let start_hash = authentication_start.canonical_sha256_hex().unwrap();
    let output = server
        .handle_frame(
            &frame(
                server.codec(),
                ClientMessage::AuthenticationStart(authentication_start),
            ),
            201,
            &mut backend,
        )
        .await;
    let challenge = match ServerEnvelope::from_frame(server.codec(), &output.frame)
        .unwrap()
        .message
    {
        ServerMessage::AuthenticationChallenge(challenge) => challenge,
        _ => panic!("challenge expected"),
    };
    let verified = verify_server_challenge(
        &challenge,
        &paired.server_identity,
        server.transport_binding(),
        &start_hash,
        202,
    )
    .unwrap();
    let wrong = wrong_key.sign_verified_challenge(&verified).unwrap();
    let output = server
        .handle_frame(
            &frame(server.codec(), ClientMessage::AuthenticationResponse(wrong)),
            202,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Closed);

    let mut expired_server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let output = expired_server
        .handle_frame(
            &frame(
                expired_server.codec(),
                ClientMessage::AuthenticationStart(start(
                    &paired,
                    [Capability::ReadBalance].into_iter().collect(),
                )),
            ),
            231,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);
    assert_eq!(expired_server.phase(), ConnectionPhase::Closed);
}

#[tokio::test]
async fn cross_wallet_capability_escalation_and_oversized_frame_fail_closed() {
    let (_, server_key, paired) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let mut backend = TestBackend::default();
    backend.registry.insert(paired.clone());

    let mut cross_wallet = start(&paired, [Capability::ReadBalance].into_iter().collect());
    cross_wallet.wallet_id = AgentWalletId::new();
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        1024,
    )
    .unwrap();
    let output = server
        .handle_frame(
            &frame(
                server.codec(),
                ClientMessage::AuthenticationStart(cross_wallet),
            ),
            201,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);

    let mut escalation = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        1024,
    )
    .unwrap();
    let output = escalation
        .handle_frame(
            &frame(
                escalation.codec(),
                ClientMessage::AuthenticationStart(start(
                    &paired,
                    [Capability::CreatePaymentIntent].into_iter().collect(),
                )),
            ),
            201,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);

    let mut oversized = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        1024,
    )
    .unwrap();
    let output = oversized
        .handle_frame(&vec![0xff; 2048], 201, &mut backend)
        .await;
    assert!(output.close_connection);
    assert_eq!(oversized.phase(), ConnectionPhase::Closed);
}

#[tokio::test]
async fn revoked_registry_epoch_invalidates_authenticated_connection() {
    let (key, server_key, paired) = paired_fixture([Capability::ReadBalance].into_iter().collect());
    let mut backend = TestBackend::default();
    backend.registry.insert(paired.clone());
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let session_id = authenticate(&mut server, &key, &paired, &mut backend).await;
    let current = backend
        .registry
        .get_mut(&paired.agent_id, &paired.wallet_id);
    current.authorization_epoch += 1;

    let request = ProtocolEnvelope::request(
        paired.agent_id.clone(),
        paired.wallet_id.clone(),
        session_id,
        1,
        203,
        220,
        AgentRequest::GetBalance,
    )
    .unwrap();
    let output = server
        .handle_frame(
            &frame(server.codec(), ClientMessage::Request(Box::new(request))),
            204,
            &mut backend,
        )
        .await;
    assert!(output.close_connection);
    assert_eq!(backend.calls.get(), 0);
}
