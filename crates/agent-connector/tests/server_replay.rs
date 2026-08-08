use std::cell::Cell;

use async_trait::async_trait;

use hpay_agent_connector::{
    AgentBackend, AgentId, AgentIdentityKey, AgentRequest, AgentResponse, AgentWalletId,
    AuthenticationStart, Capability, ClientEnvelope, ClientMessage, ConnectionPhase,
    ConnectionServer, ConnectorError, ConnectorResult, FrameCodec, OperationId, PairedAgent,
    PairingBearer, PairingRequest, PairingSession, ProtocolEnvelope, RequestId, ServerEnvelope,
    ServerIdentityKey, ServerMessage, SessionId, TransportBinding, VerifiedAgentRequest,
    WalletScope, verify_server_challenge,
};

struct TestBackend {
    paired: PairedAgent,
    calls: Cell<usize>,
    invalid_response: bool,
}

#[async_trait]
impl AgentBackend for TestBackend {
    async fn paired_agent(
        &mut self,
        agent_id: &AgentId,
        wallet_id: &AgentWalletId,
    ) -> ConnectorResult<PairedAgent> {
        if &self.paired.agent_id == agent_id && &self.paired.wallet_id == wallet_id {
            Ok(self.paired.clone())
        } else {
            Err(ConnectorError::AuthenticationFailed)
        }
    }

    async fn dispatch(&mut self, _request: VerifiedAgentRequest) -> ConnectorResult<AgentResponse> {
        self.calls.set(self.calls.get() + 1);
        if self.invalid_response {
            return Ok(AgentResponse::Operations {
                operation_ids: (0..101).map(|_| OperationId::new()).collect(),
                next_cursor: None,
            });
        }
        Ok(AgentResponse::Balance {
            available_units: 10,
            reserved_units: 1,
        })
    }
}

fn fixture() -> (AgentIdentityKey, ServerIdentityKey, PairedAgent) {
    let key = AgentIdentityKey::generate();
    let server_key = ServerIdentityKey::generate();
    let pinned = server_key
        .pinned_identity(format!("desktop_{}", uuid::Uuid::new_v4().simple()))
        .unwrap();
    let wallet_id = AgentWalletId::new();
    let capabilities = [Capability::ReadBalance].into_iter().collect();
    let mut pairing = PairingSession::activate(wallet_id, pinned, 100, 60, 2).unwrap();
    let pending = pairing
        .submit(
            101,
            PairingRequest {
                pairing_id: PairingBearer::parse(pairing.pairing_id().to_owned()).unwrap(),
                agent_name: "Replay Test".to_owned(),
                agent_version: "1".to_owned(),
                identity_public_key_sec1_hex: key.public_key_sec1_hex(),
                requested_capabilities: capabilities,
            },
        )
        .unwrap();
    let paired = pairing
        .approve(
            102,
            &pending.submission_commitment,
            [Capability::ReadBalance].into_iter().collect(),
        )
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

fn client_frame(codec: &FrameCodec, message: ClientMessage) -> Vec<u8> {
    ClientEnvelope::new(RequestId::new(), message)
        .to_frame(codec)
        .unwrap()
}

async fn authenticated_server<'a>(
    key: &AgentIdentityKey,
    server_key: &'a ServerIdentityKey,
    backend: &mut TestBackend,
) -> (ConnectionServer<'a>, SessionId) {
    let paired = backend.paired.clone();
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let start = AuthenticationStart {
        agent_id: paired.agent_id.clone(),
        wallet_id: paired.wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&paired.wallet_id),
        sequence: 1,
        nonce: hpay_agent_connector::Nonce::random(),
        issued_at_unix: 200,
        expires_at_unix: 230,
        requested_capabilities: [Capability::ReadBalance].into_iter().collect(),
    };
    let start_hash = start.canonical_sha256_hex().unwrap();
    let frame = client_frame(server.codec(), ClientMessage::AuthenticationStart(start));
    let output = server.handle_frame(&frame, 201, backend).await;
    let challenge = match ServerEnvelope::from_frame(server.codec(), &output.frame)
        .unwrap()
        .message
    {
        ServerMessage::AuthenticationChallenge(challenge) => challenge,
        other => panic!("unexpected message: {other:?}"),
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
    let frame = client_frame(
        server.codec(),
        ClientMessage::AuthenticationResponse(response),
    );
    let output = server.handle_frame(&frame, 202, backend).await;
    assert!(!output.close_connection);
    let authenticated = ServerEnvelope::from_frame(server.codec(), &output.frame).unwrap();
    assert!(matches!(
        authenticated.message,
        ServerMessage::Authenticated { .. }
    ));
    (server, session_id)
}

#[tokio::test]
async fn duplicate_request_is_dispatched_once_then_closes_session() {
    let (key, server_key, paired) = fixture();
    let mut backend = TestBackend {
        paired: paired.clone(),
        calls: Cell::new(0),
        invalid_response: false,
    };
    let (mut server, session_id) = authenticated_server(&key, &server_key, &mut backend).await;
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
    let frame = client_frame(server.codec(), ClientMessage::Request(Box::new(request)));
    let first = server.handle_frame(&frame, 204, &mut backend).await;
    assert!(!first.close_connection);
    assert_eq!(backend.calls.get(), 1);

    let replay = server.handle_frame(&frame, 205, &mut backend).await;
    assert!(replay.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Closed);
    assert_eq!(backend.calls.get(), 1);
    assert!(matches!(
        ServerEnvelope::from_frame(server.codec(), &replay.frame)
            .unwrap()
            .message,
        ServerMessage::Error(_)
    ));
}

#[tokio::test]
async fn explicit_disconnect_closes_and_session_cannot_be_reused() {
    let (key, server_key, paired) = fixture();
    let mut backend = TestBackend {
        paired: paired.clone(),
        calls: Cell::new(0),
        invalid_response: false,
    };
    let (mut server, _) = authenticated_server(&key, &server_key, &mut backend).await;
    let disconnect = client_frame(server.codec(), ClientMessage::Disconnect);
    let output = server.handle_frame(&disconnect, 203, &mut backend).await;
    assert!(output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Closed);
    assert!(matches!(
        ServerEnvelope::from_frame(server.codec(), &output.frame)
            .unwrap()
            .message,
        ServerMessage::Disconnected
    ));

    let second = server.handle_frame(&disconnect, 204, &mut backend).await;
    assert!(second.close_connection);
    assert!(matches!(
        ServerEnvelope::from_frame(server.codec(), &second.frame)
            .unwrap()
            .message,
        ServerMessage::Error(_)
    ));
}

#[tokio::test]
async fn backend_cannot_emit_an_invalid_typed_response() {
    let (key, server_key, paired) = fixture();
    let mut backend = TestBackend {
        paired: paired.clone(),
        calls: Cell::new(0),
        invalid_response: true,
    };
    let (mut server, session_id) = authenticated_server(&key, &server_key, &mut backend).await;
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
    let frame = client_frame(server.codec(), ClientMessage::Request(Box::new(request)));
    let output = server.handle_frame(&frame, 204, &mut backend).await;
    assert!(output.close_connection);
    assert_eq!(server.phase(), ConnectionPhase::Closed);
    assert!(matches!(
        ServerEnvelope::from_frame(server.codec(), &output.frame)
            .unwrap()
            .message,
        ServerMessage::Error(_)
    ));
}

#[tokio::test]
async fn unknown_fields_and_authentication_at_expiry_are_rejected() {
    let (key, server_key, paired) = fixture();
    let mut backend = TestBackend {
        paired: paired.clone(),
        calls: Cell::new(0),
        invalid_response: false,
    };
    let mut server = ConnectionServer::new(
        paired.server_identity.desktop_instance_id.clone(),
        &server_key,
        transport_binding(),
        64 * 1024,
    )
    .unwrap();
    let start = AuthenticationStart {
        agent_id: paired.agent_id.clone(),
        wallet_id: paired.wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&paired.wallet_id),
        sequence: 1,
        nonce: hpay_agent_connector::Nonce::random(),
        issued_at_unix: 200,
        expires_at_unix: 230,
        requested_capabilities: [Capability::ReadBalance].into_iter().collect(),
    };
    let start_hash = start.canonical_sha256_hex().unwrap();
    let frame = client_frame(server.codec(), ClientMessage::AuthenticationStart(start));
    let output = server.handle_frame(&frame, 201, &mut backend).await;
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
    let response = key.sign_verified_challenge(&verified).unwrap();
    let frame = client_frame(
        server.codec(),
        ClientMessage::AuthenticationResponse(response),
    );
    let output = server
        .handle_frame(&frame, challenge.expires_at_unix, &mut backend)
        .await;
    assert!(output.close_connection);

    let valid = ClientEnvelope::new(RequestId::new(), ClientMessage::Disconnect);
    let mut json = serde_json::to_value(valid).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("raw_command".to_owned(), serde_json::json!("sign"));
    let payload = serde_json::to_vec(&json).unwrap();
    let framed = FrameCodec::default().encode(&payload).unwrap();
    assert!(ClientEnvelope::from_frame(&FrameCodec::default(), &framed, 201).is_err());
}
