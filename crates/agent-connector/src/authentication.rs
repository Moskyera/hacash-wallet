use std::collections::BTreeSet;

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, ConnectorResult};
use crate::pairing::{
    PairedAgent, PairedAgentStatus, PinnedServerIdentity, ServerIdentityKey, parse_verifying_key,
};
use crate::protocol::{AgentId, AgentWalletId, Nonce, PROTOCOL_VERSION, SessionId, WalletScope};
use crate::session::{Capability, CapabilitySession, validate_desktop_instance_id};

pub const MAX_CHALLENGE_TTL_SECS: u64 = 60;
pub const AUTHENTICATED_SESSION_TTL_SECS: u64 = 15 * 60;
const LOCAL_TRANSPORT_BINDING_DOMAIN: &[u8] = b"HPAY/LOCAL-TRANSPORT-BINDING/V1";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportBinding {
    pub binding_version: u16,
    pub transport_kind: String,
    pub connection_id: Nonce,
    pub peer_identity_sha256: String,
    pub transport_transcript_sha256: String,
}

impl TransportBinding {
    /// Constructs the one canonical binding used by both ends of a local
    /// connection. The transcript commits to the endpoint, fresh connection
    /// nonce and OS-authenticated peer identity; no static fallback exists.
    pub fn for_local_transport(
        transport_kind: &str,
        endpoint: &str,
        connection_id: Nonce,
        peer_identity_sha256: &str,
    ) -> ConnectorResult<Self> {
        if endpoint.is_empty() || endpoint.len() > 1024 || endpoint.chars().any(char::is_control) {
            return Err(ConnectorError::SessionMismatch);
        }
        connection_id.validate()?;
        let mut canonical = Vec::with_capacity(256 + endpoint.len());
        append_field(&mut canonical, LOCAL_TRANSPORT_BINDING_DOMAIN)?;
        append_field(&mut canonical, transport_kind.as_bytes())?;
        append_field(&mut canonical, endpoint.as_bytes())?;
        append_field(&mut canonical, connection_id.as_str().as_bytes())?;
        append_field(&mut canonical, peer_identity_sha256.as_bytes())?;
        let binding = Self {
            binding_version: 1,
            transport_kind: transport_kind.to_owned(),
            connection_id,
            peer_identity_sha256: peer_identity_sha256.to_owned(),
            transport_transcript_sha256: hex::encode(Sha256::digest(canonical)),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> ConnectorResult<()> {
        self.connection_id.validate()?;
        if self.binding_version != 1
            || self.transport_kind.is_empty()
            || self.transport_kind.len() > 32
            || !self.transport_kind.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || !is_sha256_hex(&self.peer_identity_sha256)
            || !is_sha256_hex(&self.transport_transcript_sha256)
        {
            return Err(ConnectorError::SessionMismatch);
        }
        Ok(())
    }
}

pub struct VerifiedServerChallenge<'a> {
    payload: &'a ChallengePayload,
}

impl<'a> VerifiedServerChallenge<'a> {
    pub(crate) const fn payload(&self) -> &'a ChallengePayload {
        self.payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Active,
    Consumed,
}

/// Public, serializable challenge fields sent over the framed protocol.
///
/// This object contains no server-side liveness state. Deserializing it can
/// never create or reactivate a usable challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengePayload {
    pub protocol_version: u16,
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub wallet_scope: WalletScope,
    pub desktop_instance_id: String,
    pub session_id: SessionId,
    pub nonce: Nonce,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub authorization_epoch: u64,
    pub requested_capabilities: BTreeSet<Capability>,
    pub server_identity: PinnedServerIdentity,
    pub transport_binding: TransportBinding,
    pub authentication_start_sha256: String,
    pub server_signature_der_hex: String,
}

impl ChallengePayload {
    fn validate_unsigned_shape(&self) -> ConnectorResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        validate_desktop_instance_id(&self.desktop_instance_id)?;
        self.session_id.validate()?;
        self.nonce.validate()?;
        self.server_identity.validate()?;
        self.transport_binding.validate()?;
        if self.server_identity.desktop_instance_id != self.desktop_instance_id
            || !is_sha256_hex(&self.authentication_start_sha256)
            || self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix - self.issued_at_unix > MAX_CHALLENGE_TTL_SECS
            || self.authorization_epoch == 0
            || self.requested_capabilities.is_empty()
        {
            return Err(ConnectorError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> ConnectorResult<()> {
        self.validate_unsigned_shape()?;
        validate_der_signature_hex(&self.server_signature_der_hex)
    }

    pub fn canonical_signing_bytes(&self) -> ConnectorResult<Vec<u8>> {
        self.validate_unsigned_shape()?;
        let mut output = Vec::with_capacity(1024);
        append_field(&mut output, b"HPAY/AGENT-AUTH/CHALLENGE/V2")?;
        append_field(&mut output, &self.protocol_version.to_be_bytes())?;
        append_field(&mut output, self.agent_id.as_str().as_bytes())?;
        append_field(&mut output, self.wallet_id.as_str().as_bytes())?;
        append_field(&mut output, self.wallet_scope.as_str().as_bytes())?;
        append_field(&mut output, self.desktop_instance_id.as_bytes())?;
        append_field(&mut output, self.session_id.as_str().as_bytes())?;
        append_field(&mut output, self.nonce.as_str().as_bytes())?;
        append_field(&mut output, &self.issued_at_unix.to_be_bytes())?;
        append_field(&mut output, &self.expires_at_unix.to_be_bytes())?;
        append_field(&mut output, &self.authorization_epoch.to_be_bytes())?;
        for capability in &self.requested_capabilities {
            append_field(&mut output, capability_name(*capability))?;
        }
        append_field(
            &mut output,
            self.server_identity.desktop_instance_id.as_bytes(),
        )?;
        append_field(
            &mut output,
            self.server_identity.identity_public_key_sec1_hex.as_bytes(),
        )?;
        append_field(
            &mut output,
            self.server_identity.identity_fingerprint.as_bytes(),
        )?;
        append_field(
            &mut output,
            &self.transport_binding.binding_version.to_be_bytes(),
        )?;
        append_field(
            &mut output,
            self.transport_binding.transport_kind.as_bytes(),
        )?;
        append_field(
            &mut output,
            self.transport_binding.connection_id.as_str().as_bytes(),
        )?;
        append_field(
            &mut output,
            self.transport_binding.peer_identity_sha256.as_bytes(),
        )?;
        append_field(
            &mut output,
            self.transport_binding
                .transport_transcript_sha256
                .as_bytes(),
        )?;
        append_field(&mut output, self.authentication_start_sha256.as_bytes())?;
        Ok(output)
    }
}

pub fn verify_server_challenge<'a>(
    challenge: &'a ChallengePayload,
    pinned_server: &PinnedServerIdentity,
    expected_transport_binding: &TransportBinding,
    expected_authentication_start_sha256: &str,
    now_unix: u64,
) -> ConnectorResult<VerifiedServerChallenge<'a>> {
    challenge.validate_shape()?;
    pinned_server.validate()?;
    expected_transport_binding.validate()?;
    if &challenge.server_identity != pinned_server
        || &challenge.transport_binding != expected_transport_binding
        || challenge.authentication_start_sha256 != expected_authentication_start_sha256
        || now_unix < challenge.issued_at_unix
        || now_unix >= challenge.expires_at_unix
    {
        return Err(ConnectorError::AuthenticationFailed);
    }
    let signature_bytes = hex::decode(&challenge.server_signature_der_hex)
        .map_err(|_| ConnectorError::AuthenticationFailed)?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| ConnectorError::AuthenticationFailed)?;
    parse_verifying_key(&pinned_server.identity_public_key_sec1_hex)?
        .verify(&challenge.canonical_signing_bytes()?, &signature)
        .map_err(|_| ConnectorError::AuthenticationFailed)?;
    Ok(VerifiedServerChallenge { payload: challenge })
}
/// Server-only single-use challenge state.
///
/// This type intentionally implements neither `Debug`, `Clone`, `Serialize`
/// nor `Deserialize`. Only its public [`ChallengePayload`] may cross IPC.
pub struct AuthenticationChallenge {
    payload: ChallengePayload,
    state: ChallengeState,
}

pub struct AuthenticationChallengeContext<'a> {
    pub server_identity_key: &'a ServerIdentityKey,
    pub desktop_instance_id: String,
    pub transport_binding: TransportBinding,
    pub authentication_start_sha256: String,
    pub now_unix: u64,
    pub ttl_secs: u64,
}

impl AuthenticationChallenge {
    pub fn issue(
        paired: &PairedAgent,
        context: AuthenticationChallengeContext<'_>,
        requested_capabilities: BTreeSet<Capability>,
    ) -> ConnectorResult<Self> {
        let AuthenticationChallengeContext {
            server_identity_key,
            desktop_instance_id,
            transport_binding,
            authentication_start_sha256,
            now_unix,
            ttl_secs,
        } = context;
        paired.ensure_active()?;
        validate_desktop_instance_id(&desktop_instance_id)?;
        transport_binding.validate()?;
        if !is_sha256_hex(&authentication_start_sha256) {
            return Err(ConnectorError::SessionMismatch);
        }
        let server_identity = server_identity_key.pinned_identity(desktop_instance_id.clone())?;
        if server_identity != paired.server_identity {
            return Err(ConnectorError::AuthenticationFailed);
        }
        if now_unix == 0
            || ttl_secs == 0
            || ttl_secs > MAX_CHALLENGE_TTL_SECS
            || requested_capabilities.is_empty()
            || !requested_capabilities.is_subset(&paired.capabilities)
        {
            return Err(ConnectorError::CapabilityDenied);
        }
        let expires_at_unix = now_unix
            .checked_add(ttl_secs)
            .ok_or(ConnectorError::InvalidTimeWindow)?;
        let mut payload = ChallengePayload {
            protocol_version: PROTOCOL_VERSION,
            agent_id: paired.agent_id.clone(),
            wallet_id: paired.wallet_id.clone(),
            wallet_scope: paired.wallet_scope.clone(),
            desktop_instance_id,
            session_id: SessionId::new(),
            nonce: Nonce::random(),
            issued_at_unix: now_unix,
            expires_at_unix,
            authorization_epoch: paired.authorization_epoch,
            requested_capabilities,
            server_identity,
            transport_binding,
            authentication_start_sha256,
            server_signature_der_hex: String::new(),
        };
        payload.server_signature_der_hex =
            server_identity_key.sign_der_hex(&payload.canonical_signing_bytes()?);
        payload.validate_shape()?;
        Ok(Self {
            payload,
            state: ChallengeState::Active,
        })
    }
    pub const fn state(&self) -> ChallengeState {
        self.state
    }

    pub const fn payload(&self) -> &ChallengePayload {
        &self.payload
    }

    pub fn canonical_signing_bytes(&self) -> ConnectorResult<Vec<u8>> {
        self.payload.canonical_signing_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationResponse {
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub session_id: SessionId,
    pub challenge_nonce: Nonce,
    pub signature_der_hex: String,
}

impl AuthenticationResponse {
    pub fn validate_shape(&self) -> ConnectorResult<()> {
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.session_id.validate()?;
        self.challenge_nonce.validate()?;
        if self.signature_der_hex.len() > 160
            || self.signature_der_hex.len() < 128
            || !self
                .signature_der_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConnectorError::AuthenticationFailed);
        }
        Ok(())
    }
}

pub fn authenticate_response(
    challenge: &mut AuthenticationChallenge,
    response: &AuthenticationResponse,
    paired: &PairedAgent,
    now_unix: u64,
) -> ConnectorResult<CapabilitySession> {
    if challenge.state != ChallengeState::Active {
        return Err(ConnectorError::ReplayDetected);
    }
    challenge.state = ChallengeState::Consumed;
    paired.ensure_active()?;
    response.validate_shape()?;
    let payload = &challenge.payload;
    if paired.status != PairedAgentStatus::Active
        || paired.agent_id != payload.agent_id
        || paired.wallet_id != payload.wallet_id
        || paired.authorization_epoch != payload.authorization_epoch
        || response.agent_id != payload.agent_id
        || response.wallet_id != payload.wallet_id
        || response.session_id != payload.session_id
        || response.challenge_nonce != payload.nonce
    {
        return Err(ConnectorError::SessionMismatch);
    }
    if now_unix < payload.issued_at_unix || now_unix >= payload.expires_at_unix {
        return Err(ConnectorError::Expired);
    }
    if !payload
        .requested_capabilities
        .is_subset(&paired.capabilities)
    {
        return Err(ConnectorError::CapabilityDenied);
    }
    let signature_bytes = hex::decode(&response.signature_der_hex)
        .map_err(|_| ConnectorError::AuthenticationFailed)?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| ConnectorError::AuthenticationFailed)?;
    let canonical = payload.canonical_signing_bytes()?;
    paired
        .verifying_key()?
        .verify(&canonical, &signature)
        .map_err(|_| ConnectorError::AuthenticationFailed)?;

    CapabilitySession::new(
        paired.agent_id.clone(),
        paired.wallet_id.clone(),
        payload.desktop_instance_id.clone(),
        payload.session_id.clone(),
        payload.requested_capabilities.clone(),
        payload.authorization_epoch,
        now_unix,
        now_unix
            .checked_add(AUTHENTICATED_SESSION_TTL_SECS)
            .ok_or(ConnectorError::InvalidTimeWindow)?,
        1,
    )
}

fn validate_der_signature_hex(value: &str) -> ConnectorResult<()> {
    if value.len() < 128 || value.len() > 160 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConnectorError::AuthenticationFailed);
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn append_field(output: &mut Vec<u8>, field: &[u8]) -> ConnectorResult<()> {
    let length = u32::try_from(field.len()).map_err(|_| ConnectorError::InvalidMessage)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

const fn capability_name(capability: Capability) -> &'static [u8] {
    match capability {
        Capability::ReadWalletInfo => b"read_wallet_info",
        Capability::ReadBalance => b"read_balance",
        Capability::CreatePaymentIntent => b"create_payment_intent",
        Capability::ReadOwnOperationStatus => b"read_own_operation_status",
        Capability::ListOwnOperations => b"list_own_operations",
        Capability::CancelOwnUnsignedOperation => b"cancel_own_unsigned_operation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::{AgentIdentityKey, PairingRequest, PairingSession, ServerIdentityKey};
    use crate::protocol::{MessageType, ProtocolEnvelope, WireMessage};
    use sha2::{Digest, Sha256};

    #[test]
    fn canonical_local_binding_has_server_client_parity_and_binds_every_context_field() {
        let connection_id = Nonce::random();
        let peer = "ab".repeat(32);
        let expected = TransportBinding::for_local_transport(
            "windows_named_pipe",
            r"\\.\pipe\hpay-agent-v1-test",
            connection_id.clone(),
            &peer,
        )
        .unwrap();
        assert_eq!(
            expected,
            TransportBinding::for_local_transport(
                "windows_named_pipe",
                r"\\.\pipe\hpay-agent-v1-test",
                connection_id.clone(),
                &peer,
            )
            .unwrap()
        );

        for changed in [
            TransportBinding::for_local_transport(
                "unix_domain_socket",
                r"\\.\pipe\hpay-agent-v1-test",
                connection_id.clone(),
                &peer,
            )
            .unwrap(),
            TransportBinding::for_local_transport(
                "windows_named_pipe",
                r"\\.\pipe\hpay-agent-v1-other",
                connection_id.clone(),
                &peer,
            )
            .unwrap(),
            TransportBinding::for_local_transport(
                "windows_named_pipe",
                r"\\.\pipe\hpay-agent-v1-test",
                Nonce::random(),
                &peer,
            )
            .unwrap(),
            TransportBinding::for_local_transport(
                "windows_named_pipe",
                r"\\.\pipe\hpay-agent-v1-test",
                connection_id.clone(),
                &"cd".repeat(32),
            )
            .unwrap(),
        ] {
            assert_ne!(
                changed.transport_transcript_sha256,
                expected.transport_transcript_sha256
            );
        }
        assert!(
            TransportBinding::for_local_transport("windows_named_pipe", "", connection_id, &peer,)
                .is_err()
        );
    }

    fn binding(label: &[u8]) -> TransportBinding {
        TransportBinding {
            binding_version: 1,
            transport_kind: "local_ipc".into(),
            connection_id: Nonce::random(),
            peer_identity_sha256: hex::encode(Sha256::digest([label, b"peer"].concat())),
            transport_transcript_sha256: hex::encode(Sha256::digest(
                [label, b"transcript"].concat(),
            )),
        }
    }

    fn paired_identity() -> (AgentIdentityKey, ServerIdentityKey, PairedAgent) {
        let agent_key = AgentIdentityKey::generate();
        let server_key = ServerIdentityKey::generate();
        let desktop_id = format!("desktop_{}", uuid::Uuid::new_v4().simple());
        let pinned = server_key.pinned_identity(desktop_id).unwrap();
        let wallet_id = AgentWalletId::new();
        let mut pairing = PairingSession::activate(wallet_id, pinned, 100, 60, 2).unwrap();
        let request = PairingRequest {
            pairing_id: pairing.pairing_bearer_for_activation(),
            agent_name: "Test Agent".into(),
            agent_version: "1".into(),
            identity_public_key_sec1_hex: agent_key.public_key_sec1_hex(),
            requested_capabilities: [Capability::ReadBalance].into_iter().collect(),
        };
        let pending = pairing.submit(101, request).unwrap();
        let paired = pairing
            .approve(
                102,
                &pending.submission_commitment,
                [Capability::ReadBalance].into_iter().collect(),
            )
            .unwrap();
        (agent_key, server_key, paired)
    }

    fn issue(
        paired: &PairedAgent,
        server_key: &ServerIdentityKey,
        transport: TransportBinding,
        start_hash: &str,
        now: u64,
        ttl: u64,
    ) -> AuthenticationChallenge {
        AuthenticationChallenge::issue(
            paired,
            AuthenticationChallengeContext {
                server_identity_key: server_key,
                desktop_instance_id: paired.server_identity.desktop_instance_id.clone(),
                transport_binding: transport,
                authentication_start_sha256: start_hash.to_owned(),
                now_unix: now,
                ttl_secs: ttl,
            },
            [Capability::ReadBalance].into_iter().collect(),
        )
        .unwrap()
    }

    fn verified_response(
        agent_key: &AgentIdentityKey,
        challenge: &AuthenticationChallenge,
        paired: &PairedAgent,
        transport: &TransportBinding,
        start_hash: &str,
        now: u64,
    ) -> AuthenticationResponse {
        let verified = verify_server_challenge(
            challenge.payload(),
            &paired.server_identity,
            transport,
            start_hash,
            now,
        )
        .unwrap();
        agent_key.sign_verified_challenge(&verified).unwrap()
    }

    #[test]
    fn valid_mutual_challenge_response_creates_scoped_epoch_session() {
        let (agent_key, server_key, paired) = paired_identity();
        let transport = binding(b"valid");
        let start_hash = "ab".repeat(32);
        let mut challenge = issue(
            &paired,
            &server_key,
            transport.clone(),
            &start_hash,
            200,
            30,
        );
        let response = verified_response(
            &agent_key,
            &challenge,
            &paired,
            &transport,
            &start_hash,
            201,
        );
        let session = authenticate_response(&mut challenge, &response, &paired, 210).unwrap();
        assert_eq!(challenge.state(), ChallengeState::Consumed);
        assert_eq!(session.session_id(), &response.session_id);
        assert_eq!(session.authorization_epoch(), paired.authorization_epoch);
    }

    #[test]
    fn challenge_payload_roundtrips_without_server_liveness_state() {
        let (_, server_key, paired) = paired_identity();
        let challenge = issue(
            &paired,
            &server_key,
            binding(b"roundtrip"),
            &"cd".repeat(32),
            200,
            30,
        );
        let envelope = ProtocolEnvelope::authentication_challenge(challenge.payload().clone())
            .expect("valid challenge envelope");
        assert_eq!(envelope.message_type, MessageType::AuthenticationChallenge);
        let decoded =
            ProtocolEnvelope::from_json_bytes(&envelope.to_json_bytes().unwrap()).unwrap();
        assert!(matches!(
            decoded.payload,
            WireMessage::AuthenticationChallenge(_)
        ));
        assert_eq!(challenge.state(), ChallengeState::Active);
    }

    #[test]
    fn rogue_server_key_relay_and_wrong_transport_binding_are_rejected() {
        let (_, server_key, paired) = paired_identity();
        let expected_transport = binding(b"expected");
        let start_hash = "ef".repeat(32);
        let challenge = issue(
            &paired,
            &server_key,
            expected_transport.clone(),
            &start_hash,
            200,
            30,
        );
        let rogue_key = ServerIdentityKey::generate();
        let rogue_pinned = rogue_key
            .pinned_identity(paired.server_identity.desktop_instance_id.clone())
            .unwrap();
        assert!(matches!(
            verify_server_challenge(
                challenge.payload(),
                &rogue_pinned,
                &expected_transport,
                &start_hash,
                201,
            ),
            Err(ConnectorError::AuthenticationFailed)
        ));
        assert!(matches!(
            verify_server_challenge(
                challenge.payload(),
                &paired.server_identity,
                &binding(b"relayed"),
                &start_hash,
                201,
            ),
            Err(ConnectorError::AuthenticationFailed)
        ));
        assert!(matches!(
            verify_server_challenge(
                challenge.payload(),
                &paired.server_identity,
                &expected_transport,
                &"00".repeat(32),
                201,
            ),
            Err(ConnectorError::AuthenticationFailed)
        ));
    }

    #[test]
    fn replay_wrong_agent_expiry_and_stale_epoch_fail_closed() {
        let (agent_key, server_key, paired) = paired_identity();
        let transport = binding(b"replay");
        let start_hash = "12".repeat(32);
        let mut challenge = issue(
            &paired,
            &server_key,
            transport.clone(),
            &start_hash,
            200,
            10,
        );
        let response = verified_response(
            &agent_key,
            &challenge,
            &paired,
            &transport,
            &start_hash,
            201,
        );
        assert!(matches!(
            authenticate_response(&mut challenge, &response, &paired, 210),
            Err(ConnectorError::Expired)
        ));
        assert!(matches!(
            authenticate_response(&mut challenge, &response, &paired, 205),
            Err(ConnectorError::ReplayDetected)
        ));

        let (other_key, _, _) = paired_identity();
        let transport = binding(b"wrong-agent");
        let mut fresh = issue(
            &paired,
            &server_key,
            transport.clone(),
            &start_hash,
            300,
            10,
        );
        let verified = verify_server_challenge(
            fresh.payload(),
            &paired.server_identity,
            &transport,
            &start_hash,
            301,
        )
        .unwrap();
        let invalid = other_key.sign_verified_challenge(&verified).unwrap();
        assert!(matches!(
            authenticate_response(&mut fresh, &invalid, &paired, 305),
            Err(ConnectorError::AuthenticationFailed)
        ));

        let transport = binding(b"stale");
        let mut stale = issue(
            &paired,
            &server_key,
            transport.clone(),
            &start_hash,
            400,
            10,
        );
        let stale_response =
            verified_response(&agent_key, &stale, &paired, &transport, &start_hash, 401);
        let mut changed = paired.clone();
        changed.authorization_epoch += 1;
        assert!(matches!(
            authenticate_response(&mut stale, &stale_response, &changed, 405),
            Err(ConnectorError::SessionMismatch)
        ));
    }
}
