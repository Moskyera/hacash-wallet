use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, ConnectorResult, ErrorResponse};
use crate::framing::FrameCodec;
use crate::pairing::{PairingBearer, PairingRequest, PendingPairing};
use crate::pairing_completion::{
    AgentIdentitySigner, PairingCompletionReceipt, PairingCompletionRequest,
    PairingSubmissionCommitment,
};
use crate::protocol::RequestId;
use crate::session::Capability;

pub const PAIRING_PROTOCOL_VERSION: u16 = 1;

/// Bounded post-response acknowledgement.
///
/// Windows can discard unread named-pipe bytes when the server disconnects
/// immediately after a write. The server therefore waits for this exact,
/// hashed acknowledgement using its existing bounded read timeout. It never
/// calls unbounded FlushFileBuffers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingAcknowledgement {
    pub pairing_protocol_version: u16,
    pub request_id: RequestId,
    pub response_sha256: String,
}

impl PairingAcknowledgement {
    pub fn for_response_payload(
        request_id: RequestId,
        response_payload: &[u8],
    ) -> ConnectorResult<Self> {
        if response_payload.is_empty() || response_payload.len() > crate::MAX_FRAME_BYTES {
            return Err(ConnectorError::InvalidFrame);
        }
        let acknowledgement = Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id,
            response_sha256: hex::encode(Sha256::digest(response_payload)),
        };
        acknowledgement.validate()?;
        Ok(acknowledgement)
    }

    pub fn to_payload(&self) -> ConnectorResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)
    }

    pub fn from_payload(payload: &[u8]) -> ConnectorResult<Self> {
        let acknowledgement: Self =
            serde_json::from_slice(payload).map_err(|_| ConnectorError::InvalidMessage)?;
        acknowledgement.validate()?;
        Ok(acknowledgement)
    }

    pub fn verify_response(
        &self,
        expected_request_id: &RequestId,
        response_payload: &[u8],
    ) -> ConnectorResult<()> {
        self.validate()?;
        if &self.request_id != expected_request_id
            || self.response_sha256 != hex::encode(Sha256::digest(response_payload))
        {
            return Err(ConnectorError::AuthenticationFailed);
        }
        Ok(())
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.pairing_protocol_version != PAIRING_PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.request_id.validate()?;
        if self.response_sha256.len() != 64
            || !self
                .response_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConnectorError::InvalidMessage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingClientEnvelope {
    pub pairing_protocol_version: u16,
    pub request_id: RequestId,
    pub payload: PairingClientMessage,
}

impl PairingClientEnvelope {
    pub fn submit(request: PairingRequest) -> ConnectorResult<Self> {
        request.validate()?;
        Ok(Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id: RequestId::new(),
            payload: PairingClientMessage::Submit(request),
        })
    }

    pub fn completion(
        pairing_id: PairingBearer,
        submission_commitment: PairingSubmissionCommitment,
        signer: &dyn AgentIdentitySigner,
    ) -> ConnectorResult<Self> {
        let request = PairingCompletionRequest::new(pairing_id, submission_commitment, signer)?;
        Ok(Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id: RequestId::new(),
            payload: PairingClientMessage::Completion(request),
        })
    }

    pub fn to_payload(&self) -> ConnectorResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)
    }

    pub fn to_frame(&self, codec: &FrameCodec) -> ConnectorResult<Vec<u8>> {
        codec.encode(&self.to_payload()?)
    }

    pub fn from_frame(codec: &FrameCodec, frame: &[u8]) -> ConnectorResult<Self> {
        Self::from_payload(&codec.decode_exact(frame)?)
    }

    pub fn from_payload(payload: &[u8]) -> ConnectorResult<Self> {
        let envelope: Self =
            serde_json::from_slice(payload).map_err(|_| ConnectorError::InvalidMessage)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn classify_payload(payload: &[u8]) -> PairingPayloadClassification {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return PairingPayloadClassification::NotPairing;
        };
        let Some(object) = value.as_object() else {
            return PairingPayloadClassification::NotPairing;
        };
        if !object.contains_key("pairing_protocol_version") {
            return PairingPayloadClassification::NotPairing;
        }
        match Self::from_payload(payload) {
            Ok(envelope) => PairingPayloadClassification::Valid(envelope),
            Err(error) => PairingPayloadClassification::Invalid(error),
        }
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.pairing_protocol_version != PAIRING_PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.request_id.validate()?;
        match &self.payload {
            PairingClientMessage::Submit(request) => request.validate(),
            PairingClientMessage::Completion(request) => request.verify_identity_proof(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "action",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PairingClientMessage {
    Submit(PairingRequest),
    Completion(PairingCompletionRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingPayloadClassification {
    NotPairing,
    Valid(PairingClientEnvelope),
    Invalid(ConnectorError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingServerEnvelope {
    pub pairing_protocol_version: u16,
    pub request_id: RequestId,
    pub payload: PairingServerMessage,
}

impl PairingServerEnvelope {
    pub fn pending(request_id: RequestId, pending: &PendingPairing) -> ConnectorResult<Self> {
        let envelope = Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id,
            payload: PairingServerMessage::Pending(PairingSubmissionReceipt {
                agent_name: pending.request.agent_name.clone(),
                agent_version: pending.request.agent_version.clone(),
                identity_fingerprint: pending.identity_fingerprint.clone(),
                requested_capabilities: pending.request.requested_capabilities.clone(),
                submission_commitment: pending.submission_commitment.clone(),
            }),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn completed(
        request_id: RequestId,
        receipt: PairingCompletionReceipt,
    ) -> ConnectorResult<Self> {
        let envelope = Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id,
            payload: PairingServerMessage::Completed(receipt),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn error(request_id: RequestId, error: &ConnectorError) -> Self {
        Self {
            pairing_protocol_version: PAIRING_PROTOCOL_VERSION,
            request_id,
            payload: PairingServerMessage::Error(ErrorResponse::from_error(error)),
        }
    }

    pub fn to_payload(&self) -> ConnectorResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)
    }

    pub fn to_frame(&self, codec: &FrameCodec) -> ConnectorResult<Vec<u8>> {
        codec.encode(&self.to_payload()?)
    }

    pub fn from_frame(codec: &FrameCodec, frame: &[u8]) -> ConnectorResult<Self> {
        Self::from_payload(&codec.decode_exact(frame)?)
    }

    pub fn from_payload(payload: &[u8]) -> ConnectorResult<Self> {
        let envelope: Self =
            serde_json::from_slice(payload).map_err(|_| ConnectorError::InvalidMessage)?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.pairing_protocol_version != PAIRING_PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.request_id.validate()?;
        match &self.payload {
            PairingServerMessage::Pending(receipt) => receipt.validate(),
            PairingServerMessage::Completed(receipt) => receipt.validate_shape(),
            PairingServerMessage::Error(error) if error.message.len() <= 512 => Ok(()),
            PairingServerMessage::Error(_) => Err(ConnectorError::InvalidMessage),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "status",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PairingServerMessage {
    Pending(PairingSubmissionReceipt),
    Completed(PairingCompletionReceipt),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingSubmissionReceipt {
    pub agent_name: String,
    pub agent_version: String,
    pub identity_fingerprint: String,
    pub requested_capabilities: std::collections::BTreeSet<Capability>,
    pub submission_commitment: PairingSubmissionCommitment,
}

impl PairingSubmissionReceipt {
    fn validate(&self) -> ConnectorResult<()> {
        if self.agent_name.is_empty()
            || self.agent_version.is_empty()
            || self.identity_fingerprint.is_empty()
            || self.requested_capabilities.is_empty()
            || self.submission_commitment.validate().is_err()
        {
            return Err(ConnectorError::InvalidMessage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{AgentIdentityKey, AgentWalletId};

    fn request() -> PairingRequest {
        PairingRequest {
            pairing_id: PairingBearer::parse(format!("pair_{}", "ab".repeat(32))).unwrap(),
            agent_name: "Local Assistant".to_owned(),
            agent_version: "1.0.0".to_owned(),
            identity_public_key_sec1_hex: AgentIdentityKey::generate().public_key_sec1_hex(),
            requested_capabilities: BTreeSet::from([Capability::ReadBalance]),
        }
    }

    #[test]
    fn response_acknowledgement_is_exact_and_tamper_evident() {
        let request_id = RequestId::new();
        let response = br#"{"pairing_protocol_version":1,"ok":true}"#;
        let acknowledgement =
            PairingAcknowledgement::for_response_payload(request_id.clone(), response).unwrap();
        let encoded = acknowledgement.to_payload().unwrap();
        let decoded = PairingAcknowledgement::from_payload(&encoded).unwrap();
        decoded.verify_response(&request_id, response).unwrap();
        assert_eq!(
            decoded.verify_response(&request_id, b"tampered"),
            Err(ConnectorError::AuthenticationFailed)
        );
        assert_eq!(
            decoded.verify_response(&RequestId::new(), response),
            Err(ConnectorError::AuthenticationFailed)
        );
    }

    #[test]
    fn pairing_envelope_is_distinct_versioned_and_framed() {
        let codec = FrameCodec::default();
        let envelope = PairingClientEnvelope::submit(request()).unwrap();
        let frame = envelope.to_frame(&codec).unwrap();
        assert_eq!(
            PairingClientEnvelope::from_frame(&codec, &frame).unwrap(),
            envelope
        );
        assert!(matches!(
            PairingClientEnvelope::classify_payload(&envelope.to_payload().unwrap()),
            PairingPayloadClassification::Valid(_)
        ));
        assert!(matches!(
            PairingClientEnvelope::classify_payload(br#"{"protocol_version":1}"#),
            PairingPayloadClassification::NotPairing
        ));
    }

    #[test]
    fn malformed_pairing_marker_never_downgrades_to_normal_protocol() {
        assert!(matches!(
            PairingClientEnvelope::classify_payload(
                br#"{"pairing_protocol_version":99,"request_id":"req_bad"}"#
            ),
            PairingPayloadClassification::Invalid(_)
        ));
    }

    #[test]
    fn completion_request_proves_identity_and_redacts_the_bearer_token() {
        let key = AgentIdentityKey::generate();
        let pairing_id = format!("pair_{}", "cd".repeat(32));
        let pairing_request = PairingRequest {
            pairing_id: PairingBearer::parse(pairing_id.clone()).unwrap(),
            agent_name: "Local Assistant".to_owned(),
            agent_version: "1.0.0".to_owned(),
            identity_public_key_sec1_hex: key.public_key_sec1_hex(),
            requested_capabilities: BTreeSet::from([Capability::ReadBalance]),
        };
        let commitment = pairing_request.submission_commitment().unwrap();
        let envelope = PairingClientEnvelope::completion(
            PairingBearer::parse(pairing_id.clone()).unwrap(),
            commitment,
            &key,
        )
        .unwrap();
        let PairingClientMessage::Completion(completion) = &envelope.payload else {
            panic!("expected completion request");
        };
        completion.verify_identity_proof().unwrap();
        let debug = format!("{envelope:?}");
        assert!(!debug.contains(&pairing_id));
        assert!(!debug.contains(&completion.identity_signature_der_hex));
    }

    #[test]
    fn pending_receipt_contains_no_pairing_secret_or_raw_identity_key() {
        let key = AgentIdentityKey::generate();
        let mut session = crate::PairingSession::activate(
            AgentWalletId::new(),
            crate::ServerIdentityKey::generate()
                .pinned_identity("desktop_0123456789abcdef0123456789abcdef".to_owned())
                .unwrap(),
            100,
            60,
            2,
        )
        .unwrap();
        let mut request = request();
        request.pairing_id = session.pairing_bearer_for_activation();
        request.identity_public_key_sec1_hex = key.public_key_sec1_hex();
        let pending = session.submit(101, request).unwrap();
        let response = PairingServerEnvelope::pending(RequestId::new(), &pending).unwrap();
        let json = String::from_utf8(response.to_payload().unwrap()).unwrap();
        assert!(!json.contains(session.pairing_id()));
        assert!(!json.contains(&key.public_key_sec1_hex()));
        assert!(json.contains(&key.fingerprint()));
    }
}
