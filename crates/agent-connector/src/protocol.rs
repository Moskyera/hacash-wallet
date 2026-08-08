use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};

pub use hpay_agent_types::{AgentId, AgentWalletId, OperationId, WalletScope};

use crate::authentication::ChallengePayload;
use crate::error::{ConnectorError, ConnectorResult, ErrorResponse};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MESSAGE_LIFETIME_SECS: u64 = 5 * 60;
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;

macro_rules! prefixed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(format!("{}{}", $prefix, uuid::Uuid::new_v4().simple()))
            }

            pub fn parse(raw: impl Into<String>) -> ConnectorResult<Self> {
                let raw = raw.into();
                let suffix = raw
                    .strip_prefix($prefix)
                    .ok_or(ConnectorError::InvalidIdentifier)?;
                if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(ConnectorError::InvalidIdentifier);
                }
                Ok(Self(raw.to_ascii_lowercase()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> ConnectorResult<()> {
                let parsed = Self::parse(self.0.clone())?;
                if parsed == *self {
                    Ok(())
                } else {
                    Err(ConnectorError::InvalidIdentifier)
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

prefixed_id!(RequestId, "req_");
prefixed_id!(SessionId, "session_");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(String);

impl Nonce {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    pub fn parse(raw: impl Into<String>) -> ConnectorResult<Self> {
        let raw = raw.into();
        if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConnectorError::InvalidIdentifier);
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> ConnectorResult<()> {
        if Self::parse(self.0.clone())? == *self {
            Ok(())
        } else {
            Err(ConnectorError::InvalidIdentifier)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    PairingRequest,
    AuthenticationChallenge,
    AuthenticationResponse,
    Request,
    Response,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEnvelope {
    pub protocol_version: u16,
    pub message_type: MessageType,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub wallet_scope: WalletScope,
    pub session_id: SessionId,
    pub sequence: u64,
    pub nonce: Nonce,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub payload: WireMessage,
}

impl ProtocolEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        agent_id: AgentId,
        wallet_id: AgentWalletId,
        session_id: SessionId,
        sequence: u64,
        issued_at_unix: u64,
        expires_at_unix: u64,
        request: AgentRequest,
    ) -> ConnectorResult<Self> {
        let envelope = Self {
            protocol_version: PROTOCOL_VERSION,
            message_type: MessageType::Request,
            request_id: RequestId::new(),
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            agent_id,
            wallet_id,
            session_id,
            sequence,
            nonce: Nonce::random(),
            issued_at_unix,
            expires_at_unix,
            payload: WireMessage::Request(request),
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn authentication_challenge(payload: ChallengePayload) -> ConnectorResult<Self> {
        payload.validate_shape()?;
        let envelope = Self {
            protocol_version: payload.protocol_version,
            message_type: MessageType::AuthenticationChallenge,
            request_id: RequestId::new(),
            agent_id: payload.agent_id.clone(),
            wallet_id: payload.wallet_id.clone(),
            wallet_scope: payload.wallet_scope.clone(),
            session_id: payload.session_id.clone(),
            sequence: 1,
            nonce: payload.nonce.clone(),
            issued_at_unix: payload.issued_at_unix,
            expires_at_unix: payload.expires_at_unix,
            payload: WireMessage::AuthenticationChallenge(Box::new(payload)),
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_shape(&self) -> ConnectorResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ConnectorError::UnsupportedVersion);
        }
        self.request_id.validate()?;
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        self.session_id.validate()?;
        self.nonce.validate()?;
        validate_time_window(self.issued_at_unix, self.expires_at_unix)?;
        if self.sequence == 0 || self.message_type != self.payload.message_type() {
            return Err(ConnectorError::InvalidMessage);
        }
        self.payload.validate()?;
        if let WireMessage::AuthenticationChallenge(challenge) = &self.payload
            && (challenge.protocol_version != self.protocol_version
                || challenge.agent_id != self.agent_id
                || challenge.wallet_id != self.wallet_id
                || challenge.wallet_scope != self.wallet_scope
                || challenge.session_id != self.session_id
                || challenge.nonce != self.nonce
                || challenge.issued_at_unix != self.issued_at_unix
                || challenge.expires_at_unix != self.expires_at_unix)
        {
            return Err(ConnectorError::SessionMismatch);
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> ConnectorResult<Vec<u8>> {
        self.validate_shape()?;
        serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidMessage)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> ConnectorResult<Self> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::InvalidMessage)?;
        envelope.validate_shape()?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WireMessage {
    PairingRequest(crate::pairing::PairingRequest),
    AuthenticationChallenge(Box<ChallengePayload>),
    AuthenticationResponse(crate::authentication::AuthenticationResponse),
    Request(AgentRequest),
    Response(AgentResponse),
    Error(ErrorResponse),
}

impl WireMessage {
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::PairingRequest(_) => MessageType::PairingRequest,
            Self::AuthenticationChallenge(_) => MessageType::AuthenticationChallenge,
            Self::AuthenticationResponse(_) => MessageType::AuthenticationResponse,
            Self::Request(_) => MessageType::Request,
            Self::Response(_) => MessageType::Response,
            Self::Error(_) => MessageType::Error,
        }
    }

    pub(crate) fn validate(&self) -> ConnectorResult<()> {
        match self {
            Self::PairingRequest(request) => request.validate(),
            Self::AuthenticationChallenge(challenge) => challenge.validate_shape(),
            Self::AuthenticationResponse(response) => response.validate_shape(),
            Self::Request(request) => request.validate(),
            Self::Response(response) => response.validate(),
            Self::Error(error) if error.message.len() <= 512 => Ok(()),
            Self::Error(_) => Err(ConnectorError::InvalidMessage),
        }
    }
}

/// The complete agent-originated business API. There is intentionally no
/// generic command escape hatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "action",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AgentRequest {
    GetStatus,
    GetBalance,
    CreatePaymentIntent(CreatePaymentIntent),
    GetOwnOperationStatus { operation_id: OperationId },
    ListOwnOperations { limit: u16, cursor: Option<String> },
    CancelOwnUnsigned { operation_id: OperationId },
}

impl AgentRequest {
    pub fn validate(&self) -> ConnectorResult<()> {
        match self {
            Self::GetStatus | Self::GetBalance => Ok(()),
            Self::CreatePaymentIntent(intent) => intent.validate(),
            Self::GetOwnOperationStatus { operation_id }
            | Self::CancelOwnUnsigned { operation_id } => Ok(operation_id.validate()?),
            Self::ListOwnOperations { limit, cursor } => {
                if *limit == 0 || *limit > 100 {
                    return Err(ConnectorError::InvalidMessage);
                }
                validate_cursor(cursor)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreatePaymentIntent {
    pub idempotency_key: String,
    pub asset: String,
    pub amount_units: u64,
    pub recipient: String,
    pub reason: String,
    pub expires_at_unix: u64,
}

impl CreatePaymentIntent {
    pub fn validate(&self) -> ConnectorResult<()> {
        if !(16..=128).contains(&self.idempotency_key.len())
            || !self.idempotency_key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
            || self.asset != "HAC"
            || self.amount_units == 0
            || self.recipient.is_empty()
            || self.recipient.len() > 128
            || !self.recipient.is_ascii()
            || self.reason.len() > 256
            || !self.reason.is_ascii()
            || self.expires_at_unix == 0
        {
            return Err(ConnectorError::InvalidMessage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentOperationStatus {
    PaymentIntentCreated,
    FundsReserved,
    UnsignedTransactionPersisted,
    ApprovalRequested,
    Approved,
    Rejected,
    Signed,
    BroadcastSubmitted,
    BroadcastUncertain,
    SubmittedAwaitingFinalWitness,
    ReconciliationRequired,
    ReconciledAwaitingFinalWitness,
    Committed,
    Failed,
    Cancelled,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "result",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AgentResponse {
    Status {
        paused: bool,
        paired: bool,
    },
    Balance {
        available_units: u64,
        reserved_units: u64,
    },
    IntentCreated {
        operation_id: OperationId,
    },
    OperationStatus {
        operation_id: OperationId,
        status: AgentOperationStatus,
    },
    Operations {
        operation_ids: Vec<OperationId>,
        next_cursor: Option<String>,
    },
    Cancelled {
        operation_id: OperationId,
    },
}

impl AgentResponse {
    pub(crate) fn validate(&self) -> ConnectorResult<()> {
        match self {
            Self::Status { .. } | Self::Balance { .. } => Ok(()),
            Self::IntentCreated { operation_id }
            | Self::OperationStatus { operation_id, .. }
            | Self::Cancelled { operation_id } => Ok(operation_id.validate()?),
            Self::Operations {
                operation_ids,
                next_cursor,
            } if operation_ids.len() <= 100 => {
                operation_ids.iter().try_for_each(OperationId::validate)?;
                validate_cursor(next_cursor)
            }
            Self::Operations { .. } => Err(ConnectorError::InvalidMessage),
        }
    }
}

fn validate_cursor(cursor: &Option<String>) -> ConnectorResult<()> {
    if cursor.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) {
        return Err(ConnectorError::InvalidMessage);
    }
    Ok(())
}

pub fn validate_time_window(issued: u64, expires: u64) -> ConnectorResult<()> {
    if issued == 0 || expires <= issued || expires - issued > MAX_MESSAGE_LIFETIME_SECS {
        return Err(ConnectorError::InvalidTimeWindow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_envelope_roundtrip_is_typed() {
        let envelope = ProtocolEnvelope::request(
            AgentId::new(),
            AgentWalletId::new(),
            SessionId::new(),
            1,
            100,
            130,
            AgentRequest::GetStatus,
        )
        .unwrap();
        let encoded = envelope.to_json_bytes().unwrap();
        assert_eq!(
            ProtocolEnvelope::from_json_bytes(&encoded).unwrap(),
            envelope
        );
    }

    #[test]
    fn serde_cannot_bypass_identifier_validation() {
        let mut envelope = ProtocolEnvelope::request(
            AgentId::new(),
            AgentWalletId::new(),
            SessionId::new(),
            1,
            100,
            130,
            AgentRequest::GetBalance,
        )
        .unwrap();
        envelope.wallet_id = serde_json::from_str("\"../../personal\"").unwrap();
        assert_eq!(
            envelope.validate_shape(),
            Err(ConnectorError::InvalidIdentifier)
        );
    }

    #[test]
    fn denylisted_operations_do_not_deserialize() {
        for denied in [
            "sign",
            "sign_raw",
            "sign_bytes",
            "sign_message",
            "export_private_key",
            "export_seed",
            "send_raw_transaction",
            "broadcast_raw_transaction",
            "execute_wallet_command",
            "call_personal_wallet",
            "change_settings",
            "change_policy",
            "change_permissions",
            "open_channel",
            "close_channel",
        ] {
            let raw = format!(r#"{{"action":"{denied}"}}"#);
            assert!(
                serde_json::from_str::<AgentRequest>(&raw).is_err(),
                "{denied} unexpectedly entered the protocol"
            );
        }
    }

    #[test]
    fn floating_point_amounts_are_rejected() {
        let raw = r#"{
          "action":"create_payment_intent",
          "payload":{
            "idempotency_key":"invoice-12345678",
            "asset":"HAC",
            "amount_units":1.5,
            "recipient":"1abc",
            "reason":"test",
            "expires_at_unix":200
          }
        }"#;
        assert!(serde_json::from_str::<AgentRequest>(raw).is_err());
    }

    #[test]
    fn operation_status_and_cursor_are_typed_and_bounded() {
        let operation = OperationId::new();
        let typed = AgentResponse::OperationStatus {
            operation_id: operation,
            status: AgentOperationStatus::ApprovalRequested,
        };
        assert!(typed.validate().is_ok());
        let invalid_cursor = AgentResponse::Operations {
            operation_ids: vec![],
            next_cursor: Some("../personal".into()),
        };
        assert_eq!(
            invalid_cursor.validate(),
            Err(ConnectorError::InvalidMessage)
        );
        assert!(serde_json::from_str::<AgentOperationStatus>("\"arbitrary\"").is_err());
    }
}
