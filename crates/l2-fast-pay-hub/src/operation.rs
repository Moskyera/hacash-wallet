//! Immutable Fast Pay operation identity and reservation lifecycle.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::FastPayRequest;
use crate::error::{HubError, HubResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Created,
    Reserved,
    PersistedBeforeSigning,
    Signed,
    AwaitingRecipientConfirmation,
    Acknowledged,
    Committed,
    Rejected,
    Expired,
    RecoveryRequired,
    Released,
}

impl ReservationStatus {
    pub fn signature_may_exist(self) -> bool {
        matches!(
            self,
            Self::Signed
                | Self::AwaitingRecipientConfirmation
                | Self::Acknowledged
                | Self::Committed
                | Self::RecoveryRequired
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Rejected | Self::Expired | Self::Released
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub operation_id: String,
    pub request_commitment: String,
    pub created_at: u64,
}

pub fn validate_operation_identity(request: &FastPayRequest) -> HubResult<()> {
    let operation = uuid::Uuid::parse_str(request.operation_id.trim())
        .map_err(|_| HubError::Payment("operation_id must be a UUID".into()))?;
    if operation.is_nil() {
        return Err(HubError::Payment("operation_id must not be nil".into()));
    }
    let key = request.idempotency_key.trim();
    if !(16..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HubError::Payment(
            "idempotency_key must be 16-128 safe ASCII characters".into(),
        ));
    }
    Ok(())
}

pub fn request_commitment(request: &FastPayRequest) -> String {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L2/FAST-PAY/REQUEST/V1");
    for field in [
        request.operation_id.as_bytes(),
        request.payer.trim().as_bytes(),
        request.payee.trim().as_bytes(),
        request.amount.trim().as_bytes(),
        request.channel_id.trim().as_bytes(),
        request.fee_payer.as_deref().unwrap_or("sender").as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> FastPayRequest {
        FastPayRequest {
            operation_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: "test-idempotency-key-0001".into(),
            payer: "payer".into(),
            payee: "payee".into(),
            amount: "1.250".into(),
            channel_id: "channel".into(),
            fee_payer: None,
        }
    }

    #[test]
    fn identity_and_commitment_are_stable_and_payload_bound() {
        let request = request();
        validate_operation_identity(&request).unwrap();
        assert_eq!(request_commitment(&request), request_commitment(&request));
        let mut changed = request.clone();
        changed.amount = "1.251".into();
        assert_ne!(request_commitment(&request), request_commitment(&changed));
        changed = request.clone();
        changed.payee.push('x');
        assert_ne!(request_commitment(&request), request_commitment(&changed));
    }

    #[test]
    fn invalid_identity_is_rejected() {
        let mut request = request();
        request.operation_id = "not-a-uuid".into();
        assert!(validate_operation_identity(&request).is_err());
        request.operation_id = uuid::Uuid::new_v4().to_string();
        request.idempotency_key = "short".into();
        assert!(validate_operation_identity(&request).is_err());
    }
}
