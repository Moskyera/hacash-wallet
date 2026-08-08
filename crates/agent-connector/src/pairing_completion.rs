use std::collections::BTreeSet;
use std::fmt;

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::authentication::{AuthenticationResponse, VerifiedServerChallenge};
use crate::error::{ConnectorError, ConnectorResult};
use crate::pairing::{
    PairingBearer, PairingRequest, PinnedServerIdentity, ServerIdentityKey, canonical_public_key,
    parse_verifying_key,
};
use crate::protocol::{AgentId, AgentWalletId, Nonce, WalletScope};
use crate::session::Capability;

pub const PAIRING_COMPLETION_TTL_SECS: u64 = 120;

/// Stable digest of the exact request displayed to the user.
///
/// It binds the bearer pairing id, agent identity, name, version and requested
/// capabilities without exposing the bearer token to approval or audit UIs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PairingSubmissionCommitment(String);

impl PairingSubmissionCommitment {
    pub fn for_request(request: &PairingRequest) -> ConnectorResult<Self> {
        request.validate()?;
        let canonical_key = canonical_public_key(&request.identity_public_key_sec1_hex)?;
        let mut bytes = Vec::with_capacity(512);
        append_field(&mut bytes, b"HPAY/AGENT-PAIRING/SUBMISSION/V1")?;
        append_field(
            &mut bytes,
            request.pairing_id.expose_for_protocol().as_bytes(),
        )?;
        append_field(&mut bytes, request.agent_name.as_bytes())?;
        append_field(&mut bytes, request.agent_version.as_bytes())?;
        append_field(&mut bytes, canonical_key.as_bytes())?;
        for capability in &request.requested_capabilities {
            append_field(&mut bytes, capability_name(*capability))?;
        }
        Ok(Self(hex::encode(Sha256::digest(bytes))))
    }

    pub fn parse(value: impl Into<String>) -> ConnectorResult<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConnectorError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> ConnectorResult<()> {
        Self::parse(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for PairingSubmissionCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PairingSubmissionCommitment")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for PairingSubmissionCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Protocol-specific signing boundary for software or OS-keystore identities.
///
/// Implementations never expose raw private key bytes and cannot be asked to
/// sign an arbitrary wallet transaction. Each method receives a typed,
/// domain-separated HPAY protocol object.
pub trait AgentIdentitySigner: Send + Sync {
    fn identity_public_key_sec1_hex(&self) -> ConnectorResult<String>;

    fn sign_authentication_challenge(
        &self,
        challenge: &VerifiedServerChallenge<'_>,
    ) -> ConnectorResult<AuthenticationResponse>;

    fn sign_pairing_completion_challenge(
        &self,
        challenge: &PairingCompletionChallenge,
    ) -> ConnectorResult<String>;
}

/// Client proof-of-possession challenge used to fetch the approved pairing.
pub struct PairingCompletionChallenge<'a> {
    pairing_id: &'a PairingBearer,
    submission_commitment: &'a PairingSubmissionCommitment,
    client_nonce: &'a Nonce,
    identity_public_key_sec1_hex: &'a str,
}

impl<'a> PairingCompletionChallenge<'a> {
    fn new(
        pairing_id: &'a PairingBearer,
        submission_commitment: &'a PairingSubmissionCommitment,
        client_nonce: &'a Nonce,
        identity_public_key_sec1_hex: &'a str,
    ) -> ConnectorResult<Self> {
        pairing_id.validate()?;
        submission_commitment.validate()?;
        client_nonce.validate()?;
        let canonical = canonical_public_key(identity_public_key_sec1_hex)?;
        if canonical != identity_public_key_sec1_hex {
            return Err(ConnectorError::InvalidIdentity);
        }
        Ok(Self {
            pairing_id,
            submission_commitment,
            client_nonce,
            identity_public_key_sec1_hex,
        })
    }

    pub fn canonical_signing_bytes(&self) -> ConnectorResult<Vec<u8>> {
        self.pairing_id.validate()?;
        self.submission_commitment.validate()?;
        self.client_nonce.validate()?;
        let canonical_key = canonical_public_key(self.identity_public_key_sec1_hex)?;
        let mut bytes = Vec::with_capacity(384);
        append_field(&mut bytes, b"HPAY/AGENT-PAIRING/COMPLETE-REQUEST/V1")?;
        append_field(&mut bytes, self.pairing_id.expose_for_protocol().as_bytes())?;
        append_field(&mut bytes, self.submission_commitment.as_str().as_bytes())?;
        append_field(&mut bytes, self.client_nonce.as_str().as_bytes())?;
        append_field(&mut bytes, canonical_key.as_bytes())?;
        Ok(bytes)
    }
}

impl fmt::Debug for PairingCompletionChallenge<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCompletionChallenge")
            .field("pairing_id", &"[REDACTED]")
            .field("submission_commitment", &self.submission_commitment)
            .field("client_nonce", &self.client_nonce)
            .field(
                "identity_public_key_sec1_hex",
                &self.identity_public_key_sec1_hex,
            )
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingCompletionRequest {
    #[serde(
        serialize_with = "crate::pairing::serialize_pairing_bearer",
        deserialize_with = "crate::pairing::deserialize_pairing_bearer"
    )]
    pairing_id: PairingBearer,
    pub submission_commitment: PairingSubmissionCommitment,
    pub client_nonce: Nonce,
    pub identity_public_key_sec1_hex: String,
    pub identity_signature_der_hex: String,
}

impl PairingCompletionRequest {
    pub fn new(
        pairing_id: PairingBearer,
        submission_commitment: PairingSubmissionCommitment,
        signer: &dyn AgentIdentitySigner,
    ) -> ConnectorResult<Self> {
        Self::with_nonce(pairing_id, submission_commitment, Nonce::random(), signer)
    }

    fn with_nonce(
        pairing_id: PairingBearer,
        submission_commitment: PairingSubmissionCommitment,
        client_nonce: Nonce,
        signer: &dyn AgentIdentitySigner,
    ) -> ConnectorResult<Self> {
        let identity_public_key_sec1_hex =
            canonical_public_key(&signer.identity_public_key_sec1_hex()?)?;
        let challenge = PairingCompletionChallenge::new(
            &pairing_id,
            &submission_commitment,
            &client_nonce,
            &identity_public_key_sec1_hex,
        )?;
        let identity_signature_der_hex = signer.sign_pairing_completion_challenge(&challenge)?;
        let request = Self {
            pairing_id,
            submission_commitment,
            client_nonce,
            identity_public_key_sec1_hex,
            identity_signature_der_hex,
        };
        request.verify_identity_proof()?;
        Ok(request)
    }

    pub fn verify_identity_proof(&self) -> ConnectorResult<()> {
        let challenge = self.challenge()?;
        let signature_bytes = hex::decode(&self.identity_signature_der_hex)
            .map_err(|_| ConnectorError::AuthenticationFailed)?;
        let signature = Signature::from_der(&signature_bytes)
            .map_err(|_| ConnectorError::AuthenticationFailed)?;
        parse_verifying_key(&self.identity_public_key_sec1_hex)?
            .verify(&challenge.canonical_signing_bytes()?, &signature)
            .map_err(|_| ConnectorError::AuthenticationFailed)
    }

    /// Explicit secret accessor used only for the completion outbox lookup.
    pub fn pairing_id(&self) -> &str {
        self.pairing_id.expose_for_protocol()
    }

    pub fn submission_commitment(&self) -> &PairingSubmissionCommitment {
        &self.submission_commitment
    }

    fn challenge(&self) -> ConnectorResult<PairingCompletionChallenge<'_>> {
        PairingCompletionChallenge::new(
            &self.pairing_id,
            &self.submission_commitment,
            &self.client_nonce,
            &self.identity_public_key_sec1_hex,
        )
    }
}

impl fmt::Debug for PairingCompletionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCompletionRequest")
            .field("pairing_id", &"[REDACTED]")
            .field("submission_commitment", &self.submission_commitment)
            .field("client_nonce", &self.client_nonce)
            .field(
                "identity_public_key_sec1_hex",
                &self.identity_public_key_sec1_hex,
            )
            .field("identity_signature_der_hex", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingCompletionReceipt {
    pub submission_commitment: PairingSubmissionCommitment,
    pub client_nonce: Nonce,
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub wallet_scope: WalletScope,
    pub capabilities: BTreeSet<Capability>,
    pub authorization_epoch: u64,
    pub paired_at_unix: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub server_identity: PinnedServerIdentity,
    pub server_signature_der_hex: String,
}

impl PairingCompletionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        request: &PairingCompletionRequest,
        agent_id: AgentId,
        wallet_id: AgentWalletId,
        wallet_scope: WalletScope,
        capabilities: BTreeSet<Capability>,
        authorization_epoch: u64,
        paired_at_unix: u64,
        issued_at_unix: u64,
        expires_at_unix: u64,
        server_identity: PinnedServerIdentity,
        server_identity_key: &ServerIdentityKey,
    ) -> ConnectorResult<Self> {
        request.verify_identity_proof()?;
        let signing_identity =
            server_identity_key.pinned_identity(server_identity.desktop_instance_id.clone())?;
        if signing_identity != server_identity {
            return Err(ConnectorError::AuthenticationFailed);
        }
        let mut receipt = Self {
            submission_commitment: request.submission_commitment.clone(),
            client_nonce: request.client_nonce.clone(),
            agent_id,
            wallet_id,
            wallet_scope,
            capabilities,
            authorization_epoch,
            paired_at_unix,
            issued_at_unix,
            expires_at_unix,
            server_identity,
            server_signature_der_hex: String::new(),
        };
        receipt.validate_unsigned_shape()?;
        receipt.server_signature_der_hex =
            server_identity_key.sign_der_hex(&receipt.canonical_signing_bytes()?);
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_unsigned_shape(&self) -> ConnectorResult<()> {
        self.submission_commitment.validate()?;
        self.client_nonce.validate()?;
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        self.server_identity.validate()?;
        if self.capabilities.is_empty()
            || self.authorization_epoch == 0
            || self.paired_at_unix == 0
            || self.issued_at_unix == 0
            || self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix - self.issued_at_unix > PAIRING_COMPLETION_TTL_SECS
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
        let mut bytes = Vec::with_capacity(1024);
        append_field(&mut bytes, b"HPAY/AGENT-PAIRING/COMPLETE-RECEIPT/V1")?;
        append_field(&mut bytes, self.submission_commitment.as_str().as_bytes())?;
        append_field(&mut bytes, self.client_nonce.as_str().as_bytes())?;
        append_field(&mut bytes, self.agent_id.as_str().as_bytes())?;
        append_field(&mut bytes, self.wallet_id.as_str().as_bytes())?;
        append_field(&mut bytes, self.wallet_scope.as_str().as_bytes())?;
        for capability in &self.capabilities {
            append_field(&mut bytes, capability_name(*capability))?;
        }
        append_field(&mut bytes, &self.authorization_epoch.to_be_bytes())?;
        append_field(&mut bytes, &self.paired_at_unix.to_be_bytes())?;
        append_field(&mut bytes, &self.issued_at_unix.to_be_bytes())?;
        append_field(&mut bytes, &self.expires_at_unix.to_be_bytes())?;
        append_field(
            &mut bytes,
            self.server_identity.desktop_instance_id.as_bytes(),
        )?;
        append_field(
            &mut bytes,
            self.server_identity.identity_public_key_sec1_hex.as_bytes(),
        )?;
        append_field(
            &mut bytes,
            self.server_identity.identity_fingerprint.as_bytes(),
        )?;
        Ok(bytes)
    }
}

pub fn verify_pairing_completion_receipt(
    receipt: &PairingCompletionReceipt,
    request: &PairingCompletionRequest,
    pinned_server: &PinnedServerIdentity,
    now_unix: u64,
) -> ConnectorResult<()> {
    receipt.validate_shape()?;
    request.verify_identity_proof()?;
    pinned_server.validate()?;
    if receipt.submission_commitment != request.submission_commitment
        || receipt.client_nonce != request.client_nonce
        || &receipt.server_identity != pinned_server
        || now_unix < receipt.issued_at_unix
        || now_unix >= receipt.expires_at_unix
    {
        return Err(ConnectorError::AuthenticationFailed);
    }
    let signature_bytes = hex::decode(&receipt.server_signature_der_hex)
        .map_err(|_| ConnectorError::AuthenticationFailed)?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| ConnectorError::AuthenticationFailed)?;
    parse_verifying_key(&pinned_server.identity_public_key_sec1_hex)?
        .verify(&receipt.canonical_signing_bytes()?, &signature)
        .map_err(|_| ConnectorError::AuthenticationFailed)
}

fn validate_der_signature_hex(value: &str) -> ConnectorResult<()> {
    if value.len() < 128 || value.len() > 160 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConnectorError::AuthenticationFailed);
    }
    Ok(())
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
    use crate::{AgentIdentityKey, PairingRequest};

    fn request(pairing_id: String, key: &AgentIdentityKey) -> PairingRequest {
        PairingRequest {
            pairing_id: PairingBearer::parse(pairing_id).unwrap(),
            agent_name: "Local Assistant".to_owned(),
            agent_version: "1.0.0".to_owned(),
            identity_public_key_sec1_hex: key.public_key_sec1_hex(),
            requested_capabilities: BTreeSet::from([Capability::ReadBalance]),
        }
    }

    #[test]
    fn commitment_changes_with_every_approved_field() {
        let key = AgentIdentityKey::generate();
        let base = request(format!("pair_{}", "ab".repeat(32)), &key);
        let commitment = PairingSubmissionCommitment::for_request(&base).unwrap();
        let mut changed = base.clone();
        changed.agent_name = "Different Agent".to_owned();
        assert_ne!(
            PairingSubmissionCommitment::for_request(&changed).unwrap(),
            commitment
        );
        changed = base.clone();
        changed
            .requested_capabilities
            .insert(Capability::ReadWalletInfo);
        assert_ne!(
            PairingSubmissionCommitment::for_request(&changed).unwrap(),
            commitment
        );
    }

    #[test]
    fn debug_output_redacts_bearer_pairing_id_and_signature() {
        let key = AgentIdentityKey::generate();
        let pairing_id = format!("pair_{}", "ab".repeat(32));
        let request = request(pairing_id.clone(), &key);
        let commitment = PairingSubmissionCommitment::for_request(&request).unwrap();
        let completion = PairingCompletionRequest::new(
            PairingBearer::parse(pairing_id.clone()).unwrap(),
            commitment,
            &key,
        )
        .unwrap();
        let debug = format!("{completion:?}");
        assert!(!debug.contains(&pairing_id));
        assert!(!debug.contains(&completion.identity_signature_der_hex));
        assert!(debug.contains("[REDACTED]"));
    }
}
