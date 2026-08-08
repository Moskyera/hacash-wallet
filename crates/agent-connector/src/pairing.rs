use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::authentication::{AuthenticationResponse, VerifiedServerChallenge};
use crate::error::{ConnectorError, ConnectorResult};
use crate::pairing_completion::{
    AgentIdentitySigner, PairingCompletionChallenge, PairingSubmissionCommitment,
};
use crate::protocol::{AgentId, AgentWalletId, WalletScope};
use crate::session::Capability;

pub const DEFAULT_PAIRING_TTL_SECS: u64 = 120;
pub const DEFAULT_PAIRING_ATTEMPTS: u8 = 5;

/// One-time secret used only to bootstrap explicit local agent pairing.
///
/// Clones share one allocation instead of copying the bearer bytes. The final
/// owner drops a `Zeroizing<String>`, which clears the allocation before it is
/// released. Serialization is intentionally implemented only for the explicit
/// pairing wire field; `Debug` is always redacted and `Display` is absent.
pub struct PairingBearer {
    storage: Arc<Zeroizing<String>>,
}

impl PairingBearer {
    pub fn parse(value: String) -> ConnectorResult<Self> {
        let value = Zeroizing::new(value);
        validate_pairing_id(value.as_str())?;
        Ok(Self {
            storage: Arc::new(value),
        })
    }

    /// Explicitly reveals the bearer for the short-lived QR/activation flow.
    pub fn expose_for_activation(&self) -> &str {
        self.storage.as_str()
    }

    pub(crate) fn expose_for_protocol(&self) -> &str {
        self.storage.as_str()
    }

    pub(crate) fn validate(&self) -> ConnectorResult<()> {
        validate_pairing_id(self.expose_for_protocol())
    }

    fn random() -> Self {
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        let mut random_bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let mut value = String::with_capacity(69);
        value.push_str("pair_");
        for &byte in &random_bytes {
            value.push(LOWER_HEX[(byte >> 4) as usize] as char);
            value.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
        }
        random_bytes.zeroize();
        Self::parse(value).expect("generated pairing bearer has a valid shape")
    }
}

impl Clone for PairingBearer {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
        }
    }
}

impl PartialEq for PairingBearer {
    fn eq(&self, other: &Self) -> bool {
        self.expose_for_protocol() == other.expose_for_protocol()
    }
}

impl Eq for PairingBearer {}

impl fmt::Debug for PairingBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingBearer([REDACTED])")
    }
}

pub(crate) fn serialize_pairing_bearer<S>(
    bearer: &PairingBearer,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(bearer.expose_for_protocol())
}

pub(crate) fn deserialize_pairing_bearer<'de, D>(deserializer: D) -> Result<PairingBearer, D::Error>
where
    D: Deserializer<'de>,
{
    PairingBearer::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
}

pub struct AgentIdentityKey {
    signing_key: SigningKey,
}
/// Pinned HPAY desktop identity learned during explicit agent pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinnedServerIdentity {
    pub desktop_instance_id: String,
    pub identity_public_key_sec1_hex: String,
    pub identity_fingerprint: String,
}

impl PinnedServerIdentity {
    pub fn validate(&self) -> ConnectorResult<()> {
        crate::session::validate_desktop_instance_id(&self.desktop_instance_id)?;
        let canonical = canonical_public_key(&self.identity_public_key_sec1_hex)?;
        if canonical != self.identity_public_key_sec1_hex
            || identity_fingerprint(&canonical)? != self.identity_fingerprint
        {
            return Err(ConnectorError::InvalidIdentity);
        }
        Ok(())
    }
}

/// HPAY desktop authentication identity. This is not a wallet or blockchain
/// signing key and must be persisted by the desktop platform keystore.
pub struct ServerIdentityKey {
    signing_key: SigningKey,
}

impl ServerIdentityKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    /// Rehydrates a desktop identity from an already protected platform or
    /// encrypted-vault secret. The connector never exposes an export method.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> ConnectorResult<Self> {
        let signing_key =
            SigningKey::from_slice(secret).map_err(|_| ConnectorError::InvalidIdentity)?;
        Ok(Self { signing_key })
    }

    pub fn pinned_identity(
        &self,
        desktop_instance_id: String,
    ) -> ConnectorResult<PinnedServerIdentity> {
        crate::session::validate_desktop_instance_id(&desktop_instance_id)?;
        let identity_public_key_sec1_hex = hex::encode(
            self.signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let pinned = PinnedServerIdentity {
            desktop_instance_id,
            identity_fingerprint: identity_fingerprint(&identity_public_key_sec1_hex)?,
            identity_public_key_sec1_hex,
        };
        pinned.validate()?;
        Ok(pinned)
    }

    pub(crate) fn sign_der_hex(&self, message: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(message);
        hex::encode(signature.to_der().as_bytes())
    }
}

impl AgentIdentityKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    /// Rehydrates an identity from bytes already protected by the embedding
    /// client's encrypted vault. No private-key export API is provided.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> ConnectorResult<Self> {
        let signing_key =
            SigningKey::from_slice(secret).map_err(|_| ConnectorError::InvalidIdentity)?;
        Ok(Self { signing_key })
    }

    pub fn public_key_sec1_hex(&self) -> String {
        hex::encode(
            self.signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    pub fn fingerprint(&self) -> String {
        identity_fingerprint(&self.public_key_sec1_hex())
            .expect("generated P-256 public key is valid")
    }

    pub fn sign_verified_challenge(
        &self,
        challenge: &VerifiedServerChallenge<'_>,
    ) -> ConnectorResult<AuthenticationResponse> {
        let payload = challenge.payload();
        let canonical = payload.canonical_signing_bytes()?;
        let signature: Signature = self.signing_key.sign(&canonical);
        Ok(AuthenticationResponse {
            agent_id: payload.agent_id.clone(),
            wallet_id: payload.wallet_id.clone(),
            session_id: payload.session_id.clone(),
            challenge_nonce: payload.nonce.clone(),
            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
    }
}

impl AgentIdentitySigner for AgentIdentityKey {
    fn identity_public_key_sec1_hex(&self) -> ConnectorResult<String> {
        Ok(self.public_key_sec1_hex())
    }

    fn sign_authentication_challenge(
        &self,
        challenge: &VerifiedServerChallenge<'_>,
    ) -> ConnectorResult<AuthenticationResponse> {
        self.sign_verified_challenge(challenge)
    }

    fn sign_pairing_completion_challenge(
        &self,
        challenge: &PairingCompletionChallenge,
    ) -> ConnectorResult<String> {
        let signature: Signature = self.signing_key.sign(&challenge.canonical_signing_bytes()?);
        Ok(hex::encode(signature.to_der().as_bytes()))
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    #[serde(
        serialize_with = "serialize_pairing_bearer",
        deserialize_with = "deserialize_pairing_bearer"
    )]
    pub pairing_id: PairingBearer,
    pub agent_name: String,
    pub agent_version: String,
    pub identity_public_key_sec1_hex: String,
    pub requested_capabilities: BTreeSet<Capability>,
}

impl fmt::Debug for PairingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingRequest")
            .field("pairing_id", &"[REDACTED]")
            .field("agent_name", &self.agent_name)
            .field("agent_version", &self.agent_version)
            .field(
                "identity_public_key_sec1_hex",
                &self.identity_public_key_sec1_hex,
            )
            .field("requested_capabilities", &self.requested_capabilities)
            .finish()
    }
}

impl PairingRequest {
    pub fn validate(&self) -> ConnectorResult<()> {
        self.pairing_id.validate()?;
        validate_label(&self.agent_name, 1, 80)?;
        validate_label(&self.agent_version, 1, 32)?;
        parse_verifying_key(&self.identity_public_key_sec1_hex)?;
        if self.requested_capabilities.is_empty() {
            return Err(ConnectorError::CapabilityDenied);
        }
        Ok(())
    }

    pub fn submission_commitment(&self) -> ConnectorResult<PairingSubmissionCommitment> {
        PairingSubmissionCommitment::for_request(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairedAgentStatus {
    Active,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairedAgent {
    pub agent_id: AgentId,
    pub wallet_id: AgentWalletId,
    pub wallet_scope: WalletScope,
    pub name: String,
    pub version: String,
    pub identity_public_key_sec1_hex: String,
    pub identity_fingerprint: String,
    pub capabilities: BTreeSet<Capability>,
    pub status: PairedAgentStatus,
    pub paired_at_unix: u64,
    pub authorization_epoch: u64,
    pub server_identity: PinnedServerIdentity,
}

impl PairedAgent {
    pub(crate) fn verifying_key(&self) -> ConnectorResult<VerifyingKey> {
        parse_verifying_key(&self.identity_public_key_sec1_hex)
    }

    pub fn identity_key_sha256(&self) -> ConnectorResult<String> {
        identity_key_sha256(&self.identity_public_key_sec1_hex)
    }

    pub fn ensure_active(&self) -> ConnectorResult<()> {
        self.agent_id.validate()?;
        self.wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.wallet_id)?;
        self.server_identity.validate()?;
        if self.authorization_epoch == 0
            || self.identity_fingerprint
                != identity_fingerprint(&self.identity_public_key_sec1_hex)?
        {
            return Err(ConnectorError::InvalidIdentity);
        }
        if self.status != PairedAgentStatus::Active {
            return Err(ConnectorError::Revoked);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairing {
    pub request: PairingRequest,
    pub identity_fingerprint: String,
    pub submission_commitment: PairingSubmissionCommitment,
}

/// Short-lived bearer pairing state. It intentionally implements neither
/// `Debug` nor `Clone`, preventing accidental secret logging or duplication.
pub struct PairingSession {
    pairing_id: PairingBearer,
    wallet_id: AgentWalletId,
    server_identity: PinnedServerIdentity,
    activated_at_unix: u64,
    expires_at_unix: u64,
    attempts: u8,
    max_attempts: u8,
    consumed: bool,
    pending: Option<PendingPairing>,
}

impl PairingSession {
    pub fn activate(
        wallet_id: AgentWalletId,
        server_identity: PinnedServerIdentity,
        now_unix: u64,
        ttl_secs: u64,
        max_attempts: u8,
    ) -> ConnectorResult<Self> {
        wallet_id.validate()?;
        server_identity.validate()?;
        if now_unix == 0
            || ttl_secs == 0
            || ttl_secs > DEFAULT_PAIRING_TTL_SECS
            || max_attempts == 0
            || max_attempts > DEFAULT_PAIRING_ATTEMPTS
        {
            return Err(ConnectorError::InvalidTimeWindow);
        }
        let expires_at_unix = now_unix
            .checked_add(ttl_secs)
            .ok_or(ConnectorError::InvalidTimeWindow)?;
        Ok(Self {
            pairing_id: PairingBearer::random(),
            wallet_id,
            server_identity,
            activated_at_unix: now_unix,
            expires_at_unix,
            attempts: 0,
            max_attempts,
            consumed: false,
            pending: None,
        })
    }

    /// Explicit short-lived accessor used to render/copy the activation code.
    pub fn pairing_id(&self) -> &str {
        self.pairing_id.expose_for_activation()
    }

    /// Shares the zeroizing bearer allocation with an activation response.
    pub fn pairing_bearer_for_activation(&self) -> PairingBearer {
        self.pairing_id.clone()
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn submit(
        &mut self,
        now_unix: u64,
        mut request: PairingRequest,
    ) -> ConnectorResult<PendingPairing> {
        self.ensure_usable(now_unix)?;
        if self.pending.is_none() {
            self.attempts = self
                .attempts
                .checked_add(1)
                .ok_or(ConnectorError::PairingAttemptsExceeded)?;
            if self.attempts > self.max_attempts {
                self.consumed = true;
                self.pending = None;
                return Err(ConnectorError::PairingAttemptsExceeded);
            }
        }
        request.validate()?;
        if request.pairing_id != self.pairing_id {
            return Err(ConnectorError::AuthenticationFailed);
        }
        // Drop the separately deserialized bearer allocation and retain only a
        // shared reference to the activation session's zeroizing allocation.
        request.pairing_id = self.pairing_id.clone();
        let submission_commitment = request.submission_commitment()?;
        if let Some(pending) = &self.pending {
            return if pending.submission_commitment == submission_commitment {
                Ok(pending.clone())
            } else {
                Err(ConnectorError::AuthenticationFailed)
            };
        }
        let canonical_key = canonical_public_key(&request.identity_public_key_sec1_hex)?;
        let pending = PendingPairing {
            identity_fingerprint: identity_fingerprint(&canonical_key)?,
            request: PairingRequest {
                identity_public_key_sec1_hex: canonical_key,
                ..request
            },
            submission_commitment,
        };
        self.pending = Some(pending.clone());
        Ok(pending)
    }

    pub fn approve(
        &mut self,
        now_unix: u64,
        expected_submission_commitment: &PairingSubmissionCommitment,
        granted_capabilities: BTreeSet<Capability>,
    ) -> ConnectorResult<PairedAgent> {
        self.ensure_usable(now_unix)?;
        expected_submission_commitment.validate()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(ConnectorError::PairingInactive)?;
        if &pending.submission_commitment != expected_submission_commitment {
            return Err(ConnectorError::AuthenticationFailed);
        }
        let pending = self.pending.take().ok_or(ConnectorError::PairingInactive)?;
        if granted_capabilities.is_empty()
            || !granted_capabilities.is_subset(&pending.request.requested_capabilities)
        {
            self.consumed = true;
            return Err(ConnectorError::CapabilityDenied);
        }
        self.consumed = true;
        Ok(PairedAgent {
            agent_id: AgentId::new(),
            wallet_scope: WalletScope::for_agent_wallet(&self.wallet_id),
            wallet_id: self.wallet_id.clone(),
            name: pending.request.agent_name,
            version: pending.request.agent_version,
            identity_public_key_sec1_hex: pending.request.identity_public_key_sec1_hex,
            identity_fingerprint: pending.identity_fingerprint,
            capabilities: granted_capabilities,
            status: PairedAgentStatus::Active,
            paired_at_unix: now_unix,
            authorization_epoch: 1,
            server_identity: self.server_identity.clone(),
        })
    }

    pub fn reject(
        &mut self,
        now_unix: u64,
        expected_submission_commitment: &PairingSubmissionCommitment,
    ) -> ConnectorResult<()> {
        self.ensure_usable(now_unix)?;
        expected_submission_commitment.validate()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(ConnectorError::PairingInactive)?;
        if &pending.submission_commitment != expected_submission_commitment {
            return Err(ConnectorError::AuthenticationFailed);
        }
        self.pending = None;
        self.consumed = true;
        Ok(())
    }

    fn ensure_usable(&self, now_unix: u64) -> ConnectorResult<()> {
        if self.consumed {
            return Err(ConnectorError::PairingConsumed);
        }
        if now_unix < self.activated_at_unix || now_unix >= self.expires_at_unix {
            return Err(ConnectorError::Expired);
        }
        Ok(())
    }
}

pub(crate) fn parse_verifying_key(encoded_hex: &str) -> ConnectorResult<VerifyingKey> {
    if encoded_hex.len() > 130 {
        return Err(ConnectorError::InvalidIdentity);
    }
    let bytes = hex::decode(encoded_hex).map_err(|_| ConnectorError::InvalidIdentity)?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| ConnectorError::InvalidIdentity)
}

pub(crate) fn canonical_public_key(encoded_hex: &str) -> ConnectorResult<String> {
    Ok(hex::encode(
        parse_verifying_key(encoded_hex)?
            .to_encoded_point(true)
            .as_bytes(),
    ))
}

fn identity_key_sha256(encoded_hex: &str) -> ConnectorResult<String> {
    let key = parse_verifying_key(encoded_hex)?;
    Ok(hex::encode(Sha256::digest(
        key.to_encoded_point(true).as_bytes(),
    )))
}

fn identity_fingerprint(encoded_hex: &str) -> ConnectorResult<String> {
    let key = parse_verifying_key(encoded_hex)?;
    let digest = Sha256::digest(key.to_encoded_point(true).as_bytes());
    let short = hex::encode_upper(&digest[..10]);
    Ok(short
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-"))
}

pub(crate) fn validate_pairing_id(value: &str) -> ConnectorResult<()> {
    let suffix = value
        .strip_prefix("pair_")
        .ok_or(ConnectorError::InvalidIdentifier)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConnectorError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_label(value: &str, minimum: usize, maximum: usize) -> ConnectorResult<()> {
    if !(minimum..=maximum).contains(&value.len())
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConnectorError::InvalidMessage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pinned_server() -> PinnedServerIdentity {
        ServerIdentityKey::generate()
            .pinned_identity(format!("desktop_{}", uuid::Uuid::new_v4().simple()))
            .unwrap()
    }

    fn request(pairing_id: &str, key: &AgentIdentityKey) -> PairingRequest {
        PairingRequest {
            pairing_id: PairingBearer::parse(pairing_id.to_owned()).unwrap(),
            agent_name: "Local Assistant".into(),
            agent_version: "1.0.0".into(),
            identity_public_key_sec1_hex: key.public_key_sec1_hex(),
            requested_capabilities: [Capability::ReadBalance, Capability::CreatePaymentIntent]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn server_identity_can_be_rehydrated_without_an_export_api() {
        let secret = [7_u8; 32];
        let first = ServerIdentityKey::from_secret_bytes(&secret).unwrap();
        let second = ServerIdentityKey::from_secret_bytes(&secret).unwrap();
        let desktop = format!("desktop_{}", uuid::Uuid::new_v4().simple());
        assert_eq!(
            first.pinned_identity(desktop.clone()).unwrap(),
            second.pinned_identity(desktop).unwrap()
        );
        assert!(ServerIdentityKey::from_secret_bytes(&[0_u8; 32]).is_err());
    }

    #[test]
    fn pairing_requires_explicit_single_use_user_approval() {
        let key = AgentIdentityKey::generate();
        let mut pairing =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 60, 3).unwrap();
        let pending = pairing
            .submit(110, request(pairing.pairing_id(), &key))
            .unwrap();
        assert_eq!(pending.identity_fingerprint, key.fingerprint());
        let paired = pairing
            .approve(
                120,
                &pending.submission_commitment,
                [Capability::ReadBalance].into_iter().collect(),
            )
            .unwrap();
        assert_eq!(paired.capabilities.len(), 1);
        assert_eq!(
            pairing.reject(121, &pending.submission_commitment),
            Err(ConnectorError::PairingConsumed)
        );
    }

    #[test]
    fn expired_rejected_and_invalid_pairings_fail_closed() {
        let key = AgentIdentityKey::generate();
        let mut expired =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 10, 2).unwrap();
        assert_eq!(
            expired.submit(111, request(expired.pairing_id(), &key)),
            Err(ConnectorError::Expired)
        );

        let mut rejected =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 60, 2).unwrap();
        let rejected_pending = rejected
            .submit(101, request(rejected.pairing_id(), &key))
            .unwrap();
        rejected
            .reject(102, &rejected_pending.submission_commitment)
            .unwrap();
        assert_eq!(
            rejected.approve(
                103,
                &rejected_pending.submission_commitment,
                [Capability::ReadBalance].into_iter().collect(),
            ),
            Err(ConnectorError::PairingConsumed)
        );

        let mut invalid =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 60, 2).unwrap();
        let mut invalid_request = request(invalid.pairing_id(), &key);
        invalid_request.identity_public_key_sec1_hex = "00".into();
        assert_eq!(
            invalid.submit(101, invalid_request),
            Err(ConnectorError::InvalidIdentity)
        );
    }

    #[test]
    fn identity_rehydrates_without_any_private_key_export_api() {
        let secret = [9_u8; 32];
        let first = AgentIdentityKey::from_secret_bytes(&secret).unwrap();
        let second = AgentIdentityKey::from_secret_bytes(&secret).unwrap();
        assert_eq!(first.public_key_sec1_hex(), second.public_key_sec1_hex());
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert!(AgentIdentityKey::from_secret_bytes(&[0_u8; 32]).is_err());
    }

    #[test]
    fn first_valid_submission_is_immutable_and_approval_is_exact_cas() {
        let first_key = AgentIdentityKey::generate();
        let second_key = AgentIdentityKey::generate();
        let mut pairing =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 60, 3).unwrap();
        let first_request = request(pairing.pairing_id(), &first_key);
        let pending = pairing.submit(101, first_request.clone()).unwrap();
        assert_eq!(
            pairing.submit(102, first_request).unwrap(),
            pending,
            "an exact transport retry must be idempotent"
        );
        assert_eq!(
            pairing.submit(103, request(pairing.pairing_id(), &second_key)),
            Err(ConnectorError::AuthenticationFailed)
        );
        let wrong_commitment =
            PairingSubmissionCommitment::for_request(&request(pairing.pairing_id(), &second_key))
                .unwrap();
        assert_eq!(
            pairing.approve(
                104,
                &wrong_commitment,
                [Capability::ReadBalance].into_iter().collect(),
            ),
            Err(ConnectorError::AuthenticationFailed)
        );
        let paired = pairing
            .approve(
                105,
                &pending.submission_commitment,
                [Capability::ReadBalance].into_iter().collect(),
            )
            .unwrap();
        assert_eq!(paired.identity_fingerprint, first_key.fingerprint());
    }

    #[test]
    fn bearer_is_strict_redacted_and_shared_until_the_last_drop() {
        let raw = format!("pair_{}", "ab".repeat(32));
        let bearer = PairingBearer::parse(raw.clone()).unwrap();
        let shared = bearer.clone();
        assert!(Arc::ptr_eq(&bearer.storage, &shared.storage));
        let weak = Arc::downgrade(&bearer.storage);
        assert!(!format!("{bearer:?}").contains(&raw));
        drop(bearer);
        assert_eq!(weak.strong_count(), 1);
        drop(shared);
        assert!(weak.upgrade().is_none());

        assert!(PairingBearer::parse(format!("pair_{}", "AB".repeat(32))).is_err());
        assert!(PairingBearer::parse(format!("pair_{}", "ag".repeat(32))).is_err());
        assert!(PairingBearer::parse("pair_short".to_owned()).is_err());
    }

    #[test]
    fn zeroizing_storage_supports_explicit_memory_clear() {
        let bearer = PairingBearer::parse(format!("pair_{}", "cd".repeat(32))).unwrap();
        let mut storage = match Arc::try_unwrap(bearer.storage) {
            Ok(storage) => storage,
            Err(_) => panic!("test bearer unexpectedly has another owner"),
        };
        storage.zeroize();
        assert!(storage.is_empty());
    }

    #[test]
    fn request_debug_never_contains_the_bearer_pairing_id() {
        let key = AgentIdentityKey::generate();
        let pairing_id = format!("pair_{}", "ab".repeat(32));
        let request = request(&pairing_id, &key);
        let debug = format!("{request:?}");
        assert!(!debug.contains(&pairing_id));
        assert!(debug.contains("[REDACTED]"));
        let wire = serde_json::to_string(&request).unwrap();
        assert!(wire.contains(&pairing_id));
        assert_eq!(
            serde_json::from_str::<PairingRequest>(&wire).unwrap(),
            request
        );
    }

    #[test]
    fn public_identity_is_stored_in_one_canonical_encoding() {
        let key = AgentIdentityKey::generate();
        let compressed = key.public_key_sec1_hex();
        let uncompressed = hex::encode(
            parse_verifying_key(&compressed)
                .unwrap()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut pairing =
            PairingSession::activate(AgentWalletId::new(), pinned_server(), 100, 60, 2).unwrap();
        let mut request = request(pairing.pairing_id(), &key);
        request.identity_public_key_sec1_hex = uncompressed;
        let pending = pairing.submit(101, request).unwrap();
        assert_eq!(pending.request.identity_public_key_sec1_hex, compressed);
    }
}
