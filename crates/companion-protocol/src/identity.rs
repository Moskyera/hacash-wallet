use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

#[cfg(any(test, feature = "dev-software-identity"))]
use p256::ecdsa::SigningKey;
#[cfg(any(test, feature = "dev-software-identity"))]
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::codec::{CanonicalEncode, Encoder};
use crate::error::{CompanionError, CompanionResult};

const IDENTITY_FINGERPRINT_DOMAIN: &[u8] = b"HPAY/COMPANION/DEVICE-IDENTITY/V1";
const MAX_DEVICE_ID_BYTES: usize = 128;
const MAX_DEVICE_REGISTRY_RECORDS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn parse(raw: impl Into<String>) -> CompanionResult<Self> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > MAX_DEVICE_ID_BYTES
            || !raw.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
            })
        {
            return Err(CompanionError::InvalidDeviceId);
        }
        Ok(Self(raw))
    }

    pub fn random(role: DeviceRole) -> Self {
        let prefix = match role {
            DeviceRole::Desktop => "desktop_",
            DeviceRole::Mobile => "mobile_",
        };
        let mut random = [0_u8; 16];
        use rand::RngCore;
        OsRng.fill_bytes(&mut random);
        Self(format!("{prefix}{}", hex::encode(random)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    Desktop,
    Mobile,
}

impl DeviceRole {
    fn tag(self) -> u8 {
        match self {
            Self::Desktop => 1,
            Self::Mobile => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePermission {
    ViewAgentWalletStatus,
    ViewPendingApprovals,
    ApprovePayment,
    RejectPayment,
    ViewAgents,
    EmergencyStop,
    RevokeAgent,
    RevokeMobileDevice,
    LowerSpendingLimits,
    WitnessRollbackAnchor,
}

/// The only companion payload classes that a platform identity key may sign.
///
/// The canonical payload already contains its HPAY domain prefix. This enum is
/// an additional native-bridge guard and must be used to select the matching
/// biometric prompt and audit label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSignaturePurpose {
    PairingRequest,
    PairingConfirmation,
    PairingMobileProof,
    SessionChallenge,
    SessionResponse,
    SessionConfirmation,
    ApprovalDecision,
    AdminCommand,
    RollbackAnchor,
    WitnessReceipt,
    WitnessRotationAuthorization,
    RotationPairingTicket,
    RotationCandidateAcceptance,
    WitnessRotationBaselineReceipt,
}

/// A typed request handed to Android Keystore or Apple Secure Enclave code.
///
/// Construction is crate-private, so application code cannot turn the
/// companion identity into an arbitrary-message signing API.
#[derive(Clone, Copy)]
pub struct DeviceSigningRequest<'a> {
    purpose: DeviceSignaturePurpose,
    canonical_payload: &'a [u8],
}

impl std::fmt::Debug for DeviceSigningRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSigningRequest")
            .field("purpose", &self.purpose)
            .field(
                "payload_sha256",
                &hex::encode(Sha256::digest(self.canonical_payload)),
            )
            .finish()
    }
}

impl<'a> DeviceSigningRequest<'a> {
    pub fn purpose(&self) -> DeviceSignaturePurpose {
        self.purpose
    }

    /// Exact domain-separated bytes to sign with ECDSA P-256 + SHA-256.
    pub fn canonical_payload(&self) -> &'a [u8] {
        self.canonical_payload
    }

    fn new(purpose: DeviceSignaturePurpose, canonical_payload: &'a [u8]) -> Self {
        Self {
            purpose,
            canonical_payload,
        }
    }
}

/// P-256 signature returned by a native platform bridge.
///
/// Android and Apple APIs commonly return ASN.1 DER while Rust libraries use a
/// fixed 64-byte r||s value. Both are accepted and normalized to the existing
/// fixed-size wire representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformP256Signature {
    Fixed([u8; 64]),
    Der(Vec<u8>),
}

impl PlatformP256Signature {
    pub fn from_fixed_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let fixed: [u8; 64] = bytes
            .try_into()
            .map_err(|_| CompanionError::InvalidSignature)?;
        Signature::from_slice(&fixed).map_err(|_| CompanionError::InvalidSignature)?;
        Ok(Self::Fixed(fixed))
    }

    pub fn from_der_bytes(bytes: impl Into<Vec<u8>>) -> CompanionResult<Self> {
        let bytes = bytes.into();
        Signature::from_der(&bytes).map_err(|_| CompanionError::InvalidSignature)?;
        Ok(Self::Der(bytes))
    }

    fn normalized_signature(&self) -> CompanionResult<Signature> {
        let signature = match self {
            Self::Fixed(bytes) => {
                Signature::from_slice(bytes).map_err(|_| CompanionError::InvalidSignature)?
            }
            Self::Der(bytes) => {
                Signature::from_der(bytes).map_err(|_| CompanionError::InvalidSignature)?
            }
        };
        Ok(signature.normalize_s().unwrap_or(signature))
    }

    fn normalized_fixed_hex(&self) -> CompanionResult<String> {
        Ok(hex::encode(self.normalized_signature()?.to_bytes()))
    }
}

/// Public, immutable metadata for a non-exportable platform identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDeviceIdentity {
    device_id: DeviceId,
    role: DeviceRole,
    public_key_sec1: Vec<u8>,
}

impl PlatformDeviceIdentity {
    pub fn new(
        device_id: DeviceId,
        role: DeviceRole,
        public_key_sec1: impl Into<Vec<u8>>,
    ) -> CompanionResult<Self> {
        let public_key_sec1 = public_key_sec1.into();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_sec1)
            .map_err(|_| CompanionError::InvalidIdentityKey)?;
        Ok(Self {
            device_id,
            role,
            public_key_sec1: verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn role(&self) -> DeviceRole {
        self.role
    }

    pub fn public_key_sec1(&self) -> &[u8] {
        &self.public_key_sec1
    }

    pub fn public_key_sec1_hex(&self) -> String {
        hex::encode(&self.public_key_sec1)
    }

    pub fn fingerprint(&self) -> CompanionResult<String> {
        identity_fingerprint(&self.device_id, self.role, &self.public_key_sec1)
    }

    pub fn public_record(
        &self,
        agent_wallet_id: &str,
        permissions: BTreeSet<DevicePermission>,
        paired_at: u64,
    ) -> CompanionResult<DevicePublicRecord> {
        let record = DevicePublicRecord {
            record_version: 1,
            device_id: self.device_id.clone(),
            role: self.role,
            agent_wallet_id: agent_wallet_id.to_owned(),
            identity_public_key_sec1_hex: self.public_key_sec1_hex(),
            identity_fingerprint: self.fingerprint()?,
            authorization_epoch: 1,
            permissions,
            paired_at,
            revoked_at: None,
        };
        record.validate()?;
        Ok(record)
    }
}

pub type PlatformSignFuture<'a> =
    Pin<Box<dyn Future<Output = CompanionResult<PlatformP256Signature>> + Send + 'a>>;

/// Adapter boundary implemented by Android Keystore or Apple Secure Enclave.
///
/// Production implementations own only a platform key alias/reference. The
/// private key is generated in hardware-backed storage when available, never
/// enters Rust memory, and is never exportable through this API.
pub trait PlatformDeviceSigner: Send + Sync {
    fn identity(&self) -> &PlatformDeviceIdentity;

    fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a>;
}

/// Public-key-only verifier for platform identity signatures.
#[derive(Clone)]
pub struct DeviceSignatureVerifier {
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for DeviceSignatureVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSignatureVerifier")
            .field(
                "public_key_sec1",
                &hex::encode(self.verifying_key.to_encoded_point(true).as_bytes()),
            )
            .finish()
    }
}

impl DeviceSignatureVerifier {
    pub fn from_identity(identity: &PlatformDeviceIdentity) -> CompanionResult<Self> {
        Self::from_sec1_bytes(identity.public_key_sec1())
    }

    pub fn from_public_record(record: &DevicePublicRecord) -> CompanionResult<Self> {
        record.validate()?;
        let bytes = hex::decode(&record.identity_public_key_sec1_hex)
            .map_err(|_| CompanionError::InvalidIdentityKey)?;
        Self::from_sec1_bytes(&bytes)
    }

    fn from_sec1_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let verifying_key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CompanionError::InvalidIdentityKey)?;
        Ok(Self { verifying_key })
    }

    pub fn verify(
        &self,
        request: DeviceSigningRequest<'_>,
        signature: &PlatformP256Signature,
    ) -> CompanionResult<()> {
        self.verifying_key
            .verify(
                request.canonical_payload(),
                &signature.normalized_signature()?,
            )
            .map_err(|_| CompanionError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicRecord {
    #[serde(with = "crate::serde_decimal_u64")]
    pub record_version: u64,
    pub device_id: DeviceId,
    pub role: DeviceRole,
    pub agent_wallet_id: String,
    pub identity_public_key_sec1_hex: String,
    pub identity_fingerprint: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub authorization_epoch: u64,
    pub permissions: BTreeSet<DevicePermission>,
    #[serde(with = "crate::serde_decimal_u64")]
    pub paired_at: u64,
    #[serde(with = "crate::serde_decimal_u64::option")]
    pub revoked_at: Option<u64>,
}

impl DevicePublicRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub(crate) fn verify_signature(
        &self,
        purpose: DeviceSignaturePurpose,
        message: &[u8],
        signature_hex: &str,
    ) -> CompanionResult<()> {
        if self.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        let signature_bytes =
            hex::decode(signature_hex).map_err(|_| CompanionError::InvalidSignature)?;
        let signature = PlatformP256Signature::from_fixed_bytes(&signature_bytes)?;
        DeviceSignatureVerifier::from_public_record(self)?
            .verify(DeviceSigningRequest::new(purpose, message), &signature)
    }

    pub fn validate(&self) -> CompanionResult<()> {
        if self.record_version != 1
            || self.agent_wallet_id.is_empty()
            || self.authorization_epoch == 0
            || self.paired_at == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        if self
            .revoked_at
            .is_some_and(|revoked_at| revoked_at < self.paired_at || self.authorization_epoch < 2)
        {
            return Err(CompanionError::MalformedMessage);
        }
        let public = hex::decode(&self.identity_public_key_sec1_hex)
            .map_err(|_| CompanionError::InvalidIdentityKey)?;
        VerifyingKey::from_sec1_bytes(&public).map_err(|_| CompanionError::InvalidIdentityKey)?;
        let expected = identity_fingerprint(&self.device_id, self.role, &public)?;
        if expected != self.identity_fingerprint {
            return Err(CompanionError::FingerprintMismatch);
        }
        if self.role == DeviceRole::Desktop
            && (self.permissions.contains(&DevicePermission::ApprovePayment)
                || self.permissions.contains(&DevicePermission::RejectPayment))
        {
            return Err(CompanionError::PermissionDenied);
        }
        Ok(())
    }
}

pub(crate) async fn sign_with_platform(
    signer: &dyn PlatformDeviceSigner,
    purpose: DeviceSignaturePurpose,
    canonical_payload: &[u8],
) -> CompanionResult<String> {
    let request = DeviceSigningRequest::new(purpose, canonical_payload);
    let signature = signer.sign(request).await?;
    DeviceSignatureVerifier::from_identity(signer.identity())?.verify(request, &signature)?;
    signature.normalized_fixed_hex()
}

/// Explicit test/development signer. Never enabled in a production default
/// build and deliberately exposes no private-key export method.
#[cfg(any(test, feature = "dev-software-identity"))]
pub struct SoftwareDeviceIdentity {
    identity: PlatformDeviceIdentity,
    signing_key: SigningKey,
}

#[cfg(any(test, feature = "dev-software-identity"))]
impl std::fmt::Debug for SoftwareDeviceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareDeviceIdentity")
            .field("identity", &self.identity)
            .field("private_key", &"<test-or-development-only>")
            .finish()
    }
}

#[cfg(any(test, feature = "dev-software-identity"))]
impl SoftwareDeviceIdentity {
    pub fn generate(role: DeviceRole) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let identity = PlatformDeviceIdentity::new(
            DeviceId::random(role),
            role,
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .expect("generated P-256 public key is valid");
        Self {
            identity,
            signing_key,
        }
    }

    pub fn device_id(&self) -> &DeviceId {
        self.identity.device_id()
    }

    pub fn public_record(
        &self,
        agent_wallet_id: &str,
        permissions: BTreeSet<DevicePermission>,
        paired_at: u64,
    ) -> CompanionResult<DevicePublicRecord> {
        self.identity
            .public_record(agent_wallet_id, permissions, paired_at)
    }
}

#[cfg(any(test, feature = "dev-software-identity"))]
impl PlatformDeviceSigner for SoftwareDeviceIdentity {
    fn identity(&self) -> &PlatformDeviceIdentity {
        &self.identity
    }

    fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a> {
        Box::pin(async move {
            let signature: Signature = self.signing_key.sign(request.canonical_payload());
            PlatformP256Signature::from_fixed_bytes(signature.to_bytes().as_slice())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistry {
    #[serde(with = "crate::serde_decimal_u64")]
    pub registry_version: u64,
    devices: BTreeMap<DeviceId, DevicePublicRecord>,
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            registry_version: 1,
            devices: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, record: DevicePublicRecord) -> CompanionResult<()> {
        self.validate()?;
        record.validate()?;
        if record.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        if record.authorization_epoch != 1 {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        if let Some(existing) = self.devices.get(&record.device_id) {
            existing.validate()?;
            if existing.is_revoked() {
                return Err(CompanionError::DeviceRevoked);
            }
            if existing == &record {
                // Exact retry is idempotent and performs no state transition.
                return Ok(());
            }
            if existing.identity_fingerprint != record.identity_fingerprint
                || existing.agent_wallet_id != record.agent_wallet_id
                || existing.role != record.role
            {
                return Err(CompanionError::WalletScopeMismatch);
            }
            // Permissions, authorization epoch, paired_at, or revocation state
            // may change only through a dedicated authenticated transition.
            // register must never act as an implicit re-pair or revival API.
            return Err(CompanionError::DeviceAlreadyRegistered);
        }
        if self.devices.len() >= MAX_DEVICE_REGISTRY_RECORDS {
            return Err(CompanionError::MessageTooLarge);
        }
        self.devices.insert(record.device_id.clone(), record);
        Ok(())
    }

    /// The dedicated authenticated transition for the one delta `register`
    /// deliberately refuses: an identity this registry already trusts pairing
    /// again and moving `paired_at` forward.
    ///
    /// This admits nothing. The device must already be present and not revoked,
    /// and every authorization-bearing field — identity key, fingerprint,
    /// wallet scope, role, authorization epoch, permissions, revocation state —
    /// must be byte-identical to the stored record. `paired_at` is the only
    /// field allowed to differ, and only forwards. An unknown device, a revoked
    /// device, a permission or epoch delta, and a rewound timestamp are all
    /// refused, so this can neither admit, revive, nor re-authorize anything.
    pub fn refresh_verified_pairing(&mut self, record: DevicePublicRecord) -> CompanionResult<()> {
        self.validate()?;
        record.validate()?;
        if record.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        if record.authorization_epoch != 1 {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        let existing = self
            .devices
            .get(&record.device_id)
            .ok_or(CompanionError::UnknownDevice)?;
        existing.validate()?;
        if existing.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        if existing.identity_fingerprint != record.identity_fingerprint
            || existing.agent_wallet_id != record.agent_wallet_id
            || existing.role != record.role
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        if record.paired_at < existing.paired_at {
            return Err(CompanionError::MalformedMessage);
        }
        let mut permitted = existing.clone();
        permitted.paired_at = record.paired_at;
        if permitted != record {
            // Some field other than the pairing timestamp moved. That is not a
            // re-pair of the same trust grant and must use its own transition.
            return Err(CompanionError::DeviceAlreadyRegistered);
        }
        self.devices.insert(record.device_id.clone(), record);
        Ok(())
    }

    pub fn validate(&self) -> CompanionResult<()> {
        if self.registry_version != 1 {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.devices.len() > MAX_DEVICE_REGISTRY_RECORDS {
            return Err(CompanionError::MessageTooLarge);
        }
        for (device_id, record) in &self.devices {
            record.validate()?;
            if device_id != &record.device_id {
                return Err(CompanionError::MalformedMessage);
            }
        }
        Ok(())
    }

    pub fn require(
        &self,
        device_id: &DeviceId,
        wallet_id: &str,
        role: DeviceRole,
        permission: DevicePermission,
    ) -> CompanionResult<&DevicePublicRecord> {
        let record = self
            .devices
            .get(device_id)
            .ok_or(CompanionError::UnknownDevice)?;
        record.validate()?;
        if record.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        if record.agent_wallet_id != wallet_id || record.role != role {
            return Err(CompanionError::WalletScopeMismatch);
        }
        if !record.permissions.contains(&permission) {
            return Err(CompanionError::PermissionDenied);
        }
        Ok(record)
    }

    pub fn revoke(&mut self, device_id: &DeviceId, revoked_at: u64) -> CompanionResult<()> {
        self.validate()?;
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(CompanionError::UnknownDevice)?;
        record.validate()?;
        if record.is_revoked() {
            return Err(CompanionError::DeviceRevoked);
        }
        if revoked_at < record.paired_at {
            return Err(CompanionError::MalformedMessage);
        }
        let next_epoch = record
            .authorization_epoch
            .checked_add(1)
            .ok_or(CompanionError::AuthorizationEpochMismatch)?;
        record.revoked_at = Some(revoked_at);
        record.authorization_epoch = next_epoch;
        Ok(())
    }

    pub fn records(&self) -> impl Iterator<Item = &DevicePublicRecord> {
        self.devices.values()
    }
}

fn identity_fingerprint(
    device_id: &DeviceId,
    role: DeviceRole,
    public_key: &[u8],
) -> CompanionResult<String> {
    let mut encoder = Encoder::new(IDENTITY_FINGERPRINT_DOMAIN)?;
    encoder.push_u64(1);
    encoder.push_string(device_id.as_str())?;
    encoder.push_u8(role.tag());
    encoder.push_bytes(public_key)?;
    Ok(hex::encode(Sha256::digest(encoder.finish()?)))
}

impl CanonicalEncode for DevicePublicRecord {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.record_version);
        encoder.push_string(self.device_id.as_str())?;
        encoder.push_u8(self.role.tag());
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(&self.identity_public_key_sec1_hex)?;
        encoder.push_string(&self.identity_fingerprint)?;
        encoder.push_u64(self.authorization_epoch);
        encoder.push_u64(self.paired_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlternatePlatformSigner {
        identity: PlatformDeviceIdentity,
        signing_key: SigningKey,
        der: bool,
    }

    impl AlternatePlatformSigner {
        fn mismatched() -> Self {
            let advertised = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
            let actual = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
            Self {
                identity: advertised.identity,
                signing_key: actual.signing_key,
                der: false,
            }
        }

        fn der() -> Self {
            let software = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
            Self {
                identity: software.identity,
                signing_key: software.signing_key,
                der: true,
            }
        }
    }

    impl PlatformDeviceSigner for AlternatePlatformSigner {
        fn identity(&self) -> &PlatformDeviceIdentity {
            &self.identity
        }

        fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a> {
            Box::pin(async move {
                let signature: Signature = self.signing_key.sign(request.canonical_payload());
                if self.der {
                    PlatformP256Signature::from_der_bytes(signature.to_der().as_bytes().to_vec())
                } else {
                    let fixed: [u8; 64] = signature.to_bytes().into();
                    PlatformP256Signature::from_fixed_bytes(&fixed)
                }
            })
        }
    }

    #[tokio::test]
    async fn p256_identity_roundtrip_and_tamper_detection() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let record = identity
            .public_record(
                "aw_test",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();
        let message = b"canonical approval";
        let signature =
            sign_with_platform(&identity, DeviceSignaturePurpose::ApprovalDecision, message)
                .await
                .unwrap();
        record
            .verify_signature(
                DeviceSignaturePurpose::ApprovalDecision,
                message,
                &signature,
            )
            .unwrap();

        let mut changed = message.to_vec();
        changed[0] ^= 1;
        assert_eq!(
            record.verify_signature(
                DeviceSignaturePurpose::ApprovalDecision,
                &changed,
                &signature,
            ),
            Err(CompanionError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn registry_fails_closed_for_cross_wallet_and_revoked_device() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                identity
                    .public_record(
                        "aw_one",
                        BTreeSet::from([DevicePermission::EmergencyStop]),
                        10,
                    )
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            registry.require(
                identity.device_id(),
                "aw_two",
                DeviceRole::Mobile,
                DevicePermission::EmergencyStop
            ),
            Err(CompanionError::WalletScopeMismatch)
        );
        registry.revoke(identity.device_id(), 20).unwrap();
        assert_eq!(
            registry.require(
                identity.device_id(),
                "aw_one",
                DeviceRole::Mobile,
                DevicePermission::EmergencyStop
            ),
            Err(CompanionError::DeviceRevoked)
        );
    }

    #[test]
    fn registry_never_replaces_or_revives_an_existing_device() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let original = identity
            .public_record(
                "aw_one",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();
        let mut registry = DeviceRegistry::new();
        registry.register(original.clone()).unwrap();
        registry.register(original.clone()).unwrap();

        let mut expanded = original.clone();
        expanded.permissions.insert(DevicePermission::EmergencyStop);
        assert_eq!(
            registry.register(expanded),
            Err(CompanionError::DeviceAlreadyRegistered)
        );
        assert_eq!(
            registry.require(
                identity.device_id(),
                "aw_one",
                DeviceRole::Mobile,
                DevicePermission::EmergencyStop,
            ),
            Err(CompanionError::PermissionDenied)
        );

        let cross_wallet = identity
            .public_record(
                "aw_two",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                11,
            )
            .unwrap();
        assert_eq!(
            registry.register(cross_wallet),
            Err(CompanionError::WalletScopeMismatch)
        );

        registry.revoke(identity.device_id(), 20).unwrap();
        let revival = identity
            .public_record(
                "aw_one",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                21,
            )
            .unwrap();
        assert_eq!(
            registry.register(revival),
            Err(CompanionError::DeviceRevoked)
        );
        let stored = registry
            .records()
            .find(|record| &record.device_id == identity.device_id())
            .unwrap();
        assert_eq!(stored.revoked_at, Some(20));
        assert_eq!(stored.authorization_epoch, 2);
    }

    #[test]
    fn repair_transition_moves_only_the_pairing_timestamp_forward() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let original = identity
            .public_record(
                "aw_one",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();

        // It admits nothing: an unknown identity is refused outright.
        let mut empty = DeviceRegistry::new();
        assert_eq!(
            empty.refresh_verified_pairing(original.clone()),
            Err(CompanionError::UnknownDevice)
        );

        let mut registry = DeviceRegistry::new();
        registry.register(original.clone()).unwrap();

        let mut escalated = original.clone();
        escalated.paired_at = 30;
        escalated
            .permissions
            .insert(DevicePermission::EmergencyStop);
        assert_eq!(
            registry.refresh_verified_pairing(escalated),
            Err(CompanionError::DeviceAlreadyRegistered)
        );

        let cross_wallet = identity
            .public_record(
                "aw_two",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                30,
            )
            .unwrap();
        assert_eq!(
            registry.refresh_verified_pairing(cross_wallet),
            Err(CompanionError::WalletScopeMismatch)
        );

        let mut rewound = original.clone();
        rewound.paired_at = 9;
        assert_eq!(
            registry.refresh_verified_pairing(rewound),
            Err(CompanionError::MalformedMessage)
        );

        let mut stale_epoch = original.clone();
        stale_epoch.paired_at = 30;
        stale_epoch.authorization_epoch = 2;
        assert_eq!(
            registry.refresh_verified_pairing(stale_epoch),
            Err(CompanionError::AuthorizationEpochMismatch)
        );

        let mut refreshed = original.clone();
        refreshed.paired_at = 30;
        registry
            .refresh_verified_pairing(refreshed.clone())
            .unwrap();
        assert_eq!(
            registry
                .records()
                .find(|record| &record.device_id == identity.device_id())
                .unwrap(),
            &refreshed
        );
        registry.validate().unwrap();

        // It never revives: a revoked identity stays revoked.
        registry.revoke(identity.device_id(), 40).unwrap();
        let mut revival = original.clone();
        revival.paired_at = 50;
        assert_eq!(
            registry.refresh_verified_pairing(revival),
            Err(CompanionError::DeviceRevoked)
        );
    }

    #[test]
    fn register_accepts_only_active_epoch_one_pairing_records() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let original = identity
            .public_record(
                "aw_one",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();
        let mut registry = DeviceRegistry::new();

        let mut tombstone = original.clone();
        tombstone.authorization_epoch = 2;
        tombstone.revoked_at = Some(20);
        assert_eq!(
            registry.register(tombstone),
            Err(CompanionError::DeviceRevoked)
        );

        let mut stale_active = original.clone();
        stale_active.authorization_epoch = 2;
        assert_eq!(
            registry.register(stale_active),
            Err(CompanionError::AuthorizationEpochMismatch)
        );
        registry.register(original).unwrap();
        registry.validate().unwrap();
        assert_eq!(DeviceRegistry::default(), DeviceRegistry::new());
        DeviceRegistry::default().validate().unwrap();
    }

    #[test]
    fn registry_validate_accepts_lawful_tombstone_and_rejects_adversarial_state() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut tombstone = identity
            .public_record(
                "aw_one",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();
        tombstone.authorization_epoch = 2;
        tombstone.revoked_at = Some(20);
        let mut registry = DeviceRegistry::new();
        registry
            .devices
            .insert(tombstone.device_id.clone(), tombstone.clone());
        registry.validate().unwrap();

        let mut zero_paired_at = tombstone.clone();
        zero_paired_at.paired_at = 0;
        assert_eq!(
            zero_paired_at.validate(),
            Err(CompanionError::MalformedMessage)
        );
        let mut early_revoke = tombstone.clone();
        early_revoke.revoked_at = Some(9);
        assert_eq!(
            early_revoke.validate(),
            Err(CompanionError::MalformedMessage)
        );
        let mut epoch_one_tombstone = tombstone.clone();
        epoch_one_tombstone.authorization_epoch = 1;
        assert_eq!(
            epoch_one_tombstone.validate(),
            Err(CompanionError::MalformedMessage)
        );

        let wrong_key = DeviceId::parse("mobile_wrong_map_key").unwrap();
        let mut mismatched = DeviceRegistry::new();
        mismatched.devices.insert(wrong_key, tombstone);
        assert_eq!(mismatched.validate(), Err(CompanionError::MalformedMessage));
        let encoded = serde_json::to_vec(&mismatched).unwrap();
        let decoded: DeviceRegistry = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.validate(), Err(CompanionError::MalformedMessage));
    }

    #[test]
    fn revoke_epoch_overflow_and_invalid_time_fail_without_mutation() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut record = identity
            .public_record("aw_one", BTreeSet::new(), 10)
            .unwrap();
        record.authorization_epoch = u64::MAX;
        let device_id = record.device_id.clone();
        let mut registry = DeviceRegistry::new();
        registry.devices.insert(device_id.clone(), record);
        assert_eq!(
            registry.revoke(&device_id, 20),
            Err(CompanionError::AuthorizationEpochMismatch)
        );
        let stored = registry.devices.get(&device_id).unwrap();
        assert_eq!(stored.authorization_epoch, u64::MAX);
        assert_eq!(stored.revoked_at, None);
        assert_eq!(
            registry.revoke(&device_id, 9),
            Err(CompanionError::MalformedMessage)
        );
        assert_eq!(registry.devices.get(&device_id).unwrap().revoked_at, None);
    }

    #[tokio::test]
    async fn platform_der_signature_is_normalized_and_key_mismatch_fails_closed() {
        let der_signer = AlternatePlatformSigner::der();
        let record = der_signer
            .identity()
            .public_record(
                "aw_test",
                BTreeSet::from([DevicePermission::ApprovePayment]),
                10,
            )
            .unwrap();
        let payload = b"domain-separated canonical approval";
        let signature = sign_with_platform(
            &der_signer,
            DeviceSignaturePurpose::ApprovalDecision,
            payload,
        )
        .await
        .unwrap();
        assert_eq!(signature.len(), 128);
        record
            .verify_signature(
                DeviceSignaturePurpose::ApprovalDecision,
                payload,
                &signature,
            )
            .unwrap();

        assert_eq!(
            sign_with_platform(
                &AlternatePlatformSigner::mismatched(),
                DeviceSignaturePurpose::ApprovalDecision,
                payload,
            )
            .await,
            Err(CompanionError::InvalidSignature)
        );
    }

    #[test]
    fn identity_json_u64_fields_are_strict_decimal_strings() {
        let identity = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut record = identity
            .public_record("aw_one", BTreeSet::new(), 10)
            .unwrap();
        record.record_version = u64::MAX;
        record.authorization_epoch = u64::MAX;
        record.paired_at = u64::MAX;
        record.revoked_at = Some(u64::MAX);

        let record_value = serde_json::to_value(&record).unwrap();
        for field in [
            "record_version",
            "authorization_epoch",
            "paired_at",
            "revoked_at",
        ] {
            assert_eq!(record_value[field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(
            serde_json::from_value::<DevicePublicRecord>(record_value.clone()).unwrap(),
            record
        );

        let mut numeric_record = record_value.clone();
        numeric_record["authorization_epoch"] = serde_json::json!(1);
        assert!(serde_json::from_value::<DevicePublicRecord>(numeric_record).is_err());
        let mut numeric_option = record_value;
        numeric_option["revoked_at"] = serde_json::json!(1);
        assert!(serde_json::from_value::<DevicePublicRecord>(numeric_option).is_err());

        let mut registry = DeviceRegistry::new();
        registry.registry_version = u64::MAX;
        registry.devices.insert(record.device_id.clone(), record);
        let registry_value = serde_json::to_value(&registry).unwrap();
        assert_eq!(
            registry_value["registry_version"],
            serde_json::json!(u64::MAX.to_string())
        );
        assert_eq!(
            serde_json::from_value::<DeviceRegistry>(registry_value.clone()).unwrap(),
            registry
        );
        let mut numeric_registry = registry_value;
        numeric_registry["registry_version"] = serde_json::json!(1);
        assert!(serde_json::from_value::<DeviceRegistry>(numeric_registry).is_err());
    }

    #[tokio::test]
    async fn registry_json_rejects_unknown_fields() {
        let raw = r#"{"registry_version":1,"devices":{},"private_key":"forbidden"}"#;
        assert!(serde_json::from_str::<DeviceRegistry>(raw).is_err());
    }
}
