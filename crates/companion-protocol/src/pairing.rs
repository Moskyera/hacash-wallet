mod ack;
mod endpoint;
mod proof;
#[cfg(test)]
mod tests;

pub use endpoint::LanEndpoint;
pub use proof::MobilePairingProof;

use std::collections::BTreeSet;

use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::codec::{CanonicalEncode, Encoder};
use crate::envelope::{EncryptedCompanionFrame, SessionCipher};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DevicePublicRecord, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};

use self::endpoint::MAX_LAN_ENDPOINTS;

const PAIRING_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING/V1";
const PAIRING_REQUEST_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING-REQUEST/V1";
const PAIRING_CONFIRMATION_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING-CONFIRMATION/V1";
const PAIRING_KDF_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING-SESSION-KEY/V1";
const MAX_PAIRING_LIFETIME_SECS: u64 = 5 * 60;
const MAX_LOCAL_CONFIRMATION_ATTEMPTS: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingOffer {
    #[serde(with = "crate::serde_decimal_u64")]
    pub protocol_version: u64,
    pub pairing_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub desktop_ephemeral_public_key: String,
    pub desktop_identity_public_key: String,
    pub desktop_identity_fingerprint: String,
    pub lan_endpoints: Vec<LanEndpoint>,
    pub pairing_nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl PairingOffer {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        CanonicalEncode::canonical_bytes(self, PAIRING_DOMAIN)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        if self.protocol_version != 1 {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.pairing_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.pairing_nonce.len() < 32
            || self.lan_endpoints.len() > MAX_LAN_ENDPOINTS
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at.saturating_sub(self.issued_at) > MAX_PAIRING_LIFETIME_SECS
        {
            return Err(if self.expires_at <= now {
                CompanionError::PairingExpired
            } else {
                CompanionError::PairingMismatch
            });
        }
        decode_x25519_public(&self.desktop_ephemeral_public_key)?;
        Ok(())
    }

    fn desktop_device_record(&self) -> CompanionResult<DevicePublicRecord> {
        let record = DevicePublicRecord {
            record_version: 1,
            device_id: self.desktop_device_id.clone(),
            role: DeviceRole::Desktop,
            agent_wallet_id: self.agent_wallet_id.clone(),
            identity_public_key_sec1_hex: self.desktop_identity_public_key.clone(),
            identity_fingerprint: self.desktop_identity_fingerprint.clone(),
            authorization_epoch: 1,
            permissions: BTreeSet::new(),
            paired_at: self.issued_at,
            revoked_at: None,
        };
        record.validate()?;
        Ok(record)
    }
}

impl CanonicalEncode for PairingOffer {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(&self.desktop_ephemeral_public_key)?;
        encoder.push_string(&self.desktop_identity_public_key)?;
        encoder.push_string(&self.desktop_identity_fingerprint)?;
        if self.lan_endpoints.len() > MAX_LAN_ENDPOINTS {
            return Err(CompanionError::MessageTooLarge);
        }
        encoder.push_u32(self.lan_endpoints.len() as u32);
        for endpoint in &self.lan_endpoints {
            encoder.push_string(&endpoint.to_string())?;
        }
        encoder.push_string(&self.pairing_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    #[serde(with = "crate::serde_decimal_u64")]
    pub protocol_version: u64,
    pub pairing_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub mobile_ephemeral_public_key: String,
    pub mobile_identity_public_key: String,
    pub mobile_identity_fingerprint: String,
    pub pairing_nonce: String,
    pub mobile_challenge: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub identity_signature: String,
}

impl PairingRequest {
    fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        let mut clone = self.clone();
        clone.identity_signature.clear();
        clone.canonical_bytes(PAIRING_REQUEST_DOMAIN)
    }
}

impl CanonicalEncode for PairingRequest {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_string(&self.mobile_ephemeral_public_key)?;
        encoder.push_string(&self.mobile_identity_public_key)?;
        encoder.push_string(&self.mobile_identity_fingerprint)?;
        encoder.push_string(&self.pairing_nonce)?;
        encoder.push_string(&self.mobile_challenge)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingConfirmation {
    #[serde(with = "crate::serde_decimal_u64")]
    pub protocol_version: u64,
    pub pairing_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub desktop_challenge: String,
    pub verification_code: String,
    pub session_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub desktop_identity_signature: String,
}

impl PairingConfirmation {
    fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        let mut clone = self.clone();
        clone.desktop_identity_signature.clear();
        clone.canonical_bytes(PAIRING_CONFIRMATION_DOMAIN)
    }
}

impl CanonicalEncode for PairingConfirmation {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_string(&self.desktop_challenge)?;
        encoder.push_string(&self.verification_code)?;
        encoder.push_string(&self.session_id)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

pub struct MobilePairingAttempt {
    offer: PairingOffer,
    secret: StaticSecret,
    request: PairingRequest,
}

impl std::fmt::Debug for MobilePairingAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MobilePairingAttempt")
            .field("pairing_id", &self.offer.pairing_id)
            .field("mobile_device_id", &self.request.mobile_device_id)
            .field("ephemeral_secret", &"<memory-only>")
            .finish()
    }
}

impl MobilePairingAttempt {
    pub async fn start(
        offer: PairingOffer,
        mobile_signer: &dyn PlatformDeviceSigner,
        now: u64,
    ) -> CompanionResult<Self> {
        offer.validate_at(now)?;
        if mobile_signer.identity().role() != DeviceRole::Mobile {
            return Err(CompanionError::PairingMismatch);
        }
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut challenge = [0_u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let mut request = PairingRequest {
            protocol_version: 1,
            pairing_id: offer.pairing_id.clone(),
            agent_wallet_id: offer.agent_wallet_id.clone(),
            desktop_device_id: offer.desktop_device_id.clone(),
            mobile_device_id: mobile_signer.identity().device_id().clone(),
            mobile_ephemeral_public_key: hex::encode(public.as_bytes()),
            mobile_identity_public_key: mobile_signer.identity().public_key_sec1_hex(),
            mobile_identity_fingerprint: mobile_signer.identity().fingerprint()?,
            pairing_nonce: offer.pairing_nonce.clone(),
            mobile_challenge: hex::encode(challenge),
            issued_at: now,
            expires_at: offer.expires_at,
            identity_signature: String::new(),
        };
        request.identity_signature = sign_with_platform(
            mobile_signer,
            DeviceSignaturePurpose::PairingRequest,
            &request.unsigned_bytes()?,
        )
        .await?;
        Ok(Self {
            offer,
            secret,
            request,
        })
    }

    pub fn request(&self) -> &PairingRequest {
        &self.request
    }

    /// Completes mobile-side verification and signs the exact transcript/code.
    pub async fn confirm(
        self,
        confirmation: &PairingConfirmation,
        locally_confirmed_code: &str,
        mobile_signer: &dyn PlatformDeviceSigner,
        now: u64,
    ) -> CompanionResult<(EncryptedCompanionFrame, PairingResult)> {
        if confirmation.protocol_version != 1
            || confirmation.issued_at < self.request.issued_at
            || confirmation.issued_at > now
            || confirmation.expires_at <= now
            || confirmation.session_id.is_empty()
            || confirmation.desktop_challenge.len() != 64
            || !confirmation
                .desktop_challenge
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(if confirmation.expires_at <= now {
                CompanionError::PairingExpired
            } else {
                CompanionError::PairingMismatch
            });
        }
        if confirmation.pairing_id != self.offer.pairing_id
            || confirmation.agent_wallet_id != self.offer.agent_wallet_id
            || confirmation.desktop_device_id != self.offer.desktop_device_id
            || confirmation.mobile_device_id != self.request.mobile_device_id
            || confirmation.expires_at != self.offer.expires_at
        {
            return Err(CompanionError::PairingMismatch);
        }
        if locally_confirmed_code != confirmation.verification_code {
            return Err(CompanionError::VerificationCodeMismatch);
        }
        let desktop_record = self.offer.desktop_device_record()?;
        desktop_record.verify_signature(
            DeviceSignaturePurpose::PairingConfirmation,
            &confirmation.unsigned_bytes()?,
            &confirmation.desktop_identity_signature,
        )?;
        let desktop_ephemeral = decode_x25519_public(&self.offer.desktop_ephemeral_public_key)?;
        let shared = derive_shared(&self.secret, &desktop_ephemeral)?;
        let material = derive_pairing_material(
            &shared,
            &self.offer,
            &self.request,
            &confirmation.session_id,
        )?;
        if confirmation.verification_code != verification_code(&material) {
            return Err(CompanionError::VerificationCodeMismatch);
        }
        let mobile_record = DevicePublicRecord {
            record_version: 1,
            device_id: self.request.mobile_device_id.clone(),
            role: DeviceRole::Mobile,
            agent_wallet_id: self.request.agent_wallet_id.clone(),
            identity_public_key_sec1_hex: self.request.mobile_identity_public_key.clone(),
            identity_fingerprint: self.request.mobile_identity_fingerprint.clone(),
            authorization_epoch: 1,
            permissions: default_mobile_permissions(),
            paired_at: confirmation.issued_at,
            revoked_at: None,
        };
        mobile_record.validate()?;
        let proof = MobilePairingProof::sign(
            &self.offer,
            &self.request,
            confirmation,
            locally_confirmed_code,
            mobile_signer,
            now,
        )
        .await?;
        let encrypted_ack = ack::encrypt(proof, material.clone(), now)?;
        let result = PairingResult {
            session_id: confirmation.session_id.clone(),
            agent_wallet_id: confirmation.agent_wallet_id.clone(),
            desktop_device_id: confirmation.desktop_device_id.clone(),
            mobile_device_id: confirmation.mobile_device_id.clone(),
            desktop_device_record: desktop_record,
            mobile_device_record: mobile_record,
            verification_code: confirmation.verification_code.clone(),
            expires_at: confirmation.expires_at,
            session_key: material,
        };
        Ok((encrypted_ack, result))
    }
}

pub struct PairingSession {
    offer: PairingOffer,
    secret: StaticSecret,
    consumed: bool,
    cancelled: bool,
    accepted_request: Option<PairingRequest>,
    confirmation: Option<PairingConfirmation>,
    session_key: Option<Zeroizing<[u8; 32]>>,
    verified_mobile_record: Option<DevicePublicRecord>,
    verified_mobile_proof: Option<MobilePairingProof>,
    local_confirmation_attempts: u8,
}

impl std::fmt::Debug for PairingSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("pairing_id", &self.offer.pairing_id)
            .field("consumed", &self.consumed)
            .field("cancelled", &self.cancelled)
            .field("ephemeral_secret", &"<memory-only>")
            .finish()
    }
}

impl PairingSession {
    pub fn new(
        desktop_signer: &dyn PlatformDeviceSigner,
        agent_wallet_id: impl Into<String>,
        lan_endpoints: Vec<LanEndpoint>,
        now: u64,
        lifetime_secs: u64,
    ) -> CompanionResult<Self> {
        if desktop_signer.identity().role() != DeviceRole::Desktop
            || lifetime_secs == 0
            || lifetime_secs > MAX_PAIRING_LIFETIME_SECS
        {
            return Err(CompanionError::PairingMismatch);
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(CompanionError::PairingMismatch)?;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);
        let pairing_id = format!("pair_{}", hex::encode(&random[..16]));
        let pairing_nonce = hex::encode(random);
        let offer = PairingOffer {
            protocol_version: 1,
            pairing_id,
            agent_wallet_id: agent_wallet_id.into(),
            desktop_device_id: desktop_signer.identity().device_id().clone(),
            desktop_ephemeral_public_key: hex::encode(public.as_bytes()),
            desktop_identity_public_key: desktop_signer.identity().public_key_sec1_hex(),
            desktop_identity_fingerprint: desktop_signer.identity().fingerprint()?,
            lan_endpoints,
            pairing_nonce,
            issued_at: now,
            expires_at,
        };
        offer.validate_at(now)?;
        Ok(Self {
            offer,
            secret,
            consumed: false,
            cancelled: false,
            accepted_request: None,
            confirmation: None,
            session_key: None,
            verified_mobile_record: None,
            verified_mobile_proof: None,
            local_confirmation_attempts: 0,
        })
    }

    pub fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    /// Public identity record verified from the signed mobile request.
    /// Available only after `accept_request`; it contains no session key.
    pub fn verified_mobile_record(&self) -> Option<&DevicePublicRecord> {
        self.verified_mobile_record.as_ref()
    }

    pub async fn accept_request(
        &mut self,
        request: PairingRequest,
        desktop_signer: &dyn PlatformDeviceSigner,
        now: u64,
    ) -> CompanionResult<PairingConfirmation> {
        self.require_open(now)?;
        if self.accepted_request.is_some() {
            return Err(CompanionError::PairingAlreadyUsed);
        }
        if desktop_signer.identity().device_id() != &self.offer.desktop_device_id
            || request.protocol_version != 1
            || request.pairing_id != self.offer.pairing_id
            || request.agent_wallet_id != self.offer.agent_wallet_id
            || request.desktop_device_id != self.offer.desktop_device_id
            || request.pairing_nonce != self.offer.pairing_nonce
            || request.mobile_challenge.len() != 64
            || !request
                .mobile_challenge
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || request.issued_at > now
            || request.expires_at != self.offer.expires_at
        {
            return Err(CompanionError::PairingMismatch);
        }
        let mobile_record = DevicePublicRecord {
            record_version: 1,
            device_id: request.mobile_device_id.clone(),
            role: DeviceRole::Mobile,
            agent_wallet_id: request.agent_wallet_id.clone(),
            identity_public_key_sec1_hex: request.mobile_identity_public_key.clone(),
            identity_fingerprint: request.mobile_identity_fingerprint.clone(),
            authorization_epoch: 1,
            permissions: default_mobile_permissions(),
            paired_at: now,
            revoked_at: None,
        };
        mobile_record.validate()?;
        mobile_record.verify_signature(
            DeviceSignaturePurpose::PairingRequest,
            &request.unsigned_bytes()?,
            &request.identity_signature,
        )?;
        let mobile_ephemeral = decode_x25519_public(&request.mobile_ephemeral_public_key)?;
        let shared = derive_shared(&self.secret, &mobile_ephemeral)?;
        let mut session_random = [0_u8; 16];
        let mut desktop_challenge = [0_u8; 32];
        OsRng.fill_bytes(&mut session_random);
        OsRng.fill_bytes(&mut desktop_challenge);
        let session_id = format!("session_{}", hex::encode(session_random));
        let material = derive_pairing_material(&shared, &self.offer, &request, &session_id)?;
        let mut confirmation = PairingConfirmation {
            protocol_version: 1,
            pairing_id: self.offer.pairing_id.clone(),
            agent_wallet_id: self.offer.agent_wallet_id.clone(),
            desktop_device_id: self.offer.desktop_device_id.clone(),
            mobile_device_id: request.mobile_device_id.clone(),
            desktop_challenge: hex::encode(desktop_challenge),
            verification_code: verification_code(&material),
            session_id,
            issued_at: now,
            expires_at: self.offer.expires_at,
            desktop_identity_signature: String::new(),
        };
        confirmation.desktop_identity_signature = sign_with_platform(
            desktop_signer,
            DeviceSignaturePurpose::PairingConfirmation,
            &confirmation.unsigned_bytes()?,
        )
        .await?;
        self.accepted_request = Some(request);
        self.confirmation = Some(confirmation.clone());
        self.verified_mobile_record = Some(mobile_record);
        self.session_key = Some(material);
        Ok(confirmation)
    }

    /// Accept the mobile acknowledgement only through the encrypted pairing
    /// session. Raw proof bytes are never a desktop completion API.
    pub fn accept_encrypted_mobile_ack(
        &mut self,
        frame: &EncryptedCompanionFrame,
        now: u64,
    ) -> CompanionResult<()> {
        self.require_open(now)?;
        if self.verified_mobile_proof.is_some() {
            return Err(CompanionError::PairingAlreadyUsed);
        }
        let confirmation = self
            .confirmation
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?;
        let request = self
            .accepted_request
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?;
        let mobile_record = self
            .verified_mobile_record
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?;
        let key = self
            .session_key
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?
            .clone();
        let mobile_proof = ack::decrypt(
            frame,
            &confirmation.session_id,
            &confirmation.desktop_device_id,
            mobile_record,
            key,
            confirmation.expires_at,
            now,
        )?;
        mobile_proof.verify(&self.offer, request, confirmation, mobile_record, now)?;
        self.verified_mobile_proof = Some(mobile_proof);
        Ok(())
    }

    /// Must be called only by the trusted local desktop UI after it displays
    /// the same human verification code accepted by the mobile device.
    pub fn confirm_code(
        &mut self,
        verification_code: &str,
        now: u64,
    ) -> CompanionResult<PairingResult> {
        self.require_open(now)?;
        if self.verified_mobile_proof.is_none() {
            return Err(CompanionError::PairingMismatch);
        }
        self.local_confirmation_attempts = self
            .local_confirmation_attempts
            .checked_add(1)
            .ok_or(CompanionError::PairingCancelled)?;
        if self.local_confirmation_attempts > MAX_LOCAL_CONFIRMATION_ATTEMPTS {
            self.cancel();
            return Err(CompanionError::PairingCancelled);
        }
        let confirmation = self
            .confirmation
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?;
        if verification_code != confirmation.verification_code {
            return Err(CompanionError::VerificationCodeMismatch);
        }
        let mobile_record = self
            .verified_mobile_record
            .as_ref()
            .ok_or(CompanionError::PairingMismatch)?;
        let key = self
            .session_key
            .take()
            .ok_or(CompanionError::PairingMismatch)?;
        self.consumed = true;
        Ok(PairingResult {
            session_id: confirmation.session_id.clone(),
            agent_wallet_id: confirmation.agent_wallet_id.clone(),
            desktop_device_id: confirmation.desktop_device_id.clone(),
            mobile_device_id: confirmation.mobile_device_id.clone(),
            desktop_device_record: self.offer.desktop_device_record()?,
            mobile_device_record: mobile_record.clone(),
            verification_code: confirmation.verification_code.clone(),
            expires_at: confirmation.expires_at,
            session_key: key,
        })
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.session_key = None;
        self.verified_mobile_proof = None;
    }

    fn require_open(&self, now: u64) -> CompanionResult<()> {
        if self.cancelled {
            return Err(CompanionError::PairingCancelled);
        }
        if self.consumed {
            return Err(CompanionError::PairingAlreadyUsed);
        }
        if self.offer.expires_at <= now {
            return Err(CompanionError::PairingExpired);
        }
        Ok(())
    }
}

pub struct PairingResult {
    pub session_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub desktop_device_record: DevicePublicRecord,
    pub mobile_device_record: DevicePublicRecord,
    pub verification_code: String,
    pub expires_at: u64,
    session_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PairingResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingResult")
            .field("session_id", &self.session_id)
            .field("agent_wallet_id", &self.agent_wallet_id)
            .field("desktop_device_id", &self.desktop_device_id)
            .field("mobile_device_id", &self.mobile_device_id)
            .field("desktop_device_record", &self.desktop_device_record)
            .field("mobile_device_record", &self.mobile_device_record)
            .field("verification_code", &self.verification_code)
            .field("expires_at", &self.expires_at)
            .field("session_key", &"<memory-only>")
            .finish()
    }
}

impl PairingResult {
    pub fn into_desktop_cipher(self) -> CompanionResult<SessionCipher> {
        self.into_cipher(true)
    }

    pub fn into_mobile_cipher(self) -> CompanionResult<SessionCipher> {
        self.into_cipher(false)
    }

    fn into_cipher(self, desktop_is_local: bool) -> CompanionResult<SessionCipher> {
        let (local_device_id, remote_device_id) = if desktop_is_local {
            (self.desktop_device_id, self.mobile_device_id)
        } else {
            (self.mobile_device_id, self.desktop_device_id)
        };
        SessionCipher::new_zeroizing(
            self.session_id,
            local_device_id,
            remote_device_id,
            self.session_key,
            self.expires_at,
        )
    }
}

fn derive_pairing_material(
    shared: &[u8; 32],
    offer: &PairingOffer,
    request: &PairingRequest,
    session_id: &str,
) -> CompanionResult<Zeroizing<[u8; 32]>> {
    let mut transcript = Encoder::new(PAIRING_KDF_DOMAIN)?;
    transcript.push_bytes(&offer.canonical_bytes()?)?;
    transcript.push_bytes(&request.unsigned_bytes()?)?;
    transcript.push_string(session_id)?;
    let salt = Sha256::digest(transcript.finish()?);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(PAIRING_KDF_DOMAIN, output.as_mut())
        .map_err(|_| CompanionError::Crypto)?;
    Ok(output)
}

fn verification_code(material: &[u8; 32]) -> String {
    let digest = Sha256::digest(material);
    let number = u32::from_be_bytes(digest[..4].try_into().expect("four bytes")) % 1_000_000;
    format!("{number:06}")
}

fn decode_x25519_public(raw: &str) -> CompanionResult<PublicKey> {
    let bytes = hex::decode(raw).map_err(|_| CompanionError::PairingMismatch)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CompanionError::PairingMismatch)?;
    Ok(PublicKey::from(array))
}

fn derive_shared(
    secret: &StaticSecret,
    peer_public: &PublicKey,
) -> CompanionResult<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(peer_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CompanionError::Crypto);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

fn default_mobile_permissions() -> BTreeSet<DevicePermission> {
    #[allow(unused_mut)]
    let mut permissions = BTreeSet::from([
        DevicePermission::ViewAgentWalletStatus,
        DevicePermission::ViewPendingApprovals,
        DevicePermission::ViewAgents,
    ]);
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    permissions.extend([
        DevicePermission::ApprovePayment,
        DevicePermission::RejectPayment,
        DevicePermission::WitnessRollbackAnchor,
    ]);
    permissions
}

#[cfg(test)]
mod serde_u64_tests {
    use std::fmt::Debug;

    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::*;

    fn assert_strict_decimal_u64<T>(value: T, fields: &[&str])
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let encoded = serde_json::to_value(&value).unwrap();
        for field in fields {
            assert_eq!(encoded[*field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(serde_json::from_value::<T>(encoded.clone()).unwrap(), value);

        let mut numeric = encoded;
        numeric[fields[0]] = serde_json::json!(1);
        assert!(serde_json::from_value::<T>(numeric).is_err());
    }

    #[test]
    fn pairing_json_u64_fields_are_strict_decimal_strings() {
        assert_strict_decimal_u64(
            PairingOffer {
                protocol_version: u64::MAX,
                pairing_id: "pairing_one".to_owned(),
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
                desktop_ephemeral_public_key: "ephemeral".to_owned(),
                desktop_identity_public_key: "identity".to_owned(),
                desktop_identity_fingerprint: "fingerprint".to_owned(),
                lan_endpoints: Vec::new(),
                pairing_nonce: "nonce".to_owned(),
                issued_at: u64::MAX,
                expires_at: u64::MAX,
            },
            &["protocol_version", "issued_at", "expires_at"],
        );

        assert_strict_decimal_u64(
            PairingRequest {
                protocol_version: u64::MAX,
                pairing_id: "pairing_one".to_owned(),
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
                mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
                mobile_ephemeral_public_key: "ephemeral".to_owned(),
                mobile_identity_public_key: "identity".to_owned(),
                mobile_identity_fingerprint: "fingerprint".to_owned(),
                pairing_nonce: "nonce".to_owned(),
                mobile_challenge: "challenge".to_owned(),
                issued_at: u64::MAX,
                expires_at: u64::MAX,
                identity_signature: "signature".to_owned(),
            },
            &["protocol_version", "issued_at", "expires_at"],
        );

        assert_strict_decimal_u64(
            PairingConfirmation {
                protocol_version: u64::MAX,
                pairing_id: "pairing_one".to_owned(),
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
                mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
                desktop_challenge: "challenge".to_owned(),
                verification_code: "123456".to_owned(),
                session_id: "session_one".to_owned(),
                issued_at: u64::MAX,
                expires_at: u64::MAX,
                desktop_identity_signature: "signature".to_owned(),
            },
            &["protocol_version", "issued_at", "expires_at"],
        );
    }
}
