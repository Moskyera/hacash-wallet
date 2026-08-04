use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::DeviceId;
use crate::replay::ReplayMetadata;

use super::validation::{
    NONCE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, lower_hex, require_version, validate_common,
    validate_time,
};

pub const SESSION_PROTOCOL_VERSION: u64 = 1;

const CHALLENGE_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-CHALLENGE/V1";
const CHALLENGE_WIRE_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-CHALLENGE-WIRE/V1";
const RESPONSE_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-RESPONSE/V1";
const RESPONSE_WIRE_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-RESPONSE-WIRE/V1";
const CONFIRMATION_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-CONFIRMATION/V1";
const CONFIRMATION_WIRE_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-CONFIRMATION-WIRE/V1";
const CHALLENGE_REPLAY_CONTEXT: &str = "companion_session_challenge";
const RESPONSE_REPLAY_CONTEXT: &str = "companion_session_response";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChallenge {
    pub protocol_version: u64,
    pub session_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub desktop_authorization_epoch: u64,
    pub desktop_identity_fingerprint: String,
    pub mobile_device_id: DeviceId,
    pub mobile_authorization_epoch: u64,
    pub mobile_identity_fingerprint: String,
    pub desktop_ephemeral_public_key: String,
    pub challenge_sequence: u64,
    pub challenge_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub desktop_identity_signature: String,
}

impl SessionChallenge {
    pub fn to_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        encode_wire(
            CHALLENGE_WIRE_DOMAIN,
            &self.unsigned_bytes()?,
            &self.desktop_identity_signature,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let (unsigned, signature) = decode_wire(bytes, CHALLENGE_WIRE_DOMAIN)?;
        let mut value = Self::decode_unsigned(unsigned)?;
        value.desktop_identity_signature = signature;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        validate_time(self.issued_at, self.expires_at, now)
    }

    pub(super) fn validate_unsigned_shape(&self) -> CompanionResult<()> {
        let mut value = self.clone();
        value.desktop_identity_signature = "00".repeat(SIGNATURE_BYTES);
        value.validate_shape()
    }

    pub(super) fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_unsigned_shape()?;
        CanonicalEncode::canonical_bytes(self, CHALLENGE_DOMAIN)
    }

    pub(super) fn commitment(&self) -> CompanionResult<String> {
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            CHALLENGE_DOMAIN,
        )?))
    }

    pub(super) fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: CHALLENGE_REPLAY_CONTEXT.to_owned(),
            sender_device_id: self.desktop_device_id.clone(),
            sequence: self.challenge_sequence,
            nonce: self.challenge_nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        validate_common(
            self.protocol_version,
            &self.session_id,
            &self.agent_wallet_id,
            self.desktop_authorization_epoch,
            &self.desktop_identity_fingerprint,
            self.mobile_authorization_epoch,
            &self.mobile_identity_fingerprint,
            self.issued_at,
            self.expires_at,
        )?;
        lower_hex(&self.desktop_ephemeral_public_key, PUBLIC_KEY_BYTES)?;
        lower_hex(&self.challenge_nonce, NONCE_BYTES)?;
        lower_hex(&self.desktop_identity_signature, SIGNATURE_BYTES)?;
        if self.challenge_sequence == 0 {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn decode_unsigned(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, CHALLENGE_DOMAIN)?;
        let protocol_version = decoder.read_u64()?;
        require_version(protocol_version)?;
        let value = Self {
            protocol_version,
            session_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            desktop_authorization_epoch: decoder.read_u64()?,
            desktop_identity_fingerprint: decoder.read_string()?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_authorization_epoch: decoder.read_u64()?,
            mobile_identity_fingerprint: decoder.read_string()?,
            desktop_ephemeral_public_key: decoder.read_string()?,
            challenge_sequence: decoder.read_u64()?,
            challenge_nonce: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            desktop_identity_signature: String::new(),
        };
        decoder.finish()?;
        value.validate_unsigned_shape()?;
        Ok(value)
    }
}

impl CanonicalEncode for SessionChallenge {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.session_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_u64(self.desktop_authorization_epoch);
        encoder.push_string(&self.desktop_identity_fingerprint)?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.mobile_authorization_epoch);
        encoder.push_string(&self.mobile_identity_fingerprint)?;
        encoder.push_string(&self.desktop_ephemeral_public_key)?;
        encoder.push_u64(self.challenge_sequence);
        encoder.push_string(&self.challenge_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    pub protocol_version: u64,
    pub session_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub desktop_authorization_epoch: u64,
    pub desktop_identity_fingerprint: String,
    pub mobile_device_id: DeviceId,
    pub mobile_authorization_epoch: u64,
    pub mobile_identity_fingerprint: String,
    pub challenge_commitment: String,
    pub mobile_ephemeral_public_key: String,
    pub response_sequence: u64,
    pub response_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub mobile_identity_signature: String,
}

impl SessionResponse {
    pub fn to_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        encode_wire(
            RESPONSE_WIRE_DOMAIN,
            &self.unsigned_bytes()?,
            &self.mobile_identity_signature,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let (unsigned, signature) = decode_wire(bytes, RESPONSE_WIRE_DOMAIN)?;
        let mut value = Self::decode_unsigned(unsigned)?;
        value.mobile_identity_signature = signature;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        validate_time(self.issued_at, self.expires_at, now)
    }

    pub(super) fn validate_unsigned_shape(&self) -> CompanionResult<()> {
        let mut value = self.clone();
        value.mobile_identity_signature = "00".repeat(SIGNATURE_BYTES);
        value.validate_shape()
    }

    pub(super) fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_unsigned_shape()?;
        CanonicalEncode::canonical_bytes(self, RESPONSE_DOMAIN)
    }

    pub(super) fn commitment(&self) -> CompanionResult<String> {
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            RESPONSE_DOMAIN,
        )?))
    }

    pub(super) fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: RESPONSE_REPLAY_CONTEXT.to_owned(),
            sender_device_id: self.mobile_device_id.clone(),
            sequence: self.response_sequence,
            nonce: self.response_nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        validate_common(
            self.protocol_version,
            &self.session_id,
            &self.agent_wallet_id,
            self.desktop_authorization_epoch,
            &self.desktop_identity_fingerprint,
            self.mobile_authorization_epoch,
            &self.mobile_identity_fingerprint,
            self.issued_at,
            self.expires_at,
        )?;
        lower_hex(&self.challenge_commitment, 32)?;
        lower_hex(&self.mobile_ephemeral_public_key, PUBLIC_KEY_BYTES)?;
        lower_hex(&self.response_nonce, NONCE_BYTES)?;
        lower_hex(&self.mobile_identity_signature, SIGNATURE_BYTES)?;
        if self.response_sequence == 0 {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn decode_unsigned(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, RESPONSE_DOMAIN)?;
        let protocol_version = decoder.read_u64()?;
        require_version(protocol_version)?;
        let value = Self {
            protocol_version,
            session_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            desktop_authorization_epoch: decoder.read_u64()?,
            desktop_identity_fingerprint: decoder.read_string()?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_authorization_epoch: decoder.read_u64()?,
            mobile_identity_fingerprint: decoder.read_string()?,
            challenge_commitment: decoder.read_string()?,
            mobile_ephemeral_public_key: decoder.read_string()?,
            response_sequence: decoder.read_u64()?,
            response_nonce: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            mobile_identity_signature: String::new(),
        };
        decoder.finish()?;
        value.validate_unsigned_shape()?;
        Ok(value)
    }
}

impl CanonicalEncode for SessionResponse {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.session_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_u64(self.desktop_authorization_epoch);
        encoder.push_string(&self.desktop_identity_fingerprint)?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.mobile_authorization_epoch);
        encoder.push_string(&self.mobile_identity_fingerprint)?;
        encoder.push_string(&self.challenge_commitment)?;
        encoder.push_string(&self.mobile_ephemeral_public_key)?;
        encoder.push_u64(self.response_sequence);
        encoder.push_string(&self.response_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfirmation {
    pub protocol_version: u64,
    pub session_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub desktop_authorization_epoch: u64,
    pub desktop_identity_fingerprint: String,
    pub mobile_device_id: DeviceId,
    pub mobile_authorization_epoch: u64,
    pub mobile_identity_fingerprint: String,
    pub challenge_commitment: String,
    pub response_commitment: String,
    pub confirmation_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub desktop_identity_signature: String,
}

impl SessionConfirmation {
    pub fn to_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        encode_wire(
            CONFIRMATION_WIRE_DOMAIN,
            &self.unsigned_bytes()?,
            &self.desktop_identity_signature,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let (unsigned, signature) = decode_wire(bytes, CONFIRMATION_WIRE_DOMAIN)?;
        let mut value = Self::decode_unsigned(unsigned)?;
        value.desktop_identity_signature = signature;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        validate_time(self.issued_at, self.expires_at, now)
    }

    pub(super) fn validate_unsigned_shape(&self) -> CompanionResult<()> {
        let mut value = self.clone();
        value.desktop_identity_signature = "00".repeat(SIGNATURE_BYTES);
        value.validate_shape()
    }

    pub(super) fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_unsigned_shape()?;
        CanonicalEncode::canonical_bytes(self, CONFIRMATION_DOMAIN)
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        validate_common(
            self.protocol_version,
            &self.session_id,
            &self.agent_wallet_id,
            self.desktop_authorization_epoch,
            &self.desktop_identity_fingerprint,
            self.mobile_authorization_epoch,
            &self.mobile_identity_fingerprint,
            self.issued_at,
            self.expires_at,
        )?;
        lower_hex(&self.challenge_commitment, 32)?;
        lower_hex(&self.response_commitment, 32)?;
        lower_hex(&self.confirmation_nonce, NONCE_BYTES)?;
        lower_hex(&self.desktop_identity_signature, SIGNATURE_BYTES)
    }

    fn decode_unsigned(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, CONFIRMATION_DOMAIN)?;
        let protocol_version = decoder.read_u64()?;
        require_version(protocol_version)?;
        let value = Self {
            protocol_version,
            session_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            desktop_authorization_epoch: decoder.read_u64()?,
            desktop_identity_fingerprint: decoder.read_string()?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_authorization_epoch: decoder.read_u64()?,
            mobile_identity_fingerprint: decoder.read_string()?,
            challenge_commitment: decoder.read_string()?,
            response_commitment: decoder.read_string()?,
            confirmation_nonce: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            desktop_identity_signature: String::new(),
        };
        decoder.finish()?;
        value.validate_unsigned_shape()?;
        Ok(value)
    }
}

impl CanonicalEncode for SessionConfirmation {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.session_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_u64(self.desktop_authorization_epoch);
        encoder.push_string(&self.desktop_identity_fingerprint)?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.mobile_authorization_epoch);
        encoder.push_string(&self.mobile_identity_fingerprint)?;
        encoder.push_string(&self.challenge_commitment)?;
        encoder.push_string(&self.response_commitment)?;
        encoder.push_string(&self.confirmation_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

fn encode_wire(domain: &[u8], unsigned: &[u8], signature: &str) -> CompanionResult<Vec<u8>> {
    lower_hex(signature, SIGNATURE_BYTES)?;
    let mut encoder = Encoder::new(domain)?;
    encoder.push_bytes(unsigned)?;
    encoder.push_string(signature)?;
    encoder.finish()
}

fn decode_wire<'a>(bytes: &'a [u8], domain: &[u8]) -> CompanionResult<(&'a [u8], String)> {
    let mut decoder = Decoder::new(bytes, domain)?;
    let unsigned = decoder.read_bytes()?;
    let signature = decoder.read_string()?;
    decoder.finish()?;
    lower_hex(&signature, SIGNATURE_BYTES)?;
    Ok((unsigned, signature))
}
