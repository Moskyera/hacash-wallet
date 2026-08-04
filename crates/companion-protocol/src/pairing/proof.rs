use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{PairingConfirmation, PairingOffer, PairingRequest};
use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePublicRecord, DeviceRole, DeviceSignaturePurpose, PlatformDeviceSigner,
    sign_with_platform,
};

const PROOF_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING-MOBILE-PROOF/V1";
const PROOF_WIRE_DOMAIN: &[u8] = b"HPAY/COMPANION/PAIRING-MOBILE-PROOF-WIRE/V1";
const COMMITMENT_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Mobile's signed acknowledgement that the exact pairing transcript and
/// human verification code were accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobilePairingProof {
    #[serde(with = "crate::serde_decimal_u64")]
    pub proof_version: u64,
    pub pairing_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub session_id: String,
    pub offer_commitment: String,
    pub request_commitment: String,
    pub confirmation_commitment: String,
    pub verification_code: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub mobile_identity_signature: String,
}

impl MobilePairingProof {
    pub fn to_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        let mut encoder = Encoder::new(PROOF_WIRE_DOMAIN)?;
        encoder.push_bytes(&self.unsigned_bytes()?)?;
        encoder.push_string(&self.mobile_identity_signature)?;
        encoder.finish()
    }

    pub fn from_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, PROOF_WIRE_DOMAIN)?;
        let unsigned = decoder.read_bytes()?;
        let signature = decoder.read_string()?;
        decoder.finish()?;
        let mut value = Self::decode_unsigned(unsigned)?;
        value.mobile_identity_signature = signature;
        value.validate_shape()?;
        Ok(value)
    }

    pub(super) async fn sign(
        offer: &PairingOffer,
        request: &PairingRequest,
        confirmation: &PairingConfirmation,
        verification_code: &str,
        mobile_signer: &dyn PlatformDeviceSigner,
        now: u64,
    ) -> CompanionResult<Self> {
        if mobile_signer.identity().role() != DeviceRole::Mobile
            || mobile_signer.identity().device_id() != &request.mobile_device_id
            || mobile_signer.identity().fingerprint()? != request.mobile_identity_fingerprint
        {
            return Err(CompanionError::PairingMismatch);
        }
        let mut value = Self {
            proof_version: 1,
            pairing_id: offer.pairing_id.clone(),
            agent_wallet_id: offer.agent_wallet_id.clone(),
            desktop_device_id: offer.desktop_device_id.clone(),
            mobile_device_id: request.mobile_device_id.clone(),
            session_id: confirmation.session_id.clone(),
            offer_commitment: commitment(&offer.canonical_bytes()?),
            request_commitment: commitment(&request.unsigned_bytes()?),
            confirmation_commitment: commitment(&confirmation.unsigned_bytes()?),
            verification_code: verification_code.to_owned(),
            issued_at: now,
            expires_at: offer.expires_at,
            mobile_identity_signature: "00".repeat(SIGNATURE_BYTES),
        };
        value.validate_at(now)?;
        value.mobile_identity_signature = sign_with_platform(
            mobile_signer,
            DeviceSignaturePurpose::PairingMobileProof,
            &value.unsigned_bytes()?,
        )
        .await?;
        value.validate_at(now)?;
        Ok(value)
    }

    pub(super) fn verify(
        &self,
        offer: &PairingOffer,
        request: &PairingRequest,
        confirmation: &PairingConfirmation,
        mobile_record: &DevicePublicRecord,
        now: u64,
    ) -> CompanionResult<()> {
        self.validate_at(now)?;
        if self.pairing_id != offer.pairing_id
            || self.agent_wallet_id != offer.agent_wallet_id
            || self.desktop_device_id != offer.desktop_device_id
            || self.mobile_device_id != request.mobile_device_id
            || self.session_id != confirmation.session_id
            || self.offer_commitment != commitment(&offer.canonical_bytes()?)
            || self.request_commitment != commitment(&request.unsigned_bytes()?)
            || self.confirmation_commitment != commitment(&confirmation.unsigned_bytes()?)
            || self.verification_code != confirmation.verification_code
            || self.issued_at < confirmation.issued_at
            || self.expires_at != offer.expires_at
            || mobile_record.device_id != request.mobile_device_id
            || mobile_record.role != DeviceRole::Mobile
            || mobile_record.agent_wallet_id != offer.agent_wallet_id
            || mobile_record.identity_fingerprint != request.mobile_identity_fingerprint
            || mobile_record.authorization_epoch != 1
            || mobile_record.revoked_at.is_some()
        {
            return Err(CompanionError::PairingMismatch);
        }
        mobile_record.verify_signature(
            DeviceSignaturePurpose::PairingMobileProof,
            &self.unsigned_bytes()?,
            &self.mobile_identity_signature,
        )
    }

    fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        if self.expires_at <= now {
            return Err(CompanionError::PairingExpired);
        }
        if self.issued_at > now {
            return Err(CompanionError::PairingMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.proof_version != 1 {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.pairing_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.session_id.is_empty()
            || self.expires_at <= self.issued_at
            || !valid_code(&self.verification_code)
        {
            return Err(CompanionError::PairingMismatch);
        }
        lower_hex(&self.offer_commitment, COMMITMENT_BYTES)?;
        lower_hex(&self.request_commitment, COMMITMENT_BYTES)?;
        lower_hex(&self.confirmation_commitment, COMMITMENT_BYTES)?;
        lower_hex(&self.mobile_identity_signature, SIGNATURE_BYTES)
    }

    fn unsigned_bytes(&self) -> CompanionResult<Vec<u8>> {
        let mut clone = self.clone();
        clone.mobile_identity_signature = "00".repeat(SIGNATURE_BYTES);
        clone.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, PROOF_DOMAIN)
    }

    fn decode_unsigned(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, PROOF_DOMAIN)?;
        let proof_version = decoder.read_u64()?;
        if proof_version != 1 {
            return Err(CompanionError::UnsupportedVersion);
        }
        let value = Self {
            proof_version,
            pairing_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            session_id: decoder.read_string()?,
            offer_commitment: decoder.read_string()?,
            request_commitment: decoder.read_string()?,
            confirmation_commitment: decoder.read_string()?,
            verification_code: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            mobile_identity_signature: String::new(),
        };
        decoder.finish()?;
        let mut shape = value.clone();
        shape.mobile_identity_signature = "00".repeat(SIGNATURE_BYTES);
        shape.validate_shape()?;
        Ok(value)
    }
}

impl CanonicalEncode for MobilePairingProof {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.proof_version);
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_string(&self.session_id)?;
        encoder.push_string(&self.offer_commitment)?;
        encoder.push_string(&self.request_commitment)?;
        encoder.push_string(&self.confirmation_commitment)?;
        encoder.push_string(&self.verification_code)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

fn commitment(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn lower_hex(value: &str, expected_bytes: usize) -> CompanionResult<()> {
    if value.len() != expected_bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CompanionError::PairingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod serde_u64_tests {
    use super::*;

    #[test]
    fn mobile_pairing_proof_json_u64_fields_are_strict() {
        let proof = MobilePairingProof {
            proof_version: u64::MAX,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
            session_id: "session_one".to_owned(),
            offer_commitment: "offer".to_owned(),
            request_commitment: "request".to_owned(),
            confirmation_commitment: "confirmation".to_owned(),
            verification_code: "123456".to_owned(),
            issued_at: u64::MAX,
            expires_at: u64::MAX,
            mobile_identity_signature: "signature".to_owned(),
        };
        let value = serde_json::to_value(&proof).unwrap();
        for field in ["proof_version", "issued_at", "expires_at"] {
            assert_eq!(value[field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(
            serde_json::from_value::<MobilePairingProof>(value.clone()).unwrap(),
            proof
        );

        let mut numeric = value;
        numeric["issued_at"] = serde_json::json!(1);
        assert!(serde_json::from_value::<MobilePairingProof>(numeric).is_err());
    }
}
