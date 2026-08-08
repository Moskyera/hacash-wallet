use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DevicePublicRecord, DeviceRegistry, DeviceRole,
    DeviceSignaturePurpose, PlatformDeviceSigner, sign_with_platform,
};

const ROTATION_DOMAIN: &[u8] = b"HPAY/COMPANION/WITNESS-ROTATION/V1";
const BASELINE_DOMAIN: &[u8] = b"HPAY/COMPANION/WITNESS-ROTATION-BASELINE/V1";
const ROTATION_TICKET_DOMAIN: &[u8] = b"HPAY/COMPANION/ROTATION-PAIRING-TICKET/V1";
const CANDIDATE_ACCEPTANCE_DOMAIN: &[u8] = b"HPAY/COMPANION/ROTATION-CANDIDATE-ACCEPTANCE/V1";
const MAX_ROTATION_LIFETIME_SECS: u64 = 30 * 60;
const MAX_ROTATION_TICKET_LIFETIME_SECS: u64 = 5 * 60;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRotationMode {
    Normal,
    LostPhoneRecovery,
}

impl WitnessRotationMode {
    fn tag(self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::LostPhoneRecovery => 2,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::Normal),
            2 => Ok(Self::LostPhoneRecovery),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRotationReason {
    ReplacePhone,
    LostPhone,
    CompromisedDevice,
}

impl WitnessRotationReason {
    fn tag(self) -> u8 {
        match self {
            Self::ReplacePhone => 1,
            Self::LostPhone => 2,
            Self::CompromisedDevice => 3,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::ReplacePhone),
            2 => Ok(Self::LostPhone),
            3 => Ok(Self::CompromisedDevice),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRotationPhase {
    Stable,
    RotationRequired,
    RotationPrepared,
    RotationRequested,
    AwaitingOldWitnessAuthorization,
    RotationTicketIssued,
    AwaitingCandidatePairing,
    CandidatePairedRestricted,
    CandidateBaselineVerified,
    AwaitingOldDeviceRevocation,
    AwaitingCompletionAnchor,
    AwaitingNewDevicePairing,
    AwaitingNewWitnessBaseline,
    AwaitingRotationCompletionAnchor,
    Completed,
    BlockedByPendingApproval,
    BlockedByUnresolvedSignedOperation,
    BlockedByBroadcastUncertainty,
    RecoveryRotationRequired,
    RotationRecoveryRequired,
}

impl WitnessRotationPhase {
    pub fn permits_agent_writes(self) -> bool {
        matches!(self, Self::Stable | Self::Completed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPairingTicket {
    #[serde(with = "crate::serde_decimal_u64")]
    pub ticket_version: u64,
    pub ticket_id: String,
    pub pairing_id: String,
    pub rotation_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub old_mobile_device_id: DeviceId,
    pub expected_candidate_device_id: DeviceId,
    pub expected_candidate_identity_fingerprint: String,
    pub network_id: String,
    pub genesis_identifier: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub current_witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub next_witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub current_mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub next_mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub latest_anchor_sequence: u64,
    pub latest_anchor_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_sequence: u64,
    pub journal_head_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    pub old_mobile_authorization_commitment: Option<String>,
    pub single_use_nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl RotationPairingTicket {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, ROTATION_TICKET_DOMAIN)
    }

    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.validate_shape()?;
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            ROTATION_TICKET_DOMAIN,
        )?))
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        if self.issued_at > now {
            return Err(CompanionError::InvalidIssuedAt);
        }
        if self.expires_at <= now {
            return Err(CompanionError::PairingExpired);
        }
        Ok(())
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        let anchor_valid = (self.latest_anchor_sequence == 0
            && self.latest_anchor_hash == ZERO_HASH)
            || (self.latest_anchor_sequence > 0
                && is_hash(&self.latest_anchor_hash)
                && self.latest_anchor_hash != ZERO_HASH);
        if self.ticket_version != 1
            || self.ticket_id.is_empty()
            || self.pairing_id.is_empty()
            || self.rotation_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.desktop_device_id == self.old_mobile_device_id
            || self.desktop_device_id == self.expected_candidate_device_id
            || self.old_mobile_device_id == self.expected_candidate_device_id
            || !is_hash(&self.expected_candidate_identity_fingerprint)
            || !crate::is_supported_pilot_network_id(&self.network_id)
            || !is_hash(&self.genesis_identifier)
            || self.genesis_identifier == ZERO_HASH
            || self.current_witness_epoch == 0
            || self.next_witness_epoch != self.current_witness_epoch.saturating_add(1)
            || self.current_mobile_authorization_epoch == 0
            || self.next_mobile_authorization_epoch == 0
            || !anchor_valid
            || self.journal_sequence == 0
            || !is_hash(&self.journal_head_hash)
            || self.journal_head_hash == ZERO_HASH
            || self.policy_epoch == 0
            || self.single_use_nonce.len() != 64
            || !self
                .single_use_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_ROTATION_TICKET_LIFETIME_SECS
            || self
                .old_mobile_authorization_commitment
                .as_ref()
                .is_some_and(|value| !is_hash(value))
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for RotationPairingTicket {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.ticket_version);
        encoder.push_string(&self.ticket_id)?;
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.rotation_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.old_mobile_device_id.as_str())?;
        encoder.push_string(self.expected_candidate_device_id.as_str())?;
        encoder.push_string(&self.expected_candidate_identity_fingerprint)?;
        encoder.push_string(&self.network_id)?;
        encoder.push_string(&self.genesis_identifier)?;
        encoder.push_u64(self.current_witness_epoch);
        encoder.push_u64(self.next_witness_epoch);
        encoder.push_u64(self.current_mobile_authorization_epoch);
        encoder.push_u64(self.next_mobile_authorization_epoch);
        encoder.push_u64(self.latest_anchor_sequence);
        encoder.push_string(&self.latest_anchor_hash)?;
        encoder.push_u64(self.journal_sequence);
        encoder.push_string(&self.journal_head_hash)?;
        encoder.push_u64(self.policy_epoch);
        match &self.old_mobile_authorization_commitment {
            Some(value) => {
                encoder.push_u8(1);
                encoder.push_string(value)?;
            }
            None => encoder.push_u8(0),
        }
        encoder.push_string(&self.single_use_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRotationPairingTicket {
    pub ticket: RotationPairingTicket,
    pub desktop_signature_hex: String,
}

impl SignedRotationPairingTicket {
    pub async fn sign(
        ticket: RotationPairingTicket,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        ticket.validate_shape()?;
        if signer.identity().role() != DeviceRole::Desktop
            || signer.identity().device_id() != &ticket.desktop_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let desktop_signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::RotationPairingTicket,
            &ticket.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            ticket,
            desktop_signature_hex,
        })
    }

    pub fn verify(&self, desktop: &DevicePublicRecord, now: u64) -> CompanionResult<String> {
        self.ticket.validate_at(now)?;
        if desktop.role != DeviceRole::Desktop
            || desktop.device_id != self.ticket.desktop_device_id
            || desktop.agent_wallet_id != self.ticket.agent_wallet_id
            || desktop.is_revoked()
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        desktop.verify_signature(
            DeviceSignaturePurpose::RotationPairingTicket,
            &self.ticket.canonical_bytes()?,
            &self.desktop_signature_hex,
        )?;
        self.ticket.canonical_sha256_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationCandidateAcceptance {
    #[serde(with = "crate::serde_decimal_u64")]
    pub acceptance_version: u64,
    pub ticket_id: String,
    pub ticket_hash: String,
    pub pairing_id: String,
    pub rotation_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub candidate_device_id: DeviceId,
    pub candidate_identity_fingerprint: String,
    pub network_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub next_witness_epoch: u64,
    pub single_use_nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub accepted_at: u64,
}

impl RotationCandidateAcceptance {
    pub fn for_ticket(ticket: &RotationPairingTicket, accepted_at: u64) -> CompanionResult<Self> {
        let value = Self {
            acceptance_version: 1,
            ticket_id: ticket.ticket_id.clone(),
            ticket_hash: ticket.canonical_sha256_hex()?,
            pairing_id: ticket.pairing_id.clone(),
            rotation_id: ticket.rotation_id.clone(),
            agent_wallet_id: ticket.agent_wallet_id.clone(),
            desktop_device_id: ticket.desktop_device_id.clone(),
            candidate_device_id: ticket.expected_candidate_device_id.clone(),
            candidate_identity_fingerprint: ticket.expected_candidate_identity_fingerprint.clone(),
            network_id: ticket.network_id.clone(),
            next_witness_epoch: ticket.next_witness_epoch,
            single_use_nonce: ticket.single_use_nonce.clone(),
            accepted_at,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, CANDIDATE_ACCEPTANCE_DOMAIN)
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.acceptance_version != 1
            || self.ticket_id.is_empty()
            || !is_hash(&self.ticket_hash)
            || self.pairing_id.is_empty()
            || self.rotation_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.desktop_device_id == self.candidate_device_id
            || !is_hash(&self.candidate_identity_fingerprint)
            || !crate::is_supported_pilot_network_id(&self.network_id)
            || self.next_witness_epoch == 0
            || self.single_use_nonce.len() != 64
            || self.accepted_at == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for RotationCandidateAcceptance {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.acceptance_version);
        encoder.push_string(&self.ticket_id)?;
        encoder.push_string(&self.ticket_hash)?;
        encoder.push_string(&self.pairing_id)?;
        encoder.push_string(&self.rotation_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.candidate_device_id.as_str())?;
        encoder.push_string(&self.candidate_identity_fingerprint)?;
        encoder.push_string(&self.network_id)?;
        encoder.push_u64(self.next_witness_epoch);
        encoder.push_string(&self.single_use_nonce)?;
        encoder.push_u64(self.accepted_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRotationCandidateAcceptance {
    pub acceptance: RotationCandidateAcceptance,
    pub candidate_signature_hex: String,
}

impl SignedRotationCandidateAcceptance {
    pub async fn sign(
        acceptance: RotationCandidateAcceptance,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        acceptance.validate_shape()?;
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &acceptance.candidate_device_id
            || signer.identity().fingerprint()? != acceptance.candidate_identity_fingerprint
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let candidate_signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::RotationCandidateAcceptance,
            &acceptance.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            acceptance,
            candidate_signature_hex,
        })
    }

    pub fn verify(
        &self,
        signed_ticket: &SignedRotationPairingTicket,
        candidate: &DevicePublicRecord,
        now: u64,
    ) -> CompanionResult<()> {
        signed_ticket.ticket.validate_at(now)?;
        self.acceptance.validate_shape()?;
        let ticket = &signed_ticket.ticket;
        if self.acceptance.ticket_id != ticket.ticket_id
            || self.acceptance.ticket_hash != ticket.canonical_sha256_hex()?
            || self.acceptance.pairing_id != ticket.pairing_id
            || self.acceptance.rotation_id != ticket.rotation_id
            || self.acceptance.agent_wallet_id != ticket.agent_wallet_id
            || self.acceptance.desktop_device_id != ticket.desktop_device_id
            || self.acceptance.candidate_device_id != ticket.expected_candidate_device_id
            || self.acceptance.candidate_identity_fingerprint
                != ticket.expected_candidate_identity_fingerprint
            || self.acceptance.network_id != ticket.network_id
            || self.acceptance.next_witness_epoch != ticket.next_witness_epoch
            || self.acceptance.single_use_nonce != ticket.single_use_nonce
            || self.acceptance.accepted_at < ticket.issued_at
            || self.acceptance.accepted_at >= ticket.expires_at
            || candidate.device_id != self.acceptance.candidate_device_id
            || candidate.identity_fingerprint != self.acceptance.candidate_identity_fingerprint
            || candidate.agent_wallet_id != self.acceptance.agent_wallet_id
            || candidate.role != DeviceRole::Mobile
            || candidate.is_revoked()
        {
            return Err(CompanionError::PairingMismatch);
        }
        candidate.verify_signature(
            DeviceSignaturePurpose::RotationCandidateAcceptance,
            &self.acceptance.canonical_bytes()?,
            &self.candidate_signature_hex,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRotationRecord {
    #[serde(with = "crate::serde_decimal_u64")]
    pub rotation_version: u64,
    pub rotation_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub old_mobile_device_id: DeviceId,
    pub new_mobile_device_id: DeviceId,
    pub network_id: String,
    pub genesis_identifier: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub signer_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub old_witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub new_witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub old_mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub new_mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub last_accepted_anchor_sequence: u64,
    pub last_accepted_anchor_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_sequence: u64,
    pub journal_head_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    pub rotation_reason: WitnessRotationReason,
    pub rotation_mode: WitnessRotationMode,
    #[serde(with = "crate::serde_decimal_u64")]
    pub created_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl WitnessRotationRecord {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, ROTATION_DOMAIN)
    }

    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.validate_shape()?;
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            ROTATION_DOMAIN,
        )?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, ROTATION_DOMAIN)?;
        let value = Self {
            rotation_version: decoder.read_u64()?,
            rotation_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            old_mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            new_mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            network_id: decoder.read_string()?,
            genesis_identifier: decoder.read_string()?,
            signer_epoch: decoder.read_u64()?,
            journal_epoch: decoder.read_u64()?,
            old_witness_epoch: decoder.read_u64()?,
            new_witness_epoch: decoder.read_u64()?,
            old_mobile_authorization_epoch: decoder.read_u64()?,
            new_mobile_authorization_epoch: decoder.read_u64()?,
            last_accepted_anchor_sequence: decoder.read_u64()?,
            last_accepted_anchor_hash: decoder.read_string()?,
            journal_sequence: decoder.read_u64()?,
            journal_head_hash: decoder.read_string()?,
            policy_epoch: decoder.read_u64()?,
            rotation_reason: WitnessRotationReason::from_tag(decoder.read_u8()?)?,
            rotation_mode: WitnessRotationMode::from_tag(decoder.read_u8()?)?,
            created_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        if self.created_at > now {
            return Err(CompanionError::InvalidIssuedAt);
        }
        if self.expires_at <= now {
            return Err(CompanionError::Expired);
        }
        Ok(())
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        let sequence_hash_valid = (self.last_accepted_anchor_sequence == 0
            && self.last_accepted_anchor_hash == ZERO_HASH)
            || (self.last_accepted_anchor_sequence > 0
                && is_hash(&self.last_accepted_anchor_hash)
                && self.last_accepted_anchor_hash != ZERO_HASH);
        let mode_reason_valid = matches!(
            (self.rotation_mode, self.rotation_reason),
            (
                WitnessRotationMode::Normal,
                WitnessRotationReason::ReplacePhone
            ) | (
                WitnessRotationMode::LostPhoneRecovery,
                WitnessRotationReason::LostPhone | WitnessRotationReason::CompromisedDevice
            )
        );
        if self.rotation_version != 1
            || self.rotation_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.desktop_device_id == self.old_mobile_device_id
            || self.desktop_device_id == self.new_mobile_device_id
            || self.old_mobile_device_id == self.new_mobile_device_id
            || !crate::is_supported_pilot_network_id(&self.network_id)
            || !is_hash(&self.genesis_identifier)
            || self.genesis_identifier == ZERO_HASH
            || self.signer_epoch == 0
            || self.journal_epoch == 0
            || self.old_witness_epoch == 0
            || self.new_witness_epoch != self.old_witness_epoch.saturating_add(1)
            || self.old_mobile_authorization_epoch == 0
            || self.new_mobile_authorization_epoch == 0
            || !sequence_hash_valid
            || self.journal_sequence == 0
            || !is_hash(&self.journal_head_hash)
            || self.journal_head_hash == ZERO_HASH
            || self.policy_epoch == 0
            || !mode_reason_valid
            || self.expires_at <= self.created_at
            || self.expires_at.saturating_sub(self.created_at) > MAX_ROTATION_LIFETIME_SECS
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for WitnessRotationRecord {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.rotation_version);
        encoder.push_string(&self.rotation_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.old_mobile_device_id.as_str())?;
        encoder.push_string(self.new_mobile_device_id.as_str())?;
        encoder.push_string(&self.network_id)?;
        encoder.push_string(&self.genesis_identifier)?;
        encoder.push_u64(self.signer_epoch);
        encoder.push_u64(self.journal_epoch);
        encoder.push_u64(self.old_witness_epoch);
        encoder.push_u64(self.new_witness_epoch);
        encoder.push_u64(self.old_mobile_authorization_epoch);
        encoder.push_u64(self.new_mobile_authorization_epoch);
        encoder.push_u64(self.last_accepted_anchor_sequence);
        encoder.push_string(&self.last_accepted_anchor_hash)?;
        encoder.push_u64(self.journal_sequence);
        encoder.push_string(&self.journal_head_hash)?;
        encoder.push_u64(self.policy_epoch);
        encoder.push_u8(self.rotation_reason.tag());
        encoder.push_u8(self.rotation_mode.tag());
        encoder.push_u64(self.created_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessRotationAuthorization {
    pub rotation: WitnessRotationRecord,
    pub signature_hex: String,
}

impl SignedWitnessRotationAuthorization {
    pub async fn sign(
        rotation: WitnessRotationRecord,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if rotation.rotation_mode != WitnessRotationMode::Normal
            || signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &rotation.old_mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::WitnessRotationAuthorization,
            &rotation.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            rotation,
            signature_hex,
        })
    }

    pub fn verify(&self, registry: &DeviceRegistry, now: u64) -> CompanionResult<String> {
        self.rotation.validate_at(now)?;
        if self.rotation.rotation_mode != WitnessRotationMode::Normal {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let record = registry.require(
            &self.rotation.old_mobile_device_id,
            &self.rotation.agent_wallet_id,
            DeviceRole::Mobile,
            DevicePermission::WitnessRollbackAnchor,
        )?;
        if record.authorization_epoch != self.rotation.old_mobile_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::WitnessRotationAuthorization,
            &self.rotation.canonical_bytes()?,
            &self.signature_hex,
        )?;
        self.rotation.canonical_sha256_hex()
    }

    pub fn authorization_commitment(&self) -> CompanionResult<String> {
        let mut encoder = Encoder::new(b"HPAY/COMPANION/WITNESS-ROTATION-AUTH-COMMITMENT/V1")?;
        encoder.push_bytes(&self.rotation.canonical_bytes()?)?;
        encoder.push_string(&self.signature_hex)?;
        Ok(hex::encode(sha2::Sha256::digest(encoder.finish()?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRotationBaselineReceipt {
    #[serde(with = "crate::serde_decimal_u64")]
    pub receipt_version: u64,
    pub rotation_id: String,
    pub rotation_hash: String,
    pub agent_wallet_id: String,
    pub new_mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub new_mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub baseline_anchor_sequence: u64,
    pub baseline_anchor_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub accepted_at: u64,
}

impl WitnessRotationBaselineReceipt {
    pub fn for_rotation(
        rotation: &WitnessRotationRecord,
        rotation_hash: String,
        accepted_at: u64,
    ) -> CompanionResult<Self> {
        let value = Self {
            receipt_version: 1,
            rotation_id: rotation.rotation_id.clone(),
            rotation_hash,
            agent_wallet_id: rotation.agent_wallet_id.clone(),
            new_mobile_device_id: rotation.new_mobile_device_id.clone(),
            new_mobile_authorization_epoch: rotation.new_mobile_authorization_epoch,
            witness_epoch: rotation.new_witness_epoch,
            baseline_anchor_sequence: rotation.last_accepted_anchor_sequence,
            baseline_anchor_hash: rotation.last_accepted_anchor_hash.clone(),
            accepted_at,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, BASELINE_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, BASELINE_DOMAIN)?;
        let value = Self {
            receipt_version: decoder.read_u64()?,
            rotation_id: decoder.read_string()?,
            rotation_hash: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            new_mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            new_mobile_authorization_epoch: decoder.read_u64()?,
            witness_epoch: decoder.read_u64()?,
            baseline_anchor_sequence: decoder.read_u64()?,
            baseline_anchor_hash: decoder.read_string()?,
            accepted_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.receipt_version != 1
            || self.rotation_id.is_empty()
            || !is_hash(&self.rotation_hash)
            || self.agent_wallet_id.is_empty()
            || self.new_mobile_authorization_epoch == 0
            || self.witness_epoch == 0
            || !is_hash(&self.baseline_anchor_hash)
            || self.accepted_at == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for WitnessRotationBaselineReceipt {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.receipt_version);
        encoder.push_string(&self.rotation_id)?;
        encoder.push_string(&self.rotation_hash)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.new_mobile_device_id.as_str())?;
        encoder.push_u64(self.new_mobile_authorization_epoch);
        encoder.push_u64(self.witness_epoch);
        encoder.push_u64(self.baseline_anchor_sequence);
        encoder.push_string(&self.baseline_anchor_hash)?;
        encoder.push_u64(self.accepted_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessRotationBaselineReceipt {
    pub receipt: WitnessRotationBaselineReceipt,
    pub signature_hex: String,
}

impl SignedWitnessRotationBaselineReceipt {
    pub async fn sign(
        receipt: WitnessRotationBaselineReceipt,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &receipt.new_mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::WitnessRotationBaselineReceipt,
            &receipt.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            receipt,
            signature_hex,
        })
    }

    pub fn verify(
        &self,
        rotation: &WitnessRotationRecord,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<()> {
        rotation.validate_at(now)?;
        let rotation_hash = rotation.canonical_sha256_hex()?;
        self.receipt.validate_shape()?;
        if self.receipt.rotation_id != rotation.rotation_id
            || self.receipt.rotation_hash != rotation_hash
            || self.receipt.agent_wallet_id != rotation.agent_wallet_id
            || self.receipt.new_mobile_device_id != rotation.new_mobile_device_id
            || self.receipt.new_mobile_authorization_epoch
                != rotation.new_mobile_authorization_epoch
            || self.receipt.witness_epoch != rotation.new_witness_epoch
            || self.receipt.baseline_anchor_sequence != rotation.last_accepted_anchor_sequence
            || self.receipt.baseline_anchor_hash != rotation.last_accepted_anchor_hash
            || self.receipt.accepted_at < rotation.created_at
            || self.receipt.accepted_at >= rotation.expires_at
        {
            return Err(CompanionError::AnchorCommitmentMismatch);
        }
        let record = registry.require(
            &rotation.new_mobile_device_id,
            &rotation.agent_wallet_id,
            DeviceRole::Mobile,
            DevicePermission::WitnessRollbackAnchor,
        )?;
        if record.authorization_epoch != rotation.new_mobile_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::WitnessRotationBaselineReceipt,
            &self.receipt.canonical_bytes()?,
            &self.signature_hex,
        )
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(test, feature = "dev-software-identity"))]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{MobileWitnessState, SoftwareDeviceIdentity};

    fn fixture(
        now: u64,
    ) -> (
        SoftwareDeviceIdentity,
        SoftwareDeviceIdentity,
        SoftwareDeviceIdentity,
        DeviceRegistry,
        WitnessRotationRecord,
    ) {
        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let old_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let permissions = BTreeSet::from([DevicePermission::WitnessRollbackAnchor]);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), now - 2)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                old_mobile
                    .public_record("wallet_one", permissions.clone(), now - 2)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                new_mobile
                    .public_record("wallet_one", permissions, now - 1)
                    .unwrap(),
            )
            .unwrap();
        let rotation = WitnessRotationRecord {
            rotation_version: 1,
            rotation_id: "rotation_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            old_mobile_device_id: old_mobile.device_id().clone(),
            new_mobile_device_id: new_mobile.device_id().clone(),
            network_id: "testnet".to_owned(),
            genesis_identifier: "11".repeat(32),
            signer_epoch: 1,
            journal_epoch: 1,
            old_witness_epoch: 1,
            new_witness_epoch: 2,
            old_mobile_authorization_epoch: 1,
            new_mobile_authorization_epoch: 1,
            last_accepted_anchor_sequence: 0,
            last_accepted_anchor_hash: ZERO_HASH.to_owned(),
            journal_sequence: 5,
            journal_head_hash: "22".repeat(32),
            policy_epoch: 1,
            rotation_reason: WitnessRotationReason::ReplacePhone,
            rotation_mode: WitnessRotationMode::Normal,
            created_at: now,
            expires_at: now + 300,
        };
        (desktop, old_mobile, new_mobile, registry, rotation)
    }

    #[tokio::test]
    async fn normal_rotation_authorization_and_baseline_are_canonical_and_device_bound() {
        let (_desktop, old_mobile, new_mobile, registry, rotation) = fixture(100);
        let bytes = rotation.canonical_bytes().unwrap();
        assert_eq!(
            WitnessRotationRecord::from_canonical_bytes(&bytes).unwrap(),
            rotation
        );
        let authorization = SignedWitnessRotationAuthorization::sign(rotation.clone(), &old_mobile)
            .await
            .unwrap();
        let rotation_hash = authorization.verify(&registry, 101).unwrap();
        let receipt =
            WitnessRotationBaselineReceipt::for_rotation(&rotation, rotation_hash, 102).unwrap();
        assert_eq!(
            WitnessRotationBaselineReceipt::from_canonical_bytes(
                &receipt.canonical_bytes().unwrap()
            )
            .unwrap(),
            receipt
        );
        let signed = SignedWitnessRotationBaselineReceipt::sign(receipt, &new_mobile)
            .await
            .unwrap();
        signed.verify(&rotation, &registry, 102).unwrap();
        let baseline =
            MobileWitnessState::from_rotation_baseline(&rotation, &signed, &registry, 102).unwrap();
        assert_eq!(baseline.mobile_device_id, rotation.new_mobile_device_id);
        assert_eq!(baseline.witness_epoch, 2);
        assert_eq!(baseline.last_anchor_sequence, 0);
    }

    #[tokio::test]
    async fn rotation_payload_mutation_or_wrong_device_fails_closed() {
        let (_desktop, old_mobile, new_mobile, registry, rotation) = fixture(200);
        let authorization = SignedWitnessRotationAuthorization::sign(rotation.clone(), &old_mobile)
            .await
            .unwrap();
        let mut changed = authorization.clone();
        changed.rotation.rotation_id = "rotation_changed".to_owned();
        assert!(changed.verify(&registry, 201).is_err());
        assert!(
            SignedWitnessRotationAuthorization::sign(rotation.clone(), &new_mobile)
                .await
                .is_err()
        );
        let hash = rotation.canonical_sha256_hex().unwrap();
        let receipt = WitnessRotationBaselineReceipt::for_rotation(&rotation, hash, 202).unwrap();
        let mut signed = SignedWitnessRotationBaselineReceipt::sign(receipt, &new_mobile)
            .await
            .unwrap();
        signed.receipt.baseline_anchor_hash = "33".repeat(32);
        assert!(signed.verify(&rotation, &registry, 202).is_err());
    }

    #[tokio::test]
    async fn rotation_ticket_and_candidate_acceptance_are_identity_and_transcript_bound() {
        let (desktop, old_mobile, candidate, registry, rotation) = fixture(300);
        let old_authorization =
            SignedWitnessRotationAuthorization::sign(rotation.clone(), &old_mobile)
                .await
                .unwrap();
        let candidate_record = registry
            .records()
            .find(|record| record.device_id == *candidate.device_id())
            .unwrap()
            .clone();
        let ticket = RotationPairingTicket {
            ticket_version: 1,
            ticket_id: "ticket_one".to_owned(),
            pairing_id: "pairing_one".to_owned(),
            rotation_id: rotation.rotation_id.clone(),
            agent_wallet_id: rotation.agent_wallet_id.clone(),
            desktop_device_id: desktop.device_id().clone(),
            old_mobile_device_id: old_mobile.device_id().clone(),
            expected_candidate_device_id: candidate.device_id().clone(),
            expected_candidate_identity_fingerprint: candidate_record.identity_fingerprint.clone(),
            network_id: rotation.network_id.clone(),
            genesis_identifier: rotation.genesis_identifier.clone(),
            current_witness_epoch: rotation.old_witness_epoch,
            next_witness_epoch: rotation.new_witness_epoch,
            current_mobile_authorization_epoch: rotation.old_mobile_authorization_epoch,
            next_mobile_authorization_epoch: 1,
            latest_anchor_sequence: rotation.last_accepted_anchor_sequence,
            latest_anchor_hash: rotation.last_accepted_anchor_hash.clone(),
            journal_sequence: rotation.journal_sequence,
            journal_head_hash: rotation.journal_head_hash.clone(),
            policy_epoch: rotation.policy_epoch,
            old_mobile_authorization_commitment: Some(
                old_authorization.rotation.canonical_sha256_hex().unwrap(),
            ),
            single_use_nonce: "33".repeat(32),
            issued_at: 301,
            expires_at: 401,
        };
        let desktop_record = registry
            .records()
            .find(|record| record.device_id == *desktop.device_id())
            .unwrap();
        let signed_ticket = SignedRotationPairingTicket::sign(ticket, &desktop)
            .await
            .unwrap();
        signed_ticket.verify(desktop_record, 302).unwrap();

        let acceptance =
            RotationCandidateAcceptance::for_ticket(&signed_ticket.ticket, 303).unwrap();
        let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, &candidate)
            .await
            .unwrap();
        signed_acceptance
            .verify(&signed_ticket, &candidate_record, 304)
            .unwrap();

        let other_desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let other_desktop_record = other_desktop
            .public_record("wallet_one", BTreeSet::new(), 300)
            .unwrap();
        assert!(
            signed_ticket.verify(&other_desktop_record, 304).is_err(),
            "a ticket cannot be moved to another desktop identity"
        );
        assert!(signed_ticket.verify(desktop_record, 401).is_err());

        let mut wrong_wallet = signed_ticket.clone();
        wrong_wallet.ticket.agent_wallet_id = "wallet_two".to_owned();
        assert!(wrong_wallet.verify(desktop_record, 304).is_err());
        let mut wrong_network = signed_ticket.clone();
        wrong_network.ticket.network_id = "mainnet".to_owned();
        assert!(wrong_network.verify(desktop_record, 304).is_err());
        let mut wrong_desktop = signed_ticket.clone();
        wrong_desktop.ticket.desktop_device_id = other_desktop.device_id().clone();
        assert!(wrong_desktop.verify(desktop_record, 304).is_err());

        let substituted_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let substituted_record = substituted_candidate
            .public_record(
                "wallet_one",
                BTreeSet::from([DevicePermission::WitnessRollbackAnchor]),
                300,
            )
            .unwrap();
        assert!(
            signed_acceptance
                .verify(&signed_ticket, &substituted_record, 304)
                .is_err(),
            "candidate identity substitution must fail closed"
        );
        let substituted_acceptance =
            RotationCandidateAcceptance::for_ticket(&signed_ticket.ticket, 304).unwrap();
        assert!(
            SignedRotationCandidateAcceptance::sign(
                substituted_acceptance,
                &substituted_candidate,
            )
            .await
            .is_err(),
            "a second candidate cannot sign acceptance for the first candidate ticket"
        );

        let mut substituted = signed_acceptance.clone();
        substituted.acceptance.candidate_identity_fingerprint = "44".repeat(32);
        assert!(
            substituted
                .verify(&signed_ticket, &candidate_record, 304)
                .is_err()
        );
        assert!(
            signed_acceptance
                .verify(&signed_ticket, &candidate_record, 401)
                .is_err()
        );
    }
}
