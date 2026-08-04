use serde::{Deserialize, Serialize};

use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};
use crate::rotation::{
    SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationRecord,
};

const ANCHOR_DOMAIN: &[u8] = b"HPAY/COMPANION/ROLLBACK-ANCHOR/V1";
const RECEIPT_DOMAIN: &[u8] = b"HPAY/COMPANION/WITNESS-RECEIPT/V1";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_ANCHOR_LIFETIME_SECS: u64 = 10 * 60;
const MAX_ACCEPTED_ANCHOR_IDS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackOperationPhase {
    WalletState,
    /// Legacy V1 name retained for decoding already-persisted anchors.
    SignedAwaitingWitness,
    WitnessedAwaitingBroadcast,
    BroadcastUncertain,
    Committed,
    RecoveryRequired,
    SignedPreBroadcast,
    Submitted,
    ReconciledFinal,
}

impl RollbackOperationPhase {
    fn tag(self) -> u8 {
        match self {
            Self::WalletState => 1,
            Self::SignedAwaitingWitness => 2,
            Self::WitnessedAwaitingBroadcast => 3,
            Self::BroadcastUncertain => 4,
            Self::Committed => 5,
            Self::RecoveryRequired => 6,
            Self::SignedPreBroadcast => 7,
            Self::Submitted => 8,
            Self::ReconciledFinal => 9,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::WalletState),
            2 => Ok(Self::SignedAwaitingWitness),
            3 => Ok(Self::WitnessedAwaitingBroadcast),
            4 => Ok(Self::BroadcastUncertain),
            5 => Ok(Self::Committed),
            6 => Ok(Self::RecoveryRequired),
            7 => Ok(Self::SignedPreBroadcast),
            8 => Ok(Self::Submitted),
            9 => Ok(Self::ReconciledFinal),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessSubmissionStatus {
    NotSubmitted,
    Submitted,
    Uncertain,
}

impl WitnessSubmissionStatus {
    fn tag(self) -> u8 {
        match self {
            Self::NotSubmitted => 1,
            Self::Submitted => 2,
            Self::Uncertain => 3,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::NotSubmitted),
            2 => Ok(Self::Submitted),
            3 => Ok(Self::Uncertain),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessReconciliationStatus {
    NotStarted,
    Pending,
    Confirmed,
    Rejected,
    Unknown,
}

impl WitnessReconciliationStatus {
    fn tag(self) -> u8 {
        match self {
            Self::NotStarted => 1,
            Self::Pending => 2,
            Self::Confirmed => 3,
            Self::Rejected => 4,
            Self::Unknown => 5,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::NotStarted),
            2 => Ok(Self::Pending),
            3 => Ok(Self::Confirmed),
            4 => Ok(Self::Rejected),
            5 => Ok(Self::Unknown),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessReservationState {
    Held,
    Consumed,
    Released,
}

impl WitnessReservationState {
    fn tag(self) -> u8 {
        match self {
            Self::Held => 1,
            Self::Consumed => 2,
            Self::Released => 3,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::Held),
            2 => Ok(Self::Consumed),
            3 => Ok(Self::Released),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

/// Financial lifecycle commitments carried only by V2 witness anchors.
/// Raw transactions and signatures are deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessTransactionState {
    pub operation_id: String,
    pub agent_id: String,
    pub signed_transaction_commitment: String,
    pub transaction_id: Option<String>,
    pub submission_status: WitnessSubmissionStatus,
    pub reconciliation_status: WitnessReconciliationStatus,
    #[serde(default, with = "crate::serde_decimal_u64::option")]
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub reservation_state: WitnessReservationState,
}

impl WitnessTransactionState {
    fn validate(&self, phase: RollbackOperationPhase) -> CompanionResult<()> {
        let transaction_id_valid = self
            .transaction_id
            .as_ref()
            .is_none_or(|value| is_hash(value));
        let block_hash_valid = self.block_hash.as_ref().is_none_or(|value| is_hash(value));
        let block_pair_valid = self.block_height.is_some() == self.block_hash.is_some();
        let phase_valid = match phase {
            RollbackOperationPhase::SignedPreBroadcast => {
                self.submission_status == WitnessSubmissionStatus::NotSubmitted
                    && self.reconciliation_status == WitnessReconciliationStatus::NotStarted
                    && self.reservation_state == WitnessReservationState::Held
            }
            RollbackOperationPhase::Submitted => {
                matches!(
                    self.submission_status,
                    WitnessSubmissionStatus::Submitted | WitnessSubmissionStatus::Uncertain
                ) && matches!(
                    self.reconciliation_status,
                    WitnessReconciliationStatus::NotStarted
                        | WitnessReconciliationStatus::Pending
                        | WitnessReconciliationStatus::Unknown
                ) && self.reservation_state == WitnessReservationState::Held
            }
            RollbackOperationPhase::ReconciledFinal => {
                self.submission_status == WitnessSubmissionStatus::Submitted
                    && matches!(
                        (self.reconciliation_status, self.reservation_state),
                        (
                            WitnessReconciliationStatus::Confirmed,
                            WitnessReservationState::Consumed
                        ) | (
                            WitnessReconciliationStatus::Rejected,
                            WitnessReservationState::Released
                        )
                    )
            }
            _ => false,
        };
        if self.operation_id.is_empty()
            || self.agent_id.is_empty()
            || !is_hash(&self.signed_transaction_commitment)
            || !transaction_id_valid
            || !block_hash_valid
            || !block_pair_valid
            || !phase_valid
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_string(&self.operation_id)?;
        encoder.push_string(&self.agent_id)?;
        encoder.push_string(&self.signed_transaction_commitment)?;
        encoder.push_bool(self.transaction_id.is_some());
        if let Some(transaction_id) = &self.transaction_id {
            encoder.push_string(transaction_id)?;
        }
        encoder.push_u8(self.submission_status.tag());
        encoder.push_u8(self.reconciliation_status.tag());
        encoder.push_bool(self.block_height.is_some());
        if let Some(block_height) = self.block_height {
            encoder.push_u64(block_height);
        }
        encoder.push_bool(self.block_hash.is_some());
        if let Some(block_hash) = &self.block_hash {
            encoder.push_string(block_hash)?;
        }
        encoder.push_u8(self.reservation_state.tag());
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> CompanionResult<Self> {
        Ok(Self {
            operation_id: decoder.read_string()?,
            agent_id: decoder.read_string()?,
            signed_transaction_commitment: decoder.read_string()?,
            transaction_id: if decoder.read_bool()? {
                Some(decoder.read_string()?)
            } else {
                None
            },
            submission_status: WitnessSubmissionStatus::from_tag(decoder.read_u8()?)?,
            reconciliation_status: WitnessReconciliationStatus::from_tag(decoder.read_u8()?)?,
            block_height: if decoder.read_bool()? {
                Some(decoder.read_u64()?)
            } else {
                None
            },
            block_hash: if decoder.read_bool()? {
                Some(decoder.read_string()?)
            } else {
                None
            },
            reservation_state: WitnessReservationState::from_tag(decoder.read_u8()?)?,
        })
    }
}

/// Canonical desktop proposal for one externally witnessed Agent Wallet state.
///
/// This contains commitments only. It never carries a wallet key, password,
/// journal key, signed transaction body, or companion session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAnchor {
    #[serde(with = "crate::serde_decimal_u64")]
    pub anchor_version: u64,
    pub anchor_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub desktop_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub mobile_authorization_epoch: u64,
    pub network_id: String,
    pub genesis_identifier: String,
    pub node_profile_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub transaction_format_version: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub signer_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub anchor_sequence: u64,
    pub previous_anchor_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_sequence: u64,
    pub journal_head_hash: String,
    pub materialized_state_commitment: String,
    pub last_operation_id: Option<String>,
    pub operation_phase: RollbackOperationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<WitnessTransactionState>,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub capability_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub created_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl RollbackAnchor {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, ANCHOR_DOMAIN)
    }

    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.validate_shape()?;
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            ANCHOR_DOMAIN,
        )?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, ANCHOR_DOMAIN)?;
        let anchor_version = decoder.read_u64()?;
        let mut value = Self {
            anchor_version,
            anchor_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            desktop_authorization_epoch: decoder.read_u64()?,
            mobile_authorization_epoch: decoder.read_u64()?,
            network_id: decoder.read_string()?,
            genesis_identifier: decoder.read_string()?,
            node_profile_id: decoder.read_string()?,
            transaction_format_version: decoder.read_u64()?,
            signer_epoch: decoder.read_u64()?,
            journal_epoch: decoder.read_u64()?,
            witness_epoch: decoder.read_u64()?,
            anchor_sequence: decoder.read_u64()?,
            previous_anchor_hash: decoder.read_string()?,
            journal_sequence: decoder.read_u64()?,
            journal_head_hash: decoder.read_string()?,
            materialized_state_commitment: decoder.read_string()?,
            last_operation_id: if decoder.read_bool()? {
                Some(decoder.read_string()?)
            } else {
                None
            },
            operation_phase: RollbackOperationPhase::from_tag(decoder.read_u8()?)?,
            transaction_state: None,
            policy_epoch: decoder.read_u64()?,
            capability_epoch: decoder.read_u64()?,
            created_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
        };
        if anchor_version == 2 {
            value.transaction_state = if decoder.read_bool()? {
                Some(WitnessTransactionState::decode(&mut decoder)?)
            } else {
                None
            };
        }
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
        let valid_previous = is_hash(&self.previous_anchor_hash)
            && ((self.anchor_sequence == 1 && self.previous_anchor_hash == ZERO_HASH)
                || (self.anchor_sequence > 1 && self.previous_anchor_hash != ZERO_HASH));
        let version_valid = match self.anchor_version {
            1 => self.transaction_state.is_none(),
            2 => self
                .transaction_state
                .as_ref()
                .is_some_and(|state| state.validate(self.operation_phase).is_ok()),
            _ => false,
        };
        if !version_valid
            || self.anchor_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.desktop_authorization_epoch == 0
            || self.mobile_authorization_epoch == 0
            || !crate::is_supported_pilot_network_id(&self.network_id)
            || !is_hash(&self.genesis_identifier)
            || self.genesis_identifier == ZERO_HASH
            || !is_hash(&self.node_profile_id)
            || self.transaction_format_version == 0
            || self.signer_epoch == 0
            || self.journal_epoch == 0
            || self.witness_epoch == 0
            || self.anchor_sequence == 0
            || !valid_previous
            || self.journal_sequence == 0
            || !is_hash(&self.journal_head_hash)
            || self.journal_head_hash == ZERO_HASH
            || !is_hash(&self.materialized_state_commitment)
            || self.materialized_state_commitment == ZERO_HASH
            || self
                .last_operation_id
                .as_ref()
                .is_some_and(|value| value.is_empty())
            || self.policy_epoch == 0
            || self.capability_epoch == 0
            || self.expires_at <= self.created_at
            || self.expires_at.saturating_sub(self.created_at) > MAX_ANCHOR_LIFETIME_SECS
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for RollbackAnchor {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.anchor_version);
        encoder.push_string(&self.anchor_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.desktop_authorization_epoch);
        encoder.push_u64(self.mobile_authorization_epoch);
        encoder.push_string(&self.network_id)?;
        encoder.push_string(&self.genesis_identifier)?;
        encoder.push_string(&self.node_profile_id)?;
        encoder.push_u64(self.transaction_format_version);
        encoder.push_u64(self.signer_epoch);
        encoder.push_u64(self.journal_epoch);
        encoder.push_u64(self.witness_epoch);
        encoder.push_u64(self.anchor_sequence);
        encoder.push_string(&self.previous_anchor_hash)?;
        encoder.push_u64(self.journal_sequence);
        encoder.push_string(&self.journal_head_hash)?;
        encoder.push_string(&self.materialized_state_commitment)?;
        encoder.push_bool(self.last_operation_id.is_some());
        if let Some(operation_id) = &self.last_operation_id {
            encoder.push_string(operation_id)?;
        }
        encoder.push_u8(self.operation_phase.tag());
        encoder.push_u64(self.policy_epoch);
        encoder.push_u64(self.capability_epoch);
        encoder.push_u64(self.created_at);
        encoder.push_u64(self.expires_at);
        if self.anchor_version == 2 {
            encoder.push_bool(self.transaction_state.is_some());
            if let Some(transaction_state) = &self.transaction_state {
                transaction_state.encode(encoder)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRollbackAnchor {
    pub anchor: RollbackAnchor,
    pub signature_hex: String,
}

impl SignedRollbackAnchor {
    pub async fn sign(
        anchor: RollbackAnchor,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Desktop
            || signer.identity().device_id() != &anchor.desktop_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::RollbackAnchor,
            &anchor.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            anchor,
            signature_hex,
        })
    }

    pub fn verify(&self, registry: &DeviceRegistry, now: u64) -> CompanionResult<String> {
        self.anchor.validate_at(now)?;
        let record = registry
            .records()
            .find(|record| record.device_id == self.anchor.desktop_device_id)
            .ok_or(CompanionError::UnknownDevice)?;
        record.validate()?;
        if record.is_revoked()
            || record.role != DeviceRole::Desktop
            || record.agent_wallet_id != self.anchor.agent_wallet_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        if record.authorization_epoch != self.anchor.desktop_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        registry.require(
            &self.anchor.mobile_device_id,
            &self.anchor.agent_wallet_id,
            DeviceRole::Mobile,
            DevicePermission::WitnessRollbackAnchor,
        )?;
        record.verify_signature(
            DeviceSignaturePurpose::RollbackAnchor,
            &self.anchor.canonical_bytes()?,
            &self.signature_hex,
        )?;
        self.anchor.canonical_sha256_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt {
    #[serde(with = "crate::serde_decimal_u64")]
    pub receipt_version: u64,
    pub anchor_id: String,
    pub anchor_hash: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub mobile_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub anchor_sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub accepted_at: u64,
}

impl WitnessReceipt {
    pub fn for_anchor(
        anchor: &RollbackAnchor,
        anchor_hash: String,
        accepted_at: u64,
    ) -> CompanionResult<Self> {
        let value = Self {
            receipt_version: 1,
            anchor_id: anchor.anchor_id.clone(),
            anchor_hash,
            agent_wallet_id: anchor.agent_wallet_id.clone(),
            desktop_device_id: anchor.desktop_device_id.clone(),
            mobile_device_id: anchor.mobile_device_id.clone(),
            mobile_authorization_epoch: anchor.mobile_authorization_epoch,
            witness_epoch: anchor.witness_epoch,
            anchor_sequence: anchor.anchor_sequence,
            accepted_at,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, RECEIPT_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, RECEIPT_DOMAIN)?;
        let value = Self {
            receipt_version: decoder.read_u64()?,
            anchor_id: decoder.read_string()?,
            anchor_hash: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_authorization_epoch: decoder.read_u64()?,
            witness_epoch: decoder.read_u64()?,
            anchor_sequence: decoder.read_u64()?,
            accepted_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.receipt_version != 1
            || self.anchor_id.is_empty()
            || !is_hash(&self.anchor_hash)
            || self.anchor_hash == ZERO_HASH
            || self.agent_wallet_id.is_empty()
            || self.mobile_authorization_epoch == 0
            || self.witness_epoch == 0
            || self.anchor_sequence == 0
            || self.accepted_at == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn matches_anchor(&self, anchor: &RollbackAnchor, anchor_hash: &str) -> bool {
        self.anchor_id == anchor.anchor_id
            && self.anchor_hash == anchor_hash
            && self.agent_wallet_id == anchor.agent_wallet_id
            && self.desktop_device_id == anchor.desktop_device_id
            && self.mobile_device_id == anchor.mobile_device_id
            && self.mobile_authorization_epoch == anchor.mobile_authorization_epoch
            && self.witness_epoch == anchor.witness_epoch
            && self.anchor_sequence == anchor.anchor_sequence
            && self.accepted_at >= anchor.created_at
            && self.accepted_at < anchor.expires_at
    }
}

impl CanonicalEncode for WitnessReceipt {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.receipt_version);
        encoder.push_string(&self.anchor_id)?;
        encoder.push_string(&self.anchor_hash)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.mobile_authorization_epoch);
        encoder.push_u64(self.witness_epoch);
        encoder.push_u64(self.anchor_sequence);
        encoder.push_u64(self.accepted_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessReceipt {
    pub receipt: WitnessReceipt,
    pub signature_hex: String,
}

impl SignedWitnessReceipt {
    pub async fn sign(
        receipt: WitnessReceipt,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &receipt.mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::WitnessReceipt,
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
        expected: &SignedRollbackAnchor,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<()> {
        let anchor_hash = expected.verify(registry, now)?;
        self.receipt.validate_shape()?;
        if !self.receipt.matches_anchor(&expected.anchor, &anchor_hash) {
            return Err(CompanionError::AnchorCommitmentMismatch);
        }
        let record = registry.require(
            &self.receipt.mobile_device_id,
            &self.receipt.agent_wallet_id,
            DeviceRole::Mobile,
            DevicePermission::WitnessRollbackAnchor,
        )?;
        if record.authorization_epoch != self.receipt.mobile_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::WitnessReceipt,
            &self.receipt.canonical_bytes()?,
            &self.signature_hex,
        )
    }
}

/// Durable public checkpoint held by the paired mobile device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileWitnessState {
    #[serde(with = "crate::serde_decimal_u64")]
    pub state_version: u64,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub network_id: String,
    pub genesis_identifier: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub signer_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub journal_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub witness_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub last_anchor_sequence: u64,
    pub last_anchor_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub last_journal_sequence: u64,
    pub last_journal_head_hash: String,
    pub accepted_anchor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_receipt: Option<WitnessReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transaction_state: Option<WitnessTransactionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_baseline: Option<WitnessRotationBaselineReceipt>,
}

impl MobileWitnessState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_wallet_id: String,
        desktop_device_id: DeviceId,
        mobile_device_id: DeviceId,
        network_id: String,
        genesis_identifier: String,
        signer_epoch: u64,
        journal_epoch: u64,
        witness_epoch: u64,
    ) -> CompanionResult<Self> {
        let value = Self {
            state_version: 1,
            agent_wallet_id,
            desktop_device_id,
            mobile_device_id,
            network_id,
            genesis_identifier,
            signer_epoch,
            journal_epoch,
            witness_epoch,
            last_anchor_sequence: 0,
            last_anchor_hash: ZERO_HASH.to_owned(),
            last_journal_sequence: 0,
            last_journal_head_hash: ZERO_HASH.to_owned(),
            accepted_anchor_ids: Vec::new(),
            last_receipt: None,
            last_transaction_state: None,
            rotation_baseline: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> CompanionResult<()> {
        let uninitialized = self.last_anchor_sequence == 0
            && self.last_anchor_hash == ZERO_HASH
            && self.last_journal_sequence == 0
            && self.last_journal_head_hash == ZERO_HASH
            && self.accepted_anchor_ids.is_empty()
            && self.last_receipt.is_none()
            && self.last_transaction_state.is_none()
            && self.rotation_baseline.is_none();
        let latest_checkpoint_matches =
            self.last_receipt.as_ref().is_some_and(|receipt| {
                receipt.anchor_hash == self.last_anchor_hash
                    && receipt.anchor_sequence == self.last_anchor_sequence
                    && receipt.agent_wallet_id == self.agent_wallet_id
                    && receipt.desktop_device_id == self.desktop_device_id
                    && receipt.mobile_device_id == self.mobile_device_id
                    && receipt.witness_epoch == self.witness_epoch
            }) || self.rotation_baseline.as_ref().is_some_and(|baseline| {
                baseline.baseline_anchor_hash == self.last_anchor_hash
                    && baseline.baseline_anchor_sequence == self.last_anchor_sequence
                    && baseline.agent_wallet_id == self.agent_wallet_id
                    && baseline.new_mobile_device_id == self.mobile_device_id
                    && baseline.witness_epoch == self.witness_epoch
            });
        let initialized = self.last_anchor_sequence > 0
            && self.last_anchor_hash != ZERO_HASH
            && self.last_journal_sequence > 0
            && self.last_journal_head_hash != ZERO_HASH
            && latest_checkpoint_matches
            && self.last_transaction_state.as_ref().is_none_or(|state| {
                !state.operation_id.is_empty()
                    && !state.agent_id.is_empty()
                    && is_hash(&state.signed_transaction_commitment)
            });
        let rotation_initialized_at_zero = self.last_anchor_sequence == 0
            && self.last_anchor_hash == ZERO_HASH
            && self.last_journal_sequence > 0
            && self.last_journal_head_hash != ZERO_HASH
            && self.accepted_anchor_ids.is_empty()
            && self.last_receipt.is_none()
            && self.last_transaction_state.is_none()
            && self.rotation_baseline.as_ref().is_some_and(|baseline| {
                baseline.baseline_anchor_sequence == 0
                    && baseline.baseline_anchor_hash == ZERO_HASH
                    && baseline.agent_wallet_id == self.agent_wallet_id
                    && baseline.new_mobile_device_id == self.mobile_device_id
                    && baseline.witness_epoch == self.witness_epoch
            });
        let unique_ids = self
            .accepted_anchor_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self.state_version != 1
            || self.agent_wallet_id.is_empty()
            || !crate::is_supported_pilot_network_id(&self.network_id)
            || !is_hash(&self.genesis_identifier)
            || self.genesis_identifier == ZERO_HASH
            || self.signer_epoch == 0
            || self.journal_epoch == 0
            || self.witness_epoch == 0
            || !is_hash(&self.last_anchor_hash)
            || !is_hash(&self.last_journal_head_hash)
            || self.accepted_anchor_ids.len() > MAX_ACCEPTED_ANCHOR_IDS
            || unique_ids.len() != self.accepted_anchor_ids.len()
            || (!uninitialized && !initialized && !rotation_initialized_at_zero)
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    pub fn from_rotation_baseline(
        rotation: &WitnessRotationRecord,
        signed: &SignedWitnessRotationBaselineReceipt,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<Self> {
        signed.verify(rotation, registry, now)?;
        let mut value = Self::new(
            rotation.agent_wallet_id.clone(),
            rotation.desktop_device_id.clone(),
            rotation.new_mobile_device_id.clone(),
            rotation.network_id.clone(),
            rotation.genesis_identifier.clone(),
            rotation.signer_epoch,
            rotation.journal_epoch,
            rotation.new_witness_epoch,
        )?;
        value.last_anchor_sequence = rotation.last_accepted_anchor_sequence;
        value.last_anchor_hash = rotation.last_accepted_anchor_hash.clone();
        value.last_journal_sequence = rotation.journal_sequence;
        value.last_journal_head_hash = rotation.journal_head_hash.clone();
        value.rotation_baseline = Some(signed.receipt.clone());
        value.validate()?;
        Ok(value)
    }

    /// Verifies and advances a cloned checkpoint. The caller must durably
    /// persist the returned state before signing and returning the receipt.
    pub fn accept_anchor(
        &mut self,
        proposal: &SignedRollbackAnchor,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<WitnessReceipt> {
        self.validate()?;
        let anchor_hash = proposal.verify(registry, now)?;
        let anchor = &proposal.anchor;
        if anchor.agent_wallet_id != self.agent_wallet_id
            || anchor.desktop_device_id != self.desktop_device_id
            || anchor.mobile_device_id != self.mobile_device_id
            || anchor.network_id != self.network_id
            || anchor.genesis_identifier != self.genesis_identifier
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        if anchor.signer_epoch != self.signer_epoch
            || anchor.journal_epoch != self.journal_epoch
            || anchor.witness_epoch != self.witness_epoch
        {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        if self.accepted_anchor_ids.contains(&anchor.anchor_id) {
            return Err(CompanionError::SequenceReplay);
        }
        if self.accepted_anchor_ids.len() >= MAX_ACCEPTED_ANCHOR_IDS {
            return Err(CompanionError::WitnessRequired);
        }
        let expected_sequence = self
            .last_anchor_sequence
            .checked_add(1)
            .ok_or(CompanionError::RollbackDetected)?;
        if anchor.anchor_sequence != expected_sequence {
            return Err(if anchor.anchor_sequence <= self.last_anchor_sequence {
                CompanionError::RollbackDetected
            } else {
                CompanionError::AnchorChainMismatch
            });
        }
        if anchor.previous_anchor_hash != self.last_anchor_hash {
            return Err(CompanionError::AnchorChainMismatch);
        }
        if anchor.journal_sequence < self.last_journal_sequence {
            return Err(CompanionError::RollbackDetected);
        }
        if anchor.journal_sequence == self.last_journal_sequence
            && anchor.journal_head_hash != self.last_journal_head_hash
        {
            return Err(CompanionError::RollbackDetected);
        }
        if anchor.anchor_version == 2 {
            let next = anchor
                .transaction_state
                .as_ref()
                .ok_or(CompanionError::MalformedMessage)?;
            if let Some(previous) = &self.last_transaction_state {
                let identity_unchanged = previous.operation_id == next.operation_id
                    && previous.agent_id == next.agent_id
                    && previous.signed_transaction_commitment == next.signed_transaction_commitment
                    && previous.transaction_id == next.transaction_id;
                let lifecycle_progresses = matches!(
                    (
                        previous.submission_status,
                        previous.reconciliation_status,
                        next.submission_status,
                        next.reconciliation_status,
                    ),
                    (
                        WitnessSubmissionStatus::NotSubmitted,
                        WitnessReconciliationStatus::NotStarted,
                        WitnessSubmissionStatus::Submitted | WitnessSubmissionStatus::Uncertain,
                        WitnessReconciliationStatus::NotStarted
                            | WitnessReconciliationStatus::Pending
                            | WitnessReconciliationStatus::Unknown,
                    ) | (
                        WitnessSubmissionStatus::Submitted | WitnessSubmissionStatus::Uncertain,
                        WitnessReconciliationStatus::NotStarted
                            | WitnessReconciliationStatus::Pending
                            | WitnessReconciliationStatus::Unknown,
                        WitnessSubmissionStatus::Submitted,
                        WitnessReconciliationStatus::Confirmed
                            | WitnessReconciliationStatus::Rejected,
                    )
                );
                let starts_next_operation = matches!(
                    previous.reconciliation_status,
                    WitnessReconciliationStatus::Confirmed | WitnessReconciliationStatus::Rejected
                ) && next.operation_id != previous.operation_id
                    && anchor.operation_phase == RollbackOperationPhase::SignedPreBroadcast
                    && next.submission_status == WitnessSubmissionStatus::NotSubmitted
                    && next.reconciliation_status == WitnessReconciliationStatus::NotStarted
                    && next.reservation_state == WitnessReservationState::Held;
                if !(identity_unchanged && lifecycle_progresses || starts_next_operation) {
                    return Err(CompanionError::AnchorCommitmentMismatch);
                }
            } else if anchor.operation_phase != RollbackOperationPhase::SignedPreBroadcast {
                return Err(CompanionError::AnchorChainMismatch);
            }
            self.last_transaction_state = Some(next.clone());
        } else if self.last_transaction_state.is_some() {
            return Err(CompanionError::RollbackDetected);
        }
        self.last_anchor_sequence = anchor.anchor_sequence;
        self.last_anchor_hash = anchor_hash.clone();
        self.last_journal_sequence = anchor.journal_sequence;
        self.last_journal_head_hash = anchor.journal_head_hash.clone();
        self.accepted_anchor_ids.push(anchor.anchor_id.clone());
        let receipt = WitnessReceipt::for_anchor(anchor, anchor_hash, now)?;
        self.last_receipt = Some(receipt.clone());
        self.rotation_baseline = None;
        self.validate()?;
        Ok(receipt)
    }

    /// Returns the receipt for an anchor which was already durably accepted.
    /// This supports retrying biometric signing after a transient failure
    /// without advancing the monotonic witness state twice.
    pub fn receipt_for_accepted_anchor(
        &self,
        proposal: &SignedRollbackAnchor,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<WitnessReceipt> {
        self.validate()?;
        let anchor_hash = proposal.verify(registry, now)?;
        self.last_receipt
            .as_ref()
            .filter(|receipt| receipt.matches_anchor(&proposal.anchor, &anchor_hash))
            .cloned()
            .ok_or(CompanionError::AnchorCommitmentMismatch)
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "witness/tests.rs"]
mod tests;
