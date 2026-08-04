use serde::{Deserialize, Serialize};

use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};
use crate::replay::{ReplayGuard, ReplayMetadata, ReplayPermit};

const COMMITMENT_DOMAIN: &[u8] = b"HPAY/COMPANION/APPROVAL-COMMITMENT/V2";
const DECISION_DOMAIN: &[u8] = b"HPAY/COMPANION/APPROVAL-DECISION/V2";
const APPROVAL_CONTEXT: &str = "approval_decision";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalNetworkBinding {
    pub network_id: String,
    pub chain_id: u32,
    pub genesis_identifier: String,
    pub node_profile_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub transaction_format_version: u64,
}

impl ApprovalNetworkBinding {
    fn validate(&self) -> CompanionResult<()> {
        if !crate::is_supported_pilot_network_id(&self.network_id)
            || self.chain_id == 0
            || !is_hex_len(&self.genesis_identifier, 32)
            || !is_hex_len(&self.node_profile_id, 32)
            || self.transaction_format_version == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        self.validate()?;
        encoder.push_string(&self.network_id)?;
        encoder.push_u32(self.chain_id);
        encoder.push_string(&self.genesis_identifier)?;
        encoder.push_string(&self.node_profile_id)?;
        encoder.push_u64(self.transaction_format_version);
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> CompanionResult<Self> {
        let value = Self {
            network_id: decoder.read_string()?,
            chain_id: decoder.read_u32()?,
            genesis_identifier: decoder.read_string()?,
            node_profile_id: decoder.read_string()?,
            transaction_format_version: decoder.read_u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCommitment {
    #[serde(with = "crate::serde_decimal_u64")]
    pub approval_version: u64,
    pub approval_id: String,
    pub operation_id: String,
    pub agent_wallet_id: String,
    pub agent_id: String,
    pub desktop_device_id: DeviceId,
    pub transaction_commitment: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub wallet_fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub total_debit_units: u64,
    pub recipient: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    pub challenge_nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_binding: Option<ApprovalNetworkBinding>,
}

impl ApprovalCommitment {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate()?;
        CanonicalEncode::canonical_bytes(self, COMMITMENT_DOMAIN)
    }

    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.validate()?;
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            COMMITMENT_DOMAIN,
        )?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, COMMITMENT_DOMAIN)?;
        let approval_version = decoder.read_u64()?;
        let mut value = Self {
            approval_version,
            approval_id: decoder.read_string()?,
            operation_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            agent_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            transaction_commitment: decoder.read_string()?,
            amount_units: decoder.read_u64()?,
            fee_units: decoder.read_u64()?,
            wallet_fee_units: decoder.read_u64()?,
            total_debit_units: decoder.read_u64()?,
            recipient: decoder.read_string()?,
            policy_epoch: decoder.read_u64()?,
            challenge_nonce: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            network_binding: None,
        };
        if approval_version == 3 {
            value.network_binding = Some(ApprovalNetworkBinding::decode(&mut decoder)?);
        }
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate()?;
        if self.expires_at <= now {
            return Err(CompanionError::Expired);
        }
        if self.issued_at > now || self.expires_at <= self.issued_at {
            return Err(CompanionError::InvalidIssuedAt);
        }
        Ok(())
    }

    fn validate(&self) -> CompanionResult<()> {
        let expected_total = self
            .amount_units
            .checked_add(self.fee_units)
            .ok_or(CompanionError::MalformedMessage)?;
        let version_valid = matches!(
            (self.approval_version, &self.network_binding),
            (2, None) | (3, Some(_))
        );
        if let Some(binding) = &self.network_binding {
            binding.validate()?;
        }
        if !version_valid
            || self.approval_id.is_empty()
            || self.operation_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.agent_id.is_empty()
            || self.amount_units == 0
            || self.wallet_fee_units != 0
            || self.total_debit_units != expected_total
            || self.recipient.is_empty()
            || self.policy_epoch == 0
            || !is_hex_len(&self.transaction_commitment, 32)
            || !is_hex_len(&self.challenge_nonce, 16)
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for ApprovalCommitment {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.approval_version);
        encoder.push_string(&self.approval_id)?;
        encoder.push_string(&self.operation_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(&self.agent_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(&self.transaction_commitment)?;
        encoder.push_u64(self.amount_units);
        encoder.push_u64(self.fee_units);
        encoder.push_u64(self.wallet_fee_units);
        encoder.push_u64(self.total_debit_units);
        encoder.push_string(&self.recipient)?;
        encoder.push_u64(self.policy_epoch);
        encoder.push_string(&self.challenge_nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        if let Some(binding) = &self.network_binding {
            binding.encode(encoder)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

impl ApprovalDecision {
    fn tag(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::Reject => 2,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::Approve),
            2 => Ok(Self::Reject),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

/// The exact transaction-binding envelope signed by the paired mobile device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileApprovalDecision {
    #[serde(with = "crate::serde_decimal_u64")]
    pub decision_version: u64,
    pub approval_id: String,
    pub decision: ApprovalDecision,
    pub operation_id: String,
    pub agent_wallet_id: String,
    pub agent_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub device_authorization_epoch: u64,
    pub transaction_commitment: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub wallet_fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub total_debit_units: u64,
    pub recipient: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    pub challenge_nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub approval_sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_binding: Option<ApprovalNetworkBinding>,
}

impl MobileApprovalDecision {
    pub fn from_commitment(
        commitment: &ApprovalCommitment,
        decision: ApprovalDecision,
        mobile_device_id: DeviceId,
        device_authorization_epoch: u64,
        approval_sequence: u64,
        issued_at: u64,
    ) -> Self {
        Self {
            decision_version: commitment.approval_version,
            approval_id: commitment.approval_id.clone(),
            decision,
            operation_id: commitment.operation_id.clone(),
            agent_wallet_id: commitment.agent_wallet_id.clone(),
            agent_id: commitment.agent_id.clone(),
            desktop_device_id: commitment.desktop_device_id.clone(),
            mobile_device_id,
            device_authorization_epoch,
            transaction_commitment: commitment.transaction_commitment.clone(),
            amount_units: commitment.amount_units,
            fee_units: commitment.fee_units,
            wallet_fee_units: commitment.wallet_fee_units,
            total_debit_units: commitment.total_debit_units,
            recipient: commitment.recipient.clone(),
            policy_epoch: commitment.policy_epoch,
            challenge_nonce: commitment.challenge_nonce.clone(),
            approval_sequence,
            issued_at,
            expires_at: commitment.expires_at,
            network_binding: commitment.network_binding.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, DECISION_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, DECISION_DOMAIN)?;
        let decision_version = decoder.read_u64()?;
        let mut value = Self {
            decision_version,
            approval_id: decoder.read_string()?,
            decision: ApprovalDecision::from_tag(decoder.read_u8()?)?,
            operation_id: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            agent_id: decoder.read_string()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            device_authorization_epoch: decoder.read_u64()?,
            transaction_commitment: decoder.read_string()?,
            amount_units: decoder.read_u64()?,
            fee_units: decoder.read_u64()?,
            wallet_fee_units: decoder.read_u64()?,
            total_debit_units: decoder.read_u64()?,
            recipient: decoder.read_string()?,
            policy_epoch: decoder.read_u64()?,
            challenge_nonce: decoder.read_string()?,
            approval_sequence: decoder.read_u64()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            network_binding: None,
        };
        if decision_version == 3 {
            value.network_binding = Some(ApprovalNetworkBinding::decode(&mut decoder)?);
        }
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
    pub fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: APPROVAL_CONTEXT.to_owned(),
            sender_device_id: self.mobile_device_id.clone(),
            sequence: self.approval_sequence,
            nonce: self.challenge_nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        let expected_total = self
            .amount_units
            .checked_add(self.fee_units)
            .ok_or(CompanionError::MalformedMessage)?;
        let version_valid = matches!(
            (self.decision_version, &self.network_binding),
            (2, None) | (3, Some(_))
        );
        if let Some(binding) = &self.network_binding {
            binding.validate()?;
        }
        if !version_valid
            || self.approval_id.is_empty()
            || self.operation_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.agent_id.is_empty()
            || self.device_authorization_epoch == 0
            || self.amount_units == 0
            || self.wallet_fee_units != 0
            || self.total_debit_units != expected_total
            || self.recipient.is_empty()
            || self.policy_epoch == 0
            || !is_hex_len(&self.transaction_commitment, 32)
            || !is_hex_len(&self.challenge_nonce, 16)
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn matches_commitment(&self, expected: &ApprovalCommitment) -> bool {
        self.approval_id == expected.approval_id
            && self.operation_id == expected.operation_id
            && self.agent_wallet_id == expected.agent_wallet_id
            && self.agent_id == expected.agent_id
            && self.desktop_device_id == expected.desktop_device_id
            && self.transaction_commitment == expected.transaction_commitment
            && self.amount_units == expected.amount_units
            && self.fee_units == expected.fee_units
            && self.wallet_fee_units == expected.wallet_fee_units
            && self.total_debit_units == expected.total_debit_units
            && self.recipient == expected.recipient
            && self.policy_epoch == expected.policy_epoch
            && self.challenge_nonce == expected.challenge_nonce
            && self.issued_at >= expected.issued_at
            && self.expires_at == expected.expires_at
            && self.network_binding == expected.network_binding
    }
}

impl CanonicalEncode for MobileApprovalDecision {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.decision_version);
        encoder.push_string(&self.approval_id)?;
        encoder.push_u8(self.decision.tag());
        encoder.push_string(&self.operation_id)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(&self.agent_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.device_authorization_epoch);
        encoder.push_string(&self.transaction_commitment)?;
        encoder.push_u64(self.amount_units);
        encoder.push_u64(self.fee_units);
        encoder.push_u64(self.wallet_fee_units);
        encoder.push_u64(self.total_debit_units);
        encoder.push_string(&self.recipient)?;
        encoder.push_u64(self.policy_epoch);
        encoder.push_string(&self.challenge_nonce)?;
        encoder.push_u64(self.approval_sequence);
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        if let Some(binding) = &self.network_binding {
            binding.encode(encoder)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalDecision {
    pub decision: MobileApprovalDecision,
    pub signature_hex: String,
}

impl SignedApprovalDecision {
    pub async fn sign(
        decision: MobileApprovalDecision,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &decision.mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::ApprovalDecision,
            &decision.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            decision,
            signature_hex,
        })
    }

    pub fn verify(
        &self,
        expected: &ApprovalCommitment,
        registry: &DeviceRegistry,
        replay_guard: &ReplayGuard,
        now: u64,
    ) -> CompanionResult<ReplayPermit> {
        expected.validate_at(now)?;
        self.decision.validate_shape()?;
        if !self.decision.matches_commitment(expected) {
            return Err(CompanionError::ApprovalCommitmentMismatch);
        }
        let permission = match self.decision.decision {
            ApprovalDecision::Approve => DevicePermission::ApprovePayment,
            ApprovalDecision::Reject => DevicePermission::RejectPayment,
        };
        let record = registry.require(
            &self.decision.mobile_device_id,
            &self.decision.agent_wallet_id,
            DeviceRole::Mobile,
            permission,
        )?;
        if record.authorization_epoch != self.decision.device_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::ApprovalDecision,
            &self.decision.canonical_bytes()?,
            &self.signature_hex,
        )?;
        replay_guard.check(&self.decision.replay_metadata(), now)
    }
}

fn is_hex_len(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::admin::{AdminCommand, AdminCommandKind, SignedAdminCommand};
    use crate::identity::SoftwareDeviceIdentity as DeviceIdentity;

    fn fixture() -> (
        DeviceIdentity,
        DeviceRegistry,
        ApprovalCommitment,
        MobileApprovalDecision,
    ) {
        let desktop = DeviceIdentity::generate(DeviceRole::Desktop);
        let mobile = DeviceIdentity::generate(DeviceRole::Mobile);
        let permissions = BTreeSet::from([
            DevicePermission::ApprovePayment,
            DevicePermission::RejectPayment,
            DevicePermission::EmergencyStop,
        ]);
        let mut registry = DeviceRegistry::new();
        registry
            .register(mobile.public_record("wallet_one", permissions, 90).unwrap())
            .unwrap();
        let commitment = ApprovalCommitment {
            approval_version: 2,
            approval_id: "approval_1".to_owned(),
            operation_id: "operation_1".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            agent_id: "agent_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            transaction_commitment: "ab".repeat(32),
            amount_units: 10_000,
            fee_units: 30,
            wallet_fee_units: 0,
            total_debit_units: 10_030,
            recipient: "1Recipient".to_owned(),
            policy_epoch: 7,
            challenge_nonce: "cd".repeat(16),
            issued_at: 100,
            expires_at: 200,
            network_binding: None,
        };
        let decision = MobileApprovalDecision::from_commitment(
            &commitment,
            ApprovalDecision::Approve,
            mobile.device_id().clone(),
            1,
            1,
            101,
        );
        (mobile, registry, commitment, decision)
    }

    #[tokio::test]
    async fn valid_decision_roundtrips_and_consumes_once() {
        let (mobile, registry, commitment, decision) = fixture();
        let signed = SignedApprovalDecision::sign(decision.clone(), &mobile)
            .await
            .unwrap();
        let mut guard = ReplayGuard::new();
        let permit = signed.verify(&commitment, &registry, &guard, 102).unwrap();
        guard.commit(permit, 102).unwrap();
        assert_eq!(
            signed.verify(&commitment, &registry, &guard, 103),
            Err(CompanionError::SequenceReplay)
        );
        assert_eq!(
            MobileApprovalDecision::from_canonical_bytes(&decision.canonical_bytes().unwrap())
                .unwrap(),
            decision
        );
    }

    #[tokio::test]
    async fn device_authorization_epoch_is_signed_and_must_match_registry() {
        let (mobile, _, commitment, decision) = fixture();
        let permissions = BTreeSet::from([
            DevicePermission::ApprovePayment,
            DevicePermission::RejectPayment,
        ]);
        let mut current_registry = DeviceRegistry::new();
        current_registry
            .register(mobile.public_record("wallet_one", permissions, 90).unwrap())
            .unwrap();
        let mut persisted = serde_json::to_value(&current_registry).unwrap();
        persisted["devices"][mobile.device_id().as_str()]["authorization_epoch"] =
            serde_json::json!("2");
        let current_registry: DeviceRegistry = serde_json::from_value(persisted).unwrap();
        current_registry.validate().unwrap();

        let stale = SignedApprovalDecision::sign(decision.clone(), &mobile)
            .await
            .unwrap();
        assert_eq!(
            stale.verify(&commitment, &current_registry, &ReplayGuard::new(), 102,),
            Err(CompanionError::AuthorizationEpochMismatch)
        );

        let mut current = decision;
        current.device_authorization_epoch = 2;
        let current = SignedApprovalDecision::sign(current, &mobile)
            .await
            .unwrap();
        assert!(
            current
                .verify(&commitment, &current_registry, &ReplayGuard::new(), 102,)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn valid_shape_transaction_mutations_mismatch_the_expected_commitment() {
        let (mobile, registry, commitment, decision) = fixture();
        let signed = SignedApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        let guard = ReplayGuard::new();
        let mut mutations = Vec::new();

        let mut value = signed.clone();
        value.decision.amount_units += 1;
        value.decision.total_debit_units += 1;
        mutations.push(value);

        let mut value = signed.clone();
        value.decision.fee_units += 1;
        value.decision.total_debit_units += 1;
        mutations.push(value);

        let mut value = signed.clone();
        value.decision.recipient.push('x');
        mutations.push(value);

        let mut value = signed.clone();
        value.decision.transaction_commitment = "ef".repeat(32);
        mutations.push(value);

        let mut value = signed.clone();
        value.decision.operation_id.push('x');
        mutations.push(value);

        let mut value = signed.clone();
        value.decision.agent_id.push('x');
        mutations.push(value);

        let mut value = signed;
        value.decision.policy_epoch += 1;
        mutations.push(value);

        for mutation in mutations {
            assert_eq!(
                mutation.verify(&commitment, &registry, &guard, 102),
                Err(CompanionError::ApprovalCommitmentMismatch)
            );
        }
    }

    #[test]
    fn shape_invalid_fee_and_total_mutations_fail_as_malformed() {
        let (_, _, _, decision) = fixture();

        let mut wrong_network_fee = decision.clone();
        wrong_network_fee.fee_units += 1;
        assert_eq!(
            wrong_network_fee.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut charged_wallet_fee = decision.clone();
        charged_wallet_fee.wallet_fee_units = 1;
        charged_wallet_fee.total_debit_units += 1;
        assert_eq!(
            charged_wallet_fee.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut wrong_total = decision;
        wrong_total.total_debit_units += 1;
        assert_eq!(
            wrong_total.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );
    }

    #[tokio::test]
    async fn valid_shape_mutation_with_adjusted_expected_fails_signature_verification() {
        let (mobile, registry, commitment, decision) = fixture();
        let mut signed = SignedApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        signed.decision.amount_units += 1;
        signed.decision.total_debit_units += 1;

        let mut adjusted_expected = commitment;
        adjusted_expected.amount_units += 1;
        adjusted_expected.total_debit_units += 1;
        assert_eq!(
            signed.verify(&adjusted_expected, &registry, &ReplayGuard::new(), 102),
            Err(CompanionError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn bad_signature_expiry_and_wallet_scope_fail_closed() {
        let (mobile, registry, commitment, decision) = fixture();
        let mut signed = SignedApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        // Guaranteed to differ: a fixed "00" leaves a signature that already
        // starts with those digits untouched, and it then verifies.
        let replacement = if signed.signature_hex.starts_with("00") {
            "01"
        } else {
            "00"
        };
        signed.signature_hex.replace_range(0..2, replacement);
        assert_eq!(
            signed.verify(&commitment, &registry, &ReplayGuard::new(), 102),
            Err(CompanionError::InvalidSignature)
        );
        let valid = SignedApprovalDecision::sign(
            MobileApprovalDecision::from_commitment(
                &commitment,
                ApprovalDecision::Reject,
                mobile.device_id().clone(),
                1,
                2,
                101,
            ),
            &mobile,
        )
        .await
        .unwrap();
        assert_eq!(
            valid.verify(&commitment, &registry, &ReplayGuard::new(), 200),
            Err(CompanionError::Expired)
        );
        let mut other_wallet = commitment.clone();
        other_wallet.agent_wallet_id = "wallet_two".to_owned();
        assert_eq!(
            valid.verify(&other_wallet, &registry, &ReplayGuard::new(), 102),
            Err(CompanionError::ApprovalCommitmentMismatch)
        );
    }

    #[test]
    fn legacy_or_nonzero_wallet_fee_approval_fails_closed() {
        let (_, _, commitment, decision) = fixture();

        let mut legacy = commitment.clone();
        legacy.approval_version = 1;
        assert_eq!(
            legacy.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut charged = commitment.clone();
        charged.wallet_fee_units = 1;
        charged.total_debit_units += 1;
        assert_eq!(
            charged.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut wrong_total = commitment;
        wrong_total.total_debit_units += 1;
        assert_eq!(
            wrong_total.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut legacy_decision = decision;
        legacy_decision.decision_version = 1;
        assert_eq!(
            legacy_decision.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let (_, _, _, current_decision) = fixture();
        let mut legacy_json = serde_json::to_value(current_decision).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("device_authorization_epoch");
        assert!(serde_json::from_value::<MobileApprovalDecision>(legacy_json).is_err());
    }

    #[tokio::test]
    async fn approval_signature_cannot_authorize_admin_domain() {
        let (mobile, registry, commitment, decision) = fixture();
        let approval = SignedApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        let command = AdminCommand {
            command_version: 2,
            command_id: "command_domain_test".to_owned(),
            command_type: AdminCommandKind::SuspendAgentPayments,
            agent_wallet_id: commitment.agent_wallet_id,
            mobile_device_id: mobile.device_id().clone(),
            device_authorization_epoch: 1,
            desktop_device_id: commitment.desktop_device_id,
            policy_epoch: commitment.policy_epoch,
            command_sequence: 1,
            nonce: "ef".repeat(16),
            issued_at: 101,
            expires_at: 150,
        };
        let signed_admin = SignedAdminCommand {
            command: command.clone(),
            signature_hex: approval.signature_hex,
        };
        assert_eq!(
            signed_admin.verify(
                "wallet_one",
                &command.desktop_device_id,
                7,
                &registry,
                &ReplayGuard::new(),
                102,
            ),
            Err(CompanionError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn canonical_decoder_rejects_trailing_and_json_unknown_fields() {
        let (_, _, commitment, _) = fixture();
        let mut bytes = commitment.canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            ApprovalCommitment::from_canonical_bytes(&bytes),
            Err(CompanionError::MalformedMessage)
        );
        let mut json = serde_json::to_value(&commitment).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<ApprovalCommitment>(json).is_err());
    }

    #[test]
    fn approval_money_json_uses_decimal_strings_and_preserves_u64_max() {
        let (_, _, mut commitment, _) = fixture();
        commitment.amount_units = u64::MAX;
        commitment.fee_units = 0;
        commitment.total_debit_units = u64::MAX;

        let json = serde_json::to_value(&commitment).unwrap();
        for (field, expected) in [
            ("amount_units", u64::MAX.to_string()),
            ("fee_units", "0".to_owned()),
            ("wallet_fee_units", "0".to_owned()),
            ("total_debit_units", u64::MAX.to_string()),
        ] {
            assert_eq!(
                json.get(field).and_then(serde_json::Value::as_str),
                Some(expected.as_str())
            );
        }
        assert_eq!(
            serde_json::from_value::<ApprovalCommitment>(json).unwrap(),
            commitment
        );
    }

    #[test]
    fn approval_money_json_rejects_numbers_and_malformed_decimal_strings() {
        let (_, _, commitment, decision) = fixture();
        for field in [
            "amount_units",
            "fee_units",
            "wallet_fee_units",
            "total_debit_units",
        ] {
            let mut numeric_commitment = serde_json::to_value(&commitment).unwrap();
            numeric_commitment
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!(1));
            assert!(
                serde_json::from_value::<ApprovalCommitment>(numeric_commitment).is_err(),
                "{field} accepted a JSON number"
            );

            let mut numeric_decision = serde_json::to_value(&decision).unwrap();
            numeric_decision
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!(1));
            assert!(
                serde_json::from_value::<MobileApprovalDecision>(numeric_decision).is_err(),
                "{field} accepted a JSON number"
            );

            for malformed in [
                "",
                "-1",
                "+1",
                " 1",
                "1 ",
                "1.0",
                "00",
                "01",
                "18446744073709551616",
            ] {
                let mut malformed_commitment = serde_json::to_value(&commitment).unwrap();
                malformed_commitment
                    .as_object_mut()
                    .unwrap()
                    .insert(field.to_owned(), serde_json::json!(malformed));
                assert!(
                    serde_json::from_value::<ApprovalCommitment>(malformed_commitment).is_err(),
                    "{field} accepted malformed decimal string {malformed:?}"
                );

                let mut malformed_decision = serde_json::to_value(&decision).unwrap();
                malformed_decision
                    .as_object_mut()
                    .unwrap()
                    .insert(field.to_owned(), serde_json::json!(malformed));
                assert!(
                    serde_json::from_value::<MobileApprovalDecision>(malformed_decision).is_err(),
                    "{field} accepted malformed decimal string {malformed:?}"
                );
            }
        }
    }
}
