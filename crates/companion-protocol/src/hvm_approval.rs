//! Canonical mobile-owner approval for one exact Agent HVM Fast Pay bill.
//!
//! This schema is deliberately distinct from native ChannelPay approval. It
//! binds the reviewed HVM deployment, channel incarnation, lease snapshot,
//! durable previous bill and exact unsigned next bill before any Agent key is
//! used. It grants no generic signing or transaction authority.

use serde::{Deserialize, Serialize};

use crate::ApprovalDecision;
use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::fast_pay_approval::AgentFastPayNetworkBinding;
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};
use crate::replay::{ReplayGuard, ReplayMetadata, ReplayPermit};

const COMMITMENT_DOMAIN: &[u8] = b"HPAY/COMPANION/AGENT-HVM-APPROVAL/V1";
const DECISION_DOMAIN: &[u8] = b"HPAY/COMPANION/AGENT-HVM-DECISION/V1";
const SIGNED_DECISION_DOMAIN: &[u8] = b"HPAY/COMPANION/AGENT-HVM-SIGNED-DECISION/V1";
const DECISION_CONTEXT: &str = "agent_hvm_approval_decision";
const V1_SETTLEMENT_PROFILE: &str = "hpay-hvm-channel-v1";
const V1_REVIEWED_BYTECODE_SHA3: &str =
    "11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349";
const V2_SETTLEMENT_PROFILE: &str = "hpay-hvm-shared-registry-v2";
const V2_REVIEWED_BYTECODE_SHA3: &str =
    "2fa7429d9e686dd2457eeb1b4476f972c7ddd9be6a0371c9765eff2910209b04";
const ZHU_PER_HAC: u64 = 100_000_000;
pub const AGENT_HVM_APPROVAL_VERSION: u64 = 1;
pub const AGENT_HVM_APPROVAL_MAX_LIFETIME_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmApprovalCommitment {
    #[serde(with = "crate::serde_decimal_u64")]
    pub approval_version: u64,
    pub approval_id: String,
    pub challenge_nonce: String,
    pub operation_id: String,
    pub hub_operation_id: String,
    pub public_idempotency_key: String,
    pub hub_idempotency_key: String,
    pub agent_wallet_id: String,
    pub wallet_scope: String,
    pub agent_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub agent_authorization_epoch: u64,
    pub desktop_device_id: DeviceId,
    pub hub_url: String,
    pub hub_address: String,
    pub settlement_profile: String,
    pub contract_address: String,
    pub deployment_tx_hash: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub deployment_height: u64,
    pub bytecode_sha3: String,
    pub channel_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub channel_reuse_version: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub challenge_blocks: u64,
    pub binding_commitment: String,
    pub lease_snapshot_commitment: String,
    pub previous_bill_commitment: String,
    pub unsigned_request_commitment: String,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_zhu: u64,
    pub fee_payer: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub network_fee_zhu: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub wallet_fee_zhu: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub hub_fee_zhu: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub total_debit_zhu: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub signer_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub emergency_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub network_binding: AgentFastPayNetworkBinding,
}

impl AgentHvmApprovalCommitment {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, COMMITMENT_DOMAIN)
    }

    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.validate_shape()?;
        Ok(hex::encode(CanonicalEncode::canonical_sha256(
            self,
            COMMITMENT_DOMAIN,
        )?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, COMMITMENT_DOMAIN)?;
        let value = Self {
            approval_version: decoder.read_u64()?,
            approval_id: decoder.read_string()?,
            challenge_nonce: decoder.read_string()?,
            operation_id: decoder.read_string()?,
            hub_operation_id: decoder.read_string()?,
            public_idempotency_key: decoder.read_string()?,
            hub_idempotency_key: decoder.read_string()?,
            agent_wallet_id: decoder.read_string()?,
            wallet_scope: decoder.read_string()?,
            agent_id: decoder.read_string()?,
            agent_authorization_epoch: decoder.read_u64()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            hub_url: decoder.read_string()?,
            hub_address: decoder.read_string()?,
            settlement_profile: decoder.read_string()?,
            contract_address: decoder.read_string()?,
            deployment_tx_hash: decoder.read_string()?,
            deployment_height: decoder.read_u64()?,
            bytecode_sha3: decoder.read_string()?,
            channel_id: decoder.read_string()?,
            channel_reuse_version: decoder.read_u64()?,
            challenge_blocks: decoder.read_u64()?,
            binding_commitment: decoder.read_string()?,
            lease_snapshot_commitment: decoder.read_string()?,
            previous_bill_commitment: decoder.read_string()?,
            unsigned_request_commitment: decoder.read_string()?,
            payer: decoder.read_string()?,
            payee: decoder.read_string()?,
            amount_hac: decoder.read_string()?,
            amount_zhu: decoder.read_u64()?,
            fee_payer: decoder.read_string()?,
            network_fee_zhu: decoder.read_u64()?,
            wallet_fee_zhu: decoder.read_u64()?,
            hub_fee_zhu: decoder.read_u64()?,
            total_debit_zhu: decoder.read_u64()?,
            policy_epoch: decoder.read_u64()?,
            signer_epoch: decoder.read_u64()?,
            emergency_epoch: decoder.read_u64()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            network_binding: AgentFastPayNetworkBinding::decode(&mut decoder)?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        if self.issued_at > now {
            return Err(CompanionError::InvalidIssuedAt);
        }
        if self.expires_at <= now {
            return Err(CompanionError::Expired);
        }
        Ok(())
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        self.network_binding.validate_shape()?;
        let maximum_expiry = self
            .issued_at
            .checked_add(AGENT_HVM_APPROVAL_MAX_LIFETIME_SECS);
        if self.approval_version != AGENT_HVM_APPROVAL_VERSION
            || !valid_text(&self.approval_id)
            || !is_lower_hex_len(&self.challenge_nonce, 16)
            || !valid_text(&self.operation_id)
            || !is_canonical_uuid(&self.hub_operation_id)
            || !valid_text(&self.public_idempotency_key)
            || !self.hub_idempotency_key.starts_with("hpay-agent-hvm:")
            || !valid_text(&self.hub_idempotency_key)
            || !valid_text(&self.agent_wallet_id)
            || self.wallet_scope != format!("agent_wallet:{}", self.agent_wallet_id)
            || !valid_text(&self.agent_id)
            || self.agent_authorization_epoch == 0
            || !valid_hub_url(&self.hub_url, &self.network_binding.network_mode)
            || !valid_text(&self.hub_address)
            || !is_reviewed_settlement_artifact(&self.settlement_profile, &self.bytecode_sha3)
            || !valid_text(&self.contract_address)
            || !is_lower_hex_len(&self.deployment_tx_hash, 32)
            || self.deployment_height == 0
            || !is_lower_hex_len(&self.channel_id, 16)
            || self.channel_reuse_version == 0 && self.settlement_profile != V2_SETTLEMENT_PROFILE
            || self.challenge_blocks == 0
            || !is_lower_hex_len(&self.binding_commitment, 32)
            || !is_lower_hex_len(&self.lease_snapshot_commitment, 32)
            || !is_lower_hex_len(&self.previous_bill_commitment, 32)
            || !is_lower_hex_len(&self.unsigned_request_commitment, 32)
            || !valid_text(&self.payer)
            || !valid_text(&self.payee)
            || self.payer == self.payee
            || self.amount_zhu == 0
            || self.amount_hac != format_hac_zhu(self.amount_zhu)
            || self.fee_payer != "sender"
            || self.network_fee_zhu != 0
            || self.wallet_fee_zhu != 0
            || self.hub_fee_zhu != 0
            || self.total_debit_zhu != self.amount_zhu
            || self.policy_epoch == 0
            || self.signer_epoch == 0
            || self.emergency_epoch == 0
            || self.expires_at <= self.issued_at
            || maximum_expiry.is_none_or(|maximum| self.expires_at > maximum)
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for AgentHvmApprovalCommitment {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.approval_version);
        for value in [
            self.approval_id.as_str(),
            self.challenge_nonce.as_str(),
            self.operation_id.as_str(),
            self.hub_operation_id.as_str(),
            self.public_idempotency_key.as_str(),
            self.hub_idempotency_key.as_str(),
            self.agent_wallet_id.as_str(),
            self.wallet_scope.as_str(),
            self.agent_id.as_str(),
        ] {
            encoder.push_string(value)?;
        }
        encoder.push_u64(self.agent_authorization_epoch);
        encoder.push_string(self.desktop_device_id.as_str())?;
        for value in [
            self.hub_url.as_str(),
            self.hub_address.as_str(),
            self.settlement_profile.as_str(),
            self.contract_address.as_str(),
            self.deployment_tx_hash.as_str(),
        ] {
            encoder.push_string(value)?;
        }
        encoder.push_u64(self.deployment_height);
        for value in [self.bytecode_sha3.as_str(), self.channel_id.as_str()] {
            encoder.push_string(value)?;
        }
        encoder.push_u64(self.channel_reuse_version);
        encoder.push_u64(self.challenge_blocks);
        for value in [
            self.binding_commitment.as_str(),
            self.lease_snapshot_commitment.as_str(),
            self.previous_bill_commitment.as_str(),
            self.unsigned_request_commitment.as_str(),
            self.payer.as_str(),
            self.payee.as_str(),
            self.amount_hac.as_str(),
        ] {
            encoder.push_string(value)?;
        }
        encoder.push_u64(self.amount_zhu);
        encoder.push_string(&self.fee_payer)?;
        encoder.push_u64(self.network_fee_zhu);
        encoder.push_u64(self.wallet_fee_zhu);
        encoder.push_u64(self.hub_fee_zhu);
        encoder.push_u64(self.total_debit_zhu);
        encoder.push_u64(self.policy_epoch);
        encoder.push_u64(self.signer_epoch);
        encoder.push_u64(self.emergency_epoch);
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        self.network_binding.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmApprovalDecision {
    #[serde(with = "crate::serde_decimal_u64")]
    pub decision_version: u64,
    pub decision: ApprovalDecision,
    pub commitment: AgentHvmApprovalCommitment,
    pub commitment_sha256: String,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub device_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub approval_sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub decision_issued_at: u64,
}

impl AgentHvmApprovalDecision {
    pub fn from_commitment(
        commitment: AgentHvmApprovalCommitment,
        decision: ApprovalDecision,
        mobile_device_id: DeviceId,
        device_authorization_epoch: u64,
        approval_sequence: u64,
        decision_issued_at: u64,
    ) -> CompanionResult<Self> {
        let commitment_sha256 = commitment.canonical_sha256_hex()?;
        let value = Self {
            decision_version: AGENT_HVM_APPROVAL_VERSION,
            decision,
            commitment,
            commitment_sha256,
            mobile_device_id,
            device_authorization_epoch,
            approval_sequence,
            decision_issued_at,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, DECISION_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, DECISION_DOMAIN)?;
        let value = Self {
            decision_version: decoder.read_u64()?,
            decision: decode_decision(decoder.read_u8()?)?,
            commitment: AgentHvmApprovalCommitment::from_canonical_bytes(decoder.read_bytes()?)?,
            commitment_sha256: decoder.read_string()?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            device_authorization_epoch: decoder.read_u64()?,
            approval_sequence: decoder.read_u64()?,
            decision_issued_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.decision_version != AGENT_HVM_APPROVAL_VERSION
            || self.commitment_sha256 != self.commitment.canonical_sha256_hex()?
            || self.device_authorization_epoch == 0
            || self.approval_sequence == 0
            || self.decision_issued_at < self.commitment.issued_at
            || self.decision_issued_at >= self.commitment.expires_at
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: DECISION_CONTEXT.into(),
            sender_device_id: self.mobile_device_id.clone(),
            sequence: self.approval_sequence,
            nonce: self.commitment.challenge_nonce.clone(),
            issued_at: self.decision_issued_at,
            expires_at: self.commitment.expires_at,
        }
    }
}

impl CanonicalEncode for AgentHvmApprovalDecision {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.decision_version);
        encoder.push_u8(match self.decision {
            ApprovalDecision::Approve => 1,
            ApprovalDecision::Reject => 2,
        });
        encoder.push_bytes(&self.commitment.canonical_bytes()?)?;
        encoder.push_string(&self.commitment_sha256)?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.device_authorization_epoch);
        encoder.push_u64(self.approval_sequence);
        encoder.push_u64(self.decision_issued_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentHvmApprovalDecision {
    pub decision: AgentHvmApprovalDecision,
    pub signature_hex: String,
}

impl SignedAgentHvmApprovalDecision {
    /// Commitment to the exact owner decision and its platform signature.
    /// This lets the restricted Agent signer prove that its outer authority is
    /// derived from the exact biometric decision, not only from the unsigned
    /// review commitment.
    pub fn canonical_sha256_hex(&self) -> CompanionResult<String> {
        self.decision.validate_shape()?;
        if self.signature_hex.len() != 128
            || !self
                .signature_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CompanionError::InvalidSignature);
        }
        let decision = self.decision.canonical_bytes()?;
        let mut digest = sha2::Sha256::new();
        use sha2::Digest;
        digest.update(SIGNED_DECISION_DOMAIN);
        for field in [decision.as_slice(), self.signature_hex.as_bytes()] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        Ok(hex::encode(digest.finalize()))
    }

    pub async fn sign(
        decision: AgentHvmApprovalDecision,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &decision.mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::AgentHvmApprovalDecision,
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
        expected: &AgentHvmApprovalCommitment,
        registry: &DeviceRegistry,
        replay_guard: &ReplayGuard,
        now: u64,
    ) -> CompanionResult<ReplayPermit> {
        expected.validate_at(now)?;
        self.decision.validate_shape()?;
        if &self.decision.commitment != expected
            || self.decision.commitment_sha256 != expected.canonical_sha256_hex()?
        {
            return Err(CompanionError::ApprovalCommitmentMismatch);
        }
        let permission = match self.decision.decision {
            ApprovalDecision::Approve => DevicePermission::ApprovePayment,
            ApprovalDecision::Reject => DevicePermission::RejectPayment,
        };
        let record = registry.require(
            &self.decision.mobile_device_id,
            &expected.agent_wallet_id,
            DeviceRole::Mobile,
            permission,
        )?;
        if record.authorization_epoch != self.decision.device_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::AgentHvmApprovalDecision,
            &self.decision.canonical_bytes()?,
            &self.signature_hex,
        )?;
        replay_guard.check(&self.decision.replay_metadata(), now)
    }
}

fn decode_decision(tag: u8) -> CompanionResult<ApprovalDecision> {
    match tag {
        1 => Ok(ApprovalDecision::Approve),
        2 => Ok(ApprovalDecision::Reject),
        _ => Err(CompanionError::MalformedMessage),
    }
}

fn format_hac_zhu(zhu: u64) -> String {
    let whole = zhu / ZHU_PER_HAC;
    let fraction = zhu % ZHU_PER_HAC;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{}", format!("{fraction:08}").trim_end_matches('0'))
}

fn valid_hub_url(value: &str, network_mode: &str) -> bool {
    let transport_ok = value.starts_with("https://")
        || (network_mode == "testnet"
            && (value.starts_with("http://127.0.0.1") || value.starts_with("http://localhost")));
    transport_ok
        && valid_text(value)
        && !value.ends_with('/')
        && !value.contains('@')
        && !value.contains('?')
        && !value.contains('#')
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn is_reviewed_settlement_artifact(profile: &str, bytecode_sha3: &str) -> bool {
    matches!(
        (profile, bytecode_sha3),
        (V1_SETTLEMENT_PROFILE, V1_REVIEWED_BYTECODE_SHA3)
            | (V2_SETTLEMENT_PROFILE, V2_REVIEWED_BYTECODE_SHA3)
    )
}

fn is_lower_hex_len(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::identity::SoftwareDeviceIdentity;

    fn fixture() -> AgentHvmApprovalCommitment {
        AgentHvmApprovalCommitment {
            approval_version: AGENT_HVM_APPROVAL_VERSION,
            approval_id: "hvm-approval-1".into(),
            challenge_nonce: "11".repeat(16),
            operation_id: "hvm-operation-1".into(),
            hub_operation_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            public_idempotency_key: "public-hvm-1".into(),
            hub_idempotency_key: "hpay-agent-hvm:550e8400-e29b-41d4-a716-446655440001".into(),
            agent_wallet_id: "wallet-one".into(),
            wallet_scope: "agent_wallet:wallet-one".into(),
            agent_id: "agent-one".into(),
            agent_authorization_epoch: 2,
            desktop_device_id: DeviceId::parse("desktop-one").unwrap(),
            hub_url: "https://hub.example".into(),
            hub_address: "1Hub".into(),
            settlement_profile: V1_SETTLEMENT_PROFILE.into(),
            contract_address: "3Contract".into(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 900_000,
            bytecode_sha3: V1_REVIEWED_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            channel_reuse_version: 1,
            challenge_blocks: 12,
            binding_commitment: "44".repeat(32),
            lease_snapshot_commitment: "55".repeat(32),
            previous_bill_commitment: "66".repeat(32),
            unsigned_request_commitment: "77".repeat(32),
            payer: "1Payer".into(),
            payee: "provider:compute".into(),
            amount_hac: "0.01".into(),
            amount_zhu: 1_000_000,
            fee_payer: "sender".into(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: 1_000_000,
            policy_epoch: 3,
            signer_epoch: 4,
            emergency_epoch: 5,
            issued_at: 1_000,
            expires_at: 1_300,
            network_binding: AgentFastPayNetworkBinding {
                network_mode: "mainnet".into(),
                chain_id: 0,
                genesis_identifier: "88".repeat(32),
                node_profile_id: "99".repeat(32),
                network_instance_id: "mainnet-instance".into(),
                transaction_format_version: 2,
            },
        }
    }

    #[test]
    fn canonical_roundtrip_and_every_fee_gate_are_exact() {
        let approval = fixture();
        let bytes = approval.canonical_bytes().unwrap();
        assert_eq!(
            AgentHvmApprovalCommitment::from_canonical_bytes(&bytes).unwrap(),
            approval
        );
        for mutate in [
            |value: &mut AgentHvmApprovalCommitment| value.network_fee_zhu = 1,
            |value: &mut AgentHvmApprovalCommitment| value.wallet_fee_zhu = 1,
            |value: &mut AgentHvmApprovalCommitment| value.hub_fee_zhu = 1,
            |value: &mut AgentHvmApprovalCommitment| value.total_debit_zhu += 1,
        ] {
            let mut changed = fixture();
            mutate(&mut changed);
            assert_eq!(
                changed.canonical_bytes(),
                Err(CompanionError::MalformedMessage)
            );
        }
    }

    #[test]
    fn approval_accepts_only_exact_reviewed_profile_and_bytecode_pairs() {
        let mut registry = fixture();
        registry.settlement_profile = V2_SETTLEMENT_PROFILE.into();
        registry.bytecode_sha3 = V2_REVIEWED_BYTECODE_SHA3.into();
        let bytes = registry.canonical_bytes().unwrap();
        assert_eq!(
            AgentHvmApprovalCommitment::from_canonical_bytes(&bytes).unwrap(),
            registry
        );

        let mut mixed_v1_profile = registry.clone();
        mixed_v1_profile.settlement_profile = V1_SETTLEMENT_PROFILE.into();
        assert_eq!(
            mixed_v1_profile.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut mixed_v1_bytecode = registry;
        mixed_v1_bytecode.bytecode_sha3 = V1_REVIEWED_BYTECODE_SHA3.into();
        assert_eq!(
            mixed_v1_bytecode.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );
    }

    #[test]
    fn registry_v2_accepts_first_incarnation_without_relaxing_v1() {
        let mut registry_first = fixture();
        registry_first.settlement_profile = V2_SETTLEMENT_PROFILE.into();
        registry_first.bytecode_sha3 = V2_REVIEWED_BYTECODE_SHA3.into();
        registry_first.channel_reuse_version = 0;
        let bytes = registry_first.canonical_bytes().unwrap();
        assert_eq!(
            AgentHvmApprovalCommitment::from_canonical_bytes(&bytes).unwrap(),
            registry_first
        );

        let mut legacy_first = fixture();
        legacy_first.channel_reuse_version = 0;
        assert_eq!(
            legacy_first.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut registry_reused = registry_first;
        registry_reused.channel_reuse_version = 1;
        assert!(registry_reused.canonical_bytes().is_ok());
    }

    #[test]
    fn commitment_binds_hvm_deployment_leases_bills_network_and_epochs() {
        let original = fixture();
        let expected = original.canonical_sha256_hex().unwrap();
        type CommitmentMutation = Box<dyn Fn(&mut AgentHvmApprovalCommitment)>;
        let mutations: Vec<CommitmentMutation> = vec![
            Box::new(|v| v.hub_url = "https://other.example".into()),
            Box::new(|v| v.contract_address.push('x')),
            Box::new(|v| v.deployment_tx_hash = "aa".repeat(32)),
            Box::new(|v| v.deployment_height += 1),
            Box::new(|v| v.channel_id = "aa".repeat(16)),
            Box::new(|v| v.channel_reuse_version += 1),
            Box::new(|v| v.challenge_blocks += 1),
            Box::new(|v| v.lease_snapshot_commitment = "aa".repeat(32)),
            Box::new(|v| v.previous_bill_commitment = "aa".repeat(32)),
            Box::new(|v| v.unsigned_request_commitment = "aa".repeat(32)),
            Box::new(|v| v.agent_authorization_epoch += 1),
            Box::new(|v| v.policy_epoch += 1),
            Box::new(|v| v.signer_epoch += 1),
            Box::new(|v| v.emergency_epoch += 1),
            Box::new(|v| v.network_binding.network_instance_id.push('x')),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(changed.canonical_sha256_hex().unwrap(), expected);
        }
    }

    #[test]
    fn mainnet_requires_https_and_review_window_is_bounded() {
        let mut insecure = fixture();
        insecure.hub_url = "http://hub.example".into();
        assert_eq!(
            insecure.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );
        let mut too_long = fixture();
        too_long.expires_at += 1;
        assert_eq!(
            too_long.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );
    }

    #[tokio::test]
    async fn signed_owner_decision_is_device_epoch_and_replay_bound() {
        let commitment = fixture();
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                mobile
                    .public_record(
                        &commitment.agent_wallet_id,
                        BTreeSet::from([DevicePermission::ApprovePayment]),
                        900,
                    )
                    .unwrap(),
            )
            .unwrap();
        let decision = AgentHvmApprovalDecision::from_commitment(
            commitment.clone(),
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            1_001,
        )
        .unwrap();
        let signed = SignedAgentHvmApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        let mut replay = ReplayGuard::new();
        let permit = signed
            .verify(&commitment, &registry, &replay, 1_002)
            .unwrap();
        replay.commit(permit, 1_002).unwrap();
        assert_eq!(
            signed.verify(&commitment, &registry, &replay, 1_003),
            Err(CompanionError::SequenceReplay)
        );
    }
}
