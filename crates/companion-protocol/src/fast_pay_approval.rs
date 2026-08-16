//! Canonical owner-review commitment for one Agent Fast Pay operation.
//!
//! This type deliberately grants no signing authority. It is the exact,
//! domain-separated payload that a later owner-device decision must bind.
//! Keeping it separate from the L1 approval schema prevents an L1 transaction
//! approval from being replayed as authority for an L2 settlement bill.

use serde::{Deserialize, Serialize};

use crate::ApprovalDecision;
use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};
use crate::replay::{ReplayGuard, ReplayMetadata, ReplayPermit};

const COMMITMENT_DOMAIN: &[u8] = b"HPAY/COMPANION/AGENT-FAST-PAY-APPROVAL/V1";
const DECISION_DOMAIN: &[u8] = b"HPAY/COMPANION/AGENT-FAST-PAY-DECISION/V1";
const DECISION_CONTEXT: &str = "agent_fast_pay_approval_decision";
pub const AGENT_FAST_PAY_APPROVAL_VERSION: u64 = 1;
pub const AGENT_FAST_PAY_APPROVAL_MAX_LIFETIME_SECS: u64 = 5 * 60;
const AGENT_UNITS_PER_MILLIMEI: u64 = 1_000;
const AGENT_UNITS_PER_HAC: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFastPayNetworkBinding {
    pub network_mode: String,
    pub chain_id: u32,
    pub genesis_identifier: String,
    pub node_profile_id: String,
    pub network_instance_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub transaction_format_version: u64,
}

impl AgentFastPayNetworkBinding {
    pub fn validate_shape(&self) -> CompanionResult<()> {
        let chain_matches_network = matches!(
            (self.network_mode.as_str(), self.chain_id),
            ("mainnet", 0) | ("testnet", 1..=u32::MAX)
        );
        if !chain_matches_network
            || !is_lower_hex_len(&self.genesis_identifier, 32)
            || !valid_text(&self.node_profile_id)
            || self.node_profile_id.len() > 256
            || !valid_text(&self.network_instance_id)
            || self.transaction_format_version == 0
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        self.validate_shape()?;
        encoder.push_string(&self.network_mode)?;
        encoder.push_u32(self.chain_id);
        encoder.push_string(&self.genesis_identifier)?;
        encoder.push_string(&self.node_profile_id)?;
        encoder.push_string(&self.network_instance_id)?;
        encoder.push_u64(self.transaction_format_version);
        Ok(())
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> CompanionResult<Self> {
        let value = Self {
            network_mode: decoder.read_string()?,
            chain_id: decoder.read_u32()?,
            genesis_identifier: decoder.read_string()?,
            node_profile_id: decoder.read_string()?,
            network_instance_id: decoder.read_string()?,
            transaction_format_version: decoder.read_u64()?,
        };
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFastPayApprovalCommitment {
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
    pub desktop_device_id: DeviceId,
    pub request_commitment: String,
    pub binding_commitment: String,
    pub route_commitment: String,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_millimeis: u64,
    pub hub_url: String,
    pub hub_address: String,
    pub channel_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub channel_reuse_version: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub channel_open_height: u64,
    pub fee_payer: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub network_fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub wallet_fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub hub_fee_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub total_debit_units: u64,
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

impl AgentFastPayApprovalCommitment {
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
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            request_commitment: decoder.read_string()?,
            binding_commitment: decoder.read_string()?,
            route_commitment: decoder.read_string()?,
            payer: decoder.read_string()?,
            payee: decoder.read_string()?,
            amount_hac: decoder.read_string()?,
            amount_units: decoder.read_u64()?,
            amount_millimeis: decoder.read_u64()?,
            hub_url: decoder.read_string()?,
            hub_address: decoder.read_string()?,
            channel_id: decoder.read_string()?,
            channel_reuse_version: decoder.read_u64()?,
            channel_open_height: decoder.read_u64()?,
            fee_payer: decoder.read_string()?,
            network_fee_units: decoder.read_u64()?,
            wallet_fee_units: decoder.read_u64()?,
            hub_fee_units: decoder.read_u64()?,
            total_debit_units: decoder.read_u64()?,
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
        let expected_millimeis = self
            .amount_units
            .checked_div(AGENT_UNITS_PER_MILLIMEI)
            .filter(|_| self.amount_units.is_multiple_of(AGENT_UNITS_PER_MILLIMEI));
        let expected_expiry = self
            .issued_at
            .checked_add(AGENT_FAST_PAY_APPROVAL_MAX_LIFETIME_SECS);
        if self.approval_version != AGENT_FAST_PAY_APPROVAL_VERSION
            || !valid_text(&self.approval_id)
            || !is_lower_hex_len(&self.challenge_nonce, 16)
            || !valid_text(&self.operation_id)
            || !is_canonical_uuid(&self.hub_operation_id)
            || !valid_text(&self.public_idempotency_key)
            || !self.hub_idempotency_key.starts_with("hpay-agent:")
            || !valid_text(&self.hub_idempotency_key)
            || !valid_text(&self.agent_wallet_id)
            || self.wallet_scope != format!("agent_wallet:{}", self.agent_wallet_id)
            || !valid_text(&self.agent_id)
            || !is_lower_hex_len(&self.request_commitment, 32)
            || !is_lower_hex_len(&self.binding_commitment, 32)
            || !is_lower_hex_len(&self.route_commitment, 32)
            || !valid_text(&self.payer)
            || !valid_text(&self.payee)
            || self.payer == self.payee
            || self.amount_units == 0
            || expected_millimeis != Some(self.amount_millimeis)
            || self.amount_hac != format_agent_hac(self.amount_units)
            || !valid_hub_url(&self.hub_url, &self.network_binding.network_mode)
            || !valid_text(&self.hub_address)
            || !is_lower_hex_len(&self.channel_id, 16)
            || self.channel_reuse_version == 0
            || self.channel_open_height == 0
            || self.fee_payer != "sender"
            || self.network_fee_units != 0
            || self.wallet_fee_units != 0
            || self.hub_fee_units != 0
            || self.total_debit_units != self.amount_units
            || self.policy_epoch == 0
            || self.signer_epoch == 0
            || self.emergency_epoch == 0
            || self.expires_at <= self.issued_at
            || expected_expiry.is_none_or(|maximum| self.expires_at > maximum)
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

impl CanonicalEncode for AgentFastPayApprovalCommitment {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.approval_version);
        encoder.push_string(&self.approval_id)?;
        encoder.push_string(&self.challenge_nonce)?;
        encoder.push_string(&self.operation_id)?;
        encoder.push_string(&self.hub_operation_id)?;
        encoder.push_string(&self.public_idempotency_key)?;
        encoder.push_string(&self.hub_idempotency_key)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(&self.wallet_scope)?;
        encoder.push_string(&self.agent_id)?;
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_string(&self.request_commitment)?;
        encoder.push_string(&self.binding_commitment)?;
        encoder.push_string(&self.route_commitment)?;
        encoder.push_string(&self.payer)?;
        encoder.push_string(&self.payee)?;
        encoder.push_string(&self.amount_hac)?;
        encoder.push_u64(self.amount_units);
        encoder.push_u64(self.amount_millimeis);
        encoder.push_string(&self.hub_url)?;
        encoder.push_string(&self.hub_address)?;
        encoder.push_string(&self.channel_id)?;
        encoder.push_u64(self.channel_reuse_version);
        encoder.push_u64(self.channel_open_height);
        encoder.push_string(&self.fee_payer)?;
        encoder.push_u64(self.network_fee_units);
        encoder.push_u64(self.wallet_fee_units);
        encoder.push_u64(self.hub_fee_units);
        encoder.push_u64(self.total_debit_units);
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
pub struct AgentFastPayApprovalDecision {
    #[serde(with = "crate::serde_decimal_u64")]
    pub decision_version: u64,
    pub decision: ApprovalDecision,
    pub commitment: AgentFastPayApprovalCommitment,
    pub commitment_sha256: String,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub device_authorization_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub approval_sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub decision_issued_at: u64,
}

impl AgentFastPayApprovalDecision {
    pub fn from_commitment(
        commitment: AgentFastPayApprovalCommitment,
        decision: ApprovalDecision,
        mobile_device_id: DeviceId,
        device_authorization_epoch: u64,
        approval_sequence: u64,
        decision_issued_at: u64,
    ) -> CompanionResult<Self> {
        let commitment_sha256 = commitment.canonical_sha256_hex()?;
        let value = Self {
            decision_version: AGENT_FAST_PAY_APPROVAL_VERSION,
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
            commitment: AgentFastPayApprovalCommitment::from_canonical_bytes(
                decoder.read_bytes()?,
            )?,
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

    pub fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: DECISION_CONTEXT.to_owned(),
            sender_device_id: self.mobile_device_id.clone(),
            sequence: self.approval_sequence,
            nonce: self.commitment.challenge_nonce.clone(),
            issued_at: self.decision_issued_at,
            expires_at: self.commitment.expires_at,
        }
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        let expected_commitment = self.commitment.canonical_sha256_hex()?;
        if self.decision_version != AGENT_FAST_PAY_APPROVAL_VERSION
            || self.commitment_sha256 != expected_commitment
            || self.device_authorization_epoch == 0
            || self.approval_sequence == 0
            || self.decision_issued_at < self.commitment.issued_at
            || self.decision_issued_at >= self.commitment.expires_at
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn matches_commitment(&self, expected: &AgentFastPayApprovalCommitment) -> bool {
        &self.commitment == expected
            && self
                .commitment
                .canonical_sha256_hex()
                .is_ok_and(|commitment| commitment == self.commitment_sha256)
    }
}

impl CanonicalEncode for AgentFastPayApprovalDecision {
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
pub struct SignedAgentFastPayApprovalDecision {
    pub decision: AgentFastPayApprovalDecision,
    pub signature_hex: String,
}

impl SignedAgentFastPayApprovalDecision {
    pub async fn sign(
        decision: AgentFastPayApprovalDecision,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &decision.mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::AgentFastPayApprovalDecision,
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
        expected: &AgentFastPayApprovalCommitment,
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
            &expected.agent_wallet_id,
            DeviceRole::Mobile,
            permission,
        )?;
        if record.authorization_epoch != self.decision.device_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::AgentFastPayApprovalDecision,
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

fn format_agent_hac(units: u64) -> String {
    let whole = units / AGENT_UNITS_PER_HAC;
    let fraction = units % AGENT_UNITS_PER_HAC;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:06}").trim_end_matches('0').to_owned();
    format!("{whole}.{fraction}")
}

fn valid_hub_url(value: &str, network_mode: &str) -> bool {
    let scheme_ok = value.starts_with("https://")
        || (network_mode == "testnet" && value.starts_with("http://"));
    scheme_ok
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

    type ApprovalMutation = Box<dyn Fn(&mut AgentFastPayApprovalCommitment)>;

    fn fixture() -> AgentFastPayApprovalCommitment {
        AgentFastPayApprovalCommitment {
            approval_version: AGENT_FAST_PAY_APPROVAL_VERSION,
            approval_id: "fast_pay_approval_1".into(),
            challenge_nonce: "ab".repeat(16),
            operation_id: "operation_1".into(),
            hub_operation_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            public_idempotency_key: "agent-visible-key".into(),
            hub_idempotency_key: "hpay-agent:550e8400-e29b-41d4-a716-446655440001".into(),
            agent_wallet_id: "wallet_one".into(),
            wallet_scope: "agent_wallet:wallet_one".into(),
            agent_id: "agent_one".into(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            request_commitment: "aa".repeat(32),
            binding_commitment: "bb".repeat(32),
            route_commitment: "cc".repeat(32),
            payer: "1Payer".into(),
            payee: "1Payee".into(),
            amount_hac: "0.012".into(),
            amount_units: 12_000,
            amount_millimeis: 12,
            hub_url: "https://hub.example".into(),
            hub_address: "1Hub".into(),
            channel_id: "dd".repeat(16),
            channel_reuse_version: 7,
            channel_open_height: 900_000,
            fee_payer: "sender".into(),
            network_fee_units: 0,
            wallet_fee_units: 0,
            hub_fee_units: 0,
            total_debit_units: 12_000,
            policy_epoch: 3,
            signer_epoch: 4,
            emergency_epoch: 5,
            issued_at: 1_000,
            expires_at: 1_300,
            network_binding: AgentFastPayNetworkBinding {
                network_mode: "mainnet".into(),
                chain_id: 0,
                genesis_identifier: "ee".repeat(32),
                node_profile_id: "fa".repeat(32),
                network_instance_id: "mainnet:0".into(),
                transaction_format_version: 2,
            },
        }
    }

    #[test]
    fn canonical_roundtrip_binds_every_reviewed_field() {
        let approval = fixture();
        let encoded = approval.canonical_bytes().unwrap();
        assert_eq!(
            AgentFastPayApprovalCommitment::from_canonical_bytes(&encoded).unwrap(),
            approval
        );
        assert_eq!(approval.canonical_sha256_hex().unwrap().len(), 64);
        approval.validate_at(1_001).unwrap();
    }

    #[test]
    fn any_fee_or_amount_alias_is_rejected() {
        for mutation in [
            |value: &mut AgentFastPayApprovalCommitment| value.network_fee_units = 1,
            |value: &mut AgentFastPayApprovalCommitment| value.wallet_fee_units = 1,
            |value: &mut AgentFastPayApprovalCommitment| value.hub_fee_units = 1,
            |value: &mut AgentFastPayApprovalCommitment| value.total_debit_units += 1,
            |value: &mut AgentFastPayApprovalCommitment| value.amount_millimeis += 1,
            |value: &mut AgentFastPayApprovalCommitment| value.amount_hac = "0.0120".into(),
        ] {
            let mut approval = fixture();
            mutation(&mut approval);
            assert_eq!(
                approval.canonical_bytes(),
                Err(CompanionError::MalformedMessage)
            );
        }
    }

    #[test]
    fn approval_is_short_lived_and_network_bound() {
        let approval = fixture();
        assert_eq!(approval.validate_at(1_300), Err(CompanionError::Expired));

        let mut too_long = fixture();
        too_long.expires_at += 1;
        assert_eq!(
            too_long.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );

        let mut wrong_chain = fixture();
        wrong_chain.network_binding.chain_id = 1;
        assert_eq!(
            wrong_chain.canonical_bytes(),
            Err(CompanionError::MalformedMessage)
        );
    }

    #[test]
    fn semantically_identical_uppercase_hex_aliases_are_rejected() {
        for mutation in [
            |value: &mut AgentFastPayApprovalCommitment| {
                value.challenge_nonce.make_ascii_uppercase()
            },
            |value: &mut AgentFastPayApprovalCommitment| {
                value.request_commitment.make_ascii_uppercase()
            },
            |value: &mut AgentFastPayApprovalCommitment| value.channel_id.make_ascii_uppercase(),
            |value: &mut AgentFastPayApprovalCommitment| {
                value
                    .network_binding
                    .genesis_identifier
                    .make_ascii_uppercase()
            },
        ] {
            let mut approval = fixture();
            mutation(&mut approval);
            assert_eq!(
                approval.canonical_bytes(),
                Err(CompanionError::MalformedMessage)
            );
        }
    }

    #[test]
    fn commitment_changes_for_each_security_boundary() {
        let original = fixture();
        let expected = original.canonical_sha256_hex().unwrap();
        let mutations: Vec<ApprovalMutation> = vec![
            Box::new(|v| v.approval_id.push('x')),
            Box::new(|v| v.challenge_nonce = "cd".repeat(16)),
            Box::new(|v| v.operation_id.push('x')),
            Box::new(|v| v.hub_operation_id = "550e8400-e29b-41d4-a716-446655440002".into()),
            Box::new(|v| v.public_idempotency_key.push('x')),
            Box::new(|v| v.hub_idempotency_key.push('x')),
            Box::new(|v| v.agent_wallet_id.push('x')),
            Box::new(|v| {
                v.agent_wallet_id.push('x');
                v.wallet_scope.push('x');
            }),
            Box::new(|v| v.agent_id.push('x')),
            Box::new(|v| v.request_commitment = "77".repeat(32)),
            Box::new(|v| v.binding_commitment = "77".repeat(32)),
            Box::new(|v| v.route_commitment = "77".repeat(32)),
            Box::new(|v| v.payer.push('x')),
            Box::new(|v| v.payee.push('x')),
            Box::new(|v| {
                v.amount_units = 13_000;
                v.amount_millimeis = 13;
                v.amount_hac = "0.013".into();
                v.total_debit_units = 13_000;
            }),
            Box::new(|v| v.hub_url = "https://other.example".into()),
            Box::new(|v| v.hub_address.push('x')),
            Box::new(|v| v.channel_id = "88".repeat(16)),
            Box::new(|v| v.channel_reuse_version += 1),
            Box::new(|v| v.channel_open_height += 1),
            Box::new(|v| v.policy_epoch += 1),
            Box::new(|v| v.signer_epoch += 1),
            Box::new(|v| v.emergency_epoch += 1),
            Box::new(|v| v.issued_at += 1),
            Box::new(|v| v.network_binding.genesis_identifier = "99".repeat(32)),
            Box::new(|v| v.network_binding.node_profile_id = "99".repeat(32)),
            Box::new(|v| v.network_binding.network_instance_id.push('x')),
            Box::new(|v| v.network_binding.transaction_format_version += 1),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            match changed.canonical_sha256_hex() {
                Ok(commitment) => assert_ne!(commitment, expected),
                Err(CompanionError::MalformedMessage) => {}
                Err(error) => panic!("unexpected validation error: {error}"),
            }
        }
    }

    #[test]
    fn json_rejects_unknown_fields() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<AgentFastPayApprovalCommitment>(value).is_err());
    }

    #[tokio::test]
    async fn signed_decision_is_device_bound_and_consumed_once() {
        let commitment = fixture();
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let permissions = BTreeSet::from([
            DevicePermission::ApprovePayment,
            DevicePermission::RejectPayment,
        ]);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                mobile
                    .public_record(&commitment.agent_wallet_id, permissions, 900)
                    .unwrap(),
            )
            .unwrap();
        let decision = AgentFastPayApprovalDecision::from_commitment(
            commitment.clone(),
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            1_001,
        )
        .unwrap();
        assert_eq!(
            AgentFastPayApprovalDecision::from_canonical_bytes(
                &decision.canonical_bytes().unwrap()
            )
            .unwrap(),
            decision
        );
        let signed = SignedAgentFastPayApprovalDecision::sign(decision, &mobile)
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

    #[tokio::test]
    async fn signature_cannot_cross_l1_or_changed_fast_pay_commitment() {
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
        let decision = AgentFastPayApprovalDecision::from_commitment(
            commitment.clone(),
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            1_001,
        )
        .unwrap();
        let mut signed = SignedAgentFastPayApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        signed.decision.commitment.payee.push('x');
        signed.decision.commitment_sha256 =
            signed.decision.commitment.canonical_sha256_hex().unwrap();
        assert_eq!(
            signed.verify(&commitment, &registry, &ReplayGuard::new(), 1_002),
            Err(CompanionError::ApprovalCommitmentMismatch)
        );
    }

    #[tokio::test]
    async fn stale_epoch_expiry_wrong_device_and_bad_signature_fail_closed() {
        let commitment = fixture();
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let other = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
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
        let decision = AgentFastPayApprovalDecision::from_commitment(
            commitment.clone(),
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            1_001,
        )
        .unwrap();
        let signed = SignedAgentFastPayApprovalDecision::sign(decision.clone(), &mobile)
            .await
            .unwrap();
        let mut stale_epoch = decision.clone();
        stale_epoch.device_authorization_epoch = 2;
        let stale_epoch = SignedAgentFastPayApprovalDecision::sign(stale_epoch, &mobile)
            .await
            .unwrap();
        assert_eq!(
            stale_epoch.verify(&commitment, &registry, &ReplayGuard::new(), 1_002),
            Err(CompanionError::AuthorizationEpochMismatch)
        );
        assert_eq!(
            SignedAgentFastPayApprovalDecision::sign(decision, &other).await,
            Err(CompanionError::WalletScopeMismatch)
        );
        assert_eq!(
            signed.verify(&commitment, &registry, &ReplayGuard::new(), 1_300),
            Err(CompanionError::Expired)
        );
        let mut bad_signature = signed;
        bad_signature.signature_hex.replace_range(0..2, "00");
        assert_eq!(
            bad_signature.verify(&commitment, &registry, &ReplayGuard::new(), 1_002),
            Err(CompanionError::InvalidSignature)
        );
    }
}
