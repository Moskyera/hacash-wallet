//! Durable Agent-only operation model for the HPAY HVM settlement rail.
//!
//! Native ChannelPay and HVM bills are intentionally separate. This model
//! binds one exact Agent identity, HVM deployment/incarnation, operational
//! lease snapshot, previous fully signed bill, unsigned next bill and mobile
//! owner decision before the restricted Agent key may be used.

#![cfg_attr(
    not(feature = "agent-wallet-testnet-pilot"),
    allow(
        dead_code,
        reason = "HVM execution is intentionally unavailable when the pilot feature is disabled"
    )
)]

use hpay_companion_protocol::{
    AGENT_HVM_APPROVAL_MAX_LIFETIME_SECS, AGENT_HVM_APPROVAL_VERSION, AgentFastPayNetworkBinding,
    AgentHvmApprovalCommitment, ApprovalDecision, DeviceId, SignedAgentHvmApprovalDecision,
};
use l2_fast_pay_hub::hvm_channel::{HvmChannelBillV1, HvmChannelBindingV1};
use l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1;
use l2_fast_pay_hub::hvm_registry::{
    HvmRegistryBillV2, HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS, HvmRegistryPaymentRequestV2,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use l2_fast_pay_hub::node::HvmChannelLiveSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::service::{AgentHvmChannelBinding, AgentHvmRegistryBinding};
use crate::signer::{AgentHvmPaymentSignerBinding, AgentHvmRegistryPaymentSignerBinding};
use crate::types::{AgentId, AgentWalletId, OperationId, WalletScope};

const ZHU_PER_AGENT_UNIT: u64 = 100;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const MAX_REQUEST_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const REQUEST_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/HVM-PAYMENT/REQUEST/V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmPaymentRequest {
    pub idempotency_key: String,
    pub amount_units: HacUnits,
    pub recipient: String,
    pub reason: String,
    pub expires_at: u64,
}

impl AgentHvmPaymentRequest {
    pub(crate) fn validate(&self, now: u64) -> AgentWalletResult<()> {
        validate_text(&self.idempotency_key, MAX_IDEMPOTENCY_BYTES)?;
        validate_text(&self.recipient, MAX_TEXT_BYTES)?;
        validate_text(&self.reason, MAX_TEXT_BYTES)?;
        if self.amount_units == HacUnits::ZERO {
            return Err(AgentWalletError::InvalidAmount);
        }
        if self.expires_at <= now
            || self.expires_at.saturating_sub(now) > MAX_REQUEST_LIFETIME_SECONDS
        {
            return Err(AgentWalletError::RequestExpired);
        }
        Ok(())
    }

    pub(crate) fn amount_zhu(&self) -> AgentWalletResult<u64> {
        self.amount_units
            .get()
            .checked_mul(ZHU_PER_AGENT_UNIT)
            .ok_or(AgentWalletError::IntegerOverflow)
    }

    pub(crate) fn commitment_hex(&self) -> String {
        request_commitment(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentHvmPaymentStatus {
    PaymentIntentCreated,
    FundsReserved,
    UnsignedPrepared,
    ApprovalRequested,
    Approved,
    SigningPrepared,
    Signed,
    Submitted,
    ExactRetryReady,
    Committed,
    Rejected,
    Cancelled,
    RecoveryRequired,
}

impl AgentHvmPaymentStatus {
    pub const fn retains_reservation(self) -> bool {
        matches!(
            self,
            Self::FundsReserved
                | Self::UnsignedPrepared
                | Self::ApprovalRequested
                | Self::Approved
                | Self::SigningPrepared
                | Self::Signed
                | Self::Submitted
                | Self::ExactRetryReady
                | Self::RecoveryRequired
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmPaymentOperationView {
    pub operation_id: OperationId,
    pub hub_operation_id: String,
    pub agent_wallet_id: AgentWalletId,
    pub agent_id: AgentId,
    pub agent_authorization_epoch: u64,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub network_mode: String,
    pub hub_url: String,
    pub hub_address: String,
    pub binding_commitment: String,
    pub lease_snapshot_commitment: Option<String>,
    pub previous_bill_commitment: Option<String>,
    pub unsigned_request_commitment: Option<String>,
    pub payer: String,
    pub recipient: String,
    pub amount_units: HacUnits,
    pub amount_zhu: u64,
    pub wallet_fee_zhu: u64,
    pub hub_fee_zhu: u64,
    pub total_debit_zhu: u64,
    pub reserved_units: HacUnits,
    pub status: AgentHvmPaymentStatus,
    pub policy_epoch: u64,
    pub signer_epoch: u64,
    pub emergency_epoch: u64,
    pub approval_commitment: Option<String>,
    pub approval_decision_commitment: Option<String>,
    pub owner_authority_commitment: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub settled_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentHvmPaymentOperation {
    operation_id: OperationId,
    hub_operation_id: String,
    hub_idempotency_key: String,
    agent_wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    agent_id: AgentId,
    agent_authorization_epoch: u64,
    request: AgentHvmPaymentRequest,
    request_commitment: String,
    network_mode: String,
    network_binding: L1ChannelNetworkBinding,
    hub_url: String,
    hub_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_binding: Option<HvmChannelBindingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hvm_registry_binding: Option<HvmRegistryBindingV2>,
    binding_commitment: String,
    lease_snapshot_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepared_snapshot: Option<HvmChannelLiveSnapshot>,
    previous_bill: Option<HvmChannelBillV1>,
    previous_bill_commitment: Option<String>,
    unsigned_request: Option<HvmPaymentRequestV1>,
    unsigned_request_commitment: Option<String>,
    signed_request: Option<HvmPaymentRequestV1>,
    fully_signed_bill: Option<HvmChannelBillV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepared_registry_snapshot: Option<HvmRegistryLiveSnapshotV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_registry_bill: Option<HvmRegistryBillV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unsigned_registry_request: Option<HvmRegistryPaymentRequestV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_registry_request: Option<HvmRegistryPaymentRequestV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fully_signed_registry_bill: Option<HvmRegistryBillV2>,
    policy_epoch: u64,
    signer_epoch: u64,
    emergency_epoch: u64,
    status: AgentHvmPaymentStatus,
    reserved_units: HacUnits,
    approval_commitment: Option<String>,
    approval_request: Option<AgentHvmApprovalCommitment>,
    approval_decision: Option<SignedAgentHvmApprovalDecision>,
    approval_decision_commitment: Option<String>,
    owner_authority_commitment: Option<String>,
    created_at: u64,
    expires_at: u64,
    settled_at: Option<u64>,
}

#[derive(Clone, Copy)]
enum AgentHvmRailBindingRef<'a> {
    ChannelV1(&'a HvmChannelBindingV1),
    RegistryV2(&'a HvmRegistryBindingV2),
}

impl<'a> AgentHvmRailBindingRef<'a> {
    fn settlement_profile(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.settlement_profile,
            Self::RegistryV2(binding) => &binding.settlement_profile,
        }
    }

    fn contract_address(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.contract_address,
            Self::RegistryV2(binding) => &binding.contract_address,
        }
    }

    fn deployment_tx_hash(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.deployment_tx_hash,
            Self::RegistryV2(binding) => &binding.deployment_tx_hash,
        }
    }

    const fn deployment_height(self) -> u64 {
        match self {
            Self::ChannelV1(binding) => binding.deployment_height,
            Self::RegistryV2(binding) => binding.deployment_height,
        }
    }

    fn bytecode_sha3(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.bytecode_sha3,
            Self::RegistryV2(binding) => &binding.bytecode_sha3,
        }
    }

    fn channel_id(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.channel_id,
            Self::RegistryV2(binding) => &binding.channel_id,
        }
    }

    const fn reuse_version(self) -> u32 {
        match self {
            Self::ChannelV1(binding) => binding.reuse_version,
            Self::RegistryV2(binding) => binding.reuse_version,
        }
    }

    const fn challenge_blocks(self) -> u64 {
        match self {
            Self::ChannelV1(binding) => binding.challenge_blocks,
            Self::RegistryV2(binding) => binding.challenge_blocks,
        }
    }

    fn left_address(self) -> &'a str {
        match self {
            Self::ChannelV1(binding) => &binding.left_address,
            Self::RegistryV2(binding) => &binding.left_address,
        }
    }
}

impl AgentHvmPaymentOperation {
    pub(crate) const fn is_registry_v2(&self) -> bool {
        self.hvm_binding.is_none() && self.hvm_registry_binding.is_some()
    }

    fn rail_binding(&self) -> AgentWalletResult<AgentHvmRailBindingRef<'_>> {
        match (
            self.hvm_binding.as_ref(),
            self.hvm_registry_binding.as_ref(),
        ) {
            (Some(binding), None) => Ok(AgentHvmRailBindingRef::ChannelV1(binding)),
            (None, Some(binding)) => Ok(AgentHvmRailBindingRef::RegistryV2(binding)),
            _ => Err(AgentWalletError::RecoveryRequired),
        }
    }

    fn channel_binding(&self) -> AgentWalletResult<&HvmChannelBindingV1> {
        self.hvm_binding
            .as_ref()
            .filter(|_| self.hvm_registry_binding.is_none())
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    fn registry_binding(&self) -> AgentWalletResult<&HvmRegistryBindingV2> {
        self.hvm_registry_binding
            .as_ref()
            .filter(|_| self.hvm_binding.is_none())
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn matches_channel_binding(&self, binding: &AgentHvmChannelBinding) -> bool {
        self.agent_wallet_id == *binding.wallet_id()
            && self.network_binding == *binding.network_binding()
            && self.hub_url == binding.hub_url()
            && self.hub_address == binding.hub_address()
            && self.binding_commitment == binding.binding_commitment()
            && self.hvm_binding.as_ref() == Some(&binding.recovery_bundle().binding)
            && self.hvm_registry_binding.is_none()
    }

    pub(crate) fn matches_registry_binding(&self, binding: &AgentHvmRegistryBinding) -> bool {
        self.agent_wallet_id == *binding.wallet_id()
            && self.network_binding == *binding.network_binding()
            && self.hub_url == binding.hub_url()
            && self.hub_address == binding.hub_address()
            && self.binding_commitment == binding.binding_commitment()
            && self.hvm_registry_binding.as_ref() == Some(&binding.recovery_bundle().binding)
            && self.hvm_binding.is_none()
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        operation_id: OperationId,
        agent_id: AgentId,
        agent_wallet_id: AgentWalletId,
        request: AgentHvmPaymentRequest,
        network_mode: &str,
        network_binding: L1ChannelNetworkBinding,
        hub_url: &str,
        hub_address: &str,
        hvm_binding: HvmChannelBindingV1,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        created_at: u64,
    ) -> AgentWalletResult<Self> {
        operation_id.validate()?;
        agent_id.validate()?;
        agent_wallet_id.validate()?;
        request.validate(created_at)?;
        network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        hvm_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let canonical_hub_url =
            hacash_wallet_core::settings::validate_service_url(hub_url, "Agent HVM Fast Pay hub")
                .map_err(|_| AgentWalletError::SigningBlocked)?;
        if !matches!(network_mode, "mainnet" | "testnet")
            || network_binding.mainnet != (network_mode == "mainnet")
            || network_binding.chain_id != hvm_binding.chain_id
            || network_binding.network_instance_id != hvm_binding.network_instance_id
            || hvm_binding.network_mode != network_mode
            || hvm_binding.right_hub_address != hub_address
            || hvm_binding.left_address == request.recipient
            || canonical_hub_url != hub_url
            || network_mode == "mainnet" && !hub_url.starts_with("https://")
            || agent_authorization_epoch == 0
            || policy_epoch == 0
            || signer_epoch == 0
            || emergency_epoch == 0
        {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        let binding_commitment = hvm_binding
            .commitment()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        // Channel V1 carries no rail-level maximum request lifetime, so the
        // owner-visible deadline is the deadline that is authorized and signed.
        let expires_at = request.expires_at;
        let request_commitment = request_commitment(&request);
        let operation = Self {
            operation_id,
            hub_operation_id: uuid::Uuid::new_v4().to_string(),
            hub_idempotency_key: format!("hpay-agent-hvm:{}", uuid::Uuid::new_v4()),
            agent_wallet_id: agent_wallet_id.clone(),
            wallet_scope: WalletScope::for_agent_wallet(&agent_wallet_id),
            agent_id,
            agent_authorization_epoch,
            request,
            request_commitment,
            network_mode: network_mode.to_owned(),
            network_binding,
            hub_url: hub_url.to_owned(),
            hub_address: hub_address.to_owned(),
            hvm_binding: Some(hvm_binding),
            hvm_registry_binding: None,
            binding_commitment,
            lease_snapshot_commitment: None,
            prepared_snapshot: None,
            previous_bill: None,
            previous_bill_commitment: None,
            unsigned_request: None,
            unsigned_request_commitment: None,
            signed_request: None,
            fully_signed_bill: None,
            prepared_registry_snapshot: None,
            previous_registry_bill: None,
            unsigned_registry_request: None,
            signed_registry_request: None,
            fully_signed_registry_bill: None,
            policy_epoch,
            signer_epoch,
            emergency_epoch,
            status: AgentHvmPaymentStatus::PaymentIntentCreated,
            reserved_units: HacUnits::ZERO,
            approval_commitment: None,
            approval_request: None,
            approval_decision: None,
            approval_decision_commitment: None,
            owner_authority_commitment: None,
            created_at,
            expires_at,
            settled_at: None,
        };
        operation.validate()?;
        Ok(operation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_registry(
        operation_id: OperationId,
        agent_id: AgentId,
        agent_wallet_id: AgentWalletId,
        request: AgentHvmPaymentRequest,
        network_mode: &str,
        network_binding: L1ChannelNetworkBinding,
        hub_url: &str,
        hub_address: &str,
        hvm_binding: HvmRegistryBindingV2,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        created_at: u64,
    ) -> AgentWalletResult<Self> {
        operation_id.validate()?;
        agent_id.validate()?;
        agent_wallet_id.validate()?;
        request.validate(created_at)?;
        network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        hvm_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let canonical_hub_url =
            hacash_wallet_core::settings::validate_service_url(hub_url, "Agent HVM registry hub")
                .map_err(|_| AgentWalletError::SigningBlocked)?;
        if !matches!(network_mode, "mainnet" | "testnet")
            || network_binding.mainnet != (network_mode == "mainnet")
            || network_binding.chain_id != hvm_binding.chain_id
            || network_binding.network_instance_id != hvm_binding.network_instance_id
            || hvm_binding.network_mode != network_mode
            || hvm_binding.right_hub_address != hub_address
            || hvm_binding.left_address == request.recipient
            // Registry V2 credits only the bound Hub balance, so the payee is
            // always the exact Hub-owned identity. Anything else would be
            // rejected by the rail ledger after funds were already reserved.
            || request.recipient != hvm_binding.right_hub_address
            || canonical_hub_url != hub_url
            || network_mode == "mainnet" && !hub_url.starts_with("https://")
            || agent_authorization_epoch == 0
            || policy_epoch == 0
            || signer_epoch == 0
            || emergency_epoch == 0
        {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        let binding_commitment = hvm_binding
            .commitment()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        // Keep the public request commitment stable for idempotent retries,
        // but derive one Registry V2 authorization deadline before any
        // unsigned bill, approval or signer binding is constructed.
        let expires_at = request
            .expires_at
            .min(created_at.saturating_add(HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS));
        let request_commitment = request_commitment(&request);
        let operation = Self {
            operation_id,
            hub_operation_id: uuid::Uuid::new_v4().to_string(),
            hub_idempotency_key: format!("hpay-agent-hvm:registry:{}", uuid::Uuid::new_v4()),
            agent_wallet_id: agent_wallet_id.clone(),
            wallet_scope: WalletScope::for_agent_wallet(&agent_wallet_id),
            agent_id,
            agent_authorization_epoch,
            request,
            request_commitment,
            network_mode: network_mode.to_owned(),
            network_binding,
            hub_url: hub_url.to_owned(),
            hub_address: hub_address.to_owned(),
            hvm_binding: None,
            hvm_registry_binding: Some(hvm_binding),
            binding_commitment,
            lease_snapshot_commitment: None,
            prepared_snapshot: None,
            previous_bill: None,
            previous_bill_commitment: None,
            unsigned_request: None,
            unsigned_request_commitment: None,
            signed_request: None,
            fully_signed_bill: None,
            prepared_registry_snapshot: None,
            previous_registry_bill: None,
            unsigned_registry_request: None,
            signed_registry_request: None,
            fully_signed_registry_bill: None,
            policy_epoch,
            signer_epoch,
            emergency_epoch,
            status: AgentHvmPaymentStatus::PaymentIntentCreated,
            reserved_units: HacUnits::ZERO,
            approval_commitment: None,
            approval_request: None,
            approval_decision: None,
            approval_decision_commitment: None,
            owner_authority_commitment: None,
            created_at,
            expires_at,
            settled_at: None,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub(crate) fn reserve(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::PaymentIntentCreated)?;
        self.reserved_units = self.request.amount_units;
        self.status = AgentHvmPaymentStatus::FundsReserved;
        self.validate()
    }

    pub(crate) fn prepare_unsigned(
        &mut self,
        snapshot: &HvmChannelLiveSnapshot,
        previous: HvmChannelBillV1,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::FundsReserved)?;
        if now >= self.expires_at {
            return Err(AgentWalletError::RequestExpired);
        }
        let binding = self.channel_binding()?;
        snapshot
            .validate_runtime_binding(binding, 1, 1)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if snapshot.storage.status.value != 2
            || snapshot.storage.deadline.value != 0
            || snapshot.storage.left_claimed.value
            || snapshot.storage.right_claimed.value
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        previous
            .validate_fully_signed(binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let unsigned = HvmPaymentRequestV1::build_unsigned(
            binding,
            &previous,
            &self.hub_operation_id,
            &self.hub_idempotency_key,
            &self.request.recipient,
            self.request.amount_zhu()?,
            now,
            self.expires_at,
        )
        .map_err(|_| AgentWalletError::InvalidOperationState)?;
        self.lease_snapshot_commitment = Some(
            snapshot
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.prepared_snapshot = Some(snapshot.clone());
        self.previous_bill_commitment = Some(
            previous
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.unsigned_request_commitment = Some(
            unsigned
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.previous_bill = Some(previous);
        self.unsigned_request = Some(unsigned);
        self.status = AgentHvmPaymentStatus::UnsignedPrepared;
        self.validate()
    }

    pub(crate) fn prepare_unsigned_registry(
        &mut self,
        snapshot: &HvmRegistryLiveSnapshotV2,
        previous: HvmRegistryBillV2,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::FundsReserved)?;
        if now >= self.expires_at {
            return Err(AgentWalletError::RequestExpired);
        }
        let binding = self.registry_binding()?;
        snapshot
            .validate_runtime_binding(binding, 1, 1)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if snapshot.channel.status.value != 2
            || snapshot.channel.deadline.value != 0
            || snapshot.channel.left_claimed.value
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        previous
            .validate_fully_signed(binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let unsigned = HvmRegistryPaymentRequestV2::build_unsigned(
            &self.network_binding,
            binding,
            &previous,
            &self.hub_operation_id,
            &self.hub_idempotency_key,
            &self.request.recipient,
            self.request.amount_zhu()?,
            now,
            self.expires_at,
        )
        .map_err(|_| AgentWalletError::InvalidOperationState)?;
        self.lease_snapshot_commitment = Some(
            snapshot
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.prepared_registry_snapshot = Some(snapshot.clone());
        self.previous_bill_commitment = Some(
            previous
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.unsigned_request_commitment = Some(
            unsigned
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
        );
        self.previous_registry_bill = Some(previous);
        self.unsigned_registry_request = Some(unsigned);
        self.status = AgentHvmPaymentStatus::UnsignedPrepared;
        self.validate()
    }

    pub(crate) fn request_approval(
        &mut self,
        desktop_device_id: DeviceId,
        now: u64,
    ) -> AgentWalletResult<AgentHvmApprovalCommitment> {
        self.require_status(AgentHvmPaymentStatus::UnsignedPrepared)?;
        if now >= self.expires_at {
            return Err(AgentWalletError::RequestExpired);
        }
        let rail = self.rail_binding()?;
        let approval = AgentHvmApprovalCommitment {
            approval_version: AGENT_HVM_APPROVAL_VERSION,
            approval_id: uuid::Uuid::new_v4().to_string(),
            challenge_nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation_id: self.operation_id.as_str().to_owned(),
            hub_operation_id: self.hub_operation_id.clone(),
            public_idempotency_key: self.request.idempotency_key.clone(),
            hub_idempotency_key: self.hub_idempotency_key.clone(),
            agent_wallet_id: self.agent_wallet_id.as_str().to_owned(),
            wallet_scope: self.wallet_scope.as_str().to_owned(),
            agent_id: self.agent_id.as_str().to_owned(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            desktop_device_id,
            hub_url: self.hub_url.clone(),
            hub_address: self.hub_address.clone(),
            settlement_profile: rail.settlement_profile().to_owned(),
            contract_address: rail.contract_address().to_owned(),
            deployment_tx_hash: rail.deployment_tx_hash().to_owned(),
            deployment_height: rail.deployment_height(),
            bytecode_sha3: rail.bytecode_sha3().to_owned(),
            channel_id: rail.channel_id().to_owned(),
            channel_reuse_version: u64::from(rail.reuse_version()),
            challenge_blocks: rail.challenge_blocks(),
            binding_commitment: self.binding_commitment.clone(),
            lease_snapshot_commitment: self.required_lease_commitment()?.to_owned(),
            previous_bill_commitment: self.required_previous_commitment()?.to_owned(),
            unsigned_request_commitment: self.required_unsigned_commitment()?.to_owned(),
            payer: rail.left_address().to_owned(),
            payee: self.request.recipient.clone(),
            amount_hac: format_hac_zhu(self.request.amount_zhu()?),
            amount_zhu: self.request.amount_zhu()?,
            fee_payer: "sender".to_owned(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: self.request.amount_zhu()?,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            issued_at: now,
            expires_at: self
                .expires_at
                .min(now.saturating_add(AGENT_HVM_APPROVAL_MAX_LIFETIME_SECS)),
            network_binding: approval_network_binding(&self.network_mode, &self.network_binding),
        };
        let commitment = approval
            .canonical_sha256_hex()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        self.approval_commitment = Some(commitment);
        self.approval_request = Some(approval.clone());
        self.status = AgentHvmPaymentStatus::ApprovalRequested;
        self.validate()?;
        Ok(approval)
    }

    pub(crate) fn stored_approval_request(&self) -> AgentWalletResult<&AgentHvmApprovalCommitment> {
        self.approval_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn stored_approval_decision(&self) -> Option<&SignedAgentHvmApprovalDecision> {
        self.approval_decision.as_ref()
    }

    pub(crate) fn approved_signing_view(
        &self,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        network_mode: &str,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        self.validate()?;
        let approval = self.stored_approval_request()?;
        approval.validate_at(now).map_err(|error| match error {
            hpay_companion_protocol::CompanionError::Expired => AgentWalletError::ApprovalExpired,
            _ => AgentWalletError::ApprovalCommitmentMismatch,
        })?;
        if self.status != AgentHvmPaymentStatus::Approved
            || self
                .approval_decision
                .as_ref()
                .map(|signed| signed.decision.decision)
                != Some(ApprovalDecision::Approve)
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.policy_epoch != policy_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || self.network_mode != network_mode
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    pub(crate) fn signing_prepared_view(
        &self,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        network_mode: &str,
        now: u64,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        self.validate()?;
        self.stored_approval_request()?
            .validate_at(now)
            .map_err(|_| AgentWalletError::ApprovalExpired)?;
        if self.status != AgentHvmPaymentStatus::SigningPrepared
            || self
                .approval_decision
                .as_ref()
                .map(|signed| signed.decision.decision)
                != Some(ApprovalDecision::Approve)
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.policy_epoch != policy_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || self.network_mode != network_mode
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    pub(crate) fn signed_submission_view(
        &self,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        network_mode: &str,
    ) -> AgentWalletResult<AgentHvmPaymentOperationView> {
        self.validate()?;
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::RecoveryRequired
        ) || (self.signed_request.is_none() && self.signed_registry_request.is_none())
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.policy_epoch != policy_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || self.network_mode != network_mode
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    /// The caller must cryptographically verify the signed decision against
    /// the authorized mobile registry and replay guard before calling this.
    pub(crate) fn record_verified_owner_decision(
        &mut self,
        signed: SignedAgentHvmApprovalDecision,
    ) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::ApprovalRequested)?;
        if self
            .approval_request
            .as_ref()
            .is_none_or(|approval| signed.decision.commitment != *approval)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let signed_commitment = signed
            .canonical_sha256_hex()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let decision = signed.decision.decision;
        self.approval_decision = Some(signed);
        self.approval_decision_commitment = Some(signed_commitment);
        match decision {
            ApprovalDecision::Approve => {
                self.status = AgentHvmPaymentStatus::Approved;
                let owner_authority_commitment = if self.hvm_binding.is_some() {
                    let mut authority = self.signer_binding_unchecked()?;
                    authority.owner_authority_commitment =
                        authority.calculate_owner_authority_commitment()?;
                    authority.owner_authority_commitment
                } else {
                    let mut authority = self.registry_signer_binding_unchecked()?;
                    authority.owner_authority_commitment =
                        authority.calculate_owner_authority_commitment()?;
                    authority.owner_authority_commitment
                };
                self.owner_authority_commitment = Some(owner_authority_commitment);
            }
            ApprovalDecision::Reject => {
                self.status = AgentHvmPaymentStatus::Rejected;
                self.reserved_units = HacUnits::ZERO;
            }
        }
        self.validate()
    }

    pub(crate) fn mark_signing_prepared(&mut self, now: u64) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::Approved)?;
        self.approval_request
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)?
            .validate_at(now)
            .map_err(|_| AgentWalletError::ApprovalExpired)?;
        self.status = AgentHvmPaymentStatus::SigningPrepared;
        self.validate()
    }

    pub(crate) fn signer_binding(&self) -> AgentWalletResult<AgentHvmPaymentSignerBinding> {
        if self.status != AgentHvmPaymentStatus::SigningPrepared {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.signer_binding_unchecked()
    }

    pub(crate) fn registry_signer_binding(
        &self,
    ) -> AgentWalletResult<AgentHvmRegistryPaymentSignerBinding> {
        if self.status != AgentHvmPaymentStatus::SigningPrepared {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.registry_signer_binding_unchecked()
    }

    pub(crate) fn unsigned_request(&self) -> AgentWalletResult<&HvmPaymentRequestV1> {
        self.unsigned_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn previous_bill(&self) -> AgentWalletResult<&HvmChannelBillV1> {
        self.previous_bill
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn signed_request(&self) -> AgentWalletResult<&HvmPaymentRequestV1> {
        self.signed_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn prepared_snapshot(&self) -> AgentWalletResult<&HvmChannelLiveSnapshot> {
        self.prepared_snapshot
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn unsigned_registry_request(
        &self,
    ) -> AgentWalletResult<&HvmRegistryPaymentRequestV2> {
        self.unsigned_registry_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn previous_registry_bill(&self) -> AgentWalletResult<&HvmRegistryBillV2> {
        self.previous_registry_bill
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn signed_registry_request(
        &self,
    ) -> AgentWalletResult<&HvmRegistryPaymentRequestV2> {
        self.signed_registry_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn prepared_registry_snapshot(
        &self,
    ) -> AgentWalletResult<&HvmRegistryLiveSnapshotV2> {
        self.prepared_registry_snapshot
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    pub(crate) fn record_signed_request(
        &mut self,
        signed: HvmPaymentRequestV1,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::SigningPrepared)?;
        let binding = self.channel_binding()?;
        signed
            .validate_against(binding, self.previous_bill()?, now)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let mut normalized = signed.clone();
        normalized.proposed_bill.left_signature_hex.clear();
        if self.unsigned_request.as_ref() != Some(&normalized) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.signed_request = Some(signed);
        self.status = AgentHvmPaymentStatus::Signed;
        self.validate()
    }

    pub(crate) fn record_signed_registry_request(
        &mut self,
        signed: HvmRegistryPaymentRequestV2,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::SigningPrepared)?;
        let binding = self.registry_binding()?;
        signed
            .validate_against(binding, self.previous_registry_bill()?, now)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let mut normalized = signed.clone();
        normalized.proposed_bill.left_signature_hex.clear();
        normalized.payer_authorization_signature_hex.clear();
        if self.unsigned_registry_request.as_ref() != Some(&normalized) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.signed_registry_request = Some(signed);
        self.status = AgentHvmPaymentStatus::Signed;
        self.validate()
    }

    pub(crate) fn mark_submitted(&mut self) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::Signed | AgentHvmPaymentStatus::ExactRetryReady
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentHvmPaymentStatus::Submitted;
        self.validate()
    }

    pub(crate) fn mark_recovery_required(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentHvmPaymentStatus::RecoveryRequired {
            return Ok(());
        }
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::SigningPrepared
                | AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentHvmPaymentStatus::RecoveryRequired;
        self.validate()
    }

    pub(crate) fn mark_exact_retry_ready(&mut self) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::RecoveryRequired
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        if self.signed_request.is_none() && self.signed_registry_request.is_none() {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentHvmPaymentStatus::ExactRetryReady;
        self.validate()
    }

    /// Abandon the one crash window where key use may have happened locally
    /// but no signed bytes became durable. The execution contract never calls
    /// the Hub before `Signed` is persisted, so this cannot hide submission.
    pub(crate) fn mark_signing_abandoned(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentHvmPaymentStatus::SigningPrepared)?;
        if self.signed_request.is_some()
            || self.fully_signed_bill.is_some()
            || self.signed_registry_request.is_some()
            || self.fully_signed_registry_bill.is_some()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.status = AgentHvmPaymentStatus::Cancelled;
        self.reserved_units = HacUnits::ZERO;
        self.validate()
    }

    pub(crate) fn record_committed(
        &mut self,
        fully_signed: HvmChannelBillV1,
        now: u64,
    ) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::RecoveryRequired
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let binding = self.channel_binding()?;
        fully_signed
            .validate_fully_signed(binding)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let signed = self
            .signed_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        let mut expected_hub_unsigned = fully_signed.clone();
        expected_hub_unsigned.right_signature_hex.clear();
        if expected_hub_unsigned != signed.proposed_bill {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.fully_signed_bill = Some(fully_signed);
        self.status = AgentHvmPaymentStatus::Committed;
        self.reserved_units = HacUnits::ZERO;
        self.settled_at = Some(now);
        self.validate()
    }

    pub(crate) fn record_committed_registry(
        &mut self,
        fully_signed: HvmRegistryBillV2,
        now: u64,
    ) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::RecoveryRequired
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let binding = self.registry_binding()?;
        fully_signed
            .validate_fully_signed(binding)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let signed = self
            .signed_registry_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        let mut expected_hub_unsigned = fully_signed.clone();
        expected_hub_unsigned.hub_signature_hex.clear();
        if expected_hub_unsigned != signed.proposed_bill {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.fully_signed_registry_bill = Some(fully_signed);
        self.status = AgentHvmPaymentStatus::Committed;
        self.reserved_units = HacUnits::ZERO;
        self.settled_at = Some(now);
        self.validate()
    }

    pub(crate) fn cancel_pre_signing(&mut self) -> bool {
        if matches!(
            self.status,
            AgentHvmPaymentStatus::PaymentIntentCreated
                | AgentHvmPaymentStatus::FundsReserved
                | AgentHvmPaymentStatus::UnsignedPrepared
                | AgentHvmPaymentStatus::ApprovalRequested
                | AgentHvmPaymentStatus::Approved
        ) {
            self.status = AgentHvmPaymentStatus::Cancelled;
            self.reserved_units = HacUnits::ZERO;
            true
        } else {
            false
        }
    }

    pub(crate) fn validate(&self) -> AgentWalletResult<()> {
        self.operation_id.validate()?;
        self.agent_id.validate()?;
        self.agent_wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.agent_wallet_id)?;
        self.request.validate(self.created_at)?;
        self.network_binding
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let rail = self.rail_binding()?;
        let rail_commitment = match rail {
            AgentHvmRailBindingRef::ChannelV1(binding) => {
                binding
                    .validate()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                binding.commitment()
            }
            AgentHvmRailBindingRef::RegistryV2(binding) => {
                binding
                    .validate()
                    .map_err(|_| AgentWalletError::RecoveryRequired)?;
                binding.commitment()
            }
        }
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let prepared_required = matches!(
            self.status,
            AgentHvmPaymentStatus::UnsignedPrepared
                | AgentHvmPaymentStatus::ApprovalRequested
                | AgentHvmPaymentStatus::Approved
                | AgentHvmPaymentStatus::SigningPrepared
                | AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::Committed
                | AgentHvmPaymentStatus::Rejected
                | AgentHvmPaymentStatus::RecoveryRequired
        );
        let prepared_forbidden = matches!(
            self.status,
            AgentHvmPaymentStatus::PaymentIntentCreated | AgentHvmPaymentStatus::FundsReserved
        );
        let common_prepared = self.lease_snapshot_commitment.is_some()
            && self.previous_bill_commitment.is_some()
            && self.unsigned_request_commitment.is_some();
        let any_common_prepared = self.lease_snapshot_commitment.is_some()
            || self.previous_bill_commitment.is_some()
            || self.unsigned_request_commitment.is_some();
        let all_v1_prepared = self.prepared_snapshot.is_some()
            && self.previous_bill.is_some()
            && self.unsigned_request.is_some();
        let any_v1_evidence = self.prepared_snapshot.is_some()
            || self.previous_bill.is_some()
            || self.unsigned_request.is_some()
            || self.signed_request.is_some()
            || self.fully_signed_bill.is_some();
        let all_v2_prepared = self.prepared_registry_snapshot.is_some()
            && self.previous_registry_bill.is_some()
            && self.unsigned_registry_request.is_some();
        let any_v2_evidence = self.prepared_registry_snapshot.is_some()
            || self.previous_registry_bill.is_some()
            || self.unsigned_registry_request.is_some()
            || self.signed_registry_request.is_some()
            || self.fully_signed_registry_bill.is_some();
        let has_prepared = common_prepared
            && match rail {
                AgentHvmRailBindingRef::ChannelV1(_) => all_v1_prepared && !any_v2_evidence,
                AgentHvmRailBindingRef::RegistryV2(_) => all_v2_prepared && !any_v1_evidence,
            };
        let has_signed_request = match rail {
            AgentHvmRailBindingRef::ChannelV1(_) => self.signed_request.is_some(),
            AgentHvmRailBindingRef::RegistryV2(_) => self.signed_registry_request.is_some(),
        };
        let has_fully_signed_bill = match rail {
            AgentHvmRailBindingRef::ChannelV1(_) => self.fully_signed_bill.is_some(),
            AgentHvmRailBindingRef::RegistryV2(_) => self.fully_signed_registry_bill.is_some(),
        };
        let approved = matches!(
            self.status,
            AgentHvmPaymentStatus::Approved
                | AgentHvmPaymentStatus::SigningPrepared
                | AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::Committed
                | AgentHvmPaymentStatus::RecoveryRequired
        );
        let signed = matches!(
            self.status,
            AgentHvmPaymentStatus::Signed
                | AgentHvmPaymentStatus::Submitted
                | AgentHvmPaymentStatus::ExactRetryReady
                | AgentHvmPaymentStatus::Committed
        ) || self.status == AgentHvmPaymentStatus::RecoveryRequired
            && has_signed_request;
        let decision = self
            .approval_decision
            .as_ref()
            .map(|signed| signed.decision.decision);
        let owner_approved = decision == Some(ApprovalDecision::Approve);
        let decision_required = approved || self.status == AgentHvmPaymentStatus::Rejected;
        let expiry_and_recipient_valid = match rail {
            AgentHvmRailBindingRef::ChannelV1(_) => self.expires_at == self.request.expires_at,
            AgentHvmRailBindingRef::RegistryV2(binding) => {
                self.expires_at
                    == self.request.expires_at.min(
                        self.created_at
                            .saturating_add(HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS),
                    )
                    && self.request.recipient == binding.right_hub_address
            }
        };
        if self.request_commitment != request_commitment(&self.request)
            || self.binding_commitment != rail_commitment
            || !expiry_and_recipient_valid
            || self.network_binding.mainnet != (self.network_mode == "mainnet")
            || match rail {
                AgentHvmRailBindingRef::ChannelV1(binding) => {
                    self.network_binding.chain_id != binding.chain_id
                        || self.network_binding.network_instance_id != binding.network_instance_id
                        || binding.network_mode != self.network_mode
                        || binding.right_hub_address != self.hub_address
                }
                AgentHvmRailBindingRef::RegistryV2(binding) => {
                    self.network_binding.chain_id != binding.chain_id
                        || self.network_binding.network_instance_id != binding.network_instance_id
                        || binding.network_mode != self.network_mode
                        || binding.right_hub_address != self.hub_address
                }
            }
            || rail.left_address() == self.request.recipient
            || self.network_mode == "mainnet" && !self.hub_url.starts_with("https://")
            || self.agent_authorization_epoch == 0
            || self.policy_epoch == 0
            || self.signer_epoch == 0
            || self.emergency_epoch == 0
            || (self.status.retains_reservation()
                && self.reserved_units != self.request.amount_units)
            || (!self.status.retains_reservation()
                && self.status != AgentHvmPaymentStatus::PaymentIntentCreated
                && self.reserved_units != HacUnits::ZERO)
            || prepared_required && !has_prepared
            || prepared_forbidden
                && (has_prepared || any_common_prepared || any_v1_evidence || any_v2_evidence)
            || any_common_prepared != common_prepared
            || self.approval_commitment.is_some() != self.approval_request.is_some()
            || self.approval_decision.is_some() != self.approval_decision_commitment.is_some()
            || owner_approved != self.owner_authority_commitment.is_some()
            || decision_required && decision.is_none()
            || approved && !owner_approved
            || self.status == AgentHvmPaymentStatus::Rejected
                && decision != Some(ApprovalDecision::Reject)
            || self.status == AgentHvmPaymentStatus::ApprovalRequested && decision.is_some()
            || signed != has_signed_request
            || (self.status == AgentHvmPaymentStatus::Committed)
                != (has_fully_signed_bill && self.settled_at.is_some())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        match rail {
            AgentHvmRailBindingRef::ChannelV1(binding) => self.validate_v1_evidence(binding)?,
            AgentHvmRailBindingRef::RegistryV2(binding) => {
                self.validate_registry_evidence(binding)?
            }
        }
        if let Some(approval) = self.approval_request.as_ref()
            && (self.approval_commitment.as_deref()
                != approval.canonical_sha256_hex().ok().as_deref()
                || !self.matches_approval(approval))
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(decision) = self.approval_decision.as_ref()
            && (decision.decision.commitment
                != *self
                    .approval_request
                    .as_ref()
                    .ok_or(AgentWalletError::RecoveryRequired)?
                || self.approval_decision_commitment.as_deref()
                    != decision.canonical_sha256_hex().ok().as_deref())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if owner_approved {
            let calculated = match rail {
                AgentHvmRailBindingRef::ChannelV1(_) => self
                    .signer_binding_unchecked()?
                    .calculate_owner_authority_commitment(),
                AgentHvmRailBindingRef::RegistryV2(_) => self
                    .registry_signer_binding_unchecked()?
                    .calculate_owner_authority_commitment(),
            }
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if self.owner_authority_commitment.as_deref() != Some(calculated.as_str()) {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        Ok(())
    }

    fn validate_v1_evidence(&self, binding: &HvmChannelBindingV1) -> AgentWalletResult<()> {
        if let Some(previous) = self.previous_bill.as_ref() {
            previous
                .validate_fully_signed(binding)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if self.previous_bill_commitment.as_deref() != previous.commitment().ok().as_deref() {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        if let Some(snapshot) = self.prepared_snapshot.as_ref()
            && (snapshot.validate_runtime_binding(binding, 1, 1).is_err()
                || self.lease_snapshot_commitment.as_deref()
                    != snapshot.commitment().ok().as_deref())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(unsigned) = self.unsigned_request.as_ref() {
            let previous = self
                .previous_bill
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            unsigned
                .validate_unsigned_against(binding, previous, unsigned.created_unix)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if self.unsigned_request_commitment.as_deref() != unsigned.commitment().ok().as_deref()
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        if let Some(signed) = self.signed_request.as_ref() {
            let previous = self
                .previous_bill
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            signed
                .validate_against(binding, previous, signed.created_unix)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
        }
        if let Some(fully_signed) = self.fully_signed_bill.as_ref() {
            fully_signed
                .validate_fully_signed(binding)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            let signed = self
                .signed_request
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let mut expected = fully_signed.clone();
            expected.right_signature_hex.clear();
            if expected != signed.proposed_bill {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        Ok(())
    }

    fn validate_registry_evidence(&self, binding: &HvmRegistryBindingV2) -> AgentWalletResult<()> {
        if let Some(previous) = self.previous_registry_bill.as_ref() {
            previous
                .validate_fully_signed(binding)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if self.previous_bill_commitment.as_deref() != previous.commitment().ok().as_deref() {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        if let Some(snapshot) = self.prepared_registry_snapshot.as_ref()
            && (snapshot.validate_runtime_binding(binding, 1, 1).is_err()
                || self.lease_snapshot_commitment.as_deref()
                    != snapshot.commitment().ok().as_deref())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(unsigned) = self.unsigned_registry_request.as_ref() {
            let previous = self
                .previous_registry_bill
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            unsigned
                .validate_unsigned_against(binding, previous, unsigned.created_unix)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if self.unsigned_request_commitment.as_deref() != unsigned.commitment().ok().as_deref()
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        if let Some(signed) = self.signed_registry_request.as_ref() {
            let previous = self
                .previous_registry_bill
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            signed
                .validate_against(binding, previous, signed.created_unix)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
        }
        if let Some(fully_signed) = self.fully_signed_registry_bill.as_ref() {
            fully_signed
                .validate_fully_signed(binding)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
            let signed = self
                .signed_registry_request
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let mut expected = fully_signed.clone();
            expected.hub_signature_hex.clear();
            if expected != signed.proposed_bill {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        Ok(())
    }

    pub(crate) fn view(&self) -> AgentHvmPaymentOperationView {
        let payer = self
            .rail_binding()
            .map(|binding| binding.left_address().to_owned())
            .unwrap_or_default();
        AgentHvmPaymentOperationView {
            operation_id: self.operation_id.clone(),
            hub_operation_id: self.hub_operation_id.clone(),
            agent_wallet_id: self.agent_wallet_id.clone(),
            agent_id: self.agent_id.clone(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            idempotency_key: self.request.idempotency_key.clone(),
            request_commitment: self.request_commitment.clone(),
            network_mode: self.network_mode.clone(),
            hub_url: self.hub_url.clone(),
            hub_address: self.hub_address.clone(),
            binding_commitment: self.binding_commitment.clone(),
            lease_snapshot_commitment: self.lease_snapshot_commitment.clone(),
            previous_bill_commitment: self.previous_bill_commitment.clone(),
            unsigned_request_commitment: self.unsigned_request_commitment.clone(),
            payer,
            recipient: self.request.recipient.clone(),
            amount_units: self.request.amount_units,
            amount_zhu: self.request.amount_zhu().unwrap_or_default(),
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: self.request.amount_zhu().unwrap_or_default(),
            reserved_units: self.reserved_units,
            status: self.status,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: self.approval_commitment.clone(),
            approval_decision_commitment: self.approval_decision_commitment.clone(),
            owner_authority_commitment: self.owner_authority_commitment.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            settled_at: self.settled_at,
        }
    }

    fn signer_binding_unchecked(&self) -> AgentWalletResult<AgentHvmPaymentSignerBinding> {
        let approval = self
            .approval_request
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)?;
        Ok(AgentHvmPaymentSignerBinding {
            wallet_scope: self.wallet_scope.clone(),
            agent_id: self.agent_id.as_str().to_owned(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: self.required_approval_commitment()?.to_owned(),
            approval_decision_commitment: self
                .approval_decision_commitment
                .clone()
                .ok_or(AgentWalletError::ApprovalRequired)?,
            owner_authority_commitment: self.owner_authority_commitment.clone().unwrap_or_default(),
            approval_expires_at: approval.expires_at,
            network_mode: self.network_mode.clone(),
            network_binding: self.network_binding.clone(),
            hub_url: self.hub_url.clone(),
            hub_address: self.hub_address.clone(),
            hvm_binding: self.channel_binding()?.clone(),
            operation_id: self.hub_operation_id.clone(),
            idempotency_key: self.hub_idempotency_key.clone(),
            payer: self.channel_binding()?.left_address.clone(),
            recipient: self.request.recipient.clone(),
            amount_zhu: self.request.amount_zhu()?,
            fee_payer: "sender".to_owned(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: self.request.amount_zhu()?,
            previous_bill_commitment: self.required_previous_commitment()?.to_owned(),
            unsigned_request_commitment: self.required_unsigned_commitment()?.to_owned(),
        })
    }

    fn registry_signer_binding_unchecked(
        &self,
    ) -> AgentWalletResult<AgentHvmRegistryPaymentSignerBinding> {
        let approval = self
            .approval_request
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)?;
        Ok(AgentHvmRegistryPaymentSignerBinding {
            wallet_scope: self.wallet_scope.clone(),
            agent_id: self.agent_id.as_str().to_owned(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: self.required_approval_commitment()?.to_owned(),
            approval_decision_commitment: self
                .approval_decision_commitment
                .clone()
                .ok_or(AgentWalletError::ApprovalRequired)?,
            owner_authority_commitment: self.owner_authority_commitment.clone().unwrap_or_default(),
            approval_expires_at: approval.expires_at,
            network_mode: self.network_mode.clone(),
            network_binding: self.network_binding.clone(),
            hub_url: self.hub_url.clone(),
            hub_address: self.hub_address.clone(),
            hvm_binding: self.registry_binding()?.clone(),
            operation_id: self.hub_operation_id.clone(),
            idempotency_key: self.hub_idempotency_key.clone(),
            payer: self.registry_binding()?.left_address.clone(),
            recipient: self.request.recipient.clone(),
            amount_zhu: self.request.amount_zhu()?,
            fee_payer: "sender".to_owned(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: self.request.amount_zhu()?,
            previous_bill_commitment: self.required_previous_commitment()?.to_owned(),
            unsigned_request_commitment: self.required_unsigned_commitment()?.to_owned(),
        })
    }

    fn matches_approval(&self, approval: &AgentHvmApprovalCommitment) -> bool {
        let Ok(rail) = self.rail_binding() else {
            return false;
        };
        approval.operation_id == self.operation_id.as_str()
            && approval.hub_operation_id == self.hub_operation_id
            && approval.public_idempotency_key == self.request.idempotency_key
            && approval.hub_idempotency_key == self.hub_idempotency_key
            && approval.agent_wallet_id == self.agent_wallet_id.as_str()
            && approval.wallet_scope == self.wallet_scope.as_str()
            && approval.agent_id == self.agent_id.as_str()
            && approval.agent_authorization_epoch == self.agent_authorization_epoch
            && approval.hub_url == self.hub_url
            && approval.hub_address == self.hub_address
            && approval.settlement_profile == rail.settlement_profile()
            && approval.contract_address == rail.contract_address()
            && approval.deployment_tx_hash == rail.deployment_tx_hash()
            && approval.deployment_height == rail.deployment_height()
            && approval.bytecode_sha3 == rail.bytecode_sha3()
            && approval.channel_id == rail.channel_id()
            && approval.channel_reuse_version == u64::from(rail.reuse_version())
            && approval.challenge_blocks == rail.challenge_blocks()
            && approval.binding_commitment == self.binding_commitment
            && approval.lease_snapshot_commitment
                == self.lease_snapshot_commitment.clone().unwrap_or_default()
            && approval.previous_bill_commitment
                == self.previous_bill_commitment.clone().unwrap_or_default()
            && approval.unsigned_request_commitment
                == self.unsigned_request_commitment.clone().unwrap_or_default()
            && approval.payer == rail.left_address()
            && approval.payee == self.request.recipient
            && approval.amount_zhu == self.request.amount_zhu().unwrap_or_default()
            && approval.network_fee_zhu == 0
            && approval.wallet_fee_zhu == 0
            && approval.hub_fee_zhu == 0
            && approval.total_debit_zhu == self.request.amount_zhu().unwrap_or_default()
            && approval.policy_epoch == self.policy_epoch
            && approval.signer_epoch == self.signer_epoch
            && approval.emergency_epoch == self.emergency_epoch
            && approval.network_binding
                == approval_network_binding(&self.network_mode, &self.network_binding)
    }

    fn require_status(&self, expected: AgentHvmPaymentStatus) -> AgentWalletResult<()> {
        if self.status == expected {
            Ok(())
        } else {
            Err(AgentWalletError::InvalidOperationState)
        }
    }

    fn required_lease_commitment(&self) -> AgentWalletResult<&str> {
        self.lease_snapshot_commitment
            .as_deref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }
    fn required_previous_commitment(&self) -> AgentWalletResult<&str> {
        self.previous_bill_commitment
            .as_deref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }
    fn required_unsigned_commitment(&self) -> AgentWalletResult<&str> {
        self.unsigned_request_commitment
            .as_deref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }
    fn required_approval_commitment(&self) -> AgentWalletResult<&str> {
        self.approval_commitment
            .as_deref()
            .ok_or(AgentWalletError::ApprovalRequired)
    }

    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(crate) fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub(crate) fn agent_wallet_id(&self) -> &AgentWalletId {
        &self.agent_wallet_id
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        &self.request.idempotency_key
    }

    pub(crate) fn request_commitment(&self) -> &str {
        &self.request_commitment
    }

    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn status(&self) -> AgentHvmPaymentStatus {
        self.status
    }

    pub(crate) fn settled_at(&self) -> Option<u64> {
        self.settled_at
    }

    pub(crate) fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    /// The highest channel serial this operation *proves* was reached, taken
    /// only from bills that are fully signed and durably recorded here.
    ///
    /// This is the wallet's own history of the channel, held in Agent Wallet's
    /// encrypted state under its own key and its own journal — a different
    /// store from the L2 rollback-anchor memory, and not in the same backup
    /// set. It is what the anchor ratchet is measured against so that deleting
    /// or rewinding the L2 store alone does not reset it.
    ///
    /// A signed-but-unconfirmed proposal deliberately does not count: until a
    /// fully signed bill came back, the wallet does not know that serial was
    /// reached, and claiming a floor it cannot prove would refuse honest
    /// bills.
    pub(crate) fn committed_channel_serial(&self) -> u64 {
        let channel = self
            .fully_signed_bill
            .as_ref()
            .map(|bill| bill.serial)
            .unwrap_or(0);
        let registry = self
            .fully_signed_registry_bill
            .as_ref()
            .map(|bill| bill.serial)
            .unwrap_or(0);
        channel.max(registry)
    }
}

fn request_commitment(request: &AgentHvmPaymentRequest) -> String {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    for field in [
        request.idempotency_key.as_bytes(),
        request.amount_units.get().to_string().as_bytes(),
        request.recipient.as_bytes(),
        request.reason.as_bytes(),
        request.expires_at.to_string().as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex::encode(digest.finalize())
}

fn approval_network_binding(
    network_mode: &str,
    binding: &L1ChannelNetworkBinding,
) -> AgentFastPayNetworkBinding {
    AgentFastPayNetworkBinding {
        network_mode: network_mode.to_owned(),
        chain_id: binding.chain_id,
        genesis_identifier: binding.block_1_hash.clone(),
        node_profile_id: binding.node_profile_id.clone(),
        network_instance_id: binding.network_instance_id.clone(),
        transaction_format_version: binding.transaction_format_version,
    }
}

fn format_hac_zhu(zhu: u64) -> String {
    const ZHU_PER_HAC: u64 = 100_000_000;
    let whole = zhu / ZHU_PER_HAC;
    let fraction = zhu % ZHU_PER_HAC;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{}", format!("{fraction:08}").trim_end_matches('0'))
}

fn validate_text(value: &str, maximum_bytes: usize) -> AgentWalletResult<()> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        Err(AgentWalletError::InvalidPaymentRequest)
    } else {
        Ok(())
    }
}

#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
mod tests {
    use super::*;
    use field::{Address, Serialize as FieldSerialize, Sign};
    use hacash_wallet_core::account::WalletAccount;
    use hpay_companion_protocol::{
        AgentHvmApprovalDecision, DeviceRole, PlatformDeviceSigner, SoftwareDeviceIdentity,
    };
    use l2_fast_pay_hub::hvm_channel::{HVM_CHANNEL_BILL_SCHEMA, HVM_CHANNEL_BINDING_SCHEMA};
    use l2_fast_pay_hub::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
        HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT,
        HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT,
        HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2,
    };
    use l2_fast_pay_hub::node::{
        HPAY_CHANNEL_EXIT_BYTECODE_SHA3, HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
        HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA, HvmChannelLiveStorage, HvmStorageEntry,
    };

    fn lease<T>(value: T) -> HvmStorageEntry<T> {
        HvmStorageEntry {
            value,
            live_blocks: 100,
            recover_blocks: 50,
            active: true,
            recoverable: false,
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        WalletAccount,
        WalletAccount,
        AgentWalletId,
        AgentId,
        L1ChannelNetworkBinding,
        HvmChannelBindingV1,
        HvmChannelLiveSnapshot,
        HvmChannelBillV1,
    ) {
        hacash_wallet_core::protocol_init::ensure_protocol_setup();
        let temp = tempfile::tempdir().unwrap();
        let left = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let agent_id = AgentId::new();
        let block_one = "11".repeat(32);
        let node_profile_id = "hpay-local-pilot-chain-v1";
        let network_instance_id = hacash_wallet_core::network_instance_id(
            "local_pilot_v1",
            7,
            false,
            &block_one,
            node_profile_id,
            2,
        );
        let network_binding = L1ChannelNetworkBinding {
            network_kind: "local_pilot_v1".into(),
            chain_id: 7,
            mainnet: false,
            block_1_hash: block_one,
            node_profile_id: node_profile_id.into(),
            network_instance_id: network_instance_id.clone(),
            transaction_format_version: 2,
        };
        let binding = HvmChannelBindingV1 {
            schema: HVM_CHANNEL_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: network_instance_id.clone(),
            contract_address: vm::ContractAddress::from_unchecked(Address::create_contract(
                [7; 20],
            ))
            .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 1,
            bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 1,
            left_address: left.address(),
            right_hub_address: hub.address(),
            left_deposit_zhu: 100_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let snapshot = HvmChannelLiveSnapshot {
            ret: 0,
            schema: HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA.into(),
            chain_id: 7,
            observed_height: 10,
            evaluation_height: 11,
            contract_address: binding.contract_address.clone(),
            deployment_tx_hash: binding.deployment_tx_hash.clone(),
            deployment_height: 1,
            deployment_action_verified: true,
            bytecode_sha3: binding.bytecode_sha3.clone(),
            storage_key_count: 18,
            all_keys_active: true,
            minimum_live_blocks: 100,
            minimum_recover_blocks: 50,
            storage: HvmChannelLiveStorage {
                status: lease(2),
                network: lease(network_instance_id),
                channel_id: lease(binding.channel_id.clone()),
                reuse: lease(1),
                left: lease(left.address()),
                right: lease(hub.address()),
                left_deposit: lease(100_000_000),
                right_deposit: lease(0),
                left_paid: lease(100_000_000),
                right_paid: lease(0),
                total: lease(100_000_000),
                serial: lease(0),
                left_balance: lease(100_000_000),
                right_balance: lease(0),
                challenge_blocks: lease(12),
                deadline: lease(0),
                left_claimed: lease(false),
                right_claimed: lease(false),
            },
        };
        let mut previous = HvmChannelBillV1 {
            schema: HVM_CHANNEL_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: 100_000_000,
            right_balance_zhu: 0,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let hash = previous.signing_hash(&binding).unwrap();
        previous.left_signature_hex = hex::encode(Sign::create_by(left.inner(), &hash).serialize());
        previous.right_signature_hex = hex::encode(Sign::create_by(hub.inner(), &hash).serialize());
        (
            temp,
            left,
            hub,
            wallet_id,
            agent_id,
            network_binding,
            binding,
            snapshot,
            previous,
        )
    }

    fn registry_fixture() -> (
        tempfile::TempDir,
        WalletAccount,
        WalletAccount,
        AgentWalletId,
        AgentId,
        L1ChannelNetworkBinding,
        HvmRegistryBindingV2,
        HvmRegistryLiveSnapshotV2,
        HvmRegistryBillV2,
        HvmChannelBindingV1,
    ) {
        let (temp, left, hub, wallet_id, agent_id, network, v1, _, _) = fixture();
        let binding = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: network.chain_id,
            network_instance_id: network.network_instance_id.clone(),
            contract_address: vm::ContractAddress::from_unchecked(Address::create_contract(
                [9; 20],
            ))
            .to_readable(),
            deployment_tx_hash: "44".repeat(32),
            deployment_height: 2,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "55".repeat(16),
            reuse_version: 0,
            left_address: left.address(),
            right_hub_address: hub.address(),
            left_deposit_zhu: 100_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let snapshot = HvmRegistryLiveSnapshotV2 {
            ret: 0,
            schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            chain_id: binding.chain_id,
            network_instance_id: binding.network_instance_id.clone(),
            observed_height: 10,
            evaluation_height: 11,
            contract_address: binding.contract_address.clone(),
            deployment_tx_hash: binding.deployment_tx_hash.clone(),
            deployment_height: binding.deployment_height,
            deployment_action_verified: true,
            bytecode_sha3: binding.bytecode_sha3.clone(),
            hub_address: hub.address(),
            left_address: left.address(),
            registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
            channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
            all_keys_active: true,
            minimum_live_blocks: 100,
            minimum_recover_blocks: 50,
            registry: HvmRegistryGlobalStorageV2 {
                g_network: lease(binding.network_instance_id.clone()),
                g_hub: lease(hub.address()),
                g_locked: lease(100_000_000),
                g_left_claimable: lease(0),
                g_hub_claimable: lease(0),
                g_open_count: lease(1),
            },
            channel: HvmRegistryChannelStorageV2 {
                status: lease(2),
                channel_id: lease(binding.channel_id.clone()),
                reuse: lease(binding.reuse_version),
                deposit: lease(100_000_000),
                paid: lease(100_000_000),
                total: lease(100_000_000),
                serial: lease(0),
                left_balance: lease(100_000_000),
                hub_balance: lease(0),
                challenge_blocks: lease(12),
                deadline: lease(0),
                left_claimed: lease(false),
            },
        };
        let mut previous = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: 100_000_000,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = previous.signing_hash(&binding).unwrap();
        previous.left_signature_hex = hex::encode(Sign::create_by(left.inner(), &hash).serialize());
        previous.hub_signature_hex = hex::encode(Sign::create_by(hub.inner(), &hash).serialize());
        (
            temp, left, hub, wallet_id, agent_id, network, binding, snapshot, previous, v1,
        )
    }

    #[tokio::test]
    async fn exact_zero_fee_hvm_flow_is_durable_and_signature_bound() {
        let (temp, left, hub, wallet_id, agent_id, network, binding, snapshot, previous) =
            fixture();
        let now = 1_000;
        let mut operation = AgentHvmPaymentOperation::new(
            OperationId::new(),
            agent_id,
            wallet_id.clone(),
            AgentHvmPaymentRequest {
                idempotency_key: "agent-hvm-payment-1".into(),
                amount_units: HacUnits::new(10_000),
                recipient: "verified-hvm-service".into(),
                reason: "approved compute".into(),
                expires_at: now + 300,
            },
            "testnet",
            network,
            "http://127.0.0.1:8790",
            &hub.address(),
            binding,
            2,
            3,
            4,
            5,
            now,
        )
        .unwrap();
        operation.reserve().unwrap();
        operation
            .prepare_unsigned(&snapshot, previous.clone(), now + 1)
            .unwrap();
        let approval = operation
            .request_approval(DeviceId::random(DeviceRole::Desktop), now + 2)
            .unwrap();
        assert_eq!(approval.wallet_fee_zhu, 0);
        assert_eq!(approval.hub_fee_zhu, 0);
        assert_eq!(approval.total_debit_zhu, approval.amount_zhu);

        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let decision = AgentHvmApprovalDecision::from_commitment(
            approval,
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            now + 3,
        )
        .unwrap();
        let signed_decision = SignedAgentHvmApprovalDecision::sign(decision, &mobile)
            .await
            .unwrap();
        operation
            .record_verified_owner_decision(signed_decision)
            .unwrap();
        let mut abandoned = operation.clone();
        abandoned.mark_signing_prepared(now + 4).unwrap();
        abandoned.mark_signing_abandoned().unwrap();
        abandoned.validate().unwrap();
        let abandoned_roundtrip: AgentHvmPaymentOperation =
            serde_json::from_slice(&serde_json::to_vec(&abandoned).unwrap()).unwrap();
        assert_eq!(abandoned_roundtrip, abandoned);
        operation.mark_signing_prepared(now + 4).unwrap();

        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let signer = crate::signer::AgentTransactionSigner::new(
            wallet_id,
            left.address(),
            "testnet".into(),
            4,
            &left.secret_hex(),
            now + 4,
        )
        .unwrap();
        let authority = operation.signer_binding().unwrap();
        let signed_request = signer
            .sign_exact_hvm_payment(
                &authority,
                operation.previous_bill().unwrap(),
                operation.unsigned_request().unwrap().clone(),
                &permit,
                now + 4,
            )
            .unwrap();
        operation
            .record_signed_request(signed_request.clone(), now + 4)
            .unwrap();
        let mut exact_retry = operation.clone();
        exact_retry.mark_exact_retry_ready().unwrap();
        exact_retry.mark_submitted().unwrap();
        exact_retry.validate().unwrap();
        operation.mark_submitted().unwrap();

        let mut fully_signed = signed_request.proposed_bill;
        let bill_hash = fully_signed.signing_hash(&authority.hvm_binding).unwrap();
        fully_signed.right_signature_hex =
            hex::encode(Sign::create_by(hub.inner(), &bill_hash).serialize());
        operation.record_committed(fully_signed, now + 5).unwrap();
        let view = operation.view();
        assert_eq!(view.status, AgentHvmPaymentStatus::Committed);
        assert_eq!(view.wallet_fee_zhu, 0);
        assert_eq!(view.hub_fee_zhu, 0);
        assert_eq!(view.reserved_units, HacUnits::ZERO);
        assert_eq!(view.amount_zhu, 1_000_000);

        let bytes = serde_json::to_vec(&operation).unwrap();
        let decoded: AgentHvmPaymentOperation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, operation);
        decoded.validate().unwrap();

        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["lease_snapshot_commitment"] = serde_json::json!("aa".repeat(32));
        let tampered: AgentHvmPaymentOperation = serde_json::from_value(tampered).unwrap();
        assert_eq!(tampered.validate(), Err(AgentWalletError::RecoveryRequired));
    }

    #[tokio::test]
    async fn registry_v2_flow_is_fee_free_durable_and_rejects_mixed_rails() {
        let (temp, left, hub, wallet_id, agent_id, network, binding, snapshot, previous, v1) =
            registry_fixture();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let hub_address = hub.address();
        let mut operation = AgentHvmPaymentOperation::new_registry(
            OperationId::new(),
            agent_id,
            wallet_id.clone(),
            AgentHvmPaymentRequest {
                idempotency_key: "agent-hvm-registry-payment-1".into(),
                amount_units: HacUnits::new(10_000),
                recipient: hub_address.clone(),
                reason: "approved registry compute".into(),
                expires_at: now + 600,
            },
            "testnet",
            network,
            "http://127.0.0.1:8790",
            &hub.address(),
            binding,
            2,
            3,
            4,
            5,
            now,
        )
        .unwrap();
        operation.reserve().unwrap();
        assert_eq!(operation.view().expires_at, now + 300);
        operation
            .prepare_unsigned_registry(&snapshot, previous, now + 1)
            .unwrap();
        assert_eq!(
            operation.unsigned_registry_request().unwrap().expires_unix,
            now + 300
        );
        let approval = operation
            .request_approval(DeviceId::random(DeviceRole::Desktop), now + 2)
            .unwrap();
        assert_eq!(
            approval.settlement_profile,
            HPAY_REGISTRY_SETTLEMENT_PROFILE
        );
        assert_eq!(approval.channel_reuse_version, 0);
        assert_eq!(approval.wallet_fee_zhu, 0);
        assert_eq!(approval.hub_fee_zhu, 0);
        assert_eq!(approval.total_debit_zhu, approval.amount_zhu);

        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let decision = AgentHvmApprovalDecision::from_commitment(
            approval,
            ApprovalDecision::Approve,
            mobile.identity().device_id().clone(),
            1,
            1,
            now + 3,
        )
        .unwrap();
        operation
            .record_verified_owner_decision(
                SignedAgentHvmApprovalDecision::sign(decision, &mobile)
                    .await
                    .unwrap(),
            )
            .unwrap();
        operation.mark_signing_prepared(now + 4).unwrap();
        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let signer = crate::signer::AgentTransactionSigner::new(
            wallet_id,
            left.address(),
            "testnet".into(),
            4,
            &left.secret_hex(),
            now + 4,
        )
        .unwrap();
        let authority = operation.registry_signer_binding().unwrap();
        let signed = signer
            .sign_exact_hvm_registry_payment(
                &authority,
                operation.previous_registry_bill().unwrap(),
                operation.unsigned_registry_request().unwrap().clone(),
                &permit,
                now + 4,
            )
            .unwrap();
        assert!(!signed.payer_authorization_signature_hex.is_empty());
        operation
            .record_signed_registry_request(signed.clone(), now + 4)
            .unwrap();
        operation.mark_submitted().unwrap();
        let mut fully_signed = signed.proposed_bill;
        let hash = fully_signed.signing_hash(&authority.hvm_binding).unwrap();
        fully_signed.hub_signature_hex =
            hex::encode(Sign::create_by(hub.inner(), &hash).serialize());
        operation
            .record_committed_registry(fully_signed, now + 5)
            .unwrap();
        operation.validate().unwrap();

        let bytes = serde_json::to_vec(&operation).unwrap();
        let decoded: AgentHvmPaymentOperation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, operation);
        let mut mixed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        mixed["hvm_binding"] = serde_json::to_value(v1).unwrap();
        let mixed: AgentHvmPaymentOperation = serde_json::from_value(mixed).unwrap();
        assert_eq!(mixed.validate(), Err(AgentWalletError::RecoveryRequired));

        let mut missing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("hvm_registry_binding");
        let missing: AgentHvmPaymentOperation = serde_json::from_value(missing).unwrap();
        assert_eq!(missing.validate(), Err(AgentWalletError::RecoveryRequired));
    }

    /// Each rail owns its own request rules and neither constructor may borrow
    /// the other's. Registry V2 credits only the bound Hub balance, so the
    /// payee is pinned to the Hub identity and the authorization window is
    /// capped at the rail maximum. Channel V1 settles to the Hub but routes to
    /// a named payee, and carries no rail-level lifetime cap, so its
    /// owner-visible deadline is the deadline that gets authorized and signed.
    /// Swapping either rule builds an operation that cannot satisfy `validate`,
    /// or defers a certain rail rejection until after funds are reserved.
    #[test]
    fn rail_request_rules_stay_on_their_own_rail() {
        let (_temp, left, hub, wallet_id, agent_id, network, binding, _snapshot, _bill) = fixture();
        let now = 1_000_u64;
        let beyond_registry_cap = now + HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS * 4;

        // Channel V1 keeps the exact requested deadline. Clamping it here left
        // `expires_at` disagreeing with `request.expires_at`, which `validate`
        // rejects for this rail.
        let channel = AgentHvmPaymentOperation::new(
            OperationId::new(),
            agent_id.clone(),
            wallet_id.clone(),
            AgentHvmPaymentRequest {
                idempotency_key: "agent-hvm-payment-long-window".into(),
                amount_units: HacUnits::new(1),
                recipient: "verified-hvm-service".into(),
                reason: "named payee routed by the hub".into(),
                expires_at: beyond_registry_cap,
            },
            "testnet",
            network.clone(),
            "http://127.0.0.1:8790",
            &hub.address(),
            binding.clone(),
            2,
            3,
            4,
            5,
            now,
        )
        .unwrap();
        assert_eq!(channel.view().expires_at, beyond_registry_cap);
        assert_eq!(channel.view().recipient, "verified-hvm-service");
        channel.validate().unwrap();

        // The payer may never be the payee on either rail.
        assert_eq!(
            AgentHvmPaymentOperation::new(
                OperationId::new(),
                agent_id,
                wallet_id,
                AgentHvmPaymentRequest {
                    idempotency_key: "agent-hvm-payment-self".into(),
                    amount_units: HacUnits::new(1),
                    recipient: left.address(),
                    reason: "payer may not be the payee".into(),
                    expires_at: now + 300,
                },
                "testnet",
                network,
                "http://127.0.0.1:8790",
                &hub.address(),
                binding,
                2,
                3,
                4,
                5,
                now,
            ),
            Err(AgentWalletError::InvalidWalletScope)
        );

        let (
            _registry_temp,
            _registry_left,
            registry_hub,
            registry_wallet_id,
            registry_agent_id,
            registry_network,
            registry_binding,
            _registry_snapshot,
            _registry_bill,
            _v1,
        ) = registry_fixture();

        // Registry V2 refuses a third-party payee up front instead of letting
        // the rail ledger reject it after the reservation is taken.
        assert_eq!(
            AgentHvmPaymentOperation::new_registry(
                OperationId::new(),
                registry_agent_id.clone(),
                registry_wallet_id.clone(),
                AgentHvmPaymentRequest {
                    idempotency_key: "agent-hvm-registry-third-party".into(),
                    amount_units: HacUnits::new(1),
                    recipient: "verified-hvm-service".into(),
                    reason: "registry credits only the bound hub".into(),
                    expires_at: now + 60,
                },
                "testnet",
                registry_network.clone(),
                "http://127.0.0.1:8790",
                &registry_hub.address(),
                registry_binding.clone(),
                2,
                3,
                4,
                5,
                now,
            ),
            Err(AgentWalletError::InvalidWalletScope)
        );

        // Registry V2 caps the authorized window at the rail maximum.
        let registry = AgentHvmPaymentOperation::new_registry(
            OperationId::new(),
            registry_agent_id,
            registry_wallet_id,
            AgentHvmPaymentRequest {
                idempotency_key: "agent-hvm-registry-long-window".into(),
                amount_units: HacUnits::new(1),
                recipient: registry_hub.address(),
                reason: "registry caps the authorization window".into(),
                expires_at: beyond_registry_cap,
            },
            "testnet",
            registry_network,
            "http://127.0.0.1:8790",
            &registry_hub.address(),
            registry_binding,
            2,
            3,
            4,
            5,
            now,
        )
        .unwrap();
        assert_eq!(
            registry.view().expires_at,
            now + HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS
        );
        assert!(registry.view().expires_at < registry.request.expires_at);
        registry.validate().unwrap();
    }

    #[test]
    fn mainnet_http_and_hvm_network_drift_fail_before_reservation() {
        let (_temp, _left, hub, wallet_id, agent_id, mut network, binding, _snapshot, _bill) =
            fixture();
        network.mainnet = true;
        assert!(
            AgentHvmPaymentOperation::new(
                OperationId::new(),
                agent_id,
                wallet_id,
                AgentHvmPaymentRequest {
                    idempotency_key: "agent-hvm-payment-2".into(),
                    amount_units: HacUnits::new(1),
                    recipient: "verified-hvm-service".into(),
                    reason: "must fail".into(),
                    expires_at: 1_300,
                },
                "mainnet",
                network,
                "http://hub.example",
                &hub.address(),
                binding,
                1,
                1,
                1,
                1,
                1_000,
            )
            .is_err()
        );
    }
}
