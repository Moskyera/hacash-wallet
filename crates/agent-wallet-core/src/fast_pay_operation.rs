//! Durable Agent-only Fast Pay intent and approval model.
//!
//! This state is deliberately separate from the L1 [`AgentOperation`]. A Fast
//! Pay intent has no network fee, no wallet fee and no L1 fallback. It is bound
//! to one verified Agent channel incarnation before any approval can exist.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::CompanionError;
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use hpay_companion_protocol::{AGENT_FAST_PAY_APPROVAL_VERSION, DeviceId};
use hpay_companion_protocol::{
    AgentFastPayApprovalCommitment, ApprovalDecision, SignedAgentFastPayApprovalDecision,
};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::service::AgentL2Binding;
use crate::types::{AgentId, AgentWalletId, OperationId, WalletScope};

const REQUEST_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/FAST-PAY/REQUEST/V1";
const ROUTE_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/FAST-PAY/ROUTE/V1";
const OWNER_AUTHORITY_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/FAST-PAY/OWNER-AUTHORITY/V1";
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 1_024;
const MAX_REQUEST_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentFastPayRequest {
    pub idempotency_key: String,
    pub amount_units: HacUnits,
    pub recipient: String,
    pub reason: String,
    pub expires_at: u64,
}

impl AgentFastPayRequest {
    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn amount_millimeis(&self) -> AgentWalletResult<u64> {
        self.amount_units.to_millimeis_exact()
    }

    pub(crate) fn validate(&self, network_mode: &str, now: u64) -> AgentWalletResult<()> {
        validate_text(&self.idempotency_key, MAX_IDEMPOTENCY_BYTES)?;
        validate_text(&self.reason, MAX_REASON_BYTES)?;
        if self.amount_units == HacUnits::ZERO
            || !self
                .amount_units
                .get()
                .is_multiple_of(HacUnits::PER_MILLIMEI)
        {
            return Err(AgentWalletError::InvalidAmount);
        }
        hacash_wallet_core::require_address_for_network(&self.recipient, network_mode)
            .map_err(|_| AgentWalletError::RecipientNotAllowed)?;
        if self.expires_at <= now
            || self.expires_at.saturating_sub(now) > MAX_REQUEST_LIFETIME_SECONDS
        {
            return Err(AgentWalletError::RequestExpired);
        }
        Ok(())
    }

    pub(crate) fn commitment_hex(&self) -> String {
        digest_fields(
            REQUEST_DOMAIN,
            &[
                self.idempotency_key.as_str(),
                self.amount_units.get().to_string().as_str(),
                self.recipient.as_str(),
                self.reason.as_str(),
                self.expires_at.to_string().as_str(),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentFastPayStatus {
    PaymentIntentCreated,
    FundsReserved,
    ApprovalRequested,
    Approved,
    ExecutionPrepared,
    Signed,
    Submitted,
    AwaitingRecipient,
    ExactRetryReady,
    Committed,
    Rejected,
    Cancelled,
    RecoveryRequired,
}

impl AgentFastPayStatus {
    pub const fn retains_reservation(self) -> bool {
        matches!(
            self,
            Self::FundsReserved
                | Self::ApprovalRequested
                | Self::Approved
                | Self::ExecutionPrepared
                | Self::Signed
                | Self::Submitted
                | Self::AwaitingRecipient
                | Self::ExactRetryReady
                | Self::RecoveryRequired
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentFastPayOperationView {
    pub operation_id: OperationId,
    pub hub_operation_id: String,
    pub agent_wallet_id: AgentWalletId,
    pub agent_id: AgentId,
    pub agent_authorization_epoch: u64,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub binding_commitment: String,
    pub route_commitment: String,
    pub network_mode: String,
    pub payer: String,
    pub recipient: String,
    pub amount_units: HacUnits,
    pub network_fee_units: HacUnits,
    pub wallet_fee_units: HacUnits,
    pub total_debit_units: HacUnits,
    pub reserved_units: HacUnits,
    pub status: AgentFastPayStatus,
    pub policy_epoch: u64,
    pub signer_epoch: u64,
    pub emergency_epoch: u64,
    pub approval_commitment: Option<String>,
    pub owner_authority_commitment: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub settled_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentFastPayOperation {
    operation_id: OperationId,
    hub_operation_id: String,
    hub_idempotency_key: String,
    agent_wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    agent_id: AgentId,
    #[serde(default)]
    agent_authorization_epoch: u64,
    request: AgentFastPayRequest,
    request_commitment: String,
    binding_commitment: String,
    route_commitment: String,
    network_mode: String,
    payer: String,
    hub_url: String,
    hub_identity: String,
    channel_id: String,
    channel_reuse_version: u64,
    channel_open_height: u64,
    policy_epoch: u64,
    signer_epoch: u64,
    emergency_epoch: u64,
    status: AgentFastPayStatus,
    reserved_units: HacUnits,
    approval_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_request: Option<AgentFastPayApprovalCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_decision: Option<SignedAgentFastPayApprovalDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_authority_commitment: Option<String>,
    created_at: u64,
    expires_at: u64,
    settled_at: Option<u64>,
}

impl AgentFastPayOperation {
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn new(
        operation_id: OperationId,
        agent_id: AgentId,
        agent_wallet_id: AgentWalletId,
        request: AgentFastPayRequest,
        binding: &AgentL2Binding,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        created_at: u64,
    ) -> AgentWalletResult<Self> {
        operation_id.validate()?;
        agent_id.validate()?;
        agent_wallet_id.validate()?;
        binding.validate()?;
        request.validate(binding.network_mode(), created_at)?;
        if binding.wallet_id() != &agent_wallet_id
            || binding.agent_address() == request.recipient
            || agent_authorization_epoch == 0
            || policy_epoch == 0
            || signer_epoch == 0
            || emergency_epoch == 0
        {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        let wallet_scope = WalletScope::for_agent_wallet(&agent_wallet_id);
        if binding.wallet_scope() != &wallet_scope {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        let hub_operation_id = uuid::Uuid::new_v4().to_string();
        let hub_idempotency_key = format!("hpay-agent:{}", uuid::Uuid::new_v4());
        let request_commitment = request.commitment_hex();
        let expires_at = request.expires_at;
        let mut operation = Self {
            operation_id,
            hub_operation_id,
            hub_idempotency_key,
            agent_wallet_id,
            wallet_scope,
            agent_id,
            agent_authorization_epoch,
            request,
            request_commitment,
            binding_commitment: binding.commitment_sha256().to_owned(),
            route_commitment: String::new(),
            network_mode: binding.network_mode().to_owned(),
            payer: binding.agent_address().to_owned(),
            hub_url: binding.hub_url().to_owned(),
            hub_identity: binding.hub_address().to_owned(),
            channel_id: binding.channel_id().to_owned(),
            channel_reuse_version: binding.channel_reuse_version(),
            channel_open_height: binding.channel_open_height(),
            policy_epoch,
            signer_epoch,
            emergency_epoch,
            status: AgentFastPayStatus::PaymentIntentCreated,
            reserved_units: HacUnits::ZERO,
            approval_commitment: None,
            approval_request: None,
            approval_decision: None,
            owner_authority_commitment: None,
            created_at,
            expires_at,
            settled_at: None,
        };
        operation.route_commitment = operation.calculate_route_commitment();
        operation.validate()?;
        Ok(operation)
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn reserve(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentFastPayStatus::PaymentIntentCreated)?;
        self.reserved_units = self.request.amount_units;
        self.status = AgentFastPayStatus::FundsReserved;
        Ok(())
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn request_approval(
        &mut self,
        binding: &AgentL2Binding,
        desktop_device_id: DeviceId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayApprovalCommitment> {
        self.require_status(AgentFastPayStatus::FundsReserved)?;
        if now >= self.expires_at || !self.matches_binding(binding) {
            return Err(AgentWalletError::RequestExpired);
        }
        let expires_at = self.expires_at.min(
            now.checked_add(hpay_companion_protocol::AGENT_FAST_PAY_APPROVAL_MAX_LIFETIME_SECS)
                .ok_or(AgentWalletError::IntegerOverflow)?,
        );
        let approval = AgentFastPayApprovalCommitment {
            approval_version: AGENT_FAST_PAY_APPROVAL_VERSION,
            approval_id: uuid::Uuid::new_v4().to_string(),
            challenge_nonce: uuid::Uuid::new_v4().simple().to_string(),
            operation_id: self.operation_id.as_str().to_owned(),
            hub_operation_id: self.hub_operation_id.clone(),
            public_idempotency_key: self.request.idempotency_key.clone(),
            hub_idempotency_key: self.hub_idempotency_key.clone(),
            agent_wallet_id: self.agent_wallet_id.as_str().to_owned(),
            wallet_scope: self.wallet_scope.as_str().to_owned(),
            agent_id: self.agent_id.as_str().to_owned(),
            desktop_device_id,
            request_commitment: self.request_commitment.clone(),
            binding_commitment: self.binding_commitment.clone(),
            route_commitment: self.route_commitment.clone(),
            payer: self.payer.clone(),
            payee: self.request.recipient.clone(),
            amount_hac: format_agent_hac(self.request.amount_units.get()),
            amount_units: self.request.amount_units.get(),
            amount_millimeis: self.request.amount_millimeis()?,
            hub_url: self.hub_url.clone(),
            hub_address: self.hub_identity.clone(),
            channel_id: self.channel_id.clone(),
            channel_reuse_version: self.channel_reuse_version,
            channel_open_height: self.channel_open_height,
            fee_payer: "sender".to_owned(),
            network_fee_units: 0,
            wallet_fee_units: 0,
            hub_fee_units: 0,
            total_debit_units: self.request.amount_units.get(),
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            issued_at: now,
            expires_at,
            network_binding: binding.network_binding().clone(),
        };
        let commitment = approval
            .canonical_sha256_hex()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        self.approval_commitment = Some(commitment);
        self.approval_request = Some(approval.clone());
        self.status = AgentFastPayStatus::ApprovalRequested;
        self.validate()?;
        Ok(approval)
    }

    pub(crate) fn validate(&self) -> AgentWalletResult<()> {
        self.operation_id.validate()?;
        self.agent_id.validate()?;
        self.agent_wallet_id.validate()?;
        self.wallet_scope.validate_for(&self.agent_wallet_id)?;
        self.request.validate(&self.network_mode, self.created_at)?;
        let canonical_hub_id = uuid::Uuid::parse_str(&self.hub_operation_id)
            .ok()
            .map(|value| value.to_string());
        if canonical_hub_id.as_deref() != Some(self.hub_operation_id.as_str())
            || !self.hub_idempotency_key.starts_with("hpay-agent:")
            || self.hub_idempotency_key.len() > 256
            || self.hub_idempotency_key.chars().any(char::is_control)
            || !matches!(self.network_mode.as_str(), "mainnet" | "testnet")
            || self.payer == self.request.recipient
            || self.hub_url.is_empty()
            || self.hub_identity.is_empty()
            || self.channel_id.len() != 32
            || self.channel_reuse_version == 0
            || self.channel_open_height == 0
            || self.agent_authorization_epoch == 0
            || self.policy_epoch == 0
            || self.signer_epoch == 0
            || self.emergency_epoch == 0
            || self.request_commitment.len() != 64
            || self.binding_commitment.len() != 64
            || self.route_commitment.len() != 64
            || self.request_commitment != self.request.commitment_hex()
            || self.route_commitment != self.calculate_route_commitment()
            || self.expires_at != self.request.expires_at
            || (self.status.retains_reservation()
                && self.reserved_units != self.request.amount_units)
            || (!self.status.retains_reservation()
                && self.status != AgentFastPayStatus::PaymentIntentCreated
                && self.reserved_units != HacUnits::ZERO)
            || self.approval_commitment.as_ref().is_some_and(|value| {
                value.len() != 64
                    || self.approval_request.as_ref().is_none_or(|approval| {
                        !approval
                            .canonical_sha256_hex()
                            .is_ok_and(|expected| expected == *value)
                            || !self.matches_approval_request(approval)
                    })
            })
            || self.approval_commitment.is_some() != self.approval_request.is_some()
            || (matches!(
                self.status,
                AgentFastPayStatus::PaymentIntentCreated | AgentFastPayStatus::FundsReserved
            ) && self.approval_request.is_some())
            || self.approval_decision.as_ref().is_some_and(|signed| {
                self.approval_request.as_ref().is_none_or(|approval| {
                    signed.decision.commitment != *approval
                        || signed.decision.canonical_bytes().is_err()
                        || signed.signature_hex.is_empty()
                        || !signed.signature_hex.len().is_multiple_of(2)
                        || !signed
                            .signature_hex
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                        || !decision_matches_status(signed.decision.decision, self.status)
                        || self.owner_authority_commitment.as_deref()
                            != self
                                .calculate_owner_authority_commitment(signed)
                                .ok()
                                .as_deref()
                })
            })
            || self.owner_authority_commitment.is_some() != self.approval_decision.is_some()
            || matches!(
                self.status,
                AgentFastPayStatus::ApprovalRequested
                    | AgentFastPayStatus::Approved
                    | AgentFastPayStatus::ExecutionPrepared
                    | AgentFastPayStatus::Signed
                    | AgentFastPayStatus::Submitted
                    | AgentFastPayStatus::AwaitingRecipient
                    | AgentFastPayStatus::ExactRetryReady
                    | AgentFastPayStatus::Committed
                    | AgentFastPayStatus::Rejected
                    | AgentFastPayStatus::RecoveryRequired
            ) && self.approval_commitment.is_none()
            || (matches!(
                self.status,
                AgentFastPayStatus::ApprovalRequested
                    | AgentFastPayStatus::Approved
                    | AgentFastPayStatus::ExecutionPrepared
                    | AgentFastPayStatus::Signed
                    | AgentFastPayStatus::Submitted
                    | AgentFastPayStatus::AwaitingRecipient
                    | AgentFastPayStatus::ExactRetryReady
                    | AgentFastPayStatus::Committed
                    | AgentFastPayStatus::Rejected
                    | AgentFastPayStatus::RecoveryRequired
            ) && self.approval_request.is_none())
            || (matches!(
                self.status,
                AgentFastPayStatus::Approved
                    | AgentFastPayStatus::ExecutionPrepared
                    | AgentFastPayStatus::Signed
                    | AgentFastPayStatus::Submitted
                    | AgentFastPayStatus::AwaitingRecipient
                    | AgentFastPayStatus::ExactRetryReady
                    | AgentFastPayStatus::Committed
                    | AgentFastPayStatus::Rejected
                    | AgentFastPayStatus::RecoveryRequired
            ) && self.approval_decision.is_none())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        hacash_wallet_core::require_address_for_network(&self.payer, &self.network_mode)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        Ok(())
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
    pub(crate) fn request_commitment(&self) -> &str {
        &self.request_commitment
    }
    pub(crate) fn idempotency_key(&self) -> &str {
        &self.request.idempotency_key
    }
    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }
    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub(crate) fn settled_at(&self) -> Option<u64> {
        self.settled_at
    }
    pub(crate) fn status(&self) -> AgentFastPayStatus {
        self.status
    }
    pub(crate) fn matches_binding(&self, binding: &AgentL2Binding) -> bool {
        self.binding_commitment == binding.commitment_sha256()
            && self.agent_wallet_id == *binding.wallet_id()
            && self.wallet_scope == *binding.wallet_scope()
            && self.network_mode == binding.network_mode()
            && self.payer == binding.agent_address()
            && self.hub_url == binding.hub_url()
            && self.hub_identity == binding.hub_address()
            && self.channel_id == binding.channel_id()
            && self.channel_reuse_version == binding.channel_reuse_version()
            && self.channel_open_height == binding.channel_open_height()
            && self
                .approval_request
                .as_ref()
                .is_none_or(|approval| approval.network_binding == *binding.network_binding())
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn stored_approval_request(
        &self,
    ) -> AgentWalletResult<&AgentFastPayApprovalCommitment> {
        self.approval_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn stored_approval_decision(&self) -> Option<&SignedAgentFastPayApprovalDecision> {
        self.approval_decision.as_ref()
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn hub_idempotency_key(&self) -> &str {
        &self.hub_idempotency_key
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn signer_binding(
        &self,
    ) -> AgentWalletResult<crate::signer::AgentFastPaySignerBinding> {
        if self.status != AgentFastPayStatus::ExecutionPrepared {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let approval = self
            .approval_request
            .as_ref()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let restricted_sender_authority = self.restricted_sender_authority()?;
        Ok(crate::signer::AgentFastPaySignerBinding {
            hub_operation_id: self.hub_operation_id.clone(),
            hub_idempotency_key: self.hub_idempotency_key.clone(),
            wallet_scope: self.wallet_scope.clone(),
            hub_identity: self.hub_identity.clone(),
            channel_id: self.channel_id.clone(),
            channel_reuse_version: self.channel_reuse_version,
            network_mode: self.network_mode.clone(),
            payer: self.payer.clone(),
            payee: self.request.recipient.clone(),
            amount: self.request.amount_units.to_decimal(),
            // ClientL2Safety and the wire bill account in millimeis, while the
            // Agent ledger uses 1e-6 HAC units. Never mix the two domains.
            amount_units: self.request.amount_millimeis()?,
            restricted_sender_authority,
            approval_expires_at: approval.expires_at,
            signer_epoch: self.signer_epoch,
        })
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn restricted_sender_authority(
        &self,
    ) -> AgentWalletResult<hacash_wallet_core::l2_safety::RestrictedSenderAuthority> {
        let approval = self
            .approval_request
            .as_ref()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let owner_authority_commitment = self
            .owner_authority_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        let approval_commitment = self
            .approval_commitment
            .clone()
            .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
        Ok(hacash_wallet_core::l2_safety::RestrictedSenderAuthority {
            owner_authority_commitment,
            approval_commitment,
            agent_id: self.agent_id.as_str().to_owned(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_expires_at: approval.expires_at,
            hub_url: self.hub_url.clone(),
            channel_open_height: self.channel_open_height,
            binding_commitment: self.binding_commitment.clone(),
            chain_id: approval.network_binding.chain_id,
            genesis_identifier: approval.network_binding.genesis_identifier.clone(),
            node_profile_id: approval.network_binding.node_profile_id.clone(),
            network_instance_id: approval.network_binding.network_instance_id.clone(),
            transaction_format_version: approval.network_binding.transaction_format_version,
            fee_payer: approval.fee_payer.clone(),
            network_fee_units: approval.network_fee_units,
            wallet_fee_units: approval.wallet_fee_units,
            hub_fee_units: approval.hub_fee_units,
            // This context is consumed by wallet-core's L2 signer, whose
            // durable `amount_units` are millimeis. The signed mobile approval
            // still binds both the exact 1e-6 HAC amount and this conversion.
            total_debit_units: approval.amount_millimeis,
        })
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn record_owner_decision(
        &mut self,
        signed: SignedAgentFastPayApprovalDecision,
    ) -> AgentWalletResult<()> {
        if self.status != AgentFastPayStatus::ApprovalRequested {
            return Err(AgentWalletError::InvalidOperationState);
        }
        if self
            .approval_request
            .as_ref()
            .is_none_or(|approval| signed.decision.commitment != *approval)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let decision = signed.decision.decision;
        let owner_authority_commitment = self.calculate_owner_authority_commitment(&signed)?;
        self.approval_decision = Some(signed);
        self.owner_authority_commitment = Some(owner_authority_commitment);
        match decision {
            ApprovalDecision::Approve => self.status = AgentFastPayStatus::Approved,
            ApprovalDecision::Reject => {
                self.status = AgentFastPayStatus::Rejected;
                self.reserved_units = HacUnits::ZERO;
            }
        }
        self.validate()
    }

    /// Returns the immutable operation view that a later live pre-sign gate
    /// must reverify. This is model validation only: it performs no network
    /// call, key access, signature, Hub submission or state transition.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn approved_signing_view(
        &self,
        binding: &AgentL2Binding,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.validate()?;
        let approval = self
            .approval_request
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        let decision = self
            .approval_decision
            .as_ref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        if !matches!(
            self.status,
            AgentFastPayStatus::Approved | AgentFastPayStatus::ExecutionPrepared
        ) || decision.decision.decision != ApprovalDecision::Approve
        {
            return Err(AgentWalletError::InvalidOperationState);
        }
        approval.validate_at(now).map_err(|error| match error {
            CompanionError::Expired => AgentWalletError::ApprovalExpired,
            _ => AgentWalletError::ApprovalCommitmentMismatch,
        })?;
        if decision.decision.commitment != *approval
            || self.policy_epoch != policy_epoch
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || !self.matches_binding(binding)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn signed_submission_view(
        &self,
        binding: &AgentL2Binding,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.validate()?;
        if self.status != AgentFastPayStatus::Signed
            || self
                .approval_decision
                .as_ref()
                .map(|signed| signed.decision.decision)
                != Some(ApprovalDecision::Approve)
            || self.owner_authority_commitment.is_none()
            || self.policy_epoch != policy_epoch
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || !self.matches_binding(binding)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn post_sign_recovery_view(
        &self,
        binding: &AgentL2Binding,
        agent_authorization_epoch: u64,
        policy_epoch: u64,
        signer_epoch: u64,
        emergency_epoch: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.validate()?;
        if !matches!(
            self.status,
            AgentFastPayStatus::Signed
                | AgentFastPayStatus::Submitted
                | AgentFastPayStatus::AwaitingRecipient
                | AgentFastPayStatus::ExactRetryReady
                | AgentFastPayStatus::RecoveryRequired
        ) || self
            .approval_decision
            .as_ref()
            .map(|signed| signed.decision.decision)
            != Some(ApprovalDecision::Approve)
            || self.owner_authority_commitment.is_none()
            || self.policy_epoch != policy_epoch
            || self.agent_authorization_epoch != agent_authorization_epoch
            || self.signer_epoch != signer_epoch
            || self.emergency_epoch != emergency_epoch
            || !self.matches_binding(binding)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(self.view())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_execution_prepared(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::ExecutionPrepared {
            return Ok(());
        }
        self.require_status(AgentFastPayStatus::Approved)?;
        self.status = AgentFastPayStatus::ExecutionPrepared;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_signed(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::Signed {
            return Ok(());
        }
        self.require_status(AgentFastPayStatus::ExecutionPrepared)?;
        self.status = AgentFastPayStatus::Signed;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_submitted(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::Submitted {
            return Ok(());
        }
        self.require_status(AgentFastPayStatus::Signed)?;
        self.status = AgentFastPayStatus::Submitted;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_reconciled_submitted(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentFastPayStatus::ExactRetryReady)?;
        self.status = AgentFastPayStatus::Submitted;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_reconciled_unsigned_prepared(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentFastPayStatus::RecoveryRequired)?;
        self.status = AgentFastPayStatus::ExecutionPrepared;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_exact_retry_ready(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::ExactRetryReady {
            return Ok(());
        }
        self.require_status(AgentFastPayStatus::RecoveryRequired)?;
        self.status = AgentFastPayStatus::ExactRetryReady;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_reconciled_unsigned_cancelled(&mut self) -> AgentWalletResult<()> {
        self.require_status(AgentFastPayStatus::RecoveryRequired)?;
        self.status = AgentFastPayStatus::Cancelled;
        self.reserved_units = HacUnits::ZERO;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_awaiting_recipient(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::AwaitingRecipient {
            return Ok(());
        }
        if !matches!(
            self.status,
            AgentFastPayStatus::Signed
                | AgentFastPayStatus::Submitted
                | AgentFastPayStatus::RecoveryRequired
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentFastPayStatus::AwaitingRecipient;
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_committed(&mut self, now: u64) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::Committed {
            return Ok(());
        }
        if !matches!(
            self.status,
            AgentFastPayStatus::Signed
                | AgentFastPayStatus::Submitted
                | AgentFastPayStatus::AwaitingRecipient
                | AgentFastPayStatus::ExactRetryReady
                | AgentFastPayStatus::RecoveryRequired
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentFastPayStatus::Committed;
        self.reserved_units = HacUnits::ZERO;
        self.settled_at = Some(now);
        self.validate()
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_recovery_required(&mut self) -> AgentWalletResult<()> {
        if self.status == AgentFastPayStatus::RecoveryRequired {
            return Ok(());
        }
        if !matches!(
            self.status,
            AgentFastPayStatus::ExecutionPrepared
                | AgentFastPayStatus::Signed
                | AgentFastPayStatus::Submitted
                | AgentFastPayStatus::AwaitingRecipient
                | AgentFastPayStatus::ExactRetryReady
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = AgentFastPayStatus::RecoveryRequired;
        self.validate()
    }

    pub(crate) fn cancel_pre_signing(&mut self) -> bool {
        if matches!(
            self.status,
            AgentFastPayStatus::PaymentIntentCreated
                | AgentFastPayStatus::FundsReserved
                | AgentFastPayStatus::ApprovalRequested
                | AgentFastPayStatus::Approved
        ) {
            self.status = AgentFastPayStatus::Cancelled;
            self.reserved_units = HacUnits::ZERO;
            true
        } else {
            false
        }
    }
    pub(crate) fn view(&self) -> AgentFastPayOperationView {
        AgentFastPayOperationView {
            operation_id: self.operation_id.clone(),
            hub_operation_id: self.hub_operation_id.clone(),
            agent_wallet_id: self.agent_wallet_id.clone(),
            agent_id: self.agent_id.clone(),
            agent_authorization_epoch: self.agent_authorization_epoch,
            idempotency_key: self.request.idempotency_key.clone(),
            request_commitment: self.request_commitment.clone(),
            binding_commitment: self.binding_commitment.clone(),
            route_commitment: self.route_commitment.clone(),
            network_mode: self.network_mode.clone(),
            payer: self.payer.clone(),
            recipient: self.request.recipient.clone(),
            amount_units: self.request.amount_units,
            network_fee_units: HacUnits::ZERO,
            wallet_fee_units: HacUnits::ZERO,
            total_debit_units: self.request.amount_units,
            reserved_units: self.reserved_units,
            status: self.status,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: self.approval_commitment.clone(),
            owner_authority_commitment: self.owner_authority_commitment.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            settled_at: self.settled_at,
        }
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    fn require_status(&self, expected: AgentFastPayStatus) -> AgentWalletResult<()> {
        if self.status == expected {
            Ok(())
        } else {
            Err(AgentWalletError::InvalidOperationState)
        }
    }

    fn calculate_route_commitment(&self) -> String {
        digest_fields(
            ROUTE_DOMAIN,
            &[
                self.operation_id.as_str(),
                self.hub_operation_id.as_str(),
                self.hub_idempotency_key.as_str(),
                self.agent_wallet_id.as_str(),
                self.wallet_scope.as_str(),
                self.agent_id.as_str(),
                self.agent_authorization_epoch.to_string().as_str(),
                self.network_mode.as_str(),
                self.payer.as_str(),
                self.hub_url.as_str(),
                self.request.recipient.as_str(),
                self.request.amount_units.get().to_string().as_str(),
                self.hub_identity.as_str(),
                self.channel_id.as_str(),
                self.channel_reuse_version.to_string().as_str(),
                self.channel_open_height.to_string().as_str(),
                self.binding_commitment.as_str(),
                self.policy_epoch.to_string().as_str(),
                self.signer_epoch.to_string().as_str(),
                self.emergency_epoch.to_string().as_str(),
            ],
        )
    }

    fn matches_approval_request(&self, approval: &AgentFastPayApprovalCommitment) -> bool {
        let expected_millimeis = self.request.amount_units.get() / HacUnits::PER_MILLIMEI;
        approval.operation_id == self.operation_id.as_str()
            && approval.hub_operation_id == self.hub_operation_id
            && approval.public_idempotency_key == self.request.idempotency_key
            && approval.hub_idempotency_key == self.hub_idempotency_key
            && approval.agent_wallet_id == self.agent_wallet_id.as_str()
            && approval.wallet_scope == self.wallet_scope.as_str()
            && approval.agent_id == self.agent_id.as_str()
            && approval.request_commitment == self.request_commitment
            && approval.binding_commitment == self.binding_commitment
            && approval.route_commitment == self.route_commitment
            && approval.payer == self.payer
            && approval.payee == self.request.recipient
            && approval.amount_hac == self.request.amount_units.to_decimal()
            && approval.amount_units == self.request.amount_units.get()
            && approval.amount_millimeis == expected_millimeis
            && approval.hub_url == self.hub_url
            && approval.hub_address == self.hub_identity
            && approval.channel_id == self.channel_id
            && approval.channel_reuse_version == self.channel_reuse_version
            && approval.channel_open_height == self.channel_open_height
            && approval.fee_payer == "sender"
            && approval.network_fee_units == 0
            && approval.wallet_fee_units == 0
            && approval.hub_fee_units == 0
            && approval.total_debit_units == self.request.amount_units.get()
            && approval.policy_epoch == self.policy_epoch
            && approval.signer_epoch == self.signer_epoch
            && approval.emergency_epoch == self.emergency_epoch
            && approval.issued_at >= self.created_at
            && approval.expires_at <= self.expires_at
    }

    fn calculate_owner_authority_commitment(
        &self,
        signed: &SignedAgentFastPayApprovalDecision,
    ) -> AgentWalletResult<String> {
        let decision = signed
            .decision
            .canonical_bytes()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let mut digest = Sha256::new();
        digest.update(OWNER_AUTHORITY_DOMAIN);
        for field in [
            decision.as_slice(),
            signed.signature_hex.as_bytes(),
            self.route_commitment.as_bytes(),
            self.agent_authorization_epoch.to_string().as_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        Ok(hex::encode(digest.finalize()))
    }
}

fn decision_matches_status(decision: ApprovalDecision, status: AgentFastPayStatus) -> bool {
    match decision {
        ApprovalDecision::Approve => matches!(
            status,
            AgentFastPayStatus::Approved
                | AgentFastPayStatus::ExecutionPrepared
                | AgentFastPayStatus::Signed
                | AgentFastPayStatus::Submitted
                | AgentFastPayStatus::AwaitingRecipient
                | AgentFastPayStatus::ExactRetryReady
                | AgentFastPayStatus::Committed
                | AgentFastPayStatus::RecoveryRequired
                | AgentFastPayStatus::Cancelled
        ),
        ApprovalDecision::Reject => matches!(
            status,
            AgentFastPayStatus::Rejected | AgentFastPayStatus::Cancelled
        ),
    }
}

#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
fn format_agent_hac(units: u64) -> String {
    const UNITS_PER_HAC: u64 = 1_000_000;
    let whole = units / UNITS_PER_HAC;
    let fraction = units % UNITS_PER_HAC;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{}", format!("{fraction:06}").trim_end_matches('0'))
}

fn validate_text(value: &str, maximum_bytes: usize) -> AgentWalletResult<()> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        Err(AgentWalletError::InvalidPaymentRequest)
    } else {
        Ok(())
    }
}

fn digest_fields(domain: &[u8], fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hacash_wallet_core::account::WalletAccount;
    use hacash_wallet_core::channel::{
        CHANNEL_STATUS_OPENING, ChannelInfo, ChannelPartyBalance, derive_channel_id,
    };

    fn binding() -> (AgentWalletId, AgentId, AgentL2Binding) {
        let wallet_id = AgentWalletId::new();
        let agent_id = AgentId::new();
        let payer = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let reuse = 1;
        let channel = ChannelInfo {
            ret: 0,
            id: derive_channel_id(&payer.address(), &hub.address(), reuse),
            status: CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version: reuse,
            arbitration_lock: 5_000,
            left: ChannelPartyBalance {
                address: payer.address(),
                hacash: "1".into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: hub.address(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        };
        let binding = AgentL2Binding::from_verified_channel(
            wallet_id.clone(),
            "testnet",
            hpay_companion_protocol::AgentFastPayNetworkBinding {
                network_mode: "testnet".to_owned(),
                chain_id: 7,
                genesis_identifier:
                    "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff".to_owned(),
                node_profile_id: "77".repeat(32),
                network_instance_id: "testnet-fast-pay-operation".to_owned(),
                transaction_format_version: 2,
            },
            &payer.address(),
            "https://hub.example",
            &hub.address(),
            &channel,
            105,
            1_000,
        )
        .unwrap();
        (wallet_id, agent_id, binding)
    }

    #[test]
    fn operation_is_exact_zero_fee_and_stable_after_serialization() {
        let (wallet_id, agent_id, binding) = binding();
        let recipient = WalletAccount::create_random().unwrap().address();
        let mut operation = AgentFastPayOperation::new(
            OperationId::new(),
            agent_id,
            wallet_id,
            AgentFastPayRequest {
                idempotency_key: "agent-fast-pay-0001".into(),
                amount_units: HacUnits::new(5_000),
                recipient,
                reason: "approved inference".into(),
                expires_at: 2_000,
            },
            &binding,
            2,
            3,
            4,
            5,
            1_000,
        )
        .unwrap();
        operation.reserve().unwrap();
        let approval = operation
            .request_approval(
                &binding,
                DeviceId::parse("desktop_fast_pay_test").unwrap(),
                1_001,
            )
            .unwrap();
        let view = operation.view();
        assert_eq!(view.network_fee_units, HacUnits::ZERO);
        assert_eq!(view.wallet_fee_units, HacUnits::ZERO);
        assert_eq!(view.total_debit_units, HacUnits::new(5_000));
        assert_eq!(view.reserved_units, HacUnits::new(5_000));
        assert_eq!(view.status, AgentFastPayStatus::ApprovalRequested);
        assert_eq!(
            view.approval_commitment.as_deref(),
            Some(approval.canonical_sha256_hex().unwrap().as_str())
        );
        let encoded = serde_json::to_vec(&operation).unwrap();
        let decoded: AgentFastPayOperation = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, operation);
        decoded.validate().unwrap();

        let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        tampered["route_commitment"] = serde_json::json!("11".repeat(32));
        let tampered: AgentFastPayOperation = serde_json::from_value(tampered).unwrap();
        assert_eq!(tampered.validate(), Err(AgentWalletError::RecoveryRequired));
    }

    #[test]
    fn sub_millimei_and_self_payment_are_refused_before_reservation() {
        let (wallet_id, agent_id, binding) = binding();
        for (amount, recipient) in [
            (
                HacUnits::new(1),
                WalletAccount::create_random().unwrap().address(),
            ),
            (HacUnits::new(1_000), binding.agent_address().to_owned()),
        ] {
            assert!(
                AgentFastPayOperation::new(
                    OperationId::new(),
                    agent_id.clone(),
                    wallet_id.clone(),
                    AgentFastPayRequest {
                        idempotency_key: "agent-fast-pay-0002".into(),
                        amount_units: amount,
                        recipient,
                        reason: "invalid".into(),
                        expires_at: 2_000,
                    },
                    &binding,
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
}
