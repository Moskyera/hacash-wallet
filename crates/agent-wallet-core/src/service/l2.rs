//! Verified, Agent-only Fast Pay channel binding.
//!
//! This module does not send, sign, open, or close a channel. It defines the
//! exact immutable channel incarnation that a later Agent L2 operation must
//! reference. Construction requires node-observed channel data and never
//! accepts a caller assertion as authority.

#[cfg(feature = "agent-wallet-testnet-pilot")]
mod channel_close;
mod channel_setup;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod verification;

use hacash_wallet_core::channel::query_channel;
use hacash_wallet_core::channel::{ChannelInfo, derive_channel_id};
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::settings::validate_service_url;
use hpay_companion_protocol::AgentFastPayNetworkBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use crate::fast_pay_operation::{
    AgentFastPayOperation, AgentFastPayOperationView, AgentFastPayRequest, AgentFastPayStatus,
};
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use crate::policy::AgentPermission;
use crate::types::{AgentWalletId, WalletScope};

use super::AgentWalletManager;
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use super::payment::{
    ensure_agent_request_rate, ensure_operation_capacity, require_agent_spending_network,
    validate_policy_for_payment, wallet_id_from_scope,
};
use super::state::active_reservations;
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use super::state::scoped_idempotency_key;
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
use super::{AgentAuthorization, IdempotencyRecord, OperationRail};

const AGENT_L2_BINDING_SCHEMA: u32 = 1;
const REQUIRED_OPEN_CONFIRMATIONS: u64 = 6;
const MILLIMEI_IN_AGENT_UNITS: u64 = 1_000;
const BINDING_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/L2-BINDING/V1";
const CHANNEL_SETUP_REVIEW_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/L2-CHANNEL-SETUP-REVIEW/V1";
const CHANNEL_CLOSE_REVIEW_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/L2-CHANNEL-CLOSE-REVIEW/V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentChannelSetupPhase {
    Prepared,
    SignatureMayExist,
    Signed,
    Submitted,
    AwaitingConfirmations,
    RecoveryRequired,
    Confirmed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentChannelClosePhase {
    Prepared,
    SignatureMayExist,
    Signed,
    Submitted,
    RecoveryRequired,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentChannelCloseReview {
    pub wallet_id: AgentWalletId,
    pub operation_id: String,
    pub review_commitment: String,
    pub expires_at: u64,
    pub network_mode: String,
    pub hub_url: String,
    pub hub_address: String,
    pub channel_id: String,
    pub channel_reuse_version: u64,
    pub channel_open_height: u64,
    pub bill_auto_number: u64,
    pub original_agent_units: HacUnits,
    pub final_agent_units: HacUnits,
    pub network_fee_units: HacUnits,
    pub wallet_fee_units: HacUnits,
    pub phase: AgentChannelClosePhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentChannelCloseOperation {
    pub(crate) review: AgentChannelCloseReview,
    pub(crate) idempotency_key: String,
    pub(crate) created_at: u64,
    pub(crate) node_url: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) plan: hacash_wallet_core::channel::PreparedCooperativeChannelClose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signed_request: Option<l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transaction_hash: Option<String>,
}

impl AgentChannelCloseOperation {
    pub(crate) fn validate(
        &self,
        wallet_id: &AgentWalletId,
        address: &str,
    ) -> AgentWalletResult<()> {
        let expected_original_agent_units = self
            .plan
            .original_left_millimeis
            .checked_mul(MILLIMEI_IN_AGENT_UNITS)
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let expected_final_agent_units = self
            .plan
            .final_left_millimeis
            .checked_mul(MILLIMEI_IN_AGENT_UNITS)
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if &self.review.wallet_id != wallet_id
            || self.review.operation_id.is_empty()
            || self.review.review_commitment.len() != 64
            || self.review.expires_at <= self.created_at
            || self.review.hub_url.is_empty()
            || self.review.hub_address.is_empty()
            || self.review.hub_address == address
            || self.review.channel_id != self.plan.channel_id
            || self.review.channel_reuse_version != self.plan.reuse_version
            || self.review.channel_open_height != self.plan.open_height
            || self.review.bill_auto_number != self.plan.bill_auto_number
            || self.review.original_agent_units.get() != expected_original_agent_units
            || self.review.final_agent_units.get() != expected_final_agent_units
            || self.review.network_fee_units.to_decimal() != self.plan.network_fee
            || self.review.wallet_fee_units != HacUnits::ZERO
            || self.plan.left_address != address
            || self.plan.right_address != self.review.hub_address
            || self.idempotency_key.is_empty()
            || self.node_url.is_empty()
            || self.plan.unsigned_transaction_hex.is_empty()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.network_binding
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if (self.review.network_mode == "mainnet") != self.network_binding.mainnet
            || self.review.review_commitment != self.recompute_review_commitment()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let coherent = match self.review.phase {
            AgentChannelClosePhase::Prepared | AgentChannelClosePhase::SignatureMayExist => {
                self.signed_request.is_none() && self.transaction_hash.is_none()
            }
            AgentChannelClosePhase::Signed => {
                self.signed_request.is_some() && self.transaction_hash.is_none()
            }
            AgentChannelClosePhase::Submitted | AgentChannelClosePhase::Confirmed => {
                self.signed_request.is_some() && self.transaction_hash.is_some()
            }
            AgentChannelClosePhase::RecoveryRequired => {
                self.transaction_hash.is_none() || self.signed_request.is_some()
            }
        };
        if !coherent
            || self.transaction_hash.as_ref().is_some_and(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(request) = &self.signed_request {
            let expected = l2_fast_pay_hub::l1_channel_close::ExpectedChannelIncarnation {
                channel_id: self.review.channel_id.clone(),
                user_address: address.to_owned(),
                hub_address: self.review.hub_address.clone(),
                reuse_version: self.review.channel_reuse_version,
                open_height: self.review.channel_open_height,
            };
            let intent = l2_fast_pay_hub::l1_channel_close::validate_channel_close(
                request,
                &expected,
                &self.network_binding,
                self.created_at,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
            let expected_fee_zhu = self
                .review
                .network_fee_units
                .get()
                .checked_mul(100)
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let settlement_matches = match (&intent.settlement, self.plan.transfer_millimeis) {
                (
                    l2_fast_pay_hub::l1_channel_close::ChannelCloseSettlement::OriginalDistribution,
                    None,
                ) => true,
                (
                    l2_fast_pay_hub::l1_channel_close::ChannelCloseSettlement::PrincipalTransfer {
                        from_address,
                        to_address,
                        amount_millimeis,
                    },
                    Some(expected_amount),
                ) => {
                    self.plan.transfer_from.as_deref() == Some(from_address)
                        && self.plan.transfer_to.as_deref() == Some(to_address)
                        && *amount_millimeis == expected_amount
                }
                _ => false,
            };
            if request.operation_id != self.review.operation_id
                || request.idempotency_key != self.idempotency_key
                || request.created_unix != self.created_at
                || request.expires_unix != self.review.expires_at
                || intent.network_fee_zhu != expected_fee_zhu
                || !settlement_matches
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        Ok(())
    }

    pub(crate) fn recompute_review_commitment(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(CHANNEL_CLOSE_REVIEW_DOMAIN);
        for field in [
            self.review.wallet_id.as_str(),
            self.review.operation_id.as_str(),
            self.idempotency_key.as_str(),
            self.review.network_mode.as_str(),
            self.node_url.as_str(),
            self.review.hub_url.as_str(),
            self.review.hub_address.as_str(),
            self.review.channel_id.as_str(),
            self.plan.unsigned_transaction_hex.as_str(),
            self.plan.network_fee.as_str(),
            self.network_binding.network_kind.as_str(),
            self.network_binding.block_1_hash.as_str(),
            self.network_binding.node_profile_id.as_str(),
            self.network_binding.network_instance_id.as_str(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        for value in [
            self.review.channel_reuse_version,
            self.review.channel_open_height,
            self.review.bill_auto_number,
            self.review.original_agent_units.get(),
            self.review.final_agent_units.get(),
            self.review.network_fee_units.get(),
            self.review.wallet_fee_units.get(),
            self.created_at,
            self.review.expires_at,
            self.network_binding.chain_id as u64,
            u64::from(self.network_binding.mainnet),
            self.network_binding.transaction_format_version,
        ] {
            digest.update(value.to_be_bytes());
        }
        for field in [
            self.plan.transfer_from.as_deref().unwrap_or(""),
            self.plan.transfer_to.as_deref().unwrap_or(""),
            &self.plan.transfer_millimeis.unwrap_or(0).to_string(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        hex::encode(digest.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentChannelSetupReview {
    pub wallet_id: AgentWalletId,
    pub operation_id: String,
    pub review_commitment: String,
    pub expires_at: u64,
    pub network_mode: String,
    pub hub_url: String,
    pub hub_address: String,
    pub channel_id: String,
    pub channel_reuse_version: u64,
    pub deposit_units: HacUnits,
    pub network_fee_units: HacUnits,
    pub wallet_fee_units: HacUnits,
    pub total_debit_units: HacUnits,
    pub phase: AgentChannelSetupPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentChannelSetupOperation {
    pub(crate) review: AgentChannelSetupReview,
    pub(crate) idempotency_key: String,
    pub(crate) created_at: u64,
    pub(crate) node_url: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) unsigned_transaction_hex: String,
    pub(crate) deposit: String,
    pub(crate) network_fee: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signed_request: Option<l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transaction_hash: Option<String>,
}

impl AgentChannelSetupOperation {
    pub(crate) fn validate(
        &self,
        wallet_id: &AgentWalletId,
        address: &str,
    ) -> AgentWalletResult<()> {
        if &self.review.wallet_id != wallet_id
            || self.review.operation_id.is_empty()
            || self.review.review_commitment.len() != 64
            || self.review.expires_at <= self.created_at
            || self.review.hub_url.is_empty()
            || self.review.hub_address.is_empty()
            || self.review.hub_address == address
            || self.review.channel_id.is_empty()
            || self.review.channel_reuse_version != 1
            || self.review.deposit_units == HacUnits::ZERO
            || self.review.wallet_fee_units != HacUnits::ZERO
            || self.review.total_debit_units
                != self
                    .review
                    .deposit_units
                    .checked_add(self.review.network_fee_units)?
            || self.idempotency_key.is_empty()
            || self.node_url.is_empty()
            || self.unsigned_transaction_hex.is_empty()
            || self.deposit.is_empty()
            || self.network_fee.is_empty()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.network_binding
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if (self.review.network_mode == "mainnet") != self.network_binding.mainnet
            || self.review.review_commitment != self.recompute_review_commitment()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let phase_is_coherent = match self.review.phase {
            AgentChannelSetupPhase::Prepared | AgentChannelSetupPhase::SignatureMayExist => {
                self.signed_request.is_none() && self.transaction_hash.is_none()
            }
            AgentChannelSetupPhase::Signed => {
                self.signed_request.is_some() && self.transaction_hash.is_none()
            }
            AgentChannelSetupPhase::Submitted
            | AgentChannelSetupPhase::AwaitingConfirmations
            | AgentChannelSetupPhase::Confirmed => {
                self.signed_request.is_some() && self.transaction_hash.is_some()
            }
            AgentChannelSetupPhase::RecoveryRequired => {
                self.transaction_hash.is_none() || self.signed_request.is_some()
            }
        };
        if !phase_is_coherent
            || self.transaction_hash.as_ref().is_some_and(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(request) = &self.signed_request {
            let deposit_zhu = l2_fast_pay_hub::amount::parse_amount_mei(&self.deposit)
                .map_err(|_| AgentWalletError::RecoveryRequired)?
                .as_millimeis()
                .checked_mul(l2_fast_pay_hub::readiness::ZHU_PER_MILLIMEI)
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let expected_network_fee_zhu = self
                .review
                .network_fee_units
                .get()
                .checked_mul(100)
                .ok_or(AgentWalletError::RecoveryRequired)?;
            let intent = l2_fast_pay_hub::l1_channel::validate_channel_open(
                request,
                &self.review.hub_address,
                &self.network_binding,
                deposit_zhu,
                self.created_at,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
            if request.operation_id != self.review.operation_id
                || request.idempotency_key != self.idempotency_key
                || request.created_unix != self.created_at
                || request.expires_unix != self.review.expires_at
                || request.channel_id != self.review.channel_id
                || request.expected_reuse_version != self.review.channel_reuse_version
                || intent.user_address != address
                || intent.user_deposit_zhu != deposit_zhu
                || intent.network_fee_zhu != expected_network_fee_zhu
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        Ok(())
    }

    pub(crate) fn recompute_review_commitment(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(CHANNEL_SETUP_REVIEW_DOMAIN);
        for field in [
            self.review.wallet_id.as_str(),
            self.review.operation_id.as_str(),
            self.idempotency_key.as_str(),
            self.review.network_mode.as_str(),
            self.node_url.as_str(),
            self.review.hub_url.as_str(),
            self.review.hub_address.as_str(),
            self.review.channel_id.as_str(),
            self.deposit.as_str(),
            self.network_fee.as_str(),
            self.unsigned_transaction_hex.as_str(),
            self.network_binding.network_kind.as_str(),
            self.network_binding.block_1_hash.as_str(),
            self.network_binding.node_profile_id.as_str(),
            self.network_binding.network_instance_id.as_str(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        for value in [
            self.review.channel_reuse_version,
            self.review.deposit_units.get(),
            self.review.network_fee_units.get(),
            self.review.wallet_fee_units.get(),
            self.review.total_debit_units.get(),
            self.created_at,
            self.review.expires_at,
            self.network_binding.chain_id as u64,
            u64::from(self.network_binding.mainnet),
            self.network_binding.transaction_format_version,
        ] {
            digest.update(value.to_be_bytes());
        }
        hex::encode(digest.finalize())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentL2Binding {
    schema_version: u32,
    wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    network_mode: String,
    network_binding: AgentFastPayNetworkBinding,
    agent_address: String,
    hub_url: String,
    hub_address: String,
    channel_id: String,
    channel_reuse_version: u64,
    channel_open_height: u64,
    confirmed_at_height: u64,
    deposit_units: HacUnits,
    bound_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    closed: Option<AgentL2ClosedProof>,
    commitment_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AgentL2ClosedProof {
    transaction_hash: String,
    close_height: u64,
    closed_at: u64,
}

impl AgentL2Binding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_channel(
        wallet_id: AgentWalletId,
        network_mode: &str,
        network_binding: AgentFastPayNetworkBinding,
        agent_address: &str,
        hub_url: &str,
        expected_hub_address: &str,
        channel: &ChannelInfo,
        observed_height: u64,
        bound_at: u64,
    ) -> AgentWalletResult<Self> {
        network_binding
            .validate_shape()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if !matches!(network_mode, "mainnet" | "testnet")
            || network_binding.network_mode != network_mode
            || channel.ret != 0
            || !channel.is_open()
            || channel.open_height == 0
            || channel.close_height != 0
            || channel.reuse_version == 0
            || channel.arbitration_lock == 0
            || channel.challenging.is_some()
            || channel.left.address != agent_address
            || channel.right.address != expected_hub_address
            || channel.left.satoshi != 0
            || channel.right.satoshi != 0
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        hacash_wallet_core::require_address_for_network(agent_address, network_mode)
            .map_err(|_| AgentWalletError::InvalidWalletScope)?;
        hacash_wallet_core::require_address_for_network(expected_hub_address, network_mode)
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let hub_url = validate_service_url(hub_url, "Agent Fast Pay hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let channel_id = channel.id.to_ascii_lowercase();
        if channel.id != channel_id
            || channel_id.len() != 32
            || !channel_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || derive_channel_id(agent_address, expected_hub_address, channel.reuse_version)
                != channel_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let finality_height = channel
            .open_height
            .checked_add(REQUIRED_OPEN_CONFIRMATIONS - 1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        if observed_height < finality_height {
            return Err(AgentWalletError::SigningBlocked);
        }
        let deposit_units = HacUnits::from_decimal(&channel.left.hacash)?;
        let hub_deposit = HacUnits::from_decimal(&channel.right.hacash)?;
        if deposit_units == HacUnits::ZERO
            || hub_deposit != HacUnits::ZERO
            || !deposit_units.get().is_multiple_of(MILLIMEI_IN_AGENT_UNITS)
        {
            return Err(AgentWalletError::InvalidAmount);
        }
        let wallet_scope = WalletScope::for_agent_wallet(&wallet_id);
        let mut binding = Self {
            schema_version: AGENT_L2_BINDING_SCHEMA,
            wallet_id,
            wallet_scope,
            network_mode: network_mode.to_owned(),
            network_binding,
            agent_address: agent_address.to_owned(),
            hub_url,
            hub_address: expected_hub_address.to_owned(),
            channel_id,
            channel_reuse_version: channel.reuse_version,
            channel_open_height: channel.open_height,
            confirmed_at_height: observed_height,
            deposit_units,
            bound_at,
            closed: None,
            commitment_sha256: String::new(),
        };
        binding.commitment_sha256 = binding.calculate_commitment();
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> AgentWalletResult<()> {
        if self.schema_version != AGENT_L2_BINDING_SCHEMA
            || self.wallet_scope != WalletScope::for_agent_wallet(&self.wallet_id)
            || !matches!(self.network_mode.as_str(), "mainnet" | "testnet")
            || self.network_binding.network_mode != self.network_mode
            || self.network_binding.validate_shape().is_err()
            || self.channel_id.len() != 32
            || self.channel_id != self.channel_id.to_ascii_lowercase()
            || !self.channel_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.channel_reuse_version == 0
            || self.channel_open_height == 0
            || self.confirmed_at_height
                < self
                    .channel_open_height
                    .checked_add(REQUIRED_OPEN_CONFIRMATIONS - 1)
                    .ok_or(AgentWalletError::IntegerOverflow)?
            || self.deposit_units == HacUnits::ZERO
            || !self
                .deposit_units
                .get()
                .is_multiple_of(MILLIMEI_IN_AGENT_UNITS)
            || derive_channel_id(
                &self.agent_address,
                &self.hub_address,
                self.channel_reuse_version,
            ) != self.channel_id
            || validate_service_url(&self.hub_url, "Agent Fast Pay hub").is_err()
            || self.commitment_sha256 != self.calculate_commitment()
            || self.closed.as_ref().is_some_and(|proof| {
                proof.close_height == 0
                    || proof.closed_at < self.bound_at
                    || proof.transaction_hash.len() != 64
                    || !proof
                        .transaction_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        hacash_wallet_core::require_address_for_network(&self.agent_address, &self.network_mode)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        hacash_wallet_core::require_address_for_network(&self.hub_address, &self.network_mode)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        Ok(())
    }

    fn calculate_commitment(&self) -> String {
        let fields = [
            self.wallet_id.as_str(),
            self.wallet_scope.as_str(),
            self.network_mode.as_str(),
            self.network_binding.network_mode.as_str(),
            &self.network_binding.chain_id.to_string(),
            self.network_binding.genesis_identifier.as_str(),
            self.network_binding.node_profile_id.as_str(),
            self.network_binding.network_instance_id.as_str(),
            &self.network_binding.transaction_format_version.to_string(),
            self.agent_address.as_str(),
            self.hub_url.as_str(),
            self.hub_address.as_str(),
            self.channel_id.as_str(),
            &self.channel_reuse_version.to_string(),
            &self.channel_open_height.to_string(),
            &self.confirmed_at_height.to_string(),
            &self.deposit_units.get().to_string(),
            &self.bound_at.to_string(),
        ];
        let mut digest = Sha256::new();
        digest.update(BINDING_DOMAIN);
        for field in fields {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        hex::encode(digest.finalize())
    }

    pub fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }
    pub fn wallet_scope(&self) -> &WalletScope {
        &self.wallet_scope
    }
    pub fn network_mode(&self) -> &str {
        &self.network_mode
    }
    pub fn network_binding(&self) -> &AgentFastPayNetworkBinding {
        &self.network_binding
    }
    pub fn agent_address(&self) -> &str {
        &self.agent_address
    }
    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }
    pub fn hub_address(&self) -> &str {
        &self.hub_address
    }
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
    pub fn channel_reuse_version(&self) -> u64 {
        self.channel_reuse_version
    }
    pub fn channel_open_height(&self) -> u64 {
        self.channel_open_height
    }
    pub fn confirmed_at_height(&self) -> u64 {
        self.confirmed_at_height
    }
    pub fn deposit_units(&self) -> HacUnits {
        self.deposit_units
    }
    pub fn commitment_sha256(&self) -> &str {
        &self.commitment_sha256
    }
    pub fn is_active(&self) -> bool {
        self.closed.is_none()
    }
    pub fn close_transaction_hash(&self) -> Option<&str> {
        self.closed
            .as_ref()
            .map(|proof| proof.transaction_hash.as_str())
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn mark_closed(
        &mut self,
        transaction_hash: String,
        close_height: u64,
        closed_at: u64,
    ) -> AgentWalletResult<()> {
        if !self.is_active()
            || close_height <= self.channel_open_height
            || closed_at < self.bound_at
            || transaction_hash.len() != 64
            || !transaction_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.closed = Some(AgentL2ClosedProof {
            transaction_hash,
            close_height,
            closed_at,
        });
        self.validate()
    }

    fn same_channel_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.wallet_id == other.wallet_id
            && self.wallet_scope == other.wallet_scope
            && self.network_mode == other.network_mode
            && self.network_binding == other.network_binding
            && self.agent_address == other.agent_address
            && self.hub_url == other.hub_url
            && self.hub_address == other.hub_address
            && self.channel_id == other.channel_id
            && self.channel_reuse_version == other.channel_reuse_version
            && self.channel_open_height == other.channel_open_height
            && self.deposit_units == other.deposit_units
    }
}

impl AgentWalletManager {
    /// Create and durably reserve an Agent Fast Pay intent for owner review.
    ///
    /// This method performs no Hub request, signature, settlement or L1
    /// fallback. Mainnet remains blocked by the Agent spending gate. The
    /// stable Hub UUID and idempotency key become durable here, before a later
    /// L2 journal or network call can observe them.
    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(super) fn request_fast_pay_intent(
        &mut self,
        authorization: &AgentAuthorization,
        request: AgentFastPayRequest,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        let agent = super::validate_authorization(&state, authorization)?.clone();
        if authorization.capability() != AgentPermission::CreatePaymentIntent {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        let agent_id = authorization.agent_id();
        require_agent_spending_network(&state.network_mode, state.trusted_mainnet_fast_pay_pilot)?;
        request.validate(&state.network_mode, now)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        self.compact_aged_terminal_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let safety = self
            .emergency_controller(&wallet_id)?
            .issue_safety_permit(state.payments_suspended)?;
        let binding = state
            .l2_binding
            .clone()
            .ok_or(AgentWalletError::SigningBlocked)?;
        if !binding.is_active() {
            return Err(AgentWalletError::SigningBlocked);
        }
        if state.l2_channel_close.is_some() {
            return Err(AgentWalletError::RecoveryRequired);
        }
        safety.checkpoint(state.payments_suspended)?;

        let scoped_key = scoped_idempotency_key(agent_id, &request.idempotency_key);
        let request_commitment = request.commitment_hex();
        if let Some(existing) = state.idempotency.get(&scoped_key) {
            if existing.rail != OperationRail::FastPay
                || existing.request_commitment != request_commitment
            {
                return Err(AgentWalletError::IdempotencyConflict);
            }
            return state
                .fast_pay_operations
                .get(existing.operation_id.as_str())
                .map(AgentFastPayOperation::view)
                .ok_or(AgentWalletError::RecoveryRequired);
        }

        if state.operations.values().any(|operation| {
            operation.agent_id() == agent_id
                && operation.view().idempotency_key == request.idempotency_key
        }) {
            return Err(AgentWalletError::IdempotencyConflict);
        }
        if let Some(existing) = state.fast_pay_operations.values().find(|operation| {
            operation.agent_id() == agent_id
                && operation.idempotency_key() == request.idempotency_key
        }) {
            let view = existing.view();
            return if view.request_commitment == request_commitment {
                Ok(view)
            } else {
                Err(AgentWalletError::IdempotencyConflict)
            };
        }

        ensure_operation_capacity(&state)?;
        ensure_agent_request_rate(&state, agent_id, now)?;
        validate_policy_for_payment(
            &state,
            &agent,
            &request.recipient,
            request.amount_units,
            now,
        )?;
        let channel_exposure =
            state
                .fast_pay_operations
                .values()
                .try_fold(HacUnits::ZERO, |total, operation| {
                    let view = operation.view();
                    if view.binding_commitment != binding.commitment_sha256() {
                        return Err(AgentWalletError::RecoveryRequired);
                    }
                    if operation.status() == AgentFastPayStatus::Committed
                        || operation.status().retains_reservation()
                    {
                        total.checked_add(view.total_debit_units)
                    } else {
                        Ok(total)
                    }
                })?;
        if channel_exposure.checked_add(request.amount_units)? > binding.deposit_units() {
            return Err(AgentWalletError::InsufficientAgentBalance);
        }

        let mut operation = AgentFastPayOperation::new(
            crate::types::OperationId::new(),
            agent_id.clone(),
            wallet_id.clone(),
            request,
            &binding,
            agent.authorization_epoch,
            state.policy_epoch,
            state.signer_epoch,
            state.emergency_epoch,
            now,
        )?;
        operation.reserve()?;
        let desktop_device_id =
            hpay_companion_protocol::DeviceId::parse(state.primary_signing_device_id.clone())
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
        operation.request_approval(&binding, desktop_device_id, now)?;
        let view = operation.view();
        state.idempotency.insert(
            scoped_key,
            IdempotencyRecord {
                rail: OperationRail::FastPay,
                request_commitment,
                operation_id: view.operation_id.clone(),
            },
        );
        state
            .fast_pay_operations
            .insert(view.operation_id.as_str().to_owned(), operation);
        safety.checkpoint(state.payments_suspended)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            crate::journal::AgentJournalEventKind::ApprovalRequested,
            Some(view.operation_id.as_str().as_bytes()),
            Some(agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(view)
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(super) fn fast_pay_operation_for_verified(
        &mut self,
        authorization: &AgentAuthorization,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        self.fast_pay_state_for_permission(
            authorization,
            AgentPermission::ReadOwnOperationStatus,
            now,
        )?
        .fast_pay_operations
        .get(operation_id.as_str())
        .filter(|operation| operation.agent_id() == authorization.agent_id())
        .map(AgentFastPayOperation::view)
        .ok_or(AgentWalletError::OperationNotFound)
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(super) fn list_fast_pay_operations_for_agent(
        &mut self,
        authorization: &AgentAuthorization,
        now: u64,
    ) -> AgentWalletResult<Vec<crate::types::OperationId>> {
        let state = self.fast_pay_state_for_permission(
            authorization,
            AgentPermission::ListOwnOperations,
            now,
        )?;
        Ok(state
            .fast_pay_operations
            .values()
            .filter(|operation| operation.agent_id() == authorization.agent_id())
            .map(|operation| operation.operation_id().clone())
            .collect())
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(super) fn cancel_fast_pay_own_unsigned(
        &mut self,
        authorization: &AgentAuthorization,
        operation_id: &crate::types::OperationId,
        now: u64,
    ) -> AgentWalletResult<AgentFastPayOperationView> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        super::validate_authorization(&state, authorization)?;
        if authorization.capability() != AgentPermission::CancelOwnUnsignedOperation {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let operation = state
            .fast_pay_operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        if operation.agent_id() != authorization.agent_id() {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        if operation.status() == AgentFastPayStatus::Cancelled {
            return Ok(operation.view());
        }
        if !operation.cancel_pre_signing() {
            return Err(AgentWalletError::InvalidOperationState);
        }
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            crate::journal::AgentJournalEventKind::PaymentFailed,
            Some(operation_id.as_str().as_bytes()),
            Some(authorization.agent_id().as_str().as_bytes()),
            now,
        )?;
        Ok(state
            .fast_pay_operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?
            .view())
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    fn fast_pay_state_for_permission(
        &mut self,
        authorization: &AgentAuthorization,
        permission: AgentPermission,
        now: u64,
    ) -> AgentWalletResult<super::AgentWalletState> {
        let wallet_id = wallet_id_from_scope(authorization.wallet_scope())?;
        self.ensure_session_active(&wallet_id, now)?;
        let session = self.session(&wallet_id)?;
        let mut state =
            self.load_verified_state(&wallet_id, &session.state_master, &session.journal_key)?;
        super::validate_authorization(&state, authorization)?;
        if authorization.capability() != permission {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        Ok(state)
    }

    /// Verify and durably bind one already-open Agent-only channel.
    ///
    /// This is a trusted owner operation. It deliberately performs no send,
    /// signature, channel open/close, or mainnet enable transition.
    pub async fn verify_and_bind_l2_channel(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        channel_id: &str,
        now: u64,
    ) -> AgentWalletResult<AgentL2Binding> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if !state.payments_suspended
            || active_reservations(&state)? != HacUnits::ZERO
            || state
                .operations
                .values()
                .any(|operation| !operation.status().is_terminal())
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let hub_url = validate_service_url(hub_url, "Agent Fast Pay hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let hub = L2HubClient::new_for_wallet_policy(
            hub_url.clone(),
            &state.network_mode,
            state.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub
            .health()
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !hub_fee_is_zero(&health)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hub_address = health
            .hub_address
            .as_deref()
            .filter(|address| !address.is_empty())
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        if state.network_mode == "mainnet" {
            hub.require_mainnet_payment_ready(None)
                .await
                .map_err(|_| AgentWalletError::SigningBlocked)?;
        }
        let node_probe = crate::node_binding::probe_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await;
        if node_probe.status != crate::node_binding::AgentNodeStatus::Verified {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        let node_snapshot = node_probe
            .snapshot
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        let network_binding = AgentFastPayNetworkBinding {
            network_mode: state.network_mode.clone(),
            chain_id: node_snapshot.chain_id,
            genesis_identifier: node_snapshot.block_one_fingerprint,
            node_profile_id: node_snapshot.node_profile_commitment,
            network_instance_id: node_snapshot.network_instance_id,
            transaction_format_version: node_snapshot.transaction_format_version,
        };
        network_binding
            .validate_shape()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let node = NodeClient::new(&state.node_url).map_err(|_| AgentWalletError::NodeRejected)?;
        let channel = query_channel(&node, channel_id)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let binding = AgentL2Binding::from_verified_channel(
            wallet_id.clone(),
            &state.network_mode,
            network_binding,
            &state.address,
            &hub_url,
            hub_address,
            &channel,
            node_snapshot.current_height,
            now,
        )?;
        hub.require_channel_binding_ready(hub_address, &binding.deposit_units().to_decimal())
            .await
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if let Some(existing) = state.l2_binding.as_ref() {
            if existing.same_channel_identity(&binding) {
                return Ok(existing.clone());
            }
            return Err(AgentWalletError::RecoveryRequired);
        }
        state.l2_binding = Some(binding.clone());
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            crate::journal::AgentJournalEventKind::L2BindingVerified,
            None,
            None,
            now,
        )?;
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::operation::AgentPaymentRequest;
    use crate::types::AgentId;
    use crate::{AgentPolicy, ApprovalMode, CreateAgentWallet};
    use hacash_wallet_core::account::WalletAccount;
    use hacash_wallet_core::channel::{CHANNEL_STATUS_OPENING, ChannelPartyBalance};
    use hpay_agent_connector::{
        AgentIdentityKey, Capability, PAIRING_COMPLETION_TTL_SECS, PairingBearer, PairingRequest,
        PairingSession,
    };

    const TESTNET_ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
    const PASSPHRASE: &str = "agent fast pay integration passphrase";

    fn test_network_binding(network_mode: &str) -> AgentFastPayNetworkBinding {
        AgentFastPayNetworkBinding {
            network_mode: network_mode.to_owned(),
            chain_id: if network_mode == "mainnet" { 0 } else { 7 },
            genesis_identifier: TESTNET_ANCHOR.to_owned(),
            node_profile_id: "77".repeat(32),
            network_instance_id: format!("{network_mode}-test-instance"),
            transaction_format_version: 2,
        }
    }

    fn verified_channel(
        agent: &WalletAccount,
        hub: &WalletAccount,
        open_height: u64,
    ) -> ChannelInfo {
        let reuse_version = 1;
        ChannelInfo {
            ret: 0,
            id: derive_channel_id(&agent.address(), &hub.address(), reuse_version),
            status: CHANNEL_STATUS_OPENING,
            open_height,
            close_height: 0,
            reuse_version,
            arbitration_lock: 5_000,
            left: ChannelPartyBalance {
                address: agent.address(),
                hacash: "1".into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: hub.address(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        }
    }

    fn prepared_channel_setup(
        wallet_id: AgentWalletId,
        agent_address: &str,
        hub_address: &str,
    ) -> AgentChannelSetupOperation {
        let block_one_hash = "11".repeat(32);
        let network_kind = "local_pilot_v1";
        let node_profile_id = "hpay-local-pilot-v1";
        let chain_id = 7;
        let transaction_format_version = 2;
        let network_binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: network_kind.into(),
            chain_id,
            mainnet: false,
            block_1_hash: block_one_hash.clone(),
            node_profile_id: node_profile_id.into(),
            network_instance_id: l2_fast_pay_hub::l1_channel::canonical_network_instance_id(
                network_kind,
                chain_id,
                false,
                &block_one_hash,
                node_profile_id,
                transaction_format_version,
            ),
            transaction_format_version,
        };
        let mut operation = AgentChannelSetupOperation {
            review: AgentChannelSetupReview {
                wallet_id: wallet_id.clone(),
                operation_id: "channel-setup-operation".into(),
                review_commitment: String::new(),
                expires_at: 1_300,
                network_mode: "testnet".into(),
                hub_url: "http://127.0.0.1:8790".into(),
                hub_address: hub_address.into(),
                channel_id: derive_channel_id(agent_address, hub_address, 1),
                channel_reuse_version: 1,
                deposit_units: HacUnits::new(1_000_000),
                network_fee_units: HacUnits::new(1_000),
                wallet_fee_units: HacUnits::ZERO,
                total_debit_units: HacUnits::new(1_001_000),
                phase: AgentChannelSetupPhase::Prepared,
            },
            idempotency_key: "hpay:agent-channel-open:test".into(),
            created_at: 1_000,
            node_url: "http://127.0.0.1:8197".into(),
            network_binding,
            unsigned_transaction_hex: "00".into(),
            deposit: "1".into(),
            network_fee: "0.001".into(),
            signed_request: None,
            transaction_hash: None,
        };
        operation.review.review_commitment = operation.recompute_review_commitment();
        operation
    }

    fn manager_with_binding_and_agent(
        now: u64,
    ) -> (
        tempfile::TempDir,
        AgentWalletManager,
        AgentWalletId,
        AgentId,
        String,
    ) {
        let root = tempfile::tempdir().unwrap();
        let mut manager = AgentWalletManager::open(root.path()).unwrap();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: PASSPHRASE.into(),
                    network_mode: "testnet".into(),
                    node_url: "http://127.0.0.1:18081".into(),
                    block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
                    mainnet_pilot_acknowledgement: None,
                },
                now,
            )
            .unwrap();
        manager.unlock(&created.wallet_id, PASSPHRASE, now).unwrap();

        let recipient = WalletAccount::create_random().unwrap().address();
        let capabilities = BTreeSet::from([
            Capability::CreatePaymentIntent,
            Capability::ReadOwnOperationStatus,
            Capability::ListOwnOperations,
            Capability::CancelOwnUnsignedOperation,
        ]);
        let (desktop_id, server_key) = manager
            .connector_server_identity(&created.wallet_id, now)
            .unwrap();
        let pinned = server_key.pinned_identity(desktop_id).unwrap();
        let agent_key = AgentIdentityKey::generate();
        let mut pairing =
            PairingSession::activate(created.wallet_id.clone(), pinned, now, 60, 2).unwrap();
        let pairing_id = pairing.pairing_id().to_owned();
        let pending = pairing
            .submit(
                now,
                PairingRequest {
                    pairing_id: PairingBearer::parse(pairing_id.clone()).unwrap(),
                    agent_name: "Fast Pay Test Agent".into(),
                    agent_version: "1.0.0".into(),
                    identity_public_key_sec1_hex: agent_key.public_key_sec1_hex(),
                    requested_capabilities: capabilities.clone(),
                },
            )
            .unwrap();
        let paired = pairing
            .approve(now, &pending.submission_commitment, capabilities.clone())
            .unwrap();
        let agent_id = paired.agent_id.clone();
        manager
            .commit_paired_agent(
                paired,
                AgentPolicy {
                    permissions: capabilities,
                    max_per_payment_units: HacUnits::new(20_000),
                    max_daily_units: HacUnits::new(10_000),
                    max_pending_operations: 2,
                    allowed_recipients: BTreeSet::from([recipient.clone()]),
                    blocked_recipients: BTreeSet::new(),
                    allow_unlisted_recipient_with_approval: false,
                    approval_mode: ApprovalMode::DesktopManual,
                    policy_epoch: 1,
                },
                &pairing_id,
                pending.submission_commitment,
                now + PAIRING_COMPLETION_TTL_SECS,
                now,
            )
            .unwrap();

        let hub = WalletAccount::create_random().unwrap();
        let reuse_version = 1;
        let channel = ChannelInfo {
            ret: 0,
            id: derive_channel_id(&created.address, &hub.address(), reuse_version),
            status: CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version,
            arbitration_lock: 5_000,
            left: ChannelPartyBalance {
                address: created.address.clone(),
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
            created.wallet_id.clone(),
            "testnet",
            test_network_binding("testnet"),
            &created.address,
            "https://hub.example",
            &hub.address(),
            &channel,
            105,
            now,
        )
        .unwrap();
        let session = manager.session(&created.wallet_id).unwrap();
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = manager
            .load_verified_state(&created.wallet_id, &state_master, &journal_key)
            .unwrap();
        state.l2_binding = Some(binding);
        state.updated_at = now;
        manager
            .persist_event(
                &mut state,
                &state_master,
                &journal_key,
                crate::journal::AgentJournalEventKind::L2BindingVerified,
                None,
                None,
                now,
            )
            .unwrap();
        manager
            .enable_agent_payments_locally(&created.wallet_id, now + 1)
            .unwrap();
        (root, manager, created.wallet_id, agent_id, recipient)
    }

    fn authorization_for(
        manager: &AgentWalletManager,
        wallet_id: &AgentWalletId,
        agent_id: &AgentId,
        capability: AgentPermission,
    ) -> AgentAuthorization {
        let session = manager.session(wallet_id).unwrap();
        let state = manager
            .load_verified_state(wallet_id, &session.state_master, &session.journal_key)
            .unwrap();
        let agent = state.agents.get(agent_id.as_str()).unwrap();
        AgentAuthorization {
            wallet_id: wallet_id.clone(),
            wallet_scope: WalletScope::for_agent_wallet(wallet_id),
            agent_id: agent_id.clone(),
            authorization_epoch: agent.authorization_epoch,
            identity_key_sha256: agent.identity_key_sha256.clone(),
            capability,
        }
    }

    #[test]
    fn binding_requires_exact_agent_channel_and_six_confirmations() {
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let channel = verified_channel(&agent, &hub, 100);
        assert!(
            AgentL2Binding::from_verified_channel(
                wallet_id.clone(),
                "mainnet",
                test_network_binding("mainnet"),
                &agent.address(),
                "https://hub.example",
                &hub.address(),
                &channel,
                104,
                1_000,
            )
            .is_err()
        );
        let binding = AgentL2Binding::from_verified_channel(
            wallet_id.clone(),
            "mainnet",
            test_network_binding("mainnet"),
            &agent.address(),
            "https://hub.example",
            &hub.address(),
            &channel,
            105,
            1_000,
        )
        .unwrap();
        assert_eq!(
            binding.wallet_scope(),
            &WalletScope::for_agent_wallet(&wallet_id)
        );
        assert_eq!(binding.deposit_units(), HacUnits::new(1_000_000));
        assert_eq!(binding.commitment_sha256().len(), 64);
        binding.validate().unwrap();
    }

    #[test]
    fn channel_setup_phase_and_durable_evidence_cannot_disagree() {
        let wallet_id = AgentWalletId::new();
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let operation = prepared_channel_setup(wallet_id.clone(), &agent.address(), &hub.address());
        operation.validate(&wallet_id, &agent.address()).unwrap();

        for phase in [
            AgentChannelSetupPhase::Signed,
            AgentChannelSetupPhase::Submitted,
            AgentChannelSetupPhase::AwaitingConfirmations,
            AgentChannelSetupPhase::Confirmed,
        ] {
            let mut tampered = operation.clone();
            tampered.review.phase = phase;
            assert_eq!(
                tampered.validate(&wallet_id, &agent.address()),
                Err(AgentWalletError::RecoveryRequired)
            );
        }

        let mut hash_without_signature = operation.clone();
        hash_without_signature.transaction_hash = Some("22".repeat(32));
        assert_eq!(
            hash_without_signature.validate(&wallet_id, &agent.address()),
            Err(AgentWalletError::RecoveryRequired)
        );

        let mut noncanonical_hash = operation;
        noncanonical_hash.review.phase = AgentChannelSetupPhase::AwaitingConfirmations;
        noncanonical_hash.transaction_hash = Some("AA".repeat(32));
        assert_eq!(
            noncanonical_hash.validate(&wallet_id, &agent.address()),
            Err(AgentWalletError::RecoveryRequired)
        );
    }

    #[test]
    fn closed_proof_preserves_binding_identity_and_blocks_active_use() {
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let channel = verified_channel(&agent, &hub, 100);
        let mut binding = AgentL2Binding::from_verified_channel(
            wallet_id,
            "testnet",
            test_network_binding("testnet"),
            &agent.address(),
            "https://hub.example",
            &hub.address(),
            &channel,
            105,
            1_000,
        )
        .unwrap();
        let identity_commitment = binding.commitment_sha256().to_owned();
        binding.mark_closed("22".repeat(32), 120, 1_100).unwrap();
        assert!(!binding.is_active());
        assert_eq!(
            binding.close_transaction_hash(),
            Some("22".repeat(32).as_str())
        );
        assert_eq!(binding.commitment_sha256(), identity_commitment);
        binding.validate().unwrap();

        let mut value = serde_json::to_value(binding).unwrap();
        value["closed"]["transaction_hash"] = serde_json::json!("AA".repeat(32));
        let tampered: AgentL2Binding = serde_json::from_value(value).unwrap();
        assert_eq!(tampered.validate(), Err(AgentWalletError::RecoveryRequired));
    }

    #[test]
    fn binding_rejects_wrong_topology_hub_funds_satoshi_and_sub_millimei() {
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let other = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let baseline = verified_channel(&agent, &hub, 100);
        let mut cases = Vec::new();
        let mut wrong_topology = baseline.clone();
        wrong_topology.left.address = other.address();
        cases.push(wrong_topology);
        let mut hub_funded = baseline.clone();
        hub_funded.right.hacash = "0.001".into();
        cases.push(hub_funded);
        let mut satoshi = baseline.clone();
        satoshi.left.satoshi = 1;
        cases.push(satoshi);
        let mut sub_millimei = baseline;
        sub_millimei.left.hacash = "0.000001".into();
        cases.push(sub_millimei);
        for channel in cases {
            assert!(
                AgentL2Binding::from_verified_channel(
                    wallet_id.clone(),
                    "mainnet",
                    test_network_binding("mainnet"),
                    &agent.address(),
                    "https://hub.example",
                    &hub.address(),
                    &channel,
                    105,
                    1_000,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn serialized_binding_tampering_fails_closed() {
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let binding = AgentL2Binding::from_verified_channel(
            AgentWalletId::new(),
            "mainnet",
            test_network_binding("mainnet"),
            &agent.address(),
            "https://hub.example",
            &hub.address(),
            &verified_channel(&agent, &hub, 100),
            105,
            1_000,
        )
        .unwrap();
        assert_eq!(binding.network_binding().node_profile_id.len(), 64);
        assert_ne!(
            binding.network_binding().node_profile_id,
            hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID
        );
        let mut value = serde_json::to_value(&binding).unwrap();
        value["confirmed_at_height"] = serde_json::json!(104);
        let changed: AgentL2Binding = serde_json::from_value(value).unwrap();
        assert_eq!(changed.validate(), Err(AgentWalletError::RecoveryRequired));

        let mut value = serde_json::to_value(&binding).unwrap();
        value["network_binding"]["node_profile_id"] = serde_json::json!("88".repeat(32));
        let changed: AgentL2Binding = serde_json::from_value(value).unwrap();
        assert_eq!(changed.validate(), Err(AgentWalletError::RecoveryRequired));

        let mut value = serde_json::to_value(&binding).unwrap();
        value.as_object_mut().unwrap().remove("network_binding");
        assert!(
            serde_json::from_value::<AgentL2Binding>(value).is_err(),
            "a binding without a cryptographically committed node identity must fail closed"
        );
    }

    #[test]
    fn request_is_durable_idempotent_zero_fee_and_pause_cancels_reservation() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (_root, mut manager, wallet_id, agent_id, recipient) =
            manager_with_binding_and_agent(now);
        let authorization = authorization_for(
            &manager,
            &wallet_id,
            &agent_id,
            AgentPermission::CreatePaymentIntent,
        );
        let request = AgentFastPayRequest {
            idempotency_key: "fast-pay-preview-0001".into(),
            amount_units: HacUnits::new(6_000),
            recipient,
            reason: "bounded compute request".into(),
            expires_at: now + 600,
        };
        let first = manager
            .request_fast_pay_intent(&authorization, request.clone(), now + 2)
            .unwrap();
        let replay = manager
            .request_fast_pay_intent(&authorization, request, now + 3)
            .unwrap();
        assert_eq!(first.operation_id, replay.operation_id);
        assert_eq!(first.hub_operation_id, replay.hub_operation_id);
        assert_eq!(first.network_fee_units, HacUnits::ZERO);
        assert_eq!(first.wallet_fee_units, HacUnits::ZERO);
        assert_eq!(first.total_debit_units, first.amount_units);
        assert_eq!(first.status, AgentFastPayStatus::ApprovalRequested);
        let status_authorization = authorization_for(
            &manager,
            &wallet_id,
            &agent_id,
            AgentPermission::ReadOwnOperationStatus,
        );
        assert_eq!(
            manager
                .fast_pay_operation_for_verified(
                    &status_authorization,
                    &first.operation_id,
                    now + 3,
                )
                .unwrap()
                .status,
            AgentFastPayStatus::ApprovalRequested
        );
        let list_authorization = authorization_for(
            &manager,
            &wallet_id,
            &agent_id,
            AgentPermission::ListOwnOperations,
        );
        assert_eq!(
            manager
                .list_fast_pay_operations_for_agent(&list_authorization, now + 3)
                .unwrap(),
            vec![first.operation_id.clone()]
        );
        assert_eq!(
            manager
                .list_fast_pay_operations_admin(&wallet_id, now + 3)
                .unwrap(),
            vec![first.clone()]
        );
        let cancel_authorization = authorization_for(
            &manager,
            &wallet_id,
            &agent_id,
            AgentPermission::CancelOwnUnsignedOperation,
        );
        assert_eq!(
            manager
                .cancel_fast_pay_own_unsigned(&cancel_authorization, &first.operation_id, now + 3,)
                .unwrap()
                .status,
            AgentFastPayStatus::Cancelled
        );
        manager
            .disable_all_agent_payments(&wallet_id, now + 4)
            .unwrap();
        let session = manager.session(&wallet_id).unwrap();
        let state = manager
            .load_verified_state(&wallet_id, &session.state_master, &session.journal_key)
            .unwrap();
        let stored = state
            .fast_pay_operations
            .get(first.operation_id.as_str())
            .unwrap()
            .view();
        assert_eq!(stored.status, AgentFastPayStatus::Cancelled);
        assert_eq!(stored.reserved_units, HacUnits::ZERO);
        assert_eq!(
            manager.request_fast_pay_intent(
                &authorization,
                AgentFastPayRequest {
                    idempotency_key: "fast-pay-after-pause".into(),
                    amount_units: HacUnits::new(1_000),
                    recipient: stored.recipient,
                    reason: "must remain paused".into(),
                    expires_at: now + 700,
                },
                now + 5,
            ),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
    }

    #[test]
    fn fast_pay_and_l1_share_policy_budget_and_idempotency_boundaries() {
        let now = 20_000;
        let (_root, mut manager, wallet_id, agent_id, recipient) =
            manager_with_binding_and_agent(now);
        let authorization = authorization_for(
            &manager,
            &wallet_id,
            &agent_id,
            AgentPermission::CreatePaymentIntent,
        );
        manager
            .request_fast_pay_intent(
                &authorization,
                AgentFastPayRequest {
                    idempotency_key: "daily-fast-pay-0001".into(),
                    amount_units: HacUnits::new(6_000),
                    recipient: recipient.clone(),
                    reason: "first reservation".into(),
                    expires_at: now + 600,
                },
                now + 2,
            )
            .unwrap();
        let session = manager.session(&wallet_id).unwrap();
        let state = manager
            .load_verified_state(&wallet_id, &session.state_master, &session.journal_key)
            .unwrap();
        let agent = state.agents.get(agent_id.as_str()).unwrap();
        let l1_after_l2 = AgentPaymentRequest {
            idempotency_key: "l1-after-fast-pay".into(),
            asset: "HAC".into(),
            amount_units: HacUnits::new(5_000),
            recipient: recipient.clone(),
            reason: "must share the Fast Pay daily exposure".into(),
            expires_at: now + 600,
        };
        assert_eq!(
            super::super::payment::validate_policy_for_request(
                &state,
                agent,
                &l1_after_l2,
                HacUnits::new(6_000),
                now + 3,
            ),
            Err(AgentWalletError::DailyLimitExceeded)
        );
        let fast_pay_record = state
            .idempotency
            .get(&scoped_idempotency_key(&agent_id, "daily-fast-pay-0001"))
            .unwrap();
        assert_eq!(fast_pay_record.rail, super::super::OperationRail::FastPay);
        assert_eq!(
            manager.request_fast_pay_intent(
                &authorization,
                AgentFastPayRequest {
                    idempotency_key: "daily-fast-pay-0002".into(),
                    amount_units: HacUnits::new(5_000),
                    recipient: recipient.clone(),
                    reason: "would exceed shared daily policy".into(),
                    expires_at: now + 600,
                },
                now + 3,
            ),
            Err(AgentWalletError::DailyLimitExceeded)
        );

        let session = manager.session(&wallet_id).unwrap();
        let state_master = *session.state_master;
        let journal_key = *session.journal_key;
        let mut state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        let l1_request = AgentPaymentRequest {
            idempotency_key: "cross-rail-key".into(),
            asset: "HAC".into(),
            amount_units: HacUnits::new(1_000),
            recipient: recipient.clone(),
            reason: "existing L1 intent".into(),
            expires_at: now + 600,
        };
        let request_commitment = l1_request.commitment_hex().unwrap();
        let l1_operation = crate::operation::AgentOperation::new(
            crate::OperationId::new(),
            agent_id.clone(),
            wallet_id.clone(),
            l1_request,
            now + 3,
        )
        .unwrap();
        let l1_operation_id = l1_operation.operation_id().clone();
        state
            .operations
            .insert(l1_operation_id.as_str().to_owned(), l1_operation);
        state.idempotency.insert(
            scoped_idempotency_key(&agent_id, "cross-rail-key"),
            super::super::IdempotencyRecord {
                rail: super::super::OperationRail::L1,
                request_commitment,
                operation_id: l1_operation_id,
            },
        );
        state.updated_at = now + 3;
        manager
            .persist_event(
                &mut state,
                &state_master,
                &journal_key,
                crate::journal::AgentJournalEventKind::PaymentRequested,
                None,
                Some(agent_id.as_str().as_bytes()),
                now + 3,
            )
            .unwrap();
        assert_eq!(
            manager.request_fast_pay_intent(
                &authorization,
                AgentFastPayRequest {
                    idempotency_key: "cross-rail-key".into(),
                    amount_units: HacUnits::new(1_000),
                    recipient: recipient.clone(),
                    reason: "must not alias the L1 intent".into(),
                    expires_at: now + 600,
                },
                now + 4,
            ),
            Err(AgentWalletError::IdempotencyConflict)
        );
        assert_eq!(
            manager.request_fast_pay_intent(
                &authorization,
                AgentFastPayRequest {
                    idempotency_key: "daily-fast-pay-0001".into(),
                    amount_units: HacUnits::new(7_000),
                    recipient,
                    reason: "changed replay".into(),
                    expires_at: now + 600,
                },
                now + 5,
            ),
            Err(AgentWalletError::IdempotencyConflict)
        );
    }
}
