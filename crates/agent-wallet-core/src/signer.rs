//! Agent-only signing boundary. The unlocked session retains the blockchain
//! secret only as zeroizing bytes and constructs the upstream account for the
//! final signature call. This minimizes post-drop remnants, but it cannot
//! protect an unlocked process from an attacker who can read live memory.

use std::fmt;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use field::{Serialize as FieldSerialize, Sign};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l1_channel_close_safety::ChannelCloseJournalKeyProvider;
use hacash_wallet_core::l1_channel_safety::ChannelOpenJournalKeyProvider;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_safety::RestrictedSenderAuthority;
use hacash_wallet_core::l2_signer::FastPayJournalKeyProvider;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_signer::{FastPayBillSigner, FastPaySigningAuthorization};
use hacash_wallet_core::tx_binding::verify_hac_transfers;
use hacash_wallet_core::{WalletError, WalletResult};
use protocol::transaction;
use sha2::Digest;
use sys::ToHex;
use zeroize::{Zeroize, Zeroizing};

use crate::amount::HacUnits;
use crate::emergency::AgentSafetyPermit;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::operation::{ApprovedUnsignedTransaction, SignedAgentTransaction};
use crate::types::{AgentWalletId, WalletScope};

pub(crate) struct AgentChannelOpenSigningRequest {
    pub(crate) wallet_scope: WalletScope,
    pub(crate) network_mode: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) hub_address: String,
    pub(crate) channel_id: String,
    pub(crate) reuse_version: u64,
    pub(crate) left_deposit: String,
    pub(crate) right_deposit: String,
    pub(crate) network_fee: String,
    pub(crate) unsigned_transaction_hex: String,
    pub(crate) operation_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) created_unix: u64,
    pub(crate) expires_unix: u64,
}

#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
pub(crate) struct AgentChannelCloseSigningRequest {
    pub(crate) wallet_scope: WalletScope,
    pub(crate) network_mode: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) hub_address: String,
    pub(crate) plan: hacash_wallet_core::channel::PreparedCooperativeChannelClose,
    pub(crate) operation_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) created_unix: u64,
    pub(crate) expires_unix: u64,
}

pub(crate) struct AgentTransactionSigner {
    wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    address: String,
    network_mode: String,
    signer_epoch: u64,
    unlock_expires_at: u64,
    // The unlock session retains only zeroizing Agent-owned bytes. A
    // WalletAccount is constructed at the final signing boundary and dropped
    // immediately after fill_sign; pinned sys::Account clears its SecretKey
    // in Drop.
    secret_key: Zeroizing<[u8; 32]>,
}

pub(crate) struct SignedAgentEnvelope {
    pub(crate) transaction: SignedAgentTransaction,
    pub(crate) tx_hash: String,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentFastPaySignerBinding {
    pub(crate) hub_operation_id: String,
    pub(crate) hub_idempotency_key: String,
    pub(crate) wallet_scope: WalletScope,
    pub(crate) hub_identity: String,
    pub(crate) channel_id: String,
    pub(crate) channel_reuse_version: u64,
    pub(crate) network_mode: String,
    pub(crate) payer: String,
    pub(crate) payee: String,
    pub(crate) amount: String,
    pub(crate) amount_units: u64,
    pub(crate) restricted_sender_authority: RestrictedSenderAuthority,
    pub(crate) approval_expires_at: u64,
    pub(crate) signer_epoch: u64,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) struct RestrictedAgentFastPaySigner<'a> {
    signer: &'a AgentTransactionSigner,
    binding: AgentFastPaySignerBinding,
    safety_permit: &'a AgentSafetyPermit,
}

/// Complete, immutable owner authority for one exact Agent HVM payment.
///
/// This is deliberately wider than the HVM bill itself. The bill signature is
/// cryptographically bound to the channel, balances and serial, while this
/// outer authorization additionally binds the Agent identity/epochs, the live
/// node identity, the exact Hub origin and the zero-fee product policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentHvmPaymentSignerBinding {
    pub(crate) wallet_scope: WalletScope,
    pub(crate) agent_id: String,
    pub(crate) agent_authorization_epoch: u64,
    pub(crate) policy_epoch: u64,
    pub(crate) signer_epoch: u64,
    pub(crate) emergency_epoch: u64,
    pub(crate) approval_commitment: String,
    pub(crate) approval_decision_commitment: String,
    pub(crate) owner_authority_commitment: String,
    pub(crate) approval_expires_at: u64,
    pub(crate) network_mode: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) hub_url: String,
    pub(crate) hub_address: String,
    pub(crate) hvm_binding: l2_fast_pay_hub::hvm_channel::HvmChannelBindingV1,
    pub(crate) operation_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) payer: String,
    pub(crate) recipient: String,
    pub(crate) amount_zhu: u64,
    pub(crate) fee_payer: String,
    pub(crate) network_fee_zhu: u64,
    pub(crate) wallet_fee_zhu: u64,
    pub(crate) hub_fee_zhu: u64,
    pub(crate) total_debit_zhu: u64,
    pub(crate) previous_bill_commitment: String,
    pub(crate) unsigned_request_commitment: String,
}

/// Complete owner authority for one exact shared-registry V2 payment.
/// Kept distinct from V1 so an approval or signature can never downgrade
/// between settlement profiles through a generic enum/default branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentHvmRegistryPaymentSignerBinding {
    pub(crate) wallet_scope: WalletScope,
    pub(crate) agent_id: String,
    pub(crate) agent_authorization_epoch: u64,
    pub(crate) policy_epoch: u64,
    pub(crate) signer_epoch: u64,
    pub(crate) emergency_epoch: u64,
    pub(crate) approval_commitment: String,
    pub(crate) approval_decision_commitment: String,
    pub(crate) owner_authority_commitment: String,
    pub(crate) approval_expires_at: u64,
    pub(crate) network_mode: String,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    pub(crate) hub_url: String,
    pub(crate) hub_address: String,
    pub(crate) hvm_binding: l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2,
    pub(crate) operation_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) payer: String,
    pub(crate) recipient: String,
    pub(crate) amount_zhu: u64,
    pub(crate) fee_payer: String,
    pub(crate) network_fee_zhu: u64,
    pub(crate) wallet_fee_zhu: u64,
    pub(crate) hub_fee_zhu: u64,
    pub(crate) total_debit_zhu: u64,
    pub(crate) previous_bill_commitment: String,
    pub(crate) unsigned_request_commitment: String,
}

#[derive(serde::Serialize)]
struct AgentHvmOwnerAuthorityCommitment<'a> {
    schema: &'static str,
    wallet_scope: &'a WalletScope,
    agent_id: &'a str,
    agent_authorization_epoch: u64,
    policy_epoch: u64,
    signer_epoch: u64,
    emergency_epoch: u64,
    approval_commitment: &'a str,
    approval_decision_commitment: &'a str,
    approval_expires_at: u64,
    network_mode: &'a str,
    network_binding: &'a l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    hub_url: &'a str,
    hub_address: &'a str,
    hvm_binding: &'a l2_fast_pay_hub::hvm_channel::HvmChannelBindingV1,
    operation_id: &'a str,
    idempotency_key: &'a str,
    payer: &'a str,
    recipient: &'a str,
    amount_zhu: u64,
    fee_payer: &'a str,
    network_fee_zhu: u64,
    wallet_fee_zhu: u64,
    hub_fee_zhu: u64,
    total_debit_zhu: u64,
    previous_bill_commitment: &'a str,
    unsigned_request_commitment: &'a str,
}

impl AgentHvmPaymentSignerBinding {
    pub(crate) fn calculate_owner_authority_commitment(&self) -> AgentWalletResult<String> {
        let payload = AgentHvmOwnerAuthorityCommitment {
            schema: "hpay-agent-hvm-owner-authority/1",
            wallet_scope: &self.wallet_scope,
            agent_id: &self.agent_id,
            agent_authorization_epoch: self.agent_authorization_epoch,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: &self.approval_commitment,
            approval_decision_commitment: &self.approval_decision_commitment,
            approval_expires_at: self.approval_expires_at,
            network_mode: &self.network_mode,
            network_binding: &self.network_binding,
            hub_url: &self.hub_url,
            hub_address: &self.hub_address,
            hvm_binding: &self.hvm_binding,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            payer: &self.payer,
            recipient: &self.recipient,
            amount_zhu: self.amount_zhu,
            fee_payer: &self.fee_payer,
            network_fee_zhu: self.network_fee_zhu,
            wallet_fee_zhu: self.wallet_fee_zhu,
            hub_fee_zhu: self.hub_fee_zhu,
            total_debit_zhu: self.total_debit_zhu,
            previous_bill_commitment: &self.previous_bill_commitment,
            unsigned_request_commitment: &self.unsigned_request_commitment,
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        Ok(hex::encode(sha2::Sha256::digest(bytes)))
    }
}

#[derive(serde::Serialize)]
struct AgentHvmRegistryOwnerAuthorityCommitment<'a> {
    schema: &'static str,
    wallet_scope: &'a WalletScope,
    agent_id: &'a str,
    agent_authorization_epoch: u64,
    policy_epoch: u64,
    signer_epoch: u64,
    emergency_epoch: u64,
    approval_commitment: &'a str,
    approval_decision_commitment: &'a str,
    approval_expires_at: u64,
    network_mode: &'a str,
    network_binding: &'a l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    hub_url: &'a str,
    hub_address: &'a str,
    hvm_registry_binding: &'a l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2,
    operation_id: &'a str,
    idempotency_key: &'a str,
    payer: &'a str,
    recipient: &'a str,
    amount_zhu: u64,
    fee_payer: &'a str,
    network_fee_zhu: u64,
    wallet_fee_zhu: u64,
    hub_fee_zhu: u64,
    total_debit_zhu: u64,
    previous_bill_commitment: &'a str,
    unsigned_request_commitment: &'a str,
}

impl AgentHvmRegistryPaymentSignerBinding {
    pub(crate) fn calculate_owner_authority_commitment(&self) -> AgentWalletResult<String> {
        let payload = AgentHvmRegistryOwnerAuthorityCommitment {
            schema: "hpay-agent-hvm-registry-owner-authority/2",
            wallet_scope: &self.wallet_scope,
            agent_id: &self.agent_id,
            agent_authorization_epoch: self.agent_authorization_epoch,
            policy_epoch: self.policy_epoch,
            signer_epoch: self.signer_epoch,
            emergency_epoch: self.emergency_epoch,
            approval_commitment: &self.approval_commitment,
            approval_decision_commitment: &self.approval_decision_commitment,
            approval_expires_at: self.approval_expires_at,
            network_mode: &self.network_mode,
            network_binding: &self.network_binding,
            hub_url: &self.hub_url,
            hub_address: &self.hub_address,
            hvm_registry_binding: &self.hvm_binding,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            payer: &self.payer,
            recipient: &self.recipient,
            amount_zhu: self.amount_zhu,
            fee_payer: &self.fee_payer,
            network_fee_zhu: self.network_fee_zhu,
            wallet_fee_zhu: self.wallet_fee_zhu,
            hub_fee_zhu: self.hub_fee_zhu,
            total_debit_zhu: self.total_debit_zhu,
            previous_bill_commitment: &self.previous_bill_commitment,
            unsigned_request_commitment: &self.unsigned_request_commitment,
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        Ok(hex::encode(sha2::Sha256::digest(bytes)))
    }
}

impl AgentTransactionSigner {
    /// Attach the Agent's left signature to one exact, already-approved HVM
    /// payment request. No network call or Hub submission occurs here.
    ///
    /// The caller must perform live node/Hub/channel/lease checks immediately
    /// before entering this synchronous boundary and durably persist the exact
    /// returned signature before any submission attempt.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[allow(
        dead_code,
        reason = "staged for the authenticated Agent HVM operation integration gate"
    )]
    pub(crate) fn sign_exact_hvm_payment(
        &self,
        authority: &AgentHvmPaymentSignerBinding,
        previous: &l2_fast_pay_hub::hvm_channel::HvmChannelBillV1,
        mut request: l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1> {
        safety_permit.checkpoint(false)?;
        authority
            .network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        authority
            .hvm_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let canonical_hub_url = hacash_wallet_core::settings::validate_service_url(
            &authority.hub_url,
            "Agent HVM Fast Pay hub",
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        let previous_commitment = previous
            .commitment()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let unsigned_request_commitment = request
            .commitment()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if authority.wallet_scope != self.wallet_scope
            || authority.network_mode != self.network_mode
            || authority.network_binding.mainnet != (self.network_mode == "mainnet")
            || authority.network_binding.chain_id != authority.hvm_binding.chain_id
            || authority.network_binding.network_instance_id
                != authority.hvm_binding.network_instance_id
            || authority.hvm_binding.network_mode != self.network_mode
            || authority.hvm_binding.left_address != self.address
            || authority.hvm_binding.right_hub_address != authority.hub_address
            || canonical_hub_url != authority.hub_url
            || authority.network_mode == "mainnet" && !authority.hub_url.starts_with("https://")
            || authority.agent_id.trim().is_empty()
            || authority.agent_authorization_epoch == 0
            || authority.policy_epoch == 0
            || authority.signer_epoch != self.signer_epoch
            || authority.emergency_epoch == 0
            || !is_lower_hex_32(&authority.approval_commitment)
            || !is_lower_hex_32(&authority.approval_decision_commitment)
            || !is_lower_hex_32(&authority.owner_authority_commitment)
            || authority.owner_authority_commitment
                != authority.calculate_owner_authority_commitment()?
            || authority.approval_expires_at <= now
            || now >= self.unlock_expires_at
            || authority.operation_id.trim().is_empty()
            || authority.idempotency_key.trim().is_empty()
            || authority.payer != self.address
            || authority.payer != authority.hvm_binding.left_address
            || authority.recipient.trim().is_empty()
            || authority.payer == authority.recipient
            || authority.amount_zhu == 0
            || authority.fee_payer != "sender"
            || authority.network_fee_zhu != 0
            || authority.wallet_fee_zhu != 0
            || authority.hub_fee_zhu != 0
            || authority.total_debit_zhu != authority.amount_zhu
            || authority.previous_bill_commitment != previous_commitment
            || authority.unsigned_request_commitment != unsigned_request_commitment
            || request.operation_id != authority.operation_id
            || request.idempotency_key != authority.idempotency_key
            || request.payer != authority.payer
            || request.recipient != authority.recipient
            || request.amount_zhu != authority.amount_zhu
            || request.hub_fee_zhu != 0
            || request.expires_unix != authority.approval_expires_at
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        request
            .validate_unsigned_against(&authority.hvm_binding, previous, now)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;

        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let hash = request
            .proposed_bill
            .signing_hash(&authority.hvm_binding)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        request.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(account.inner(), &hash).serialize());
        request
            .validate_against(&authority.hvm_binding, previous, now)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        safety_permit.checkpoint(false)?;
        Ok(request)
    }

    /// Attach the Agent's left signature to one exact, owner-approved shared
    /// HVM registry V2 bill. This synchronous boundary performs no network I/O
    /// and returns only the exact signed request for durable persistence.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn sign_exact_hvm_registry_payment(
        &self,
        authority: &AgentHvmRegistryPaymentSignerBinding,
        previous: &l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2,
        mut request: l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2> {
        safety_permit.checkpoint(false)?;
        authority
            .network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        authority
            .hvm_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let canonical_hub_url = hacash_wallet_core::settings::validate_service_url(
            &authority.hub_url,
            "Agent HVM registry hub",
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        let previous_commitment = previous
            .commitment()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let unsigned_request_commitment = request
            .commitment()
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if authority.wallet_scope != self.wallet_scope
            || authority.network_mode != self.network_mode
            || authority.network_binding.mainnet != (self.network_mode == "mainnet")
            || authority.network_binding.chain_id != authority.hvm_binding.chain_id
            || authority.network_binding.network_instance_id
                != authority.hvm_binding.network_instance_id
            || authority.hvm_binding.network_mode != self.network_mode
            || authority.hvm_binding.left_address != self.address
            || authority.hvm_binding.right_hub_address != authority.hub_address
            || authority.recipient != authority.hub_address
            || canonical_hub_url != authority.hub_url
            || authority.network_mode == "mainnet" && !authority.hub_url.starts_with("https://")
            || authority.agent_id.trim().is_empty()
            || authority.agent_authorization_epoch == 0
            || authority.policy_epoch == 0
            || authority.signer_epoch != self.signer_epoch
            || authority.emergency_epoch == 0
            || !is_lower_hex_32(&authority.approval_commitment)
            || !is_lower_hex_32(&authority.approval_decision_commitment)
            || !is_lower_hex_32(&authority.owner_authority_commitment)
            || authority.owner_authority_commitment
                != authority.calculate_owner_authority_commitment()?
            || authority.approval_expires_at <= now
            || now >= self.unlock_expires_at
            || authority.operation_id.trim().is_empty()
            || authority.idempotency_key.trim().is_empty()
            || authority.payer != self.address
            || authority.payer != authority.hvm_binding.left_address
            || authority.recipient.trim().is_empty()
            || authority.payer == authority.recipient
            || authority.amount_zhu == 0
            || authority.fee_payer != "sender"
            || authority.network_fee_zhu != 0
            || authority.wallet_fee_zhu != 0
            || authority.hub_fee_zhu != 0
            || authority.total_debit_zhu != authority.amount_zhu
            || authority.previous_bill_commitment != previous_commitment
            || authority.unsigned_request_commitment != unsigned_request_commitment
            || request.operation_id != authority.operation_id
            || request.idempotency_key != authority.idempotency_key
            || request.payer != authority.payer
            || request.recipient != authority.recipient
            || request.amount_zhu != authority.amount_zhu
            || request.network_fee_zhu != 0
            || request.network_binding != authority.network_binding
            || request.wallet_fee_zhu != 0
            || request.hub_fee_zhu != 0
            || request.total_debit_zhu != request.amount_zhu
            || request.expires_unix != authority.approval_expires_at
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        request
            .validate_unsigned_against(&authority.hvm_binding, previous, now)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;

        safety_permit.checkpoint(false)?;
        // Refresh time after all preceding checks and immediately before the
        // restricted Agent secret is accessed. A request that expired while
        // readiness/approval work was in progress never reaches key use.
        let key_use_now = current_unix().max(now);
        if authority.approval_expires_at <= key_use_now || key_use_now >= self.unlock_expires_at {
            return Err(AgentWalletError::ApprovalExpired);
        }
        request
            .validate_unsigned_against(&authority.hvm_binding, previous, key_use_now)
            .map_err(|_| AgentWalletError::ApprovalExpired)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let hash = request
            .proposed_bill
            .signing_hash(&authority.hvm_binding)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        request.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(account.inner(), &hash).serialize());
        let payer_authorization_hash = request
            .payer_authorization_hash(&authority.hvm_binding, previous)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        request.payer_authorization_signature_hex =
            hex::encode(Sign::create_by(account.inner(), &payer_authorization_hash).serialize());
        request
            .validate_against(&authority.hvm_binding, previous, key_use_now)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        safety_permit.checkpoint(false)?;
        Ok(request)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn restrict_fast_pay<'a>(
        &'a self,
        binding: AgentFastPaySignerBinding,
        safety_permit: &'a AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<RestrictedAgentFastPaySigner<'a>> {
        safety_permit.checkpoint(false)?;
        if binding.wallet_scope != self.wallet_scope
            || binding.network_mode != self.network_mode
            || binding.payer != self.address
            || binding.signer_epoch != self.signer_epoch
            || binding.approval_expires_at <= now
            || now >= self.unlock_expires_at
            || binding.hub_operation_id.is_empty()
            || binding.hub_idempotency_key.is_empty()
            || binding.hub_identity.is_empty()
            || binding.channel_id.is_empty()
            || binding.channel_reuse_version == 0
            || binding.payer == binding.payee
            || binding.amount_units == 0
            || binding
                .restricted_sender_authority
                .owner_authority_commitment
                .len()
                != 64
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        Ok(RestrictedAgentFastPaySigner {
            signer: self,
            binding,
            safety_permit,
        })
    }

    pub(crate) fn new(
        wallet_id: AgentWalletId,
        address: String,
        network_mode: String,
        signer_epoch: u64,
        secret_hex: &str,
        unlocked_at: u64,
    ) -> AgentWalletResult<Self> {
        if signer_epoch == 0 || !matches!(network_mode.as_str(), "mainnet" | "testnet") {
            return Err(AgentWalletError::SigningBlocked);
        }
        if secret_hex.len() != 64 {
            return Err(AgentWalletError::Vault);
        }
        let decoded = Zeroizing::new(hex::decode(secret_hex).map_err(|_| AgentWalletError::Vault)?);
        if decoded.len() != 32 {
            return Err(AgentWalletError::Vault);
        }
        let mut secret_key = Zeroizing::new([0_u8; 32]);
        secret_key.copy_from_slice(decoded.as_slice());
        {
            let encoded = Zeroizing::new(hex::encode(secret_key.as_slice()));
            let account =
                WalletAccount::from_secret_hex(&encoded).map_err(|_| AgentWalletError::Vault)?;
            if account.address() != address {
                return Err(AgentWalletError::InvalidWalletScope);
            }
        }
        let wallet_scope = WalletScope::for_agent_wallet(&wallet_id);
        let unlock_expires_at = unlocked_at
            .checked_add(15 * 60)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        Ok(Self {
            wallet_id,
            wallet_scope,
            address,
            network_mode,
            signer_epoch,
            unlock_expires_at,
            secret_key,
        })
    }

    pub(crate) fn sign(
        &self,
        approved: ApprovedUnsignedTransaction,
        expected_wallet_scope: &WalletScope,
        expected_signer_epoch: u64,
        now: u64,
    ) -> AgentWalletResult<SignedAgentEnvelope> {
        if expected_wallet_scope != &self.wallet_scope
            || approved.agent_wallet_id() != &self.wallet_id
            || expected_signer_epoch != self.signer_epoch
            || approved.expires_at() == 0
            || now >= self.unlock_expires_at
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if approved.asset() != "HAC" {
            return Err(AgentWalletError::UnsupportedAsset);
        }
        if approved.approval_commitment_sha256().len() != 64
            || approved.amount_units() == HacUnits::ZERO
            || approved.network_fee_units() != HacUnits::MIN_NETWORK_FEE
            || approved.wallet_fee_units() != HacUnits::ZERO
            || approved
                .amount_units()
                .checked_add(approved.network_fee_units())?
                != approved.total_debit_units()
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        // Door two of two, at the signing boundary itself, because a check
        // placed only where an intent is created is a check an operation
        // restored from a durable record walks straight past.
        hacash_wallet_core::require_agent_payment_recipient(
            approved.recipient(),
            &self.network_mode,
        )
        .map_err(|_| AgentWalletError::RecipientNotAllowed)?;

        let amount = approved.amount_units().to_decimal();
        let network_fee = approved.network_fee_units().to_decimal();
        let transfers = [(approved.recipient(), amount.as_str())];
        let canonical = verify_hac_transfers(
            approved.unsigned_tx_hex(),
            &self.address,
            &network_fee,
            &transfers,
        )
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if canonical.tx_type != 2
            || canonical.main_address != self.address
            || !canonical
                .required_signers
                .iter()
                .any(|signer| signer == &self.address)
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        approved.revalidate_transaction_commitment()?;

        let body = hex::decode(approved.unsigned_tx_hex())
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        let (mut transaction, consumed) =
            transaction::transaction_create(&body).map_err(|_| AgentWalletError::SigningBlocked)?;
        if consumed != body.len() || transaction.ty() != 2 {
            return Err(AgentWalletError::SigningBlocked);
        }
        // Create the upstream account only for the actual signature call.
        // Both the temporary encoding and pinned sys::Account secret are
        // erased by their respective Drop implementations on every exit path.
        {
            let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
            let account = WalletAccount::from_secret_hex(&encoded)
                .map_err(|_| AgentWalletError::SigningBlocked)?;
            if account.address() != self.address {
                return Err(AgentWalletError::SigningBlocked);
            }
            transaction
                .fill_sign(account.inner())
                .map_err(|_| AgentWalletError::SigningBlocked)?;
        }
        let tx_hash = transaction.hash().to_hex();
        if tx_hash.is_empty() {
            return Err(AgentWalletError::SigningBlocked);
        }
        let signed_hex = transaction.serialize().to_hex();
        let transaction = approved.into_signed(signed_hex)?;
        Ok(SignedAgentEnvelope {
            transaction,
            tx_hash,
        })
    }

    pub(crate) fn wallet_scope(&self) -> &WalletScope {
        &self.wallet_scope
    }

    pub(crate) fn sign_exact_channel_open(
        &self,
        request: AgentChannelOpenSigningRequest,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest> {
        safety_permit.checkpoint(false)?;
        request
            .network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if request.wallet_scope != self.wallet_scope
            || request.network_mode != self.network_mode
            || request.network_binding.mainnet != (self.network_mode == "mainnet")
            || request.hub_address == self.address
            || request.hub_address.is_empty()
            || request.channel_id.is_empty()
            || request.reuse_version != 1
            || request.operation_id.is_empty()
            || request.idempotency_key.is_empty()
            || request.created_unix == 0
            || request.expires_unix <= request.created_unix
            || now >= request.expires_unix
            || now >= self.unlock_expires_at
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let right_deposit = l2_fast_pay_hub::amount::parse_amount_mei(&request.right_deposit)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if right_deposit.as_millimeis() != 0 {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let encoded_channel_id =
            hacash_wallet_core::channel::encoded_channel_id(&request.channel_id)
                .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let canonical = hacash_wallet_core::tx_binding::verify_transaction_intent(
            &request.unsigned_transaction_hex,
            &self.address,
            &request.network_fee,
            &[
                serde_json::json!({
                    "kind": 0x0411,
                    "chains": [request.network_binding.chain_id]
                }),
                serde_json::json!({
                    "kind": 2,
                    "channel_id": encoded_channel_id,
                    "left_bill": {
                        "address": self.address,
                        "amount": request.left_deposit,
                    },
                    "right_bill": {
                        "address": request.hub_address,
                        "amount": request.right_deposit,
                    }
                }),
            ],
        )
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if canonical.tx_type != 2
            || canonical.main_address != self.address
            || canonical.actions.len() != 2
            || canonical.actions[0].kind != 0x0411
            || canonical.actions[1].kind != 2
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let raw = hex::decode(&request.unsigned_transaction_hex)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let (mut transaction, consumed) = transaction::transaction_create(&raw)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if consumed != raw.len() || transaction.ty() != 2 {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        transaction
            .fill_sign(account.inner())
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        let partial_transaction_hex = transaction.serialize().to_hex();
        hacash_wallet_core::l1_channel_flow::verify_partial_channel_signature(
            &partial_transaction_hex,
            &self.address,
            2,
            request.network_binding.chain_id,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        let mut signed_request = l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest {
            schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.into(),
            network: request.network_binding.network_kind,
            chain_id: request.network_binding.chain_id,
            mainnet: request.network_binding.mainnet,
            block_1_hash: request.network_binding.block_1_hash,
            node_profile_id: request.network_binding.node_profile_id,
            network_instance_id: request.network_binding.network_instance_id,
            transaction_format_version: request.network_binding.transaction_format_version,
            operation_id: request.operation_id,
            idempotency_key: request.idempotency_key,
            created_unix: request.created_unix,
            expires_unix: request.expires_unix,
            hub_address: request.hub_address,
            channel_id: request.channel_id,
            expected_reuse_version: request.reuse_version,
            partial_transaction_commitment: l2_fast_pay_hub::l1_channel::transaction_commitment(
                &partial_transaction_hex,
            )
            .map_err(|_| AgentWalletError::SigningBlocked)?,
            partial_transaction_hex,
            authorization_public_key_hex: hex::encode(
                account.inner().public_key().serialize_compressed(),
            ),
            authorization_signature_hex: String::new(),
        };
        let commitment: [u8; 32] = hex::decode(
            l2_fast_pay_hub::l1_channel::request_commitment(&signed_request)
                .map_err(|_| AgentWalletError::SigningBlocked)?,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?
        .try_into()
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        signed_request.authorization_signature_hex =
            hex::encode(account.inner().do_sign(&commitment));
        safety_permit.checkpoint(false)?;
        Ok(signed_request)
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn sign_exact_channel_close(
        &self,
        request: AgentChannelCloseSigningRequest,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest> {
        safety_permit.checkpoint(false)?;
        request
            .network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if request.wallet_scope != self.wallet_scope
            || request.network_mode != self.network_mode
            || request.network_binding.mainnet != (self.network_mode == "mainnet")
            || request.hub_address.is_empty()
            || request.hub_address == self.address
            || request.plan.channel_id.is_empty()
            || request.plan.reuse_version == 0
            || request.plan.open_height == 0
            || request.plan.left_address != self.address
            || request.plan.right_address != request.hub_address
            || request.operation_id.is_empty()
            || request.idempotency_key.is_empty()
            || request.created_unix == 0
            || request.expires_unix <= request.created_unix
            || now >= request.expires_unix
            || now >= self.unlock_expires_at
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let actions = request
            .plan
            .exact_actions(request.network_binding.chain_id)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let canonical = hacash_wallet_core::tx_binding::verify_transaction_intent(
            &request.plan.unsigned_transaction_hex,
            &self.address,
            &request.plan.network_fee,
            &actions,
        )
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if canonical.tx_type != 2
            || canonical.main_address != self.address
            || canonical.actions.len() != actions.len()
            || canonical.actions[0].kind != 0x0411
            || canonical.actions[1].kind != 3
            || canonical
                .actions
                .get(2)
                .is_some_and(|action| action.kind != 14)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let raw = hex::decode(&request.plan.unsigned_transaction_hex)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let (mut transaction, consumed) = transaction::transaction_create(&raw)
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if consumed != raw.len() || transaction.ty() != 2 {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        transaction
            .fill_sign(account.inner())
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        let partial_transaction_hex = transaction.serialize().to_hex();
        hacash_wallet_core::l1_channel_flow::verify_partial_channel_signature(
            &partial_transaction_hex,
            &self.address,
            3,
            request.network_binding.chain_id,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        let mut signed_request = l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest {
            schema: l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA.into(),
            network: request.network_binding.network_kind,
            chain_id: request.network_binding.chain_id,
            mainnet: request.network_binding.mainnet,
            block_1_hash: request.network_binding.block_1_hash,
            node_profile_id: request.network_binding.node_profile_id,
            network_instance_id: request.network_binding.network_instance_id,
            transaction_format_version: request.network_binding.transaction_format_version,
            operation_id: request.operation_id,
            idempotency_key: request.idempotency_key,
            created_unix: request.created_unix,
            expires_unix: request.expires_unix,
            hub_address: request.hub_address,
            user_address: self.address.clone(),
            channel_id: request.plan.channel_id,
            reuse_version: request.plan.reuse_version,
            open_height: request.plan.open_height,
            partial_transaction_commitment: l2_fast_pay_hub::l1_channel::transaction_commitment(
                &partial_transaction_hex,
            )
            .map_err(|_| AgentWalletError::SigningBlocked)?,
            partial_transaction_hex,
            authorization_public_key_hex: hex::encode(
                account.inner().public_key().serialize_compressed(),
            ),
            authorization_signature_hex: String::new(),
        };
        let commitment: [u8; 32] = hex::decode(
            l2_fast_pay_hub::l1_channel_close::close_request_commitment(&signed_request)
                .map_err(|_| AgentWalletError::SigningBlocked)?,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?
        .try_into()
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        signed_request.authorization_signature_hex =
            hex::encode(account.inner().do_sign(&commitment));
        safety_permit.checkpoint(false)?;
        Ok(signed_request)
    }

    /// Sign the one exit transaction a durable record has already committed
    /// to, and refuse anything else.
    ///
    /// # Why this is narrower than it looks
    ///
    /// The other four signers here each verify a transaction *intent* they
    /// were handed. This one does not accept a transaction at all. It accepts
    /// a kit, a plan and the wallet's own durable record of that step, and it
    /// **builds** the bytes itself through
    /// [`hacash_wallet_core::hvm_registry_exit::build_user_exit_transaction`],
    /// which re-derives the canonical call source for the step and refuses any
    /// plan whose call source is not that exact string. There is therefore no
    /// caller-supplied transaction body for an attacker to smuggle anything
    /// into: the only inputs that reach the chain are the binding, the bill,
    /// the step, and three numbers the record already fixed.
    ///
    /// # What the key may not be used for
    ///
    /// * Any kit whose channel does not pay **this** address
    ///   (`binding.left_address == self.address`). An exit kit is a bearer
    ///   proof of entitlement, and this is the check that keeps a kit for
    ///   somebody else's channel from being signed by this wallet's key.
    /// * Any record that is not this kit's own channel incarnation.
    /// * Any step the record does not currently permit signing for. The
    ///   authority is [`resume_action`]'s own `may_sign`, read here as well as
    ///   in the driver: two independent readers of the same durable phase, so
    ///   a driver bug alone cannot produce a second signature for a step whose
    ///   bytes already exist.
    /// * Any fee above the per-transaction channel ceiling, or a zero fee, a
    ///   zero gas ceiling or a zero timestamp. The record is authenticated,
    ///   but it is authenticated by this wallet, and a wallet that wrote a
    ///   nonsense fee should not then spend it.
    /// * A claim payout aimed anywhere but this address. The contract pins the
    ///   destination too; this is the same refusal one layer earlier, where it
    ///   costs nothing.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn sign_exact_registry_exit(
        &self,
        request: AgentRegistryExitSigningRequest<'_>,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<
        l2_fast_pay_hub::hvm_registry_watchtower::SignedHvmRegistryCallTransactionV2,
    > {
        use hacash_wallet_core::hvm_registry_exit::HvmRegistryExitPlanV1;

        safety_permit.checkpoint(false)?;
        if request.wallet_scope != &self.wallet_scope
            || request.network_mode != self.network_mode
            || request.signer_epoch != self.signer_epoch
            || now >= self.unlock_expires_at
        {
            return Err(AgentWalletError::SigningBlocked);
        }

        let kit = request.kit;
        let record = request.record;
        let binding = &kit.binding;
        // The channel this key is being asked to walk out of has to be this
        // wallet's own, and the money has to land here.
        if binding.left_address != self.address || binding.right_hub_address == self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let binding_commitment = binding
            .commitment()
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if binding_commitment != request.binding_commitment
            || record.binding_commitment != binding_commitment
        {
            return Err(AgentWalletError::SigningBlocked);
        }

        // The record's own phase decides whether the key may be used at all.
        if !hacash_wallet_core::hvm_registry_exit_record::resume_action(record).may_sign() {
            return Err(AgentWalletError::SigningBlocked);
        }
        if record.network_fee_zhu == 0
            || record.network_fee_zhu > l2_fast_pay_hub::l1_channel::MAX_CHANNEL_NETWORK_FEE_ZHU
            || record.gas_max == 0
            || record.transaction_timestamp == 0
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }

        // The plan and the record must be the same step, with the same call
        // source. `build_user_exit_transaction` re-derives that source from
        // the binding and refuses a plan that does not match it, so agreeing
        // here means all three agree.
        match request.plan {
            HvmRegistryExitPlanV1::Wait { .. } => {
                return Err(AgentWalletError::SigningBlocked);
            }
            HvmRegistryExitPlanV1::Call { step, call_source } => {
                if record.step != *step
                    || &record.call_source != call_source
                    || record.claim_payee.is_some()
                    || record.claim_amount_zhu.is_some()
                {
                    return Err(AgentWalletError::ApprovalCommitmentMismatch);
                }
            }
            HvmRegistryExitPlanV1::Claim {
                payee,
                amount_zhu,
                call_source,
            } => {
                if record.step != hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep::Claim
                    || &record.call_source != call_source
                    || payee != &self.address
                    || record.claim_payee.as_deref() != Some(self.address.as_str())
                    || record.claim_amount_zhu != Some(*amount_zhu)
                    || *amount_zhu == 0
                {
                    return Err(AgentWalletError::ApprovalCommitmentMismatch);
                }
            }
        }

        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let signed = hacash_wallet_core::hvm_registry_exit::build_user_exit_transaction(
            account.inner(),
            kit,
            request.plan,
            record.network_fee_zhu,
            record.transaction_timestamp,
            record.gas_max,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        if signed.transaction_hash.len() != 64 || signed.signed_transaction_hex.is_empty() {
            return Err(AgentWalletError::SigningBlocked);
        }
        safety_permit.checkpoint(false)?;
        Ok(signed)
    }

    /// Left-sign the serial-1 full-refund bill that has to exist before this
    /// wallet's money may enter a registry channel, and refuse to sign
    /// anything else at open.
    ///
    /// # Why this signature is the one that matters most
    ///
    /// Every other signature this boundary makes spends something. This one
    /// creates the user's only unaided way back out. Until it exists, no Agent
    /// Wallet in this app can hold a provider channel at all: adoption needs a
    /// serial-1 refund carrying *this wallet's own* left signature, that
    /// signature can only be made at open, and nothing in `agent-wallet-core`
    /// made one. The exit driver, proven on a real chain, had nothing to act
    /// on for anybody.
    ///
    /// # What the key may not be used for
    ///
    /// * Any binding whose `left_address` is not this wallet. A refund bill is
    ///   a claim on a specific channel; signing one for a channel this wallet
    ///   is not the left party of gives away a signature for nothing.
    /// * A binding that puts this wallet on both sides, or that carries a
    ///   right-hub deposit the shared V2 profile does not fund.
    /// * A binding for another network than the one this signer is unlocked
    ///   for, or under a stale scope, epoch or expired unlock.
    /// * **Any bill that is not the whole refund.** Serial 1, the entire left
    ///   deposit on the left line, zero on the Hub line. This is checked here
    ///   on the object that comes back out of the builder, not only on the
    ///   inputs that went in, so a builder that started returning a partial
    ///   refund would be refused by the boundary rather than signed by it.
    ///
    /// The bytes themselves are produced by
    /// [`hacash_wallet_core::hvm_registry_open::build_left_signed_refund_request`],
    /// which signs `HvmRegistryBillV2::signing_hash` - the same encoder both
    /// parties use for every bill of this channel's life. There is no second
    /// encoder here.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn sign_exact_registry_channel_open(
        &self,
        request: AgentRegistryChannelOpenSigningRequest<'_>,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<l2_fast_pay_hub::hvm_registry::HvmRegistryRefundCountersignRequestV2>
    {
        safety_permit.checkpoint(false)?;
        if request.wallet_scope != &self.wallet_scope
            || request.network_mode != self.network_mode
            || request.signer_epoch != self.signer_epoch
            || now >= self.unlock_expires_at
            || now == 0
        {
            return Err(AgentWalletError::SigningBlocked);
        }

        let binding = request.binding;
        if binding.network_mode != self.network_mode
            || binding.left_address != self.address
            || binding.right_hub_address == self.address
            || binding.left_deposit_zhu == 0
            || binding.right_hub_deposit_zhu != 0
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        binding
            .validate()
            .map_err(|_| AgentWalletError::SigningBlocked)?;

        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let ask = hacash_wallet_core::hvm_registry_open::build_left_signed_refund_request(
            account.inner(),
            binding.clone(),
            now,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;

        // Read back what was actually signed. The builder already refuses
        // anything but the full refund; this is the boundary refusing to
        // delegate that question.
        let bill = &ask.left_signed_refund_bill;
        if ask.binding != *binding
            || bill.serial != 1
            || bill.left_balance_zhu != binding.left_deposit_zhu
            || bill.hub_balance_zhu != 0
            || !bill.hub_signature_hex.is_empty()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        bill.validate_left_signed(binding)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        safety_permit.checkpoint(false)?;
        Ok(ask)
    }

    /// Sign the exact deposit transfer that funds a registry channel.
    ///
    /// # Why this is a separate boundary rather than the ordinary send path
    ///
    /// Because it is the one transfer in this wallet whose *destination is a
    /// contract*, and the ordinary agent payment path is now forbidden to
    /// build one at all (see `super::service::payment`). Funding a channel is
    /// not a payment to a person; it is the act of putting principal somewhere
    /// only a countersigned refund can get it back out of, and the thing that
    /// makes it safe is not the signature but what had to be true before this
    /// function could be called.
    ///
    /// # What cannot be substituted here
    ///
    /// Not the destination, not the amount, not the chain. Every one of them
    /// is read out of the countersigned bundle, and the permission the caller
    /// must hand in - `HvmRegistryFundingAuthorizationV1` - has private
    /// fields, no `Deserialize` and exactly one constructor, which refuses
    /// unless the wallet's own pinned fullnode has just confirmed that the
    /// contract at that address is the reviewed registry, on this wallet's own
    /// chain, carrying the exact unfunded channel the refund is signed over.
    /// A caller with a contract address and an amount cannot reach this.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn sign_exact_registry_funding(
        &self,
        request: AgentRegistryFundingSigningRequest<'_>,
        safety_permit: &AgentSafetyPermit,
        now: u64,
    ) -> AgentWalletResult<
        l2_fast_pay_hub::hvm_registry_watchtower::SignedHvmRegistryFundingTransactionV2,
    > {
        safety_permit.checkpoint(false)?;
        if request.wallet_scope != &self.wallet_scope
            || request.network_mode != self.network_mode
            || request.signer_epoch != self.signer_epoch
            || now >= self.unlock_expires_at
            || now == 0
            || request.network_fee_zhu == 0
            || request.gas_max == 0
        {
            return Err(AgentWalletError::SigningBlocked);
        }

        let binding = &request.bundle.binding;
        if binding.network_mode != self.network_mode
            || binding.left_address != self.address
            || binding.right_hub_address == self.address
            || binding.left_deposit_zhu == 0
            || binding.right_hub_deposit_zhu != 0
            || request.authorization.left_address() != self.address
            || request.authorization.amount_zhu() != binding.left_deposit_zhu
            || request.authorization.contract_address() != binding.contract_address
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        binding
            .validate()
            .map_err(|_| AgentWalletError::SigningBlocked)?;

        safety_permit.checkpoint(false)?;
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        if account.address() != self.address {
            return Err(AgentWalletError::SigningBlocked);
        }
        let signed = hacash_wallet_core::hvm_registry_open::build_registry_funding_transaction(
            account.inner(),
            request.authorization,
            request.bundle,
            request.network_fee_zhu,
            request.timestamp,
            request.gas_max,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;

        // Read back what was actually signed, through a reader that shares no
        // line of code with the builder.
        if signed.contract_address != binding.contract_address
            || signed.amount_zhu != binding.left_deposit_zhu
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        l2_fast_pay_hub::hvm_registry_watchtower::read_exact_registry_funding_transaction(
            &signed.signed_transaction_hex,
            binding,
        )
        .map_err(|_| AgentWalletError::SigningBlocked)?;
        safety_permit.checkpoint(false)?;
        Ok(signed)
    }
}

/// Everything the funding signer is allowed to be told.
///
/// The authorization is the load-bearing field, and it is borrowed rather than
/// owned for the same reason the exit's kit is: a caller cannot construct one,
/// so being able to name the type at this call site is itself the proof that
/// the chain check ran.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) struct AgentRegistryFundingSigningRequest<'a> {
    pub(crate) wallet_scope: &'a WalletScope,
    pub(crate) network_mode: &'a str,
    pub(crate) signer_epoch: u64,
    pub(crate) authorization:
        &'a hacash_wallet_core::hvm_registry_open::HvmRegistryFundingAuthorizationV1,
    pub(crate) bundle: &'a l2_fast_pay_hub::hvm_registry::HvmRegistryRecoveryBundleV2,
    pub(crate) network_fee_zhu: u64,
    pub(crate) timestamp: u64,
    pub(crate) gas_max: u8,
}

/// Everything the channel-open signer is allowed to be told.
///
/// The binding is borrowed and is the wallet's own derivation, not a Hub's
/// proposal: the whole point of the open exchange is that the Hub sees the
/// bill the wallet built and can only add 97 bytes to it.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) struct AgentRegistryChannelOpenSigningRequest<'a> {
    pub(crate) wallet_scope: &'a WalletScope,
    pub(crate) network_mode: &'a str,
    pub(crate) signer_epoch: u64,
    pub(crate) binding: &'a l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2,
}

/// Everything the exit signer is allowed to be told, and nothing it is allowed
/// to be told twice.
///
/// Deliberately all borrowed and all read-only: the kit and the record come
/// out of authenticated wallet state, the plan comes out of the chain, and
/// this struct exists so a caller cannot substitute one of the three for a
/// value of its own choosing without it being visible at the call site.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) struct AgentRegistryExitSigningRequest<'a> {
    pub(crate) wallet_scope: &'a WalletScope,
    pub(crate) network_mode: &'a str,
    pub(crate) signer_epoch: u64,
    pub(crate) binding_commitment: &'a str,
    pub(crate) kit: &'a hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1,
    pub(crate) plan: &'a hacash_wallet_core::hvm_registry_exit::HvmRegistryExitPlanV1,
    pub(crate) record:
        &'a hacash_wallet_core::hvm_registry_exit_record::PersistedHvmRegistryExitStepV1,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl FastPayBillSigner for RestrictedAgentFastPaySigner<'_> {
    fn fast_pay_address(&self) -> &str {
        &self.signer.address
    }

    fn cosign_authorized_fast_pay_bill(
        &self,
        authorization: &FastPaySigningAuthorization,
    ) -> WalletResult<String> {
        self.safety_permit.checkpoint(false).map_err(|_| {
            WalletError::Policy("Agent Fast Pay emergency authority changed".into())
        })?;
        let expected_scope = if self.binding.network_mode == "mainnet" {
            self.binding.wallet_scope.as_str().to_owned()
        } else {
            format!(
                "{}@{}",
                self.binding.wallet_scope.as_str(),
                self.binding.network_mode
            )
        };
        if current_unix() >= self.binding.approval_expires_at
            || current_unix() >= self.signer.unlock_expires_at
            || authorization.operation_id() != self.binding.hub_operation_id
            || authorization.idempotency_key() != self.binding.hub_idempotency_key
            || authorization.wallet_scope() != expected_scope
            || authorization.hub_identity() != self.binding.hub_identity
            || authorization.channel_id() != self.binding.channel_id
            || authorization.channel_reuse_version() != self.binding.channel_reuse_version
            || authorization.network_mode() != self.binding.network_mode
            || authorization.payer() != self.binding.payer
            || authorization.payee() != self.binding.payee
            || authorization.amount() != self.binding.amount
            || authorization.amount_units() != self.binding.amount_units
            || authorization.owner_authority_commitment()
                != Some(
                    self.binding
                        .restricted_sender_authority
                        .owner_authority_commitment
                        .as_str(),
                )
            || authorization.restricted_sender_authority()
                != Some(&self.binding.restricted_sender_authority)
        {
            return Err(WalletError::Policy(
                "Agent Fast Pay signing authority changed after owner approval".into(),
            ));
        }
        let encoded = Zeroizing::new(hex::encode(self.signer.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| WalletError::Policy("Agent Fast Pay signing key is unavailable".into()))?;
        if account.address() != self.signer.address {
            return Err(WalletError::Policy(
                "Agent Fast Pay signer address changed".into(),
            ));
        }
        account.cosign_authorized_fast_pay_bill(authorization)
    }
}

impl FastPayJournalKeyProvider for AgentTransactionSigner {
    fn fast_pay_journal_address(&self) -> &str {
        &self.address
    }

    fn derive_fast_pay_journal_key(
        &self,
        wallet_scope: &str,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        if wallet_scope != self.wallet_scope.as_str()
            || network_mode != self.network_mode
            || hub_identity.is_empty()
            || channel_id.is_empty()
            || current_unix() >= self.unlock_expires_at
        {
            return Err(WalletError::Policy(
                "Agent Fast Pay journal binding does not match the unlocked Agent Wallet".into(),
            ));
        }
        // Construct the upstream account only inside this narrow derivation
        // boundary. It is dropped immediately and is never returned to the
        // Agent service or connector.
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| WalletError::Policy("Agent Fast Pay key derivation failed".into()))?;
        if account.address() != self.address {
            return Err(WalletError::Policy(
                "Agent Fast Pay signer address changed".into(),
            ));
        }
        account.derive_fast_pay_journal_key(wallet_scope, network_mode, hub_identity, channel_id)
    }
}

impl ChannelOpenJournalKeyProvider for AgentTransactionSigner {
    fn derive_channel_open_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
        reuse_version: u64,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        if wallet_scope != self.wallet_scope.as_str()
            || hub_identity.is_empty()
            || channel_id.is_empty()
            || reuse_version == 0
            || current_unix() >= self.unlock_expires_at
        {
            return Err(WalletError::Policy(
                "Agent channel-open journal binding does not match the unlocked Agent Wallet"
                    .into(),
            ));
        }
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| WalletError::Policy("Agent channel-open key derivation failed".into()))?;
        if account.address() != self.address {
            return Err(WalletError::Policy(
                "Agent channel-open signer address changed".into(),
            ));
        }
        account.derive_channel_open_journal_key(
            wallet_scope,
            hub_identity,
            channel_id,
            reuse_version,
        )
    }
}

impl ChannelCloseJournalKeyProvider for AgentTransactionSigner {
    fn derive_channel_close_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        if wallet_scope != self.wallet_scope.as_str()
            || hub_identity.is_empty()
            || channel_id.is_empty()
            || current_unix() >= self.unlock_expires_at
        {
            return Err(WalletError::Policy(
                "Agent channel-close journal binding does not match the unlocked Agent Wallet"
                    .into(),
            ));
        }
        let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
        let account = WalletAccount::from_secret_hex(&encoded)
            .map_err(|_| WalletError::Policy("Agent channel-close key derivation failed".into()))?;
        if account.address() != self.address {
            return Err(WalletError::Policy(
                "Agent channel-close signer address changed".into(),
            ));
        }
        account.derive_channel_close_journal_key(wallet_scope, hub_identity, channel_id)
    }
}

fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl fmt::Debug for AgentTransactionSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentTransactionSigner")
            .field("wallet_id", &self.wallet_id)
            .field("wallet_scope", &self.wallet_scope)
            .field("address", &self.address)
            .field("network_mode", &self.network_mode)
            .field("signer_epoch", &self.signer_epoch)
            .field("unlock_expires_at", &self.unlock_expires_at)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AgentTransactionSigner {
    fn drop(&mut self) {
        self.address.zeroize();
        self.network_mode.zeroize();
        self.secret_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use basis::interface::Transaction;
    use field::{Address, Amount, ChannelId, Field, Serialize as FieldSerialize, Uint4};
    use hacash_wallet_core::l2_safety::ClientL2Safety;
    use mint::action::ChannelClose;
    use protocol::action::{ChainAllow, ChainIDList};
    use protocol::transaction::TransactionType2;

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn hvm_signing_fixture() -> (
        tempfile::TempDir,
        crate::emergency::AgentEmergencyController,
        AgentTransactionSigner,
        AgentHvmPaymentSignerBinding,
        l2_fast_pay_hub::hvm_channel::HvmChannelBillV1,
        l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1,
    ) {
        hacash_wallet_core::protocol_init::ensure_protocol_setup();
        let temp = tempfile::tempdir().unwrap();
        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            agent.address(),
            "testnet".into(),
            7,
            &agent.secret_hex(),
            now,
        )
        .unwrap();
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
        let network_binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: "local_pilot_v1".into(),
            chain_id: 7,
            mainnet: false,
            block_1_hash: block_one,
            node_profile_id: node_profile_id.into(),
            network_instance_id: network_instance_id.clone(),
            transaction_format_version: 2,
        };
        let hvm_binding = l2_fast_pay_hub::hvm_channel::HvmChannelBindingV1 {
            schema: l2_fast_pay_hub::hvm_channel::HVM_CHANNEL_BINDING_SCHEMA.into(),
            settlement_profile: l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id,
            contract_address: vm::ContractAddress::from_unchecked(Address::create_contract(
                [7; 20],
            ))
            .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 1,
            bytecode_sha3: l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 1,
            left_address: agent.address(),
            right_hub_address: hub.address(),
            left_deposit_zhu: 100_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut previous = l2_fast_pay_hub::hvm_channel::HvmChannelBillV1 {
            schema: l2_fast_pay_hub::hvm_channel::HVM_CHANNEL_BILL_SCHEMA.into(),
            binding_commitment: hvm_binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: hvm_binding.left_deposit_zhu,
            right_balance_zhu: 0,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let previous_hash = previous.signing_hash(&hvm_binding).unwrap();
        previous.left_signature_hex =
            hex::encode(Sign::create_by(agent.inner(), &previous_hash).serialize());
        previous.right_signature_hex =
            hex::encode(Sign::create_by(hub.inner(), &previous_hash).serialize());
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("hpay:agent-hvm:{}", uuid::Uuid::new_v4());
        let recipient = "verified-hvm-service";
        let request = l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1::build_unsigned(
            &hvm_binding,
            &previous,
            &operation_id,
            &idempotency_key,
            recipient,
            1_000_000,
            now,
            now + 300,
        )
        .unwrap();
        let mut authority = AgentHvmPaymentSignerBinding {
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            agent_id: "agent-alpha".into(),
            agent_authorization_epoch: 3,
            policy_epoch: 5,
            signer_epoch: 7,
            emergency_epoch: 11,
            approval_commitment: "44".repeat(32),
            approval_decision_commitment: "55".repeat(32),
            owner_authority_commitment: String::new(),
            approval_expires_at: now + 300,
            network_mode: "testnet".into(),
            network_binding,
            hub_url: "http://127.0.0.1:8790".into(),
            hub_address: hub.address(),
            hvm_binding,
            operation_id,
            idempotency_key,
            payer: agent.address(),
            recipient: recipient.into(),
            amount_zhu: 1_000_000,
            fee_payer: "sender".into(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: 1_000_000,
            previous_bill_commitment: previous.commitment().unwrap(),
            unsigned_request_commitment: request.commitment().unwrap(),
        };
        authority.owner_authority_commitment =
            authority.calculate_owner_authority_commitment().unwrap();
        (temp, emergency, signer, authority, previous, request)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn hvm_registry_signing_fixture() -> (
        tempfile::TempDir,
        crate::emergency::AgentEmergencyController,
        AgentTransactionSigner,
        AgentHvmRegistryPaymentSignerBinding,
        l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2,
        l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2,
    ) {
        hacash_wallet_core::protocol_init::ensure_protocol_setup();
        let temp = tempfile::tempdir().unwrap();
        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            agent.address(),
            "testnet".into(),
            7,
            &agent.secret_hex(),
            now,
        )
        .unwrap();
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
        let network_binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: "local_pilot_v1".into(),
            chain_id: 7,
            mainnet: false,
            block_1_hash: block_one,
            node_profile_id: node_profile_id.into(),
            network_instance_id: network_instance_id.clone(),
            transaction_format_version: 2,
        };
        let hvm_binding = l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2 {
            schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE
                .into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id,
            contract_address: vm::ContractAddress::from_unchecked(Address::create_contract(
                [8; 20],
            ))
            .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 1,
            bytecode_sha3: l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 1,
            left_address: agent.address(),
            right_hub_address: hub.address(),
            left_deposit_zhu: 100_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut previous = l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2 {
            schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: hvm_binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: hvm_binding.left_deposit_zhu,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let previous_hash = previous.signing_hash(&hvm_binding).unwrap();
        previous.left_signature_hex =
            hex::encode(Sign::create_by(agent.inner(), &previous_hash).serialize());
        previous.hub_signature_hex =
            hex::encode(Sign::create_by(hub.inner(), &previous_hash).serialize());
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("hpay:agent-hvm-registry:{}", uuid::Uuid::new_v4());
        let recipient = hub.address();
        let request =
            l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2::build_unsigned(
                &network_binding,
                &hvm_binding,
                &previous,
                &operation_id,
                &idempotency_key,
                &recipient,
                1_000_000,
                now,
                now + 300,
            )
            .unwrap();
        let mut authority = AgentHvmRegistryPaymentSignerBinding {
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            agent_id: "agent-alpha".into(),
            agent_authorization_epoch: 3,
            policy_epoch: 5,
            signer_epoch: 7,
            emergency_epoch: 11,
            approval_commitment: "44".repeat(32),
            approval_decision_commitment: "55".repeat(32),
            owner_authority_commitment: String::new(),
            approval_expires_at: now + 300,
            network_mode: "testnet".into(),
            network_binding,
            hub_url: "http://127.0.0.1:8790".into(),
            hub_address: hub.address(),
            hvm_binding,
            operation_id,
            idempotency_key,
            payer: agent.address(),
            recipient,
            amount_zhu: 1_000_000,
            fee_payer: "sender".into(),
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: 1_000_000,
            previous_bill_commitment: previous.commitment().unwrap(),
            unsigned_request_commitment: request.commitment().unwrap(),
        };
        authority.owner_authority_commitment =
            authority.calculate_owner_authority_commitment().unwrap();
        (temp, emergency, signer, authority, previous, request)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn hvm_signer_signs_only_the_exact_approved_fee_free_bill() {
        let (_temp, emergency, signer, authority, previous, request) = hvm_signing_fixture();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let now = request.created_unix;
        let signed = signer
            .sign_exact_hvm_payment(&authority, &previous, request, &permit, now)
            .unwrap();
        assert!(!signed.proposed_bill.left_signature_hex.is_empty());
        assert!(signed.proposed_bill.right_signature_hex.is_empty());
        signed
            .validate_against(&authority.hvm_binding, &previous, now)
            .unwrap();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn hvm_signer_rejects_any_authority_fee_or_request_mutation() {
        let (_temp, emergency, signer, authority, previous, request) = hvm_signing_fixture();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let now = request.created_unix;
        let rejects =
            |changed: AgentHvmPaymentSignerBinding,
             changed_request: l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1| {
                assert!(
                    signer
                        .sign_exact_hvm_payment(&changed, &previous, changed_request, &permit, now,)
                        .is_err()
                );
            };

        let mut changed = authority.clone();
        changed.wallet_fee_zhu = 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.hub_fee_zhu = 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.agent_authorization_epoch += 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.emergency_epoch += 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.approval_decision_commitment = "ab".repeat(32);
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.hub_url = "https://other.example".into();
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.unsigned_request_commitment = "66".repeat(32);
        rejects(changed, request.clone());
        let mut changed_request = request.clone();
        changed_request.recipient = "other-service".into();
        rejects(authority.clone(), changed_request);
        let mut changed_request = request.clone();
        changed_request.proposed_bill.serial += 1;
        rejects(authority, changed_request);
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn hvm_registry_signer_signs_only_the_exact_approved_fee_free_bill() {
        let (_temp, emergency, signer, authority, previous, request) =
            hvm_registry_signing_fixture();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let now = request.created_unix;
        let signed = signer
            .sign_exact_hvm_registry_payment(&authority, &previous, request, &permit, now)
            .unwrap();
        assert!(!signed.proposed_bill.left_signature_hex.is_empty());
        assert!(!signed.payer_authorization_signature_hex.is_empty());
        assert!(signed.proposed_bill.hub_signature_hex.is_empty());
        signed
            .validate_against(&authority.hvm_binding, &previous, now)
            .unwrap();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn hvm_registry_signer_rejects_fee_authority_and_request_mutations() {
        let (_temp, emergency, signer, authority, previous, request) =
            hvm_registry_signing_fixture();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let now = request.created_unix;
        let rejects = |changed: AgentHvmRegistryPaymentSignerBinding,
                       changed_request: l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2| {
            assert!(
                signer
                    .sign_exact_hvm_registry_payment(
                        &changed,
                        &previous,
                        changed_request,
                        &permit,
                        now,
                    )
                    .is_err()
            );
        };

        let mut changed = authority.clone();
        changed.wallet_fee_zhu = 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.hub_fee_zhu = 1;
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.hvm_binding.channel_id = "66".repeat(16);
        rejects(changed, request.clone());
        let mut changed = authority.clone();
        changed.unsigned_request_commitment = "77".repeat(32);
        rejects(changed, request.clone());
        let mut changed_request = request.clone();
        changed_request.network_binding.node_profile_id.push('x');
        rejects(authority.clone(), changed_request);
        let mut changed_request = request;
        changed_request.amount_zhu += 1;
        rejects(authority, changed_request);
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn hvm_registry_signer_rechecks_expiry_before_key_use() {
        let (_temp, emergency, signer, authority, previous, request) =
            hvm_registry_signing_fixture();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let expired_at = request.expires_unix;
        assert_eq!(
            signer.sign_exact_hvm_registry_payment(
                &authority, &previous, request, &permit, expired_at,
            ),
            Err(AgentWalletError::ApprovalCommitmentMismatch)
        );
    }

    #[tokio::test]
    async fn channel_open_signer_accepts_only_exact_guarded_zero_hub_deposit() {
        hacash_wallet_core::protocol_init::ensure_protocol_setup();
        let temp = tempfile::tempdir().unwrap();
        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            agent.address(),
            "testnet".into(),
            1,
            &agent.secret_hex(),
            now,
        )
        .unwrap();
        let channel_id =
            hacash_wallet_core::channel::derive_channel_id(&agent.address(), &hub.address(), 1);
        let node = hacash_wallet_core::node::NodeClient::new("http://127.0.0.1:1").unwrap();
        let built = hacash_wallet_core::channel::build_channel_open_tx(
            &node,
            7,
            &agent.address(),
            &channel_id,
            &agent.address(),
            "1",
            &hub.address(),
            "0",
            "0.0001",
        )
        .await
        .unwrap();
        let block_one = "11".repeat(32);
        let profile = "hpay-local-pilot-chain-v1";
        let network_instance_id = hacash_wallet_core::network_instance_id(
            "local_pilot_v1",
            7,
            false,
            &block_one,
            profile,
            2,
        );
        let request = AgentChannelOpenSigningRequest {
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            network_mode: "testnet".into(),
            network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
                network_kind: "local_pilot_v1".into(),
                chain_id: 7,
                mainnet: false,
                block_1_hash: block_one,
                node_profile_id: profile.into(),
                network_instance_id,
                transaction_format_version: 2,
            },
            hub_address: hub.address(),
            channel_id,
            reuse_version: 1,
            left_deposit: "1".into(),
            right_deposit: "0".into(),
            network_fee: "0.0001".into(),
            unsigned_transaction_hex: built.body.unwrap(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: format!("hpay:agent-channel-open:{}", uuid::Uuid::new_v4()),
            created_unix: now,
            expires_unix: now + 300,
        };
        let signed = signer
            .sign_exact_channel_open(request, &permit, now)
            .unwrap();
        assert_eq!(signed.chain_id, 7);
        assert_eq!(signed.hub_address, hub.address());
        assert!(!signed.authorization_signature_hex.is_empty());

        let mut wrong_deposit = signed.clone();
        wrong_deposit.partial_transaction_hex.clear();
        assert!(
            l2_fast_pay_hub::l1_channel::validate_channel_open(
                &wrong_deposit,
                &signed.hub_address,
                &l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
                    network_kind: signed.network.clone(),
                    chain_id: signed.chain_id,
                    mainnet: signed.mainnet,
                    block_1_hash: signed.block_1_hash.clone(),
                    node_profile_id: signed.node_profile_id.clone(),
                    network_instance_id: signed.network_instance_id.clone(),
                    transaction_format_version: signed.transaction_format_version,
                },
                u64::MAX,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn channel_close_signer_accepts_only_exact_guarded_zero_wallet_fee_plan() {
        hacash_wallet_core::protocol_init::ensure_protocol_setup();
        let temp = tempfile::tempdir().unwrap();
        let storage = crate::storage::AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let emergency =
            crate::emergency::AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let permit = emergency.issue_safety_permit(false).unwrap();
        let agent = WalletAccount::create_random().unwrap();
        let hub = WalletAccount::create_random().unwrap();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            agent.address(),
            "testnet".into(),
            1,
            &agent.secret_hex(),
            now,
        )
        .unwrap();
        let channel_id =
            hacash_wallet_core::channel::derive_channel_id(&agent.address(), &hub.address(), 1);
        let mut tx = TransactionType2::new_by(
            Address::from_readable(&agent.address()).unwrap(),
            Amount::from("0.001").unwrap(),
            now,
        );
        let mut guard = ChainAllow::new();
        guard.chains = ChainIDList::from_list(vec![Uint4::from(7)]).unwrap();
        tx.push_action(Box::new(guard)).unwrap();
        let mut close = ChannelClose::new();
        close.channel_id = ChannelId::must(&hex::decode(&channel_id).unwrap());
        tx.push_action(Box::new(close)).unwrap();
        let block_one = "11".repeat(32);
        let profile = "hpay-local-pilot-chain-v1";
        let network_binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: "local_pilot_v1".into(),
            chain_id: 7,
            mainnet: false,
            block_1_hash: block_one.clone(),
            node_profile_id: profile.into(),
            network_instance_id: hacash_wallet_core::network_instance_id(
                "local_pilot_v1",
                7,
                false,
                &block_one,
                profile,
                2,
            ),
            transaction_format_version: 2,
        };
        let plan = hacash_wallet_core::channel::PreparedCooperativeChannelClose {
            channel_id: channel_id.clone(),
            reuse_version: 1,
            open_height: 100,
            bill_auto_number: 1,
            left_address: agent.address(),
            right_address: hub.address(),
            original_left_millimeis: 1_000,
            original_right_millimeis: 0,
            final_left_millimeis: 1_000,
            final_right_millimeis: 0,
            transfer_from: None,
            transfer_to: None,
            transfer_millimeis: None,
            unsigned_transaction_hex: hex::encode(tx.serialize()),
            network_fee: "0.001".into(),
            fee_estimate_degraded: None,
        };
        let signed = signer
            .sign_exact_channel_close(
                AgentChannelCloseSigningRequest {
                    wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
                    network_mode: "testnet".into(),
                    network_binding: network_binding.clone(),
                    hub_address: hub.address(),
                    plan,
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    idempotency_key: format!("hpay:agent-channel-close:{}", uuid::Uuid::new_v4()),
                    created_unix: now,
                    expires_unix: now + 300,
                },
                &permit,
                now,
            )
            .unwrap();
        let intent = l2_fast_pay_hub::l1_channel_close::validate_channel_close(
            &signed,
            &l2_fast_pay_hub::l1_channel_close::ExpectedChannelIncarnation {
                channel_id,
                user_address: agent.address(),
                hub_address: hub.address(),
                reuse_version: 1,
                open_height: 100,
            },
            &network_binding,
            now,
        )
        .unwrap();
        assert_eq!(intent.network_fee_zhu, 100_000);
        assert_eq!(
            intent.settlement,
            l2_fast_pay_hub::l1_channel_close::ChannelCloseSettlement::OriginalDistribution
        );
        assert!(!signed.authorization_signature_hex.is_empty());
    }

    #[test]
    fn signer_holds_only_zeroizing_secret_bytes_and_redacts_debug() {
        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let signer = AgentTransactionSigner::new(
            AgentWalletId::new(),
            account.address(),
            "testnet".into(),
            1,
            &secret,
            1_000,
        )
        .unwrap();

        let debug = format!("{signer:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(secret.as_str()));
        assert!(std::mem::needs_drop::<AgentTransactionSigner>());
        assert!(std::mem::needs_drop::<WalletAccount>());
        assert!(std::mem::needs_drop::<sys::Account>());
    }

    #[test]
    fn signer_rejects_secret_from_another_agent_wallet() {
        let account_a = WalletAccount::create_random().unwrap();
        let account_b = WalletAccount::create_random().unwrap();
        let secret_b = account_b.secret_hex();
        let result = AgentTransactionSigner::new(
            AgentWalletId::new(),
            account_a.address(),
            "testnet".into(),
            1,
            &secret_b,
            1_000,
        );
        assert!(matches!(result, Err(AgentWalletError::InvalidWalletScope)));
    }

    #[test]
    fn agent_journal_key_is_available_only_for_its_exact_scope() {
        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let wallet_id = AgentWalletId::new();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            account.address(),
            "testnet".into(),
            1,
            &secret,
            now,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let scope = WalletScope::for_agent_wallet(&wallet_id);
        let safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
            &signer,
            directory.path().join("agent-l2"),
            scope.as_str(),
            "testnet",
            "hub",
            "channel",
        )
        .unwrap();
        drop(safety);
        assert!(
            ClientL2Safety::open_scoped_with_key_provider_for_network(
                &signer,
                directory.path().join("other-agent-l2"),
                WalletScope::for_agent_wallet(&AgentWalletId::new()).as_str(),
                "testnet",
                "hub",
                "channel",
            )
            .is_err()
        );
        assert!(
            ClientL2Safety::open_scoped_with_key_provider_for_network(
                &signer,
                directory.path().join("personal-l2"),
                &format!("personal:{}", account.address()),
                "testnet",
                "hub",
                "channel",
            )
            .is_err()
        );
    }

    #[test]
    fn agent_channel_journals_are_scope_bound_and_domain_separated() {
        let account = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            account.address(),
            "testnet".into(),
            1,
            &account.secret_hex(),
            now,
        )
        .unwrap();
        let scope = WalletScope::for_agent_wallet(&wallet_id);
        let open_key = signer
            .derive_channel_open_journal_key(scope.as_str(), "hub", "channel", 1)
            .unwrap();
        let close_key = signer
            .derive_channel_close_journal_key(scope.as_str(), "hub", "channel")
            .unwrap();
        assert_ne!(open_key.as_slice(), close_key.as_slice());
        assert!(
            signer
                .derive_channel_open_journal_key(
                    WalletScope::for_agent_wallet(&AgentWalletId::new()).as_str(),
                    "hub",
                    "channel",
                    1,
                )
                .is_err()
        );
        assert!(
            signer
                .derive_channel_close_journal_key(
                    &format!("personal:{}", account.address()),
                    "hub",
                    "channel",
                )
                .is_err()
        );
    }

    #[test]
    fn expired_agent_session_cannot_derive_an_l2_journal_key() {
        let account = WalletAccount::create_random().unwrap();
        let wallet_id = AgentWalletId::new();
        let now = current_unix();
        let signer = AgentTransactionSigner::new(
            wallet_id.clone(),
            account.address(),
            "testnet".into(),
            1,
            &account.secret_hex(),
            now.saturating_sub(16 * 60),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("expired-agent-l2");
        assert!(
            ClientL2Safety::open_scoped_with_key_provider_for_network(
                &signer,
                &root,
                WalletScope::for_agent_wallet(&wallet_id).as_str(),
                "testnet",
                "hub",
                "channel",
            )
            .is_err()
        );
        assert!(!root.exists());
    }
}
