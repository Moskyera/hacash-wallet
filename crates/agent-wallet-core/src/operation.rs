use hpay_companion_protocol::ApprovalCommitment;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::{AgentId, AgentWalletId, OperationId};

const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/PAYMENT-REQUEST";
const TRANSACTION_COMMITMENT_DOMAIN: &[u8] = b"HPAY/AGENT-WALLET/UNSIGNED-TRANSACTION";
const REQUEST_COMMITMENT_VERSION: u64 = 1;
const TRANSACTION_COMMITMENT_VERSION: u64 = 1;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 1024;
const MAX_ADDRESS_BYTES: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_TRANSACTION_BYTES: usize = 256 * 1024;
const MAX_REQUEST_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    DesktopManual,
    MobileManual,
    EitherTrustedDevice,
}

impl ApprovalMode {
    /// Stage 1 intentionally has no autonomous approval mode.
    pub const fn requires_explicit_user_action(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPaymentRequest {
    pub idempotency_key: String,
    pub asset: String,
    pub amount_units: HacUnits,
    pub recipient: String,
    pub reason: String,
    pub expires_at: u64,
}

impl AgentPaymentRequest {
    pub(crate) fn validate(&self, now: u64) -> AgentWalletResult<()> {
        validate_nonempty_bounded(
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_BYTES,
            AgentWalletError::InvalidPaymentRequest,
        )?;
        if self.asset != "HAC" {
            return Err(AgentWalletError::UnsupportedAsset);
        }
        if self.amount_units == HacUnits::ZERO {
            return Err(AgentWalletError::InvalidAmount);
        }
        validate_nonempty_bounded(
            &self.recipient,
            MAX_ADDRESS_BYTES,
            AgentWalletError::InvalidPaymentRequest,
        )?;
        validate_nonempty_bounded(
            &self.reason,
            MAX_REASON_BYTES,
            AgentWalletError::InvalidPaymentRequest,
        )?;
        if self.expires_at <= now
            || self.expires_at.saturating_sub(now) > MAX_REQUEST_LIFETIME_SECONDS
        {
            return Err(AgentWalletError::RequestExpired);
        }
        Ok(())
    }

    pub fn commitment_hex(&self) -> AgentWalletResult<String> {
        let mut encoder =
            CanonicalCommitment::new(REQUEST_COMMITMENT_DOMAIN, REQUEST_COMMITMENT_VERSION);
        encoder.push_string(&self.idempotency_key)?;
        encoder.push_string(&self.asset)?;
        encoder.push_u64(self.amount_units.get());
        encoder.push_string(&self.recipient)?;
        encoder.push_string(&self.reason)?;
        encoder.push_u64(self.expires_at);
        Ok(encoder.finish_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    PaymentIntentCreated,
    FundsReserved,
    UnsignedTransactionPersisted,
    ApprovalRequested,
    Approved,
    Rejected,
    Signed,
    SignedAwaitingWitness,
    WitnessedAwaitingBroadcast,
    BroadcastSubmitted,
    BroadcastUncertain,
    SubmittedAwaitingFinalWitness,
    ReconciliationRequired,
    ReconciledAwaitingFinalWitness,
    Committed,
    Failed,
    Cancelled,
    RecoveryRequired,
}

impl OperationStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Committed | Self::Failed | Self::Cancelled
        )
    }

    pub const fn retains_reservation(self) -> bool {
        matches!(
            self,
            Self::FundsReserved
                | Self::UnsignedTransactionPersisted
                | Self::ApprovalRequested
                | Self::Approved
                | Self::Signed
                | Self::SignedAwaitingWitness
                | Self::WitnessedAwaitingBroadcast
                | Self::BroadcastSubmitted
                | Self::BroadcastUncertain
                | Self::SubmittedAwaitingFinalWitness
                | Self::ReconciliationRequired
                | Self::ReconciledAwaitingFinalWitness
                | Self::RecoveryRequired
        )
    }

    pub const fn is_pre_signing(self) -> bool {
        matches!(
            self,
            Self::PaymentIntentCreated
                | Self::FundsReserved
                | Self::UnsignedTransactionPersisted
                | Self::ApprovalRequested
                | Self::Approved
        )
    }

    /// The statuses for which the desktop will hand the paired mobile witness a
    /// rollback anchor to sign.
    ///
    /// This is the single definition of that set. `pending_rollback_anchor`
    /// admits exactly these, and the companion snapshot filter discloses the id
    /// of an operation to a witness phone only while it sits in exactly these.
    /// If the two ever diverged the phone would either be handed a pointer it
    /// cannot act on - a disclosure with no purpose - or be left unable to
    /// discover an operation that is stranded waiting for it. Set equality is
    /// asserted directly over every variant by
    /// `witness_pending_status_names_equal_the_anchor_admission_set`.
    pub const fn awaits_mobile_witness(self) -> bool {
        matches!(
            self,
            Self::SignedAwaitingWitness
                | Self::SubmittedAwaitingFinalWitness
                | Self::BroadcastUncertain
                | Self::ReconciledAwaitingFinalWitness
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentOperationView {
    pub operation_id: OperationId,
    pub agent_wallet_id: AgentWalletId,
    pub agent_id: AgentId,
    pub idempotency_key: String,
    pub request_commitment: String,
    pub asset: String,
    pub amount_units: HacUnits,
    pub recipient: String,
    pub reason: String,
    pub status: OperationStatus,
    pub network_fee_units: HacUnits,
    pub wallet_fee_units: HacUnits,
    pub total_debit_units: HacUnits,
    pub reserved_units: HacUnits,
    pub transaction_commitment: Option<String>,
    pub approval_mode: Option<ApprovalMode>,
    pub created_at: u64,
    pub expires_at: u64,
    pub tx_hash: Option<String>,
    pub final_result: Option<String>,
}

/// Durable operation model. It is intentionally crate-private: an agent can
/// receive only [`PaymentOperationView`] and can never mutate signing state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentOperation {
    operation_id: OperationId,
    agent_id: AgentId,
    agent_wallet_id: AgentWalletId,
    request: AgentPaymentRequest,
    request_commitment: String,
    status: OperationStatus,
    created_at: u64,
    expires_at: u64,
    network_fee_units: HacUnits,
    wallet_fee_units: HacUnits,
    total_debit_units: HacUnits,
    reserved_units: HacUnits,
    unsigned_tx_hex: Option<String>,
    transaction_commitment: Option<String>,
    approval_commitment: Option<ApprovalCommitment>,
    approval_decision: Option<ApprovalDecision>,
    signed_tx_hex: Option<String>,
    tx_hash: Option<String>,
    settled_at: Option<u64>,
    final_result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
enum ApprovalDecision {
    Approved {
        mode: ApprovalMode,
        commitment_sha256: String,
        decided_at: u64,
    },
    Rejected {
        mode: ApprovalMode,
        decided_at: u64,
    },
}

impl AgentOperation {
    pub(crate) fn new(
        operation_id: OperationId,
        agent_id: AgentId,
        agent_wallet_id: AgentWalletId,
        request: AgentPaymentRequest,
        created_at: u64,
    ) -> AgentWalletResult<Self> {
        request.validate(created_at)?;
        let request_commitment = request.commitment_hex()?;
        let expires_at = request.expires_at;
        Ok(Self {
            operation_id,
            agent_id,
            agent_wallet_id,
            request,
            request_commitment,
            status: OperationStatus::PaymentIntentCreated,
            created_at,
            expires_at,
            network_fee_units: HacUnits::ZERO,
            wallet_fee_units: HacUnits::ZERO,
            total_debit_units: HacUnits::ZERO,
            reserved_units: HacUnits::ZERO,
            unsigned_tx_hex: None,
            transaction_commitment: None,
            approval_commitment: None,
            approval_decision: None,
            signed_tx_hex: None,
            tx_hash: None,
            settled_at: None,
            final_result: None,
        })
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

    pub(crate) fn status(&self) -> OperationStatus {
        self.status
    }

    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn signed_tx_hex(&self) -> AgentWalletResult<&str> {
        self.signed_tx_hex
            .as_deref()
            .ok_or(AgentWalletError::InvalidOperationState)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn signed_transaction_commitment(&self) -> AgentWalletResult<String> {
        transaction_commitment_hex(self.signed_tx_hex()?)
    }

    pub(crate) fn settled_at(&self) -> Option<u64> {
        self.settled_at
    }

    pub(crate) fn stored_approval(&self) -> AgentWalletResult<&ApprovalCommitment> {
        self.approval_commitment
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)
    }

    pub(crate) fn reserve(&mut self, network_fee_units: HacUnits) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::PaymentIntentCreated)?;
        if network_fee_units != HacUnits::MIN_NETWORK_FEE {
            return Err(AgentWalletError::InvalidPaymentRequest);
        }
        let total_debit_units = self.request.amount_units.checked_add(network_fee_units)?;
        self.network_fee_units = network_fee_units;
        self.wallet_fee_units = HacUnits::ZERO;
        self.total_debit_units = total_debit_units;
        self.reserved_units = total_debit_units;
        self.status = OperationStatus::FundsReserved;
        Ok(())
    }

    pub(crate) fn persist_unsigned_transaction(
        &mut self,
        unsigned_tx_hex: String,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::FundsReserved)?;
        let transaction_commitment = transaction_commitment_hex(&unsigned_tx_hex)?;
        self.unsigned_tx_hex = Some(unsigned_tx_hex);
        self.transaction_commitment = Some(transaction_commitment);
        self.status = OperationStatus::UnsignedTransactionPersisted;
        Ok(())
    }

    pub(crate) fn request_approval(
        &mut self,
        approval: ApprovalCommitment,
        expected_policy_epoch: u64,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::UnsignedTransactionPersisted)?;
        validate_approval_shape(&approval, now)?;
        self.validate_approval_binding(&approval, expected_policy_epoch)?;
        self.approval_commitment = Some(approval);
        self.status = OperationStatus::ApprovalRequested;
        Ok(())
    }

    pub(crate) fn record_approval(
        &mut self,
        approval: ApprovalCommitment,
        mode: ApprovalMode,
        expected_policy_epoch: u64,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::ApprovalRequested)?;
        validate_approval_shape(&approval, now)?;
        self.validate_approval_binding(&approval, expected_policy_epoch)?;
        let stored = self
            .approval_commitment
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)?;
        if stored != &approval {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let commitment_sha256 = approval_commitment_hex(&approval)?;
        self.approval_decision = Some(ApprovalDecision::Approved {
            mode,
            commitment_sha256,
            decided_at: now,
        });
        self.status = OperationStatus::Approved;
        Ok(())
    }

    pub(crate) fn record_rejection(
        &mut self,
        mode: ApprovalMode,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::ApprovalRequested)?;
        self.approval_decision = Some(ApprovalDecision::Rejected {
            mode,
            decided_at: now,
        });
        self.status = OperationStatus::Rejected;
        self.reserved_units = HacUnits::ZERO;
        self.final_result = Some("rejected".to_owned());
        Ok(())
    }

    pub(crate) fn persisted_unsigned(&self) -> AgentWalletResult<PersistedUnsignedTransaction> {
        if !matches!(
            self.status,
            OperationStatus::UnsignedTransactionPersisted
                | OperationStatus::ApprovalRequested
                | OperationStatus::Approved
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        Ok(PersistedUnsignedTransaction {
            operation_id: self.operation_id.clone(),
            agent_id: self.agent_id.clone(),
            agent_wallet_id: self.agent_wallet_id.clone(),
            request_commitment: self.request_commitment.clone(),
            asset: self.request.asset.clone(),
            amount_units: self.request.amount_units,
            recipient: self.request.recipient.clone(),
            network_fee_units: self.network_fee_units,
            wallet_fee_units: self.wallet_fee_units,
            total_debit_units: self.total_debit_units,
            expires_at: self.expires_at,
            unsigned_tx_hex: self
                .unsigned_tx_hex
                .clone()
                .ok_or(AgentWalletError::InvalidOperationState)?,
            transaction_commitment: self
                .transaction_commitment
                .clone()
                .ok_or(AgentWalletError::InvalidOperationState)?,
        })
    }

    pub(crate) fn record_signed(
        &mut self,
        signed: &SignedAgentTransaction,
        tx_hash: String,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::Approved)?;
        signed.require_same_operation(self)?;
        validate_tx_hash(&tx_hash)?;
        self.signed_tx_hex = Some(signed.signed_tx_hex().to_owned());
        self.tx_hash = Some(tx_hash);
        self.status = if cfg!(feature = "agent-wallet-testnet-pilot") {
            OperationStatus::SignedAwaitingWitness
        } else {
            OperationStatus::Signed
        };
        Ok(())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_witnessed(&mut self) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::SignedAwaitingWitness)?;
        self.status = OperationStatus::WitnessedAwaitingBroadcast;
        Ok(())
    }

    pub(crate) fn mark_broadcast_submitted(&mut self, tx_hash: String) -> AgentWalletResult<()> {
        let expected = if cfg!(feature = "agent-wallet-testnet-pilot") {
            OperationStatus::WitnessedAwaitingBroadcast
        } else {
            OperationStatus::Signed
        };
        self.require_status(expected)?;
        validate_tx_hash(&tx_hash)?;
        if self.tx_hash.as_deref() != Some(tx_hash.as_str()) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.status = OperationStatus::BroadcastSubmitted;
        Ok(())
    }

    pub(crate) fn mark_broadcast_uncertain(&mut self) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            OperationStatus::Signed
                | OperationStatus::SignedAwaitingWitness
                | OperationStatus::WitnessedAwaitingBroadcast
                | OperationStatus::BroadcastSubmitted
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = OperationStatus::BroadcastUncertain;
        self.final_result = Some("broadcast_uncertain".to_owned());
        Ok(())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_submitted_awaiting_final_witness(&mut self) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::BroadcastSubmitted)?;
        self.status = OperationStatus::SubmittedAwaitingFinalWitness;
        self.final_result = Some("submitted_awaiting_final_witness".to_owned());
        Ok(())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_reconciliation_required(&mut self) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            OperationStatus::SubmittedAwaitingFinalWitness | OperationStatus::BroadcastUncertain
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.status = OperationStatus::ReconciliationRequired;
        self.final_result = Some("reconciliation_required".to_owned());
        Ok(())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_reconciled_awaiting_final_witness(
        &mut self,
        tx_hash: String,
        settled_at: u64,
    ) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::ReconciliationRequired)?;
        validate_tx_hash(&tx_hash)?;
        if self.tx_hash.as_deref() != Some(tx_hash.as_str()) {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        self.settled_at = Some(settled_at);
        self.final_result = Some("reconciled_awaiting_final_witness".to_owned());
        self.status = OperationStatus::ReconciledAwaitingFinalWitness;
        Ok(())
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn mark_committed_after_final_witness(&mut self) -> AgentWalletResult<()> {
        self.require_status(OperationStatus::ReconciledAwaitingFinalWitness)?;
        self.final_result = Some("confirmed".to_owned());
        self.status = OperationStatus::Committed;
        self.reserved_units = HacUnits::ZERO;
        Ok(())
    }

    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn mark_committed(
        &mut self,
        tx_hash: String,
        final_result: String,
        settled_at: u64,
    ) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            OperationStatus::BroadcastSubmitted | OperationStatus::BroadcastUncertain
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        validate_nonempty_bounded(
            &tx_hash,
            MAX_IDENTIFIER_BYTES,
            AgentWalletError::InvalidOperationState,
        )?;
        self.tx_hash = Some(tx_hash);
        self.settled_at = Some(settled_at);
        self.final_result = Some(final_result);
        self.status = OperationStatus::Committed;
        self.reserved_units = HacUnits::ZERO;
        Ok(())
    }

    pub(crate) fn fail_unsigned(&mut self, result: &str) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            OperationStatus::PaymentIntentCreated
                | OperationStatus::FundsReserved
                | OperationStatus::UnsignedTransactionPersisted
                | OperationStatus::ApprovalRequested
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        validate_nonempty_bounded(
            result,
            MAX_IDENTIFIER_BYTES,
            AgentWalletError::InvalidOperationState,
        )?;
        self.status = OperationStatus::Failed;
        self.reserved_units = HacUnits::ZERO;
        self.final_result = Some(result.to_owned());
        Ok(())
    }

    pub(crate) fn cancel_unsigned(&mut self) -> AgentWalletResult<()> {
        if !matches!(
            self.status,
            OperationStatus::PaymentIntentCreated
                | OperationStatus::FundsReserved
                | OperationStatus::UnsignedTransactionPersisted
                | OperationStatus::ApprovalRequested
        ) {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.cancel_with_result("cancelled")
    }

    pub(crate) fn cancel_pre_signing(&mut self, result: &str) -> AgentWalletResult<bool> {
        if !self.status.is_pre_signing() {
            return Ok(false);
        }
        self.cancel_with_result(result)?;
        Ok(true)
    }

    /// Abandons a payment that was signed and then never witnessed.
    ///
    /// `SignedAwaitingWitness` is the one and only status admitted here, and
    /// that is the whole safety argument: it is the status the desktop writes
    /// before anything is offered to the node, and the only transition out of it
    /// that leads to a broadcast is `mark_witnessed`, which needs a receipt.
    /// So a payment in this status provably never reached the network, and
    /// abandoning it cannot un-spend anything - it releases a reservation.
    ///
    /// It is deliberately not folded into `cancel_pre_signing`. That helper is
    /// called by sweeps and by policy edits, on their own initiative; this one
    /// exists only for an owner who pressed a control, and a signed transaction
    /// must never be discarded by a timer.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(crate) fn abandon_awaiting_witness(&mut self) -> AgentWalletResult<()> {
        if self.status != OperationStatus::SignedAwaitingWitness {
            return Err(AgentWalletError::InvalidOperationState);
        }
        self.cancel_with_result("witness_abandoned")
    }

    fn cancel_with_result(&mut self, result: &str) -> AgentWalletResult<()> {
        validate_nonempty_bounded(
            result,
            MAX_IDENTIFIER_BYTES,
            AgentWalletError::InvalidOperationState,
        )?;
        self.status = OperationStatus::Cancelled;
        self.reserved_units = HacUnits::ZERO;
        self.final_result = Some(result.to_owned());
        Ok(())
    }

    pub(crate) fn view(&self) -> PaymentOperationView {
        let approval_mode = self
            .approval_decision
            .as_ref()
            .map(|decision| match decision {
                ApprovalDecision::Approved { mode, .. }
                | ApprovalDecision::Rejected { mode, .. } => *mode,
            });
        PaymentOperationView {
            operation_id: self.operation_id.clone(),
            agent_wallet_id: self.agent_wallet_id.clone(),
            agent_id: self.agent_id.clone(),
            idempotency_key: self.request.idempotency_key.clone(),
            request_commitment: self.request_commitment.clone(),
            asset: self.request.asset.clone(),
            amount_units: self.request.amount_units,
            recipient: self.request.recipient.clone(),
            reason: self.request.reason.clone(),
            status: self.status,
            network_fee_units: self.network_fee_units,
            wallet_fee_units: self.wallet_fee_units,
            total_debit_units: self.total_debit_units,
            reserved_units: self.reserved_units,
            transaction_commitment: self.transaction_commitment.clone(),
            approval_mode,
            created_at: self.created_at,
            expires_at: self.expires_at,
            tx_hash: self.tx_hash.clone(),
            final_result: self.final_result.clone(),
        }
    }

    fn validate_approval_binding(
        &self,
        approval: &ApprovalCommitment,
        expected_policy_epoch: u64,
    ) -> AgentWalletResult<()> {
        let expected_tx_commitment = self
            .transaction_commitment
            .as_deref()
            .ok_or(AgentWalletError::InvalidOperationState)?;
        let bound = approval.operation_id == self.operation_id.as_str()
            && approval.agent_wallet_id == self.agent_wallet_id.as_str()
            && approval.agent_id == self.agent_id.as_str()
            && self.request.asset == "HAC"
            && approval.amount_units == self.request.amount_units.get()
            && approval.recipient == self.request.recipient
            && approval.fee_units == self.network_fee_units.get()
            && approval.wallet_fee_units == self.wallet_fee_units.get()
            && approval.total_debit_units == self.total_debit_units.get()
            && approval.transaction_commitment == expected_tx_commitment
            && approval.policy_epoch == expected_policy_epoch
            && approval.expires_at <= self.expires_at;
        if !bound {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(())
    }

    fn require_status(&self, expected: OperationStatus) -> AgentWalletResult<()> {
        if self.status != expected {
            return Err(AgentWalletError::InvalidOperationState);
        }
        Ok(())
    }
}

/// Only a transaction already present in the durable operation record can
/// enter the approval boundary. Fields are private to prevent fabrication.
#[derive(Debug, Clone)]
pub(crate) struct PersistedUnsignedTransaction {
    operation_id: OperationId,
    agent_id: AgentId,
    agent_wallet_id: AgentWalletId,
    request_commitment: String,
    asset: String,
    amount_units: HacUnits,
    recipient: String,
    network_fee_units: HacUnits,
    wallet_fee_units: HacUnits,
    total_debit_units: HacUnits,
    expires_at: u64,
    unsigned_tx_hex: String,
    transaction_commitment: String,
}

impl PersistedUnsignedTransaction {
    /// This transition succeeds only after the operation containing the exact
    /// approval decision has itself been persisted by the caller.
    pub(crate) fn into_approved(
        self,
        persisted_operation: &AgentOperation,
        now: u64,
    ) -> AgentWalletResult<ApprovedUnsignedTransaction> {
        if persisted_operation.status != OperationStatus::Approved
            || persisted_operation.operation_id != self.operation_id
            || persisted_operation.agent_id != self.agent_id
            || persisted_operation.agent_wallet_id != self.agent_wallet_id
            || persisted_operation.request_commitment != self.request_commitment
            || persisted_operation.request.asset != self.asset
            || persisted_operation.request.amount_units != self.amount_units
            || persisted_operation.request.recipient != self.recipient
            || persisted_operation.network_fee_units != self.network_fee_units
            || persisted_operation.wallet_fee_units != self.wallet_fee_units
            || persisted_operation.total_debit_units != self.total_debit_units
            || persisted_operation.expires_at != self.expires_at
            || persisted_operation.unsigned_tx_hex.as_deref() != Some(&self.unsigned_tx_hex)
            || persisted_operation.transaction_commitment.as_deref()
                != Some(&self.transaction_commitment)
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let approval = persisted_operation
            .approval_commitment
            .as_ref()
            .ok_or(AgentWalletError::ApprovalRequired)?;
        validate_approval_shape(approval, now)?;
        let stored_digest = match persisted_operation.approval_decision.as_ref() {
            Some(ApprovalDecision::Approved {
                commitment_sha256, ..
            }) => commitment_sha256,
            Some(ApprovalDecision::Rejected { .. }) => {
                return Err(AgentWalletError::ApprovalRejected);
            }
            None => return Err(AgentWalletError::ApprovalRequired),
        };
        if &approval_commitment_hex(approval)? != stored_digest {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(ApprovedUnsignedTransaction {
            persisted: self,
            approval_commitment_sha256: stored_digest.clone(),
        })
    }
}

/// The only input shape an Agent Wallet blockchain signer may accept.
#[derive(Debug)]
pub(crate) struct ApprovedUnsignedTransaction {
    persisted: PersistedUnsignedTransaction,
    approval_commitment_sha256: String,
}

impl ApprovedUnsignedTransaction {
    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.persisted.operation_id
    }

    pub(crate) fn agent_wallet_id(&self) -> &AgentWalletId {
        &self.persisted.agent_wallet_id
    }

    pub(crate) fn asset(&self) -> &str {
        &self.persisted.asset
    }

    pub(crate) fn amount_units(&self) -> HacUnits {
        self.persisted.amount_units
    }

    pub(crate) fn recipient(&self) -> &str {
        &self.persisted.recipient
    }

    pub(crate) fn network_fee_units(&self) -> HacUnits {
        self.persisted.network_fee_units
    }

    pub(crate) fn wallet_fee_units(&self) -> HacUnits {
        self.persisted.wallet_fee_units
    }

    pub(crate) fn total_debit_units(&self) -> HacUnits {
        self.persisted.total_debit_units
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.persisted.expires_at
    }

    pub(crate) fn unsigned_tx_hex(&self) -> &str {
        &self.persisted.unsigned_tx_hex
    }

    pub(crate) fn transaction_commitment(&self) -> &str {
        &self.persisted.transaction_commitment
    }

    pub(crate) fn approval_commitment_sha256(&self) -> &str {
        &self.approval_commitment_sha256
    }

    pub(crate) fn revalidate_transaction_commitment(&self) -> AgentWalletResult<()> {
        let actual = transaction_commitment_hex(&self.persisted.unsigned_tx_hex)?;
        if actual != self.persisted.transaction_commitment {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(())
    }

    /// Crate-private by design. The signer creates this only after signing
    /// `unsigned_tx_hex`; no agent-facing API can construct a signed typestate.
    pub(crate) fn into_signed(
        self,
        signed_tx_hex: String,
    ) -> AgentWalletResult<SignedAgentTransaction> {
        validate_transaction_hex(&signed_tx_hex)?;
        Ok(SignedAgentTransaction {
            approved: self,
            signed_tx_hex,
        })
    }
}

#[derive(Debug)]
pub(crate) struct SignedAgentTransaction {
    approved: ApprovedUnsignedTransaction,
    signed_tx_hex: String,
}

impl SignedAgentTransaction {
    pub(crate) fn operation_id(&self) -> &OperationId {
        self.approved.operation_id()
    }

    pub(crate) fn signed_tx_hex(&self) -> &str {
        &self.signed_tx_hex
    }

    fn require_same_operation(&self, operation: &AgentOperation) -> AgentWalletResult<()> {
        if self.operation_id() != &operation.operation_id
            || self.approved.transaction_commitment()
                != operation
                    .transaction_commitment
                    .as_deref()
                    .ok_or(AgentWalletError::InvalidOperationState)?
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        Ok(())
    }
}

struct CanonicalCommitment {
    hasher: Sha256,
}

impl CanonicalCommitment {
    fn new(domain: &[u8], version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(version.to_be_bytes());
        Self { hasher }
    }

    fn push_string(&mut self, value: &str) -> AgentWalletResult<()> {
        let length =
            u32::try_from(value.len()).map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        self.hasher.update(length.to_be_bytes());
        self.hasher.update(value.as_bytes());
        Ok(())
    }

    fn push_u64(&mut self, value: u64) {
        self.hasher.update(value.to_be_bytes());
    }

    fn finish_hex(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

fn validate_approval_shape(approval: &ApprovalCommitment, now: u64) -> AgentWalletResult<()> {
    if approval.expires_at <= now {
        return Err(AgentWalletError::ApprovalExpired);
    }
    let expected_total = approval
        .amount_units
        .checked_add(approval.fee_units)
        .ok_or(AgentWalletError::ApprovalCommitmentMismatch)?;
    if approval.fee_units != HacUnits::MIN_NETWORK_FEE.get()
        || approval.wallet_fee_units != HacUnits::ZERO.get()
        || approval.total_debit_units != expected_total
        || approval.issued_at > now
        || approval.issued_at >= approval.expires_at
    {
        return Err(AgentWalletError::ApprovalCommitmentMismatch);
    }
    approval
        .canonical_sha256_hex()
        .map(|_| ())
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)
}

fn approval_commitment_hex(approval: &ApprovalCommitment) -> AgentWalletResult<String> {
    approval
        .canonical_sha256_hex()
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)
}

fn transaction_commitment_hex(unsigned_tx_hex: &str) -> AgentWalletResult<String> {
    let bytes = validate_transaction_hex(unsigned_tx_hex)?;
    let mut encoder = CanonicalCommitment::new(
        TRANSACTION_COMMITMENT_DOMAIN,
        TRANSACTION_COMMITMENT_VERSION,
    );
    let length = u32::try_from(bytes.len()).map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
    encoder.hasher.update(length.to_be_bytes());
    encoder.hasher.update(bytes);
    Ok(encoder.finish_hex())
}

fn validate_tx_hash(value: &str) -> AgentWalletResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AgentWalletError::InvalidOperationState);
    }
    Ok(())
}

fn validate_transaction_hex(raw: &str) -> AgentWalletResult<Vec<u8>> {
    if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES * 2 || !raw.len().is_multiple_of(2) {
        return Err(AgentWalletError::InvalidPaymentRequest);
    }
    hex::decode(raw).map_err(|_| AgentWalletError::InvalidPaymentRequest)
}

fn validate_nonempty_bounded(
    value: &str,
    maximum: usize,
    error: AgentWalletError,
) -> AgentWalletResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED_AT: u64 = 1_000;
    const EXPIRES_AT: u64 = 2_000;
    const POLICY_EPOCH: u64 = 7;

    fn ids() -> (OperationId, AgentId, AgentWalletId) {
        (
            OperationId::parse("op_11111111111111111111111111111111").unwrap(),
            AgentId::parse("agent_22222222222222222222222222222222").unwrap(),
            AgentWalletId::parse("aw_33333333333333333333333333333333").unwrap(),
        )
    }

    fn request() -> AgentPaymentRequest {
        AgentPaymentRequest {
            idempotency_key: "invoice-2026-07".to_owned(),
            asset: "HAC".to_owned(),
            amount_units: HacUnits::new(5_000_000),
            recipient: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".to_owned(),
            reason: "Monthly server invoice".to_owned(),
            expires_at: EXPIRES_AT,
        }
    }

    fn unsigned_hex() -> String {
        "020102030405".to_owned()
    }

    fn prepared_operation() -> AgentOperation {
        let (operation_id, agent_id, wallet_id) = ids();
        let mut operation =
            AgentOperation::new(operation_id, agent_id, wallet_id, request(), CREATED_AT).unwrap();
        operation.reserve(HacUnits::MIN_NETWORK_FEE).unwrap();
        operation
            .persist_unsigned_transaction(unsigned_hex())
            .unwrap();
        let approval = approval_for(&operation);
        operation
            .request_approval(approval, POLICY_EPOCH, 1_100)
            .unwrap();
        operation
    }

    fn approval_for(operation: &AgentOperation) -> ApprovalCommitment {
        ApprovalCommitment {
            approval_version: 2,
            approval_id: "approval-1".to_owned(),
            operation_id: operation.operation_id.to_string(),
            agent_wallet_id: operation.agent_wallet_id.to_string(),
            agent_id: operation.agent_id.to_string(),
            desktop_device_id: hpay_companion_protocol::DeviceId::parse("desktop-home").unwrap(),
            transaction_commitment: operation.transaction_commitment.clone().unwrap(),
            amount_units: operation.request.amount_units.get(),
            fee_units: operation.network_fee_units.get(),
            wallet_fee_units: operation.wallet_fee_units.get(),
            total_debit_units: operation.total_debit_units.get(),
            recipient: operation.request.recipient.clone(),
            policy_epoch: POLICY_EPOCH,
            challenge_nonce: "cd".repeat(16),
            issued_at: 1_100,
            expires_at: 1_900,
            network_binding: None,
        }
    }

    #[test]
    fn request_commitment_is_deterministic_and_binds_every_request_field() {
        let request = request();
        let expected = request.commitment_hex().unwrap();
        assert_eq!(expected.len(), 64);
        assert_eq!(request.commitment_hex().unwrap(), expected);

        let mut changed = request.clone();
        changed.reason.push('!');
        assert_ne!(changed.commitment_hex().unwrap(), expected);
        changed = request.clone();
        changed.amount_units = HacUnits::new(changed.amount_units.get() + 1);
        assert_ne!(changed.commitment_hex().unwrap(), expected);
        changed = request.clone();
        changed.expires_at += 1;
        assert_ne!(changed.commitment_hex().unwrap(), expected);
    }

    #[test]
    fn canonical_encoder_uses_unambiguous_big_endian_length_prefixes() {
        let mut first = CanonicalCommitment::new(b"test-domain", 1);
        first.push_string("ab").unwrap();
        first.push_string("c").unwrap();
        first.push_u64(7);

        let mut second = CanonicalCommitment::new(b"test-domain", 1);
        second.push_string("a").unwrap();
        second.push_string("bc").unwrap();
        second.push_u64(7);

        assert_ne!(first.finish_hex(), second.finish_hex());
    }

    #[test]
    fn agent_wallet_fee_is_zero_and_total_is_amount_plus_network_fee() {
        let view = prepared_operation().view();
        assert_eq!(view.wallet_fee_units, HacUnits::ZERO);
        assert_eq!(view.network_fee_units, HacUnits::MIN_NETWORK_FEE);
        assert_eq!(
            view.total_debit_units,
            view.amount_units
                .checked_add(view.network_fee_units)
                .unwrap()
        );
        assert_eq!(view.reserved_units, view.total_debit_units);
    }

    #[test]
    fn approval_commitment_binds_transaction_identity_amount_fee_and_expiry() {
        let operation = prepared_operation();
        let approval = approval_for(&operation);
        let expected = approval_commitment_hex(&approval).unwrap();
        assert_eq!(expected.len(), 64);

        let mut changed = approval.clone();
        changed.transaction_commitment = "00".repeat(32);
        assert_ne!(approval_commitment_hex(&changed).unwrap(), expected);
        changed = approval.clone();
        changed.recipient.push('x');
        assert_ne!(approval_commitment_hex(&changed).unwrap(), expected);
        changed = approval.clone();
        changed.fee_units += 1;
        changed.total_debit_units += 1;
        assert_eq!(
            validate_approval_shape(&changed, 1_100),
            Err(AgentWalletError::ApprovalCommitmentMismatch)
        );
        changed = approval;
        changed.expires_at += 1;
        assert_ne!(approval_commitment_hex(&changed).unwrap(), expected);
    }

    #[test]
    fn only_exact_persisted_approval_can_cross_the_signing_typestate() {
        let mut operation = prepared_operation();
        let persisted = operation.persisted_unsigned().unwrap();
        let approval = approval_for(&operation);
        operation
            .record_approval(approval, ApprovalMode::DesktopManual, POLICY_EPOCH, 1_200)
            .unwrap();

        let approved = persisted.into_approved(&operation, 1_300).unwrap();
        assert_eq!(approved.unsigned_tx_hex(), unsigned_hex());
        let signed = approved.into_signed("0201020304050607".to_owned()).unwrap();
        operation.record_signed(&signed, "ab".repeat(32)).unwrap();
        assert_eq!(
            operation.status(),
            if cfg!(feature = "agent-wallet-testnet-pilot") {
                OperationStatus::SignedAwaitingWitness
            } else {
                OperationStatus::Signed
            }
        );
        assert!(operation.view().reserved_units > HacUnits::ZERO);
    }

    #[test]
    fn changed_approval_is_rejected_before_signing() {
        let mut operation = prepared_operation();
        let approval = approval_for(&operation);
        let mut changed = approval.clone();
        changed.amount_units = approval.amount_units + 1;
        assert_eq!(
            operation.record_approval(changed, ApprovalMode::DesktopManual, POLICY_EPOCH, 1_200,),
            Err(AgentWalletError::ApprovalCommitmentMismatch)
        );
        assert_eq!(operation.status(), OperationStatus::ApprovalRequested);
    }

    #[test]
    fn nonzero_legacy_wallet_fee_is_rejected_before_signing() {
        let mut operation = prepared_operation();
        let mut approval = approval_for(&operation);
        approval.wallet_fee_units = 1;
        approval.total_debit_units = approval.total_debit_units.checked_add(1).unwrap();
        assert_eq!(
            operation.record_approval(approval, ApprovalMode::DesktopManual, POLICY_EPOCH, 1_200,),
            Err(AgentWalletError::ApprovalCommitmentMismatch)
        );
        assert_eq!(operation.status(), OperationStatus::ApprovalRequested);
    }

    #[test]
    fn legacy_v1_approval_fails_closed() {
        let operation = prepared_operation();
        let mut approval = approval_for(&operation);
        approval.approval_version = 1;
        assert_eq!(
            validate_approval_shape(&approval, 1_200),
            Err(AgentWalletError::ApprovalCommitmentMismatch)
        );

        let legacy_json = serde_json::json!({
            "approval_version": 1,
            "approval_id": "approval-legacy",
            "operation_id": operation.operation_id.as_str(),
            "agent_wallet_id": operation.agent_wallet_id.as_str(),
            "agent_id": operation.agent_id.as_str(),
            "desktop_device_id": "desktop-home",
            "asset": "HAC",
            "amount_units": "5000000",
            "recipient": operation.request.recipient,
            "fee_units": "1000",
            "wallet_fee_units": "0",
            "total_debit_units": "5001000",
            "transaction_commitment": operation.transaction_commitment.unwrap(),
            "policy_epoch": POLICY_EPOCH,
            "approval_nonce": "legacy-nonce",
            "issued_at": 1100,
            "expires_at": 1900
        });
        assert!(serde_json::from_value::<ApprovalCommitment>(legacy_json).is_err());
    }

    #[test]
    fn expired_approval_and_request_fail_closed() {
        let mut expired_request = request();
        expired_request.expires_at = CREATED_AT;
        let (operation_id, agent_id, wallet_id) = ids();
        assert_eq!(
            AgentOperation::new(
                operation_id,
                agent_id,
                wallet_id,
                expired_request,
                CREATED_AT
            ),
            Err(AgentWalletError::RequestExpired)
        );

        let mut operation = prepared_operation();
        let approval = approval_for(&operation);
        assert_eq!(
            operation.record_approval(approval, ApprovalMode::DesktopManual, POLICY_EPOCH, 1_900,),
            Err(AgentWalletError::ApprovalExpired)
        );
    }

    #[test]
    fn unsigned_build_failure_releases_the_reservation_without_signing() {
        let (operation_id, agent_id, wallet_id) = ids();
        let mut operation =
            AgentOperation::new(operation_id, agent_id, wallet_id, request(), CREATED_AT).unwrap();
        operation.reserve(HacUnits::MIN_NETWORK_FEE).unwrap();
        assert!(operation.status().retains_reservation());

        operation.fail_unsigned("transaction_build_failed").unwrap();

        let view = operation.view();
        assert_eq!(view.status, OperationStatus::Failed);
        assert_eq!(view.reserved_units, HacUnits::ZERO);
        assert_eq!(
            view.final_result.as_deref(),
            Some("transaction_build_failed")
        );
        assert!(view.transaction_commitment.is_none());
        assert!(view.tx_hash.is_none());
    }

    #[test]
    fn signed_or_uncertain_operations_keep_their_reservation() {
        for status in [
            OperationStatus::Signed,
            OperationStatus::BroadcastSubmitted,
            OperationStatus::BroadcastUncertain,
            OperationStatus::RecoveryRequired,
        ] {
            assert!(status.retains_reservation());
        }
        assert!(!OperationStatus::Committed.retains_reservation());
        assert!(!OperationStatus::Rejected.retains_reservation());
    }

    #[test]
    fn pre_signing_cancellation_includes_approved_but_never_post_signing_states() {
        let mut approved = prepared_operation();
        let approval = approval_for(&approved);
        approved
            .record_approval(approval, ApprovalMode::DesktopManual, POLICY_EPOCH, 1_200)
            .unwrap();
        assert!(approved.cancel_pre_signing("expired").unwrap());
        assert_eq!(approved.status(), OperationStatus::Cancelled);
        assert_eq!(approved.view().reserved_units, HacUnits::ZERO);
        assert_eq!(approved.view().final_result.as_deref(), Some("expired"));

        for status in [
            OperationStatus::Signed,
            OperationStatus::BroadcastSubmitted,
            OperationStatus::BroadcastUncertain,
            OperationStatus::RecoveryRequired,
        ] {
            let mut protected = prepared_operation();
            protected.status = status;
            let before = protected.clone();
            assert!(!protected.cancel_pre_signing("expired").unwrap());
            assert_eq!(protected, before);
        }
    }

    #[test]
    fn operation_view_never_contains_raw_transaction_material() {
        let operation = prepared_operation();
        let encoded = serde_json::to_string(&operation.view()).unwrap();
        assert!(!encoded.contains(&unsigned_hex()));
        assert!(!encoded.contains("signed_tx_hex"));
        assert!(encoded.contains("transaction_commitment"));
    }

    #[test]
    fn autonomous_approval_mode_does_not_exist() {
        for mode in [
            ApprovalMode::DesktopManual,
            ApprovalMode::MobileManual,
            ApprovalMode::EitherTrustedDevice,
        ] {
            assert!(mode.requires_explicit_user_action());
        }
        assert!(serde_json::from_str::<ApprovalMode>("\"auto_approve\"").is_err());
    }
}
