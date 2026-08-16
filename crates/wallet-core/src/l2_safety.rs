//! Scoped wallet Fast Pay recovery journal.
//!
//! This module is intentionally separate from the vault, transaction history
//! and final dispute-bill store. It persists only the minimum operation state
//! required to prevent duplicate signing and to recover an uncertain L2
//! submission. Its authentication key is derived with HKDF domain separation;
//! the blockchain signing key is never stored in this state.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use field::Serialize as FieldSerialize;
use fs2::FileExt;
use hkdf::Hkdf;
use l2_fast_pay_hub::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::l2_signer::FastPayJournalKeyProvider;
use crate::l2_storage_scope::validate_scoped_l2_storage;
use crate::paths::{secure_write, wallet_data_root};

const KEY_DOMAIN: &[u8] = b"HPAY/L2/JOURNAL/AUTH/V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientOperationStatus {
    PaymentIntentCreated,
    PersistedBeforeSigning,
    Signed,
    Submitted,
    AwaitingRecipient,
    Committed,
    Rejected,
    RecoveryRequired,
}

impl ClientOperationStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Rejected)
    }

    pub fn requires_explicit_reconciliation(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Submitted | Self::AwaitingRecipient | Self::RecoveryRequired
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientL2Operation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub wallet_scope: String,
    pub hub_identity: String,
    pub channel_id: String,
    pub channel_reuse_version: u64,
    #[serde(default)]
    pub network_mode: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    /// Exact L2 millimeis (1 HAC = 1,000), not application-specific ledger
    /// units. Callers with finer accounting precision must convert exactly and
    /// reject remainders before opening this durable operation.
    pub amount_units: u64,
    pub intent_commitment: String,
    pub request_commitment: String,
    /// Optional owner-authority commitment for restricted signers.
    ///
    /// Personal Wallet operations intentionally leave this unset for backward
    /// compatibility. Agent Wallet must set it before the first Hub call and
    /// the restricted signer must require the exact same value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_authority_commitment: Option<String>,
    /// Explicit, authenticated authority context for a restricted Agent
    /// signer. Personal Wallet operations intentionally keep this unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_sender_authority: Option<RestrictedSenderAuthority>,
    pub status: ClientOperationStatus,
    pub unsigned_bill_hex: Option<String>,
    pub signed_bill_hex: Option<String>,
    pub unsigned_state_commitment: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClientL2State {
    schema_version: u32,
    journal_sequence: u64,
    journal_head: String,
    state_commitment: String,
    operations: BTreeMap<String, ClientL2Operation>,
}

pub struct RecipientOperationInput<'a> {
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
    pub payer: &'a str,
    pub payee: &'a str,
    pub amount: &'a str,
    /// Exact L2 millimeis; see [`ClientL2Operation::amount_units`].
    pub amount_units: u64,
    pub channel_reuse_version: u64,
}

/// Stable caller-owned identity for a durable sender operation.
///
/// Agent Wallet creates and persists this identity in its own encrypted
/// operation journal before opening the scoped L2 store. Reusing it after a
/// restart resumes the same Hub request instead of creating an orphan payment.
pub struct ClientOperationIdentity<'a> {
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
}

/// Additional durable authority required by a restricted Agent signer.
///
/// The commitment is opaque to wallet-core. Agent Wallet owns its canonical
/// encoding and binds the owner approval, agent identity, policy/signer/
/// emergency epochs, network, Hub, channel incarnation, route, fees and
/// expiry into this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestrictedSenderAuthority {
    pub owner_authority_commitment: String,
    pub approval_commitment: String,
    pub agent_id: String,
    pub agent_authorization_epoch: u64,
    pub policy_epoch: u64,
    pub signer_epoch: u64,
    pub emergency_epoch: u64,
    pub approval_expires_at: u64,
    pub hub_url: String,
    pub channel_open_height: u64,
    pub binding_commitment: String,
    pub chain_id: u32,
    pub genesis_identifier: String,
    pub node_profile_id: String,
    pub network_instance_id: String,
    pub transaction_format_version: u64,
    pub fee_payer: String,
    pub network_fee_units: u64,
    pub wallet_fee_units: u64,
    pub hub_fee_units: u64,
    pub total_debit_units: u64,
}

pub struct ClientL2Safety {
    path: PathBuf,
    wallet_scope: String,
    network_mode: String,
    local_address: String,
    hub_identity: String,
    channel_id: String,
    journal: AuthenticatedJournal,
    state: ClientL2State,
    _lock: fs::File,
}

impl ClientL2Safety {
    pub fn open(
        account: &WalletAccount,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        Self::open_for_network(account, "mainnet", hub_identity, channel_id)
    }

    pub fn open_for_network(
        account: &WalletAccount,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        let wallet_scope = format!("personal:{}", account.address());
        Self::open_scoped_for_network(
            account,
            wallet_data_root().join("l2").join("personal"),
            &wallet_scope,
            network_mode,
            hub_identity,
            channel_id,
        )
    }

    pub fn open_scoped(
        account: &WalletAccount,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        Self::open_scoped_for_network(
            account,
            trusted_l2_root,
            wallet_scope,
            "mainnet",
            hub_identity,
            channel_id,
        )
    }

    pub fn open_scoped_for_network(
        account: &WalletAccount,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        Self::open_scoped_with_key_provider_for_network(
            account,
            trusted_l2_root,
            wallet_scope,
            network_mode,
            hub_identity,
            channel_id,
        )
    }

    pub fn open_scoped_with_key_provider(
        key_provider: &dyn FastPayJournalKeyProvider,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        Self::open_scoped_with_key_provider_for_network(
            key_provider,
            trusted_l2_root,
            wallet_scope,
            "mainnet",
            hub_identity,
            channel_id,
        )
    }

    pub fn open_scoped_with_key_provider_for_network(
        key_provider: &dyn FastPayJournalKeyProvider,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        validate_network_mode(network_mode)?;
        let trusted_l2_root = trusted_l2_root.as_ref();
        validate_scoped_l2_storage(trusted_l2_root, wallet_scope)?;
        // Authorize and derive before touching the filesystem. A rejected
        // scope must not leave a directory or lock artifact behind.
        let local_address = key_provider.fast_pay_journal_address().to_owned();
        let mut key = key_provider.derive_fast_pay_journal_key(
            wallet_scope,
            network_mode,
            hub_identity,
            channel_id,
        )?;
        let authenticated_scope = network_bound_scope(wallet_scope, network_mode);
        let directory = scoped_safety_directory(
            trusted_l2_root,
            wallet_scope,
            network_mode,
            hub_identity,
            channel_id,
        );
        fs::create_dir_all(&directory).map_err(l2_io)?;
        let path = directory.join("operations.json");
        let lock = acquire_lock(&directory.join("operations.lock"))?;
        let journal = AuthenticatedJournal::open(
            directory.join("operations.journal.jsonl"),
            &key[..],
            JournalBinding {
                wallet_scope: authenticated_scope.clone(),
                hub_or_provider_identity: hub_identity.to_owned(),
                channel_id: Some(channel_id.to_owned()),
            },
        )
        .map_err(l2_hub_error)?;
        key.zeroize();
        let mut state = load_state(&path)?;
        initialize_state(
            &path,
            &mut state,
            &journal,
            &authenticated_scope,
            hub_identity,
            channel_id,
        )?;
        Ok(Self {
            path,
            wallet_scope: authenticated_scope,
            network_mode: network_mode.to_owned(),
            local_address,
            hub_identity: hub_identity.to_owned(),
            channel_id: channel_id.to_owned(),
            journal,
            state,
            _lock: lock,
        })
    }

    pub fn begin_or_resume(
        &mut self,
        payer: &str,
        payee: &str,
        amount: &str,
        amount_units: u64,
        channel_reuse_version: u64,
    ) -> WalletResult<ClientL2Operation> {
        let intent_commitment = intent_commitment(
            payer,
            payee,
            amount,
            &self.network_mode,
            &self.binding_channel_id()?,
            &self.binding_hub_identity()?,
        );
        if let Some(existing) = self
            .state
            .operations
            .values()
            .find(|operation| {
                !operation.status.is_terminal() && operation.intent_commitment == intent_commitment
            })
            .cloned()
        {
            return Ok(existing);
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("hpay:{}", uuid::Uuid::new_v4());
        self.begin_or_resume_with_identity(
            ClientOperationIdentity {
                operation_id: &operation_id,
                idempotency_key: &idempotency_key,
            },
            payer,
            payee,
            amount,
            amount_units,
            channel_reuse_version,
        )
    }

    pub fn begin_or_resume_with_identity(
        &mut self,
        identity: ClientOperationIdentity<'_>,
        payer: &str,
        payee: &str,
        amount: &str,
        amount_units: u64,
        channel_reuse_version: u64,
    ) -> WalletResult<ClientL2Operation> {
        validate_client_operation_identity(&identity)?;
        let wallet_scope = self.binding_wallet_scope()?;
        let hub_identity = self.binding_hub_identity()?;
        let channel_id = self.binding_channel_id()?;
        let intent_commitment = intent_commitment(
            payer,
            payee,
            amount,
            &self.network_mode,
            &channel_id,
            &hub_identity,
        );
        if let Some(existing) = self.state.operations.get(identity.operation_id).cloned() {
            if existing.idempotency_key != identity.idempotency_key
                || existing.intent_commitment != intent_commitment
                || existing.payer != payer
                || existing.payee != payee
                || existing.amount != amount
                || existing.amount_units != amount_units
                || existing.channel_reuse_version != channel_reuse_version
                || existing.network_mode != self.network_mode
            {
                return Err(WalletError::L2(
                    "idempotency conflict: stable Fast Pay operation identity changed".into(),
                ));
            }
            return Ok(existing);
        }
        if self.state.operations.values().any(|operation| {
            operation.idempotency_key == identity.idempotency_key
                || (!operation.status.is_terminal()
                    && operation.intent_commitment == intent_commitment)
        }) {
            return Err(WalletError::L2(
                "idempotency conflict: stable Fast Pay identity maps to another operation".into(),
            ));
        }
        if self
            .state
            .operations
            .values()
            .any(|operation| !operation.status.is_terminal() && operation.channel_id == channel_id)
        {
            return Err(WalletError::L2(
                "RecoveryRequired: this channel has an unresolved Fast Pay operation".into(),
            ));
        }

        let now = unix_timestamp();
        let request_commitment = request_commitment(
            identity.operation_id,
            payer,
            payee,
            amount,
            &self.network_mode,
            &channel_id,
        );
        let operation = ClientL2Operation {
            operation_id: identity.operation_id.to_owned(),
            idempotency_key: identity.idempotency_key.to_owned(),
            wallet_scope,
            hub_identity,
            channel_id,
            channel_reuse_version,
            network_mode: self.network_mode.clone(),
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: amount.to_owned(),
            amount_units,
            intent_commitment,
            request_commitment,
            owner_authority_commitment: None,
            restricted_sender_authority: None,
            status: ClientOperationStatus::PaymentIntentCreated,
            unsigned_bill_hex: None,
            signed_bill_hex: None,
            unsigned_state_commitment: None,
            created_at: now,
            updated_at: now,
        };
        self.transition(operation.clone(), JournalPhase::PaymentIntentCreated)?;
        Ok(operation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_or_resume_restricted_sender(
        &mut self,
        identity: ClientOperationIdentity<'_>,
        authority: RestrictedSenderAuthority,
        payer: &str,
        payee: &str,
        amount: &str,
        amount_units: u64,
        channel_reuse_version: u64,
    ) -> WalletResult<ClientL2Operation> {
        validate_restricted_sender_authority(&authority, &self.network_mode, amount_units)?;
        let mut operation = self.begin_or_resume_with_identity(
            identity,
            payer,
            payee,
            amount,
            amount_units,
            channel_reuse_version,
        )?;
        if let Some(existing) = operation.owner_authority_commitment.as_deref() {
            if existing != authority.owner_authority_commitment
                || operation.restricted_sender_authority.as_ref() != Some(&authority)
            {
                return Err(WalletError::L2(
                    "idempotency conflict: restricted signer authority changed".into(),
                ));
            }
            return Ok(operation);
        }
        if operation.status != ClientOperationStatus::PaymentIntentCreated {
            return Err(WalletError::L2(
                "RecoveryRequired: restricted signer authority was not durable before execution"
                    .into(),
            ));
        }
        operation.owner_authority_commitment = Some(authority.owner_authority_commitment.clone());
        operation.restricted_sender_authority = Some(authority);
        operation.updated_at = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::PaymentIntentCreated)?;
        Ok(operation)
    }

    pub fn import_recipient_operation(
        &mut self,
        input: RecipientOperationInput<'_>,
    ) -> WalletResult<ClientL2Operation> {
        let RecipientOperationInput {
            operation_id,
            idempotency_key,
            payer,
            payee,
            amount,
            amount_units,
            channel_reuse_version,
        } = input;
        if let Some(existing) = self.state.operations.get(operation_id).cloned() {
            if existing.idempotency_key != idempotency_key
                || existing.payer != payer
                || existing.payee != payee
                || existing.amount != amount
            {
                return Err(WalletError::L2(
                    "idempotency conflict: recipient operation payload changed".into(),
                ));
            }
            return Ok(existing);
        }
        if self.state.operations.values().any(|operation| {
            !operation.status.is_terminal() && operation.channel_id == self.channel_id
        }) {
            return Err(WalletError::L2(
                "RecoveryRequired: recipient channel has an unresolved Fast Pay operation".into(),
            ));
        }
        let now = unix_timestamp();
        let operation = ClientL2Operation {
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            wallet_scope: self.wallet_scope.clone(),
            hub_identity: self.hub_identity.clone(),
            channel_id: self.channel_id.clone(),
            channel_reuse_version,
            network_mode: self.network_mode.clone(),
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: amount.to_owned(),
            amount_units,
            intent_commitment: intent_commitment(
                payer,
                payee,
                amount,
                &self.network_mode,
                &self.channel_id,
                &self.hub_identity,
            ),
            request_commitment: request_commitment(
                operation_id,
                payer,
                payee,
                amount,
                &self.network_mode,
                &self.channel_id,
            ),
            owner_authority_commitment: None,
            restricted_sender_authority: None,
            status: ClientOperationStatus::PaymentIntentCreated,
            unsigned_bill_hex: None,
            signed_bill_hex: None,
            unsigned_state_commitment: None,
            created_at: now,
            updated_at: now,
        };
        self.transition(operation.clone(), JournalPhase::PaymentIntentCreated)?;
        Ok(operation)
    }

    pub fn persist_before_signing(
        &mut self,
        operation_id: &str,
        unsigned_bill_hex: &str,
    ) -> WalletResult<ClientL2Operation> {
        let mut operation = self.operation(operation_id)?;
        let documents =
            ChannelPayCompleteDocuments::from_bill_hex(unsigned_bill_hex).map_err(l2_hub_error)?;
        let commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        if let Some(existing) = &operation.unsigned_state_commitment {
            if existing != &commitment
                || operation.unsigned_bill_hex.as_deref() != Some(unsigned_bill_hex)
            {
                return Err(WalletError::L2(
                    "idempotency conflict: hub changed the prepared Fast Pay bill".into(),
                ));
            }
            return Ok(operation);
        }
        if operation.status != ClientOperationStatus::PaymentIntentCreated {
            return Err(WalletError::L2(
                "RecoveryRequired: invalid pre-sign operation state".into(),
            ));
        }
        operation.unsigned_state_commitment = Some(commitment);
        operation.unsigned_bill_hex = Some(unsigned_bill_hex.to_owned());
        operation.status = ClientOperationStatus::PersistedBeforeSigning;
        operation.updated_at = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::StatePersistedBeforeSigning)?;
        Ok(operation)
    }

    /// Restores a bill obtained by an exact read-only Hub reconciliation after
    /// the original preparation response was lost. A signature must not exist.
    pub(crate) fn persist_reconciled_before_signing(
        &mut self,
        operation_id: &str,
        unsigned_bill_hex: &str,
    ) -> WalletResult<ClientL2Operation> {
        let mut operation = self.operation(operation_id)?;
        if operation.status == ClientOperationStatus::PersistedBeforeSigning {
            if operation.unsigned_bill_hex.as_deref() == Some(unsigned_bill_hex)
                && operation.signed_bill_hex.is_none()
            {
                return Ok(operation);
            }
            return Err(WalletError::L2(
                "idempotency conflict: reconciled Hub bill changed".into(),
            ));
        }
        if operation.status != ClientOperationStatus::RecoveryRequired
            || operation.signed_bill_hex.is_some()
        {
            return Err(WalletError::L2(
                "Fast Pay unsigned recovery requires RecoveryRequired without signed bytes".into(),
            ));
        }
        let documents =
            ChannelPayCompleteDocuments::from_bill_hex(unsigned_bill_hex).map_err(l2_hub_error)?;
        let commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        if let Some(existing) = operation.unsigned_state_commitment.as_deref()
            && (existing != commitment
                || operation.unsigned_bill_hex.as_deref() != Some(unsigned_bill_hex))
        {
            return Err(WalletError::L2(
                "idempotency conflict: reconciled Hub bill changed".into(),
            ));
        }
        operation.unsigned_state_commitment = Some(commitment);
        operation.unsigned_bill_hex = Some(unsigned_bill_hex.to_owned());
        operation.status = ClientOperationStatus::PersistedBeforeSigning;
        operation.updated_at = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::ReconciliationCompleted)?;
        Ok(operation)
    }

    /// Releases a definitely unsigned recovered operation after its owner
    /// approval expired. The retained unsigned bill is audit evidence only and
    /// can never be submitted without a signature.
    pub fn reject_reconciled_unsigned(&mut self, operation_id: &str) -> WalletResult<()> {
        let operation = self.operation(operation_id)?;
        if operation.status != ClientOperationStatus::PersistedBeforeSigning
            || operation.unsigned_bill_hex.is_none()
            || operation.signed_bill_hex.is_some()
        {
            return Err(WalletError::L2(
                "Fast Pay unsigned rejection requires a reconciled unsigned bill".into(),
            ));
        }
        self.set_status(
            operation_id,
            ClientOperationStatus::Rejected,
            JournalPhase::RecoveryCompleted,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn require_exact_sender_request(
        &self,
        operation_id: &str,
        idempotency_key: &str,
        payer: &str,
        payee: &str,
        amount: &str,
        amount_units: u64,
        channel_id: &str,
        channel_reuse_version: u64,
        hub_identity: &str,
    ) -> WalletResult<ClientL2Operation> {
        let operation = self.operation(operation_id)?;
        let expected_request = request_commitment(
            operation_id,
            payer,
            payee,
            amount,
            &self.network_mode,
            channel_id,
        );
        if self.local_address != payer
            || self.channel_id != channel_id
            || self.hub_identity != hub_identity
            || operation.wallet_scope != self.wallet_scope
            || operation.operation_id != operation_id
            || operation.idempotency_key != idempotency_key
            || operation.hub_identity != hub_identity
            || operation.channel_id != channel_id
            || operation.channel_reuse_version != channel_reuse_version
            || operation.network_mode != self.network_mode
            || operation.payer != payer
            || operation.payee != payee
            || operation.amount != amount
            || operation.amount_units != amount_units
            || operation.request_commitment != expected_request
        {
            return Err(WalletError::L2(
                "idempotency conflict: Fast Pay request does not match its durable operation"
                    .into(),
            ));
        }
        Ok(operation)
    }

    pub fn persist_signature(
        &mut self,
        operation_id: &str,
        signed_bill_hex: &str,
    ) -> WalletResult<ClientL2Operation> {
        let mut operation = self.operation(operation_id)?;
        let documents =
            ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex).map_err(l2_hub_error)?;
        let unsigned_hex = operation.unsigned_bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2("Fast Pay operation is missing its durable unsigned bill".into())
        })?;
        require_only_local_signature_added(unsigned_hex, signed_bill_hex, &self.local_address)?;
        let commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.local_address)
        {
            return Err(WalletError::L2(
                "Fast Pay bill does not contain the verified local wallet signature".into(),
            ));
        }
        if operation.unsigned_state_commitment.as_deref() != Some(&commitment) {
            return Err(WalletError::L2(
                "signed Fast Pay bill does not match the durable unsigned commitment".into(),
            ));
        }
        if let Some(existing) = &operation.signed_bill_hex {
            if existing != signed_bill_hex {
                return Err(WalletError::L2(
                    "idempotency conflict: operation already has a different signature".into(),
                ));
            }
            return Ok(operation);
        }
        if operation.status != ClientOperationStatus::PersistedBeforeSigning {
            return Err(WalletError::L2(
                "RecoveryRequired: signature was produced from an invalid operation state".into(),
            ));
        }
        operation.signed_bill_hex = Some(signed_bill_hex.to_owned());
        operation.status = ClientOperationStatus::Signed;
        operation.updated_at = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::SignatureProduced)?;
        Ok(operation)
    }

    pub fn mark_submitted(&mut self, operation_id: &str) -> WalletResult<()> {
        self.set_status(
            operation_id,
            ClientOperationStatus::Submitted,
            JournalPhase::PaymentSubmitted,
        )
    }

    pub(crate) fn mark_reconciled_submitted(&mut self, operation_id: &str) -> WalletResult<()> {
        let mut operation = self.operation(operation_id)?;
        if operation.status != ClientOperationStatus::RecoveryRequired
            || operation.signed_bill_hex.is_none()
        {
            return Err(WalletError::L2(
                "Fast Pay exact retry requires RecoveryRequired with durable signed bytes".into(),
            ));
        }
        operation.status = ClientOperationStatus::Submitted;
        operation.updated_at = unix_timestamp();
        self.transition(operation, JournalPhase::PaymentSubmitted)
    }

    pub fn mark_awaiting_recipient(&mut self, operation_id: &str) -> WalletResult<()> {
        self.set_status(
            operation_id,
            ClientOperationStatus::AwaitingRecipient,
            JournalPhase::PaymentAcknowledged,
        )
    }

    pub(crate) fn mark_reconciled_awaiting_recipient(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<()> {
        let mut operation = self.operation(operation_id)?;
        if operation.status == ClientOperationStatus::AwaitingRecipient {
            return Ok(());
        }
        if operation.status != ClientOperationStatus::RecoveryRequired {
            return Err(WalletError::L2(
                "Fast Pay awaiting-recipient reconciliation requires RecoveryRequired".into(),
            ));
        }
        operation.status = ClientOperationStatus::AwaitingRecipient;
        operation.updated_at = unix_timestamp();
        self.transition(operation, JournalPhase::PaymentAcknowledged)
    }

    pub fn mark_committed(&mut self, operation_id: &str) -> WalletResult<()> {
        self.set_status(
            operation_id,
            ClientOperationStatus::Committed,
            JournalPhase::PaymentCommitted,
        )
    }

    pub fn mark_recovery_required(&mut self, operation_id: &str) -> WalletResult<()> {
        self.set_status(
            operation_id,
            ClientOperationStatus::RecoveryRequired,
            JournalPhase::RecoveryStarted,
        )
    }

    pub fn operation(&self, operation_id: &str) -> WalletResult<ClientL2Operation> {
        self.state
            .operations
            .get(operation_id)
            .cloned()
            .ok_or_else(|| WalletError::L2(format!("Fast Pay operation {operation_id} not found")))
    }

    fn set_status(
        &mut self,
        operation_id: &str,
        status: ClientOperationStatus,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let mut operation = self.operation(operation_id)?;
        if operation.status == status {
            return Ok(());
        }
        if operation.status == ClientOperationStatus::RecoveryRequired
            && status != ClientOperationStatus::Committed
        {
            return Err(WalletError::L2(
                "RecoveryRequired: reconciliation must complete before state can advance".into(),
            ));
        }
        operation.status = status;
        operation.updated_at = unix_timestamp();
        self.transition(operation, phase)
    }

    fn transition(
        &mut self,
        operation: ClientL2Operation,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let previous_commitment = state_commitment(&self.state)?;
        let mut next = self.state.clone();
        next.schema_version = 1;
        next.operations
            .insert(operation.operation_id.clone(), operation.clone());
        let new_commitment = state_commitment(&next)?;
        let record = self
            .journal
            .append(JournalEvent {
                wallet_scope: operation.wallet_scope.clone(),
                hub_or_provider_identity: operation.hub_identity.clone(),
                channel_id: operation.channel_id.clone(),
                channel_reuse_version: operation.channel_reuse_version,
                operation_id: operation.operation_id.clone(),
                operation_type: JournalOperationType::FastPay,
                operation_phase: phase,
                amount_units: operation.amount_units,
                sender: operation.payer.clone(),
                recipient: operation.payee.clone(),
                previous_state_commitment: previous_commitment,
                new_state_commitment: new_commitment.clone(),
                idempotency_key: operation.idempotency_key.clone(),
                request_commitment: operation.request_commitment.clone(),
                expected_bill_number: None,
                unsigned_state_commitment: operation.unsigned_state_commitment.clone(),
                created_at: operation.updated_at,
            })
            .map_err(l2_hub_error)?;
        next.journal_sequence = record.entry_sequence;
        next.journal_head = record.entry_hash.clone();
        next.state_commitment = new_commitment.clone();
        save_state(&self.path, &next)?;
        self.journal
            .write_checkpoint(&JournalHead {
                sequence: record.entry_sequence,
                entry_hash: record.entry_hash,
                state_commitment: new_commitment,
            })
            .map_err(l2_hub_error)?;
        self.state = next;
        Ok(())
    }

    fn binding_wallet_scope(&self) -> WalletResult<String> {
        Ok(self.wallet_scope.clone())
    }

    fn binding_hub_identity(&self) -> WalletResult<String> {
        Ok(self.hub_identity.clone())
    }

    fn binding_channel_id(&self) -> WalletResult<String> {
        Ok(self.channel_id.clone())
    }
}

fn require_only_local_signature_added(
    unsigned_bill_hex: &str,
    signed_bill_hex: &str,
    local_address: &str,
) -> WalletResult<()> {
    let unsigned =
        ChannelPayCompleteDocuments::from_bill_hex(unsigned_bill_hex).map_err(l2_hub_error)?;
    let signed =
        ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex).map_err(l2_hub_error)?;
    if !unsigned.prove_bindings_valid()
        || !signed.prove_bindings_valid()
        || unsigned.chain_payment.sign_stuff_hash() != signed.chain_payment.sign_stuff_hash()
        || unsigned.prove_bodies.len() != signed.prove_bodies.len()
        || unsigned.chain_payment.must_sign_addresses.len()
            != signed.chain_payment.must_sign_addresses.len()
        || unsigned.chain_payment.must_signs.len() != signed.chain_payment.must_signs.len()
    {
        return Err(WalletError::L2(
            "Fast Pay signer changed the validated settlement document".into(),
        ));
    }
    if unsigned
        .prove_bodies
        .iter()
        .zip(&signed.prove_bodies)
        .any(|(before, after)| {
            FieldSerialize::serialize(before) != FieldSerialize::serialize(after)
        })
    {
        return Err(WalletError::L2(
            "Fast Pay signer changed a validated settlement proof".into(),
        ));
    }
    let mut local_slots = 0_u8;
    for (((before_address, before_sign), after_address), after_sign) in unsigned
        .chain_payment
        .must_sign_addresses
        .iter()
        .zip(unsigned.chain_payment.must_signs.iter())
        .zip(signed.chain_payment.must_sign_addresses.iter())
        .zip(signed.chain_payment.must_signs.iter())
    {
        if before_address.to_readable() != after_address.to_readable() {
            return Err(WalletError::L2(
                "Fast Pay signer changed the required signer list".into(),
            ));
        }
        if before_address.to_readable() == local_address {
            local_slots = local_slots.saturating_add(1);
            if unsigned
                .chain_payment
                .signature_verified_for_readable(local_address)
                || !signed
                    .chain_payment
                    .signature_verified_for_readable(local_address)
                || FieldSerialize::serialize(before_sign) == FieldSerialize::serialize(after_sign)
            {
                return Err(WalletError::L2(
                    "Fast Pay signer did not add exactly one new local signature".into(),
                ));
            }
        } else if FieldSerialize::serialize(before_sign) != FieldSerialize::serialize(after_sign) {
            return Err(WalletError::L2(
                "Fast Pay signer changed another required signature".into(),
            ));
        }
    }
    if local_slots != 1 {
        return Err(WalletError::L2(
            "Fast Pay bill must contain exactly one local signing slot".into(),
        ));
    }
    Ok(())
}

fn validate_client_operation_identity(identity: &ClientOperationIdentity<'_>) -> WalletResult<()> {
    let operation_id = identity.operation_id.trim();
    let parsed = uuid::Uuid::parse_str(operation_id)
        .map_err(|_| WalletError::L2("Fast Pay operation ID must be a canonical UUID".into()))?;
    if parsed.to_string() != operation_id
        || identity.idempotency_key.is_empty()
        || identity.idempotency_key.len() > 256
        || identity.idempotency_key.chars().any(char::is_control)
    {
        return Err(WalletError::L2(
            "Fast Pay operation identity is invalid or non-canonical".into(),
        ));
    }
    Ok(())
}

fn validate_owner_authority_commitment(commitment: &str) -> WalletResult<()> {
    if commitment.len() == 64
        && commitment
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WalletError::L2(
            "restricted signer authority commitment must be lowercase SHA-256 hex".into(),
        ))
    }
}

pub(crate) fn validate_restricted_sender_authority(
    authority: &RestrictedSenderAuthority,
    network_mode: &str,
    amount_units: u64,
) -> WalletResult<()> {
    validate_owner_authority_commitment(&authority.owner_authority_commitment)?;
    validate_owner_authority_commitment(&authority.approval_commitment)?;
    validate_owner_authority_commitment(&authority.binding_commitment)?;
    validate_owner_authority_commitment(&authority.genesis_identifier)?;
    validate_owner_authority_commitment(&authority.node_profile_id)?;
    let valid_network = matches!(
        (network_mode, authority.chain_id),
        ("mainnet", 0) | ("testnet", 1..=u32::MAX)
    );
    if authority.agent_id.is_empty()
        || authority.agent_id.len() > 256
        || authority.agent_id.chars().any(char::is_control)
        || authority.agent_authorization_epoch == 0
        || authority.policy_epoch == 0
        || authority.signer_epoch == 0
        || authority.emergency_epoch == 0
        || authority.approval_expires_at == 0
        || authority.hub_url.is_empty()
        || authority.hub_url.len() > 2_048
        || authority.hub_url.chars().any(char::is_control)
        || authority.channel_open_height == 0
        || !valid_network
        || authority.network_instance_id.is_empty()
        || authority.network_instance_id.len() > 256
        || authority.network_instance_id.chars().any(char::is_control)
        || authority.transaction_format_version == 0
        || authority.fee_payer != "sender"
        || authority.network_fee_units != 0
        || authority.wallet_fee_units != 0
        || authority.hub_fee_units != 0
        || authority.total_debit_units != amount_units
    {
        return Err(WalletError::L2(
            "restricted signer authority context is invalid or charges a fee".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn safety_directory(wallet_scope: &str, hub_identity: &str, channel_id: &str) -> PathBuf {
    scoped_safety_directory(
        &wallet_data_root().join("l2").join("personal"),
        wallet_scope,
        "mainnet",
        hub_identity,
        channel_id,
    )
}

fn scoped_safety_directory(
    trusted_l2_root: &Path,
    wallet_scope: &str,
    network_mode: &str,
    hub_identity: &str,
    channel_id: &str,
) -> PathBuf {
    let mut digest = Sha256::new();
    // Legacy domain kept intentionally so existing Personal Wallet journals
    // stay at the same path. The trusted root and authenticated wallet_scope
    // provide the Personal/Agent separation for scoped stores.
    digest.update(b"HPAY/L2/PERSONAL/STORE/V1");
    hash_field(&mut digest, wallet_scope.as_bytes());
    if network_mode != "mainnet" {
        hash_field(&mut digest, b"network");
        hash_field(&mut digest, network_mode.as_bytes());
    }
    hash_field(&mut digest, hub_identity.as_bytes());
    hash_field(&mut digest, channel_id.as_bytes());
    trusted_l2_root.join(hex::encode(digest.finalize()))
}

pub(crate) fn derive_journal_key(
    account: &WalletAccount,
    wallet_scope: &str,
    network_mode: &str,
    hub_identity: &str,
    channel_id: &str,
) -> WalletResult<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new(account.inner().secret_key().serialize());
    let mut salt = Sha256::new();
    salt.update(KEY_DOMAIN);
    hash_field(&mut salt, wallet_scope.as_bytes());
    if network_mode != "mainnet" {
        hash_field(&mut salt, b"network");
        hash_field(&mut salt, network_mode.as_bytes());
    }
    hash_field(&mut salt, hub_identity.as_bytes());
    hash_field(&mut salt, channel_id.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), secret.as_slice());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(KEY_DOMAIN, output.as_mut())
        .map_err(|_| WalletError::L2("L2 journal key derivation failed".into()))?;
    secret.zeroize();
    Ok(output)
}

fn initialize_state(
    path: &Path,
    state: &mut ClientL2State,
    journal: &AuthenticatedJournal,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
) -> WalletResult<()> {
    let had_authenticated_state = state.schema_version != 0
        || state.journal_sequence != 0
        || !state.journal_head.is_empty()
        || !state.state_commitment.is_empty();
    let records = journal.verify().map_err(l2_hub_error)?;
    let checkpoint = journal.read_checkpoint().map_err(l2_hub_error)?;
    if records.is_empty() {
        if had_authenticated_state || checkpoint.is_some() {
            return Err(WalletError::L2("JournalSequenceRollback".into()));
        }
        state.schema_version = 1;
        let current = state_commitment(state)?;
        let now = unix_timestamp();
        let record = journal
            .append(JournalEvent {
                wallet_scope: wallet_scope.to_owned(),
                hub_or_provider_identity: hub_identity.to_owned(),
                channel_id: channel_id.to_owned(),
                channel_reuse_version: 0,
                operation_id: "personal-l2-store-v1".into(),
                operation_type: JournalOperationType::Migration,
                operation_phase: JournalPhase::RecoveryCompleted,
                amount_units: 0,
                sender: String::new(),
                recipient: String::new(),
                previous_state_commitment: current.clone(),
                new_state_commitment: current.clone(),
                idempotency_key: "personal-l2-store-v1".into(),
                request_commitment: current.clone(),
                expected_bill_number: None,
                unsigned_state_commitment: None,
                created_at: now,
            })
            .map_err(l2_hub_error)?;
        state.schema_version = 1;
        state.journal_sequence = record.entry_sequence;
        state.journal_head = record.entry_hash.clone();
        state.state_commitment = current.clone();
        save_state(path, state)?;
        journal
            .write_checkpoint(&JournalHead {
                sequence: record.entry_sequence,
                entry_hash: record.entry_hash,
                state_commitment: current,
            })
            .map_err(l2_hub_error)?;
        return Ok(());
    }
    if state.schema_version != 1 {
        return Err(WalletError::L2(
            "authenticated Personal Wallet L2 state schema is invalid".into(),
        ));
    }
    let current = state_commitment(state)?;
    let last = records
        .last()
        .ok_or_else(|| WalletError::L2("L2 journal head is missing".into()))?;
    if checkpoint
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.sequence > last.entry_sequence)
    {
        return Err(WalletError::L2("JournalSequenceRollback".into()));
    }
    if state.journal_sequence != last.entry_sequence
        || state.journal_head != last.entry_hash
        || state.state_commitment != current
        || last.new_state_commitment != current
    {
        return Err(WalletError::L2(
            "RecoveryRequired: L2 journal and materialized state differ".into(),
        ));
    }
    Ok(())
}

fn load_state(path: &Path) -> WalletResult<ClientL2State> {
    if !path.exists() {
        return Ok(ClientL2State::default());
    }
    let metadata = fs::metadata(path).map_err(l2_io)?;
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(WalletError::L2("L2 operation state is oversized".into()));
    }
    let bytes = fs::read(path).map_err(l2_io)?;
    serde_json::from_slice(&bytes).map_err(|error| WalletError::L2(error.to_string()))
}

fn save_state(path: &Path, state: &ClientL2State) -> WalletResult<()> {
    let bytes = serde_json::to_vec(state).map_err(|error| WalletError::L2(error.to_string()))?;
    secure_write(path, &bytes).map_err(l2_io)
}

fn state_commitment(state: &ClientL2State) -> WalletResult<String> {
    let mut value =
        serde_json::to_value(state).map_err(|error| WalletError::L2(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| WalletError::L2("L2 state is not an object".into()))?;
    object.remove("journal_sequence");
    object.remove("journal_head");
    object.remove("state_commitment");
    let bytes = serde_json::to_vec(&value).map_err(|error| WalletError::L2(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn acquire_lock(path: &Path) -> WalletResult<fs::File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(l2_io)?;
    file.try_lock_exclusive()
        .map_err(|_| WalletError::L2("another wallet process owns this L2 channel state".into()))?;
    Ok(file)
}

fn intent_commitment(
    payer: &str,
    payee: &str,
    amount: &str,
    network_mode: &str,
    channel_id: &str,
    hub_identity: &str,
) -> String {
    digest_fields(
        b"HPAY/L2/PERSONAL/INTENT/V1",
        &[payer, payee, amount, network_mode, channel_id, hub_identity],
    )
}

fn request_commitment(
    operation_id: &str,
    payer: &str,
    payee: &str,
    amount: &str,
    network_mode: &str,
    channel_id: &str,
) -> String {
    digest_fields(
        b"HPAY/L2/FAST-PAY/REQUEST/V1",
        &[
            operation_id,
            payer,
            payee,
            amount,
            network_mode,
            channel_id,
            "sender",
        ],
    )
}

fn validate_network_mode(network_mode: &str) -> WalletResult<()> {
    if matches!(network_mode, "mainnet" | "testnet") {
        Ok(())
    } else {
        Err(WalletError::L2(
            "Fast Pay network mode must be mainnet or testnet".into(),
        ))
    }
}

fn network_bound_scope(wallet_scope: &str, network_mode: &str) -> String {
    if network_mode == "mainnet" {
        // Mainnet keeps the historical authenticated scope and key/path
        // derivation. Testnet is explicitly qualified, so the two can never
        // open or authenticate each other's state.
        wallet_scope.to_owned()
    } else {
        format!("{wallet_scope}@{network_mode}")
    }
}

fn digest_fields(domain: &[u8], fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        hash_field(&mut digest, field.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn l2_io(error: std::io::Error) -> WalletError {
    WalletError::L2(error.to_string())
}

fn l2_hub_error(error: l2_fast_pay_hub::HubError) -> WalletError {
    WalletError::L2(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;
    use field::{Fixed33, Fixed64, Sign};
    use l2_fast_pay_hub::amount::HacAmount;
    use l2_fast_pay_hub::channel_id::derive_channel_id;
    use l2_fast_pay_hub::node::{ChannelInfo, ChannelPartyBalance, ChannelSide};
    use l2_fast_pay_hub::wire::{ChannelWireInput, build_same_channel_bill};
    use sys::Account;

    fn unsigned_bill(account: &WalletAccount) -> (String, String) {
        let hub = Account::create_by("client-safety-hub").unwrap();
        let channel_id = derive_channel_id(&account.address(), hub.readable(), 1);
        let channel = ChannelInfo {
            ret: 0,
            id: channel_id.clone(),
            status: 0,
            open_height: 100,
            close_height: 0,
            reuse_version: 1,
            left: ChannelPartyBalance {
                address: account.address(),
                hacash: "10".into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: hub.readable().to_owned(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        };
        let mut document = build_same_channel_bill(
            &ChannelWireInput {
                channel,
                channel_id_hex: channel_id,
                left_balance_mei: HacAmount::from_millimeis(9_000),
                right_balance_mei: HacAmount::from_millimeis(1_000),
                left_satoshi: 0,
                right_satoshi: 0,
                bill_auto_number: 1,
            },
            ChannelSide::Left,
            HacAmount::from_millimeis(1_000),
            1_700_000_000,
        )
        .unwrap();
        document.chain_payment.fill_sign_by_account(&hub).unwrap();
        let unsigned = document.to_bill_hex();
        document
            .chain_payment
            .fill_sign_by_account(account.inner())
            .unwrap();
        (unsigned, document.to_bill_hex())
    }

    #[test]
    fn same_intent_resumes_and_conflicting_channel_operation_is_blocked() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-safety-test").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let first = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let resumed = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        assert_eq!(first.operation_id, resumed.operation_id);
        assert!(
            safety
                .begin_or_resume(&account.address(), "other", "1.000", 1_000, 1)
                .is_err()
        );
    }

    #[test]
    fn stable_identity_resumes_exactly_after_restart() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-stable-identity").unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("agent:{}", uuid::Uuid::new_v4());
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let first = safety
            .begin_or_resume_with_identity(
                ClientOperationIdentity {
                    operation_id: &operation_id,
                    idempotency_key: &idempotency_key,
                },
                &account.address(),
                "payee",
                "1.000",
                1_000,
                1,
            )
            .unwrap();
        drop(safety);

        let mut reopened = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let resumed = reopened
            .begin_or_resume_with_identity(
                ClientOperationIdentity {
                    operation_id: &operation_id,
                    idempotency_key: &idempotency_key,
                },
                &account.address(),
                "payee",
                "1.000",
                1_000,
                1,
            )
            .unwrap();
        assert_eq!(first, resumed);
    }

    #[test]
    fn stable_identity_rejects_aliases_mutation_and_parallel_intent() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-stable-conflict").unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("agent:{}", uuid::Uuid::new_v4());
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        safety
            .begin_or_resume_with_identity(
                ClientOperationIdentity {
                    operation_id: &operation_id,
                    idempotency_key: &idempotency_key,
                },
                &account.address(),
                "payee",
                "1.000",
                1_000,
                1,
            )
            .unwrap();

        let another_id = uuid::Uuid::new_v4().to_string();
        assert!(
            safety
                .begin_or_resume_with_identity(
                    ClientOperationIdentity {
                        operation_id: &another_id,
                        idempotency_key: &idempotency_key,
                    },
                    &account.address(),
                    "payee",
                    "1.000",
                    1_000,
                    1,
                )
                .is_err()
        );
        assert!(
            safety
                .begin_or_resume_with_identity(
                    ClientOperationIdentity {
                        operation_id: &operation_id,
                        idempotency_key: &idempotency_key,
                    },
                    &account.address(),
                    "changed-payee",
                    "1.000",
                    1_000,
                    1,
                )
                .is_err()
        );
        assert!(
            safety
                .begin_or_resume_with_identity(
                    ClientOperationIdentity {
                        operation_id: &operation_id.to_uppercase(),
                        idempotency_key: &idempotency_key,
                    },
                    &account.address(),
                    "payee",
                    "1.000",
                    1_000,
                    1,
                )
                .is_err()
        );
        assert!(
            safety
                .begin_or_resume_with_identity(
                    ClientOperationIdentity {
                        operation_id: &uuid::Uuid::new_v4().to_string(),
                        idempotency_key: "agent:\ninvalid",
                    },
                    &account.address(),
                    "payee",
                    "2.000",
                    2_000,
                    1,
                )
                .is_err()
        );
    }

    #[test]
    fn durable_sender_operation_rejects_every_request_alias() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-request-binding").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let operation = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 7)
            .unwrap();
        safety
            .require_exact_sender_request(
                &operation.operation_id,
                &operation.idempotency_key,
                &account.address(),
                "payee",
                "1.000",
                1_000,
                "channel",
                7,
                "hub",
            )
            .unwrap();
        for changed in [
            ("wrong-idempotency", "payee", "1.000", 1_000_u64, 7_u64),
            (
                operation.idempotency_key.as_str(),
                "other-payee",
                "1.000",
                1_000,
                7,
            ),
            (
                operation.idempotency_key.as_str(),
                "payee",
                "1.001",
                1_001,
                7,
            ),
            (
                operation.idempotency_key.as_str(),
                "payee",
                "1.000",
                1_000,
                8,
            ),
        ] {
            assert!(
                safety
                    .require_exact_sender_request(
                        &operation.operation_id,
                        changed.0,
                        &account.address(),
                        changed.1,
                        changed.2,
                        changed.3,
                        "channel",
                        changed.4,
                        "hub",
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn scoped_personal_and_agent_stores_cannot_read_lock_or_mutate_each_other() {
        let directory = tempfile::tempdir().unwrap();
        let personal_root = directory.path().join("personal-l2");
        let agent_root = directory.path().join("agent-l2");
        let account = WalletAccount::create("l2-scoped-isolation").unwrap();
        let personal_scope = format!("personal:{}", account.address());
        let agent_scope = "agent_wallet:wallet-one";

        let mut personal = ClientL2Safety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        let mut agent = ClientL2Safety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();

        assert!(personal.path.starts_with(&personal_root));
        assert!(agent.path.starts_with(&agent_root));
        assert_ne!(personal.path, agent.path);

        let personal_operation = personal
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        assert!(agent.operation(&personal_operation.operation_id).is_err());
        assert!(
            agent
                .mark_recovery_required(&personal_operation.operation_id)
                .is_err()
        );
        assert_eq!(
            personal
                .operation(&personal_operation.operation_id)
                .unwrap()
                .status,
            ClientOperationStatus::PaymentIntentCreated
        );

        let agent_operation = agent
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        assert!(personal.operation(&agent_operation.operation_id).is_err());
        drop(personal);
        drop(agent);

        let personal = ClientL2Safety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        let agent = ClientL2Safety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        assert!(personal.operation(&personal_operation.operation_id).is_ok());
        assert!(personal.operation(&agent_operation.operation_id).is_err());
        assert!(agent.operation(&agent_operation.operation_id).is_ok());
        assert!(agent.operation(&personal_operation.operation_id).is_err());
    }

    #[test]
    fn mainnet_and_testnet_stores_have_distinct_paths_keys_and_operations() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("network-scoped-l2");
        let account = WalletAccount::create("l2-network-isolation").unwrap();
        let scope = format!("personal:{}", account.address());
        let mut mainnet = ClientL2Safety::open_scoped_for_network(
            &account, &root, &scope, "mainnet", "hub", "channel",
        )
        .unwrap();
        let mut testnet = ClientL2Safety::open_scoped_for_network(
            &account, &root, &scope, "testnet", "hub", "channel",
        )
        .unwrap();
        assert_ne!(mainnet.path, testnet.path);
        let mainnet_operation = mainnet
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let testnet_operation = testnet
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        assert_eq!(mainnet_operation.network_mode, "mainnet");
        assert_eq!(testnet_operation.network_mode, "testnet");
        assert_ne!(
            mainnet_operation.intent_commitment,
            testnet_operation.intent_commitment
        );
        assert!(mainnet.operation(&testnet_operation.operation_id).is_err());
        assert!(testnet.operation(&mainnet_operation.operation_id).is_err());
    }

    #[test]
    fn different_wallet_key_cannot_authenticate_operation_state() {
        let _isolated = IsolatedWalletData::new();
        let first = WalletAccount::create("l2-safety-first").unwrap();
        let mut safety = ClientL2Safety::open(&first, "hub", "channel").unwrap();
        safety
            .begin_or_resume(&first.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let directory =
            safety_directory(&format!("personal:{}", first.address()), "hub", "channel");
        drop(safety);
        let wrong_key = [7_u8; 32];
        assert!(
            AuthenticatedJournal::open(
                directory.join("operations.journal.jsonl"),
                &wrong_key,
                JournalBinding {
                    wallet_scope: format!("personal:{}", first.address()),
                    hub_or_provider_identity: "hub".into(),
                    channel_id: Some("channel".into()),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn signature_is_impossible_to_persist_before_the_unsigned_state_is_durable() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-signature-order").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let operation = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let (unsigned, signed) = unsigned_bill(&account);
        assert!(
            safety
                .persist_signature(&operation.operation_id, &signed)
                .is_err()
        );
        safety
            .persist_before_signing(&operation.operation_id, &unsigned)
            .unwrap();
        safety
            .persist_signature(&operation.operation_id, &signed)
            .unwrap();
        drop(safety);

        let reopened = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let recovered = reopened.operation(&operation.operation_id).unwrap();
        assert_eq!(recovered.status, ClientOperationStatus::Signed);
        assert_eq!(recovered.signed_bill_hex.as_deref(), Some(signed.as_str()));
    }

    #[test]
    fn unsigned_input_cannot_be_recorded_as_a_local_signature() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-signature-verification").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let operation = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let (unsigned, _) = unsigned_bill(&account);
        safety
            .persist_before_signing(&operation.operation_id, &unsigned)
            .unwrap();
        let error = safety
            .persist_signature(&operation.operation_id, &unsigned)
            .unwrap_err()
            .to_string();
        assert!(error.contains("local signature"), "{error}");
    }

    #[test]
    fn signer_cannot_change_an_existing_non_local_signature() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-signature-slot-isolation").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let operation = safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let (unsigned, signed) = unsigned_bill(&account);
        safety
            .persist_before_signing(&operation.operation_id, &unsigned)
            .unwrap();
        let mut malicious = ChannelPayCompleteDocuments::from_bill_hex(&signed).unwrap();
        let non_local = malicious
            .chain_payment
            .must_sign_addresses
            .iter()
            .position(|address| address.to_readable() != account.address())
            .unwrap();
        malicious.chain_payment.must_signs[non_local] = Sign {
            publickey: Fixed33::default(),
            signature: Fixed64::default(),
        };
        let error = safety
            .persist_signature(&operation.operation_id, &malicious.to_bill_hex())
            .unwrap_err()
            .to_string();
        assert!(error.contains("another required signature"), "{error}");
    }

    #[test]
    fn tampered_materialized_state_fails_closed_on_restart() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-tamper-state").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        safety
            .begin_or_resume(&account.address(), "payee", "1.000", 1_000, 1)
            .unwrap();
        let path = safety.path.clone();
        drop(safety);
        let mut raw = fs::read_to_string(&path).unwrap();
        raw = raw.replace("\"amount_units\":1000", "\"amount_units\":1001");
        fs::write(&path, raw).unwrap();
        assert!(ClientL2Safety::open(&account, "hub", "channel").is_err());
    }

    #[test]
    fn unresolved_store_has_a_single_process_owner() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-client-lock").unwrap();
        let first = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        assert!(ClientL2Safety::open(&account, "hub", "channel").is_err());
        drop(first);
        assert!(ClientL2Safety::open(&account, "hub", "channel").is_ok());
    }

    #[test]
    fn deleting_the_client_journal_is_detected() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-deleted-client-journal").unwrap();
        let safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let directory = safety.path.parent().unwrap().to_path_buf();
        drop(safety);
        fs::remove_file(directory.join("operations.journal.jsonl")).unwrap();
        let error = ClientL2Safety::open(&account, "hub", "channel")
            .err()
            .expect("deleted authenticated journal must fail closed");
        assert!(error.to_string().contains("JournalSequenceRollback"));
    }

    #[test]
    fn signed_and_uncertain_states_require_explicit_reconciliation() {
        assert!(!ClientOperationStatus::PaymentIntentCreated.requires_explicit_reconciliation());
        assert!(!ClientOperationStatus::PersistedBeforeSigning.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::Signed.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::Submitted.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::AwaitingRecipient.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::RecoveryRequired.requires_explicit_reconciliation());
        assert!(!ClientOperationStatus::Committed.requires_explicit_reconciliation());
    }

    #[test]
    fn restricted_sender_authority_is_durable_exact_and_never_added_late() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("l2-restricted-authority").unwrap();
        let mut safety = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = "hpay-agent:restricted-authority";
        let authority = RestrictedSenderAuthority {
            owner_authority_commitment: "ab".repeat(32),
            approval_commitment: "cd".repeat(32),
            agent_id: "agent-1".to_owned(),
            agent_authorization_epoch: 1,
            policy_epoch: 1,
            signer_epoch: 1,
            emergency_epoch: 1,
            approval_expires_at: u64::MAX,
            hub_url: "https://hub.example".to_owned(),
            channel_open_height: 1,
            binding_commitment: "ef".repeat(32),
            chain_id: 0,
            genesis_identifier: "01".repeat(32),
            node_profile_id: "02".repeat(32),
            network_instance_id: "mainnet-v1".to_owned(),
            transaction_format_version: 2,
            fee_payer: "sender".to_owned(),
            network_fee_units: 0,
            wallet_fee_units: 0,
            hub_fee_units: 0,
            total_debit_units: 1_000,
        };
        let operation = safety
            .begin_or_resume_restricted_sender(
                ClientOperationIdentity {
                    operation_id: &operation_id,
                    idempotency_key,
                },
                authority.clone(),
                &account.address(),
                "payee",
                "1.000",
                1_000,
                1,
            )
            .unwrap();
        assert_eq!(
            operation.owner_authority_commitment.as_deref(),
            Some(authority.owner_authority_commitment.as_str())
        );
        assert_eq!(
            operation.restricted_sender_authority.as_ref(),
            Some(&authority)
        );
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut value = authority.clone();
                value.$field = $value;
                value
            }};
        }
        let changed_authorities = vec![
            changed!(owner_authority_commitment, "11".repeat(32)),
            changed!(approval_commitment, "12".repeat(32)),
            changed!(agent_id, "agent-2".to_owned()),
            changed!(agent_authorization_epoch, 2),
            changed!(policy_epoch, 2),
            changed!(signer_epoch, 2),
            changed!(emergency_epoch, 2),
            changed!(approval_expires_at, u64::MAX - 1),
            changed!(hub_url, "https://other-hub.example".to_owned()),
            changed!(channel_open_height, 2),
            changed!(binding_commitment, "13".repeat(32)),
            changed!(chain_id, 7),
            changed!(genesis_identifier, "14".repeat(32)),
            changed!(node_profile_id, "15".repeat(32)),
            changed!(network_instance_id, "mainnet-v2".to_owned()),
            changed!(transaction_format_version, 3),
            changed!(fee_payer, "recipient".to_owned()),
            changed!(network_fee_units, 1),
            changed!(wallet_fee_units, 1),
            changed!(hub_fee_units, 1),
            changed!(total_debit_units, 1_001),
        ];
        for changed_authority in changed_authorities {
            assert!(
                safety
                    .begin_or_resume_restricted_sender(
                        ClientOperationIdentity {
                            operation_id: &operation_id,
                            idempotency_key,
                        },
                        changed_authority,
                        &account.address(),
                        "payee",
                        "1.000",
                        1_000,
                        1,
                    )
                    .is_err()
            );
        }
        drop(safety);

        let reopened = ClientL2Safety::open(&account, "hub", "channel").unwrap();
        assert_eq!(
            reopened
                .operation(&operation_id)
                .unwrap()
                .owner_authority_commitment
                .as_deref(),
            Some(authority.owner_authority_commitment.as_str())
        );
        assert_eq!(
            reopened
                .operation(&operation_id)
                .unwrap()
                .restricted_sender_authority
                .as_ref(),
            Some(&authority)
        );
    }
}
