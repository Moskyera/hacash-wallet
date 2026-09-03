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

use field::Parse as FieldParse;
use field::Serialize as FieldSerialize;
use fs2::FileExt;
use hkdf::Hkdf;
use l2_fast_pay_hub::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use l2_fast_pay_hub::rollback_anchor::SignedHubWitnessReceiptV1;
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::hvm_registry_exit::{HvmRegistryExitKitV1, HvmRegistryExitStep};
use crate::hvm_registry_exit_record::{
    HvmRegistryExitIntentV1, HvmRegistryExitPhase, HvmRegistryExitResumeV1,
    PersistedHvmRegistryExitStepV1, REFUSAL_EXIT_STEP_BLOCKED, exit_record_key, resume_action,
    validate_persisted_exit_step,
};
use crate::l2_signer::FastPayJournalKeyProvider;
use crate::l2_storage_scope::validate_scoped_l2_storage;
use crate::paths::{secure_write, wallet_data_root};

const KEY_DOMAIN: &[u8] = b"HPAY/L2/JOURNAL/AUTH/V1";

/// A `field::Sign` on the wire: compressed public key plus signature.
const ANCHOR_SIGN_WIRE_BYTES: usize = 33 + 64;

/// A bill carries one receipt per witness. The Hub client is single-witness
/// today; the cap exists so a Hub cannot make the decision prompt unreadable
/// by padding it.
const MAX_ANCHOR_RECEIPTS_PER_BILL: usize = 8;

/// Stable prefix on the error returned when the Hub's witness set has shrunk
/// and a human must answer before the channel can advance. Callers match on
/// this to route the parked decision to a user interface; the evidence itself
/// is durable and is read back with
/// [`ClientL2Safety::pending_anchor_decision`].
pub const ANCHOR_WITNESS_DECISION_REQUIRED: &str = "AnchorWitnessChangeRequiresDecision";

/// Reused deliberately from `rollback_anchor::protocol` rather than invented
/// here: a witness this wallet remembers has contradicted itself, and the
/// operator procedure is the same Procedure B the Hub-side refusal indexes.
pub const REFUSAL_WITNESS_BEHIND_HUB: &str = "rollback_anchor_witness_behind_hub";

/// This wallet's own anchor memory is behind this wallet's own payment
/// history.
///
/// The counterparty ratchet lives in one store. That store is a file on the
/// counterparty's disk, and a file can be deleted or restored from an older
/// coherent snapshot — journal, checkpoint and state together — which opens
/// clean because nothing inside it is inconsistent. Whoever can restore the
/// Hub's state can usually also reach this one.
///
/// So the ratchet is anchored a second time, outside itself: the caller states
/// the highest serial it knows this channel reached, taken from a store this
/// one does not own (Agent Wallet's own encrypted operation state, under a
/// different key, with its own journal). A memory that is missing or behind
/// that number was lost or rewound, and this refuses rather than quietly
/// re-baselining. It is not a witness-set change, so it is not a user
/// decision: it is an integrity failure, and the honest answer is to stop.
pub const REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET: &str = "rollback_anchor_memory_behind_wallet";

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
    /// Per-channel memory of the external rollback-anchor witnesses this
    /// wallet has provably seen receipt a bill on this channel.
    ///
    /// Keyed by `binding_commitment`, not `channel_id`: the binding carries
    /// the reuse version, and a new incarnation is a genuinely new channel
    /// that legitimately starts a fresh ratchet.
    ///
    /// `skip_serializing_if` is load bearing and not cosmetic. Every existing
    /// store on disk was written without this key; if an empty map were
    /// emitted, `state_commitment` would change for every one of them and
    /// [`initialize_state`] would refuse to open them with
    /// "RecoveryRequired: L2 journal and materialized state differ". Skipping
    /// the empty map keeps the serialized bytes byte-identical to what the
    /// previous version wrote.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    anchor_witness_memory: BTreeMap<String, ChannelAnchorMemoryV1>,
    /// One durable record per `(binding_commitment, step)` of a user-side
    /// unilateral registry exit, keyed by
    /// [`crate::hvm_registry_exit_record::exit_record_key`].
    ///
    /// This is what makes an exit survive the wallet closing. Everything the
    /// resume path needs is here — the call source and its commitment, the
    /// exact signed bytes, the transaction hash, the chain as it was read
    /// before signing, and the phase — so a reopened wallet can find out
    /// whether the transaction it signed last time was mined instead of
    /// signing a second one.
    ///
    /// `skip_serializing_if` is load bearing for the same reason it is on
    /// `anchor_witness_memory`: every store already on disk was written
    /// without this key, and emitting an empty map would change
    /// `state_commitment` for all of them and make [`initialize_state`] refuse
    /// to open them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    exit_operations: BTreeMap<String, PersistedHvmRegistryExitStepV1>,
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

/// One witness the wallet has *provably* seen sign an anchor receipt for one
/// exact channel.
///
/// `signer_address` is recovered from the signature, never copied off the
/// wire. `witness_id` is a label the Hub typed (`is_identifier` is its only
/// validation, `rollback_anchor/protocol.rs:93-95`); it is kept as evidence
/// for a human and is never part of the overlap key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorWitnessRecordV1 {
    pub signer_address: String,
    pub witness_instance_id: String,
    pub witness_id: String,
    pub witness_epoch: u64,
    pub first_seen_serial: u64,
    pub last_seen_serial: u64,
    pub highest_counter_value: u64,
}

impl AnchorWitnessRecordV1 {
    /// The overlap identity: the pair `(verified signer address, witness
    /// store instance)`.
    ///
    /// The instance is in the key deliberately. Re-provisioning a witness
    /// store with the same key yields the same address with a counter back at
    /// zero — the amnesia attack. Keyed on the address alone that attack would
    /// pass overlap silently; keyed on the pair it is a drop, and therefore
    /// exactly as loud as a witness swap.
    pub fn overlap_key(&self) -> String {
        format!("{}|{}", self.signer_address, self.witness_instance_id)
    }
}

/// The evidence shown to a human when the Hub's witness set has shrunk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorWitnessChangeV1 {
    pub binding_commitment: String,
    pub hub_identity: String,
    pub serial: u64,
    pub proposed_bill_commitment: String,
    pub last_accepted_serial: u64,
    pub last_accepted_bill_commitment: String,
    pub dropped: Vec<AnchorWitnessRecordV1>,
    pub retained: Vec<AnchorWitnessRecordV1>,
    pub offered: Vec<AnchorWitnessRecordV1>,
    pub raised_at: u64,
}

impl AnchorWitnessChangeV1 {
    pub fn is_zero_overlap(&self) -> bool {
        self.retained.is_empty()
    }

    /// The sentence a human is shown. Deliberately concrete: this is the only
    /// moment at which the counterparty can tell a legitimate witness rotation
    /// apart from a Hub swapping its witness in order to re-sign history, and
    /// a warning icon does not carry enough information to decide.
    pub fn headline(&self) -> String {
        if self.is_zero_overlap() {
            "this Hub no longer shares any witness with the one that signed your last bill"
                .to_owned()
        } else {
            format!(
                "this Hub has stopped using {} of the witnesses that signed your last bill; {} of {} still cover it",
                self.dropped.len(),
                self.retained.len(),
                self.dropped.len() + self.retained.len()
            )
        }
    }
}

/// The only two answers. There is deliberately no third: no "ask me later and
/// proceed", no timeout that picks one, no configuration default.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorWitnessDecision {
    /// The new set becomes the baseline. Dropped witnesses are retired, not
    /// erased, so the event survives in the record and in the journal.
    AcceptNewWitnessSet,
    /// The channel is marked closing. The cooperative close runs against the
    /// last accepted head, which keeps its intact receipt set.
    CloseChannel,
}

/// What a human actually chose, kept durably beside the memory it changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorWitnessResolutionV1 {
    pub change: AnchorWitnessChangeV1,
    pub decision: AnchorWitnessDecision,
    pub decided_at: u64,
}

/// Everything this wallet remembers about the external rollback anchor
/// covering one exact channel incarnation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelAnchorMemoryV1 {
    pub schema_version: u32,
    pub hub_identity: String,
    pub accepted_serial: u64,
    pub accepted_bill_commitment: String,
    pub witnesses: BTreeMap<String, AnchorWitnessRecordV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub retired: BTreeMap<String, AnchorWitnessRecordV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_decision: Option<AnchorWitnessChangeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_decision: Option<AnchorWitnessResolutionV1>,
    #[serde(default, skip_serializing_if = "is_not_closing")]
    pub closing: bool,
}

fn is_not_closing(closing: &bool) -> bool {
    !*closing
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

    /// Read back the parked witness-set decision for one channel, if any.
    ///
    /// This is the only supported way to obtain the evidence a human needs.
    /// It is deliberately a plain read: the decision is already durable, so a
    /// crashed or killed user interface cannot lose it, and a wallet that
    /// restarts comes back still parked rather than silently advancing.
    pub fn pending_anchor_decision(
        &self,
        binding_commitment: &str,
    ) -> Option<AnchorWitnessChangeV1> {
        self.state
            .anchor_witness_memory
            .get(binding_commitment)
            .and_then(|memory| memory.pending_decision.clone())
    }

    pub fn anchor_memory(&self, binding_commitment: &str) -> Option<ChannelAnchorMemoryV1> {
        self.state
            .anchor_witness_memory
            .get(binding_commitment)
            .cloned()
    }

    /// Verify the anchor receipts riding with one anchored bill, compare the
    /// witness set they prove against what this wallet remembers for this
    /// channel, and advance the channel head only when nothing was dropped.
    ///
    /// `Ok(())` is the *only* way a caller can be told the bill may become the
    /// new head. Returning a verdict alongside the bill was rejected: a caller
    /// that ignores a verdict is one `let _ =` away from a silent accept.
    ///
    /// Three outcomes, and none of them is a bypass:
    ///
    /// * silent accept — nothing recorded disappeared; the memory is advanced
    ///   in one journalled [`Self::transition`]-shaped write and `Ok(())` is
    ///   returned;
    /// * decision required — at least one remembered witness is absent from
    ///   this bill. The change is parked in `pending_decision`, nothing else
    ///   is written, and an error prefixed [`ANCHOR_WITNESS_DECISION_REQUIRED`]
    ///   is returned. The channel does not advance and does not halt;
    /// * hard refusal — a receipt does not verify, is bound to another bill,
    ///   channel or Hub, a remembered witness contradicted itself, or this
    ///   wallet's own memory is behind its own payment history. Nothing is
    ///   written and an error is returned. This is never a user choice.
    ///
    /// An empty `receipts` slice is not "skip the check": it means every
    /// remembered witness was dropped, which is the loudest prompt in the
    /// system. An absent wire field must therefore deserialise to an empty
    /// vector, never to "unknown".
    ///
    /// `independent_serial_floor` is the highest serial the caller knows this
    /// channel reached, read from a store this one does not own. Pass `0` only
    /// when the caller genuinely has no independent record. It is a mandatory
    /// argument rather than an option with a default because a defaulted
    /// hardening argument is a bypass with a nicer name: see
    /// [`REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET`].
    pub fn accept_anchored_bill(
        &mut self,
        binding_commitment: &str,
        hub_identity: &str,
        proposed_bill_commitment: &str,
        serial: u64,
        receipts: &[SignedHubWitnessReceiptV1],
        independent_serial_floor: u64,
    ) -> WalletResult<()> {
        require_anchor_hash(binding_commitment, "channel binding commitment")?;
        require_anchor_hash(proposed_bill_commitment, "proposed bill commitment")?;
        if serial == 0 {
            return Err(WalletError::L2(
                "anchored bill serial must be greater than zero".into(),
            ));
        }
        if hub_identity != self.hub_identity {
            return Err(WalletError::L2(
                "anchored bill was co-signed by a different Hub than this channel store".into(),
            ));
        }
        if receipts.len() > MAX_ANCHOR_RECEIPTS_PER_BILL {
            return Err(WalletError::L2(
                "anchored bill carries more witness receipts than the protocol allows".into(),
            ));
        }

        // Admission runs on every receipt in the envelope. One failure refuses
        // the whole envelope, so a Hub cannot pad with junk to obscure which
        // receipt is the real one.
        let mut offered: BTreeMap<String, AnchorWitnessRecordV1> = BTreeMap::new();
        for receipt in receipts {
            let record = admit_anchor_receipt(
                receipt,
                hub_identity,
                binding_commitment,
                proposed_bill_commitment,
                serial,
            )?;
            if offered.insert(record.overlap_key(), record).is_some() {
                return Err(WalletError::L2(
                    "anchored bill carries two receipts from the same witness instance".into(),
                ));
            }
        }

        let Some(memory) = self
            .state
            .anchor_witness_memory
            .get(binding_commitment)
            .cloned()
        else {
            // No memory. Either this really is the first bill on this channel,
            // or the memory was lost — the store deleted, or restored from an
            // older snapshot that predates this channel. The caller's
            // independent history is what tells the two apart, and it is the
            // only thing that can: everything inside this store agrees with
            // itself in both cases.
            if independent_serial_floor > 0 {
                return Err(WalletError::L2(format!(
                    "{REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET}: this wallet's own payment history \
                     reaches serial {independent_serial_floor} on this channel, but its \
                     rollback-anchor memory for the channel is gone. A missing memory is a lost \
                     memory, not a new channel, and re-baselining it here would hand the Hub the \
                     witness set of its choice. Restore the L2 store from the same backup as the \
                     rest of this wallet, or close the channel"
                )));
            }
            // First bill for this binding. No comparison is possible and none
            // is faked: admission still ran in full, the ratchet has nothing
            // to compare against, and the baseline is recorded silently. An
            // empty set here is still recorded, as the durable statement
            // "this Hub showed me no anchor at serial N" — that is what stops
            // a later Hub resetting the ratchet by omission.
            let memory = ChannelAnchorMemoryV1 {
                schema_version: 1,
                hub_identity: hub_identity.to_owned(),
                accepted_serial: serial,
                accepted_bill_commitment: proposed_bill_commitment.to_owned(),
                witnesses: offered,
                retired: BTreeMap::new(),
                pending_decision: None,
                last_decision: None,
                closing: false,
            };
            return self.write_anchor_memory(
                binding_commitment,
                memory,
                serial,
                proposed_bill_commitment,
                JournalPhase::RollbackAnchorReceiptPersisted,
            );
        };

        if memory.hub_identity != hub_identity {
            return Err(WalletError::L2(
                "anchor memory for this channel was established under a different Hub".into(),
            ));
        }
        // The second anchor, and the reason this store is not its own only
        // witness. A coherent older triple — state, journal, checkpoint —
        // opens clean, because nothing in it is inconsistent; it is simply
        // behind. The caller's independent history is in a different store,
        // under a different key, and was not in that backup set.
        if independent_serial_floor > memory.accepted_serial {
            return Err(WalletError::L2(format!(
                "{REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET}: this wallet's own payment history reaches \
                 serial {independent_serial_floor} on this channel but its rollback-anchor memory \
                 stops at serial {}. This store went backwards, which a restore from an older \
                 backup is the usual cause of. Nothing was accepted",
                memory.accepted_serial
            )));
        }
        if memory.closing {
            return Err(WalletError::L2(
                "this channel is closing on its last accepted head and will not advance".into(),
            ));
        }
        if let Some(pending) = &memory.pending_decision {
            return Err(WalletError::L2(format!(
                "{ANCHOR_WITNESS_DECISION_REQUIRED}: this channel is parked at serial {} awaiting an answer about its rollback-anchor witnesses",
                pending.serial
            )));
        }

        // Re-affirming the exact head already recorded is the crash window
        // between the Hub co-signing and this wallet persisting; without a way
        // through it a wallet that died there could never accept that head
        // again and the channel would be stuck with no honest way out.
        //
        // It is a *narrower* door than it looks, and deliberately not the
        // first thing checked. An earlier draft returned `Ok(())` here before
        // the counter ratchet and the drop comparison had run, which made the
        // recorded head the one place a bill was handed back as accepted with
        // the whole rule skipped — a Hub could re-serve the head with an empty
        // receipt list, or with a witness whose counter had gone backwards
        // after a Hub+witness co-restore, and be told yes. Everything below
        // therefore runs first, and re-affirmation is granted only when the
        // offered set still covers every witness this wallet recorded.
        let is_recorded_head = serial == memory.accepted_serial
            && proposed_bill_commitment == memory.accepted_bill_commitment;
        if !is_recorded_head && serial <= memory.accepted_serial {
            return Err(WalletError::L2(format!(
                "{REFUSAL_WITNESS_BEHIND_HUB}: anchored bill serial {serial} is at or below the accepted head {}",
                memory.accepted_serial
            )));
        }

        // Ratchet. A witness this wallet remembers may not go backwards. The
        // witness counter is global per Hub identity and strictly monotone, so
        // a decrease has no honest reading. This is the check that catches the
        // case ADR-001 declares undetectable Hub-side: an operator restoring
        // Hub and witness together to an earlier point cannot also restore the
        // counterparty's memory, which was in neither backup set.
        //
        // On a re-affirmation of the recorded head the honest Hub replays the
        // *same* receipts, so equality is expected there and only a genuine
        // decrease is refused. Anywhere else the counter must have moved.
        //
        // `retired` is consulted alongside `witnesses`, and that is not a
        // detail. Accepting a witness-set change moves the dropped records to
        // `retired` rather than erasing them, precisely so the event survives
        // - but if only `witnesses` were ratcheted, a witness that had been
        // dropped and accepted away could come back with its counter at zero
        // and be treated as brand new. That is the amnesia attack with one
        // extra step: drop the witness, get the prompt accepted once, then
        // re-offer the same store rebuilt from nothing. The record exists; it
        // has to be read.
        for (key, candidate) in &offered {
            if let Some(known) = memory
                .witnesses
                .get(key)
                .or_else(|| memory.retired.get(key))
            {
                let went_backwards = if is_recorded_head {
                    candidate.highest_counter_value < known.highest_counter_value
                } else {
                    candidate.highest_counter_value <= known.highest_counter_value
                };
                if went_backwards {
                    return Err(WalletError::L2(format!(
                        "{REFUSAL_WITNESS_BEHIND_HUB}: witness {key} presented counter {} at or below the {} this wallet already recorded",
                        candidate.highest_counter_value, known.highest_counter_value
                    )));
                }
            }
        }

        let dropped: Vec<AnchorWitnessRecordV1> = memory
            .witnesses
            .iter()
            .filter(|(key, _)| !offered.contains_key(*key))
            .map(|(_, record)| record.clone())
            .collect();

        if is_recorded_head && dropped.is_empty() {
            // The head is unchanged and still fully covered. Nothing to write.
            return Ok(());
        }

        if dropped.is_empty() {
            let mut next = memory.clone();
            merge_offered_witnesses(&mut next.witnesses, &offered, serial);
            next.accepted_serial = serial;
            next.accepted_bill_commitment = proposed_bill_commitment.to_owned();
            return self.write_anchor_memory(
                binding_commitment,
                next,
                serial,
                proposed_bill_commitment,
                JournalPhase::RollbackAnchorReceiptPersisted,
            );
        }

        // At least one remembered witness disappeared. "At least one survives"
        // was rejected as the predicate: a Hub running its own witness E
        // alongside an honest W would satisfy it forever while dropping W, the
        // only witness that actually holds the serial it wants to re-spend.
        // Dropping one is therefore exactly as loud as dropping all.
        let retained: Vec<AnchorWitnessRecordV1> = memory
            .witnesses
            .iter()
            .filter(|(key, _)| offered.contains_key(*key))
            .map(|(_, record)| record.clone())
            .collect();
        let change = AnchorWitnessChangeV1 {
            binding_commitment: binding_commitment.to_owned(),
            hub_identity: hub_identity.to_owned(),
            serial,
            proposed_bill_commitment: proposed_bill_commitment.to_owned(),
            last_accepted_serial: memory.accepted_serial,
            last_accepted_bill_commitment: memory.accepted_bill_commitment.clone(),
            dropped,
            retained,
            offered: offered.into_values().collect(),
            raised_at: unix_timestamp(),
        };
        let headline = change.headline();
        let mut next = memory;
        next.pending_decision = Some(change);
        self.write_anchor_memory(
            binding_commitment,
            next,
            serial,
            proposed_bill_commitment,
            JournalPhase::RollbackAnchorRefused,
        )?;
        Err(WalletError::L2(format!(
            "{ANCHOR_WITNESS_DECISION_REQUIRED}: {headline}"
        )))
    }

    /// Record the human's answer to a parked witness-set change.
    ///
    /// Both answers are durable and both are journalled. Accepting adopts the
    /// new set as the baseline and retires — never erases — what was dropped,
    /// so the event can still be found afterwards. Closing latches the channel
    /// on its last accepted head, whose receipt set is intact, and never
    /// advances the head.
    pub fn resolve_anchor_witness_change(
        &mut self,
        binding_commitment: &str,
        decision: AnchorWitnessDecision,
    ) -> WalletResult<()> {
        let memory = self
            .state
            .anchor_witness_memory
            .get(binding_commitment)
            .cloned()
            .ok_or_else(|| {
                WalletError::L2("this channel has no rollback-anchor memory to resolve".into())
            })?;
        let change = memory.pending_decision.clone().ok_or_else(|| {
            WalletError::L2("this channel has no parked rollback-anchor decision".into())
        })?;
        let resolution = AnchorWitnessResolutionV1 {
            change: change.clone(),
            decision,
            decided_at: unix_timestamp(),
        };
        let mut next = memory;
        next.pending_decision = None;
        next.last_decision = Some(resolution);
        let phase = match decision {
            AnchorWitnessDecision::AcceptNewWitnessSet => {
                for record in &change.dropped {
                    next.witnesses.remove(&record.overlap_key());
                    next.retired.insert(record.overlap_key(), record.clone());
                }
                let offered: BTreeMap<String, AnchorWitnessRecordV1> = change
                    .offered
                    .iter()
                    .map(|record| (record.overlap_key(), record.clone()))
                    .collect();
                merge_offered_witnesses(&mut next.witnesses, &offered, change.serial);
                next.accepted_serial = change.serial;
                next.accepted_bill_commitment = change.proposed_bill_commitment.clone();
                JournalPhase::RollbackAnchorReceiptPersisted
            }
            AnchorWitnessDecision::CloseChannel => {
                // The head is deliberately not advanced. A cooperative close
                // runs against the last accepted bill, and must not depend on
                // the Hub's anchor being intact or on this bill being
                // accepted.
                next.closing = true;
                JournalPhase::RollbackAnchorRefused
            }
        };
        self.write_anchor_memory(
            binding_commitment,
            next,
            change.serial,
            &change.proposed_bill_commitment.clone(),
            phase,
        )
    }

    fn write_anchor_memory(
        &mut self,
        binding_commitment: &str,
        memory: ChannelAnchorMemoryV1,
        serial: u64,
        proposed_bill_commitment: &str,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let mut next = self.state.clone();
        next.schema_version = 1;
        next.anchor_witness_memory
            .insert(binding_commitment.to_owned(), memory);
        let now = unix_timestamp();
        self.commit(
            next,
            JournalEvent {
                wallet_scope: self.wallet_scope.clone(),
                hub_or_provider_identity: self.hub_identity.clone(),
                channel_id: self.channel_id.clone(),
                channel_reuse_version: 0,
                operation_id: format!("rollback-anchor-witness:{binding_commitment}"),
                operation_type: JournalOperationType::HvmPayment,
                operation_phase: phase,
                amount_zhu: 0,
                sender: String::new(),
                recipient: String::new(),
                previous_state_commitment: String::new(),
                new_state_commitment: String::new(),
                idempotency_key: format!("rollback-anchor-witness:{binding_commitment}:{serial}"),
                request_commitment: proposed_bill_commitment.to_owned(),
                expected_bill_number: Some(serial),
                unsigned_state_commitment: None,
                created_at: now,
            },
        )
    }

    // =====================================================================
    // The durable user-side registry exit.
    //
    // An exit runs for hours: `binding.challenge_blocks` plus the response
    // margin plus the lease slack, at a 300s block target. A wallet that is
    // closed halfway through is the ordinary case, so every step of it is
    // written here first, in this store, under this object's exclusive lock
    // and inside `state_commitment`.
    //
    // Nothing below trusts a stored record. Every one of these methods loads
    // the record and runs `validate_persisted_exit_step` against the caller's
    // exit kit before it looks at a phase, which re-derives the call source
    // from the binding and the wallet's own head bill using the Hub's own
    // encoders. This is the wallet's peer of
    // `validate_hvm_registry_chain_operations_v2`.
    // =====================================================================

    /// Read one step's record without deciding anything about it. For a
    /// screen that wants to say where an exit stands.
    pub fn exit_step_record(
        &self,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
    ) -> Option<PersistedHvmRegistryExitStepV1> {
        self.state
            .exit_operations
            .get(&exit_record_key(binding_commitment, step))
            .cloned()
    }

    /// Every exit step this wallet has ever recorded for one channel
    /// incarnation, in step order.
    pub fn exit_step_records(
        &self,
        binding_commitment: &str,
    ) -> Vec<PersistedHvmRegistryExitStepV1> {
        let prefix = format!("{binding_commitment}:");
        self.state
            .exit_operations
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// What reopening the wallet should do about a step, decided from the
    /// durable record and refusing outright if that record does not re-derive.
    ///
    /// `Ok(None)` means this wallet has never started this step.
    pub fn resume_exit_step(
        &self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
    ) -> WalletResult<Option<HvmRegistryExitResumeV1>> {
        let Some(record) = self.exit_step_record(binding_commitment, step) else {
            return Ok(None);
        };
        validate_persisted_exit_step(&record, kit)?;
        Ok(Some(resume_action(&record)))
    }

    /// Make a step durable before anything is signed, or resume the one that
    /// is already there.
    ///
    /// This never overwrites an unresolved step. A record whose phase says
    /// bytes may exist comes back as
    /// [`HvmRegistryExitResumeV1::AwaitChain`] or
    /// [`HvmRegistryExitResumeV1::ResignExact`], and in neither case may the
    /// caller build a fresh transaction — which is the entire point. The one
    /// exception is a lease renewal whose previous attempt is *terminal*: a
    /// long objection window can outlive the lease bought at its start, and a
    /// proven-mined previous attempt cannot be duplicated by a new one. Its
    /// transaction hash is carried forward, never dropped.
    pub fn begin_or_resume_exit_step(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        intent: &HvmRegistryExitIntentV1,
    ) -> WalletResult<HvmRegistryExitResumeV1> {
        let key = intent.record_key();
        let now = unix_timestamp();
        let fresh = PersistedHvmRegistryExitStepV1::open(intent, now);
        // Validate the record we are about to write by the same rule that
        // guards the ones already written. A record this store would refuse to
        // read back must never be written.
        validate_persisted_exit_step(&fresh, kit)?;

        let Some(existing) = self.state.exit_operations.get(&key).cloned() else {
            self.write_exit_step(fresh.clone(), JournalPhase::HvmChainIntentPersisted)?;
            return Ok(HvmRegistryExitResumeV1::SignFresh { record: fresh });
        };
        validate_persisted_exit_step(&existing, kit)?;

        if existing.phase.is_terminal() {
            if !intent.step.is_lease_renewal() {
                return Ok(HvmRegistryExitResumeV1::Done { record: existing });
            }
            let next = existing.supersede(intent, now);
            validate_persisted_exit_step(&next, kit)?;
            self.write_exit_step(next.clone(), JournalPhase::HvmChainIntentPersisted)?;
            return Ok(HvmRegistryExitResumeV1::SignFresh { record: next });
        }

        // Unresolved. The stored terms are the terms; a caller arriving with
        // different ones is a caller who would have signed a second, different
        // transaction for a step that may already be mined.
        if existing.call_source != intent.call_source {
            // Unreachable through a coherent chain: a claim's amount is pinned
            // to the settled balance its own snapshot read and to status 4, a
            // challenge's and a response's source is pinned to the serial of
            // the bill this wallet holds, and the other three sources depend on
            // the binding alone. So a differing source means the record and the
            // kit disagree about the world in a way validation did not catch,
            // and quietly overwriting it is the one thing that must not happen.
            return Err(blocked_exit_step(format!(
                "this exit step is already recorded for a different call and may already be on \
                 chain: the stored {} does not match the one just planned",
                intent.step.slug()
            )));
        }
        if existing.transaction_timestamp != intent.transaction_timestamp
            || existing.network_fee_zhu != intent.network_fee_zhu
            || existing.gas_max != intent.gas_max
        {
            // This used to overwrite the record whenever it was still at
            // `IntentPersisted`, on the reasoning that nothing was signed yet.
            // The reasoning holds only for a driver that obeys the protocol,
            // and the record's whole job is to be right about a driver that
            // did not: a process that signed *before* announcing it, and died,
            // leaves bytes on somebody's wire and a record that says
            // `IntentPersisted`. Re-planning that record onto a new clock made
            // those bytes unaccountable and authorised a second, different
            // transaction for the same step — measured, with the first hash on
            // the wire and nothing on chain to stop it.
            //
            // So the terms are sticky from the moment the step is opened.
            // Re-signing them is deterministic and reproduces whatever was
            // already produced, which is the only outcome that cannot double
            // anything. Refusing instead would trap the exit; overwriting
            // would duplicate it; keeping them does neither.
            if existing.phase == HvmRegistryExitPhase::IntentPersisted {
                return Ok(HvmRegistryExitResumeV1::SignFresh { record: existing });
            }
            return Err(blocked_exit_step(format!(
                "this exit step is already recorded on different terms and may already be on \
                 chain: {} was signed at timestamp {} for fee {} zhu",
                intent.step.slug(),
                existing.transaction_timestamp,
                existing.network_fee_zhu
            )));
        }
        Ok(resume_action(&existing))
    }

    /// Replace a lease renewal whose bytes are on the wire and are not being
    /// mined, at a strictly higher fee.
    ///
    /// # Why this door exists and why it is only this wide
    ///
    /// Retiring a step whose signature is live is the single operation in this
    /// store that can put two payable transactions on the wire, so
    /// [`Self::mark_exit_step_settled_elsewhere`] refuses to do it. That
    /// refusal is right for `challenge`, `respond`, `finalize` and the Action
    /// 14 claim, because for those the contract itself makes the second
    /// transaction a no-op: the status has already moved, or `c_left_claimed_`
    /// is already true, so a duplicate costs a fee and cannot pay twice.
    ///
    /// A lease renewal is the exception in both directions. Two renewals both
    /// *execute*, so a careless second one really is money. And a renewal that
    /// never mines is the only failure in this system that destroys a deposit
    /// outright — when the storage keys lapse, `c_status_` reads Nil and every
    /// entry point aborts, with nobody able to reach the coin. Refusing a
    /// replacement is therefore not the safe answer; it is the expensive one.
    ///
    /// So the door is opened by evidence rather than by intent: the step must
    /// be a lease renewal, its bytes must already have been handed to a node,
    /// the caller must have looked the hash up and found that neither a block
    /// nor the node's own mempool carries it, the replacement must pay strictly
    /// more, and it must be a different transaction. The superseded hash is
    /// carried forward, never dropped, so "did we already put something on the
    /// wire for this" stays answerable afterwards.
    ///
    /// What is deliberately **not** a term is elapsed wall-clock time. It reads
    /// like extra safety and is not: the honest signal is the node's own
    /// answer, which this call already demands, and a clock term would be
    /// untestable here while a caller in a hurry could simply wait it out. The
    /// worst case this door permits is two renewals both executing, which costs
    /// a second fee and buys a longer lease. The worst case of not having it is
    /// the storage keys lapsing, which destroys the deposit for everyone
    /// forever.
    pub fn supersede_stuck_lease_renewal(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        intent: &HvmRegistryExitIntentV1,
        chain_carries_the_stuck_transaction: bool,
    ) -> WalletResult<HvmRegistryExitResumeV1> {
        if !intent.step.is_lease_renewal() {
            return Err(blocked_exit_step(
                "only a storage lease renewal may be replaced while its bytes are live".into(),
            ));
        }
        if chain_carries_the_stuck_transaction {
            return Err(blocked_exit_step(
                "this lease renewal is on chain and must be confirmed, not replaced".into(),
            ));
        }
        let existing = self.require_exit_step(kit, &intent.binding_commitment, intent.step)?;
        if existing.phase != HvmRegistryExitPhase::Submitted {
            return Err(blocked_exit_step(format!(
                "a lease renewal can only be replaced once its bytes were handed to a node: it is {}",
                phase_label(existing.phase)
            )));
        }
        let now = unix_timestamp();
        if intent.network_fee_zhu <= existing.network_fee_zhu {
            return Err(blocked_exit_step(format!(
                "a replacement lease renewal must pay more than the {} zhu already offered",
                existing.network_fee_zhu
            )));
        }
        if intent.transaction_timestamp == existing.transaction_timestamp {
            return Err(blocked_exit_step(
                "a replacement lease renewal must be a different transaction from the one it \
                 replaces"
                    .into(),
            ));
        }
        let next = existing.supersede(intent, now);
        validate_persisted_exit_step(&next, kit)?;
        self.write_exit_step(next.clone(), JournalPhase::HvmChainIntentPersisted)?;
        Ok(HvmRegistryExitResumeV1::SignFresh { record: next })
    }

    /// Record that the signing key is about to be used for this step.
    ///
    /// Called **before** the signer, so that a process killed inside it leaves
    /// a state this store can name. Its peer on the Fast Pay path is
    /// [`Self::persist_before_signing`], and the reason is identical: an
    /// unrecorded signature is a transaction nobody can account for.
    pub fn mark_exit_step_signature_may_exist(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        match record.phase {
            HvmRegistryExitPhase::SignatureMayExist => return Ok(record),
            HvmRegistryExitPhase::IntentPersisted => {}
            other => {
                return Err(blocked_exit_step(format!(
                    "this exit step is past signing: it is {}",
                    phase_label(other)
                )));
            }
        }
        record.phase = HvmRegistryExitPhase::SignatureMayExist;
        record.updated_unix = unix_timestamp();
        self.write_exit_step(record.clone(), JournalPhase::HvmChainSignatureMayExist)?;
        Ok(record)
    }

    /// Make the exact signed bytes and their transaction hash durable.
    ///
    /// The bytes are write-once. A second call carrying anything different is
    /// refused, because the first transaction may already be mined and a
    /// second one for the same step is either a wasted fee or a double
    /// payout attempt the contract will reject after the fee is spent.
    pub fn persist_exit_step_signature(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        if signed_transaction_hex.trim().is_empty() {
            return Err(WalletError::L2(
                "an exit step signature needs its exact bytes".into(),
            ));
        }
        require_anchor_hash(transaction_hash, "exit step transaction hash")?;
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        // The bytes are checked against the record rather than believed.
        //
        // This used to take the caller's word for both halves: any hex, any
        // hash, as long as the phase was right. Measured, that was the gap a
        // rolled-back store walked through — the record came back at its
        // original terms, the caller signed at a *different* timestamp, and the
        // store wrote down a second transaction for a payout it had already
        // watched mine. The record stores the complete set of non-deterministic
        // inputs precisely so this is checkable, and now it is checked.
        exit_bytes_match_record(signed_transaction_hex, transaction_hash, &record)?;
        match record.phase {
            HvmRegistryExitPhase::Signed | HvmRegistryExitPhase::Submitted => {
                let same = record.transaction_hash.as_deref() == Some(transaction_hash)
                    && record.signed_transaction_hex.as_deref() == Some(signed_transaction_hex);
                if same {
                    return Ok(record);
                }
                return Err(blocked_exit_step(format!(
                    "a different transaction is already durable for this exit step: {} may \
                     already be on chain",
                    record.transaction_hash.as_deref().unwrap_or("unknown")
                )));
            }
            HvmRegistryExitPhase::SignatureMayExist => {}
            other => {
                return Err(blocked_exit_step(format!(
                    "an exit step signature cannot be recorded from {}",
                    phase_label(other)
                )));
            }
        }
        record.signed_transaction_hex = Some(signed_transaction_hex.to_owned());
        record.transaction_hash = Some(transaction_hash.to_owned());
        record.phase = HvmRegistryExitPhase::Signed;
        record.updated_unix = unix_timestamp();
        self.write_exit_step(record.clone(), JournalPhase::HvmChainSigned)?;
        Ok(record)
    }

    /// Record that the durable bytes were handed to a node.
    pub fn mark_exit_step_submitted(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        let now = unix_timestamp();
        match record.phase {
            HvmRegistryExitPhase::Submitted => return Ok(record),
            HvmRegistryExitPhase::Signed => {}
            other => {
                return Err(blocked_exit_step(format!(
                    "an exit step cannot be submitted from {}",
                    phase_label(other)
                )));
            }
        }
        record.phase = HvmRegistryExitPhase::Submitted;
        record.submitted_unix = Some(now);
        record.updated_unix = now;
        self.write_exit_step(record.clone(), JournalPhase::HvmChainSubmitted)?;
        Ok(record)
    }

    /// Record that **our own** transaction for this step was observed on
    /// chain.
    ///
    /// The hash is checked against the stored one rather than taken as given.
    /// A confirmation for some other transaction is not evidence about this
    /// step, and accepting one would retire a record whose bytes are still
    /// live.
    pub fn mark_exit_step_confirmed(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
        transaction_hash: &str,
        block_height: u64,
        block_hash: &str,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        require_anchor_hash(transaction_hash, "exit step transaction hash")?;
        require_anchor_hash(block_hash, "exit step block hash")?;
        if block_height == 0 {
            return Err(WalletError::L2(
                "an exit step confirmation needs the height it was mined at".into(),
            ));
        }
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        if record.transaction_hash.as_deref() != Some(transaction_hash) {
            return Err(WalletError::L2(
                "this confirmation is for a different transaction than the one this step signed"
                    .into(),
            ));
        }
        match record.phase {
            HvmRegistryExitPhase::Confirmed => {
                if record.confirmed_block_height == Some(block_height)
                    && record.confirmed_block_hash.as_deref() == Some(block_hash)
                {
                    return Ok(record);
                }
                return Err(blocked_exit_step(
                    "this exit step was already confirmed in a different block: the chain \
                     reorganised under it"
                        .into(),
                ));
            }
            HvmRegistryExitPhase::Signed | HvmRegistryExitPhase::Submitted => {}
            other => {
                return Err(blocked_exit_step(format!(
                    "an exit step cannot be confirmed from {}",
                    phase_label(other)
                )));
            }
        }
        record.phase = HvmRegistryExitPhase::Confirmed;
        record.confirmed_block_height = Some(block_height);
        record.confirmed_block_hash = Some(block_hash.to_owned());
        record.updated_unix = unix_timestamp();
        self.write_exit_step(record.clone(), JournalPhase::HvmChainConfirmed)?;
        Ok(record)
    }

    /// Record that this step's effect was found already done on chain without
    /// our transaction being the cause.
    ///
    /// `finalize` and the Action 14 payout are permissionless: anybody may
    /// press them, and the payout's destination is pinned by the contract, so
    /// a third party finishing first pays the same user the same amount. It is
    /// an ordinary ending and never an error — but it owns no block of ours,
    /// so it must not claim one.
    pub fn mark_exit_step_settled_elsewhere(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
        observed_height: u64,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        if observed_height == 0 {
            return Err(WalletError::L2(
                "an exit step settled elsewhere needs the height it was observed at".into(),
            ));
        }
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        match record.phase {
            HvmRegistryExitPhase::SettledElsewhere => {
                if record.settled_elsewhere_height == Some(observed_height) {
                    return Ok(record);
                }
                return Err(WalletError::L2(
                    "this exit step was already recorded settled at a different height".into(),
                ));
            }
            HvmRegistryExitPhase::Confirmed => {
                return Err(blocked_exit_step(
                    "this exit step is confirmed in a block of its own and was not settled by \
                     anybody else"
                        .into(),
                ));
            }
            // The arm that used to be `_ => {}`, which quietly accepted
            // `Signed` and `Submitted` too. Retiring a step whose own bytes are
            // live is the one transition in this store that can produce two
            // payable transactions: it moves the record to a terminal phase,
            // and a terminal phase is what
            // [`Self::begin_or_resume_exit_step`] treats as permission to open
            // a fresh attempt at a lease renewal. Measured through the public
            // API, that turned one submitted renewal into two payable ones with
            // no tampering and no filesystem access.
            //
            // Someone else finishing a permissionless step first is still an
            // ordinary ending — it is simply not this call's business once our
            // own signature exists. Our bytes either mine (confirm them) or
            // they do not, and a renewal that does not has
            // [`Self::supersede_stuck_lease_renewal`], which asks for evidence.
            phase @ (HvmRegistryExitPhase::SignatureMayExist
            | HvmRegistryExitPhase::Signed
            | HvmRegistryExitPhase::Submitted) => {
                return Err(blocked_exit_step(format!(
                    "this exit step cannot be retired while its own transaction {} may still \
                     execute: it is {}",
                    record.transaction_hash.as_deref().unwrap_or("unknown"),
                    phase_label(phase)
                )));
            }
            HvmRegistryExitPhase::IntentPersisted => {}
        }
        record.phase = HvmRegistryExitPhase::SettledElsewhere;
        record.settled_elsewhere_height = Some(observed_height);
        record.updated_unix = unix_timestamp();
        self.write_exit_step(record.clone(), JournalPhase::HvmChainConfirmed)?;
        Ok(record)
    }

    /// Take a confirmation back because the chain took the block back.
    ///
    /// # The wedge this ends
    ///
    /// [`Self::mark_exit_step_confirmed`] refuses a second confirmation in a
    /// different block, on the correct reasoning that a step cannot be mined
    /// twice. Paired with a `Confirmed` phase that nothing could leave, that
    /// turned an ordinary reorg into a permanent trap: confirm a payout one
    /// block deep, watch the chain reorganise it away, and the record says
    /// `Done` for a transaction the chain no longer carries.
    /// `mark_exit_step_settled_elsewhere` refuses from `Confirmed` and
    /// `begin_or_resume_exit_step` answers `Done`, so the deposit is stranded
    /// by the wallet's own bookkeeping while the contract still holds it.
    ///
    /// The way out cannot be a new signature — that is the thing this whole
    /// module exists to prevent — so it is not one. The record keeps its exact
    /// bytes and its exact hash and simply goes back to `Submitted`, which is
    /// what it truthfully is: bytes handed to a node, fate unknown. The driver
    /// then does what it does with any `AwaitChain`, which is look the hash up
    /// and re-submit *those same bytes* if the chain does not have them.
    ///
    /// The caller must name the block it is disowning, and it must be the
    /// block the record recorded. A caller that cannot say which block it
    /// watched vanish has not watched anything.
    pub fn mark_exit_step_reorged_out(
        &mut self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
        vanished_block_height: u64,
        vanished_block_hash: &str,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        require_anchor_hash(vanished_block_hash, "exit step block hash")?;
        let mut record = self.require_exit_step(kit, binding_commitment, step)?;
        if record.phase != HvmRegistryExitPhase::Confirmed {
            return Err(blocked_exit_step(format!(
                "only a confirmed exit step can be reorganised out of its block: it is {}",
                phase_label(record.phase)
            )));
        }
        if record.confirmed_block_height != Some(vanished_block_height)
            || record.confirmed_block_hash.as_deref() != Some(vanished_block_hash)
        {
            return Err(WalletError::L2(
                "this reorg names a block this exit step was never confirmed in".into(),
            ));
        }
        let now = unix_timestamp();
        record.phase = HvmRegistryExitPhase::Submitted;
        record.confirmed_block_height = None;
        record.confirmed_block_hash = None;
        record.submitted_unix = Some(record.submitted_unix.unwrap_or(now));
        record.updated_unix = now;
        self.write_exit_step(record.clone(), JournalPhase::HvmChainSubmitted)?;
        Ok(record)
    }

    fn require_exit_step(
        &self,
        kit: &HvmRegistryExitKitV1,
        binding_commitment: &str,
        step: HvmRegistryExitStep,
    ) -> WalletResult<PersistedHvmRegistryExitStepV1> {
        let record = self
            .exit_step_record(binding_commitment, step)
            .ok_or_else(|| {
                WalletError::L2(format!(
                    "this wallet has no durable record of the {} step of this exit",
                    step.slug()
                ))
            })?;
        validate_persisted_exit_step(&record, kit)?;
        Ok(record)
    }

    /// The single durable write for an exit step. Goes through the same
    /// [`Self::commit`] as every other write in this store, so the record is
    /// inside `state_commitment` and carries an authenticated journal entry.
    fn write_exit_step(
        &mut self,
        record: PersistedHvmRegistryExitStepV1,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let mut next = self.state.clone();
        next.schema_version = 1;
        let key = record.record_key();
        let operation_id = format!("registry-exit:{key}");
        let idempotency_key = format!("registry-exit:{key}:{}", record.attempt);
        let expected_bill_number = record.bill_serial;
        let recipient = record.claim_payee.clone().unwrap_or_default();
        let request_commitment = record.call_source_commitment.clone();
        let operation_type = if record.step.is_lease_renewal() {
            JournalOperationType::HvmLeaseRenewal
        } else {
            JournalOperationType::HvmWatchtower
        };
        let created_at = record.updated_unix;
        next.exit_operations.insert(key, record);
        self.commit(
            next,
            JournalEvent {
                wallet_scope: self.wallet_scope.clone(),
                hub_or_provider_identity: self.hub_identity.clone(),
                channel_id: self.channel_id.clone(),
                channel_reuse_version: 0,
                operation_id,
                operation_type,
                operation_phase: phase,
                amount_zhu: 0,
                sender: self.local_address.clone(),
                recipient,
                previous_state_commitment: String::new(),
                new_state_commitment: String::new(),
                idempotency_key,
                request_commitment,
                expected_bill_number,
                unsigned_state_commitment: None,
                created_at,
            },
        )
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
        let mut next = self.state.clone();
        next.schema_version = 1;
        next.operations
            .insert(operation.operation_id.clone(), operation.clone());
        // `ClientL2Operation::amount_units` is millimeis and is inside
        // `state_commitment`, so it keeps its unit and its scale here; the
        // journal takes zhu from every writer, so the conversion happens on
        // the way into the entry rather than in the persisted operation.
        let amount_zhu = operation
            .amount_units
            .checked_mul(crate::l2_hub::ZHU_PER_MILLIMEI)
            .ok_or_else(|| WalletError::L2("L2 amount overflows when converted to zhu".into()))?;
        self.commit(
            next,
            JournalEvent {
                wallet_scope: operation.wallet_scope.clone(),
                hub_or_provider_identity: operation.hub_identity.clone(),
                channel_id: operation.channel_id.clone(),
                channel_reuse_version: operation.channel_reuse_version,
                operation_id: operation.operation_id.clone(),
                operation_type: JournalOperationType::FastPay,
                operation_phase: phase,
                amount_zhu,
                sender: operation.payer.clone(),
                recipient: operation.payee.clone(),
                previous_state_commitment: String::new(),
                new_state_commitment: String::new(),
                idempotency_key: operation.idempotency_key.clone(),
                request_commitment: operation.request_commitment.clone(),
                expected_bill_number: None,
                unsigned_state_commitment: operation.unsigned_state_commitment.clone(),
                created_at: operation.updated_at,
            },
        )
    }

    /// The single durable write for this store: commitment over the whole
    /// next state, one authenticated journal record, one state file, one
    /// checkpoint, under the exclusive lock this object holds for its life.
    ///
    /// Both callers go through here on purpose. Anything added to
    /// [`ClientL2State`] is inside `state_commitment` by construction (it
    /// removes exactly three keys and hashes the rest), so a record written
    /// here cannot be blanked with a text editor without
    /// [`initialize_state`] refusing to open the store.
    ///
    /// The two commitment fields on `event` are filled in here; whatever the
    /// caller put in them is discarded, so no caller can journal a commitment
    /// that does not match the bytes it wrote.
    fn commit(&mut self, mut next: ClientL2State, mut event: JournalEvent) -> WalletResult<()> {
        let previous_commitment = state_commitment(&self.state)?;
        let new_commitment = state_commitment(&next)?;
        event.previous_state_commitment = previous_commitment;
        event.new_state_commitment = new_commitment.clone();
        let record = self.journal.append(event).map_err(l2_hub_error)?;
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

/// Tag a refusal that is about *this step's phase* rather than about a
/// record's integrity: what was asked cannot be done from where the step
/// already stands. The marker is what lets a caller above wallet-core tell
/// "your exit is further along than you thought" apart from "your durable
/// record is broken". Those have opposite remedies, and collapsing them would
/// route an owner whose exit is simply in flight into a recovery procedure.
/// Do these bytes actually say what this record says they say?
///
/// Two facts, both cheap and both load bearing:
///
/// * the transaction hash is **recomputed from the bytes**, so a caller cannot
///   file one transaction under another one's name; and
/// * the transaction's own timestamp equals the record's, which is the whole
///   set of non-deterministic input the record carries. Signing is RFC 6979
///   deterministic, so bytes that agree with the record on the timestamp, the
///   fee and the call are the bytes the record committed to and no others.
///
/// Refusing here is what makes the sticky terms in
/// [`ClientL2Safety::begin_or_resume_exit_step`] worth having: sticky terms
/// stop the record moving, and this stops a signature that ignored it.
fn exit_bytes_match_record(
    signed_transaction_hex: &str,
    transaction_hash: &str,
    record: &PersistedHvmRegistryExitStepV1,
) -> WalletResult<()> {
    crate::protocol_init::ensure_protocol_setup();
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|error| WalletError::L2(format!("exit step bytes are not hex: {error}")))?;
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::L2(format!("exit step bytes do not parse: {error}")))?;
    if consumed != raw.len() {
        return Err(WalletError::L2(
            "exit step bytes carry trailing rubbish".into(),
        ));
    }
    if hex::encode(transaction.hash().as_bytes()) != transaction_hash {
        return Err(blocked_exit_step(
            "these exit step bytes do not hash to the transaction hash filed with them".into(),
        ));
    }
    if transaction.timestamp().uint() != record.transaction_timestamp {
        return Err(blocked_exit_step(format!(
            "these exit step bytes were signed at timestamp {} and this step is recorded at {}",
            transaction.timestamp().uint(),
            record.transaction_timestamp
        )));
    }
    Ok(())
}

fn blocked_exit_step(message: String) -> WalletError {
    WalletError::L2(format!("{REFUSAL_EXIT_STEP_BLOCKED}: {message}"))
}

/// Plain English for a phase, for refusals a person has to act on.
fn phase_label(phase: HvmRegistryExitPhase) -> &'static str {
    match phase {
        HvmRegistryExitPhase::IntentPersisted => "recorded but unsigned",
        HvmRegistryExitPhase::SignatureMayExist => "part way through signing",
        HvmRegistryExitPhase::Signed => "signed and waiting to be submitted",
        HvmRegistryExitPhase::Submitted => "submitted and waiting for a block",
        HvmRegistryExitPhase::Confirmed => "confirmed on chain",
        HvmRegistryExitPhase::SettledElsewhere => "already settled by somebody else",
    }
}

fn require_anchor_hash(value: &str, label: &str) -> WalletResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WalletError::L2(format!(
            "{label} is not canonical lowercase hex"
        )))
    }
}

/// Recover the address that provably signed these exact receipt bytes.
///
/// Two steps, and both are needed. A Hacash `Sign` carries the compressed
/// public key alongside the signature, so step one derives the address from
/// the key that is actually on the wire. Step two re-encodes the receipt
/// canonically and verifies the signature against that recovered address.
///
/// Step two alone, against a Hub-supplied address, proves nothing. Step one
/// alone checks no signature. Together they answer "who provably signed these
/// exact bytes", and that answer — never the Hub-typed `witness_id` label —
/// is what enters the overlap set.
fn recover_anchor_receipt_signer(receipt: &SignedHubWitnessReceiptV1) -> WalletResult<String> {
    let bytes = hex::decode(&receipt.signature_hex)
        .map_err(|_| WalletError::L2("anchor receipt signature is not hex".into()))?;
    if bytes.len() != ANCHOR_SIGN_WIRE_BYTES {
        return Err(WalletError::L2(
            "anchor receipt signature is not a canonical Hacash signature".into(),
        ));
    }
    let mut signature = field::Sign::default();
    let used = signature
        .parse(&bytes)
        .map_err(|_| WalletError::L2("anchor receipt signature cannot be parsed".into()))?;
    if used != bytes.len() {
        return Err(WalletError::L2(
            "anchor receipt signature has trailing bytes".into(),
        ));
    }
    let signer = field::Address::from(sys::Account::get_address_by_public_key(
        *signature.publickey,
    ))
    .to_readable();
    receipt
        .verify_against_pinned_key(&signer)
        .map_err(|error| {
            WalletError::L2(format!(
                "anchor receipt signature does not verify against the key it carries: {error}"
            ))
        })?;
    Ok(signer)
}

/// Admission for one receipt. Every check here runs on the first bill of a
/// channel exactly as on the thousandth: the first bill establishes the
/// baseline, so junk admitted there poisons every comparison after it.
///
/// There is deliberately no wall-clock check. `receipt_expires_at` is the
/// Hub's own pre-signing gate, bounded to 120 seconds after `accepted_at`. A
/// wallet that also enforced it would refuse every bill that took two minutes
/// to arrive and would hand anyone with clock skew a denial of service on a
/// path where no bypass is permitted — and it would buy nothing, because
/// obtaining the receipt already advanced the witness's counter.
fn admit_anchor_receipt(
    receipt: &SignedHubWitnessReceiptV1,
    hub_identity: &str,
    binding_commitment: &str,
    proposed_bill_commitment: &str,
    serial: u64,
) -> WalletResult<AnchorWitnessRecordV1> {
    // Shape, including `receipt_version == 1`, is enforced inside
    // `canonical_bytes` before the signature is checked at all.
    let signer_address = recover_anchor_receipt_signer(receipt)?;
    let inner = &receipt.receipt;
    // The receipt commits to the PAYER-SIGNED, HUB-UNSIGNED bill: the Hub
    // fills its own signature in afterwards and the bill commitment covers the
    // whole struct including signatures. So this must be compared against the
    // commitment of the proposal the wallet itself sent, never against the
    // fully signed bill that came back.
    if inner.proposed_bill_commitment != proposed_bill_commitment {
        return Err(WalletError::L2(
            "anchor receipt authorises a different bill than the one this wallet proposed".into(),
        ));
    }
    if inner.serial != serial {
        return Err(WalletError::L2(
            "anchor receipt is bound to a different serial than this bill".into(),
        ));
    }
    if inner.binding_commitment != binding_commitment {
        return Err(WalletError::L2(
            "anchor receipt is bound to a different channel".into(),
        ));
    }
    if inner.hub_identity != hub_identity {
        return Err(WalletError::L2(
            "anchor receipt is bound to a different Hub".into(),
        ));
    }
    Ok(AnchorWitnessRecordV1 {
        signer_address,
        witness_instance_id: inner.witness_instance_id.clone(),
        witness_id: inner.witness_id.clone(),
        witness_epoch: inner.witness_epoch,
        first_seen_serial: serial,
        last_seen_serial: serial,
        highest_counter_value: inner.counter_value,
    })
}

fn merge_offered_witnesses(
    witnesses: &mut BTreeMap<String, AnchorWitnessRecordV1>,
    offered: &BTreeMap<String, AnchorWitnessRecordV1>,
    serial: u64,
) {
    for (key, candidate) in offered {
        match witnesses.get_mut(key) {
            Some(known) => {
                known.witness_id = candidate.witness_id.clone();
                known.witness_epoch = candidate.witness_epoch;
                known.last_seen_serial = serial;
                known.highest_counter_value = known
                    .highest_counter_value
                    .max(candidate.highest_counter_value);
            }
            None => {
                witnesses.insert(key.clone(), candidate.clone());
            }
        }
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
                amount_zhu: 0,
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
