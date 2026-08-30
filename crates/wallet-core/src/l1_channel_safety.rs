//! Durable Personal Wallet recovery state for an L1 Fast Pay channel opening.
//!
//! A channel-open needs two signatures. This store is written before the local
//! signature is produced and keeps the exact idempotent Hub request afterwards.
//! A crash or timeout therefore resumes one operation instead of constructing a
//! second transaction. The blockchain key is used only to derive a separate
//! journal-authentication key and is never serialized here.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use hkdf::Hkdf;
use l2_fast_pay_hub::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use l2_fast_pay_hub::l1_channel::{L1ChannelOpenRequest, L1ChannelOpenStatusResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::l2_storage_scope::validate_scoped_l2_storage;
use crate::paths::{secure_write, wallet_data_root};

const KEY_DOMAIN: &[u8] = b"HPAY/L1/CHANNEL-OPEN/JOURNAL/AUTH/V1";
const KEY_DOMAIN_V2: &[u8] = b"HPAY/L1/CHANNEL-OPEN/JOURNAL/AUTH/V2";

/// Narrow authority used only to derive an authenticated channel-open journal
/// key. Implementations must not expose the wallet secret or generic signing.
pub trait ChannelOpenJournalKeyProvider {
    fn derive_channel_open_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
        reuse_version: u64,
    ) -> WalletResult<Zeroizing<[u8; 32]>>;
}

impl ChannelOpenJournalKeyProvider for WalletAccount {
    fn derive_channel_open_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
        reuse_version: u64,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        derive_key(self, wallet_scope, hub_identity, channel_id, reuse_version)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelOpenStatus {
    PersistedBeforeSigning,
    SignatureMayExist,
    UserSigned,
    HubCosigned,
    NodeSubmitted,
    Opening,
    Confirmed,
    RecoveryRequired,
    CancelledBeforeSigning,
    /// A user signature exists, its request envelope is long dead, and nothing
    /// ever came back from the Hub or the chain for it.
    ///
    /// Distinct from `CancelledBeforeSigning`, which asserts no signature was
    /// ever produced. This one asserts the opposite and retires it anyway,
    /// because a channel-open transaction carrying only the user's signature
    /// cannot be mined - the Hub's countersignature is a consensus requirement
    /// of the action - and the Hub will not produce one for a request whose
    /// envelope has expired. See `abandon_dead_request` for the full set of
    /// conditions, every one of which is checked before this is written.
    AbandonedDeadRequest,
}

impl ChannelOpenStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::CancelledBeforeSigning | Self::AbandonedDeadRequest
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingChannelOpenLocator {
    pub operation_id: String,
    pub hub_identity: String,
    pub channel_id: String,
    #[serde(default = "default_channel_reuse_version")]
    pub reuse_version: u64,
    pub user_address: String,
    pub left_deposit: String,
    pub right_deposit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelOpenOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub wallet_scope: String,
    pub hub_identity: String,
    pub channel_id: String,
    #[serde(default = "default_channel_reuse_version")]
    pub reuse_version: u64,
    pub user_address: String,
    pub user_deposit_zhu: u64,
    pub unsigned_transaction_hex: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub status: ChannelOpenStatus,
    pub request: Option<L1ChannelOpenRequest>,
    pub response: Option<L1ChannelOpenStatusResponse>,
    pub node_transaction_hash: Option<String>,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ChannelOpenState {
    schema_version: u32,
    journal_sequence: u64,
    journal_head: String,
    state_commitment: String,
    operation: Option<ChannelOpenOperation>,
}

pub struct ChannelOpenSafety {
    path: PathBuf,
    wallet_scope: String,
    hub_identity: String,
    channel_id: String,
    journal: AuthenticatedJournal,
    state: ChannelOpenState,
    _lock: fs::File,
}

pub struct BeginChannelOpen<'a> {
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
    pub user_address: &'a str,
    pub reuse_version: u64,
    pub user_deposit_zhu: u64,
    pub unsigned_transaction_hex: &'a str,
    pub created_unix: u64,
    pub expires_unix: u64,
}

impl ChannelOpenSafety {
    pub fn open(
        account: &WalletAccount,
        hub_identity: &str,
        channel_id: &str,
        reuse_version: u64,
    ) -> WalletResult<Self> {
        let wallet_scope = format!("personal:{}", account.address());
        Self::open_scoped(
            account,
            wallet_data_root().join("l2").join("personal"),
            &wallet_scope,
            hub_identity,
            channel_id,
            reuse_version,
        )
    }

    pub fn open_scoped(
        key_provider: &impl ChannelOpenJournalKeyProvider,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
        reuse_version: u64,
    ) -> WalletResult<Self> {
        let trusted_l2_root = trusted_l2_root.as_ref();
        validate_scoped_l2_storage(trusted_l2_root, wallet_scope)?;
        if reuse_version == 0 {
            return Err(WalletError::L2(
                "channel reuse version must be positive".into(),
            ));
        }
        let directory = scoped_safety_directory(
            trusted_l2_root,
            wallet_scope,
            hub_identity,
            channel_id,
            reuse_version,
        );
        fs::create_dir_all(&directory).map_err(io_error)?;
        let path = directory.join("channel-open.json");
        let lock = acquire_lock(&directory.join("channel-open.lock"))?;
        let mut key = key_provider.derive_channel_open_journal_key(
            wallet_scope,
            hub_identity,
            channel_id,
            reuse_version,
        )?;
        let journal = AuthenticatedJournal::open(
            directory.join("channel-open.journal.jsonl"),
            &key[..],
            JournalBinding {
                wallet_scope: wallet_scope.to_owned(),
                hub_or_provider_identity: hub_identity.to_owned(),
                channel_id: Some(channel_id.to_owned()),
            },
        )
        .map_err(hub_error)?;
        key.zeroize();
        let mut state = load_state(&path)?;
        initialize_state(
            &path,
            &mut state,
            &journal,
            wallet_scope,
            hub_identity,
            channel_id,
            reuse_version,
        )?;
        Ok(Self {
            path,
            wallet_scope: wallet_scope.to_owned(),
            hub_identity: hub_identity.to_owned(),
            channel_id: channel_id.to_owned(),
            journal,
            state,
            _lock: lock,
        })
    }
    pub fn begin_or_resume(
        &mut self,
        input: BeginChannelOpen<'_>,
    ) -> WalletResult<ChannelOpenOperation> {
        if let Some(existing) = self.state.operation.clone() {
            if same_intent(
                &existing,
                &input,
                &self.wallet_scope,
                &self.hub_identity,
                &self.channel_id,
            ) {
                return Ok(existing);
            }
            if existing.status == ChannelOpenStatus::CancelledBeforeSigning {
                // A definitely unsigned intent may be replaced after explicit recovery cancellation.
            } else if existing.status == ChannelOpenStatus::AbandonedDeadRequest {
                // A signed intent whose envelope died with nothing behind it
                // may be replaced too, and it has to be: this store is keyed by
                // the deterministic channel ID, so refusing here is what left
                // an owner unable to ever open a Fast Pay channel again. The
                // retirement itself is what carries the safety argument; see
                // `abandon_dead_request`. The chain is the backstop: a fresh
                // open re-reads the reuse version, and if the retired
                // transaction ever did land, that read returns 2 and the
                // wallet refuses the new open before it signs anything.
            } else if !existing.status.is_terminal() {
                return Err(WalletError::L2(
                    "RecoveryRequired: a different channel-open operation is unresolved".into(),
                ));
            } else {
                return Err(WalletError::L2(
                    "this deterministic channel ID has already been used".into(),
                ));
            }
        }
        if input.created_unix == 0 || input.expires_unix <= input.created_unix {
            return Err(WalletError::L2(
                "invalid channel-open recovery time window".into(),
            ));
        }
        let operation = ChannelOpenOperation {
            operation_id: input.operation_id.to_owned(),
            idempotency_key: input.idempotency_key.to_owned(),
            wallet_scope: self.wallet_scope.clone(),
            hub_identity: self.hub_identity.clone(),
            channel_id: self.channel_id.clone(),
            reuse_version: input.reuse_version,
            user_address: input.user_address.to_owned(),
            user_deposit_zhu: input.user_deposit_zhu,
            unsigned_transaction_hex: input.unsigned_transaction_hex.to_owned(),
            created_unix: input.created_unix,
            expires_unix: input.expires_unix,
            status: ChannelOpenStatus::PersistedBeforeSigning,
            request: None,
            response: None,
            node_transaction_hash: None,
            updated_unix: input.created_unix,
        };
        self.transition(operation.clone(), JournalPhase::L1IntentValidated)?;
        Ok(operation)
    }

    pub fn mark_signature_may_exist(&mut self) -> WalletResult<ChannelOpenOperation> {
        let mut operation = self.operation()?;
        if operation.status == ChannelOpenStatus::SignatureMayExist {
            return Ok(operation);
        }
        if operation.status != ChannelOpenStatus::PersistedBeforeSigning {
            return Err(WalletError::L2(
                "RecoveryRequired: channel-open signing state is not fresh".into(),
            ));
        }
        operation.status = ChannelOpenStatus::SignatureMayExist;
        operation.updated_unix = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::L1OpenSignatureMayExist)?;
        Ok(operation)
    }

    pub fn persist_user_signed(
        &mut self,
        request: &L1ChannelOpenRequest,
    ) -> WalletResult<ChannelOpenOperation> {
        let mut operation = self.operation()?;
        require_request_binding(&operation, request)?;
        if let Some(existing) = &operation.request {
            if existing != request {
                return Err(WalletError::L2(
                    "idempotency conflict: channel-open signature changed".into(),
                ));
            }
            return Ok(operation);
        }
        if operation.status != ChannelOpenStatus::SignatureMayExist {
            return Err(WalletError::L2(
                "RecoveryRequired: exact open bytes were not preceded by the durable signing marker"
                    .into(),
            ));
        }
        operation.request = Some(request.clone());
        operation.status = ChannelOpenStatus::UserSigned;
        operation.updated_unix = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::L1SignatureProduced)?;
        Ok(operation)
    }

    pub fn persist_hub_status(
        &mut self,
        response: &L1ChannelOpenStatusResponse,
    ) -> WalletResult<ChannelOpenOperation> {
        let mut operation = self.operation()?;
        if response.schema != l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA
            || response.operation_id != operation.operation_id
            || response.channel_id != operation.channel_id
            || !matches!(
                response.status.as_str(),
                "submission_started" | "submitted" | "confirmed" | "recovery_required"
            )
            || response.transaction_hash.as_ref().is_none_or(|hash| {
                hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(WalletError::L2(
                "Hub channel-open status changed the durable operation".into(),
            ));
        }
        if let Some(existing) = &operation.response
            && (existing.operation_id != response.operation_id
                || existing.channel_id != response.channel_id
                || existing.transaction_hash != response.transaction_hash)
        {
            return Err(WalletError::L2(
                "idempotency conflict: Hub changed the channel-open transaction identity".into(),
            ));
        }
        if !matches!(
            operation.status,
            ChannelOpenStatus::UserSigned
                | ChannelOpenStatus::HubCosigned
                | ChannelOpenStatus::NodeSubmitted
                | ChannelOpenStatus::Opening
                | ChannelOpenStatus::RecoveryRequired
        ) {
            return Err(WalletError::L2(
                "RecoveryRequired: Hub open status arrived in an invalid state".into(),
            ));
        }
        operation.response = Some(response.clone());
        operation.node_transaction_hash = response.transaction_hash.clone();
        let phase = if response.status == "recovery_required" {
            operation.status = ChannelOpenStatus::RecoveryRequired;
            JournalPhase::RecoveryStarted
        } else {
            operation.status = ChannelOpenStatus::NodeSubmitted;
            JournalPhase::PaymentSubmitted
        };
        operation.updated_unix = unix_timestamp();
        self.transition(operation.clone(), phase)?;
        Ok(operation)
    }
    pub fn mark_node_submitted(&mut self, transaction_hash: &str) -> WalletResult<()> {
        let mut operation = self.operation()?;
        if operation.status == ChannelOpenStatus::Confirmed {
            return Ok(());
        }
        if operation.response.is_none()
            || !matches!(
                operation.status,
                ChannelOpenStatus::HubCosigned
                    | ChannelOpenStatus::NodeSubmitted
                    | ChannelOpenStatus::Opening
                    | ChannelOpenStatus::RecoveryRequired
            )
        {
            return Err(WalletError::L2(
                "RecoveryRequired: channel-open cannot be marked submitted without exact Hub bytes"
                    .into(),
            ));
        }
        if let Some(existing) = &operation.node_transaction_hash
            && existing != transaction_hash
        {
            return Err(WalletError::L2(
                "idempotency conflict: node returned a different transaction hash".into(),
            ));
        }
        operation.node_transaction_hash = Some(transaction_hash.to_owned());
        operation.status = ChannelOpenStatus::NodeSubmitted;
        operation.updated_unix = unix_timestamp();
        self.transition(operation, JournalPhase::PaymentSubmitted)
    }

    pub fn mark_opening(&mut self) -> WalletResult<()> {
        self.set_status(
            ChannelOpenStatus::Opening,
            JournalPhase::PaymentAcknowledged,
        )
    }

    pub fn mark_confirmed(&mut self) -> WalletResult<()> {
        self.set_status(ChannelOpenStatus::Confirmed, JournalPhase::PaymentCommitted)
    }

    pub fn mark_recovery_required(&mut self) -> WalletResult<()> {
        if self.operation()?.status == ChannelOpenStatus::Confirmed {
            return Err(WalletError::L2(
                "confirmed channel-open recovery state is terminal".into(),
            ));
        }
        self.set_status(
            ChannelOpenStatus::RecoveryRequired,
            JournalPhase::RecoveryStarted,
        )
    }

    pub fn cancel_before_signing(&mut self) -> WalletResult<()> {
        let operation = self.operation()?;
        if operation.status != ChannelOpenStatus::PersistedBeforeSigning
            || operation.request.is_some()
            || operation.response.is_some()
        {
            return Err(WalletError::L2(
                "RecoveryRequired: only a definitely unsigned channel-open may be cancelled".into(),
            ));
        }
        self.set_status(
            ChannelOpenStatus::CancelledBeforeSigning,
            JournalPhase::RecoveryCompleted,
        )
    }

    /// Retire a signed channel-open request that is provably dead.
    ///
    /// # What this is for
    ///
    /// `cancel_before_signing` covers the case where no signature was ever
    /// produced. It cannot cover the case an owner actually reached: signed,
    /// refused by the Hub, envelope expired. That state had no exit at all.
    /// The setup could not be confirmed (the Hub refuses an expired envelope),
    /// could not be discarded (a signature exists), and blocked every future
    /// `prepare` for the life of the wallet.
    ///
    /// # What must hold, all of it, checked here
    ///
    /// * The Hub never answered. `response.is_none()`.
    /// * Nothing was ever broadcast. `node_transaction_hash.is_none()`.
    /// * The store never advanced past the user's own signature. Only
    ///   `SignatureMayExist`, `UserSigned` and `RecoveryRequired` qualify;
    ///   `HubCosigned`, `NodeSubmitted`, `Opening` and `Confirmed` all mean
    ///   something left this machine and are refused.
    /// * `now` is past `expires_unix`, so no honest Hub will cosign these
    ///   bytes: the request envelope is checked against the Hub's own clock in
    ///   `l2_fast_pay_hub::l1_channel`.
    ///
    /// The caller adds the two facts this module cannot see: that the chain
    /// does not carry this channel, and that enough time has passed that the
    /// transaction's own timestamp is outside the Hub's acceptance window.
    ///
    /// # Why retiring a real signature is safe
    ///
    /// A `ChannelOpen` action needs both parties' signatures to be valid. The
    /// bytes retired here carry exactly one, the user's. They cannot be mined
    /// by anybody, including whoever received the POST, unless the Hub
    /// cosigns - and the conditions above are precisely the conditions under
    /// which it will not.
    pub fn abandon_dead_request(&mut self, now: u64) -> WalletResult<()> {
        let operation = self.operation()?;
        if operation.status == ChannelOpenStatus::AbandonedDeadRequest {
            // A previous run got this far and died before the caller finished.
            return Ok(());
        }
        if operation.request.is_none()
            || operation.response.is_some()
            || operation.node_transaction_hash.is_some()
            || now <= operation.expires_unix
            || !matches!(
                operation.status,
                ChannelOpenStatus::SignatureMayExist
                    | ChannelOpenStatus::UserSigned
                    | ChannelOpenStatus::RecoveryRequired
            )
        {
            return Err(WalletError::L2(
                "RecoveryRequired: only an expired channel-open request that never reached the Hub or the chain may be retired"
                    .into(),
            ));
        }
        self.set_status(
            ChannelOpenStatus::AbandonedDeadRequest,
            JournalPhase::RecoveryCompleted,
        )
    }

    pub fn operation(&self) -> WalletResult<ChannelOpenOperation> {
        self.state
            .operation
            .clone()
            .ok_or_else(|| WalletError::L2("channel-open recovery operation is missing".into()))
    }

    fn set_status(&mut self, status: ChannelOpenStatus, phase: JournalPhase) -> WalletResult<()> {
        let mut operation = self.operation()?;
        if operation.status == status {
            return Ok(());
        }
        if operation.status == ChannelOpenStatus::Confirmed {
            return Err(WalletError::L2(
                "confirmed channel-open recovery state is terminal".into(),
            ));
        }
        operation.status = status;
        operation.updated_unix = unix_timestamp();
        self.transition(operation, phase)
    }

    fn transition(
        &mut self,
        operation: ChannelOpenOperation,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let previous_commitment = state_commitment(&self.state)?;
        let mut next = self.state.clone();
        next.schema_version = 1;
        next.operation = Some(operation.clone());
        let new_commitment = state_commitment(&next)?;
        let request_commitment = operation
            .request
            .as_ref()
            .map(l2_fast_pay_hub::l1_channel::request_commitment)
            .transpose()
            .map_err(hub_error)?
            .unwrap_or_else(|| {
                hex::encode(Sha256::digest(
                    operation.unsigned_transaction_hex.as_bytes(),
                ))
            });
        let unsigned_state_commitment = operation
            .request
            .as_ref()
            .map(|request| request.partial_transaction_commitment.clone());
        let record = self
            .journal
            .append(JournalEvent {
                wallet_scope: operation.wallet_scope.clone(),
                hub_or_provider_identity: operation.hub_identity.clone(),
                channel_id: operation.channel_id.clone(),
                channel_reuse_version: operation.reuse_version,
                operation_id: operation.operation_id.clone(),
                operation_type: JournalOperationType::L1ChannelOpen,
                operation_phase: phase,
                amount_units: operation.user_deposit_zhu,
                sender: operation.user_address.clone(),
                recipient: operation.hub_identity.clone(),
                previous_state_commitment: previous_commitment,
                new_state_commitment: new_commitment.clone(),
                idempotency_key: operation.idempotency_key.clone(),
                request_commitment,
                expected_bill_number: None,
                unsigned_state_commitment,
                created_at: operation.updated_unix,
            })
            .map_err(hub_error)?;
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
            .map_err(hub_error)?;
        self.state = next;
        Ok(())
    }
}

pub fn persist_pending_locator(
    account: &WalletAccount,
    locator: &PendingChannelOpenLocator,
) -> WalletResult<()> {
    validate_locator(account, locator)?;
    let path = pending_locator_path(account);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    if path.exists() {
        let existing = load_pending_locator(account)?
            .ok_or_else(|| WalletError::L2("channel-open recovery locator disappeared".into()))?;
        if existing != *locator {
            return Err(WalletError::L2(
                "RecoveryRequired: another channel-open operation is pending".into(),
            ));
        }
        return Ok(());
    }
    let bytes = serde_json::to_vec(locator).map_err(|error| WalletError::L2(error.to_string()))?;
    secure_write(&path, &bytes).map_err(io_error)
}

pub fn load_pending_locator(
    account: &WalletAccount,
) -> WalletResult<Option<PendingChannelOpenLocator>> {
    let path = pending_locator_path(account);
    if !path.exists() {
        return Ok(None);
    }
    if fs::metadata(&path).map_err(io_error)?.len() > 16 * 1024 {
        return Err(WalletError::L2(
            "channel-open recovery locator is oversized".into(),
        ));
    }
    let locator: PendingChannelOpenLocator =
        serde_json::from_slice(&fs::read(&path).map_err(io_error)?).map_err(|error| {
            WalletError::L2(format!("invalid channel-open recovery locator: {error}"))
        })?;
    validate_locator(account, &locator)?;
    Ok(Some(locator))
}

pub fn clear_pending_locator(account: &WalletAccount, operation_id: &str) -> WalletResult<()> {
    let path = pending_locator_path(account);
    let Some(locator) = load_pending_locator(account)? else {
        return Ok(());
    };
    if locator.operation_id != operation_id {
        return Err(WalletError::L2(
            "channel-open recovery locator belongs to a different operation".into(),
        ));
    }
    fs::remove_file(path).map_err(io_error)
}

fn validate_locator(
    account: &WalletAccount,
    locator: &PendingChannelOpenLocator,
) -> WalletResult<()> {
    let bounded = [
        locator.operation_id.as_str(),
        locator.hub_identity.as_str(),
        locator.channel_id.as_str(),
        locator.user_address.as_str(),
        locator.left_deposit.as_str(),
        locator.right_deposit.as_str(),
    ]
    .iter()
    .all(|value| !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control));
    if !bounded
        || locator.user_address != account.address()
        || locator.reuse_version == 0
        || locator.channel_id.len() != 32
        || !locator
            .channel_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WalletError::L2(
            "channel-open recovery locator failed validation".into(),
        ));
    }
    Ok(())
}

fn pending_locator_path(account: &WalletAccount) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L1/CHANNEL-OPEN/PENDING/V1");
    hash_field(&mut digest, account.address().as_bytes());
    wallet_data_root()
        .join("l2")
        .join("personal")
        .join("channel-open")
        .join(format!("pending-{}.json", hex::encode(digest.finalize())))
}
fn same_intent(
    existing: &ChannelOpenOperation,
    input: &BeginChannelOpen<'_>,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
) -> bool {
    existing.operation_id == input.operation_id
        && existing.idempotency_key == input.idempotency_key
        && existing.wallet_scope == wallet_scope
        && existing.hub_identity == hub_identity
        && existing.channel_id == channel_id
        && existing.reuse_version == input.reuse_version
        && existing.user_address == input.user_address
        && existing.user_deposit_zhu == input.user_deposit_zhu
        && existing.unsigned_transaction_hex == input.unsigned_transaction_hex
        && existing.created_unix == input.created_unix
        && existing.expires_unix == input.expires_unix
}

fn require_request_binding(
    operation: &ChannelOpenOperation,
    request: &L1ChannelOpenRequest,
) -> WalletResult<()> {
    if request.operation_id != operation.operation_id
        || request.idempotency_key != operation.idempotency_key
        || request.hub_address != operation.hub_identity
        || request.channel_id != operation.channel_id
        || request.expected_reuse_version != operation.reuse_version
        || request.created_unix != operation.created_unix
        || request.expires_unix != operation.expires_unix
    {
        return Err(WalletError::L2(
            "signed channel-open request does not match durable intent".into(),
        ));
    }
    Ok(())
}

fn scoped_safety_directory(
    trusted_l2_root: &Path,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
    reuse_version: u64,
) -> PathBuf {
    let mut digest = Sha256::new();
    if reuse_version == 1 {
        // Preserve the exact V1 path so an existing first-incarnation recovery
        // operation remains recoverable after this upgrade.
        digest.update(b"HPAY/L1/CHANNEL-OPEN/STORE/V1");
    } else {
        digest.update(b"HPAY/L1/CHANNEL-OPEN/STORE/V2");
    }
    hash_field(&mut digest, wallet_scope.as_bytes());
    hash_field(&mut digest, hub_identity.as_bytes());
    hash_field(&mut digest, channel_id.as_bytes());
    if reuse_version > 1 {
        hash_field(&mut digest, &reuse_version.to_be_bytes());
    }
    trusted_l2_root
        .join("channel-open")
        .join(hex::encode(digest.finalize()))
}

fn derive_key(
    account: &WalletAccount,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
    reuse_version: u64,
) -> WalletResult<Zeroizing<[u8; 32]>> {
    let domain = if reuse_version == 1 {
        KEY_DOMAIN
    } else {
        KEY_DOMAIN_V2
    };
    let mut secret = Zeroizing::new(account.inner().secret_key().serialize());
    let mut salt = Sha256::new();
    salt.update(domain);
    hash_field(&mut salt, wallet_scope.as_bytes());
    hash_field(&mut salt, hub_identity.as_bytes());
    hash_field(&mut salt, channel_id.as_bytes());
    if reuse_version > 1 {
        hash_field(&mut salt, &reuse_version.to_be_bytes());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), secret.as_slice());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(domain, output.as_mut())
        .map_err(|_| WalletError::L2("channel-open journal key derivation failed".into()))?;
    secret.zeroize();
    Ok(output)
}

fn initialize_state(
    path: &Path,
    state: &mut ChannelOpenState,
    journal: &AuthenticatedJournal,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
    reuse_version: u64,
) -> WalletResult<()> {
    let had_state = state.schema_version != 0
        || state.journal_sequence != 0
        || !state.journal_head.is_empty()
        || !state.state_commitment.is_empty();
    let records = journal.verify().map_err(hub_error)?;
    let checkpoint = journal.read_checkpoint().map_err(hub_error)?;
    if records.is_empty() {
        if had_state || checkpoint.is_some() {
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
                channel_reuse_version: reuse_version,
                operation_id: "personal-channel-open-store-v1".into(),
                operation_type: JournalOperationType::Migration,
                operation_phase: JournalPhase::RecoveryCompleted,
                amount_units: 0,
                sender: String::new(),
                recipient: hub_identity.to_owned(),
                previous_state_commitment: current.clone(),
                new_state_commitment: current.clone(),
                idempotency_key: "personal-channel-open-store-v1".into(),
                request_commitment: current.clone(),
                expected_bill_number: None,
                unsigned_state_commitment: None,
                created_at: now,
            })
            .map_err(hub_error)?;
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
            .map_err(hub_error)?;
        return Ok(());
    }
    if state.schema_version != 1 {
        return Err(WalletError::L2(
            "authenticated channel-open state schema is invalid".into(),
        ));
    }
    let current = state_commitment(state)?;
    let last = records
        .last()
        .ok_or_else(|| WalletError::L2("channel-open journal head is missing".into()))?;
    if checkpoint
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.sequence > last.entry_sequence)
        || state.journal_sequence != last.entry_sequence
        || state.journal_head != last.entry_hash
        || state.state_commitment != current
        || last.new_state_commitment != current
    {
        return Err(WalletError::L2(
            "RecoveryRequired: channel-open journal and state differ".into(),
        ));
    }
    Ok(())
}

fn load_state(path: &Path) -> WalletResult<ChannelOpenState> {
    if !path.exists() {
        return Ok(ChannelOpenState::default());
    }
    if fs::metadata(path).map_err(io_error)?.len() > 4 * 1024 * 1024 {
        return Err(WalletError::L2(
            "channel-open recovery state is oversized".into(),
        ));
    }
    let bytes = fs::read(path).map_err(io_error)?;
    reject_legacy_channel_open_request(&bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| WalletError::L2(error.to_string()))
}

fn reject_legacy_channel_open_request(bytes: &[u8]) -> WalletResult<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        WalletError::L2(format!("invalid channel-open recovery state: {error}"))
    })?;
    let Some(request) = value
        .get("operation")
        .and_then(|operation| operation.get("request"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let schema_is_current = request.get("schema").and_then(serde_json::Value::as_str)
        == Some(l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA);
    let has_network_binding = [
        "network",
        "chain_id",
        "mainnet",
        "block_1_hash",
        "node_profile_id",
        "network_instance_id",
        "transaction_format_version",
    ]
    .iter()
    .all(|field| request.contains_key(*field));
    if !schema_is_current || !has_network_binding {
        return Err(WalletError::L2(
            "RecoveryRequired: legacy channel-open request has no authenticated network binding; it cannot be signed, retried, or broadcast automatically"
                .into(),
        ));
    }
    Ok(())
}

fn save_state(path: &Path, state: &ChannelOpenState) -> WalletResult<()> {
    let bytes = serde_json::to_vec(state).map_err(|error| WalletError::L2(error.to_string()))?;
    secure_write(path, &bytes).map_err(io_error)
}

fn state_commitment(state: &ChannelOpenState) -> WalletResult<String> {
    let mut value =
        serde_json::to_value(state).map_err(|error| WalletError::L2(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| WalletError::L2("channel-open state is not an object".into()))?;
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
        .map_err(io_error)?;
    file.try_lock_exclusive().map_err(|_| {
        WalletError::L2("another wallet process owns this channel-open state".into())
    })?;
    Ok(file)
}

fn hash_field(digest: &mut Sha256, field: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
}

fn default_channel_reuse_version() -> u64 {
    1
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn io_error(error: std::io::Error) -> WalletError {
    WalletError::L2(error.to_string())
}

fn hub_error(error: l2_fast_pay_hub::HubError) -> WalletError {
    WalletError::L2(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    fn input<'a>(account: &'a WalletAccount) -> BeginChannelOpen<'a> {
        BeginChannelOpen {
            operation_id: "f7f2fd0b-7470-42bf-8c1b-a8db7e135204",
            idempotency_key: "hpay:test:channel-open:one",
            user_address: Box::leak(account.address().into_boxed_str()),
            reuse_version: 1,
            user_deposit_zhu: 100_000,
            unsigned_transaction_hex: "020001",
            created_unix: 1_700_000_000,
            expires_unix: 1_700_000_300,
        }
    }

    fn signed_request_for(operation: &ChannelOpenOperation) -> L1ChannelOpenRequest {
        L1ChannelOpenRequest {
            schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: "00".repeat(32),
            node_profile_id: "hacash-mainnet".into(),
            network_instance_id: "ab".repeat(32),
            transaction_format_version: 2,
            operation_id: operation.operation_id.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            created_unix: operation.created_unix,
            expires_unix: operation.expires_unix,
            hub_address: operation.hub_identity.clone(),
            channel_id: operation.channel_id.clone(),
            expected_reuse_version: operation.reuse_version,
            partial_transaction_hex: "020001".into(),
            partial_transaction_commitment: "cd".repeat(32),
            authorization_public_key_hex: "02".to_owned() + &"11".repeat(32),
            authorization_signature_hex: "ef".repeat(64),
        }
    }

    /// A signed store, driven through the real calls, ready to be retired.
    ///
    /// Returns the store and the instant one second past the envelope, which
    /// is the earliest moment `abandon_dead_request` will look at anything
    /// else.
    fn signed_store(
        account: &WalletAccount,
        root: &std::path::Path,
        scope: &str,
    ) -> (ChannelOpenSafety, u64) {
        let mut safety =
            ChannelOpenSafety::open_scoped(account, root, scope, "1Hub", "1Channel", 1).unwrap();
        let operation = safety.begin_or_resume(input(account)).unwrap();
        let request = signed_request_for(&operation);
        safety.mark_signature_may_exist().unwrap();
        safety.persist_user_signed(&request).unwrap();
        let dead = operation.expires_unix + 1;
        (safety, dead)
    }

    /// Every conjunct of the retirement bar, one at a time, at the store.
    ///
    /// The manager repeats most of these before it ever opens the store. They
    /// are pinned here as well because the store is the copy that survives a
    /// crash and is read first on the way back up, and a guard that only one
    /// layer holds is a guard one refactor away from nobody holding it.
    #[test]
    fn a_dead_request_is_only_retired_when_every_condition_holds() {
        let data = tempfile::tempdir().unwrap();
        let account = WalletAccount::create("dead-request-retirement").unwrap();
        let scope = format!("personal:{}", account.address());

        // The envelope is still open.
        {
            let root = data.path().join("l2-live");
            let (mut safety, dead) = signed_store(&account, &root, &scope);
            let envelope = dead - 1;
            let error = safety.abandon_dead_request(envelope).unwrap_err();
            println!("envelope still open -> {error}");
            assert!(safety.abandon_dead_request(envelope).is_err());
            assert_eq!(
                safety.operation().unwrap().status,
                ChannelOpenStatus::UserSigned
            );
        }

        // THE DANGEROUS ONE. A Hub that answers "recovery_required" carries a
        // transaction hash and drives the operation to `RecoveryRequired`,
        // which is one of the three statuses a retirement accepts. Only the
        // response and hash conjuncts stand between that state and a wallet
        // forgetting an open the Hub cosigned and broadcast. This is the state
        // the owner's wallet was one Hub answer away from.
        {
            let root = data.path().join("l2-answered");
            let (mut safety, dead) = signed_store(&account, &root, &scope);
            let operation = safety.operation().unwrap();
            safety
                .persist_hub_status(&L1ChannelOpenStatusResponse {
                    schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.into(),
                    operation_id: operation.operation_id.clone(),
                    channel_id: operation.channel_id.clone(),
                    status: "recovery_required".into(),
                    transaction_hash: Some("ab".repeat(32)),
                })
                .unwrap();
            let answered = safety.operation().unwrap();
            assert_eq!(answered.status, ChannelOpenStatus::RecoveryRequired);
            assert!(answered.response.is_some());
            assert!(answered.node_transaction_hash.is_some());
            let error = safety.abandon_dead_request(dead).unwrap_err();
            println!("hub answered recovery_required with a hash -> {error}");
            assert_eq!(
                safety.operation().unwrap().status,
                ChannelOpenStatus::RecoveryRequired
            );
        }

        // A status that means something left this machine.
        for status in [
            ChannelOpenStatus::HubCosigned,
            ChannelOpenStatus::NodeSubmitted,
            ChannelOpenStatus::Opening,
            ChannelOpenStatus::Confirmed,
            ChannelOpenStatus::PersistedBeforeSigning,
            ChannelOpenStatus::CancelledBeforeSigning,
        ] {
            let root = data.path().join(format!("l2-status-{status:?}"));
            let (mut safety, dead) = signed_store(&account, &root, &scope);
            let mut moved = safety.operation().unwrap();
            moved.status = status;
            safety.state.operation = Some(moved);
            assert!(
                safety.abandon_dead_request(dead).is_err(),
                "{status:?} must never be retired"
            );
            assert_eq!(safety.operation().unwrap().status, status);
        }

        // And the one shape that qualifies.
        {
            let root = data.path().join("l2-dead");
            let (mut safety, dead) = signed_store(&account, &root, &scope);
            safety.abandon_dead_request(dead).unwrap();
            assert_eq!(
                safety.operation().unwrap().status,
                ChannelOpenStatus::AbandonedDeadRequest
            );
            assert!(
                safety.operation().unwrap().request.is_some(),
                "the signature is retired, never forgotten"
            );
            // Running it again finishes a crash between the store write and
            // the wallet-state write rather than refusing.
            safety.abandon_dead_request(dead).unwrap();
        }
    }

    /// A retired operation survives a restart, and the store it lives in can
    /// carry a fresh open afterwards. Without the second half the owner could
    /// never open a Fast Pay channel again: the store directory is derived
    /// from the deterministic channel ID.
    #[test]
    fn a_retired_dead_request_survives_restart_and_frees_the_channel_id() {
        let data = tempfile::tempdir().unwrap();
        let account = WalletAccount::create("retired-dead-request-restart").unwrap();
        let scope = format!("personal:{}", account.address());
        let root = data.path().join("l2");

        let dead = {
            let (mut safety, dead) = signed_store(&account, &root, &scope);
            safety.abandon_dead_request(dead).unwrap();
            dead
        };

        let mut reopened =
            ChannelOpenSafety::open_scoped(&account, &root, &scope, "1Hub", "1Channel", 1).unwrap();
        assert_eq!(
            reopened.operation().unwrap().status,
            ChannelOpenStatus::AbandonedDeadRequest
        );
        assert_eq!(reopened.abandon_dead_request(dead).ok(), Some(()));

        let fresh = reopened
            .begin_or_resume(BeginChannelOpen {
                operation_id: "0d5a2d0f-1f7a-4a91-9d5c-1f0f8a5f1f4a",
                idempotency_key: "hpay:test:channel-open:two",
                user_address: Box::leak(account.address().into_boxed_str()),
                reuse_version: 1,
                user_deposit_zhu: 100_000,
                unsigned_transaction_hex: "020001",
                created_unix: 1_700_001_000,
                expires_unix: 1_700_001_300,
            })
            .expect("a retired dead request must not brick this channel ID");
        assert_eq!(fresh.status, ChannelOpenStatus::PersistedBeforeSigning);
        assert!(fresh.request.is_none());
    }

    /// The durable channel-open store round-trips the signed request without
    /// changing a byte, so the resume comparison in
    /// `service/l2/channel_setup.rs` (`setup.signed_request != Some(&request)`)
    /// does not fire on a request that was written once and read back.
    #[test]
    fn a_reloaded_durable_request_is_byte_identical_to_the_one_persisted() {
        let data = tempfile::tempdir().unwrap();
        let account = WalletAccount::create("durable-open-request-roundtrip").unwrap();
        let scope = format!("personal:{}", account.address());
        let root = data.path().join("l2");

        let request = {
            let mut safety =
                ChannelOpenSafety::open_scoped(&account, &root, &scope, "1Hub", "1Channel", 1)
                    .unwrap();
            let operation = safety.begin_or_resume(input(&account)).unwrap();
            let request = signed_request_for(&operation);
            safety.mark_signature_may_exist().unwrap();
            safety.persist_user_signed(&request).unwrap();
            request
        };

        let reloaded =
            ChannelOpenSafety::open_scoped(&account, &root, &scope, "1Hub", "1Channel", 1)
                .unwrap()
                .operation()
                .unwrap()
                .request
                .expect("the durable store must still hold the request");
        assert_eq!(
            reloaded, request,
            "a reloaded durable request must equal the one that was persisted"
        );
    }

    /// A repeat `mark_recovery_required` on an operation that is already in
    /// `RecoveryRequired` returns `Ok` from the early return in `set_status`
    /// without touching the store. That, and not a failed request comparison,
    /// is why a retry leaves `updated_unix` frozen.
    #[test]
    fn a_repeat_recovery_marker_leaves_the_durable_store_untouched() {
        let data = tempfile::tempdir().unwrap();
        let account = WalletAccount::create("repeat-recovery-marker").unwrap();
        let scope = format!("personal:{}", account.address());
        let root = data.path().join("l2");
        let mut safety =
            ChannelOpenSafety::open_scoped(&account, &root, &scope, "1Hub", "1Channel", 1).unwrap();
        let operation = safety.begin_or_resume(input(&account)).unwrap();
        let request = signed_request_for(&operation);
        safety.mark_signature_may_exist().unwrap();
        safety.persist_user_signed(&request).unwrap();

        safety.mark_recovery_required().unwrap();
        let first = safety.operation().unwrap();
        assert_eq!(first.status, ChannelOpenStatus::RecoveryRequired);
        let path = safety.path.clone();
        let bytes_after_first = std::fs::read(&path).unwrap();

        // The two retries. Both return Ok and neither writes.
        safety.mark_recovery_required().unwrap();
        safety.mark_recovery_required().unwrap();
        let after_retries = safety.operation().unwrap();

        assert_eq!(
            after_retries.updated_unix, first.updated_unix,
            "updated_unix must stay frozen across repeat recovery markers"
        );
        assert_eq!(after_retries, first);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes_after_first,
            "the durable channel-open file must not be rewritten"
        );
        assert!(
            after_retries.request.is_some() && after_retries.response.is_none(),
            "request present, response absent, exactly as the owner's store reads"
        );
    }

    #[test]
    fn scoped_personal_and_agent_open_stores_are_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let personal_root = directory.path().join("personal-l2");
        let agent_root = directory.path().join("agent-l2");
        let account = WalletAccount::create("channel-open-scoped-isolation").unwrap();
        let personal_scope = format!("personal:{}", account.address());
        let agent_scope = "agent_wallet:wallet-one";

        let mut personal = ChannelOpenSafety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
            1,
        )
        .unwrap();
        let mut agent = ChannelOpenSafety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
            1,
        )
        .unwrap();

        assert!(
            personal
                .path
                .starts_with(personal_root.join("channel-open"))
        );
        assert!(agent.path.starts_with(agent_root.join("channel-open")));
        assert_ne!(personal.path, agent.path);
        assert!(agent.operation().is_err());
        assert!(
            ChannelOpenSafety::open_scoped(
                &account,
                &personal_root,
                &personal_scope,
                "../same-hub",
                "../same-channel",
                1,
            )
            .is_err()
        );

        let personal_operation = personal.begin_or_resume(input(&account)).unwrap();
        let mut agent_input = input(&account);
        agent_input.operation_id = "a9915554-98a3-4a88-8e51-c620b9a5d8b8";
        agent_input.idempotency_key = "hpay:test:channel-open:agent";
        let agent_operation = agent.begin_or_resume(agent_input).unwrap();
        agent.mark_signature_may_exist().unwrap();

        assert_eq!(personal.operation().unwrap(), personal_operation);
        assert_eq!(
            agent.operation().unwrap().status,
            ChannelOpenStatus::SignatureMayExist
        );
        assert_ne!(
            personal_operation.operation_id,
            agent_operation.operation_id
        );
        drop(personal);
        drop(agent);

        let personal = ChannelOpenSafety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
            1,
        )
        .unwrap();
        let agent = ChannelOpenSafety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
            1,
        )
        .unwrap();
        assert_eq!(
            personal.operation().unwrap().status,
            ChannelOpenStatus::PersistedBeforeSigning
        );
        assert_eq!(
            agent.operation().unwrap().status,
            ChannelOpenStatus::SignatureMayExist
        );
    }

    #[test]
    fn persisted_intent_survives_restart_and_resumes_exactly() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-restart").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        let first = safety.begin_or_resume(input(&account)).unwrap();
        drop(safety);
        let mut reopened = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        let resumed = reopened.begin_or_resume(input(&account)).unwrap();
        assert_eq!(first, resumed);
        assert_eq!(resumed.status, ChannelOpenStatus::PersistedBeforeSigning);
    }

    #[test]
    fn changed_intent_is_blocked_while_recovery_is_unresolved() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-conflict").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        safety.begin_or_resume(input(&account)).unwrap();
        let mut changed = input(&account);
        changed.unsigned_transaction_hex = "020002";
        assert!(safety.begin_or_resume(changed).is_err());
    }

    #[test]
    fn tampered_state_fails_closed() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-tamper").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        safety.begin_or_resume(input(&account)).unwrap();
        let path = safety.path.clone();
        drop(safety);
        let raw = fs::read_to_string(&path).unwrap();
        fs::write(&path, raw.replace("100000", "100001")).unwrap();
        assert!(ChannelOpenSafety::open(&account, "hub", "channel", 1).is_err());
    }
    #[test]
    fn signing_requires_durable_may_exist_marker() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-sign-marker").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        let operation = safety.begin_or_resume(input(&account)).unwrap();
        let request = L1ChannelOpenRequest {
            schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: "00".repeat(32),
            node_profile_id: "hpay-hacash-mainnet-v1".into(),
            network_instance_id: "11".repeat(32),
            transaction_format_version: 2,
            operation_id: operation.operation_id.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            created_unix: operation.created_unix,
            expires_unix: operation.expires_unix,
            hub_address: operation.hub_identity.clone(),
            channel_id: operation.channel_id.clone(),
            expected_reuse_version: operation.reuse_version,
            partial_transaction_commitment: "00".repeat(32),
            partial_transaction_hex: "020001".into(),
            authorization_public_key_hex: "02".repeat(33),
            authorization_signature_hex: "00".repeat(64),
        };
        assert!(safety.persist_user_signed(&request).is_err());
        safety.mark_signature_may_exist().unwrap();
        safety.persist_user_signed(&request).unwrap();
    }

    #[test]
    fn legacy_signed_request_is_reported_as_recovery_required() {
        let legacy = br#"{
            "schema_version":1,
            "journal_sequence":1,
            "journal_head":"head",
            "state_commitment":"commitment",
            "operation":{
                "request":{
                    "schema":"hpay-l1-channel-open/2",
                    "network":"mainnet",
                    "chain_id":0
                }
            }
        }"#;
        let error = reject_legacy_channel_open_request(legacy).unwrap_err();
        assert!(error.to_string().contains("RecoveryRequired"));
        assert!(error.to_string().contains("network binding"));
    }

    #[test]
    fn ambiguous_signing_marker_survives_restart_without_bytes() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-ambiguous-sign").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        safety.begin_or_resume(input(&account)).unwrap();
        safety.mark_signature_may_exist().unwrap();
        drop(safety);
        let reopened = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        let operation = reopened.operation().unwrap();
        assert_eq!(operation.status, ChannelOpenStatus::SignatureMayExist);
        assert!(operation.request.is_none());
    }

    #[test]
    fn pending_locator_is_account_scoped_and_exact() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-locator").unwrap();
        let locator = PendingChannelOpenLocator {
            operation_id: "f7f2fd0b-7470-42bf-8c1b-a8db7e135204".into(),
            hub_identity: "1Hub".into(),
            channel_id: "ab".repeat(16),
            reuse_version: 1,
            user_address: account.address(),
            left_deposit: "8:248".into(),
            right_deposit: "0:248".into(),
        };
        persist_pending_locator(&account, &locator).unwrap();
        assert_eq!(
            load_pending_locator(&account).unwrap(),
            Some(locator.clone())
        );
        assert!(clear_pending_locator(&account, "different-operation").is_err());
        clear_pending_locator(&account, &locator.operation_id).unwrap();
        assert_eq!(load_pending_locator(&account).unwrap(), None);
    }

    #[test]
    fn channel_reuse_incarnations_have_independent_authenticated_stores() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-reuse-isolation").unwrap();

        let mut first = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        let first_path = first.path.clone();
        let first_operation = first.begin_or_resume(input(&account)).unwrap();
        assert_eq!(first_operation.reuse_version, 1);
        drop(first);

        let mut second = ChannelOpenSafety::open(&account, "hub", "channel", 2).unwrap();
        let second_path = second.path.clone();
        let mut second_input = input(&account);
        second_input.reuse_version = 2;
        let second_operation = second.begin_or_resume(second_input).unwrap();
        assert_eq!(second_operation.reuse_version, 2);
        assert_ne!(first_path, second_path);
        drop(second);

        let reopened_first = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        assert_eq!(reopened_first.operation().unwrap(), first_operation);
    }

    #[test]
    fn definitely_unsigned_operation_can_be_cancelled_and_replaced() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-open-cancel").unwrap();
        let mut safety = ChannelOpenSafety::open(&account, "hub", "channel", 1).unwrap();
        safety.begin_or_resume(input(&account)).unwrap();
        safety.cancel_before_signing().unwrap();
        let mut replacement = input(&account);
        replacement.operation_id = "18a97658-cf33-401a-96a5-65c8a28dd4cb";
        replacement.idempotency_key = "hpay:test:channel-open:two";
        let operation = safety.begin_or_resume(replacement).unwrap();
        assert_eq!(
            operation.operation_id,
            "18a97658-cf33-401a-96a5-65c8a28dd4cb"
        );
        assert_eq!(operation.status, ChannelOpenStatus::PersistedBeforeSigning);
    }
}
