//! Authenticated Personal Wallet recovery state for a Hub-coordinated L1 close.
//!
//! The exact user-signed Hub request is persisted before network submission.
//! If a crash happens after the pre-sign marker but before those exact bytes are
//! durable, the operation remains permanently recovery-required and is never
//! signed again.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use hkdf::Hkdf;
use l2_fast_pay_hub::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use l2_fast_pay_hub::l1_channel::MAX_CHANNEL_TRANSACTION_BYTES;
use l2_fast_pay_hub::l1_channel_close::{
    L1_CHANNEL_CLOSE_VOUCHER_STATUS, L1ChannelCloseRequest, L1ChannelCloseResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::l2_storage_scope::validate_scoped_l2_storage;
use crate::paths::{secure_write, wallet_data_root};

const KEY_DOMAIN: &[u8] = b"HPAY/L1/CHANNEL-CLOSE/JOURNAL/AUTH/V1";

/// Narrow authority used only to derive an authenticated channel-close journal
/// key. Implementations must not expose the wallet secret or generic signing.
pub trait ChannelCloseJournalKeyProvider {
    fn derive_channel_close_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>>;
}

impl ChannelCloseJournalKeyProvider for WalletAccount {
    fn derive_channel_close_journal_key(
        &self,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        derive_key(self, wallet_scope, hub_identity, channel_id)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelCloseStatus {
    PersistedBeforeSigning,
    SignatureMayExist,
    UserSigned,
    HubSubmitted,
    Confirmed,
    RecoveryRequired,
    /// The Hub countersigned a delta-zero close and handed the exact bytes
    /// back instead of broadcasting them. The channel is still open and still
    /// payable; nothing has reached a chain.
    ///
    /// This is not a trustless exit and must never be described as one. The
    /// Hub chose to sign once and could have refused, in which case the
    /// deposit would have been stuck. Once these bytes exist the Hub carries
    /// the whole exposure, because they refund the balances recorded at open
    /// no matter how far the channel is later spent down. That is acceptable
    /// only in this bounded pilot, where the owner runs the Hub.
    VoucherHeld,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelCloseOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub wallet_scope: String,
    pub hub_identity: String,
    pub channel_id: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub user_address: String,
    pub unsigned_transaction_hex: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub status: ChannelCloseStatus,
    pub request: Option<L1ChannelCloseRequest>,
    pub response: Option<L1ChannelCloseResponse>,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ChannelCloseState {
    schema_version: u32,
    journal_sequence: u64,
    journal_head: String,
    state_commitment: String,
    operation: Option<ChannelCloseOperation>,
}

pub struct BeginChannelClose<'a> {
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
    pub user_address: &'a str,
    pub reuse_version: u64,
    pub open_height: u64,
    pub unsigned_transaction_hex: &'a str,
    pub created_unix: u64,
    pub expires_unix: u64,
}

pub struct ChannelCloseSafety {
    path: PathBuf,
    wallet_scope: String,
    hub_identity: String,
    channel_id: String,
    journal: AuthenticatedJournal,
    state: ChannelCloseState,
    _lock: fs::File,
}

impl ChannelCloseSafety {
    pub fn open(
        account: &WalletAccount,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        let wallet_scope = format!("personal:{}", account.address());
        Self::open_scoped(
            account,
            wallet_data_root().join("l2").join("personal"),
            &wallet_scope,
            hub_identity,
            channel_id,
        )
    }

    pub fn open_scoped(
        key_provider: &impl ChannelCloseJournalKeyProvider,
        trusted_l2_root: impl AsRef<Path>,
        wallet_scope: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Self> {
        let trusted_l2_root = trusted_l2_root.as_ref();
        validate_scoped_l2_storage(trusted_l2_root, wallet_scope)?;
        let directory =
            scoped_safety_directory(trusted_l2_root, wallet_scope, hub_identity, channel_id);
        fs::create_dir_all(&directory).map_err(io_error)?;
        let path = directory.join("channel-close.json");
        let lock = acquire_lock(&directory.join("channel-close.lock"))?;
        let mut key = key_provider.derive_channel_close_journal_key(
            wallet_scope,
            hub_identity,
            channel_id,
        )?;
        let journal = AuthenticatedJournal::open(
            directory.join("channel-close.journal.jsonl"),
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
        input: BeginChannelClose<'_>,
    ) -> WalletResult<ChannelCloseOperation> {
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
            return Err(WalletError::L2(
                "RecoveryRequired: a different channel-close operation is unresolved".into(),
            ));
        }
        if input.reuse_version == 0
            || input.open_height == 0
            || input.created_unix == 0
            || input.expires_unix <= input.created_unix
        {
            return Err(WalletError::L2(
                "invalid channel-close recovery binding".into(),
            ));
        }
        let operation = ChannelCloseOperation {
            operation_id: input.operation_id.to_owned(),
            idempotency_key: input.idempotency_key.to_owned(),
            wallet_scope: self.wallet_scope.clone(),
            hub_identity: self.hub_identity.clone(),
            channel_id: self.channel_id.clone(),
            reuse_version: input.reuse_version,
            open_height: input.open_height,
            user_address: input.user_address.to_owned(),
            unsigned_transaction_hex: input.unsigned_transaction_hex.to_owned(),
            created_unix: input.created_unix,
            expires_unix: input.expires_unix,
            status: ChannelCloseStatus::PersistedBeforeSigning,
            request: None,
            response: None,
            updated_unix: input.created_unix,
        };
        self.transition(
            operation.clone(),
            JournalPhase::L1CloseFreezeIntentPersisted,
        )?;
        Ok(operation)
    }

    pub fn mark_signature_may_exist(&mut self) -> WalletResult<ChannelCloseOperation> {
        let mut operation = self.operation()?;
        if operation.status == ChannelCloseStatus::SignatureMayExist {
            return Ok(operation);
        }
        if operation.status != ChannelCloseStatus::PersistedBeforeSigning {
            return Err(WalletError::L2(
                "RecoveryRequired: channel-close signing state is not fresh".into(),
            ));
        }
        operation.status = ChannelCloseStatus::SignatureMayExist;
        operation.updated_unix = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::L1CloseSignatureMayExist)?;
        Ok(operation)
    }

    pub fn persist_user_signed(
        &mut self,
        request: &L1ChannelCloseRequest,
    ) -> WalletResult<ChannelCloseOperation> {
        let mut operation = self.operation()?;
        require_request_binding(&operation, request)?;
        if let Some(existing) = &operation.request {
            if existing != request {
                return Err(WalletError::L2(
                    "idempotency conflict: channel-close signed bytes changed".into(),
                ));
            }
            return Ok(operation);
        }
        if operation.status != ChannelCloseStatus::SignatureMayExist {
            return Err(WalletError::L2(
                "RecoveryRequired: exact close bytes were not preceded by the durable signing marker"
                    .into(),
            ));
        }
        operation.request = Some(request.clone());
        operation.status = ChannelCloseStatus::UserSigned;
        operation.updated_unix = unix_timestamp();
        self.transition(operation.clone(), JournalPhase::L1SignatureProduced)?;
        Ok(operation)
    }

    pub fn validate_hub_response(&self, response: &L1ChannelCloseResponse) -> WalletResult<()> {
        validate_hub_response(&self.operation()?, response)
    }
    pub fn persist_hub_response(
        &mut self,
        response: &L1ChannelCloseResponse,
    ) -> WalletResult<ChannelCloseOperation> {
        let mut operation = self.operation()?;
        validate_hub_response(&operation, response)?;
        let next_status =
            durable_status_for_hub_status(response.status.as_str()).ok_or_else(|| {
                WalletError::L2(format!(
                    "Hub returned an unsupported channel-close status: {}",
                    response.status
                ))
            })?;
        if !can_accept_hub_status(operation.status, next_status) {
            return Err(WalletError::L2(format!(
                "channel-close state cannot move backward from {:?} to {:?}",
                operation.status, next_status
            )));
        }
        if let Some(existing) = &operation.response
            && operation.status == ChannelCloseStatus::Confirmed
            && existing != response
        {
            return Err(WalletError::L2(
                "idempotency conflict: confirmed channel-close response changed".into(),
            ));
        }
        if operation.status == ChannelCloseStatus::Confirmed {
            return Ok(operation);
        }
        operation.response = Some(response.clone());
        operation.status = next_status;
        operation.updated_unix = unix_timestamp();
        let phase = match operation.status {
            ChannelCloseStatus::Confirmed => JournalPhase::L1CloseConfirmed,
            ChannelCloseStatus::HubSubmitted => JournalPhase::L1CloseSubmitted,
            ChannelCloseStatus::RecoveryRequired => JournalPhase::L1CloseRecoveryRequired,
            ChannelCloseStatus::VoucherHeld => JournalPhase::L1CloseVoucherIssued,
            _ => unreachable!(),
        };
        self.transition(operation.clone(), phase)?;
        Ok(operation)
    }
    pub fn mark_recovery_required(&mut self) -> WalletResult<()> {
        let mut operation = self.operation()?;
        if operation.status == ChannelCloseStatus::RecoveryRequired {
            return Ok(());
        }
        if operation.status == ChannelCloseStatus::Confirmed {
            return Err(WalletError::L2(
                "confirmed channel-close recovery state is terminal".into(),
            ));
        }
        // A verified voucher in hand is a success, not a failure to recover
        // from. Overwriting it would throw away the owner's only route out of
        // the channel that does not need the Hub.
        if operation.status == ChannelCloseStatus::VoucherHeld {
            return Err(WalletError::L2(
                "a verified close voucher is terminal and is never replaced".into(),
            ));
        }
        operation.status = ChannelCloseStatus::RecoveryRequired;
        operation.updated_unix = unix_timestamp();
        self.transition(operation, JournalPhase::L1CloseRecoveryRequired)
    }

    pub fn operation(&self) -> WalletResult<ChannelCloseOperation> {
        self.state
            .operation
            .clone()
            .ok_or_else(|| WalletError::L2("channel-close recovery operation is missing".into()))
    }

    fn transition(
        &mut self,
        operation: ChannelCloseOperation,
        phase: JournalPhase,
    ) -> WalletResult<()> {
        let previous = state_commitment(&self.state)?;
        let mut next = self.state.clone();
        next.schema_version = 1;
        next.operation = Some(operation.clone());
        let new_commitment = state_commitment(&next)?;
        let request_commitment = operation
            .request
            .as_ref()
            .map(l2_fast_pay_hub::l1_channel_close::close_request_commitment)
            .transpose()
            .map_err(hub_error)?
            .unwrap_or_else(|| {
                hex::encode(Sha256::digest(
                    operation.unsigned_transaction_hex.as_bytes(),
                ))
            });
        let record = self
            .journal
            .append(JournalEvent {
                wallet_scope: operation.wallet_scope.clone(),
                hub_or_provider_identity: operation.hub_identity.clone(),
                channel_id: operation.channel_id.clone(),
                channel_reuse_version: operation.reuse_version,
                operation_id: operation.operation_id.clone(),
                operation_type: JournalOperationType::L1ChannelClose,
                operation_phase: phase,
                amount_units: 0,
                sender: operation.user_address.clone(),
                recipient: operation.hub_identity.clone(),
                previous_state_commitment: previous,
                new_state_commitment: new_commitment.clone(),
                idempotency_key: operation.idempotency_key.clone(),
                request_commitment,
                expected_bill_number: None,
                unsigned_state_commitment: operation
                    .request
                    .as_ref()
                    .map(|request| request.partial_transaction_commitment.clone()),
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

fn validate_hub_response(
    operation: &ChannelCloseOperation,
    response: &L1ChannelCloseResponse,
) -> WalletResult<()> {
    if response.schema != l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA
        || response.operation_id != operation.operation_id
        || !response
            .channel_id
            .eq_ignore_ascii_case(&operation.channel_id)
        || response.reuse_version != operation.reuse_version
        || response.open_height != operation.open_height
    {
        return Err(WalletError::L2(
            "Hub channel-close response changed the durable operation".into(),
        ));
    }
    if let Some(hash) = response.transaction_hash.as_deref() {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(WalletError::L2(
                "Hub channel-close response contains an invalid transaction hash".into(),
            ));
        }
        let request = operation.request.as_ref().ok_or_else(|| {
            WalletError::L2("exact user-signed close request is unavailable".into())
        })?;
        let raw = hex::decode(&request.partial_transaction_hex)
            .map_err(|error| WalletError::Transaction(error.to_string()))?;
        let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
            .map_err(|error| WalletError::Transaction(error.to_string()))?;
        if consumed != raw.len()
            || !hex::encode(transaction.hash().as_bytes()).eq_ignore_ascii_case(hash)
        {
            return Err(WalletError::L2(
                "Hub channel-close transaction hash differs from the exact signed request".into(),
            ));
        }
    } else if matches!(
        response.status.as_str(),
        "submitted" | "confirmed_closed" | "retired" | L1_CHANNEL_CLOSE_VOUCHER_STATUS
    ) {
        return Err(WalletError::L2(
            "Hub channel-close response is missing its transaction hash".into(),
        ));
    }
    validate_voucher_fields(operation, response)
}

/// Re-prove a voucher response from the bytes, never from the Hub's word.
///
/// The Hub already ran this exact check before it signed
/// (`l2_fast_pay_hub::l1_channel_close::validate_and_cosign_channel_close`).
/// Repeating it here is deliberate: the wallet is about to store these bytes
/// as the owner's only route out of the channel without the Hub, so a claim by
/// the Hub that they are valid is worth nothing. An unverified voucher is
/// never stored.
fn validate_voucher_fields(
    operation: &ChannelCloseOperation,
    response: &L1ChannelCloseResponse,
) -> WalletResult<()> {
    if response.status != L1_CHANNEL_CLOSE_VOUCHER_STATUS {
        // Only the voucher path returns bytes. On any other status the Hub
        // owns the broadcast, so a second copy of a live close arriving here
        // is not something to store quietly.
        if response.signed_transaction_hex.is_some()
            || response.signed_transaction_commitment.is_some()
        {
            return Err(WalletError::L2(
                "Hub returned signed close bytes on a status that must never carry them".into(),
            ));
        }
        return Ok(());
    }
    let request = operation.request.as_ref().ok_or_else(|| {
        WalletError::L2(
            "a close voucher cannot be verified without the exact user-signed request".into(),
        )
    })?;
    let transaction_hash = response.transaction_hash.as_deref().ok_or_else(|| {
        WalletError::L2("Hub close voucher is missing its transaction hash".into())
    })?;
    let signed_transaction_hex = response.signed_transaction_hex.as_deref().ok_or_else(|| {
        WalletError::L2("Hub close voucher is missing its countersigned bytes".into())
    })?;
    let commitment = response
        .signed_transaction_commitment
        .as_deref()
        .ok_or_else(|| {
            WalletError::L2("Hub close voucher is missing its bytes commitment".into())
        })?;
    let verified = verify_channel_close_voucher_bytes(
        signed_transaction_hex,
        transaction_hash,
        &operation.user_address,
        &operation.hub_identity,
        &operation.channel_id,
        request.chain_id,
    )?;
    if !verified
        .signed_transaction_commitment
        .eq_ignore_ascii_case(commitment)
    {
        return Err(WalletError::L2(
            "Hub close voucher commitment does not cover the returned bytes".into(),
        ));
    }
    Ok(())
}

/// The transaction hash of an encoded transaction, read from the bytes.
///
/// Exists so a caller can prove that a countersigned transaction is the one it
/// authored: `fill_sign` adds a signature without changing `hash()`, so a
/// voucher whose hash differs from the wallet's own partial bytes is a
/// different transaction, whatever the Hub called it.
pub fn transaction_hash_of_hex(transaction_hex: &str) -> WalletResult<String> {
    let raw = hex::decode(transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if consumed != raw.len() {
        return Err(WalletError::L2(
            "transaction bytes contain trailing data".into(),
        ));
    }
    Ok(hex::encode(transaction.hash().as_bytes()))
}

/// What a verified delta-zero close voucher is, once the bytes have proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelCloseVoucher {
    pub transaction_hash: String,
    pub signed_transaction_commitment: String,
}

/// Prove that these exact bytes are a fully countersigned, delta-zero
/// `[ChainAllow, ChannelClose]` for this exact channel, and nothing else.
///
/// Everything here is derived from the bytes themselves, so the caller depends
/// on the Hub for the signature only, never for the claim about it. The two
/// action topology is load bearing: a third Action 14 would move principal,
/// and a delta-zero voucher must move none. `close_channel_default` then
/// refunds the balances recorded at open, which for a zero-Hub-deposit channel
/// is the whole deposit to the owner.
pub fn verify_channel_close_voucher_bytes(
    signed_transaction_hex: &str,
    expected_transaction_hash: &str,
    owner_address: &str,
    hub_address: &str,
    channel_id: &str,
    chain_id: u32,
) -> WalletResult<VerifiedChannelCloseVoucher> {
    if owner_address.is_empty() || hub_address.is_empty() || owner_address == hub_address {
        return Err(WalletError::L2(
            "close voucher parties are missing or identical".into(),
        ));
    }
    if expected_transaction_hash.len() != 64
        || !expected_transaction_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WalletError::L2(
            "close voucher transaction hash is malformed".into(),
        ));
    }
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if raw.is_empty() || raw.len() > MAX_CHANNEL_TRANSACTION_BYTES {
        return Err(WalletError::L2(
            "close voucher bytes are empty or oversized".into(),
        ));
    }
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if consumed != raw.len() {
        return Err(WalletError::L2(
            "close voucher bytes contain trailing data".into(),
        ));
    }
    if transaction.ty() != 2 {
        return Err(WalletError::L2(
            "close voucher must be a Type 2 transaction".into(),
        ));
    }
    let actions = transaction.actions();
    if actions.len() != 2 || actions[0].kind() != 0x0411 || actions[1].kind() != 3 {
        return Err(WalletError::L2(
            "close voucher actions must be exactly [ChainAllow, ChannelClose]".into(),
        ));
    }
    if actions
        .iter()
        .any(|action| protocol::action::HacFromToTrs::downcast(action).is_some())
    {
        return Err(WalletError::L2(
            "close voucher carries a principal transfer and is not delta zero".into(),
        ));
    }
    let guard = protocol::action::ChainAllow::downcast(&actions[0])
        .ok_or_else(|| WalletError::L2("close voucher ChainAllow codec mismatch".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != chain_id {
        return Err(WalletError::L2(format!(
            "close voucher must bind exactly chain {chain_id}"
        )));
    }
    let close = mint::action::ChannelClose::downcast(&actions[1])
        .ok_or_else(|| WalletError::L2("close voucher ChannelClose codec mismatch".into()))?;
    if hex::encode(close.channel_id.as_bytes()) != channel_id.to_ascii_lowercase() {
        return Err(WalletError::L2(
            "close voucher names a different channel".into(),
        ));
    }
    let owner = field::Address::from_readable(owner_address)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let hub = field::Address::from_readable(hub_address)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if transaction.main() != owner {
        return Err(WalletError::L2(
            "close voucher fee payer is not the channel owner".into(),
        ));
    }
    if !hex::encode(transaction.hash().as_bytes()).eq_ignore_ascii_case(expected_transaction_hash) {
        return Err(WalletError::L2(
            "close voucher bytes hash to a different transaction".into(),
        ));
    }
    if transaction.signs().len() != 2 {
        return Err(WalletError::L2(
            "close voucher must carry exactly the two party signatures".into(),
        ));
    }
    let signers: Vec<field::Address> = transaction
        .signs()
        .iter()
        .map(|sign| field::Address::from(sys::Account::get_address_by_public_key(*sign.publickey)))
        .collect();
    if !signers.contains(&owner) || !signers.contains(&hub) {
        return Err(WalletError::L2(
            "close voucher signatures are not the owner and the Hub".into(),
        ));
    }
    let owner_verified =
        protocol::transaction::verify_target_signature(&owner, transaction.as_read())
            .map_err(|error| WalletError::L2(error.to_string()))?;
    let hub_verified = protocol::transaction::verify_target_signature(&hub, transaction.as_read())
        .map_err(|error| WalletError::L2(error.to_string()))?;
    if !owner_verified || !hub_verified {
        return Err(WalletError::L2(
            "close voucher is missing a verified party signature".into(),
        ));
    }
    Ok(VerifiedChannelCloseVoucher {
        transaction_hash: expected_transaction_hash.to_ascii_lowercase(),
        signed_transaction_commitment: hex::encode(Sha256::digest(&raw)),
    })
}

fn durable_status_for_hub_status(status: &str) -> Option<ChannelCloseStatus> {
    match status {
        "retired" => Some(ChannelCloseStatus::Confirmed),
        "submitted" | "confirmed_closed" => Some(ChannelCloseStatus::HubSubmitted),
        "recovery_required" => Some(ChannelCloseStatus::RecoveryRequired),
        L1_CHANNEL_CLOSE_VOUCHER_STATUS => Some(ChannelCloseStatus::VoucherHeld),
        _ => None,
    }
}

fn can_accept_hub_status(current: ChannelCloseStatus, next: ChannelCloseStatus) -> bool {
    use ChannelCloseStatus::*;
    match current {
        Confirmed => next == Confirmed,
        // Holding a voucher is its own terminal shape. The Hub broadcasts
        // nothing on this path, so there is no later submission or
        // confirmation for it to report, and a channel that has a voucher can
        // never also be closed cooperatively.
        VoucherHeld => next == VoucherHeld,
        PersistedBeforeSigning | SignatureMayExist | UserSigned => {
            matches!(
                next,
                HubSubmitted | RecoveryRequired | Confirmed | VoucherHeld
            )
        }
        // Once a close was submitted or has failed into recovery, a voucher
        // for the same operation would be a second signed close.
        HubSubmitted | RecoveryRequired => {
            matches!(next, HubSubmitted | RecoveryRequired | Confirmed)
        }
    }
}
fn same_intent(
    existing: &ChannelCloseOperation,
    input: &BeginChannelClose<'_>,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
) -> bool {
    existing.operation_id == input.operation_id
        && existing.idempotency_key == input.idempotency_key
        && existing.wallet_scope == wallet_scope
        && existing.hub_identity == hub_identity
        && existing.channel_id == channel_id
        && existing.user_address == input.user_address
        && existing.reuse_version == input.reuse_version
        && existing.open_height == input.open_height
        && existing.unsigned_transaction_hex == input.unsigned_transaction_hex
        && existing.created_unix == input.created_unix
        && existing.expires_unix == input.expires_unix
}

fn require_request_binding(
    operation: &ChannelCloseOperation,
    request: &L1ChannelCloseRequest,
) -> WalletResult<()> {
    if request.operation_id != operation.operation_id
        || request.idempotency_key != operation.idempotency_key
        || request.hub_address != operation.hub_identity
        || request.user_address != operation.user_address
        || !request
            .channel_id
            .eq_ignore_ascii_case(&operation.channel_id)
        || request.reuse_version != operation.reuse_version
        || request.open_height != operation.open_height
        || request.created_unix != operation.created_unix
        || request.expires_unix != operation.expires_unix
    {
        return Err(WalletError::L2(
            "signed channel-close request does not match durable intent".into(),
        ));
    }
    Ok(())
}

fn scoped_safety_directory(
    trusted_l2_root: &Path,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L1/CHANNEL-CLOSE/STORE/V1");
    hash_field(&mut digest, wallet_scope.as_bytes());
    hash_field(&mut digest, hub_identity.as_bytes());
    hash_field(&mut digest, channel_id.as_bytes());
    trusted_l2_root
        .join("channel-close")
        .join(hex::encode(digest.finalize()))
}

fn derive_key(
    account: &WalletAccount,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
) -> WalletResult<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new(account.inner().secret_key().serialize());
    let mut salt = Sha256::new();
    salt.update(KEY_DOMAIN);
    hash_field(&mut salt, wallet_scope.as_bytes());
    hash_field(&mut salt, hub_identity.as_bytes());
    hash_field(&mut salt, channel_id.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), secret.as_slice());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(KEY_DOMAIN, output.as_mut())
        .map_err(|_| WalletError::L2("channel-close journal key derivation failed".into()))?;
    secret.zeroize();
    Ok(output)
}

fn initialize_state(
    path: &Path,
    state: &mut ChannelCloseState,
    journal: &AuthenticatedJournal,
    wallet_scope: &str,
    hub_identity: &str,
    channel_id: &str,
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
        let record = journal
            .append(JournalEvent {
                wallet_scope: wallet_scope.to_owned(),
                hub_or_provider_identity: hub_identity.to_owned(),
                channel_id: channel_id.to_owned(),
                channel_reuse_version: 0,
                operation_id: "personal-channel-close-store-v1".into(),
                operation_type: JournalOperationType::Migration,
                operation_phase: JournalPhase::RecoveryCompleted,
                amount_units: 0,
                sender: String::new(),
                recipient: hub_identity.to_owned(),
                previous_state_commitment: current.clone(),
                new_state_commitment: current.clone(),
                idempotency_key: "personal-channel-close-store-v1".into(),
                request_commitment: current.clone(),
                expected_bill_number: None,
                unsigned_state_commitment: None,
                created_at: unix_timestamp(),
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
            "authenticated channel-close state schema is invalid".into(),
        ));
    }
    let current = state_commitment(state)?;
    let last = records
        .last()
        .ok_or_else(|| WalletError::L2("channel-close journal head is missing".into()))?;
    if checkpoint
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.sequence > last.entry_sequence)
        || state.journal_sequence != last.entry_sequence
        || state.journal_head != last.entry_hash
        || state.state_commitment != current
        || last.new_state_commitment != current
    {
        return Err(WalletError::L2(
            "RecoveryRequired: channel-close journal and state differ".into(),
        ));
    }
    Ok(())
}

fn load_state(path: &Path) -> WalletResult<ChannelCloseState> {
    if !path.exists() {
        return Ok(ChannelCloseState::default());
    }
    if fs::metadata(path).map_err(io_error)?.len() > 4 * 1024 * 1024 {
        return Err(WalletError::L2(
            "channel-close recovery state is oversized".into(),
        ));
    }
    let bytes = fs::read(path).map_err(io_error)?;
    reject_legacy_channel_close_request(&bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| WalletError::L2(error.to_string()))
}

fn reject_legacy_channel_close_request(bytes: &[u8]) -> WalletResult<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        WalletError::L2(format!("invalid channel-close recovery state: {error}"))
    })?;
    let Some(request) = value
        .get("operation")
        .and_then(|operation| operation.get("request"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let schema_is_current = request.get("schema").and_then(serde_json::Value::as_str)
        == Some(l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA);
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
            "RecoveryRequired: legacy channel-close request has no authenticated network binding; it cannot be signed, retried, or broadcast automatically"
                .into(),
        ));
    }
    Ok(())
}

fn save_state(path: &Path, state: &ChannelCloseState) -> WalletResult<()> {
    let bytes = serde_json::to_vec(state).map_err(|error| WalletError::L2(error.to_string()))?;
    secure_write(path, &bytes).map_err(io_error)
}

fn state_commitment(state: &ChannelCloseState) -> WalletResult<String> {
    let mut value =
        serde_json::to_value(state).map_err(|error| WalletError::L2(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| WalletError::L2("channel-close state is not an object".into()))?;
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
        WalletError::L2("another wallet process owns this channel-close state".into())
    })?;
    Ok(file)
}

fn hash_field(digest: &mut Sha256, field: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
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
mod voucher_tests {
    use basis::interface::{Transaction, TransactionRead};
    use field::{AddrOrPtr, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
    use l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA;
    use mint::action::ChannelClose;
    use protocol::action::{ChainAllow, ChainIDList, HacFromToTrs};
    use protocol::transaction::TransactionType2;
    use sys::Account;

    use super::*;

    const CHANNEL_ID: &str = "00112233445566778899aabbccddeeff";
    const CHAIN_ID: u32 = 7;

    fn account(byte: u8) -> Account {
        Account::create_by(&hex::encode([byte; 32])).unwrap()
    }

    struct VoucherFixture {
        owner: String,
        hub: String,
        operation: ChannelCloseOperation,
        response: L1ChannelCloseResponse,
    }

    /// Build the exact thing the Hub returns on the voucher path: a Type 2
    /// `[ChainAllow, ChannelClose]` carrying both party signatures.
    fn voucher_fixture(with_principal_transfer: bool, sign_hub: bool) -> VoucherFixture {
        crate::protocol_init::ensure_protocol_setup();
        let owner = account(41);
        let hub = account(43);
        let mut close = ChannelClose::new();
        close.channel_id =
            ChannelId::from(<[u8; 16]>::try_from(hex::decode(CHANNEL_ID).unwrap()).unwrap());
        let now = 1_700_000_000_u64;
        let mut tx = TransactionType2::new_by(
            Address::from_readable(owner.readable()).unwrap(),
            Amount::from("0.0001").unwrap(),
            now,
        );
        let mut guard = ChainAllow::new();
        guard.chains = ChainIDList::from_list(vec![Uint4::from(CHAIN_ID)]).unwrap();
        tx.push_action(Box::new(guard)).unwrap();
        tx.push_action(Box::new(close)).unwrap();
        if with_principal_transfer {
            let mut principal = HacFromToTrs::new();
            principal.from = AddrOrPtr::from_addr(Address::from_readable(hub.readable()).unwrap());
            principal.to = AddrOrPtr::from_addr(Address::from_readable(owner.readable()).unwrap());
            principal.hacash = Amount::from("0.5").unwrap();
            tx.push_action(Box::new(principal)).unwrap();
        }
        tx.fill_sign(&owner).unwrap();
        let partial_transaction_hex = hex::encode(tx.serialize());
        if sign_hub {
            tx.fill_sign(&hub).unwrap();
        }
        let signed = tx.serialize();
        let signed_transaction_hex = hex::encode(&signed);
        let transaction_hash = hex::encode(tx.hash().as_bytes());

        let request = L1ChannelCloseRequest {
            schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
            network: "testnet".into(),
            chain_id: CHAIN_ID,
            mainnet: false,
            block_1_hash: "11".repeat(32),
            node_profile_id: "hpay-pilot".into(),
            network_instance_id: "aa".repeat(16),
            transaction_format_version: 2,
            operation_id: "8a5b3fb0-2f0f-4a34-92a2-4a4b7d0a1b11".into(),
            idempotency_key: "hpay:test:voucher:one".into(),
            created_unix: now,
            expires_unix: now + 300,
            hub_address: hub.readable().into(),
            user_address: owner.readable().into(),
            channel_id: CHANNEL_ID.into(),
            reuse_version: 1,
            open_height: 900_000,
            partial_transaction_commitment: hex::encode(Sha256::digest(
                partial_transaction_hex.as_bytes(),
            )),
            partial_transaction_hex,
            authorization_public_key_hex: hex::encode(owner.public_key().serialize_compressed()),
            authorization_signature_hex: String::new(),
        };
        let operation = ChannelCloseOperation {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            wallet_scope: "agent_wallet:voucher".into(),
            hub_identity: hub.readable().into(),
            channel_id: CHANNEL_ID.into(),
            reuse_version: 1,
            open_height: 900_000,
            user_address: owner.readable().into(),
            unsigned_transaction_hex: "020001".into(),
            created_unix: now,
            expires_unix: now + 300,
            status: ChannelCloseStatus::UserSigned,
            request: Some(request),
            response: None,
            updated_unix: now,
        };
        let response = L1ChannelCloseResponse {
            schema: l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA.into(),
            operation_id: operation.operation_id.clone(),
            channel_id: CHANNEL_ID.into(),
            reuse_version: 1,
            open_height: 900_000,
            status: L1_CHANNEL_CLOSE_VOUCHER_STATUS.into(),
            transaction_hash: Some(transaction_hash),
            signed_transaction_hex: Some(signed_transaction_hex),
            signed_transaction_commitment: Some(hex::encode(Sha256::digest(&signed))),
        };
        VoucherFixture {
            owner: owner.readable().into(),
            hub: hub.readable().into(),
            operation,
            response,
        }
    }

    #[test]
    fn voucher_issued_is_a_durable_wallet_state_that_never_moves_on() {
        assert_eq!(
            durable_status_for_hub_status(L1_CHANNEL_CLOSE_VOUCHER_STATUS),
            Some(ChannelCloseStatus::VoucherHeld)
        );
        assert!(can_accept_hub_status(
            ChannelCloseStatus::UserSigned,
            ChannelCloseStatus::VoucherHeld
        ));
        assert!(can_accept_hub_status(
            ChannelCloseStatus::VoucherHeld,
            ChannelCloseStatus::VoucherHeld
        ));
        for next in [
            ChannelCloseStatus::HubSubmitted,
            ChannelCloseStatus::Confirmed,
            ChannelCloseStatus::RecoveryRequired,
        ] {
            assert!(
                !can_accept_hub_status(ChannelCloseStatus::VoucherHeld, next),
                "a held voucher must not move to {next:?}"
            );
            assert!(
                !can_accept_hub_status(next, ChannelCloseStatus::VoucherHeld),
                "{next:?} must not become a voucher"
            );
        }
    }

    #[test]
    fn a_fully_countersigned_delta_zero_voucher_is_accepted() {
        let fixture = voucher_fixture(false, true);
        validate_hub_response(&fixture.operation, &fixture.response).unwrap();
        let verified = verify_channel_close_voucher_bytes(
            fixture.response.signed_transaction_hex.as_deref().unwrap(),
            fixture.response.transaction_hash.as_deref().unwrap(),
            &fixture.owner,
            &fixture.hub,
            CHANNEL_ID,
            CHAIN_ID,
        )
        .unwrap();
        assert_eq!(
            Some(verified.signed_transaction_commitment.as_str()),
            fixture.response.signed_transaction_commitment.as_deref()
        );
    }

    #[test]
    fn every_missing_voucher_property_is_refused() {
        let good = voucher_fixture(false, true);
        let hex_bytes = good.response.signed_transaction_hex.clone().unwrap();

        // Only one signature: the Hub never countersigned.
        let unsigned_by_hub = voucher_fixture(false, false);
        let error = validate_hub_response(&unsigned_by_hub.operation, &unsigned_by_hub.response)
            .unwrap_err()
            .to_string();
        assert!(error.contains("two party signatures"), "{error}");

        // A principal transfer is not delta zero.
        let transfer = voucher_fixture(true, true);
        let error = validate_hub_response(&transfer.operation, &transfer.response)
            .unwrap_err()
            .to_string();
        assert!(error.contains("[ChainAllow, ChannelClose]"), "{error}");

        // Trailing bytes.
        let mut trailing = good.response.clone();
        trailing.signed_transaction_hex = Some(format!("{hex_bytes}00"));
        assert!(validate_hub_response(&good.operation, &trailing).is_err());

        // Bytes that do not hash to the announced transaction.
        let mut wrong_hash = good.response.clone();
        wrong_hash.transaction_hash = Some("cd".repeat(32));
        assert!(validate_hub_response(&good.operation, &wrong_hash).is_err());

        // Missing bytes on a voucher status.
        let mut no_bytes = good.response.clone();
        no_bytes.signed_transaction_hex = None;
        let error = validate_hub_response(&good.operation, &no_bytes)
            .unwrap_err()
            .to_string();
        assert!(error.contains("countersigned bytes"), "{error}");

        // Missing or wrong commitment over those bytes.
        let mut bad_commitment = good.response.clone();
        bad_commitment.signed_transaction_commitment = Some("00".repeat(32));
        let error = validate_hub_response(&good.operation, &bad_commitment)
            .unwrap_err()
            .to_string();
        assert!(error.contains("commitment"), "{error}");

        // A different Hub address in the durable operation.
        let mut other_hub = good.operation.clone();
        other_hub.hub_identity = account(97).readable().into();
        assert!(validate_hub_response(&other_hub, &good.response).is_err());

        // A different chain in the durable request.
        let mut other_chain = good.operation.clone();
        other_chain.request.as_mut().unwrap().chain_id = 0;
        let error = validate_hub_response(&other_chain, &good.response)
            .unwrap_err()
            .to_string();
        assert!(error.contains("bind exactly chain 0"), "{error}");

        // A different channel.
        let error = verify_channel_close_voucher_bytes(
            &hex_bytes,
            good.response.transaction_hash.as_deref().unwrap(),
            &good.owner,
            &good.hub,
            "ffeeddccbbaa99887766554433221100",
            CHAIN_ID,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("different channel"), "{error}");
    }

    #[test]
    fn signed_bytes_on_a_cooperative_close_status_are_refused() {
        let fixture = voucher_fixture(false, true);
        let mut response = fixture.response.clone();
        response.status = "submitted".into();
        let error = validate_hub_response(&fixture.operation, &response)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must never carry them"), "{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    #[test]
    fn legacy_signed_request_is_reported_as_recovery_required() {
        let legacy = br#"{
            "schema_version":1,
            "journal_sequence":1,
            "journal_head":"head",
            "state_commitment":"commitment",
            "operation":{
                "request":{
                    "schema":"hpay-l1-channel-close/1",
                    "network":"mainnet",
                    "chain_id":0
                }
            }
        }"#;
        let error = reject_legacy_channel_close_request(legacy).unwrap_err();
        assert!(error.to_string().contains("RecoveryRequired"));
        assert!(error.to_string().contains("network binding"));
    }

    #[test]
    fn only_retired_is_a_terminal_wallet_close_state() {
        assert_eq!(
            durable_status_for_hub_status("retired"),
            Some(ChannelCloseStatus::Confirmed)
        );
        assert_eq!(
            durable_status_for_hub_status("confirmed_closed"),
            Some(ChannelCloseStatus::HubSubmitted)
        );
        assert_eq!(
            durable_status_for_hub_status("submitted"),
            Some(ChannelCloseStatus::HubSubmitted)
        );
    }

    #[test]
    fn restart_resumes_exact_intent_and_changed_intent_is_rejected() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-close-restart").unwrap();
        let mut safety = ChannelCloseSafety::open(&account, "hub", "channel").unwrap();
        let initial_address = account.address();
        let input = BeginChannelClose {
            operation_id: "4ed50c2c-7c7a-48df-a714-18b50550cf08",
            idempotency_key: "hpay:test:channel-close:one",
            user_address: &initial_address,
            reuse_version: 1,
            open_height: 900_000,
            unsigned_transaction_hex: "020001",
            created_unix: 1_700_000_000,
            expires_unix: 1_700_000_300,
        };
        let first = safety.begin_or_resume(input).unwrap();
        drop(safety);
        let mut reopened = ChannelCloseSafety::open(&account, "hub", "channel").unwrap();
        let address = account.address();
        let resumed = reopened
            .begin_or_resume(BeginChannelClose {
                operation_id: &first.operation_id,
                idempotency_key: &first.idempotency_key,
                user_address: &address,
                reuse_version: 1,
                open_height: 900_000,
                unsigned_transaction_hex: "020001",
                created_unix: 1_700_000_000,
                expires_unix: 1_700_000_300,
            })
            .unwrap();
        assert_eq!(first, resumed);
        assert!(
            reopened
                .begin_or_resume(BeginChannelClose {
                    operation_id: &first.operation_id,
                    idempotency_key: &first.idempotency_key,
                    user_address: &address,
                    reuse_version: 2,
                    open_height: 900_000,
                    unsigned_transaction_hex: "020001",
                    created_unix: 1_700_000_000,
                    expires_unix: 1_700_000_300,
                })
                .is_err()
        );
    }

    #[test]
    fn crash_after_pre_sign_marker_never_allows_signing_again() {
        let _isolated = IsolatedWalletData::new();
        let account = WalletAccount::create("channel-close-sign-marker").unwrap();
        let address = account.address();
        let mut safety = ChannelCloseSafety::open(&account, "hub", "channel").unwrap();
        safety
            .begin_or_resume(BeginChannelClose {
                operation_id: "b73a5507-9607-4a30-9733-5bf2ef65f6a5",
                idempotency_key: "hpay:test:channel-close:marker",
                user_address: &address,
                reuse_version: 1,
                open_height: 900_000,
                unsigned_transaction_hex: "020001",
                created_unix: 1_700_000_000,
                expires_unix: 1_700_000_300,
            })
            .unwrap();
        safety.mark_signature_may_exist().unwrap();
        drop(safety);
        let mut reopened = ChannelCloseSafety::open(&account, "hub", "channel").unwrap();
        assert!(reopened.mark_signature_may_exist().is_ok());
        assert_eq!(
            reopened.operation().unwrap().status,
            ChannelCloseStatus::SignatureMayExist
        );
    }

    #[test]
    fn scoped_personal_and_agent_close_stores_are_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let personal_root = directory.path().join("personal-l2");
        let agent_root = directory.path().join("agent-l2");
        let account = WalletAccount::create("channel-close-scoped-isolation").unwrap();
        let address = account.address();
        let personal_scope = format!("personal:{address}");
        let agent_scope = "agent_wallet:wallet-one";

        let mut personal = ChannelCloseSafety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        let mut agent = ChannelCloseSafety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();

        assert!(
            personal
                .path
                .starts_with(personal_root.join("channel-close"))
        );
        assert!(agent.path.starts_with(agent_root.join("channel-close")));
        assert_ne!(personal.path, agent.path);
        assert!(agent.operation().is_err());
        assert!(
            ChannelCloseSafety::open_scoped(
                &account,
                &personal_root,
                &personal_scope,
                "../same-hub",
                "../same-channel",
            )
            .is_err()
        );

        let personal_operation = personal
            .begin_or_resume(BeginChannelClose {
                operation_id: "10a6bd37-0dd5-4fc0-b706-798717dc6cb0",
                idempotency_key: "hpay:test:channel-close:personal",
                user_address: &address,
                reuse_version: 1,
                open_height: 900_000,
                unsigned_transaction_hex: "020001",
                created_unix: 1_700_000_000,
                expires_unix: 1_700_000_300,
            })
            .unwrap();
        let agent_operation = agent
            .begin_or_resume(BeginChannelClose {
                operation_id: "576a615b-5324-4da8-a860-f5fe774fd0e1",
                idempotency_key: "hpay:test:channel-close:agent",
                user_address: &address,
                reuse_version: 1,
                open_height: 900_000,
                unsigned_transaction_hex: "020001",
                created_unix: 1_700_000_000,
                expires_unix: 1_700_000_300,
            })
            .unwrap();
        agent.mark_signature_may_exist().unwrap();

        assert_eq!(personal.operation().unwrap(), personal_operation);
        assert_eq!(
            agent.operation().unwrap().status,
            ChannelCloseStatus::SignatureMayExist
        );
        assert_ne!(
            personal_operation.operation_id,
            agent_operation.operation_id
        );
        drop(personal);
        drop(agent);

        let personal = ChannelCloseSafety::open_scoped(
            &account,
            &personal_root,
            &personal_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        let agent = ChannelCloseSafety::open_scoped(
            &account,
            &agent_root,
            agent_scope,
            "../same-hub",
            "../same-channel",
        )
        .unwrap();
        assert_eq!(
            personal.operation().unwrap().status,
            ChannelCloseStatus::PersistedBeforeSigning
        );
        assert_eq!(
            agent.operation().unwrap().status,
            ChannelCloseStatus::SignatureMayExist
        );
    }
}
