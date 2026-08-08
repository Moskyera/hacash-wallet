//! Personal-wallet Fast Pay recovery journal.
//!
//! This module is intentionally separate from the vault, transaction history
//! and final dispute-bill store. It persists only the minimum operation state
//! required to prevent duplicate signing and to recover an uncertain L2
//! submission. Its authentication key is derived with HKDF domain separation;
//! the blockchain signing key is never stored in this state.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

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
            Self::Submitted | Self::AwaitingRecipient | Self::RecoveryRequired
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
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub amount_units: u64,
    pub intent_commitment: String,
    pub request_commitment: String,
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
    pub amount_units: u64,
    pub channel_reuse_version: u64,
}

pub struct ClientL2Safety {
    path: PathBuf,
    wallet_scope: String,
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
        let wallet_scope = format!("personal:{}", account.address());
        let directory = safety_directory(&wallet_scope, hub_identity, channel_id);
        fs::create_dir_all(&directory).map_err(l2_io)?;
        let path = directory.join("operations.json");
        let lock = acquire_lock(&directory.join("operations.lock"))?;
        let mut key = derive_key(account, &wallet_scope, hub_identity, channel_id)?;
        let journal = AuthenticatedJournal::open(
            directory.join("operations.journal.jsonl"),
            &key[..],
            JournalBinding {
                wallet_scope: wallet_scope.clone(),
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
            &wallet_scope,
            hub_identity,
            channel_id,
        )?;
        Ok(Self {
            path,
            wallet_scope,
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
        let wallet_scope = self.binding_wallet_scope()?;
        let hub_identity = self.binding_hub_identity()?;
        let channel_id = self.binding_channel_id()?;
        let intent_commitment = intent_commitment(payer, payee, amount, &channel_id, &hub_identity);
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
        let operation_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = format!("hpay:{}", uuid::Uuid::new_v4());
        let request_commitment =
            request_commitment(&operation_id, payer, payee, amount, &channel_id);
        let operation = ClientL2Operation {
            operation_id: operation_id.clone(),
            idempotency_key,
            wallet_scope,
            hub_identity,
            channel_id,
            channel_reuse_version,
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: amount.to_owned(),
            amount_units,
            intent_commitment,
            request_commitment,
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
            payer: payer.to_owned(),
            payee: payee.to_owned(),
            amount: amount.to_owned(),
            amount_units,
            intent_commitment: intent_commitment(
                payer,
                payee,
                amount,
                &self.channel_id,
                &self.hub_identity,
            ),
            request_commitment: request_commitment(
                operation_id,
                payer,
                payee,
                amount,
                &self.channel_id,
            ),
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

    pub fn persist_signature(
        &mut self,
        operation_id: &str,
        signed_bill_hex: &str,
    ) -> WalletResult<ClientL2Operation> {
        let mut operation = self.operation(operation_id)?;
        let documents =
            ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex).map_err(l2_hub_error)?;
        let commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        let local_address = self
            .wallet_scope
            .strip_prefix("personal:")
            .ok_or_else(|| WalletError::L2("invalid Personal Wallet L2 scope".into()))?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(local_address)
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

    pub fn mark_awaiting_recipient(&mut self, operation_id: &str) -> WalletResult<()> {
        self.set_status(
            operation_id,
            ClientOperationStatus::AwaitingRecipient,
            JournalPhase::PaymentAcknowledged,
        )
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

fn safety_directory(wallet_scope: &str, hub_identity: &str, channel_id: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L2/PERSONAL/STORE/V1");
    hash_field(&mut digest, wallet_scope.as_bytes());
    hash_field(&mut digest, hub_identity.as_bytes());
    hash_field(&mut digest, channel_id.as_bytes());
    wallet_data_root()
        .join("l2")
        .join("personal")
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
    channel_id: &str,
    hub_identity: &str,
) -> String {
    digest_fields(
        b"HPAY/L2/PERSONAL/INTENT/V1",
        &[payer, payee, amount, channel_id, hub_identity],
    )
}

fn request_commitment(
    operation_id: &str,
    payer: &str,
    payee: &str,
    amount: &str,
    channel_id: &str,
) -> String {
    digest_fields(
        b"HPAY/L2/FAST-PAY/REQUEST/V1",
        &[operation_id, payer, payee, amount, channel_id, "sender"],
    )
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
        assert!(
            safety
                .persist_signature(&operation.operation_id, &unsigned)
                .unwrap_err()
                .to_string()
                .contains("verified local wallet signature")
        );
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
    fn only_uncertain_states_require_explicit_reconciliation() {
        assert!(!ClientOperationStatus::PaymentIntentCreated.requires_explicit_reconciliation());
        assert!(!ClientOperationStatus::PersistedBeforeSigning.requires_explicit_reconciliation());
        assert!(!ClientOperationStatus::Signed.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::Submitted.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::AwaitingRecipient.requires_explicit_reconciliation());
        assert!(ClientOperationStatus::RecoveryRequired.requires_explicit_reconciliation());
        assert!(!ClientOperationStatus::Committed.requires_explicit_reconciliation());
    }
}
