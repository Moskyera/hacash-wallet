//! Agent Wallet STATE backup and restore, and the warning that is part of it.
//!
//! WHAT THIS IS, AND WHAT IT IS NOT. The Personal Wallet's backup is a KEY
//! backup: one vault file, one private key, and restoring it loses nothing,
//! because a key has no history. An Agent Wallet's private key is worth almost
//! nothing on its own - what makes the wallet safe is the record of what has
//! been spent, which agents are allowed to spend, which agent has been revoked,
//! and which phone is the witness. That record lives in four files that only
//! mean anything together:
//!
//!   * `registry.json`                     - the wallet exists, at this address
//!   * `wallets/<id>/vault.json`           - the keys, encrypted
//!   * `wallets/<id>/journal.json`         - the authenticated history
//!   * `wallets/<id>/wallet_state.enc.json`- the materialized state
//!
//! So this is a STATE backup, and a restore is a ROLLBACK. That is not a defect
//! of this implementation; it is what restoring a spending record means, and
//! `ReplayGuardSnapshot` says so in its own documentation: its storage must be
//! rollback-protected. Everything in [`AGENT_WALLET_BACKUP_WARNING`] was
//! established by execution before any of this was written, and it is enforced
//! rather than printed: neither entry point will run without an
//! [`AgentWalletBackupAcknowledgement`] whose four fields are all true, one per
//! consequence.
//!
//! THE FORMAT IS THE PERSONAL WALLET'S, NOT A NEW ONE. A backup file is the same
//! envelope shape the Personal Wallet exports - authenticated metadata, salt,
//! nonce, ciphertext - sealed with the same primitives the Agent Wallet's own
//! vault uses: Argon2id at the paranoid profile over the owner's passphrase, and
//! AES-256-GCM with the canonical metadata as additional authenticated data.
//! Nothing about the Personal Wallet is read, written or changed by this module.
//!
//! NOTHING SECRET IS EVER IN CLEAR. The payload carries the four documents byte
//! for byte, which means the keys travel as the vault's own ciphertext and the
//! state travels as its own encrypted envelope - and then the whole bundle is
//! encrypted again under the passphrase. No passphrase, no private key, no vault
//! plaintext and no session key is written to the backup, to a log, or into any
//! error in this file. A wrong passphrase is one opaque `Vault` error.
//!
//! A RESTORE REFUSES RATHER THAN HALF-RUNS, AND A HALF-RESTORE IS NOT POSSIBLE.
//! Every one of the four documents is parsed, decrypted, cross-checked against
//! the other three and authenticated - the journal's MAC chain re-verified in
//! memory, the state commitment in its head compared against the state - BEFORE
//! a single byte is written.
//!
//! That check is not enough on its own, and an earlier version of this comment
//! claimed it was. "The registry entry is published last, so a failure leaves an
//! unregistered private directory and never a half-restored wallet" was FALSE as
//! written: an unregistered private directory WITH THE KEYS IN IT is exactly a
//! half-restored wallet, and it was the one state with no exit. Executed: a crash
//! between the vault write and the journal write left `vault=true state=false
//! registered=false`; `list_wallets` never showed the wallet, `unlock_session`
//! answered `AgentWalletNotFound`, and the restore's own pre-check answered
//! `AgentWalletAlreadyExists` for ever - to the retry, and to a retry after a
//! reboot - because it could not tell its own debris from a live wallet.
//!
//! So the five writes are now one transaction, the same way the Personal
//! Wallet's four-file restore has always been (`transactional_apply_at`):
//! `begin_wallet_restore` records which wallet is being built BEFORE anything of
//! it reaches disk, the registry entry at the end is the commit point, and
//! `recover_interrupted_wallet_restore` - which runs at every
//! `AgentWalletManager::open` and again at the top of every restore - finishes
//! the story either way. Everything lands, or nothing does, including when the
//! restore itself is interrupted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use hacash_wallet_core::kdf::KdfParams;

use crate::emergency::AgentEmergencyController;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournal;
use crate::storage::{AgentWalletRegistryEntry, decrypt_foreign_state_envelope};
use crate::types::{AgentWalletId, WalletScope};
use crate::vault::{AgentEncryptedVault, derive_domain_key};

use super::state::{journal_path, state_commitment, validate_state};
use super::{
    AgentWalletManager, AgentWalletState, PENDING_STATE_NAME, RestoreCrashPoint, STATE_NAME,
    STATE_SCHEMA_VERSION,
};

const BACKUP_VERSION: u32 = 1;
const BACKUP_KIND: &str = "hpay_agent_wallet_state_backup";
const BACKUP_AAD_DOMAIN: &[u8] = b"HPAY/agent-wallet/state-backup/v1";
const MAX_BACKUP_BYTES: usize = 12 * 1024 * 1024;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// The four things an owner must be told, in plain language, before they create
/// a backup and again before they restore one.
///
/// Every one of these was established by running the wallet, not by reading it:
/// the spend window really did go from 33,000 back to 11,000; the wallet really
/// did pay again believing it had spent 22,000 when it had spent 44,000; a
/// revoked agent really did come back live with its allowance reset; and the old
/// witness phone really does answer `RollbackDetected` for ever afterwards.
///
/// It is a fixed list rather than free text so that a caller cannot render three
/// of the four. The desktop asserts all four reach the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AgentWalletBackupWarning {
    /// What the owner is about to do.
    pub headline: &'static str,
    /// The four consequences, each of which the owner must tick.
    pub restore_rewinds_spending: &'static str,
    pub revoked_agents_return: &'static str,
    pub old_phone_must_be_replaced: &'static str,
    pub the_file_is_a_working_wallet: &'static str,
}

impl AgentWalletBackupWarning {
    /// The four facts, named. Every fact must appear here, must have a sentence
    /// in both warnings, and must have a field of the same name on
    /// [`AgentWalletBackupAcknowledgement`] that gates it.
    ///
    /// This exists so that "all four are unavoidable" can be asked as a question
    /// about the code rather than asserted in a comment: a test walks these keys,
    /// turns each one off in isolation, and requires both entry points to refuse.
    /// A fifth fact added to the warning and not to the acknowledgement fails
    /// [`Self::fact`]'s round trip, and a fifth field added to the
    /// acknowledgement and not gated fails to compile, because
    /// [`AgentWalletBackupAcknowledgement::is_complete`] destructures the whole
    /// struct.
    pub const FACT_KEYS: [&'static str; 4] = [
        "restore_rewinds_spending",
        "revoked_agents_return",
        "old_phone_must_be_replaced",
        "the_file_is_a_working_wallet",
    ];

    /// The sentence this warning uses for one named fact.
    pub fn fact(&self, key: &str) -> Option<&'static str> {
        match key {
            "restore_rewinds_spending" => Some(self.restore_rewinds_spending),
            "revoked_agents_return" => Some(self.revoked_agents_return),
            "old_phone_must_be_replaced" => Some(self.old_phone_must_be_replaced),
            "the_file_is_a_working_wallet" => Some(self.the_file_is_a_working_wallet),
            _ => None,
        }
    }
}

/// Shown before a backup is created.
pub const AGENT_WALLET_BACKUP_WARNING: AgentWalletBackupWarning = AgentWalletBackupWarning {
    headline: "This backup saves the record of what your agents have already spent. \
               Restoring it later will put that record back to how it is today, and \
               everything below follows from that. Read all four before you continue.",
    restore_rewinds_spending: "Restoring this backup rewinds the record of what has been spent. Spending limits \
         go back to what they were at the moment you made it, and this wallet may pay \
         again for something it has already paid for. That money is really gone twice.",
    revoked_agents_return: "Restoring this backup brings back every agent that was allowed to spend when you \
         made it. An agent you have revoked since then comes back live, with its \
         allowance reset. You have to revoke it again yourself.",
    old_phone_must_be_replaced: "After a restore your current witness phone will refuse to approve anything, for \
         ever, because it can see the wallet has gone backwards. You will have to run a \
         lost-phone witness rotation onto a different handset before this wallet can pay \
         at all.",
    the_file_is_a_working_wallet: "This backup file plus its passphrase IS a working wallet that can spend your \
         money, at the same time as this one. Anyone who has both has your agent wallet. \
         Store it as you would store cash, and never in the same place as the passphrase.",
};

/// Shown again before a backup is restored, in the present tense.
pub const AGENT_WALLET_RESTORE_WARNING: AgentWalletBackupWarning = AgentWalletBackupWarning {
    headline: "You are about to put this wallet's spending record back to how it was when \
               the backup was made. This is not a repair - it is a rewind, and it cannot be \
               undone. Read all four before you continue.",
    restore_rewinds_spending: "This rewinds the record of what has been spent. Spending limits go back to what \
         they were when the backup was made, and this wallet may pay again for something \
         it has already paid for. That money is really gone twice.",
    revoked_agents_return: "Every agent that was allowed to spend when the backup was made comes back live, \
         with its allowance reset - including any agent you have revoked since. You have \
         to revoke it again yourself.",
    old_phone_must_be_replaced: "Your current witness phone will refuse to approve anything after this, for ever, \
         because it can see the wallet has gone backwards. You will have to run a \
         lost-phone witness rotation onto a different handset before this wallet can pay \
         at all.",
    the_file_is_a_working_wallet: "The backup file you are about to restore, plus its passphrase, is itself a \
         working wallet that can spend. Anyone else holding a copy can spend from this \
         wallet too. Delete spare copies once you are done.",
};

/// One tick per consequence in [`AgentWalletBackupWarning`].
///
/// Both entry points refuse unless all four are true. This is deliberately four
/// separate fields and not one `confirmed: bool`, because one boolean is exactly
/// how a warning becomes a footnote: a caller can set it without ever having
/// shown the reader the second, third or fourth fact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletBackupAcknowledgement {
    pub restore_rewinds_spending: bool,
    pub revoked_agents_return: bool,
    pub old_phone_must_be_replaced: bool,
    pub the_file_is_a_working_wallet: bool,
}

impl AgentWalletBackupAcknowledgement {
    pub const fn complete() -> Self {
        Self {
            restore_rewinds_spending: true,
            revoked_agents_return: true,
            old_phone_must_be_replaced: true,
            the_file_is_a_working_wallet: true,
        }
    }

    /// True only when every fact is ticked.
    ///
    /// It destructures the whole struct rather than reading four fields, so a
    /// fifth consequence added here is a COMPILE ERROR until it is gated too.
    /// That is the only way "one more fact was added and quietly not enforced"
    /// stops being possible, and it is the failure this whole shape exists for.
    pub const fn is_complete(self) -> bool {
        let Self {
            restore_rewinds_spending,
            revoked_agents_return,
            old_phone_must_be_replaced,
            the_file_is_a_working_wallet,
        } = self;
        restore_rewinds_spending
            && revoked_agents_return
            && old_phone_must_be_replaced
            && the_file_is_a_working_wallet
    }

    /// Whether one named fact has been ticked, or `None` if there is no such
    /// fact - which is what makes [`AgentWalletBackupWarning::FACT_KEYS`] and
    /// this struct provably the same four things rather than two lists that
    /// happen to be the same length.
    pub fn fact(self, key: &str) -> Option<bool> {
        match key {
            "restore_rewinds_spending" => Some(self.restore_rewinds_spending),
            "revoked_agents_return" => Some(self.revoked_agents_return),
            "old_phone_must_be_replaced" => Some(self.old_phone_must_be_replaced),
            "the_file_is_a_working_wallet" => Some(self.the_file_is_a_working_wallet),
            _ => None,
        }
    }

    /// The same acknowledgement with one named fact set, for a caller - or a
    /// test - that has to be able to withhold exactly one.
    pub fn with_fact(mut self, key: &str, value: bool) -> Option<Self> {
        match key {
            "restore_rewinds_spending" => self.restore_rewinds_spending = value,
            "revoked_agents_return" => self.revoked_agents_return = value,
            "old_phone_must_be_replaced" => self.old_phone_must_be_replaced = value,
            "the_file_is_a_working_wallet" => self.the_file_is_a_working_wallet = value,
            _ => return None,
        }
        Some(self)
    }

    /// Which facts have not been ticked, by name.
    pub fn missing_facts(self) -> Vec<&'static str> {
        AgentWalletBackupWarning::FACT_KEYS
            .into_iter()
            .filter(|key| self.fact(key) != Some(true))
            .collect()
    }

    /// The gate itself. Asked from the two entry points and nowhere else.
    ///
    /// It refuses on the NAMED facts rather than on `is_complete` alone, so the
    /// list the owner is shown and the list that is enforced are one list. A
    /// fact present in the warning and absent from this struct makes
    /// `self.fact(key)` return `None`, `missing_facts` report it, and every
    /// backup and every restore refuse until it is wired up - which is what
    /// "load-bearing" has to mean if it is to mean anything.
    fn require(self) -> AgentWalletResult<()> {
        if self.missing_facts().is_empty() && self.is_complete() {
            Ok(())
        } else {
            Err(AgentWalletError::BackupWarningNotAcknowledged)
        }
    }
}

/// Authenticated, non-secret metadata. Also the AEAD's additional authenticated
/// data, so none of it can be edited without the whole file failing to open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletBackupMetadata {
    pub backup_version: u32,
    pub kind: String,
    /// The schema of the state document sealed inside. A build whose state
    /// schema has moved on cannot restore this file, and says so by name rather
    /// than failing somewhere further in as an unexplained decryption error.
    pub state_schema_version: u32,
    pub wallet_id: String,
    pub address: String,
    pub network_mode: String,
    pub store_uuid: String,
    pub primary_signing_device_id: String,
    pub signer_epoch: u64,
    /// The journal position this backup froze. A restore rewinds to exactly
    /// this, and the owner is shown it before they press.
    pub journal_sequence: u64,
    pub journal_head_hash: String,
    pub wallet_created_at_unix: u64,
    pub backed_up_at_unix: u64,
    pub kdf: String,
    /// SHA-256 over the four documents, so a bundle cannot be reassembled from
    /// pieces of two different backups even by whoever holds the passphrase.
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWalletBackupFile {
    pub metadata: AgentWalletBackupMetadata,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// The four files, byte for byte. Encrypted inside the backup, never on its own.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct AgentWalletBackupBundle {
    registry_entry_json: String,
    vault_json: String,
    journal_json: String,
    state_envelope_json: String,
}

/// What an owner can see about a backup file WITHOUT its passphrase, so they can
/// tell which wallet and which moment it is before they decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentWalletBackupPreview {
    pub wallet_id: String,
    pub address: String,
    pub network_mode: String,
    pub journal_sequence: u64,
    pub backed_up_at_unix: u64,
    pub wallet_created_at_unix: u64,
    /// True when a wallet with this id is already present in this store, which
    /// is refused: a restore never overwrites a live wallet.
    pub already_present: bool,
    pub warning: AgentWalletBackupWarning,
}

/// What actually happened, and what the owner has to do next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentWalletRestoreOutcome {
    pub wallet_id: AgentWalletId,
    pub address: String,
    pub network_mode: String,
    /// The journal position the wallet is now at - the backup's, not the one it
    /// may have been at before.
    pub journal_sequence: u64,
    /// True when the restored state names a witness phone. That handset will
    /// answer `RollbackDetected` from here on, so a lost-phone rotation onto a
    /// different handset is required before this wallet can pay.
    pub witness_phone_must_be_replaced: bool,
    /// True when the restored state re-admits agents that may spend. The owner
    /// is told how many, because "a revoked agent can come back" is only useful
    /// if they know to go and look.
    pub restored_active_agents: usize,
}

impl AgentWalletManager {
    /// Everything the owner can be shown about a backup file before they type a
    /// passphrase, including the warning they must read.
    pub fn preview_agent_wallet_backup(
        &self,
        backup_json: &str,
    ) -> AgentWalletResult<AgentWalletBackupPreview> {
        let file = parse_backup_file(backup_json)?;
        let wallet_id = AgentWalletId::parse(file.metadata.wallet_id.clone())?;
        let already_present = self.storage.load_registry()?.wallet(&wallet_id).is_some();
        Ok(AgentWalletBackupPreview {
            wallet_id: file.metadata.wallet_id,
            address: file.metadata.address,
            network_mode: file.metadata.network_mode,
            journal_sequence: file.metadata.journal_sequence,
            backed_up_at_unix: file.metadata.backed_up_at_unix,
            wallet_created_at_unix: file.metadata.wallet_created_at_unix,
            already_present,
            warning: AGENT_WALLET_RESTORE_WARNING,
        })
    }

    /// Seals this wallet's four files into one encrypted backup document.
    ///
    /// It needs the owner's passphrase, and it uses it: the vault is really
    /// unlocked, the state is really decrypted, and the journal is really
    /// authenticated against that state, so a backup is mutually consistent by
    /// construction rather than by hope. A wallet whose four files disagree
    /// right now cannot be backed up at all - that is a wallet to recover, not
    /// to photograph.
    ///
    /// It writes no file and returns the document to the caller, so nothing here
    /// decides where a working copy of the owner's wallet is stored.
    pub fn create_agent_wallet_backup(
        &self,
        wallet_id: &AgentWalletId,
        passphrase: &str,
        acknowledgement: AgentWalletBackupAcknowledgement,
        now: u64,
    ) -> AgentWalletResult<String> {
        acknowledgement.require()?;
        let registry = self.storage.load_registry()?;
        let entry = registry
            .wallet(wallet_id)
            .ok_or(AgentWalletError::AgentWalletNotFound)?
            .clone();
        let paths = self.storage.paths(wallet_id)?;
        let vault = AgentEncryptedVault::load(&paths.vault_path())?;
        if vault.wallet_id() != wallet_id || vault.address() != entry.address {
            return Err(AgentWalletError::BackupInconsistent);
        }
        // The passphrase is verified by really opening the vault, and the
        // secrets are dropped as soon as the four files have been checked
        // against each other. None of them reaches the backup.
        let secrets = vault.unlock(passphrase)?;
        let state_master = Zeroizing::new(*secrets.state_master());
        let journal_key = Zeroizing::new(derive_domain_key(
            &state_master,
            wallet_id,
            vault.store_uuid(),
            b"journal-authentication/v1",
        )?);
        drop(secrets);

        let state: AgentWalletState = self.storage.read_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
        )?;
        let journal_bytes = read_document(&journal_path(&paths))?;
        let state_envelope_bytes = read_document(&paths.encrypted_state_path(STATE_NAME)?)?;
        let bundle = AgentWalletBackupBundle {
            registry_entry_json: serde_json::to_string(&entry)
                .map_err(|_| AgentWalletError::PersistenceFailed)?,
            vault_json: String::from_utf8(vault.to_bytes()?)
                .map_err(|_| AgentWalletError::Vault)?,
            journal_json: String::from_utf8(journal_bytes)
                .map_err(|_| AgentWalletError::PersistenceFailed)?,
            state_envelope_json: String::from_utf8(state_envelope_bytes)
                .map_err(|_| AgentWalletError::PersistenceFailed)?,
        };
        // The consistency a restore will demand is proved here first, against
        // the live files, so a backup is never a snapshot of a broken wallet.
        let checked = check_bundle_consistency(&bundle, &state_master, &journal_key)?;
        if checked.state_commitment != state_commitment(&state)? {
            return Err(AgentWalletError::BackupInconsistent);
        }

        let metadata = AgentWalletBackupMetadata {
            backup_version: BACKUP_VERSION,
            kind: BACKUP_KIND.to_owned(),
            state_schema_version: STATE_SCHEMA_VERSION,
            wallet_id: wallet_id.to_string(),
            address: vault.address().to_owned(),
            network_mode: vault.network_mode().to_owned(),
            store_uuid: vault.store_uuid().to_owned(),
            primary_signing_device_id: vault.primary_signing_device_id().to_owned(),
            signer_epoch: vault.signer_epoch(),
            journal_sequence: state.journal_sequence,
            journal_head_hash: state.journal_head_hash.clone(),
            wallet_created_at_unix: vault.created_at(),
            backed_up_at_unix: now,
            kdf: KdfParams::paranoid().label(),
            bundle_sha256: bundle_commitment(&bundle)?,
        };
        seal(&metadata, &bundle, passphrase)
    }

    /// Restores a wallet from a backup document, in full, and refuses outright
    /// if the four documents inside it do not agree.
    ///
    /// It will not overwrite a wallet that is already here. Removing a live
    /// Agent Wallet is the owner's own explicit act, not a side effect of a
    /// restore, because that act destroys the only record of what has been
    /// spent.
    ///
    /// The restored wallet is left LOCKED. The owner unlocks it themselves,
    /// which is also what runs the ordinary interrupted-transition recoveries
    /// against it.
    pub fn restore_agent_wallet_backup(
        &mut self,
        backup_json: &str,
        passphrase: &str,
        acknowledgement: AgentWalletBackupAcknowledgement,
        now: u64,
    ) -> AgentWalletResult<AgentWalletRestoreOutcome> {
        acknowledgement.require()?;
        // A restore that was interrupted has to finish its story before this one
        // may start, because the pre-checks below read the disk and cannot tell
        // an interrupted restore's debris from a live wallet. This is the same
        // order the Personal Wallet uses: `transactional_apply_at` calls
        // `recover_at_root` before it touches anything.
        self.storage.recover_interrupted_wallet_restore()?;
        let file = parse_backup_file(backup_json)?;
        let wallet_id = AgentWalletId::parse(file.metadata.wallet_id.clone())?;
        let registry_before = self.storage.load_registry()?;
        if registry_before.wallet(&wallet_id).is_some() {
            return Err(AgentWalletError::AgentWalletAlreadyExists);
        }
        let paths = self.storage.paths(&wallet_id)?;
        if paths.vault_path().exists() || paths.encrypted_state_path(STATE_NAME)?.exists() {
            return Err(AgentWalletError::AgentWalletAlreadyExists);
        }

        // 1. OPEN THE ENVELOPE. A wrong passphrase and a tampered metadata field
        //    are the same opaque failure, and neither says anything about the
        //    passphrase.
        let bundle = open(&file, passphrase)?;
        if bundle_commitment(&bundle)? != file.metadata.bundle_sha256 {
            return Err(AgentWalletError::BackupInconsistent);
        }

        // 2. THE VAULT, AND THE PASSPHRASE AGAINST IT.
        let vault = AgentEncryptedVault::from_bytes(bundle.vault_json.as_bytes())?;
        if vault.wallet_id() != &wallet_id
            || vault.address() != file.metadata.address
            || vault.network_mode() != file.metadata.network_mode
            || vault.store_uuid() != file.metadata.store_uuid
            || vault.primary_signing_device_id() != file.metadata.primary_signing_device_id
            || vault.signer_epoch() != file.metadata.signer_epoch
        {
            return Err(AgentWalletError::BackupInconsistent);
        }
        let secrets = vault.unlock(passphrase)?;
        let state_master = Zeroizing::new(*secrets.state_master());
        let journal_key = Zeroizing::new(derive_domain_key(
            &state_master,
            &wallet_id,
            vault.store_uuid(),
            b"journal-authentication/v1",
        )?);
        drop(secrets);

        // 3. THE OTHER THREE, AGAINST THE VAULT AND AGAINST EACH OTHER. Nothing
        //    is written until this returns.
        let checked = check_bundle_consistency(&bundle, &state_master, &journal_key)?;
        if checked.state.journal_sequence != file.metadata.journal_sequence
            || checked.state.journal_head_hash != file.metadata.journal_head_hash
            || checked.state.address != *vault.address()
            || checked.state.network_mode != *vault.network_mode()
            || checked.state.primary_signing_device_id != *vault.primary_signing_device_id()
            || checked.state.signer_epoch != vault.signer_epoch()
            || checked.registry_entry.wallet_id != wallet_id
            || checked.registry_entry.address != *vault.address()
        {
            return Err(AgentWalletError::BackupInconsistent);
        }
        let witness_phone_must_be_replaced = checked.state.rollback_witness.is_some();
        let restored_active_agents = checked
            .state
            .agents
            .values()
            .filter(|agent| agent.status == crate::policy::AgentStatus::Active)
            .count();
        let journal_sequence = checked.state.journal_sequence;
        let address = vault.address().to_owned();
        let network_mode = vault.network_mode().to_owned();

        // 4. WRITE, AS ONE TRANSACTION. The write-ahead record goes down first
        //    and names the wallet about to be built, so from here to the registry
        //    entry there is no disk state a recovery cannot finish. Each window
        //    below is a durable write followed by another step, and each one is
        //    crashed at by `every_window_in_the_restore_lands_all_four_or_none`.
        self.storage.begin_wallet_restore(&wallet_id)?;
        self.restore_crash(RestoreCrashPoint::AfterWriteAheadRecord)?;
        let paths = self.storage.ensure_wallet_layout(&wallet_id)?;
        self.restore_crash(RestoreCrashPoint::AfterWalletLayout)?;
        let emergency = AgentEmergencyController::new(&paths, &wallet_id)?;
        vault.save(&paths.vault_path())?;
        self.restore_crash(RestoreCrashPoint::AfterVault)?;
        hacash_wallet_core::paths::secure_write(
            &journal_path(&paths),
            bundle.journal_json.as_bytes(),
        )
        .map_err(|_| AgentWalletError::PersistenceFailed)?;
        self.restore_crash(RestoreCrashPoint::AfterJournal)?;
        // The state is re-encrypted for THIS store rather than copied, because
        // an encrypted state envelope is bound to the store it lives in. The
        // plaintext is byte-identical, so the state commitment the journal head
        // carries is unchanged - which is what the verification below re-checks.
        self.storage.write_encrypted(
            &wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            &checked.state,
        )?;
        self.restore_crash(RestoreCrashPoint::AfterState)?;
        // A stale pending slot from some earlier life of this directory would be
        // read as an interrupted transition. There must not be one.
        let pending_path = paths.encrypted_state_path(PENDING_STATE_NAME)?;
        if pending_path.exists() {
            std::fs::remove_file(&pending_path).map_err(|_| AgentWalletError::PersistenceFailed)?;
        }
        self.restore_crash(RestoreCrashPoint::AfterPendingRemoval)?;

        // 5. RE-READ EVERYTHING THROUGH THE ORDINARY PATH. This is what proves
        //    the restore worked, and it is the same code every unlock runs.
        let reloaded: AgentWalletState = self.storage.read_encrypted(
            &wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
        )?;
        validate_state(&reloaded, &wallet_id)?;
        let reloaded_commitment = state_commitment(&reloaded)?;
        let journal = AgentJournal::open(
            journal_path(&paths),
            WalletScope::for_agent_wallet(&wallet_id),
            &journal_key,
        )?;
        let recovery = journal.verify()?;
        if reloaded_commitment != checked.state_commitment
            || recovery.head.sequence != journal_sequence
            || hex::encode(recovery.head.record_hash.as_bytes()) != reloaded.journal_head_hash
            || recovery.head.state_commitment != Some(reloaded_commitment)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.restore_crash(RestoreCrashPoint::AfterVerification)?;

        // 6. AND ONLY NOW IS THE WALLET DISCOVERABLE. This single write is the
        //    commit point of the whole transaction: before it, a recovery removes
        //    everything above; after it, a recovery keeps everything above.
        let mut registry = self.storage.load_registry()?;
        registry.insert(checked.registry_entry.clone())?;
        self.storage.save_registry(&registry)?;
        self.restore_crash(RestoreCrashPoint::AfterRegistry)?;
        // 7. THE RECORD HAS DONE ITS WORK. Failing to retire it is not a failure
        //    of the restore - the wallet exists, and the next open sees a
        //    committed wallet and retires it there.
        let _ = self.storage.finish_wallet_restore();
        self.emergency_controllers
            .insert(wallet_id.as_str().to_owned(), emergency);
        let _ = now;
        Ok(AgentWalletRestoreOutcome {
            wallet_id,
            address,
            network_mode,
            journal_sequence,
            witness_phone_must_be_replaced,
            restored_active_agents,
        })
    }
}

/// Which of the four documents a test is replacing.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum BackupDocument {
    RegistryEntry,
    Vault,
    Journal,
    StateEnvelope,
}

/// Rebuilds a backup file with one document replaced, `bundle_sha256` recomputed
/// and the envelope re-sealed under the same passphrase.
///
/// This exists so the consistency refusal can be EXECUTED rather than argued
/// about. A bundle whose commitment and AEAD both verify, and whose four
/// documents nonetheless disagree, is exactly the case that must be refused
/// rather than half-restored, and it is not reachable by flipping a byte: the
/// commitment and the AEAD would catch that first. Test builds only.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
pub(crate) fn replace_backup_document_for_test(
    backup_json: &str,
    passphrase: &str,
    document: BackupDocument,
    replacement: String,
) -> AgentWalletResult<String> {
    let file = parse_backup_file(backup_json)?;
    let mut bundle = open(&file, passphrase)?;
    match document {
        BackupDocument::RegistryEntry => bundle.registry_entry_json = replacement,
        BackupDocument::Vault => bundle.vault_json = replacement,
        BackupDocument::Journal => bundle.journal_json = replacement,
        BackupDocument::StateEnvelope => bundle.state_envelope_json = replacement,
    }
    let mut metadata = file.metadata.clone();
    metadata.bundle_sha256 = bundle_commitment(&bundle)?;
    seal(&metadata, &bundle, passphrase)
}

/// Rebuilds a backup file with its authenticated metadata edited and the
/// envelope re-sealed under the same passphrase.
///
/// This is the realistic adversary for the metadata, and the only one there is:
/// the metadata is the AEAD's additional authenticated data, so nobody WITHOUT
/// the passphrase can change a field of it and still have the file open at all -
/// that case is already executed as the tampered-metadata assertion. Whoever
/// holds the file and the passphrase, on the other hand, can re-seal anything
/// they like, and a restore still has to refuse a file whose declared version or
/// declared wallet does not match what is actually inside it. Test builds only.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
pub(crate) fn reseal_backup_metadata_for_test(
    backup_json: &str,
    passphrase: &str,
    mutate: impl FnOnce(&mut AgentWalletBackupMetadata),
) -> AgentWalletResult<String> {
    let file = parse_backup_file(backup_json)?;
    let bundle = open(&file, passphrase)?;
    let mut metadata = file.metadata.clone();
    mutate(&mut metadata);
    seal(&metadata, &bundle, passphrase)
}

/// The four documents of a backup, for a test that needs to splice them.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
pub(crate) fn backup_documents_for_test(
    backup_json: &str,
    passphrase: &str,
) -> AgentWalletResult<[String; 4]> {
    let file = parse_backup_file(backup_json)?;
    let bundle = open(&file, passphrase)?;
    Ok([
        bundle.registry_entry_json.clone(),
        bundle.vault_json.clone(),
        bundle.journal_json.clone(),
        bundle.state_envelope_json.clone(),
    ])
}

/// The four documents, parsed and proved to agree.
struct CheckedBundle {
    registry_entry: AgentWalletRegistryEntry,
    state: AgentWalletState,
    state_commitment: crate::journal::JournalCommitment,
}

/// The one definition of "these four files agree", asked by backup against the
/// live wallet and by restore against the document, so the two cannot drift.
///
/// It authenticates rather than inspects: the state envelope must decrypt under
/// the wallet's own `state_master`, the journal's every record must re-hash and
/// re-MAC under the wallet's own journal key with an unbroken sequence and
/// previous-hash chain, and the journal head's state commitment must be the
/// commitment of the state document. A backup assembled from two different
/// wallets, or two different moments of one wallet, fails here.
fn check_bundle_consistency(
    bundle: &AgentWalletBackupBundle,
    state_master: &[u8; 32],
    journal_key: &[u8; 32],
) -> AgentWalletResult<CheckedBundle> {
    let registry_entry: AgentWalletRegistryEntry =
        serde_json::from_str(&bundle.registry_entry_json)
            .map_err(|_| AgentWalletError::BackupInconsistent)?;
    let wallet_id = registry_entry.wallet_id.clone();
    let mut plaintext = Zeroizing::new(decrypt_foreign_state_envelope(
        bundle.state_envelope_json.as_bytes(),
        &wallet_id,
        STATE_NAME,
        STATE_SCHEMA_VERSION,
        state_master,
    )?);
    let state: AgentWalletState = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| AgentWalletError::BackupInconsistent)?;
    plaintext.zeroize();
    validate_state(&state, &wallet_id)?;
    if state.address != registry_entry.address {
        return Err(AgentWalletError::BackupInconsistent);
    }

    let journal =
        AgentJournal::open_detached(WalletScope::for_agent_wallet(&wallet_id), journal_key)?;
    let recovery = journal.verify_bytes(bundle.journal_json.as_bytes())?;
    let commitment = state_commitment(&state)?;
    if recovery.head.sequence != state.journal_sequence
        || hex::encode(recovery.head.record_hash.as_bytes()) != state.journal_head_hash
        || recovery.head.state_commitment != Some(commitment)
    {
        return Err(AgentWalletError::BackupInconsistent);
    }
    Ok(CheckedBundle {
        registry_entry,
        state,
        state_commitment: commitment,
    })
}

fn bundle_commitment(bundle: &AgentWalletBackupBundle) -> AgentWalletResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_AAD_DOMAIN);
    for field in [
        bundle.registry_entry_json.as_bytes(),
        bundle.vault_json.as_bytes(),
        bundle.journal_json.as_bytes(),
        bundle.state_envelope_json.as_bytes(),
    ] {
        let length = u32::try_from(field.len()).map_err(|_| AgentWalletError::IntegerOverflow)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn metadata_aad(metadata: &AgentWalletBackupMetadata) -> AgentWalletResult<Vec<u8>> {
    let mut aad = Vec::with_capacity(512);
    aad.extend_from_slice(BACKUP_AAD_DOMAIN);
    aad.extend_from_slice(&metadata.backup_version.to_be_bytes());
    for field in [
        metadata.kind.as_bytes(),
        metadata.wallet_id.as_bytes(),
        metadata.address.as_bytes(),
        metadata.network_mode.as_bytes(),
        metadata.store_uuid.as_bytes(),
        metadata.primary_signing_device_id.as_bytes(),
        metadata.journal_head_hash.as_bytes(),
        metadata.kdf.as_bytes(),
        metadata.bundle_sha256.as_bytes(),
    ] {
        let length = u32::try_from(field.len()).map_err(|_| AgentWalletError::IntegerOverflow)?;
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad.extend_from_slice(&metadata.state_schema_version.to_be_bytes());
    aad.extend_from_slice(&metadata.signer_epoch.to_be_bytes());
    aad.extend_from_slice(&metadata.journal_sequence.to_be_bytes());
    aad.extend_from_slice(&metadata.wallet_created_at_unix.to_be_bytes());
    aad.extend_from_slice(&metadata.backed_up_at_unix.to_be_bytes());
    Ok(aad)
}

fn seal(
    metadata: &AgentWalletBackupMetadata,
    bundle: &AgentWalletBackupBundle,
    passphrase: &str,
) -> AgentWalletResult<String> {
    use rand::RngCore;

    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let plaintext = Zeroizing::new(
        serde_json::to_vec(bundle).map_err(|_| AgentWalletError::PersistenceFailed)?,
    );
    let ciphertext = crate::vault::seal_backup_payload(
        passphrase,
        &salt,
        &nonce,
        &metadata_aad(metadata)?,
        plaintext.as_slice(),
    )?;
    let file = AgentWalletBackupFile {
        metadata: metadata.clone(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    };
    let json =
        serde_json::to_string_pretty(&file).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if json.len() > MAX_BACKUP_BYTES {
        return Err(AgentWalletError::PersistenceFailed);
    }
    Ok(json)
}

fn open(
    file: &AgentWalletBackupFile,
    passphrase: &str,
) -> AgentWalletResult<AgentWalletBackupBundle> {
    let salt: [u8; SALT_LEN] = decode_fixed(&file.salt_hex)?;
    let nonce: [u8; NONCE_LEN] = decode_fixed(&file.nonce_hex)?;
    let ciphertext = hex::decode(&file.ciphertext_hex).map_err(|_| AgentWalletError::Vault)?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_BACKUP_BYTES {
        return Err(AgentWalletError::Vault);
    }
    let plaintext = Zeroizing::new(crate::vault::open_backup_payload(
        passphrase,
        &salt,
        &nonce,
        &metadata_aad(&file.metadata)?,
        &ciphertext,
    )?);
    serde_json::from_slice(plaintext.as_slice()).map_err(|_| AgentWalletError::Vault)
}

fn parse_backup_file(backup_json: &str) -> AgentWalletResult<AgentWalletBackupFile> {
    let trimmed = backup_json.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_BACKUP_BYTES {
        return Err(AgentWalletError::Vault);
    }
    let file: AgentWalletBackupFile =
        serde_json::from_str(trimmed).map_err(|_| AgentWalletError::Vault)?;
    // WHICH VERSION WROTE THIS, ASKED FIRST AND ANSWERED BY NAME. These three
    // fields are the file's own non-secret declaration of its format, so an
    // owner holding a backup from a different build is told that, instead of
    // being handed the same opaque error a wrong passphrase produces and left
    // retyping a passphrase that was never wrong. Everything below this point
    // stays deliberately indistinguishable from a wrong passphrase.
    if file.metadata.backup_version != BACKUP_VERSION
        || file.metadata.kind != BACKUP_KIND
        || file.metadata.state_schema_version != STATE_SCHEMA_VERSION
    {
        return Err(AgentWalletError::BackupUnsupportedVersion);
    }
    if file.metadata.journal_head_hash.len() != 64
        || !file
            .metadata
            .journal_head_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || file.metadata.bundle_sha256.len() != 64
        || !file
            .metadata
            .bundle_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || file.metadata.signer_epoch == 0
        || file.metadata.address.is_empty()
        || !matches!(file.metadata.network_mode.as_str(), "mainnet" | "testnet")
    {
        return Err(AgentWalletError::Vault);
    }
    AgentWalletId::parse(file.metadata.wallet_id.clone())?;
    KdfParams::from_metadata_kdf(&file.metadata.kdf).map_err(|_| AgentWalletError::Vault)?;
    Ok(file)
}

fn decode_fixed<const N: usize>(encoded: &str) -> AgentWalletResult<[u8; N]> {
    if encoded.len() != N * 2 {
        return Err(AgentWalletError::Vault);
    }
    let decoded = hex::decode(encoded).map_err(|_| AgentWalletError::Vault)?;
    decoded.try_into().map_err(|_| AgentWalletError::Vault)
}

fn read_document(path: &std::path::Path) -> AgentWalletResult<Vec<u8>> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() as usize > MAX_BACKUP_BYTES
    {
        return Err(AgentWalletError::PersistenceFailed);
    }
    std::fs::read(path).map_err(|_| AgentWalletError::PersistenceFailed)
}
