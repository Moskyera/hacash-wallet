use std::collections::BTreeSet;
use std::path::PathBuf;

use hacash_wallet_core::settings::validate_node_url;

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::{AgentJournal, AgentJournalEvent, AgentJournalEventKind, JournalCommitment};
use crate::node_binding::validate_stored_anchor;
use crate::operation::OperationStatus;
use crate::pairing_outbox::MAX_PAIRING_COMPLETION_OUTBOX_ENTRIES;
use crate::storage::AgentWalletPaths;
use crate::types::{AgentId, AgentWalletId, WalletScope};

use super::{
    AgentWalletManager, AgentWalletState, JOURNAL_FILE, MAX_OPERATIONS_PER_WALLET,
    PENDING_STATE_NAME, STATE_NAME, STATE_SCHEMA_VERSION, UnlockedAgentWallet, ZERO_HASH_HEX,
    connector,
};

impl AgentWalletManager {
    pub(super) fn sweep_expired_pre_signing_operations(
        &self,
        state: &mut AgentWalletState,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        now: u64,
    ) -> AgentWalletResult<usize> {
        let mut expired = 0;
        for operation in state.operations.values_mut() {
            if operation.expires_at() <= now && operation.cancel_pre_signing("expired")? {
                expired += 1;
            }
        }
        if expired == 0 {
            return Ok(0);
        }
        state.updated_at = now;
        self.persist_event(
            state,
            state_master,
            journal_key,
            AgentJournalEventKind::OperationsExpired,
            None,
            None,
            now,
        )?;
        Ok(expired)
    }

    pub(super) fn compact_aged_terminal_pre_signing_operations(
        &self,
        state: &mut AgentWalletState,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        now: u64,
    ) -> AgentWalletResult<usize> {
        let compacted = prune_aged_terminal_pre_signing_operations(state, now);
        if compacted == 0 {
            return Ok(0);
        }
        state.updated_at = now;
        self.persist_event(
            state,
            state_master,
            journal_key,
            AgentJournalEventKind::OperationsCompacted,
            None,
            None,
            now,
        )?;
        Ok(compacted)
    }
    pub(super) fn expire_session(&mut self, wallet_id: &AgentWalletId, now: u64) {
        if self
            .unlocked
            .get(wallet_id.as_str())
            .is_some_and(|session| now >= session.unlock_expires_at)
        {
            self.unlocked.remove(wallet_id.as_str());
        }
    }

    pub(super) fn ensure_session_active(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.expire_session(wallet_id, now);
        if self.unlocked.contains_key(wallet_id.as_str()) {
            Ok(())
        } else {
            Err(AgentWalletError::AgentWalletLocked)
        }
    }

    pub(super) fn session(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<&UnlockedAgentWallet> {
        self.unlocked
            .get(wallet_id.as_str())
            .ok_or(AgentWalletError::AgentWalletLocked)
    }

    pub(super) fn load_verified_state(
        &self,
        wallet_id: &AgentWalletId,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
    ) -> AgentWalletResult<AgentWalletState> {
        let current: AgentWalletState = self.storage.read_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
        )?;
        validate_state(&current, wallet_id)?;
        let journal = AgentJournal::open(
            journal_path(&self.storage.paths(wallet_id)?),
            WalletScope::for_agent_wallet(wallet_id),
            journal_key,
        )?;
        let recovery = journal.verify()?;
        let actual_head = hex::encode(recovery.head.record_hash.as_bytes());
        let current_commitment = state_commitment(&current)?;
        if current.journal_sequence == recovery.head.sequence
            && current.journal_head_hash == actual_head
            && recovery.head.state_commitment == Some(current_commitment)
        {
            return Ok(current);
        }

        // Recover exactly one interrupted transition:
        // pending state was durable, journal append succeeded, current state
        // replacement did not. Anything else remains fail-closed.
        let latest = recovery
            .records
            .last()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let expected_sequence = current
            .journal_sequence
            .checked_add(1)
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let pending: AgentWalletState = self
            .storage
            .read_encrypted_if_exists(
                wallet_id,
                PENDING_STATE_NAME,
                STATE_SCHEMA_VERSION,
                state_master,
            )?
            .ok_or(AgentWalletError::RecoveryRequired)?;
        validate_state(&pending, wallet_id)?;
        let pending_commitment = state_commitment(&pending)?;
        if latest.sequence() != expected_sequence
            || latest.previous_record_hash().as_bytes() != &hex_to_hash(&current.journal_head_hash)?
            || latest.previous_state_commitment() != current_commitment
            || latest.state_commitment() != pending_commitment
            || recovery.head.state_commitment != Some(pending_commitment)
            || pending.journal_sequence != current.journal_sequence
            || pending.journal_head_hash != current.journal_head_hash
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let mut recovered = pending;
        recovered.journal_sequence = recovery.head.sequence;
        recovered.journal_head_hash = actual_head;
        self.storage.write_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
            &recovered,
        )?;
        let verified: AgentWalletState = self.storage.read_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
        )?;
        if state_commitment(&verified)? != pending_commitment
            || verified.journal_sequence != recovery.head.sequence
            || verified.journal_head_hash != hex::encode(recovery.head.record_hash.as_bytes())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(verified)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn persist_event(
        &self,
        state: &mut AgentWalletState,
        state_master: &[u8; 32],
        journal_key: &[u8; 32],
        kind: AgentJournalEventKind,
        operation_id: Option<&[u8]>,
        actor_id: Option<&[u8]>,
        now: u64,
    ) -> AgentWalletResult<()> {
        validate_state(state, &state.wallet_id)?;
        let paths = self.storage.ensure_wallet_layout(&state.wallet_id)?;
        let mut journal = AgentJournal::open(
            journal_path(&paths),
            WalletScope::for_agent_wallet(&state.wallet_id),
            journal_key,
        )?;
        let recovery = journal.verify()?;
        if recovery.head.sequence != state.journal_sequence
            || hex::encode(recovery.head.record_hash.as_bytes()) != state.journal_head_hash
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let previous_state = recovery
            .head
            .state_commitment
            .unwrap_or_else(|| JournalCommitment::from_bytes([0_u8; 32]));
        let new_state = state_commitment(state)?;
        let event = AgentJournalEvent {
            kind,
            operation_commitment: operation_id
                .map(|value| JournalCommitment::commit(b"operation-id", value)),
            actor_commitment: actor_id.map(|value| JournalCommitment::commit(b"actor-id", value)),
            metadata_commitment: None,
            previous_state_commitment: previous_state,
            new_state_commitment: new_state,
            occurred_at_unix_ms: now.saturating_mul(1000),
        };
        // Durable intent slot is written first. It remains bound to the
        // old journal head until the journal append commits the transition.
        self.storage.write_encrypted(
            &state.wallet_id,
            PENDING_STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
            state,
        )?;
        let record = journal.append(event)?;
        state.journal_sequence = record.sequence();
        state.journal_head_hash = hex::encode(record.record_hash().as_bytes());
        self.storage.write_encrypted(
            &state.wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
            state,
        )?;
        let persisted: AgentWalletState = self.storage.read_encrypted(
            &state.wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            state_master,
        )?;
        if state_commitment(&persisted)? != new_state
            || persisted.journal_sequence != record.sequence()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }
}

fn validate_state(
    state: &AgentWalletState,
    expected_wallet_id: &AgentWalletId,
) -> AgentWalletResult<()> {
    if state.schema_version != STATE_SCHEMA_VERSION
        || &state.wallet_id != expected_wallet_id
        || state.address.is_empty()
        || !matches!(state.network_mode.as_str(), "mainnet" | "testnet")
        || state.signer_epoch == 0
        || state.policy_epoch == 0
        || state.emergency_epoch == 0
        || state.journal_head_hash.len() != 64
        || !state
            .journal_head_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AgentWalletError::RecoveryRequired);
    }
    validate_node_url(&state.node_url).map_err(|_| AgentWalletError::RecoveryRequired)?;
    validate_stored_anchor(&state.network_mode, &state.block_one_fingerprint)?;
    for (key, operation) in &state.operations {
        if key != operation.operation_id().as_str()
            || operation.agent_wallet_id() != expected_wallet_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
    }
    if state.operations.len() > MAX_OPERATIONS_PER_WALLET
        || state.idempotency.len() > MAX_OPERATIONS_PER_WALLET
    {
        return Err(AgentWalletError::RecoveryRequired);
    }
    for (key, record) in &state.idempotency {
        let operation = state
            .operations
            .get(record.operation_id.as_str())
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let view = operation.view();
        if key != &scoped_idempotency_key(operation.agent_id(), &view.idempotency_key)
            || record.request_commitment != view.request_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
    }
    if !state.authentication_challenges.is_empty() || !state.authenticated_sessions.is_empty() {
        return Err(AgentWalletError::RecoveryRequired);
    }
    for (key, agent) in &state.agents {
        if key != agent.agent_id.as_str()
            || connector::validate_agent_record(
                agent,
                expected_wallet_id,
                &state.primary_signing_device_id,
            )
            .is_err()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
    }
    if state.pairing_completion_outbox.len() > MAX_PAIRING_COMPLETION_OUTBOX_ENTRIES {
        return Err(AgentWalletError::RecoveryRequired);
    }
    for (key, completion) in &state.pairing_completion_outbox {
        let persisted_agent = state.agents.get(completion.record().agent_id.as_str());
        if key != completion.pairing_id_sha256()
            || completion.validate().is_err()
            || persisted_agent != Some(completion.record())
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
    }
    if let Some(companion_security) = &state.companion_security {
        companion_security
            .validate(&state.wallet_id, state.updated_at)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
    }
    if let Some(rollback_witness) = &state.rollback_witness {
        rollback_witness
            .validate(&state.wallet_id)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        if state.witness_rotation_history.len() > 4_096 {
            return Err(AgentWalletError::RecoveryRequired);
        }
        for rotation in &state.witness_rotation_history {
            rotation.validate_completed_history(state)?;
        }
        for pair in state.witness_rotation_history.windows(2) {
            if pair[0].record.new_mobile_device_id != pair[1].record.old_mobile_device_id
                || pair[0].record.new_witness_epoch != pair[1].record.old_witness_epoch
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        if let (Some(previous), Some(active)) = (
            state.witness_rotation_history.last(),
            state.witness_rotation.as_ref(),
        ) && (previous.record.new_mobile_device_id != active.record.old_mobile_device_id
            || previous.record.new_witness_epoch != active.record.old_witness_epoch)
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
    }
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    if let Some(rotation) = &state.witness_rotation {
        rotation.validate(state)?;
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    if state.witness_rotation.is_some() || !state.witness_rotation_history.is_empty() {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok(())
}

pub(super) fn state_commitment(state: &AgentWalletState) -> AgentWalletResult<JournalCommitment> {
    let mut material = state.clone();
    material.journal_sequence = 0;
    material.journal_head_hash = ZERO_HASH_HEX.into();
    let bytes = serde_json::to_vec(&material).map_err(|_| AgentWalletError::PersistenceFailed)?;
    Ok(JournalCommitment::commit(b"materialized-state/v1", &bytes))
}

pub(super) fn mark_explicit_emergency_stop(
    state: &mut AgentWalletState,
) -> AgentWalletResult<bool> {
    let was_suspended = state.payments_suspended;
    let was_explicit = was_suspended && state.emergency_epoch > 1;
    let changed = suspend_state_for_emergency(state)?;
    if was_suspended && !was_explicit {
        state.emergency_epoch = state
            .emergency_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        return Ok(true);
    }
    Ok(changed)
}

fn suspend_state_for_emergency(state: &mut AgentWalletState) -> AgentWalletResult<bool> {
    let newly_suspended = !state.payments_suspended;
    if newly_suspended {
        state.payments_suspended = true;
        state.emergency_epoch = state
            .emergency_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
    }
    state.authenticated_sessions.clear();
    state.authentication_challenges.clear();
    let cancelled = cancel_pre_signing_operations(state, None, "emergency_stop")?;
    Ok(newly_suspended || cancelled != 0)
}

pub(super) fn cancel_pre_signing_operations(
    state: &mut AgentWalletState,
    agent_id: Option<&AgentId>,
    result: &str,
) -> AgentWalletResult<usize> {
    let mut cancelled = 0;
    for operation in state.operations.values_mut() {
        if agent_id.is_none_or(|expected| operation.agent_id() == expected)
            && operation.cancel_pre_signing(result)?
        {
            cancelled += 1;
        }
    }
    Ok(cancelled)
}

pub(super) fn active_reservations(state: &AgentWalletState) -> AgentWalletResult<HacUnits> {
    state
        .operations
        .values()
        .filter(|operation| operation.status().retains_reservation())
        .try_fold(HacUnits::ZERO, |total, operation| {
            total.checked_add(operation.view().reserved_units)
        })
}

pub(super) fn spent_in_window(
    state: &AgentWalletState,
    now: u64,
    window_seconds: u64,
) -> AgentWalletResult<HacUnits> {
    state
        .operations
        .values()
        .filter(|operation| {
            let view = operation.view();
            view.status == OperationStatus::Committed
                && operation
                    .settled_at()
                    .is_some_and(|settled| settled >= now.saturating_sub(window_seconds))
        })
        .try_fold(HacUnits::ZERO, |total, operation| {
            total.checked_add(operation.view().total_debit_units)
        })
}

pub(super) fn exposure_for_agent_in_window(
    state: &AgentWalletState,
    agent_id: &AgentId,
    now: u64,
    window_seconds: u64,
) -> AgentWalletResult<HacUnits> {
    state
        .operations
        .values()
        .filter(|operation| {
            let view = operation.view();
            operation.agent_id() == agent_id
                && ((view.status == OperationStatus::Committed
                    && operation
                        .settled_at()
                        .is_some_and(|settled| settled >= now.saturating_sub(window_seconds)))
                    || view.status.retains_reservation())
        })
        .try_fold(HacUnits::ZERO, |total, operation| {
            total.checked_add(operation.view().total_debit_units)
        })
}

fn hex_to_hash(encoded: &str) -> AgentWalletResult<[u8; 32]> {
    if encoded.len() != 64 {
        return Err(AgentWalletError::RecoveryRequired);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| AgentWalletError::RecoveryRequired)?;
    Ok(bytes)
}

pub(super) fn prune_aged_terminal_pre_signing_operations(
    state: &mut AgentWalletState,
    now: u64,
) -> usize {
    let prunable: BTreeSet<String> = state
        .operations
        .iter()
        .filter(|(_, operation)| {
            let outside_rate_window = operation.created_at() < now.saturating_sub(60);
            is_terminal_pre_signing_outcome(operation.status())
                && now >= operation.expires_at()
                && outside_rate_window
        })
        .map(|(key, _)| key.clone())
        .collect();
    remove_operations_and_idempotency(state, &prunable)
}

pub(super) fn prune_terminal_pre_signing_for_agent(
    state: &mut AgentWalletState,
    agent_id: &AgentId,
) -> usize {
    let prunable: BTreeSet<String> = state
        .operations
        .iter()
        .filter(|(_, operation)| {
            operation.agent_id() == agent_id && is_terminal_pre_signing_outcome(operation.status())
        })
        .map(|(key, _)| key.clone())
        .collect();
    remove_operations_and_idempotency(state, &prunable)
}

const fn is_terminal_pre_signing_outcome(status: OperationStatus) -> bool {
    matches!(
        status,
        OperationStatus::Rejected | OperationStatus::Failed | OperationStatus::Cancelled
    )
}

fn remove_operations_and_idempotency(
    state: &mut AgentWalletState,
    prunable: &BTreeSet<String>,
) -> usize {
    if prunable.is_empty() {
        return 0;
    }
    state
        .idempotency
        .retain(|_, record| !prunable.contains(record.operation_id.as_str()));
    state.operations.retain(|key, _| !prunable.contains(key));
    prunable.len()
}

pub(super) fn scoped_idempotency_key(agent_id: &AgentId, idempotency_key: &str) -> String {
    format!("{agent_id}\u{001f}{idempotency_key}")
}

pub(super) fn journal_path(paths: &AgentWalletPaths) -> PathBuf {
    paths.wallet_root().join(JOURNAL_FILE)
}

pub(super) fn validate_text(value: &str, maximum_bytes: usize) -> AgentWalletResult<()> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        Err(AgentWalletError::InvalidPaymentRequest)
    } else {
        Ok(())
    }
}
