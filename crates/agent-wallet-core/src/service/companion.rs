//! Durable mobile-companion authority for one explicit Agent Wallet.
//!
//! This module owns only authenticated public device records, replay state and
//! manually signed decisions. It has no transport, private mobile key, generic
//! signing, Personal Wallet, or autonomous-payment surface.

use hpay_companion_protocol::{
    AdminCommandKind, ApprovalDecision, CompanionError, DeviceId, DevicePublicRecord,
    DeviceRegistry, DeviceRole, ReplayGuard, ReplayGuardSnapshot, SignedAdminCommand,
    SignedApprovalDecision,
};
use serde::{Deserialize, Serialize};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::operation::{ApprovalMode, OperationStatus, PaymentOperationView};
use crate::types::{AgentWalletId, OperationId};

use super::{AgentWalletManager, mark_explicit_emergency_stop, require_agent_spending_network};

const COMPANION_SECURITY_STATE_VERSION: u64 = 1;
const MAX_ACTIVE_MOBILE_DEVICES: usize = 16;
const MAX_MOBILE_DEVICE_TOMBSTONES: usize = 256;

mod pairing;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod rotation;
mod session;
mod snapshot;
mod transport;
#[cfg(feature = "agent-wallet-testnet-pilot")]
mod witness;
pub use pairing::{
    AgentCompanionPairingAttempt, AgentCompletedCompanionPairing, AgentPairingAttemptBudget,
    MAX_PAIRING_REQUEST_ATTEMPTS,
};
pub use session::AgentDesktopSessionAttempt;

/// Optional state extension. Keeping the whole extension absent preserves the
/// exact serialized bytes and journal commitment of legacy Agent Wallets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompanionSecurityState {
    state_version: u64,
    device_registry: DeviceRegistry,
    replay_guard: ReplayGuardSnapshot,
    #[serde(default, skip_serializing_if = "is_zero")]
    desktop_challenge_sequence: u64,
}

impl CompanionSecurityState {
    fn empty(now: u64) -> AgentWalletResult<Self> {
        Ok(Self {
            state_version: COMPANION_SECURITY_STATE_VERSION,
            device_registry: DeviceRegistry::new(),
            replay_guard: ReplayGuard::new()
                .snapshot(now)
                .map_err(map_companion_state_error)?,
            desktop_challenge_sequence: 0,
        })
    }

    pub(super) fn validate(&self, wallet_id: &AgentWalletId, now: u64) -> AgentWalletResult<()> {
        if self.state_version != COMPANION_SECURITY_STATE_VERSION
            || self.device_registry.registry_version != 1
        {
            return Err(AgentWalletError::RecoveryRequired);
        }

        self.device_registry
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let mut total = 0_usize;
        let mut active = 0_usize;
        for record in self.device_registry.records() {
            total = total
                .checked_add(1)
                .ok_or(AgentWalletError::RecoveryRequired)?;
            if !record.is_revoked() {
                active = active
                    .checked_add(1)
                    .ok_or(AgentWalletError::RecoveryRequired)?;
            }
            if total > MAX_MOBILE_DEVICE_TOMBSTONES
                || active > MAX_ACTIVE_MOBILE_DEVICES
                || record.role != DeviceRole::Mobile
                || record.agent_wallet_id != wallet_id.as_str()
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
        }
        ReplayGuard::from_snapshot(self.replay_guard.clone(), now)
            .map(|_| ())
            .map_err(|_| AgentWalletError::RecoveryRequired)
    }

    fn replay_guard(&self, now: u64) -> AgentWalletResult<ReplayGuard> {
        ReplayGuard::from_snapshot(self.replay_guard.clone(), now)
            .map_err(map_companion_state_error)
    }
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl AgentWalletManager {
    /// Persists a public record only after the caller has completed and
    /// verified the typed companion pairing transcript and user code match.
    ///
    /// This API accepts no session key and no private key. A record cannot
    /// replace, revive, or silently re-authorize an existing device identity.
    pub(super) fn register_verified_companion_device(
        &mut self,
        wallet_id: &AgentWalletId,
        record: DevicePublicRecord,
        now: u64,
    ) -> AgentWalletResult<DevicePublicRecord> {
        record
            .validate()
            .map_err(|_| AgentWalletError::PairingDeviceRecordRejected)?;
        if record.is_revoked() {
            return Err(AgentWalletError::PairingDeviceRevoked);
        }
        if record.role != DeviceRole::Mobile || record.agent_wallet_id != wallet_id.as_str() {
            return Err(AgentWalletError::PairingDeviceRecordRejected);
        }

        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let had_companion_state = state.companion_security.is_some();
        let mut companion = state
            .companion_security
            .take()
            .map(Ok)
            .unwrap_or_else(|| CompanionSecurityState::empty(now))?;
        companion.validate(wallet_id, now)?;
        let total_devices = companion.device_registry.records().count();
        let active_devices = companion
            .device_registry
            .records()
            .filter(|current| !current.is_revoked())
            .count();
        let existing = companion
            .device_registry
            .records()
            .find(|current| current.device_id == record.device_id);
        if (total_devices >= MAX_MOBILE_DEVICE_TOMBSTONES && existing.is_none())
            || (active_devices >= MAX_ACTIVE_MOBILE_DEVICES
                && existing.is_none_or(|current| current.is_revoked()))
        {
            return Err(AgentWalletError::TooManyCompanionDevices);
        }
        // A phone keeps its hardware companion identity across a phone-side
        // reset, so an owner re-pairing the same handset presents the same
        // device id, key and fingerprint with only a newer `paired_at`.
        // `register` refuses that by design, because it must never act as an
        // implicit re-pair. The caller has just completed and verified the full
        // pairing transcript for this exact record, so route the re-pair
        // through the dedicated transition, which still refuses revoked
        // devices and any permission, epoch or identity delta.
        let is_repair_of_active_device = existing.is_some_and(|current| !current.is_revoked());
        let before = companion.device_registry.clone();
        if is_repair_of_active_device {
            companion
                .device_registry
                .refresh_verified_pairing(record.clone())
        } else {
            companion.device_registry.register(record.clone())
        }
        .map_err(map_pairing_registration_error)?;
        if before == companion.device_registry && had_companion_state {
            return Ok(record);
        }
        companion.validate(wallet_id, now)?;
        state.companion_security = Some(companion);
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::CompanionDevicePaired,
            None,
            Some(record.device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(record)
    }

    pub fn list_companion_devices(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<DevicePublicRecord>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        Ok(state
            .companion_security
            .map(|companion| companion.device_registry.records().cloned().collect())
            .unwrap_or_default())
    }

    /// Local trusted-UI revocation. Revocation is durable and advances the
    /// authorization epoch, invalidating every pre-revocation signed message.
    pub fn revoke_companion_device_locally(
        &mut self,
        wallet_id: &AgentWalletId,
        device_id: &DeviceId,
        now: u64,
    ) -> AgentWalletResult<DevicePublicRecord> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        companion.validate(wallet_id, now)?;
        let current = companion
            .device_registry
            .records()
            .find(|record| &record.device_id == device_id)
            .cloned()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        if current.is_revoked() {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }
        let expected_epoch = current
            .authorization_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        companion
            .device_registry
            .revoke(device_id, now)
            .map_err(map_companion_authorization_error)?;
        let revoked = companion
            .device_registry
            .records()
            .find(|record| &record.device_id == device_id)
            .cloned()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if revoked.revoked_at != Some(now) || revoked.authorization_epoch != expected_epoch {
            return Err(AgentWalletError::RecoveryRequired);
        }
        companion.validate(wallet_id, now)?;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::CompanionDeviceRevoked,
            None,
            Some(device_id.as_str().as_bytes()),
            now,
        )?;
        Ok(revoked)
    }

    /// Applies one signed mobile approval or rejection. The exact decision and
    /// replay consumption share one authenticated journal transition. Approval
    /// is reloaded by resume_payment before any signer call.
    pub async fn apply_mobile_approval_and_broadcast(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedApprovalDecision,
        now: u64,
    ) -> AgentWalletResult<PaymentOperationView> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        if signed.decision.decision == ApprovalDecision::Approve {
            require_agent_spending_network(&state.network_mode)?;
        }
        let operation_id = OperationId::parse(signed.decision.operation_id.clone())
            .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        let (expected, view, agent_id, operation_status) = {
            let operation = state
                .operations
                .get(operation_id.as_str())
                .ok_or(AgentWalletError::OperationNotFound)?;
            (
                operation.stored_approval()?.clone(),
                operation.view(),
                operation.agent_id().clone(),
                operation.status(),
            )
        };
        if view.network_fee_units != HacUnits::MIN_NETWORK_FEE
            || view.wallet_fee_units != HacUnits::ZERO
            || view.total_debit_units != view.amount_units.checked_add(view.network_fee_units)?
            || expected.fee_units != HacUnits::MIN_NETWORK_FEE.get()
            || expected.wallet_fee_units != 0
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        let approval_mode = state
            .agents
            .get(agent_id.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?
            .policy
            .approval_mode;
        if !matches!(
            approval_mode,
            ApprovalMode::MobileManual | ApprovalMode::EitherTrustedDevice
        ) {
            return Err(AgentWalletError::AgentPermissionDenied);
        }
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        companion.validate(wallet_id, now)?;
        let mut replay = companion.replay_guard(now)?;
        let permit = signed
            .verify(&expected, &companion.device_registry, &replay, now)
            .map_err(map_companion_decision_error)?;
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        if signed.decision.decision == ApprovalDecision::Approve {
            companion
                .device_registry
                .require(
                    &signed.decision.mobile_device_id,
                    wallet_id.as_str(),
                    DeviceRole::Mobile,
                    hpay_companion_protocol::DevicePermission::WitnessRollbackAnchor,
                )
                .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
        }
        if operation_status != OperationStatus::ApprovalRequested {
            return Err(AgentWalletError::InvalidOperationState);
        }
        let replay_snapshot = replay
            .commit_and_snapshot(permit, now)
            .map_err(map_companion_replay_error)?;
        let decision = signed.decision.decision;
        let mobile_device_id = signed.decision.mobile_device_id.clone();
        let operation = state
            .operations
            .get_mut(operation_id.as_str())
            .ok_or(AgentWalletError::OperationNotFound)?;
        let event = match decision {
            ApprovalDecision::Approve => {
                operation.record_approval(
                    expected,
                    ApprovalMode::MobileManual,
                    state.policy_epoch,
                    now,
                )?;
                AgentJournalEventKind::ApprovalGranted
            }
            ApprovalDecision::Reject => {
                operation.record_rejection(ApprovalMode::MobileManual, now)?;
                AgentJournalEventKind::ApprovalRejected
            }
        };
        state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .replay_guard = replay_snapshot;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            event,
            Some(operation_id.as_str().as_bytes()),
            Some(mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        let persisted = state
            .operations
            .get(operation_id.as_str())
            .ok_or(AgentWalletError::RecoveryRequired)?
            .view();
        if decision == ApprovalDecision::Reject {
            return Ok(persisted);
        }
        self.resume_payment(wallet_id, &operation_id, now).await
    }

    /// Applies only fail-safe mobile administration. The independent emergency
    /// marker is written before replay/state persistence; if persistence fails,
    /// the wallet remains stopped.
    pub fn apply_mobile_admin_command(
        &mut self,
        wallet_id: &AgentWalletId,
        signed: SignedAdminCommand,
        now: u64,
    ) -> AgentWalletResult<()> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let desktop_device_id = DeviceId::parse(state.primary_signing_device_id.clone())
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        companion.validate(wallet_id, now)?;
        let mut replay = companion.replay_guard(now)?;
        let permit = signed
            .verify(
                wallet_id.as_str(),
                &desktop_device_id,
                state.policy_epoch,
                &companion.device_registry,
                &replay,
                now,
            )
            .map_err(map_companion_admin_error)?;
        if signed.command.command_type != AdminCommandKind::SuspendAgentPayments {
            return Err(AgentWalletError::AgentPermissionDenied);
        }

        // Marker first: this invalidates outstanding safety permits without
        // waiting for this manager-held state transition.
        self.emergency_controller(wallet_id)?.request_stop()?;
        mark_explicit_emergency_stop(&mut state)?;
        let replay_snapshot = replay
            .commit_and_snapshot(permit, now)
            .map_err(map_companion_replay_error)?;
        state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .replay_guard = replay_snapshot;
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::EmergencyStopEnabled,
            None,
            Some(signed.command.mobile_device_id.as_str().as_bytes()),
            now,
        )
    }
}

fn map_companion_state_error(_: CompanionError) -> AgentWalletError {
    AgentWalletError::RecoveryRequired
}

fn map_companion_authorization_error(_: CompanionError) -> AgentWalletError {
    AgentWalletError::CompanionAuthorizationFailed
}

/// Names why the durable device registry refused the last step of a pairing.
///
/// This is the step that runs after the owner has already pressed "Yes, the
/// codes match", so an opaque failure here reads as a dead button. The refusals
/// themselves are unchanged; only the message the owner reads is.
fn map_pairing_registration_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::DeviceRevoked => AgentWalletError::PairingDeviceRevoked,
        CompanionError::DeviceAlreadyRegistered => AgentWalletError::PairingDeviceAlreadyRegistered,
        _ => AgentWalletError::PairingDeviceRecordRejected,
    }
}

fn map_companion_replay_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::SequenceReplay | CompanionError::NonceReplay => {
            AgentWalletError::CompanionReplayRejected
        }
        CompanionError::Expired => AgentWalletError::ApprovalExpired,
        _ => AgentWalletError::CompanionAuthorizationFailed,
    }
}

fn map_companion_decision_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::Expired => AgentWalletError::ApprovalExpired,
        CompanionError::ApprovalCommitmentMismatch | CompanionError::MalformedMessage => {
            AgentWalletError::ApprovalCommitmentMismatch
        }
        CompanionError::SequenceReplay | CompanionError::NonceReplay => {
            AgentWalletError::CompanionReplayRejected
        }
        _ => AgentWalletError::CompanionAuthorizationFailed,
    }
}

fn map_companion_admin_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::Expired => AgentWalletError::RequestExpired,
        CompanionError::SequenceReplay | CompanionError::NonceReplay => {
            AgentWalletError::CompanionReplayRejected
        }
        _ => AgentWalletError::CompanionAuthorizationFailed,
    }
}

#[cfg(test)]
#[path = "companion/tests/mod.rs"]
mod tests;
