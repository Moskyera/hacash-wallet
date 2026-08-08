//! Manager-owned, durable desktop companion reconnect lifecycle.

use super::super::{AgentWalletManager, AgentWalletState};
use crate::companion_signer::AgentDesktopCompanionSigner;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::types::AgentWalletId;
use hpay_companion_protocol::{
    CompanionError, DesktopSessionAttempt, DeviceId, DevicePublicRecord, DeviceRegistry,
    DeviceRole, EstablishedSession, PlatformDeviceSigner, SessionChallenge, SessionConfirmation,
    SessionResponse,
};
use std::collections::BTreeSet;

/// Single-use, memory-only desktop half of a reconnect handshake.
/// Ephemeral keys and established session keys are never serializable here.
pub struct AgentDesktopSessionAttempt {
    inner: DesktopSessionAttempt,
    wallet_id: AgentWalletId,
    mobile_device_id: DeviceId,
    desktop_authorization_epoch: u64,
    mobile_authorization_epoch: u64,
    emergency_epoch: u64,
    emergency_generation: u64,
    signer_authority: AgentDesktopCompanionSigner,
    rotation_candidate: bool,
}

impl std::fmt::Debug for AgentDesktopSessionAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentDesktopSessionAttempt")
            .field("session_id", &self.inner.challenge().session_id)
            .field("wallet_id", &self.wallet_id)
            .field("mobile_device_id", &self.mobile_device_id)
            .field(
                "desktop_authorization_epoch",
                &self.desktop_authorization_epoch,
            )
            .field(
                "mobile_authorization_epoch",
                &self.mobile_authorization_epoch,
            )
            .field("ephemeral_secret", &"<memory-only>")
            .finish()
    }
}

impl AgentDesktopSessionAttempt {
    pub fn challenge(&self) -> &SessionChallenge {
        self.inner.challenge()
    }
}

impl AgentWalletManager {
    /// Issues the next `challenge_sequence` for this wallet's desktop identity.
    ///
    /// The peer treats this field as a strictly increasing anti-replay counter
    /// for the `companion_session_challenge` scope, so it must never be drawn
    /// independently per handshake. The source is in memory and the durable
    /// high-water mark is fed back in, which keeps this phase free of durable
    /// writes for an unauthenticated peer while still never reissuing a
    /// sequence the desktop has already had accepted.
    fn next_challenge_sequence(
        &self,
        wallet_id: &AgentWalletId,
        durable_high_water: u64,
        now: u64,
    ) -> AgentWalletResult<u64> {
        let mut sequences = self
            .challenge_sequences
            .lock()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        sequences
            .entry(wallet_id.as_str().to_owned())
            .or_default()
            .next(durable_high_water, now)
            .map_err(map_session_error)
    }

    /// Constructs a single-use challenge without changing durable state.
    ///
    /// An unauthenticated peer can request this phase, so the ephemeral key
    /// material and the 32-byte challenge nonce that carry this handshake's
    /// unpredictability remain memory-only, and no durable write happens here.
    /// The signed response replay state is persisted by
    /// `accept_companion_desktop_response` before any successful session is
    /// released, together with the challenge sequence that was accepted.
    pub async fn start_companion_desktop_session(
        &mut self,
        wallet_id: &AgentWalletId,
        mobile_device_id: &DeviceId,
        now: u64,
        lifetime_secs: u64,
    ) -> AgentWalletResult<AgentDesktopSessionAttempt> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let durable_challenge_sequence = state
            .companion_security
            .as_ref()
            .map_or(0, |companion| companion.desktop_challenge_sequence);
        let emergency = self.emergency_controller(wallet_id)?;
        let safety = emergency.issue_connectivity_permit()?;
        let registry = composite_registry(&state, &session.desktop_companion_signer, now)?;
        let (mobile, rotation_candidate) =
            match active_mobile_record(&registry, wallet_id, mobile_device_id) {
                Ok(record) => (record.clone(), false),
                Err(_) => (
                    rotation_candidate_record(&state, wallet_id, mobile_device_id, now)?.clone(),
                    true,
                ),
            };
        let mut handshake_registry = registry;
        if rotation_candidate {
            handshake_registry
                .register(mobile.clone())
                .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
        }
        safety.checkpoint()?;

        let signer_authority = session.desktop_companion_signer.clone();
        let challenge_sequence =
            self.next_challenge_sequence(wallet_id, durable_challenge_sequence, now)?;
        let inner = DesktopSessionAttempt::start(
            &signer_authority,
            &handshake_registry,
            wallet_id.as_str(),
            mobile_device_id.clone(),
            challenge_sequence,
            now,
            lifetime_secs,
        )
        .await
        .map_err(map_session_error)?;
        safety.checkpoint()?;
        Ok(AgentDesktopSessionAttempt {
            inner,
            wallet_id: wallet_id.clone(),
            mobile_device_id: mobile.device_id,
            desktop_authorization_epoch: state.signer_epoch,
            mobile_authorization_epoch: mobile.authorization_epoch,
            emergency_epoch: state.emergency_epoch,
            emergency_generation: safety.generation(),
            signer_authority,
            rotation_candidate,
        })
    }
    /// Persists the consumed inbound replay state before releasing either the
    /// confirmation or memory-only established session to the caller.
    pub async fn accept_companion_desktop_response(
        &mut self,
        wallet_id: &AgentWalletId,
        mut attempt: AgentDesktopSessionAttempt,
        response: &SessionResponse,
        now: u64,
    ) -> AgentWalletResult<(SessionConfirmation, EstablishedSession)> {
        if &attempt.wallet_id != wallet_id {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        if !attempt
            .signer_authority
            .shares_authority_with(&session.desktop_companion_signer)
        {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let emergency = self.emergency_controller(wallet_id)?;
        let safety = emergency.issue_connectivity_permit()?;
        if safety.generation() != attempt.emergency_generation
            || state.emergency_epoch != attempt.emergency_epoch
            || state.signer_epoch != attempt.desktop_authorization_epoch
        {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }
        let companion = state
            .companion_security
            .as_ref()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        let challenge = attempt.inner.challenge();
        if challenge.agent_wallet_id != wallet_id.as_str()
            || challenge.mobile_device_id != attempt.mobile_device_id
            || challenge.desktop_authorization_epoch != attempt.desktop_authorization_epoch
            || challenge.mobile_authorization_epoch != attempt.mobile_authorization_epoch
            || challenge.challenge_sequence == 0
        {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }
        let accepted_challenge_sequence = challenge.challenge_sequence;

        let mut registry = composite_registry(&state, &session.desktop_companion_signer, now)?;
        let current_mobile = if attempt.rotation_candidate {
            let candidate =
                rotation_candidate_record(&state, wallet_id, &attempt.mobile_device_id, now)?
                    .clone();
            registry
                .register(candidate)
                .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
            registry
                .records()
                .find(|record| record.device_id == attempt.mobile_device_id)
                .ok_or(AgentWalletError::CompanionAuthorizationFailed)?
        } else {
            active_mobile_record(&registry, wallet_id, &attempt.mobile_device_id)?
        };
        if current_mobile.authorization_epoch != attempt.mobile_authorization_epoch {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }
        let mut replay = companion.replay_guard(now)?;
        safety.checkpoint()?;
        let (confirmation, established) = attempt
            .inner
            .accept_response(
                response,
                &session.desktop_companion_signer,
                &registry,
                &mut replay,
                now,
            )
            .await
            .map_err(map_session_error)?;
        established
            .validate_at(&registry, now)
            .map_err(map_session_error)?;
        let replay_snapshot = replay.snapshot(now).map_err(map_session_error)?;
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        companion.replay_guard = replay_snapshot;
        // Durable high-water mark for the challenge counter. The peer's replay
        // guard has now accepted this sequence, so a restarted desktop must
        // never offer it, or anything below it, again.
        if accepted_challenge_sequence > companion.desktop_challenge_sequence {
            companion.desktop_challenge_sequence = accepted_challenge_sequence;
        }
        state.updated_at = now;
        safety.checkpoint()?;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::CompanionSessionEstablished,
            None,
            Some(attempt.mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        safety.checkpoint()?;
        Ok((confirmation, established))
    }
}

fn rotation_candidate_record<'a>(
    state: &'a AgentWalletState,
    wallet_id: &AgentWalletId,
    mobile_device_id: &DeviceId,
    now: u64,
) -> AgentWalletResult<&'a DevicePublicRecord> {
    let rotation = state
        .witness_rotation
        .as_ref()
        .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
    let candidate = rotation
        .candidate_device
        .as_ref()
        .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
    if candidate.device_id != *mobile_device_id
        || candidate.agent_wallet_id != wallet_id.as_str()
        || candidate.is_revoked()
        || rotation.ticket_consumed_at.is_none()
        || rotation.candidate_acceptance.is_none()
        || !matches!(
            rotation.phase,
            hpay_companion_protocol::WitnessRotationPhase::CandidatePairedRestricted
                | hpay_companion_protocol::WitnessRotationPhase::CandidateBaselineVerified
                | hpay_companion_protocol::WitnessRotationPhase::AwaitingOldDeviceRevocation
                | hpay_companion_protocol::WitnessRotationPhase::AwaitingCompletionAnchor
                | hpay_companion_protocol::WitnessRotationPhase::AwaitingRotationCompletionAnchor
        )
    {
        return Err(AgentWalletError::CompanionAuthorizationFailed);
    }
    rotation
        .pairing_ticket
        .as_ref()
        .ok_or(AgentWalletError::CompanionAuthorizationFailed)?
        .ticket
        .validate_at(now)
        .or_else(|error| {
            if matches!(
                rotation.phase,
                hpay_companion_protocol::WitnessRotationPhase::AwaitingCompletionAnchor
                    | hpay_companion_protocol::WitnessRotationPhase::AwaitingRotationCompletionAnchor
            ) {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
    Ok(candidate)
}

pub(super) fn composite_registry(
    state: &AgentWalletState,
    signer: &AgentDesktopCompanionSigner,
    now: u64,
) -> AgentWalletResult<DeviceRegistry> {
    let companion = state
        .companion_security
        .as_ref()
        .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
    companion.validate(&state.wallet_id, now)?;
    let identity = signer.identity();
    let primary = DeviceId::parse(state.primary_signing_device_id.clone())
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
    if identity.role() != DeviceRole::Desktop || identity.device_id() != &primary {
        return Err(AgentWalletError::RecoveryRequired);
    }
    let desktop = DevicePublicRecord {
        record_version: 1,
        device_id: primary,
        role: DeviceRole::Desktop,
        agent_wallet_id: state.wallet_id.to_string(),
        identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
        identity_fingerprint: identity
            .fingerprint()
            .map_err(|_| AgentWalletError::RecoveryRequired)?,
        authorization_epoch: state.signer_epoch,
        permissions: BTreeSet::new(),
        paired_at: 1,
        revoked_at: None,
    };
    desktop
        .validate()
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
    let mut registry = companion.device_registry.clone();
    registry
        .register(desktop)
        .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
    registry
        .validate()
        .map_err(|_| AgentWalletError::RecoveryRequired)?;
    Ok(registry)
}

fn active_mobile_record<'a>(
    registry: &'a DeviceRegistry,
    wallet_id: &AgentWalletId,
    mobile_device_id: &DeviceId,
) -> AgentWalletResult<&'a DevicePublicRecord> {
    let record = registry
        .records()
        .find(|record| &record.device_id == mobile_device_id)
        .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
    record
        .validate()
        .map_err(|_| AgentWalletError::CompanionAuthorizationFailed)?;
    if record.role != DeviceRole::Mobile
        || record.agent_wallet_id != wallet_id.as_str()
        || record.is_revoked()
    {
        return Err(AgentWalletError::CompanionAuthorizationFailed);
    }
    Ok(record)
}

fn map_session_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::SequenceReplay | CompanionError::NonceReplay => {
            AgentWalletError::CompanionReplayRejected
        }
        CompanionError::Expired => AgentWalletError::RequestExpired,
        _ => AgentWalletError::CompanionAuthorizationFailed,
    }
}
