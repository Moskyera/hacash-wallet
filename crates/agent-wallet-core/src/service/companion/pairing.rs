//! Manager-owned, memory-only mobile companion pairing lifecycle.
//!
//! The manager binds every protocol transition to one unlocked Agent Wallet,
//! its current desktop signer authority, and its current emergency generation.
//! Pairing secrets never enter authenticated state or a serializable wrapper.

use hpay_companion_protocol::{
    CompanionError, DevicePublicRecord, EncryptedCompanionFrame, LanEndpoint, PairingConfirmation,
    PairingOffer, PairingRequest, PairingResult, PairingSession, SessionCipher,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::{SignedRotationCandidateAcceptance, SignedRotationPairingTicket};

use crate::companion_signer::AgentDesktopCompanionSigner;
use crate::emergency::AgentConnectivityPermit;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

use super::super::AgentWalletManager;

const MAX_ACTIVE_PAIRING_ATTEMPTS: usize = 4;

/// How many signed mobile pairing requests one offer will answer before it is
/// destroyed.
///
/// This budget is deliberately visible to the trusted UI. Silently spending it
/// is what made a sixth attempt look like a dead button.
pub const MAX_PAIRING_REQUEST_ATTEMPTS: u8 = 5;

/// The attempt budget of one live pairing, safe to show in the trusted UI.
///
/// It carries no pairing identifier, code, nonce or key material, so it can be
/// serialized to the desktop without widening what leaves the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentPairingAttemptBudget {
    used: u8,
    max: u8,
}

impl AgentPairingAttemptBudget {
    /// Signed mobile requests this pairing has already answered.
    pub fn used(&self) -> u8 {
        self.used
    }

    /// Total signed mobile requests this pairing will ever answer.
    pub fn max(&self) -> u8 {
        self.max
    }

    /// Attempts left before the pairing is destroyed. Saturating, never wraps.
    pub fn remaining(&self) -> u8 {
        self.max.saturating_sub(self.used)
    }

    /// The 1-based attempt the next press will consume, capped at `max`.
    pub fn next_attempt(&self) -> u8 {
        self.used.saturating_add(1).min(self.max)
    }
}

/// Opaque, single-wallet desktop pairing state.
///
/// This type intentionally implements neither `Clone` nor serialization. Its
/// protocol session owns the ephemeral X25519 secret and derived session key.
pub struct AgentCompanionPairingAttempt {
    inner: PairingSession,
    wallet_id: AgentWalletId,
    pairing_id: String,
    expires_at: u64,
    signer_epoch: u64,
    emergency_epoch: u64,
    emergency_generation: u64,
    request_attempts: u8,
    signer_authority: AgentDesktopCompanionSigner,
    purpose: PairingPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PairingPurpose {
    GeneralCompanion,
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    RotationCandidate {
        rotation_id: String,
    },
}

impl std::fmt::Debug for AgentCompanionPairingAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentCompanionPairingAttempt")
            .field("wallet_id", &self.wallet_id)
            .field("pairing_id", &self.pairing_id)
            .field("expires_at", &self.expires_at)
            .field("signer_epoch", &self.signer_epoch)
            .field("emergency_epoch", &self.emergency_epoch)
            .field("pairing_secret", &"<memory-only>")
            .finish()
    }
}

impl AgentCompanionPairingAttempt {
    /// Public offer safe to encode in the trusted UI's pairing QR.
    pub fn offer(&self) -> &PairingOffer {
        self.inner.offer()
    }

    /// How much of the bounded request budget this pairing has spent.
    pub fn attempt_budget(&self) -> AgentPairingAttemptBudget {
        AgentPairingAttemptBudget {
            used: self.request_attempts.min(MAX_PAIRING_REQUEST_ATTEMPTS),
            max: MAX_PAIRING_REQUEST_ATTEMPTS,
        }
    }
}

impl Drop for AgentCompanionPairingAttempt {
    fn drop(&mut self) {
        self.inner.cancel();
    }
}

/// A successfully verified pairing whose mobile record is already durable.
///
/// The only key-bearing exit is a consuming desktop cipher. There is no raw
/// session-key accessor and no mobile-cipher conversion on the desktop side.
pub struct AgentCompletedCompanionPairing {
    result: PairingResult,
}

impl std::fmt::Debug for AgentCompletedCompanionPairing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentCompletedCompanionPairing")
            .field("mobile_device_record", &self.result.mobile_device_record)
            .field("session_key", &"<memory-only>")
            .finish()
    }
}

impl AgentCompletedCompanionPairing {
    pub fn mobile_device_record(&self) -> &DevicePublicRecord {
        &self.result.mobile_device_record
    }

    pub fn into_desktop_cipher(self) -> AgentWalletResult<SessionCipher> {
        self.result.into_desktop_cipher().map_err(map_pairing_error)
    }
}

impl AgentWalletManager {
    /// Starts an in-memory pairing for one unlocked, emergency-safe wallet.
    pub fn start_companion_pairing(
        &mut self,
        wallet_id: &AgentWalletId,
        lan_endpoints: Vec<LanEndpoint>,
        now: u64,
        lifetime_secs: u64,
    ) -> AgentWalletResult<AgentCompanionPairingAttempt> {
        self.ensure_session_active(wallet_id, now)?;
        let (signer_authority, signer_epoch, emergency_epoch, safety) = {
            let session = self.session(wallet_id)?;
            let state =
                self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
            let emergency = self.emergency_controller(wallet_id)?;
            let safety = emergency.issue_connectivity_permit()?;
            (
                session.desktop_companion_signer.clone(),
                state.signer_epoch,
                state.emergency_epoch,
                safety,
            )
        };
        safety.checkpoint()?;

        let mut inner = PairingSession::new(
            &signer_authority,
            wallet_id.as_str(),
            lan_endpoints,
            now,
            lifetime_secs,
        )
        .map_err(map_pairing_error)?;
        let pairing_id = inner.offer().pairing_id.clone();
        let expires_at = inner.offer().expires_at;

        let session = self
            .unlocked
            .get_mut(wallet_id.as_str())
            .ok_or(AgentWalletError::AgentWalletLocked)?;
        session
            .active_companion_pairings
            .retain(|_, registered_expiry| *registered_expiry > now);
        if session.active_companion_pairings.len() >= MAX_ACTIVE_PAIRING_ATTEMPTS {
            inner.cancel();
            return Err(AgentWalletError::RateLimited);
        }
        if session
            .active_companion_pairings
            .insert(pairing_id.clone(), expires_at)
            .is_some()
        {
            inner.cancel();
            return Err(AgentWalletError::PairingAlreadyRegistered);
        }
        if let Err(error) = safety.checkpoint() {
            session.active_companion_pairings.remove(&pairing_id);
            inner.cancel();
            return Err(error);
        }

        Ok(AgentCompanionPairingAttempt {
            inner,
            wallet_id: wallet_id.clone(),
            pairing_id,
            expires_at,
            signer_epoch,
            emergency_epoch,
            emergency_generation: safety.generation(),
            request_attempts: 0,
            signer_authority,
            purpose: PairingPurpose::GeneralCompanion,
        })
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub fn start_rotation_candidate_pairing(
        &mut self,
        wallet_id: &AgentWalletId,
        rotation_id: &str,
        lan_endpoints: Vec<LanEndpoint>,
        now: u64,
        lifetime_secs: u64,
    ) -> AgentWalletResult<AgentCompanionPairingAttempt> {
        self.require_rotation_candidate_pairing(wallet_id, rotation_id, now)?;
        let mut attempt =
            self.start_companion_pairing(wallet_id, lan_endpoints, now, lifetime_secs)?;
        attempt.purpose = PairingPurpose::RotationCandidate {
            rotation_id: rotation_id.to_owned(),
        };
        Ok(attempt)
    }

    /// Accepts only the typed, signed mobile request for this exact attempt.
    pub async fn accept_companion_pairing_request(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        request: PairingRequest,
        now: u64,
    ) -> AgentWalletResult<PairingConfirmation> {
        if attempt.purpose != PairingPurpose::GeneralCompanion {
            return Err(AgentWalletError::PairingPurposeMismatch);
        }
        self.accept_pairing_request_inner(wallet_id, attempt, request, now)
            .await
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub async fn accept_rotation_candidate_pairing_request(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        request: PairingRequest,
        now: u64,
    ) -> AgentWalletResult<(PairingConfirmation, SignedRotationPairingTicket)> {
        let rotation_id = match &attempt.purpose {
            PairingPurpose::RotationCandidate { rotation_id } => rotation_id.clone(),
            PairingPurpose::GeneralCompanion => {
                return Err(AgentWalletError::PairingPurposeMismatch);
            }
        };
        let confirmation = self
            .accept_pairing_request_inner(wallet_id, attempt, request, now)
            .await?;
        let candidate = attempt
            .inner
            .verified_mobile_record()
            .cloned()
            .ok_or(AgentWalletError::PairingPhoneRecordMissing)?;
        let ticket = self
            .issue_rotation_pairing_ticket(
                wallet_id,
                &rotation_id,
                attempt.pairing_id.clone(),
                candidate,
                now,
                attempt.expires_at,
            )
            .await?;
        Ok((confirmation, ticket))
    }

    async fn accept_pairing_request_inner(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        request: PairingRequest,
        now: u64,
    ) -> AgentWalletResult<PairingConfirmation> {
        let safety = self.validate_pairing_attempt(wallet_id, attempt, now)?;
        attempt.request_attempts = attempt
            .request_attempts
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        if attempt.request_attempts > MAX_PAIRING_REQUEST_ATTEMPTS {
            self.invalidate_pairing_attempt(attempt);
            return Err(AgentWalletError::PairingAttemptsExhausted);
        }
        let confirmation = match attempt
            .inner
            .accept_request(request, &attempt.signer_authority, now)
            .await
        {
            Ok(confirmation) => confirmation,
            Err(error) => {
                if attempt.request_attempts >= MAX_PAIRING_REQUEST_ATTEMPTS {
                    self.invalidate_pairing_attempt(attempt);
                }
                return Err(map_pairing_error(error));
            }
        };
        if let Err(error) = safety.checkpoint() {
            self.invalidate_pairing_attempt(attempt);
            return Err(error);
        }
        if let Err(error) = self.validate_pairing_attempt(wallet_id, attempt, now) {
            self.invalidate_pairing_attempt(attempt);
            return Err(error);
        }
        Ok(confirmation)
    }

    /// Accepts no plaintext proof and no downgraded acknowledgement.
    pub fn accept_companion_pairing_ack(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        frame: &EncryptedCompanionFrame,
        now: u64,
    ) -> AgentWalletResult<()> {
        let safety = self.validate_pairing_attempt(wallet_id, attempt, now)?;
        attempt
            .inner
            .accept_encrypted_mobile_ack(frame, now)
            .map_err(map_pairing_error)?;
        if let Err(error) = safety.checkpoint() {
            self.invalidate_pairing_attempt(attempt);
            return Err(error);
        }
        if let Err(error) = self.validate_pairing_attempt(wallet_id, attempt, now) {
            self.invalidate_pairing_attempt(attempt);
            return Err(error);
        }
        Ok(())
    }

    /// Confirms the locally displayed code and persists the exact mobile
    /// record before returning any usable session cipher.
    pub fn complete_companion_pairing_code(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        verification_code: &str,
        now: u64,
    ) -> AgentWalletResult<AgentCompletedCompanionPairing> {
        if attempt.purpose != PairingPurpose::GeneralCompanion {
            return Err(AgentWalletError::PairingPurposeMismatch);
        }
        let safety = self.validate_pairing_attempt(wallet_id, attempt, now)?;
        let result = match attempt.inner.confirm_code(verification_code, now) {
            Ok(result) => result,
            Err(error) => {
                if error != CompanionError::VerificationCodeMismatch {
                    self.invalidate_pairing_attempt(attempt);
                }
                return Err(map_pairing_error(error));
            }
        };
        self.remove_pairing_registration(attempt);
        safety.checkpoint()?;

        let expected = result.mobile_device_record.clone();
        let registered =
            self.register_verified_companion_device(wallet_id, expected.clone(), now)?;
        if registered != expected {
            return Err(AgentWalletError::RecoveryRequired);
        }
        safety.checkpoint()?;
        Ok(AgentCompletedCompanionPairing { result })
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub fn complete_rotation_candidate_pairing_code(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &mut AgentCompanionPairingAttempt,
        verification_code: &str,
        signed_acceptance: SignedRotationCandidateAcceptance,
        now: u64,
    ) -> AgentWalletResult<DevicePublicRecord> {
        let rotation_id = match &attempt.purpose {
            PairingPurpose::RotationCandidate { rotation_id } => rotation_id.clone(),
            PairingPurpose::GeneralCompanion => {
                return Err(AgentWalletError::PairingPurposeMismatch);
            }
        };
        let safety = self.validate_pairing_attempt(wallet_id, attempt, now)?;
        let result = match attempt.inner.confirm_code(verification_code, now) {
            Ok(result) => result,
            Err(error) => {
                if error != CompanionError::VerificationCodeMismatch {
                    self.invalidate_pairing_attempt(attempt);
                }
                return Err(map_pairing_error(error));
            }
        };
        self.remove_pairing_registration(attempt);
        safety.checkpoint()?;
        let candidate = result.mobile_device_record.clone();
        self.accept_rotation_candidate(
            wallet_id,
            &rotation_id,
            candidate.clone(),
            signed_acceptance,
            now,
        )?;
        safety.checkpoint()?;
        drop(result);
        Ok(candidate)
    }

    /// Cancels the protocol state and releases its bounded in-memory slot.
    pub fn cancel_companion_pairing(
        &mut self,
        wallet_id: &AgentWalletId,
        mut attempt: AgentCompanionPairingAttempt,
    ) -> AgentWalletResult<()> {
        if &attempt.wallet_id != wallet_id {
            self.remove_pairing_registration(&attempt);
            attempt.inner.cancel();
            return Err(AgentWalletError::InvalidWalletScope);
        }
        self.remove_pairing_registration(&attempt);
        attempt.inner.cancel();
        Ok(())
    }

    fn validate_pairing_attempt(
        &mut self,
        wallet_id: &AgentWalletId,
        attempt: &AgentCompanionPairingAttempt,
        now: u64,
    ) -> AgentWalletResult<AgentConnectivityPermit> {
        if &attempt.wallet_id != wallet_id {
            return Err(AgentWalletError::InvalidWalletScope);
        }
        if now >= attempt.expires_at {
            return Err(AgentWalletError::RequestExpired);
        }
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        // Two independent refusals that used to share one opaque error. A lock,
        // unlock or restart replaces the desktop signer authority; a cancelled,
        // expired or already-consumed pairing is simply no longer registered.
        if !attempt
            .signer_authority
            .shares_authority_with(&session.desktop_companion_signer)
        {
            return Err(AgentWalletError::PairingSignerAuthorityChanged);
        }
        if session
            .active_companion_pairings
            .get(&attempt.pairing_id)
            .copied()
            != Some(attempt.expires_at)
        {
            // Same refusal, honest reason: a pairing that spent its whole
            // request budget was destroyed here on purpose, so tell the owner
            // that instead of the generic "this desktop is not holding it".
            if attempt.request_attempts >= MAX_PAIRING_REQUEST_ATTEMPTS {
                return Err(AgentWalletError::PairingAttemptsExhausted);
            }
            return Err(AgentWalletError::PairingUnknownToSession);
        }
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let emergency = self.emergency_controller(wallet_id)?;
        let safety = emergency.issue_connectivity_permit()?;
        // The interlock check: a pairing must never be completed across an
        // emergency stop, a signer rotation or a pause/resume.
        if state.signer_epoch != attempt.signer_epoch
            || state.emergency_epoch != attempt.emergency_epoch
            || safety.generation() != attempt.emergency_generation
        {
            return Err(AgentWalletError::PairingStateChangedSinceStart);
        }
        // The offer on screen must still be the offer this attempt owns.
        if attempt.inner.offer().agent_wallet_id != wallet_id.as_str()
            || attempt.inner.offer().pairing_id != attempt.pairing_id
            || attempt.inner.offer().expires_at != attempt.expires_at
        {
            return Err(AgentWalletError::PairingOfferBindingMismatch);
        }
        safety.checkpoint()?;
        Ok(safety)
    }

    fn invalidate_pairing_attempt(&mut self, attempt: &mut AgentCompanionPairingAttempt) {
        self.remove_pairing_registration(attempt);
        attempt.inner.cancel();
    }

    fn remove_pairing_registration(&mut self, attempt: &AgentCompanionPairingAttempt) {
        if let Some(session) = self.unlocked.get_mut(attempt.wallet_id.as_str())
            && session
                .active_companion_pairings
                .get(&attempt.pairing_id)
                .copied()
                == Some(attempt.expires_at)
        {
            session
                .active_companion_pairings
                .remove(&attempt.pairing_id);
        }
    }
}

/// Names the real protocol reason a pairing step refused.
///
/// Every arm keeps the same fail-closed outcome the single opaque variant had.
/// Only the message the owner reads changes, and none of them can carry a code,
/// nonce, fingerprint or key: the protocol error itself holds no such value.
fn map_pairing_error(error: CompanionError) -> AgentWalletError {
    match error {
        CompanionError::PairingExpired | CompanionError::Expired => {
            AgentWalletError::RequestExpired
        }
        CompanionError::VerificationCodeMismatch => {
            AgentWalletError::PairingVerificationCodeMismatch
        }
        CompanionError::InvalidSignature
        | CompanionError::InvalidIdentityKey
        | CompanionError::InvalidDeviceId
        | CompanionError::FingerprintMismatch
        | CompanionError::PlatformSignerUnavailable => AgentWalletError::PairingIdentityMismatch,
        CompanionError::DeviceRevoked => AgentWalletError::PairingDeviceRevoked,
        CompanionError::DeviceAlreadyRegistered => AgentWalletError::PairingDeviceAlreadyRegistered,
        CompanionError::PairingAlreadyUsed | CompanionError::PairingCancelled => {
            AgentWalletError::PairingAlreadyUsed
        }
        _ => AgentWalletError::PairingTranscriptMismatch,
    }
}
