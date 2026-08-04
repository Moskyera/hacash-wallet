use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::kdf::{
    decode_public, derive_session_key, diffie_hellman, ephemeral_public, random_secret,
};
use super::types::{
    SESSION_PROTOCOL_VERSION, SessionChallenge, SessionConfirmation, SessionResponse,
};
use super::validation::{
    NONCE_BYTES, SESSION_RANDOM_BYTES, current_record, signer_matches, validate_requested_lifetime,
};
use crate::envelope::SessionCipher;
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DeviceRegistry, DeviceRole, DeviceSignaturePurpose, PlatformDeviceSigner,
    sign_with_platform,
};
use crate::replay::{MAX_CLOCK_SKEW_SECS, ReplayGuard};

pub struct DesktopSessionAttempt {
    challenge: SessionChallenge,
    ephemeral_secret: Zeroizing<[u8; 32]>,
    consumed: bool,
}

impl std::fmt::Debug for DesktopSessionAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopSessionAttempt")
            .field("session_id", &self.challenge.session_id)
            .field("desktop_device_id", &self.challenge.desktop_device_id)
            .field("mobile_device_id", &self.challenge.mobile_device_id)
            .field("ephemeral_secret", &"<memory-only>")
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl DesktopSessionAttempt {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        desktop_signer: &dyn PlatformDeviceSigner,
        registry: &DeviceRegistry,
        agent_wallet_id: impl Into<String>,
        mobile_device_id: DeviceId,
        challenge_sequence: u64,
        now: u64,
        lifetime_secs: u64,
    ) -> CompanionResult<Self> {
        let agent_wallet_id = agent_wallet_id.into();
        validate_requested_lifetime(now, lifetime_secs)?;
        let desktop_record = current_record(
            registry,
            desktop_signer.identity().device_id(),
            &agent_wallet_id,
            DeviceRole::Desktop,
            None,
            None,
        )?;
        signer_matches(desktop_signer, desktop_record, DeviceRole::Desktop)?;
        let mobile_record = current_record(
            registry,
            &mobile_device_id,
            &agent_wallet_id,
            DeviceRole::Mobile,
            None,
            None,
        )?;

        let ephemeral_secret = random_secret();
        let ephemeral_public = ephemeral_public(&ephemeral_secret);
        let mut session_random = [0_u8; SESSION_RANDOM_BYTES];
        let mut challenge_nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut session_random);
        OsRng.fill_bytes(&mut challenge_nonce);
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(CompanionError::InvalidSession)?;
        let mut challenge = SessionChallenge {
            protocol_version: SESSION_PROTOCOL_VERSION,
            session_id: format!("session_{}", hex::encode(session_random)),
            agent_wallet_id,
            desktop_device_id: desktop_record.device_id.clone(),
            desktop_authorization_epoch: desktop_record.authorization_epoch,
            desktop_identity_fingerprint: desktop_record.identity_fingerprint.clone(),
            mobile_device_id: mobile_record.device_id.clone(),
            mobile_authorization_epoch: mobile_record.authorization_epoch,
            mobile_identity_fingerprint: mobile_record.identity_fingerprint.clone(),
            desktop_ephemeral_public_key: hex::encode(ephemeral_public.as_bytes()),
            challenge_sequence,
            challenge_nonce: hex::encode(challenge_nonce),
            issued_at: now,
            expires_at,
            desktop_identity_signature: String::new(),
        };
        challenge.validate_unsigned_shape()?;
        challenge.desktop_identity_signature = sign_with_platform(
            desktop_signer,
            DeviceSignaturePurpose::SessionChallenge,
            &challenge.unsigned_bytes()?,
        )
        .await?;
        challenge.validate_at(now)?;
        Ok(Self {
            challenge,
            ephemeral_secret,
            consumed: false,
        })
    }

    pub fn challenge(&self) -> &SessionChallenge {
        &self.challenge
    }

    pub async fn accept_response(
        &mut self,
        response: &SessionResponse,
        desktop_signer: &dyn PlatformDeviceSigner,
        registry: &DeviceRegistry,
        replay_guard: &mut ReplayGuard,
        now: u64,
    ) -> CompanionResult<(SessionConfirmation, EstablishedSession)> {
        if self.consumed {
            return Err(CompanionError::InvalidSession);
        }
        self.challenge.validate_at(now)?;
        response.validate_at(now)?;
        response_matches(response, &self.challenge)?;
        let desktop_record = current_record(
            registry,
            &self.challenge.desktop_device_id,
            &self.challenge.agent_wallet_id,
            DeviceRole::Desktop,
            Some(self.challenge.desktop_authorization_epoch),
            Some(&self.challenge.desktop_identity_fingerprint),
        )?;
        signer_matches(desktop_signer, desktop_record, DeviceRole::Desktop)?;
        let mobile_record = current_record(
            registry,
            &self.challenge.mobile_device_id,
            &self.challenge.agent_wallet_id,
            DeviceRole::Mobile,
            Some(self.challenge.mobile_authorization_epoch),
            Some(&self.challenge.mobile_identity_fingerprint),
        )?;
        mobile_record.verify_signature(
            DeviceSignaturePurpose::SessionResponse,
            &response.unsigned_bytes()?,
            &response.mobile_identity_signature,
        )?;
        let replay_permit = replay_guard.check(&response.replay_metadata(), now)?;
        let mobile_ephemeral = decode_public(&response.mobile_ephemeral_public_key)?;
        let shared_secret = diffie_hellman(&self.ephemeral_secret, &mobile_ephemeral)?;

        let mut confirmation_nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut confirmation_nonce);
        let mut confirmation = SessionConfirmation {
            protocol_version: SESSION_PROTOCOL_VERSION,
            session_id: self.challenge.session_id.clone(),
            agent_wallet_id: self.challenge.agent_wallet_id.clone(),
            desktop_device_id: self.challenge.desktop_device_id.clone(),
            desktop_authorization_epoch: self.challenge.desktop_authorization_epoch,
            desktop_identity_fingerprint: self.challenge.desktop_identity_fingerprint.clone(),
            mobile_device_id: self.challenge.mobile_device_id.clone(),
            mobile_authorization_epoch: self.challenge.mobile_authorization_epoch,
            mobile_identity_fingerprint: self.challenge.mobile_identity_fingerprint.clone(),
            challenge_commitment: self.challenge.commitment()?,
            response_commitment: response.commitment()?,
            confirmation_nonce: hex::encode(confirmation_nonce),
            issued_at: now,
            expires_at: self.challenge.expires_at,
            desktop_identity_signature: String::new(),
        };
        confirmation.validate_unsigned_shape()?;
        let session_key =
            derive_session_key(&shared_secret, &self.challenge, response, &confirmation)?;
        confirmation.desktop_identity_signature = sign_with_platform(
            desktop_signer,
            DeviceSignaturePurpose::SessionConfirmation,
            &confirmation.unsigned_bytes()?,
        )
        .await?;
        replay_guard.commit(replay_permit, now)?;
        self.consumed = true;
        Ok((
            confirmation,
            EstablishedSession::new(&self.challenge, session_key),
        ))
    }
}

pub struct EstablishedSession {
    pub session_id: String,
    pub agent_wallet_id: String,
    pub desktop_device_id: DeviceId,
    pub mobile_device_id: DeviceId,
    pub desktop_authorization_epoch: u64,
    pub mobile_authorization_epoch: u64,
    pub expires_at: u64,
    session_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for EstablishedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EstablishedSession")
            .field("session_id", &self.session_id)
            .field("agent_wallet_id", &self.agent_wallet_id)
            .field("desktop_device_id", &self.desktop_device_id)
            .field("mobile_device_id", &self.mobile_device_id)
            .field(
                "desktop_authorization_epoch",
                &self.desktop_authorization_epoch,
            )
            .field(
                "mobile_authorization_epoch",
                &self.mobile_authorization_epoch,
            )
            .field("expires_at", &self.expires_at)
            .field("session_key", &"<memory-only>")
            .finish()
    }
}

impl EstablishedSession {
    pub(super) fn new(challenge: &SessionChallenge, session_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            session_id: challenge.session_id.clone(),
            agent_wallet_id: challenge.agent_wallet_id.clone(),
            desktop_device_id: challenge.desktop_device_id.clone(),
            mobile_device_id: challenge.mobile_device_id.clone(),
            desktop_authorization_epoch: challenge.desktop_authorization_epoch,
            mobile_authorization_epoch: challenge.mobile_authorization_epoch,
            expires_at: challenge.expires_at,
            session_key,
        }
    }

    #[cfg(test)]
    pub(crate) fn session_key_for_testing(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Consumes the established handshake state without exporting or copying
    /// the session key into caller-owned memory.
    pub fn into_desktop_cipher(self) -> CompanionResult<SessionCipher> {
        self.into_cipher(true)
    }

    /// Mobile counterpart of [`Self::into_desktop_cipher`].
    pub fn into_mobile_cipher(self) -> CompanionResult<SessionCipher> {
        self.into_cipher(false)
    }

    fn into_cipher(self, desktop_is_local: bool) -> CompanionResult<SessionCipher> {
        let (local_device_id, remote_device_id) = if desktop_is_local {
            (self.desktop_device_id, self.mobile_device_id)
        } else {
            (self.mobile_device_id, self.desktop_device_id)
        };
        SessionCipher::new_zeroizing(
            self.session_id,
            local_device_id,
            remote_device_id,
            self.session_key,
            self.expires_at,
        )
    }

    pub fn validate_at(&self, registry: &DeviceRegistry, now: u64) -> CompanionResult<()> {
        if now >= self.expires_at {
            return Err(CompanionError::InvalidSession);
        }
        current_record(
            registry,
            &self.desktop_device_id,
            &self.agent_wallet_id,
            DeviceRole::Desktop,
            Some(self.desktop_authorization_epoch),
            None,
        )?;
        current_record(
            registry,
            &self.mobile_device_id,
            &self.agent_wallet_id,
            DeviceRole::Mobile,
            Some(self.mobile_authorization_epoch),
            None,
        )?;
        Ok(())
    }
}

fn response_matches(
    response: &SessionResponse,
    challenge: &SessionChallenge,
) -> CompanionResult<()> {
    if response.protocol_version != challenge.protocol_version
        || response.session_id != challenge.session_id
        || response.agent_wallet_id != challenge.agent_wallet_id
        || response.desktop_device_id != challenge.desktop_device_id
        || response.desktop_authorization_epoch != challenge.desktop_authorization_epoch
        || response.desktop_identity_fingerprint != challenge.desktop_identity_fingerprint
        || response.mobile_device_id != challenge.mobile_device_id
        || response.mobile_authorization_epoch != challenge.mobile_authorization_epoch
        || response.mobile_identity_fingerprint != challenge.mobile_identity_fingerprint
        || response.challenge_commitment != challenge.commitment()?
        // The phone stamps `issued_at` with its own clock, so this compares two
        // clocks and carries the same bounded, forward-only budget the rest of
        // the crate gives that comparison. A phone a second behind its desktop
        // is not answering before it was asked; it is a phone a second behind.
        // The binding of this response to this challenge is `challenge_commitment`
        // above - a SHA-256 over the whole signed challenge - not this ordering.
        || challenge.issued_at.saturating_sub(response.issued_at) > MAX_CLOCK_SKEW_SECS
        || response.expires_at != challenge.expires_at
    {
        return Err(CompanionError::InvalidSession);
    }
    Ok(())
}
