use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::desktop::EstablishedSession;
use super::kdf::{
    decode_public, derive_session_key, diffie_hellman, ephemeral_public, random_secret,
};
use super::types::{
    SESSION_PROTOCOL_VERSION, SessionChallenge, SessionConfirmation, SessionResponse,
};
use super::validation::{NONCE_BYTES, current_record, signer_matches};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceRegistry, DeviceRole, DeviceSignaturePurpose, PlatformDeviceSigner, sign_with_platform,
};
use crate::replay::{MAX_CLOCK_SKEW_SECS, ReplayGuard};

pub struct MobileSessionAttempt {
    challenge: SessionChallenge,
    response: SessionResponse,
    ephemeral_secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for MobileSessionAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MobileSessionAttempt")
            .field("session_id", &self.challenge.session_id)
            .field("desktop_device_id", &self.challenge.desktop_device_id)
            .field("mobile_device_id", &self.challenge.mobile_device_id)
            .field("ephemeral_secret", &"<memory-only>")
            .finish()
    }
}

impl MobileSessionAttempt {
    pub async fn respond(
        challenge: SessionChallenge,
        mobile_signer: &dyn PlatformDeviceSigner,
        registry: &DeviceRegistry,
        replay_guard: &mut ReplayGuard,
        response_sequence: u64,
        now: u64,
    ) -> CompanionResult<Self> {
        challenge.validate_at(now)?;
        let desktop_record = current_record(
            registry,
            &challenge.desktop_device_id,
            &challenge.agent_wallet_id,
            DeviceRole::Desktop,
            Some(challenge.desktop_authorization_epoch),
            Some(&challenge.desktop_identity_fingerprint),
        )?;
        let mobile_record = current_record(
            registry,
            &challenge.mobile_device_id,
            &challenge.agent_wallet_id,
            DeviceRole::Mobile,
            Some(challenge.mobile_authorization_epoch),
            Some(&challenge.mobile_identity_fingerprint),
        )?;
        signer_matches(mobile_signer, mobile_record, DeviceRole::Mobile)?;
        desktop_record.verify_signature(
            DeviceSignaturePurpose::SessionChallenge,
            &challenge.unsigned_bytes()?,
            &challenge.desktop_identity_signature,
        )?;
        let replay_permit = replay_guard.check(&challenge.replay_metadata(), now)?;

        let ephemeral_secret = random_secret();
        let ephemeral_public = ephemeral_public(&ephemeral_secret);
        let desktop_ephemeral = decode_public(&challenge.desktop_ephemeral_public_key)?;
        diffie_hellman(&ephemeral_secret, &desktop_ephemeral)?;
        let mut response_nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut response_nonce);
        let mut response = SessionResponse {
            protocol_version: SESSION_PROTOCOL_VERSION,
            session_id: challenge.session_id.clone(),
            agent_wallet_id: challenge.agent_wallet_id.clone(),
            desktop_device_id: challenge.desktop_device_id.clone(),
            desktop_authorization_epoch: challenge.desktop_authorization_epoch,
            desktop_identity_fingerprint: challenge.desktop_identity_fingerprint.clone(),
            mobile_device_id: challenge.mobile_device_id.clone(),
            mobile_authorization_epoch: challenge.mobile_authorization_epoch,
            mobile_identity_fingerprint: challenge.mobile_identity_fingerprint.clone(),
            challenge_commitment: challenge.commitment()?,
            mobile_ephemeral_public_key: hex::encode(ephemeral_public.as_bytes()),
            response_sequence,
            response_nonce: hex::encode(response_nonce),
            issued_at: now,
            expires_at: challenge.expires_at,
            mobile_identity_signature: String::new(),
        };
        response.validate_unsigned_shape()?;
        response.mobile_identity_signature = sign_with_platform(
            mobile_signer,
            DeviceSignaturePurpose::SessionResponse,
            &response.unsigned_bytes()?,
        )
        .await?;
        replay_guard.commit(replay_permit, now)?;
        Ok(Self {
            challenge,
            response,
            ephemeral_secret,
        })
    }

    pub fn response(&self) -> &SessionResponse {
        &self.response
    }

    pub fn verify_confirmation(
        self,
        confirmation: &SessionConfirmation,
        registry: &DeviceRegistry,
        now: u64,
    ) -> CompanionResult<EstablishedSession> {
        self.challenge.validate_at(now)?;
        self.response.validate_at(now)?;
        confirmation.validate_at(now)?;
        confirmation_matches(confirmation, &self.challenge, &self.response)?;
        let desktop_record = current_record(
            registry,
            &self.challenge.desktop_device_id,
            &self.challenge.agent_wallet_id,
            DeviceRole::Desktop,
            Some(self.challenge.desktop_authorization_epoch),
            Some(&self.challenge.desktop_identity_fingerprint),
        )?;
        current_record(
            registry,
            &self.challenge.mobile_device_id,
            &self.challenge.agent_wallet_id,
            DeviceRole::Mobile,
            Some(self.challenge.mobile_authorization_epoch),
            Some(&self.challenge.mobile_identity_fingerprint),
        )?;
        desktop_record.verify_signature(
            DeviceSignaturePurpose::SessionConfirmation,
            &confirmation.unsigned_bytes()?,
            &confirmation.desktop_identity_signature,
        )?;
        let desktop_ephemeral = decode_public(&self.challenge.desktop_ephemeral_public_key)?;
        let shared_secret = diffie_hellman(&self.ephemeral_secret, &desktop_ephemeral)?;
        let session_key = derive_session_key(
            &shared_secret,
            &self.challenge,
            &self.response,
            confirmation,
        )?;
        Ok(EstablishedSession::new(&self.challenge, session_key))
    }
}

fn confirmation_matches(
    confirmation: &SessionConfirmation,
    challenge: &SessionChallenge,
    response: &SessionResponse,
) -> CompanionResult<()> {
    if confirmation.protocol_version != challenge.protocol_version
        || confirmation.session_id != challenge.session_id
        || confirmation.agent_wallet_id != challenge.agent_wallet_id
        || confirmation.desktop_device_id != challenge.desktop_device_id
        || confirmation.desktop_authorization_epoch != challenge.desktop_authorization_epoch
        || confirmation.desktop_identity_fingerprint != challenge.desktop_identity_fingerprint
        || confirmation.mobile_device_id != challenge.mobile_device_id
        || confirmation.mobile_authorization_epoch != challenge.mobile_authorization_epoch
        || confirmation.mobile_identity_fingerprint != challenge.mobile_identity_fingerprint
        || confirmation.challenge_commitment != challenge.commitment()?
        || confirmation.response_commitment != response.commitment()?
        // Same two-clock comparison as `response_matches`, in the other
        // direction: this one refuses a phone whose clock runs ahead of its
        // desktop's. `response_commitment` above is what binds the confirmation
        // to this response.
        || response.issued_at.saturating_sub(confirmation.issued_at) > MAX_CLOCK_SKEW_SECS
        || confirmation.expires_at != challenge.expires_at
    {
        return Err(CompanionError::InvalidSession);
    }
    Ok(())
}
