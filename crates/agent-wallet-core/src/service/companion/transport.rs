//! Durable replay admission for authenticated encrypted companion frames.
//!
//! This primitive consumes only the outer encrypted-frame replay metadata. It
//! intentionally executes no message action: sensitive signed actions retain
//! their own independently persisted authorization and replay transitions.

use hpay_companion_protocol::{DeviceId, DeviceRole, ReplayMetadata};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::types::AgentWalletId;

use super::{AgentWalletManager, map_companion_replay_error};

const ENCRYPTED_FRAME_CONTEXT_PREFIX: &str = "encrypted_frame:";

impl AgentWalletManager {
    /// Durably consumes one authenticated mobile encrypted-frame replay token.
    ///
    /// The transport must call this only after decrypting and authenticating
    /// the frame. Success means the exact replay snapshot was committed to the
    /// authenticated Agent Wallet journal; it does not authorize or execute
    /// the contained message.
    pub fn consume_companion_transport_replay(
        &mut self,
        wallet_id: &AgentWalletId,
        authenticated_mobile_device_id: &DeviceId,
        metadata: &ReplayMetadata,
        now: u64,
    ) -> AgentWalletResult<()> {
        if metadata.sender_device_id != *authenticated_mobile_device_id
            || metadata
                .context
                .strip_prefix(ENCRYPTED_FRAME_CONTEXT_PREFIX)
                .is_none_or(|session_id| session_id.is_empty())
        {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }

        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let emergency = self.emergency_controller(wallet_id)?;
        let safety = emergency.issue_connectivity_permit()?;
        let companion = state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        companion.validate(wallet_id, now)?;
        let active_mobile = companion
            .device_registry
            .records()
            .find(|record| record.device_id == *authenticated_mobile_device_id)
            .ok_or(AgentWalletError::CompanionAuthorizationFailed)?;
        if active_mobile.role != DeviceRole::Mobile
            || active_mobile.agent_wallet_id != wallet_id.as_str()
            || active_mobile.authorization_epoch == 0
            || active_mobile.is_revoked()
        {
            return Err(AgentWalletError::CompanionAuthorizationFailed);
        }

        let mut replay = companion.replay_guard(now)?;
        let permit = replay
            .check(metadata, now)
            .map_err(map_companion_replay_error)?;
        safety.checkpoint()?;
        let replay_snapshot = replay
            .commit_and_snapshot(permit, now)
            .map_err(map_companion_replay_error)?;
        state
            .companion_security
            .as_mut()
            .ok_or(AgentWalletError::RecoveryRequired)?
            .replay_guard = replay_snapshot;
        state.updated_at = now;
        safety.checkpoint()?;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::CompanionTransportFrameConsumed,
            None,
            Some(authenticated_mobile_device_id.as_str().as_bytes()),
            now,
        )?;
        safety.checkpoint()
    }
}
