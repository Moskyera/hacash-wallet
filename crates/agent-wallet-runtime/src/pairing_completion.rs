use agent_wallet_core::{AgentWalletId, PairingCompletionOutboxEntry};
use hpay_agent_connector::{
    ConnectorError, PairingCompletionReceipt, PairingCompletionRequest, ServerIdentityKey,
};

use crate::error::{RuntimeError, RuntimeResult};

pub(crate) struct ApprovedPairingCompletion {
    persisted: PairingCompletionOutboxEntry,
}

impl ApprovedPairingCompletion {
    pub(crate) const fn new(persisted: PairingCompletionOutboxEntry) -> Self {
        Self { persisted }
    }

    pub(crate) fn complete(
        &self,
        request: &PairingCompletionRequest,
        wallet_id: &AgentWalletId,
        server_identity_key: &ServerIdentityKey,
        now_unix: u64,
    ) -> RuntimeResult<PairingCompletionReceipt> {
        let record = self.persisted.record();
        if now_unix < record.paired_at || now_unix >= self.persisted.expires_at_unix() {
            return Err(ConnectorError::Expired.into());
        }
        request.verify_identity_proof()?;
        if request.submission_commitment() != self.persisted.submission_commitment()
            || request.identity_public_key_sec1_hex != record.identity_public_key_sec1
        {
            return Err(ConnectorError::AuthenticationFailed.into());
        }
        PairingCompletionReceipt::signed(
            request,
            record.agent_id.clone(),
            wallet_id.clone(),
            record.wallet_scope.clone(),
            record.policy.permissions.clone(),
            record.authorization_epoch,
            record.paired_at,
            record.paired_at,
            self.persisted.expires_at_unix(),
            record.server_identity.clone(),
            server_identity_key,
        )
        .map_err(RuntimeError::from)
    }
}
