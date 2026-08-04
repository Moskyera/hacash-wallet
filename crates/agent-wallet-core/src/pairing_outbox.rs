use std::fmt;

use hpay_agent_connector::{
    PAIRING_COMPLETION_TTL_SECS, PairingCompletionRequest, PairingSubmissionCommitment,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentRecord, AgentWalletError, AgentWalletResult};

pub(crate) const MAX_PAIRING_COMPLETION_OUTBOX_ENTRIES: usize = 8;
const PAIRING_ID_HASH_DOMAIN: &[u8] = b"HPAY/AGENT-PAIRING/OUTBOX-KEY/V1";

/// Durable authorization material needed to recover pairing completion after
/// a process restart. The raw bearer pairing id is never stored.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingCompletionOutboxEntry {
    pairing_id_sha256: String,
    submission_commitment: PairingSubmissionCommitment,
    record: AgentRecord,
    expires_at_unix: u64,
}

impl PairingCompletionOutboxEntry {
    pub(crate) fn new(
        pairing_id: &str,
        submission_commitment: PairingSubmissionCommitment,
        record: AgentRecord,
        expires_at_unix: u64,
    ) -> AgentWalletResult<Self> {
        submission_commitment
            .validate()
            .map_err(|_| AgentWalletError::AgentAuthenticationFailed)?;
        let entry = Self {
            pairing_id_sha256: pairing_id_sha256(pairing_id)?,
            submission_commitment,
            record,
            expires_at_unix,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn submission_commitment(&self) -> &PairingSubmissionCommitment {
        &self.submission_commitment
    }

    pub fn record(&self) -> &AgentRecord {
        &self.record
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub(crate) fn pairing_id_sha256(&self) -> &str {
        &self.pairing_id_sha256
    }

    pub(crate) fn matches_request(
        &self,
        request: &PairingCompletionRequest,
        now_unix: u64,
    ) -> AgentWalletResult<()> {
        request
            .verify_identity_proof()
            .map_err(|_| AgentWalletError::AgentAuthenticationFailed)?;
        if now_unix < self.record.paired_at || now_unix >= self.expires_at_unix {
            return Err(AgentWalletError::RequestExpired);
        }
        if pairing_id_sha256(request.pairing_id())? != self.pairing_id_sha256
            || request.submission_commitment() != &self.submission_commitment
            || request.identity_public_key_sec1_hex != self.record.identity_public_key_sec1
        {
            return Err(AgentWalletError::AgentAuthenticationFailed);
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> AgentWalletResult<()> {
        self.submission_commitment
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if !is_lower_sha256(&self.pairing_id_sha256)
            || self.record.paired_at == 0
            || self.expires_at_unix <= self.record.paired_at
            || self.expires_at_unix - self.record.paired_at > PAIRING_COMPLETION_TTL_SECS
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }
}

impl fmt::Debug for PairingCompletionOutboxEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCompletionOutboxEntry")
            .field("pairing_id", &"[HASHED]")
            .field("submission_commitment", &self.submission_commitment)
            .field("agent_id", &self.record.agent_id)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

pub(crate) fn pairing_id_sha256(pairing_id: &str) -> AgentWalletResult<String> {
    let suffix = pairing_id
        .strip_prefix("pair_")
        .ok_or(AgentWalletError::InvalidIdentifier)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AgentWalletError::InvalidIdentifier);
    }
    let mut hasher = Sha256::new();
    hasher.update(PAIRING_ID_HASH_DOMAIN);
    hasher.update((pairing_id.len() as u64).to_be_bytes());
    hasher.update(pairing_id.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpay_agent_connector::{
        AgentIdentityKey, Capability, PairingBearer, PairingRequest, ServerIdentityKey,
    };

    use crate::{
        AgentId, AgentPermission, AgentPolicy, AgentStatus, AgentWalletId, ApprovalMode, HacUnits,
        WalletScope,
    };

    #[test]
    fn outbox_key_is_domain_separated_and_debug_redacts_the_bearer() {
        let pairing_id = format!("pair_{}", "ab".repeat(32));
        let identity = AgentIdentityKey::generate();
        let request = PairingRequest {
            pairing_id: PairingBearer::parse(pairing_id.clone()).unwrap(),
            agent_name: "Local Assistant".into(),
            agent_version: "1.0.0".into(),
            identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
            requested_capabilities: [Capability::ReadBalance].into_iter().collect(),
        };
        let commitment = request.submission_commitment().unwrap();
        let wallet_id = AgentWalletId::new();
        let record = AgentRecord {
            agent_id: AgentId::new(),
            wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
            name: request.agent_name.clone(),
            version: request.agent_version.clone(),
            identity_public_key_sec1: request.identity_public_key_sec1_hex.clone(),
            identity_fingerprint: identity.fingerprint(),
            identity_key_sha256: "cd".repeat(32),
            server_identity: ServerIdentityKey::generate()
                .pinned_identity(format!("desktop_{}", "12".repeat(16)))
                .unwrap(),
            status: AgentStatus::Active,
            authorization_epoch: 1,
            policy: AgentPolicy {
                permissions: [AgentPermission::ReadBalance].into_iter().collect(),
                max_per_payment_units: HacUnits::ZERO,
                max_daily_units: HacUnits::ZERO,
                max_pending_operations: 0,
                allowed_recipients: Default::default(),
                blocked_recipients: Default::default(),
                approval_mode: ApprovalMode::DesktopManual,
                policy_epoch: 1,
            },
            paired_at: 100,
        };
        let entry =
            PairingCompletionOutboxEntry::new(&pairing_id, commitment, record, 220).unwrap();
        let debug = format!("{entry:?}");
        assert_ne!(pairing_id_sha256(&pairing_id).unwrap(), &pairing_id[5..]);
        assert!(!debug.contains(&pairing_id));
        assert!(debug.contains("[HASHED]"));
        assert!(
            pairing_id_sha256(&pairing_id)
                .unwrap()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }
}
