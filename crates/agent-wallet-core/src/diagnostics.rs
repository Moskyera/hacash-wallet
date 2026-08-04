//! Explicit, local-only diagnostics for the strict Agent Wallet testnet pilot.
//!
//! The model is an allowlist. It has no generic log, path, environment, vault,
//! transaction-body, signature, prompt, token, or secret fields.

use std::path::{Path, PathBuf};

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::RollbackOperationPhase;
use hpay_companion_protocol::WitnessRotationPhase;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AgentWalletError, AgentWalletResult};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use crate::operation::OperationStatus;

#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;
const MAX_DIAGNOSTIC_BYTES: usize = 256 * 1024;
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) const MAX_ITEMS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPilotDiagnostics {
    pub schema_version: u64,
    pub application_version: String,
    pub pilot_protocol_version: String,
    pub platform: String,
    pub build_profile: String,
    pub network_id: String,
    pub node_profile_id: String,
    pub node_capability_summary: Vec<String>,
    pub agent_wallet_id_redacted: String,
    pub agent_ids_redacted: Vec<String>,
    pub desktop_device_id_redacted: String,
    pub mobile_device_id_redacted: Option<String>,
    pub witness_epoch: Option<u64>,
    pub signer_epoch: u64,
    pub journal_epoch: u64,
    pub journal_sequence: u64,
    pub anchor_sequence: Option<u64>,
    pub anchor_phases: Vec<String>,
    pub witness_rotation_phase: Option<WitnessRotationPhase>,
    pub operation_states: Vec<String>,
    pub typed_error_codes: Vec<String>,
    pub public_transaction_ids: Vec<String>,
    pub build_hashes: Vec<String>,
    pub artifact_hashes: Vec<String>,
    pub test_execution_summary: Vec<String>,
    pub state_updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPilotDiagnosticsPreview {
    pub categories: Vec<String>,
    pub excluded_categories: Vec<String>,
    pub diagnostics: AgentPilotDiagnostics,
    pub preview_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPilotDiagnosticsExport {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

pub fn export_pilot_diagnostics(
    preview: &AgentPilotDiagnosticsPreview,
    expected_preview_sha256: &str,
    path: &Path,
) -> AgentWalletResult<AgentPilotDiagnosticsExport> {
    if preview.preview_sha256 != expected_preview_sha256
        || diagnostics_sha256(&preview.diagnostics)? != expected_preview_sha256
    {
        return Err(AgentWalletError::DiagnosticConfirmationMismatch);
    }
    if path.extension().and_then(|value| value.to_str()) != Some("json") || path.exists() {
        return Err(AgentWalletError::PersistenceFailed);
    }
    let bytes = serde_json::to_vec_pretty(&preview.diagnostics)
        .map_err(|_| AgentWalletError::PersistenceFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(AgentWalletError::DiagnosticTooLarge);
    }
    hacash_wallet_core::paths::secure_write(path, &bytes)
        .map_err(|_| AgentWalletError::PersistenceFailed)?;
    let written = std::fs::read(path).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if written != bytes {
        return Err(AgentWalletError::PersistenceFailed);
    }
    Ok(AgentPilotDiagnosticsExport {
        path: path.to_path_buf(),
        size_bytes: bytes
            .len()
            .try_into()
            .map_err(|_| AgentWalletError::IntegerOverflow)?,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

pub(crate) fn diagnostics_sha256(value: &AgentPilotDiagnostics) -> AgentWalletResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if bytes.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(AgentWalletError::DiagnosticTooLarge);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(any(feature = "agent-wallet-testnet-pilot", test))]
pub(crate) fn redact_identifier(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"HPAY/AGENT/DIAGNOSTIC-REDACTION/V1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{domain}_{}", &digest[..16])
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) fn phase_name(phase: RollbackOperationPhase) -> &'static str {
    match phase {
        RollbackOperationPhase::WalletState => "wallet_state",
        RollbackOperationPhase::SignedAwaitingWitness => "signed_awaiting_witness_legacy",
        RollbackOperationPhase::WitnessedAwaitingBroadcast => "witnessed_awaiting_broadcast",
        RollbackOperationPhase::BroadcastUncertain => "broadcast_uncertain",
        RollbackOperationPhase::Committed => "committed_legacy",
        RollbackOperationPhase::RecoveryRequired => "recovery_required",
        RollbackOperationPhase::SignedPreBroadcast => "signed_pre_broadcast",
        RollbackOperationPhase::Submitted => "submitted",
        RollbackOperationPhase::ReconciledFinal => "reconciled_final",
    }
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) fn operation_status_name(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::PaymentIntentCreated => "payment_intent_created",
        OperationStatus::FundsReserved => "funds_reserved",
        OperationStatus::UnsignedTransactionPersisted => "unsigned_transaction_persisted",
        OperationStatus::ApprovalRequested => "approval_requested",
        OperationStatus::Approved => "approved",
        OperationStatus::Rejected => "rejected",
        OperationStatus::Signed => "signed",
        OperationStatus::SignedAwaitingWitness => "signed_awaiting_witness",
        OperationStatus::WitnessedAwaitingBroadcast => "witnessed_awaiting_broadcast",
        OperationStatus::BroadcastSubmitted => "broadcast_submitted",
        OperationStatus::BroadcastUncertain => "broadcast_uncertain",
        OperationStatus::SubmittedAwaitingFinalWitness => "submitted_awaiting_final_witness",
        OperationStatus::ReconciliationRequired => "reconciliation_required",
        OperationStatus::ReconciledAwaitingFinalWitness => "reconciled_awaiting_final_witness",
        OperationStatus::Committed => "committed",
        OperationStatus::Failed => "failed",
        OperationStatus::Cancelled => "cancelled",
        OperationStatus::RecoveryRequired => "recovery_required",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_is_deterministic_bounded_and_domain_separated() {
        let wallet = redact_identifier("wallet", "secret-id");
        assert_eq!(wallet, redact_identifier("wallet", "secret-id"));
        assert_ne!(wallet, redact_identifier("agent", "secret-id"));
        assert!(!wallet.contains("secret-id"));
        assert_eq!(wallet.len(), "wallet_".len() + 16);
    }

    #[test]
    fn export_rejects_changed_confirmation_and_contains_no_secret_markers() {
        let diagnostics = AgentPilotDiagnostics {
            schema_version: 1,
            application_version: "test".to_owned(),
            pilot_protocol_version: "test".to_owned(),
            platform: "test".to_owned(),
            build_profile: "test".to_owned(),
            network_id: "testnet".to_owned(),
            node_profile_id: "11".repeat(32),
            node_capability_summary: vec!["wallet_fee_units=0".to_owned()],
            agent_wallet_id_redacted: redact_identifier("wallet", "TEST_PRIVATE_KEY_MARKER"),
            agent_ids_redacted: vec![redact_identifier("agent", "TEST_PASSPHRASE_MARKER")],
            desktop_device_id_redacted: redact_identifier("desktop", "TEST_SESSION_SECRET_MARKER"),
            mobile_device_id_redacted: Some(redact_identifier("mobile", "TEST_SIGNED_BODY_MARKER")),
            witness_epoch: Some(1),
            signer_epoch: 1,
            journal_epoch: 1,
            journal_sequence: 1,
            anchor_sequence: Some(0),
            anchor_phases: Vec::new(),
            witness_rotation_phase: None,
            operation_states: Vec::new(),
            typed_error_codes: Vec::new(),
            public_transaction_ids: Vec::new(),
            build_hashes: Vec::new(),
            artifact_hashes: Vec::new(),
            test_execution_summary: Vec::new(),
            state_updated_at: 1,
        };
        let hash = diagnostics_sha256(&diagnostics).unwrap();
        let preview = AgentPilotDiagnosticsPreview {
            categories: vec!["redacted_identifiers".to_owned()],
            excluded_categories: vec!["secrets".to_owned()],
            diagnostics,
            preview_sha256: hash.clone(),
        };
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("diagnostics.json");
        assert_eq!(
            export_pilot_diagnostics(&preview, &"00".repeat(32), &path),
            Err(AgentWalletError::DiagnosticConfirmationMismatch)
        );
        let result = export_pilot_diagnostics(&preview, &hash, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(result.sha256, hex::encode(Sha256::digest(&bytes)));
        for marker in [
            "TEST_PRIVATE_KEY_MARKER",
            "TEST_PASSPHRASE_MARKER",
            "TEST_SESSION_SECRET_MARKER",
            "TEST_SIGNED_BODY_MARKER",
        ] {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
        }
        assert_eq!(
            export_pilot_diagnostics(&preview, &hash, &path),
            Err(AgentWalletError::PersistenceFailed),
            "diagnostic export must never replace an existing user file"
        );
        assert_eq!(
            export_pilot_diagnostics(&preview, &hash, &root.path().join("diagnostics.txt")),
            Err(AgentWalletError::PersistenceFailed),
            "diagnostic export is restricted to explicit JSON files"
        );
    }
}
