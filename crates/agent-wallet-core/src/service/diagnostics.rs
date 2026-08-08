use crate::diagnostics::{
    AgentPilotDiagnostics, AgentPilotDiagnosticsPreview, DIAGNOSTIC_SCHEMA_VERSION, MAX_ITEMS,
    diagnostics_sha256, operation_status_name, phase_name, redact_identifier,
};
use crate::error::AgentWalletResult;
use crate::node_binding::verified_agent_node;
use crate::types::AgentWalletId;

use super::AgentWalletManager;

impl AgentWalletManager {
    pub async fn pilot_diagnostics_preview(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<AgentPilotDiagnosticsPreview> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let node = verified_agent_node(
            &state.node_url,
            &state.network_mode,
            &state.block_one_fingerprint,
        )
        .await?;
        let witness = state.rollback_witness.as_ref();
        let mut anchor_phases = witness
            .into_iter()
            .flat_map(|value| value.history.iter())
            .map(|completed| phase_name(completed.proposal.anchor.operation_phase).to_owned())
            .collect::<Vec<_>>();
        if let Some(pending) = witness.and_then(|value| value.pending.as_ref()) {
            anchor_phases.push(phase_name(pending.proposal.anchor.operation_phase).to_owned());
        }
        anchor_phases.truncate(MAX_ITEMS);
        let mut operation_states = state
            .operations
            .values()
            .map(|operation| operation_status_name(operation.status()).to_owned())
            .collect::<Vec<_>>();
        operation_states.sort();
        operation_states.truncate(MAX_ITEMS);
        let mut transaction_ids = state
            .operations
            .values()
            .filter_map(|operation| operation.view().tx_hash)
            .collect::<Vec<_>>();
        transaction_ids.sort();
        transaction_ids.dedup();
        transaction_ids.truncate(MAX_ITEMS);
        let mut agent_ids_redacted = state
            .agents
            .keys()
            .map(|value| redact_identifier("agent", value))
            .collect::<Vec<_>>();
        agent_ids_redacted.sort();
        agent_ids_redacted.truncate(MAX_ITEMS);
        let diagnostics = AgentPilotDiagnostics {
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            pilot_protocol_version: "witness-v2-rotation-v1".to_owned(),
            platform: std::env::consts::OS.to_owned(),
            build_profile: if cfg!(debug_assertions) {
                "debug".to_owned()
            } else {
                "release".to_owned()
            },
            network_id: node.network_kind().to_owned(),
            node_profile_id: node.node_profile_id().to_owned(),
            node_capability_summary: vec![
                "hacash-fullnode=1.0.10".to_owned(),
                format!("network_instance_id={}", node.network_instance_id()),
                "transaction_type=2".to_owned(),
                "action_kind=1".to_owned(),
                "wallet_fee_units=0".to_owned(),
                "agent_l2=disabled".to_owned(),
                "hip20_send=disabled".to_owned(),
                "mainnet_send=disabled".to_owned(),
            ],
            agent_wallet_id_redacted: redact_identifier("wallet", wallet_id.as_str()),
            agent_ids_redacted,
            desktop_device_id_redacted: redact_identifier(
                "desktop",
                &state.primary_signing_device_id,
            ),
            mobile_device_id_redacted: witness
                .map(|value| redact_identifier("mobile", value.mobile_device_id.as_str())),
            witness_epoch: witness.map(|value| value.witness_epoch),
            signer_epoch: state.signer_epoch,
            journal_epoch: 1,
            journal_sequence: state.journal_sequence,
            anchor_sequence: witness.map(|value| value.last_anchor_sequence),
            anchor_phases,
            witness_rotation_phase: state
                .witness_rotation
                .as_ref()
                .map(|rotation| rotation.phase),
            operation_states,
            typed_error_codes: Vec::new(),
            public_transaction_ids: transaction_ids,
            build_hashes: Vec::new(),
            artifact_hashes: Vec::new(),
            test_execution_summary: Vec::new(),
            state_updated_at: state.updated_at,
        };
        let preview_sha256 = diagnostics_sha256(&diagnostics)?;
        Ok(AgentPilotDiagnosticsPreview {
            categories: vec![
                "build_and_platform".to_owned(),
                "network_capabilities".to_owned(),
                "redacted_identifiers".to_owned(),
                "witness_and_rotation_epochs".to_owned(),
                "operation_state_names".to_owned(),
                "public_transaction_ids".to_owned(),
            ],
            excluded_categories: vec![
                "private_keys_and_seeds".to_owned(),
                "passphrases_and_vault_plaintext".to_owned(),
                "journal_and_vault_keys".to_owned(),
                "device_and_session_private_keys".to_owned(),
                "pairing_secrets_and_tokens".to_owned(),
                "raw_transactions_and_signatures".to_owned(),
                "ai_prompts".to_owned(),
                "filesystem_paths".to_owned(),
            ],
            diagnostics,
            preview_sha256,
        })
    }
}
