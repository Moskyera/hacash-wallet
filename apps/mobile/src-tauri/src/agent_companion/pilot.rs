//! Explicit Android-only commands for the strict Agent Wallet testnet pilot.
//!
//! The mobile device signs only exact approval decisions and rollback witness
//! receipts. It never receives a wallet key or a signed transaction body.

use hpay_companion_protocol::{
    ApprovalCommitment, ApprovalDecision, SignedRollbackAnchor, WitnessRotationPhase,
};
#[cfg(target_os = "android")]
use hpay_companion_protocol::{
    CompanionPayload, DevicePermission, MobileApprovalDecision, MobileWitnessState,
    RollbackOperationPhase, SignedApprovalDecision, SignedWitnessReceipt,
    SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
    WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationRecord,
};
use serde::{Deserialize, Serialize};
use tauri::Webview;

use super::AgentCompanionMobileState;
use super::commands::require_agent_companion_webview;
#[cfg(target_os = "android")]
use super::storage::MobilePendingApproval;
#[cfg(target_os = "android")]
use super::unix_now;

#[cfg(any(target_os = "android", test))]
const AGENT_NETWORK_FEE_UNITS: u64 = 1_000;

#[cfg(target_os = "android")]
enum PreparedPilotDecision {
    Fresh(SignedApprovalDecision),
    PendingRecovery,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionPilotDecisionRequest {
    commitment: ApprovalCommitment,
    decision: ApprovalDecision,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionPilotDecisionView {
    operation_id: String,
    approved: bool,
    witnessed: bool,
    anchor_id: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionWitnessView {
    anchor_id: String,
    accepted: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionRotationView {
    rotation_id: String,
    phase: WitnessRotationPhase,
    detail: String,
}

fn require_pilot_enabled() -> Result<(), String> {
    if cfg!(feature = "agent-wallet-testnet-pilot") {
        Ok(())
    } else {
        Err("Agent Wallet testnet pilot is disabled in this build".to_owned())
    }
}

#[cfg(target_os = "android")]
impl AgentCompanionMobileState {
    async fn persist_rotation_phase(
        &self,
        phase: WitnessRotationPhase,
        clear_authorization: bool,
        clear_baseline: bool,
    ) -> Result<(), String> {
        let mut slot = self.shared.state.lock().await;
        let mut next = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?
            .clone();
        next.rotation_phase = phase;
        if clear_authorization {
            next.pending_rotation_authorization = None;
        }
        if clear_baseline {
            next.pending_rotation_baseline = None;
        }
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }

    async fn sign_rotation_authorization(
        &self,
        app: &tauri::AppHandle,
        rotation: &WitnessRotationRecord,
    ) -> Result<SignedWitnessRotationAuthorization, String> {
        let now = unix_now()?;
        {
            let slot = self.shared.state.lock().await;
            let current = slot
                .as_ref()
                .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?;
            current.validate_at(now)?;
            rotation
                .validate_at(now)
                .map_err(|error| error.to_string())?;
            if rotation.rotation_mode != WitnessRotationMode::Normal
                || rotation.agent_wallet_id != current.agent_wallet_id
                || rotation.desktop_device_id != current.desktop_device_id
                || rotation.old_mobile_device_id != current.mobile_device_id
            {
                return Err("Witness rotation does not match the old approval phone".to_owned());
            }
            if let Some(existing) = &current.pending_rotation_authorization {
                if existing.rotation != *rotation {
                    return Err("A different witness rotation is pending".to_owned());
                }
                return Ok(existing.clone());
            }
        }
        let signer = crate::agent_companion_identity::open(app)
            .await?
            .ok_or_else(|| "Android companion identity is not configured".to_owned())?;
        let signed = SignedWitnessRotationAuthorization::sign(rotation.clone(), &signer)
            .await
            .map_err(|error| error.to_string())?;
        let mut slot = self.shared.state.lock().await;
        let mut next = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?
            .clone();
        if next.mobile_device_id != rotation.old_mobile_device_id {
            return Err("Witness rotation phone changed during authorization".to_owned());
        }
        next.rotation_phase = WitnessRotationPhase::AwaitingOldWitnessAuthorization;
        next.pending_rotation_authorization = Some(signed.clone());
        next.pending_rotation_baseline = None;
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(signed)
    }

    async fn sign_rotation_baseline(
        &self,
        app: &tauri::AppHandle,
        rotation: &WitnessRotationRecord,
    ) -> Result<SignedWitnessRotationBaselineReceipt, String> {
        let now = unix_now()?;
        {
            let slot = self.shared.state.lock().await;
            let current = slot
                .as_ref()
                .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?;
            current.validate_at(now)?;
            rotation
                .validate_at(now)
                .map_err(|error| error.to_string())?;
            if rotation.agent_wallet_id != current.agent_wallet_id
                || rotation.desktop_device_id != current.desktop_device_id
                || rotation.new_mobile_device_id != current.mobile_device_id
            {
                return Err("Witness rotation does not match the replacement phone".to_owned());
            }
            if let Some(existing) = &current.pending_rotation_baseline {
                if existing.receipt.rotation_id != rotation.rotation_id
                    || existing.receipt.rotation_hash
                        != rotation
                            .canonical_sha256_hex()
                            .map_err(|error| error.to_string())?
                {
                    return Err("A different witness rotation baseline is pending".to_owned());
                }
                return Ok(existing.clone());
            }
        }
        let receipt = WitnessRotationBaselineReceipt::for_rotation(
            rotation,
            rotation
                .canonical_sha256_hex()
                .map_err(|error| error.to_string())?,
            now,
        )
        .map_err(|error| error.to_string())?;
        let signer = crate::agent_companion_identity::open(app)
            .await?
            .ok_or_else(|| "Android companion identity is not configured".to_owned())?;
        let signed = SignedWitnessRotationBaselineReceipt::sign(receipt, &signer)
            .await
            .map_err(|error| error.to_string())?;
        let mut slot = self.shared.state.lock().await;
        let mut next = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?
            .clone();
        if next.mobile_device_id != rotation.new_mobile_device_id {
            return Err("Witness rotation phone changed during baseline signing".to_owned());
        }
        next.witness = Some(
            MobileWitnessState::from_rotation_baseline(rotation, &signed, &next.registry, now)
                .map_err(|error| error.to_string())?,
        );
        next.rotation_phase = WitnessRotationPhase::CandidateBaselineVerified;
        next.pending_rotation_authorization = None;
        next.pending_rotation_baseline = Some(signed.clone());
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(signed)
    }

    async fn sign_rotation_completion_witness(
        &self,
        app: &tauri::AppHandle,
        proposal: &SignedRollbackAnchor,
    ) -> Result<SignedWitnessReceipt, String> {
        let now = unix_now()?;
        let mut slot = self.shared.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before completing witness rotation".to_owned())?
            .clone();
        current.validate_at(now)?;
        proposal
            .verify(&current.registry, now)
            .map_err(|error| error.to_string())?;
        if proposal.anchor.operation_phase != RollbackOperationPhase::WalletState
            || proposal.anchor.last_operation_id.is_some()
            || proposal.anchor.transaction_state.is_some()
            || proposal.anchor.agent_wallet_id != current.agent_wallet_id
            || proposal.anchor.desktop_device_id != current.desktop_device_id
            || proposal.anchor.mobile_device_id != current.mobile_device_id
            || proposal.anchor.network_id != "testnet"
        {
            return Err("Rotation completion anchor scope is invalid".to_owned());
        }
        let mut next = current;
        let witness = next
            .witness
            .as_mut()
            .ok_or_else(|| "Replacement witness baseline is not durable".to_owned())?;
        let receipt = match witness.receipt_for_accepted_anchor(proposal, &next.registry, now) {
            Ok(receipt) => receipt,
            Err(_) => witness
                .accept_anchor(proposal, &next.registry, now)
                .map_err(|error| error.to_string())?,
        };
        next.rotation_phase = WitnessRotationPhase::AwaitingCompletionAnchor;
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        drop(slot);
        let signer = crate::agent_companion_identity::open(app)
            .await?
            .ok_or_else(|| "Android companion identity is not configured".to_owned())?;
        SignedWitnessReceipt::sign(receipt, &signer)
            .await
            .map_err(|error| error.to_string())
    }

    async fn finish_rotation_anchor(
        &self,
        app: tauri::AppHandle,
        proposal: SignedRollbackAnchor,
    ) -> Result<CompanionRotationView, String> {
        let rotation_id = self
            .shared
            .current()
            .await?
            .and_then(|state| state.pending_rotation_baseline)
            .map(|signed| signed.receipt.rotation_id)
            .ok_or_else(|| "Replacement witness baseline is not available".to_owned())?;
        let receipt = self
            .sign_rotation_completion_witness(&app, &proposal)
            .await?;
        let response = self
            .exchange_with_reconnect(app, super::session::OutboundKind::Witness(receipt))
            .await?;
        let CompanionPayload::WitnessAck {
            anchor_id,
            accepted,
            detail,
        } = response.payload
        else {
            return Err("Desktop returned an unexpected rotation completion response".to_owned());
        };
        if !accepted
            || anchor_id != proposal.anchor.anchor_id
            || detail != "witness_rotation_completed"
        {
            return Err("Desktop did not confirm the exact rotation completion anchor".to_owned());
        }
        self.persist_rotation_phase(WitnessRotationPhase::Completed, true, true)
            .await?;
        Ok(CompanionRotationView {
            rotation_id,
            phase: WitnessRotationPhase::Completed,
            detail,
        })
    }

    async fn sign_pilot_decision(
        &self,
        app: &tauri::AppHandle,
        request: CompanionPilotDecisionRequest,
    ) -> Result<PreparedPilotDecision, String> {
        let now = unix_now()?;
        request
            .commitment
            .validate_at(now)
            .map_err(|error| error.to_string())?;
        let binding = request
            .commitment
            .network_binding
            .as_ref()
            .ok_or_else(|| "Pilot approval requires an exact network binding".to_owned())?;
        if request.commitment.approval_version != 3
            || binding.network_id != "testnet"
            || binding.chain_id == 0
            || binding.transaction_format_version != 2
        {
            return Err("Pilot approval network binding is invalid".to_owned());
        }
        let commitment_hash = request
            .commitment
            .canonical_sha256_hex()
            .map_err(|error| error.to_string())?;
        let mut slot = self.shared.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before approving a payment".to_owned())?
            .clone();
        current.validate_at(now)?;
        if request.commitment.agent_wallet_id != current.agent_wallet_id
            || request.commitment.desktop_device_id != current.desktop_device_id
            || request.commitment.wallet_fee_units != 0
            || request.commitment.fee_units != AGENT_NETWORK_FEE_UNITS
        {
            return Err("Approval does not match this paired Agent Wallet".to_owned());
        }
        let permission = match request.decision {
            ApprovalDecision::Approve => DevicePermission::ApprovePayment,
            ApprovalDecision::Reject => DevicePermission::RejectPayment,
        };
        let mobile_authorization_epoch = current
            .registry
            .require(
                &current.mobile_device_id,
                &current.agent_wallet_id,
                hpay_companion_protocol::DeviceRole::Mobile,
                permission,
            )
            .map_err(|error| error.to_string())?
            .authorization_epoch;
        let mut next = current;
        let (decision, pending_recovery) = if let Some(pending) = &next.pending_approval {
            if pending.commitment_hash != commitment_hash
                || pending.decision.decision != request.decision
            {
                return Err("A different pilot approval is already pending recovery".to_owned());
            }
            (pending.decision.clone(), true)
        } else {
            let approval_sequence = next
                .approval_sequence
                .checked_add(1)
                .ok_or_else(|| "Mobile approval sequence is exhausted".to_owned())?;
            let decision = MobileApprovalDecision::from_commitment(
                &request.commitment,
                request.decision,
                next.mobile_device_id.clone(),
                mobile_authorization_epoch,
                approval_sequence,
                now,
            );
            next.approval_sequence = approval_sequence;
            next.pending_approval = Some(MobilePendingApproval {
                state_version: "1".to_owned(),
                commitment_hash,
                decision: decision.clone(),
            });
            // Consume the exact approval and monotonic sequence durably before
            // biometric signing or transport. An exact retry reuses this record.
            self.shared.persist_locked(&next)?;
            *slot = Some(next);
            (decision, false)
        };
        drop(slot);
        if pending_recovery {
            return Ok(PreparedPilotDecision::PendingRecovery);
        }
        let signer = crate::agent_companion_identity::open(app)
            .await?
            .ok_or_else(|| "Android companion identity is not configured".to_owned())?;
        match SignedApprovalDecision::sign(decision.clone(), &signer).await {
            Ok(signed) => Ok(PreparedPilotDecision::Fresh(signed)),
            Err(error) => {
                // No signed decision reached transport. Clear only this exact
                // unsigned recovery record so biometric cancellation can be retried
                // with a new monotonic sequence instead of wedging the companion.
                self.clear_pending_approval(&decision.operation_id)
                    .await
                    .map_err(|clear_error| {
                        format!(
                            "Biometric signing failed and approval recovery could not be cleared: {clear_error}"
                        )
                    })?;
                Err(error.to_string())
            }
        }
    }

    async fn sign_pilot_witness(
        &self,
        app: &tauri::AppHandle,
        proposal: &SignedRollbackAnchor,
    ) -> Result<SignedWitnessReceipt, String> {
        let now = unix_now()?;
        let mut slot = self.shared.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before witnessing signed state".to_owned())?
            .clone();
        current.validate_at(now)?;
        proposal
            .verify(&current.registry, now)
            .map_err(|error| error.to_string())?;
        let anchor = &proposal.anchor;
        let pending = current
            .pending_approval
            .as_ref()
            .ok_or_else(|| "No exact pilot approval is pending for this witness".to_owned())?;
        let approval_binding = pending
            .decision
            .network_binding
            .as_ref()
            .ok_or_else(|| "Pending pilot approval has no network binding".to_owned())?;
        if anchor.last_operation_id.as_deref() != Some(pending.decision.operation_id.as_str())
            || anchor.policy_epoch != pending.decision.policy_epoch
            || anchor.network_id != approval_binding.network_id
            || anchor.genesis_identifier != approval_binding.genesis_identifier
            || anchor.node_profile_id != approval_binding.node_profile_id
            || anchor.transaction_format_version != approval_binding.transaction_format_version
        {
            return Err("Rollback anchor does not match the approved network binding".to_owned());
        }
        if anchor.agent_wallet_id != current.agent_wallet_id
            || anchor.desktop_device_id != current.desktop_device_id
            || anchor.mobile_device_id != current.mobile_device_id
            || anchor.network_id != "testnet"
        {
            return Err("Rollback anchor does not match this paired testnet wallet".to_owned());
        }
        let mut next = current.clone();
        let receipt = if let Some(witness) = next.witness.as_mut() {
            match witness.receipt_for_accepted_anchor(proposal, &current.registry, now) {
                Ok(receipt) => receipt,
                Err(_) => witness
                    .accept_anchor(proposal, &current.registry, now)
                    .map_err(|error| error.to_string())?,
            }
        } else {
            let mut witness = MobileWitnessState::new(
                current.agent_wallet_id.clone(),
                current.desktop_device_id.clone(),
                current.mobile_device_id.clone(),
                anchor.network_id.clone(),
                anchor.genesis_identifier.clone(),
                anchor.signer_epoch,
                anchor.journal_epoch,
                anchor.witness_epoch,
            )
            .map_err(|error| error.to_string())?;
            let receipt = witness
                .accept_anchor(proposal, &current.registry, now)
                .map_err(|error| error.to_string())?;
            next.witness = Some(witness);
            receipt
        };
        // The accepted anchor is durable before biometric signing and before
        // any signed receipt can leave the process.
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        drop(slot);
        let signer = crate::agent_companion_identity::open(app)
            .await?
            .ok_or_else(|| "Android companion identity is not configured".to_owned())?;
        SignedWitnessReceipt::sign(receipt, &signer)
            .await
            .map_err(|error| error.to_string())
    }

    async fn clear_pending_approval(&self, operation_id: &str) -> Result<(), String> {
        let mut slot = self.shared.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before completing an approval".to_owned())?
            .clone();
        let pending = current
            .pending_approval
            .as_ref()
            .ok_or_else(|| "No pilot approval is pending".to_owned())?;
        if pending.decision.operation_id != operation_id {
            return Err("Pilot approval completion scope mismatch".to_owned());
        }
        let mut next = current;
        next.pending_approval = None;
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }

    async fn recover_pending_proposal(
        &self,
        app: tauri::AppHandle,
        operation_id: &str,
    ) -> Result<SignedRollbackAnchor, String> {
        let response = self
            .exchange_with_reconnect(
                app,
                super::session::OutboundKind::RecoverPendingWitness(operation_id.to_owned()),
            )
            .await?;
        let CompanionPayload::RollbackAnchorProposal(proposal) = response.payload else {
            return Err("Desktop returned an unexpected pending witness response".to_owned());
        };
        if proposal.anchor.last_operation_id.as_deref() != Some(operation_id) {
            return Err("Recovered rollback anchor operation does not match".to_owned());
        }
        Ok(proposal)
    }
    async fn send_witness(
        &self,
        app: tauri::AppHandle,
        mut proposal: SignedRollbackAnchor,
    ) -> Result<CompanionWitnessView, String> {
        let operation_id = proposal
            .anchor
            .last_operation_id
            .clone()
            .ok_or_else(|| "Witnessed anchor has no operation id".to_owned())?;
        for _ in 0..3 {
            let receipt = self.sign_pilot_witness(&app, &proposal).await?;
            let message = self
                .exchange_with_reconnect(
                    app.clone(),
                    super::session::OutboundKind::Witness(receipt),
                )
                .await?;
            match message.payload {
                CompanionPayload::RollbackAnchorProposal(next) => {
                    if next.anchor.last_operation_id.as_deref() != Some(operation_id.as_str())
                        || next.anchor.anchor_sequence
                            != proposal.anchor.anchor_sequence.saturating_add(1)
                    {
                        return Err(
                            "Desktop returned a mismatched witness lifecycle anchor".to_owned()
                        );
                    }
                    proposal = next;
                }
                CompanionPayload::WitnessAck {
                    anchor_id,
                    accepted,
                    detail,
                } => {
                    if anchor_id != proposal.anchor.anchor_id || !accepted {
                        return Err("Desktop rejected the rollback witness receipt".to_owned());
                    }
                    if detail == "final_witness_accepted_committed" {
                        self.clear_pending_approval(&operation_id).await?;
                    }
                    return Ok(CompanionWitnessView {
                        anchor_id,
                        accepted,
                        detail,
                    });
                }
                _ => {
                    return Err("Desktop returned an unexpected witness response".to_owned());
                }
            }
        }
        Err("Witness lifecycle exceeded the maximum chained anchor count".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_decide_payment(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionPilotDecisionRequest,
) -> Result<CompanionPilotDecisionView, String> {
    require_agent_companion_webview(&webview)?;
    require_pilot_enabled()?;
    #[cfg(target_os = "android")]
    {
        let operation_id = request.commitment.operation_id.clone();
        let approved = request.decision == ApprovalDecision::Approve;
        let prepared = state.sign_pilot_decision(&app, request).await?;
        let response = match prepared {
            PreparedPilotDecision::Fresh(signed) => Some(
                state
                    .exchange_with_reconnect(
                        app.clone(),
                        super::session::OutboundKind::Approval(signed),
                    )
                    .await,
            ),
            PreparedPilotDecision::PendingRecovery => None,
        };
        if !approved {
            let response = response.ok_or_else(|| {
                "A payment rejection is pending; duplicate approval transport is forbidden"
                    .to_owned()
            })??;
            let CompanionPayload::AdminAck {
                command_id,
                accepted,
                detail,
            } = response.payload
            else {
                return Err("Desktop returned an unexpected rejection response".to_owned());
            };
            if !accepted || command_id != operation_id {
                return Err("Desktop did not accept the exact payment rejection".to_owned());
            }
            state.clear_pending_approval(&operation_id).await?;
            return Ok(CompanionPilotDecisionView {
                operation_id,
                approved: false,
                witnessed: false,
                anchor_id: None,
                detail,
            });
        }
        // Approval transport is never replayed. If the response was lost, or
        // this is a restart retry, recover only the desktop's durable pending
        // witness proposal for the exact operation and binding.
        let proposal = match response {
            Some(Ok(message)) => {
                let CompanionPayload::RollbackAnchorProposal(proposal) = message.payload else {
                    return Err("Desktop did not return a rollback anchor".to_owned());
                };
                proposal
            }
            Some(Err(_)) | None => {
                state
                    .recover_pending_proposal(app.clone(), &operation_id)
                    .await?
            }
        };
        let witness = state.send_witness(app, proposal).await?;
        Ok(CompanionPilotDecisionView {
            operation_id,
            approved: true,
            witnessed: witness.accepted,
            anchor_id: Some(witness.anchor_id),
            detail: witness.detail,
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let CompanionPilotDecisionRequest {
            commitment,
            decision,
        } = request;
        let _ = (app, state, commitment, decision);
        Err("Agent Wallet pilot approval is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_witness_anchor(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    proposal: SignedRollbackAnchor,
) -> Result<CompanionWitnessView, String> {
    require_agent_companion_webview(&webview)?;
    require_pilot_enabled()?;
    #[cfg(target_os = "android")]
    {
        state.send_witness(app, proposal).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, proposal);
        Err("Rollback witnessing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_rotation_step(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionRotationView, String> {
    require_agent_companion_webview(&webview)?;
    require_pilot_enabled()?;
    #[cfg(target_os = "android")]
    {
        let _rotation = state.rotation.lock().await;
        let response = state
            .exchange_with_reconnect(
                app.clone(),
                super::session::OutboundKind::RotationPoll(None),
            )
            .await?;
        match response.payload {
            CompanionPayload::WitnessRotationProposal(record) => {
                let rotation_id = record.rotation_id.clone();
                let current = state
                    .shared
                    .current()
                    .await?
                    .ok_or_else(|| "Pair this phone before rotating a witness".to_owned())?;
                if current.mobile_device_id == record.old_mobile_device_id {
                    let signed = state.sign_rotation_authorization(&app, &record).await?;
                    let response = state
                        .exchange_with_reconnect(
                            app,
                            super::session::OutboundKind::RotationAuthorization(signed),
                        )
                        .await?;
                    let CompanionPayload::AdminAck {
                        command_id,
                        accepted,
                        detail,
                    } = response.payload
                    else {
                        return Err(
                            "Desktop returned an unexpected old-phone authorization response"
                                .to_owned(),
                        );
                    };
                    if !accepted
                        || command_id != rotation_id
                        || detail != "old_witness_authorization_accepted"
                    {
                        return Err(
                            "Desktop did not accept the exact old-phone authorization".to_owned()
                        );
                    }
                    state
                        .persist_rotation_phase(
                            WitnessRotationPhase::AwaitingCandidatePairing,
                            true,
                            false,
                        )
                        .await?;
                    Ok(CompanionRotationView {
                        rotation_id,
                        phase: WitnessRotationPhase::AwaitingCandidatePairing,
                        detail,
                    })
                } else if current.mobile_device_id == record.new_mobile_device_id {
                    let signed = state.sign_rotation_baseline(&app, &record).await?;
                    let response = state
                        .exchange_with_reconnect(
                            app.clone(),
                            super::session::OutboundKind::RotationBaseline(signed),
                        )
                        .await?;
                    let CompanionPayload::RollbackAnchorProposal(proposal) = response.payload
                    else {
                        return Err(
                            "Desktop returned an unexpected replacement baseline response"
                                .to_owned(),
                        );
                    };
                    state.finish_rotation_anchor(app, proposal).await
                } else {
                    Err("Witness rotation is not assigned to this phone".to_owned())
                }
            }
            CompanionPayload::RollbackAnchorProposal(proposal) => {
                state.finish_rotation_anchor(app, proposal).await
            }
            CompanionPayload::AdminAck {
                command_id,
                accepted,
                detail,
            } => {
                if !accepted {
                    return Err("Desktop rejected the witness rotation status".to_owned());
                }
                let phase = match detail.as_str() {
                    "old_witness_authorization_accepted" => {
                        WitnessRotationPhase::AwaitingCandidatePairing
                    }
                    "witness_rotation_completed" => WitnessRotationPhase::Completed,
                    _ => {
                        return Err(
                            "Desktop returned an unknown witness rotation status".to_owned()
                        );
                    }
                };
                state
                    .persist_rotation_phase(phase, true, phase == WitnessRotationPhase::Completed)
                    .await?;
                Ok(CompanionRotationView {
                    rotation_id: command_id,
                    phase,
                    detail,
                })
            }
            _ => Err("Desktop returned an unexpected witness rotation payload".to_owned()),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state);
        Err("Witness rotation is available only on Android".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pilot_is_explicitly_feature_gated() {
        assert_eq!(
            require_pilot_enabled().is_ok(),
            cfg!(feature = "agent-wallet-testnet-pilot")
        );
    }

    #[test]
    fn pilot_fee_is_network_only_and_has_no_wallet_fee() {
        assert_eq!(AGENT_NETWORK_FEE_UNITS, 1_000);
    }
}
