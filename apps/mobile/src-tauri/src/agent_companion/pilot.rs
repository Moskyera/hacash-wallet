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
use super::storage::{MobilePendingApproval, MobilePendingWitness};
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

/// The exact operation the owner confirmed on the phone, in the words the phone
/// showed them. Every field comes from the one disclosed pending-witness entry;
/// nothing here is chosen by the webview.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionPendingWitnessRequest {
    operation_id: String,
    amount_units: String,
    recipient: String,
    status: String,
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

/// Refuses unless this phone already holds a durable record authorizing it to
/// witness this exact operation.
///
/// There are exactly two such records, and never both for different operations:
///
/// * `pending_approval` - the owner approved this payment on this handset. That
///   path is unchanged, field for field, including the comparison against the
///   approval's own network binding.
/// * `pending_witness` - the owner approved this payment on HPAY Desktop and
///   then confirmed here, on this phone, the exact amount and recipient they
///   were shown. There is no approval on this handset to compare a binding
///   against, and comparing the anchor against a binding the same desktop
///   supplied in the same exchange would prove nothing anyway. The network
///   fields are measured instead against the durable `MobileWitnessState` pins,
///   which this phone owns and the desktop cannot move.
///
/// An anchor that matches neither record is refused. This is the check that
/// keeps the rollback witness a deliberate act rather than an automatic
/// co-signature, so it has no "missing input" branch that lets it pass.
#[cfg(any(target_os = "android", test))]
fn require_authorized_witness_binding(
    current: &super::storage::MobileCompanionDurableState,
    anchor: &hpay_companion_protocol::RollbackAnchor,
) -> Result<(), String> {
    let operation_id = anchor
        .last_operation_id
        .as_deref()
        .ok_or_else(|| "Rollback anchor names no operation to witness".to_owned())?;
    let approval = current
        .pending_approval
        .as_ref()
        .filter(|pending| pending.decision.operation_id == operation_id);
    let confirmation = current
        .pending_witness
        .as_ref()
        .filter(|pending| pending.operation_id == operation_id);
    match (approval, confirmation) {
        (Some(pending), _) => {
            let approval_binding = pending
                .decision
                .network_binding
                .as_ref()
                .ok_or_else(|| "Pending pilot approval has no network binding".to_owned())?;
            if anchor.policy_epoch != pending.decision.policy_epoch
                || anchor.network_id != approval_binding.network_id
                || anchor.genesis_identifier != approval_binding.genesis_identifier
                || anchor.node_profile_id != approval_binding.node_profile_id
                || anchor.transaction_format_version != approval_binding.transaction_format_version
            {
                return Err(
                    "Rollback anchor does not match the approved network binding".to_owned(),
                );
            }
            Ok(())
        }
        (None, Some(pending)) => {
            pending.validate()?;
            // A leftover approval naming some other operation would mean two
            // live payments on one phone, which cannot legitimately happen.
            if current.pending_approval.is_some() {
                return Err("Another pilot approval is still pending on this phone".to_owned());
            }
            Ok(())
        }
        (None, None) => Err(
            "No exact pilot approval or witness confirmation is pending for this anchor".to_owned(),
        ),
    }
}

/// Whether an acknowledgement the desktop returned for a witness receipt ends
/// this phone's part in the operation, and so retires the consent record that
/// authorized it.
///
/// Every accepted acknowledgement does, and the `detail` is deliberately not
/// read. It used to be, and only one exact string cleared, so a receipt the
/// desktop accepted into `ReconciliationRequired` - a success, reported to the
/// owner as a success - left the confirmation behind for ever: the operation
/// leaves `awaits_mobile_witness`, so the desktop stops offering it, the witness
/// card disappears, and the one control that could reach the clear goes with it.
/// Any future acknowledgement string the desktop learns to send is covered here
/// by construction rather than by remembering to add it.
///
/// This retires an intent to sign, never a signature. The signed evidence is
/// `MobileWitnessState`, which nothing on this path touches, and a rejected
/// acknowledgement retires nothing at all.
#[cfg(any(target_os = "android", test))]
fn witness_ack_retires_consent(accepted: bool, detail: &str) -> bool {
    let _ = detail;
    accepted
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
        require_authorized_witness_binding(&current, anchor)?;
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

    /// Records the owner's consent, on this phone, to witness one exact
    /// operation that was approved on the desktop.
    ///
    /// This runs before anything is fetched, accepted or signed, and it is the
    /// only thing that lets `sign_pilot_witness` proceed without a
    /// `pending_approval`. The amount and recipient are the ones the screen
    /// actually showed, so what is durable is what the owner read.
    async fn confirm_pending_witness(
        &self,
        operation_id: &str,
        amount_units: &str,
        recipient: &str,
        status: &str,
    ) -> Result<(), String> {
        let now = unix_now()?;
        let mut slot = self.shared.state.lock().await;
        let current = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before witnessing a payment".to_owned())?
            .clone();
        current.validate_at(now)?;
        // Deliberately no `requires_controlled_rotation` gate here. A refused
        // reset durably writes a blocking rotation phase, so gating on it would
        // wedge the owner: confirm, hit a network failure, try the reset, and
        // the retry that would have finished the payment is refused forever.
        // Nothing is lost by leaving it out - a rotation changes the witness
        // epoch, and `accept_anchor` refuses any anchor whose witness epoch does
        // not match this phone's durable state, so a rotated phone cannot
        // witness for the old one no matter what is confirmed here.
        if current.pending_approval.is_some() {
            return Err(
                "Finish the payment already waiting for your approval before witnessing another"
                    .to_owned(),
            );
        }
        let confirmation = MobilePendingWitness {
            state_version: "1".to_owned(),
            operation_id: operation_id.to_owned(),
            amount_units: amount_units.to_owned(),
            recipient: recipient.to_owned(),
            status: status.to_owned(),
            confirmed_at: now.to_string(),
        };
        confirmation.validate()?;
        if let Some(existing) = &current.pending_witness {
            // A retry after a crash or a lost response resumes the same
            // payment. Anything else is refused rather than overwritten: the
            // owner consented to one operation, not to whichever arrives next.
            if existing.operation_id != confirmation.operation_id
                || existing.amount_units != confirmation.amount_units
                || existing.recipient != confirmation.recipient
            {
                return Err(
                    "A different payment is already waiting for your witness on this phone"
                        .to_owned(),
                );
            }
            return Ok(());
        }
        let mut next = current;
        next.pending_witness = Some(confirmation);
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }

    async fn clear_pending_witness(&self, operation_id: &str) -> Result<(), String> {
        let mut slot = self.shared.state.lock().await;
        let mut next = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before completing a witness".to_owned())?
            .clone();
        // The clearing rule, including the rotation-marker rewind, lives once in
        // the storage layer so the approval and the confirmation cannot drift
        // into two different lifecycles again.
        next.clear_pending_witness_for(operation_id)?;
        self.shared.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }

    /// Retires whichever durable consent record named this now-finished
    /// operation.
    ///
    /// A desktop-approved payment has no `pending_approval` to clear, and
    /// calling the approval-only version for one used to be an error at the very
    /// end of a fully successful witness lifecycle.
    ///
    /// Finding nothing to clear is success, not failure. This runs after the
    /// desktop has already accepted the receipt, so returning an error here
    /// would report a payment that actually worked as a failure - and would do
    /// it precisely on the retry paths where the record was already retired.
    async fn clear_completed_operation(&self, operation_id: &str) -> Result<(), String> {
        let (has_approval, has_confirmation) = {
            let slot = self.shared.state.lock().await;
            let current = slot
                .as_ref()
                .ok_or_else(|| "Pair this phone before completing a payment".to_owned())?;
            (
                current
                    .pending_approval
                    .as_ref()
                    .is_some_and(|pending| pending.decision.operation_id == operation_id),
                current
                    .pending_witness
                    .as_ref()
                    .is_some_and(|pending| pending.operation_id == operation_id),
            )
        };
        if has_approval {
            self.clear_pending_approval(operation_id).await?;
        }
        if has_confirmation {
            self.clear_pending_witness(operation_id).await?;
        }
        Ok(())
    }

    async fn clear_pending_approval(&self, operation_id: &str) -> Result<(), String> {
        let mut slot = self.shared.state.lock().await;
        let mut next = slot
            .as_ref()
            .ok_or_else(|| "Pair this phone before completing an approval".to_owned())?
            .clone();
        next.clear_pending_approval_for(operation_id)?;
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
                    // An accepted acknowledgement ends this phone's part in the
                    // operation, whatever the desktop then does with it. Only
                    // `final_witness_accepted_committed` used to clear, so a
                    // receipt that was accepted into `ReconciliationRequired`
                    // left the confirmation behind - on a success path, with the
                    // screen reporting success, and with the operation no longer
                    // offered for witness so no control could ever reach the
                    // clear again. Nothing is lost by clearing here: if
                    // reconciliation later needs a final witness, the desktop
                    // offers the operation again and the owner confirms again.
                    if witness_ack_retires_consent(accepted, &detail) {
                        self.clear_completed_operation(&operation_id).await?;
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
        // Held for the whole flow so the automatic sweep cannot retire the
        // consent record this flow is in the middle of using.
        let _flow = state.consent_flow.lock().await;
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

/// Witnesses one operation the owner approved on HPAY Desktop.
///
/// The phone does not receive the wallet's activity list. It receives, under the
/// `WitnessRollbackAnchor` permission it already holds, the id of the single
/// operation that is stranded waiting for its signature, plus the amount and
/// recipient needed to render a confirmation the owner can actually read. The
/// anchor itself still arrives only through `RecoverPendingWitness`, still
/// carries a real desktop signature, and is still checked against this phone's
/// durable witness state before anything is signed.
#[tauri::command]
pub async fn agent_wallet_companion_witness_pending(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionPendingWitnessRequest,
) -> Result<CompanionWitnessView, String> {
    require_agent_companion_webview(&webview)?;
    require_pilot_enabled()?;
    #[cfg(target_os = "android")]
    {
        let _flow = state.consent_flow.lock().await;
        // Durable owner consent first, before a single byte is fetched.
        state
            .confirm_pending_witness(
                &request.operation_id,
                &request.amount_units,
                &request.recipient,
                &request.status,
            )
            .await?;
        let proposal = state
            .recover_pending_proposal(app.clone(), &request.operation_id)
            .await?;
        state.send_witness(app, proposal).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let CompanionPendingWitnessRequest {
            operation_id,
            amount_units,
            recipient,
            status,
        } = request;
        let _ = (app, state, operation_id, amount_units, recipient, status);
        Err("Rollback witnessing is available only on Android".to_owned())
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
        let _flow = state.consent_flow.lock().await;
        state.send_witness(app, proposal).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, proposal);
        Err("Rollback witnessing is available only on Android".to_owned())
    }
}

/// Advances a controlled witness rotation from this phone.
///
/// This used to be gated wholesale on the pilot feature, which meant a handset
/// carrying a rotation marker in a read-only build had no control at all: the
/// reset was refused, the rotation panel was hidden, and the command refused
/// too. The old-phone half - poll the desktop, then sign an authorization for
/// this handset's own replacement - is now available in every build, because it
/// authorizes nothing, spends nothing and only ever gives authority away. The
/// replacement phone's half, which ends in a witness receipt over a rollback
/// anchor, stays pilot-only and is refused branch by branch below.
#[tauri::command]
pub async fn agent_wallet_companion_rotation_step(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionRotationView, String> {
    require_agent_companion_webview(&webview)?;
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
                    // The replacement phone's half ends in a witness receipt.
                    require_pilot_enabled()?;
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
                // Signing the completion anchor is a rollback witness receipt.
                require_pilot_enabled()?;
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

    /// The headline stranding path.
    ///
    /// These are the two acknowledgements
    /// `crates/wallet-tauri-common/src/companion_backend.rs` returns with
    /// `accepted: true` for an ordinary payment witness. Only the committed one
    /// used to retire the confirmation, so a receipt the desktop accepted into
    /// `ReconciliationRequired` stranded the phone on a success path.
    #[test]
    fn every_accepted_witness_acknowledgement_retires_the_confirmation() {
        for detail in [
            "final_witness_accepted_committed",
            "submitted_witness_accepted_reconciliation_required",
        ] {
            assert!(
                witness_ack_retires_consent(true, detail),
                "an accepted acknowledgement must end this phone's part: {detail}"
            );
        }
        // A string the desktop has not learned to send yet must not strand a
        // phone either, so the detail is not read at all.
        assert!(witness_ack_retires_consent(
            true,
            "some_future_terminal_detail"
        ));
        // A refusal retires nothing: the operation may still need this phone.
        assert!(!witness_ack_retires_consent(
            false,
            "final_witness_accepted_committed"
        ));
    }

    mod witness_binding {
        use hpay_companion_protocol::{
            DeviceId, DeviceRegistry, LanEndpoint, ReplayGuard, RollbackAnchor,
            RollbackOperationPhase, WitnessRotationPhase,
        };

        use super::super::require_authorized_witness_binding;
        use crate::agent_companion::STATE_VERSION;
        use crate::agent_companion::storage::{MobileCompanionDurableState, MobilePendingWitness};

        const GENESIS: &str = "11b008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
        const NODE_PROFILE: &str =
            "22b008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

        /// Only the two durable consent records matter to the function under
        /// test; every other field is inert scaffolding it never reads.
        fn paired_state() -> MobileCompanionDurableState {
            MobileCompanionDurableState {
                state_version: STATE_VERSION,
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
                mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
                endpoints: vec![LanEndpoint::parse("hpay-lan://192.168.1.8:42492").unwrap()],
                registry: DeviceRegistry::new(),
                replay: ReplayGuard::new().snapshot(1_000).unwrap(),
                response_sequence: 0,
                approval_sequence: 0,
                pending_pairing_ack: None,
                pending_approval: None,
                pending_witness: None,
                discarded_consents: Vec::new(),
                discarded_consents_dropped: 0,
                witness: None,
                rotation_phase: WitnessRotationPhase::Stable,
                pending_rotation_authorization: None,
                pending_rotation_baseline: None,
                rotation_ticket: None,
                rotation_candidate_acceptance: None,
            }
        }

        fn confirmation(operation_id: &str) -> MobilePendingWitness {
            MobilePendingWitness {
                state_version: "1".to_owned(),
                operation_id: operation_id.to_owned(),
                amount_units: "50000000".to_owned(),
                recipient: "1NewDeveloper".to_owned(),
                status: "signed_awaiting_witness".to_owned(),
                confirmed_at: "1000".to_owned(),
            }
        }

        fn anchor(operation_id: &str) -> RollbackAnchor {
            RollbackAnchor {
                anchor_version: 1,
                anchor_id: "anchor_one".to_owned(),
                agent_wallet_id: "wallet_one".to_owned(),
                desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
                mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
                desktop_authorization_epoch: 1,
                mobile_authorization_epoch: 1,
                network_id: "testnet".to_owned(),
                genesis_identifier: GENESIS.to_owned(),
                node_profile_id: NODE_PROFILE.to_owned(),
                transaction_format_version: 2,
                signer_epoch: 1,
                journal_epoch: 1,
                witness_epoch: 1,
                anchor_sequence: 1,
                previous_anchor_hash: "0".repeat(64),
                journal_sequence: 7,
                journal_head_hash: "33".repeat(32),
                materialized_state_commitment: "44".repeat(32),
                last_operation_id: Some(operation_id.to_owned()),
                operation_phase: RollbackOperationPhase::SignedAwaitingWitness,
                transaction_state: None,
                policy_epoch: 1,
                capability_epoch: 1,
                created_at: 999,
                expires_at: 1_060,
            }
        }

        /// The whole point of the change: a payment the owner approved on the
        /// desktop leaves no approval on this phone, and it can still be
        /// witnessed - but only because the owner confirmed it here first.
        #[test]
        fn a_payment_this_phone_never_approved_can_be_witnessed_after_confirmation() {
            let mut state = paired_state();
            assert!(state.pending_approval.is_none());

            // Before the owner confirms anything, there is nothing to witness.
            assert_eq!(
                require_authorized_witness_binding(&state, &anchor("operation_one")),
                Err(
                    "No exact pilot approval or witness confirmation is pending for this anchor"
                        .to_owned()
                )
            );

            state.pending_witness = Some(confirmation("operation_one"));
            require_authorized_witness_binding(&state, &anchor("operation_one")).unwrap();
        }

        /// The confirmation binds one operation, not "whatever arrives next".
        #[test]
        fn a_confirmation_never_authorizes_a_different_operation() {
            let mut state = paired_state();
            state.pending_witness = Some(confirmation("operation_one"));
            assert!(require_authorized_witness_binding(&state, &anchor("operation_two")).is_err());

            let mut anonymous = anchor("operation_one");
            anonymous.last_operation_id = None;
            assert_eq!(
                require_authorized_witness_binding(&state, &anonymous),
                Err("Rollback anchor names no operation to witness".to_owned())
            );
        }

        /// Discarding a confirmation can only ever make witnessing harder.
        ///
        /// This is the guarantee that makes every exit in this change safe: the
        /// consent record is an admission gate, never evidence. Once it is
        /// gone, the exact anchor that was admissible a moment ago is refused,
        /// so nothing unwitnessed can be made to look witnessed by clearing.
        #[test]
        fn a_discarded_confirmation_authorizes_no_anchor_at_all() {
            let mut state = paired_state();
            state.pending_witness = Some(confirmation("operation_one"));
            require_authorized_witness_binding(&state, &anchor("operation_one")).unwrap();

            let discarded = state
                .owner_discard_consent("operation_one", 2_000)
                .expect("the owner may discard the payment this phone is holding");
            assert_eq!(discarded.operation_id, "operation_one");
            assert_eq!(
                require_authorized_witness_binding(&state, &anchor("operation_one")),
                Err(
                    "No exact pilot approval or witness confirmation is pending for this anchor"
                        .to_owned()
                )
            );
            // The receipt the discard left behind is not a second consent
            // record: it authorizes nothing, and the anchor stays refused.
            assert_eq!(state.discarded_consents.len(), 1);
            assert!(state.pending_witness.is_none());
            assert!(state.pending_approval.is_none());
        }

        /// A record the phone would not have written itself is refused rather
        /// than trusted, so a corrupted or hand-edited state cannot smuggle a
        /// consent through.
        #[test]
        fn a_malformed_confirmation_authorizes_nothing() {
            for broken in [
                MobilePendingWitness {
                    status: "committed".to_owned(),
                    ..confirmation("operation_one")
                },
                MobilePendingWitness {
                    amount_units: "0".to_owned(),
                    ..confirmation("operation_one")
                },
                MobilePendingWitness {
                    recipient: String::new(),
                    ..confirmation("operation_one")
                },
                MobilePendingWitness {
                    state_version: "2".to_owned(),
                    ..confirmation("operation_one")
                },
            ] {
                let mut state = paired_state();
                state.pending_witness = Some(broken);
                assert!(
                    require_authorized_witness_binding(&state, &anchor("operation_one")).is_err()
                );
            }
        }
    }
}
