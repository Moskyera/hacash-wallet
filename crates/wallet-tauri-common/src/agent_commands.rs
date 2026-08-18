//! Desktop-only Tauri surface for the independent AI Agent Wallet.
//!
//! Every command is restricted to the exact trusted local `main` webview.
//! The local AI connector has a separate scoped protocol and cannot call
//! Tauri IPC.

#[cfg(feature = "agent-wallet-testnet-pilot")]
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use agent_wallet_core::export_pilot_diagnostics;
use agent_wallet_core::{
    AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING, AgentId, AgentPaymentRequest,
    AgentPolicy, AgentRecord, AgentWalletBackupAcknowledgement, AgentWalletId, ApprovalCommitment,
    ApprovalMode, CreateAgentWallet, OperationId, PaymentOperationView,
};
use agent_wallet_runtime::RuntimeStatus;
use hpay_companion_protocol::{
    DeviceId, DeviceRole, EncryptedCompanionFrame, LanEndpoint, PairingRequest,
    SignedRotationCandidateAcceptance,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::{WitnessRotationMode, WitnessRotationReason};
use serde_json::{Value, json};
use tauri::Webview;
use tokio::sync::Mutex;

use crate::agent_runtime::phase_name;
use crate::state::AgentAppState;

#[tauri::command]
pub async fn agent_wallet_runtime_status(
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let Some(manager) = manager_arc(&state) else {
        return Ok(json!({
            "available": false,
            "pilot_enabled": cfg!(feature = "agent-wallet-testnet-pilot"),
            "application_version": env!("CARGO_PKG_VERSION"),
            "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "error": state.initialization_error.as_deref().unwrap_or("Agent Wallet unavailable"),
            "wallets": [],
            "connector": runtime_status_value(state.runtime.status()),
        }));
    };
    let wallets = manager.lock().await.list_wallets().map_err(public_error)?;
    Ok(json!({
        "available": true,
        "pilot_enabled": cfg!(feature = "agent-wallet-testnet-pilot"),
        "application_version": env!("CARGO_PKG_VERSION"),
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "error": Value::Null,
        "wallets": wallets,
        "connector": runtime_status_value(state.runtime.status()),
    }))
}

#[tauri::command]
pub async fn agent_wallet_pilot_diagnostics_preview(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let preview = require_manager(&state)?
            .lock()
            .await
            .pilot_diagnostics_preview(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(preview)
            .map_err(|_| "pilot diagnostics preview encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("pilot diagnostics are disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_pilot_diagnostics_export(
    wallet_id: String,
    expected_preview_sha256: String,
    destination_path: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        if destination_path.is_empty() || destination_path.len() > 32 * 1024 {
            return Err("pilot diagnostics destination path is invalid".to_owned());
        }
        let wallet_id = parse_wallet_id(wallet_id)?;
        let preview = require_manager(&state)?
            .lock()
            .await
            .pilot_diagnostics_preview(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        let result = export_pilot_diagnostics(
            &preview,
            &expected_preview_sha256,
            &PathBuf::from(destination_path),
        )
        .map_err(public_error)?;
        serde_json::to_value(result)
            .map_err(|_| "pilot diagnostics export encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, expected_preview_sha256, destination_path, state);
        Err("pilot diagnostics are disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_witness_rotation_prepare(
    wallet_id: String,
    rotation_id: String,
    new_mobile_device_id: String,
    mode: String,
    reason: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let new_mobile_device_id = DeviceId::parse(new_mobile_device_id)
            .map_err(|_| "invalid replacement mobile device id".to_owned())?;
        let mode = match mode.as_str() {
            "normal" => WitnessRotationMode::Normal,
            "lost_phone_recovery" => WitnessRotationMode::LostPhoneRecovery,
            _ => return Err("invalid witness rotation mode".to_owned()),
        };
        let reason = match reason.as_str() {
            "replace_phone" => WitnessRotationReason::ReplacePhone,
            "lost_phone" => WitnessRotationReason::LostPhone,
            "compromised_device" => WitnessRotationReason::CompromisedDevice,
            _ => return Err("invalid witness rotation reason".to_owned()),
        };
        let record = require_manager(&state)?
            .lock()
            .await
            .prepare_witness_rotation(
                &wallet_id,
                rotation_id,
                &new_mobile_device_id,
                mode,
                reason,
                unix_now()?,
            )
            .await
            .map_err(public_error)?;
        serde_json::to_value(record).map_err(|_| "witness rotation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (
            wallet_id,
            rotation_id,
            new_mobile_device_id,
            mode,
            reason,
            state,
        );
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_witness_rotation_status(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let value = require_manager(&state)?
            .lock()
            .await
            .current_witness_rotation(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(value).map_err(|_| "witness rotation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_witness_rotation_cancel(
    wallet_id: String,
    rotation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        state
            .companion
            .cancel_pairing(&wallet_id, require_manager(&state)?)
            .await?;
        require_manager(&state)?
            .lock()
            .await
            .cancel_witness_rotation(&wallet_id, &rotation_id, unix_now()?)
            .map_err(public_error)
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, rotation_id, state);
        Err("witness rotation is disabled in this build".to_owned())
    }
}

/// The payment that is waiting on a phone witness, and which recovery controls
/// would actually succeed on it right now.
///
/// Answers `null` when nothing is waiting. The core evaluates the same
/// predicates it enforces, so this never offers a control that is then refused.
#[tauri::command]
pub async fn agent_wallet_stranded_witness(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let stranded = require_manager(&state)?
            .lock()
            .await
            .stranded_witness_recovery(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(stranded).map_err(|_| "stranded witness encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Ok(Value::Null)
    }
}

/// Gives up a signed payment that no phone can witness any more.
///
/// It releases the reservation and moves no money: a payment in
/// `SignedAwaitingWitness` provably never reached the node. The desktop must
/// say what it costs before the press; see `AgentAdminPages.tsx` and
/// `ABANDON_STRANDED_PAYMENT_WARNING` in `irreversibleActions.ts`.
#[tauri::command]
pub async fn agent_wallet_abandon_stranded_witness(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = agent_wallet_core::OperationId::parse(operation_id)
            .map_err(|_| "operation id is invalid".to_owned())?;
        let _transition = state.transition.lock().await;
        let view = require_manager(&state)?
            .lock()
            .await
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(view).map_err(|_| "operation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("stranded witness recovery is disabled in this build".to_owned())
    }
}

/// Drops a rollback anchor that expired unwitnessed out of the single pending
/// slot, leaving the payment exactly where it stands.
///
/// It moves no money, marks nothing witnessed and does not touch the operation:
/// the returned view is the same one that was there before. It exists because
/// that one occupied slot is what refuses the phone replacement, which is the
/// only exit when the phone itself can no longer sign for the payment. The core
/// accepts it only once nothing is outstanding that could still become a
/// witness.
#[tauri::command]
pub async fn agent_wallet_release_dead_witness_anchor(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = agent_wallet_core::OperationId::parse(operation_id)
            .map_err(|_| "operation id is invalid".to_owned())?;
        let _transition = state.transition.lock().await;
        let view = require_manager(&state)?
            .lock()
            .await
            .release_dead_witness_anchor(&wallet_id, &operation_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(view).map_err(|_| "operation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("stranded witness recovery is disabled in this build".to_owned())
    }
}

/// Which rotation escapes the desktop may offer right now.
///
/// The core answers with the same predicates it enforces, so the desktop never
/// shows a control that would then be refused - and never hides the only one
/// that still works.
#[tauri::command]
pub async fn agent_wallet_witness_rotation_controls(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let controls = require_manager(&state)?
            .lock()
            .await
            .witness_rotation_controls(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(controls).map_err(|_| "witness rotation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Ok(serde_json::json!({ "cancellable": false, "retargetable": false }))
    }
}

/// Points a rotation stranded past the authority transition at a different
/// replacement phone.
///
/// The abandoned candidate's baseline and registration are discarded and its
/// witness epoch is burned. The caller must have said so before the press; see
/// `WitnessRotationPanel.tsx`.
#[tauri::command]
pub async fn agent_wallet_witness_rotation_retarget(
    wallet_id: String,
    rotation_id: String,
    new_rotation_id: String,
    new_candidate_slot_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let new_candidate_slot_id = DeviceId::parse(new_candidate_slot_id)
            .map_err(|_| "invalid replacement mobile device id".to_owned())?;
        let _transition = state.transition.lock().await;
        // Any half-finished candidate pairing belongs to the attempt being
        // abandoned. It is dropped before the durable re-target, never after.
        state
            .companion
            .cancel_pairing(&wallet_id, require_manager(&state)?)
            .await?;
        let record = require_manager(&state)?
            .lock()
            .await
            .retarget_witness_rotation(
                &wallet_id,
                &rotation_id,
                new_rotation_id,
                &new_candidate_slot_id,
                unix_now()?,
            )
            .map_err(public_error)?;
        serde_json::to_value(record).map_err(|_| "witness rotation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (
            wallet_id,
            rotation_id,
            new_rotation_id,
            new_candidate_slot_id,
            state,
        );
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_runtime_start(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let status = state
        .runtime
        .start(wallet_id.clone(), require_manager(&state)?)
        .await?;
    Ok(runtime_value(Some(wallet_id), status))
}

#[tauri::command]
pub async fn agent_wallet_runtime_stop(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let status = state.runtime.stop(&wallet_id).await?;
    Ok(runtime_value(Some(wallet_id), status))
}

#[tauri::command]
pub async fn agent_wallet_pairing_activate(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let activation = state.runtime.activate_pairing(wallet_id).await?;
    // pairing_id is a bearer secret. This is its one and only UI exposure.
    Ok(json!({
        "pairingId": activation.pairing_id(),
        "walletId": activation.wallet_id(),
        "expiresAtUnix": activation.expires_at_unix().to_string(),
        "serverIdentity": activation.server_identity(),
    }))
}

#[tauri::command]
pub async fn agent_wallet_pairing_pending(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let Some(pending) = state.runtime.pending_pairing(&wallet_id)? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "walletId": pending.wallet_id,
        "agentName": pending.agent_name,
        "agentVersion": pending.agent_version,
        "identityFingerprint": pending.identity_fingerprint,
        "requestedCapabilities": pending.requested_capabilities,
        "submissionCommitment": pending.submission_commitment,
        "expiresAtUnix": pending.expires_at_unix.to_string(),
    }))
}

#[tauri::command]
pub async fn agent_wallet_pairing_approve(
    wallet_id: String,
    pairing_id: String,
    submission_commitment: String,
    policy: AgentPolicy,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<AgentRecord, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let commitment =
        hpay_agent_connector::PairingSubmissionCommitment::parse(submission_commitment)
            .map_err(|error| error.to_string())?;
    state
        .runtime
        .approve_pairing(&wallet_id, &pairing_id, &commitment, policy)
        .await
}

#[tauri::command]
pub async fn agent_wallet_pairing_reject(
    wallet_id: String,
    pairing_id: String,
    submission_commitment: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let commitment =
        hpay_agent_connector::PairingSubmissionCommitment::parse(submission_commitment)
            .map_err(|error| error.to_string())?;
    state
        .runtime
        .reject_pairing(&wallet_id, &pairing_id, &commitment)
}

#[tauri::command]
pub async fn agent_wallet_create(
    passphrase: String,
    network_mode: String,
    node_url: String,
    block_one_fingerprint: Option<String>,
    mainnet_pilot_acknowledgement: Option<String>,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    let mut guard = manager.lock().await;
    let created = guard
        .create_wallet(
            CreateAgentWallet {
                passphrase,
                network_mode,
                node_url,
                block_one_fingerprint,
                mainnet_pilot_acknowledgement,
            },
            unix_now()?,
        )
        .map_err(public_error)?;
    let controller = guard
        .emergency_controller(&created.wallet_id)
        .map_err(public_error)?;
    state
        .runtime
        .cache_emergency_controller(&created.wallet_id, controller);
    serde_json::to_value(created).map_err(|_| "Agent Wallet response encoding failed".into())
}

/// The two warnings, so the desktop renders the core's own words rather than a
/// copy of them that can drift.
///
/// Both are handed over in full. A caller that shows three of the four lines has
/// still failed the owner, which is why the acknowledgement below is four
/// separate flags and not one.
#[tauri::command]
pub async fn agent_wallet_backup_warnings(webview: Webview) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    Ok(json!({
        "backup": AGENT_WALLET_BACKUP_WARNING,
        "restore": AGENT_WALLET_RESTORE_WARNING,
    }))
}

/// Creates an encrypted state backup and returns the document to the frontend.
///
/// It writes no file: where a working copy of the owner's agent wallet is stored
/// is the owner's decision, made in their own save dialog, and never this
/// command's. The passphrase is used to open the wallet's own vault and is not
/// retained, logged, or echoed.
#[tauri::command]
pub async fn agent_wallet_backup_create(
    wallet_id: String,
    passphrase: String,
    acknowledgement: AgentWalletBackupAcknowledgement,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    let guard = manager.lock().await;
    let document = guard
        .create_agent_wallet_backup(&wallet_id, &passphrase, acknowledgement, unix_now()?)
        .map_err(public_error)?;
    Ok(json!({
        "document": document,
        "warning": AGENT_WALLET_BACKUP_WARNING,
    }))
}

/// What a backup file says about itself, with no passphrase.
///
/// The restore warning travels with it, because this is the screen the owner is
/// looking at when they decide.
#[tauri::command]
pub async fn agent_wallet_backup_preview(
    document: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let manager = require_manager(&state)?;
    let guard = manager.lock().await;
    let preview = guard
        .preview_agent_wallet_backup(&document)
        .map_err(public_error)?;
    serde_json::to_value(preview).map_err(|_| "Agent Wallet response encoding failed".into())
}

/// Restores a wallet from a backup document, in full, or refuses and writes
/// nothing.
#[tauri::command]
pub async fn agent_wallet_backup_restore(
    document: String,
    passphrase: String,
    acknowledgement: AgentWalletBackupAcknowledgement,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    let mut guard = manager.lock().await;
    let outcome = guard
        .restore_agent_wallet_backup(&document, &passphrase, acknowledgement, unix_now()?)
        .map_err(public_error)?;
    let controller = guard
        .emergency_controller(&outcome.wallet_id)
        .map_err(public_error)?;
    state
        .runtime
        .cache_emergency_controller(&outcome.wallet_id, controller);
    serde_json::to_value(outcome).map_err(|_| "Agent Wallet response encoding failed".into())
}

#[tauri::command]
pub async fn agent_wallet_unlock(
    wallet_id: String,
    passphrase: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    let mut guard = manager.lock().await;
    let status = guard
        .unlock(&wallet_id, &passphrase, unix_now()?)
        .map_err(public_error)?;
    // Finish a witness the last run was interrupted in the middle of.
    //
    // `AgentWalletManager::unlock` already completed every interrupted witness
    // whose remaining step is pure state. The one residue it cannot reach is a
    // payment the phone witnessed and the process died before broadcasting,
    // because finishing that needs the node. This is the first place after an
    // unlock that can await, so it runs here.
    //
    // A failure is not an unlock failure: the owner is already in, the residue
    // is untouched, and the next unlock tries again. It broadcasts nothing that
    // was not already approved by the owner and witnessed by the paired phone.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let _ = guard
            .resume_interrupted_witness(&wallet_id, unix_now()?)
            .await;
    }
    // And finish an approval the last run was interrupted in the middle of.
    //
    // Both approval paths journal the decision and only then sign, so a process
    // that dies in that gap leaves a payment durably `Approved` with nothing
    // pointed at it. On the phone path the owner cannot even repeat the press:
    // the decision's replay token went out with the same durable write.
    //
    // It needs the node for the same reason the witness resume does - the
    // approved transaction has to be built against the bound node before it is
    // signed - so it runs here rather than inside `unlock`. It signs only an
    // approval that is already on disk, refuses an expired one, and a failure
    // is not an unlock failure.
    let _ = guard
        .resume_interrupted_approval(&wallet_id, unix_now()?)
        .await;
    let controller = guard
        .emergency_controller(&wallet_id)
        .map_err(public_error)?;
    state
        .runtime
        .cache_emergency_controller(&wallet_id, controller);
    serde_json::to_value(status).map_err(|_| "Agent Wallet response encoding failed".into())
}

#[tauri::command]
pub async fn agent_wallet_lock(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    // Join the connector before removing signer access. A timeout retains the
    // runtime and leaves the wallet unlocked so there is no detached worker.
    let manager = require_manager(&state)?;
    state
        .companion
        .cancel_pairing(&wallet_id, Arc::clone(&manager))
        .await?;
    state.companion.stop(&wallet_id).await?;
    state.runtime.stop(&wallet_id).await?;
    manager
        .lock()
        .await
        .lock(&wallet_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_overview(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    let overview = manager
        .lock()
        .await
        .overview(&wallet_id, unix_now()?)
        .await
        .map_err(public_error)?;
    serde_json::to_value(overview).map_err(|_| "Agent Wallet response encoding failed".into())
}

#[tauri::command]
pub async fn agent_wallet_prepare_fast_pay_channel(
    wallet_id: String,
    hub_url: String,
    deposit: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .prepare_l2_channel_setup(&wallet_id, &hub_url, &deposit, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review).map_err(|_| "Agent channel review encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, deposit, state);
        Err("Agent channel setup is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_confirm_fast_pay_channel_setup(
    wallet_id: String,
    operation_id: String,
    review_commitment: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .confirm_l2_channel_setup(&wallet_id, &operation_id, &review_commitment, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review).map_err(|_| "Agent channel result encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, review_commitment, state);
        Err("Agent channel setup is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_recover_fast_pay_channel_setup(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .recover_l2_channel_setup(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review)
            .map_err(|_| "Agent channel recovery encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent channel setup is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_prepare_fast_pay_channel_close(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .prepare_l2_channel_close(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review)
            .map_err(|_| "Agent channel close review encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent channel close is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_confirm_fast_pay_channel_close(
    wallet_id: String,
    operation_id: String,
    review_commitment: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .confirm_l2_channel_close(&wallet_id, &operation_id, &review_commitment, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review)
            .map_err(|_| "Agent channel close result encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, review_commitment, state);
        Err("Agent channel close is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_recover_fast_pay_channel_close(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let review = require_manager(&state)?
            .lock()
            .await
            .recover_l2_channel_close(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(review)
            .map_err(|_| "Agent channel close recovery encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent channel close is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_enable_payments(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .enable_agent_payments_locally(&wallet_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_emergency_stop(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let controller = state
        .runtime
        .emergency_controller(&wallet_id)
        .ok_or_else(|| {
            "Agent emergency controller is unavailable; signing remains disabled".to_owned()
        })?;
    // Close both network gates before awaiting any join or durable mutation.
    controller.request_stop().map_err(public_error)?;
    state.companion.request_shutdown(&wallet_id)?;
    state.runtime.request_shutdown(&wallet_id)?;
    let manager = require_manager(&state)?;
    let _ = state
        .companion
        .cancel_pairing(&wallet_id, Arc::clone(&manager))
        .await;
    let companion_join = state.companion.stop(&wallet_id).await;
    let runtime_join = state.runtime.stop(&wallet_id).await;
    manager
        .lock()
        .await
        .disable_all_agent_payments(&wallet_id, unix_now()?)
        .map_err(public_error)?;
    companion_join?;
    runtime_join.map(|_| ())
}

#[tauri::command]
pub async fn agent_wallet_list_agents(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Vec<AgentRecord>, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .list_agents_admin(&wallet_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_get_policy(
    wallet_id: String,
    agent_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<AgentPolicy, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let agent_id = AgentId::parse(agent_id).map_err(|error| error.to_string())?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .agent_policy_admin(&wallet_id, &agent_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_update_policy(
    wallet_id: String,
    agent_id: String,
    policy: AgentPolicy,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<AgentPolicy, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let agent_id = AgentId::parse(agent_id).map_err(|error| error.to_string())?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .update_agent_policy_admin(&wallet_id, &agent_id, policy, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_list_activity(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Vec<PaymentOperationView>, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .list_operations_admin(&wallet_id, unix_now()?)
        .map_err(public_error)
}

/// Reads the independent Agent Fast Pay journal for the trusted desktop UI.
/// This command cannot sign, submit, retry, or fall back to L1.
#[tauri::command]
pub async fn agent_wallet_list_fast_pay_activity(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let manager = require_manager(&state)?;
        let operations = manager
            .lock()
            .await
            .list_fast_pay_operations_admin(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(operations)
            .map_err(|_| "Agent Fast Pay activity encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent Fast Pay is disabled in this build".to_owned())
    }
}

/// Owner-triggered execution of one exact, already approved Agent Fast Pay
/// operation. The core durably stores the unsigned bill and signature before
/// submission and has no L1 fallback.
#[tauri::command]
pub async fn agent_wallet_execute_approved_fast_pay(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let manager = require_manager(&state)?;
        let mut manager = manager.lock().await;
        manager
            .sign_prepared_approved_fast_pay_bill(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        let operation = manager
            .submit_signed_approved_fast_pay_bill(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation)
            .map_err(|_| "Agent Fast Pay result encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent Fast Pay is disabled in this build".to_owned())
    }
}

/// Read-only Hub reconciliation across the pre-sign/post-sign uncertainty
/// boundary. It never signs, resubmits, creates new identifiers, or falls back
/// to L1.
#[tauri::command]
pub async fn agent_wallet_reconcile_fast_pay(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let manager = require_manager(&state)?;
        let operation = manager
            .lock()
            .await
            .recover_fast_pay_operation(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation)
            .map_err(|_| "Agent Fast Pay reconciliation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent Fast Pay is disabled in this build".to_owned())
    }
}

/// Explicit retry of the exact durable signed bytes after recovery. The core
/// first proves that the bound Hub still holds the same pending bill.
#[tauri::command]
pub async fn agent_wallet_retry_fast_pay_exact(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let manager = require_manager(&state)?;
        let operation = manager
            .lock()
            .await
            .retry_reconciled_fast_pay_submission(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation)
            .map_err(|_| "Agent Fast Pay retry encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent Fast Pay is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_bind_hvm_channel(
    wallet_id: String,
    hub_url: String,
    binding_commitment: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let binding = require_manager(&state)?
            .lock()
            .await
            .verify_and_bind_hvm_channel(&wallet_id, &hub_url, &binding_commitment, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(binding).map_err(|_| "Agent HVM channel encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, binding_commitment, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_bind_hvm_registry(
    wallet_id: String,
    hub_url: String,
    binding_commitment: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let binding = require_manager(&state)?
            .lock()
            .await
            .verify_and_bind_hvm_registry(&wallet_id, &hub_url, &binding_commitment, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(binding).map_err(|_| "Agent HVM registry encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, binding_commitment, state);
        Err("Agent HVM registry Fast Pay is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_list_hvm_activity(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operations = require_manager(&state)?
            .lock()
            .await
            .list_hvm_operations_admin(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(operations)
            .map_err(|_| "Agent HVM activity encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_execute_approved_hvm(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let _transition = state.transition.lock().await;
        let operation = require_manager(&state)?
            .lock()
            .await
            .execute_approved_hvm_payment(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation).map_err(|_| "Agent HVM result encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_reconcile_hvm(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let _transition = state.transition.lock().await;
        let operation = require_manager(&state)?
            .lock()
            .await
            .recover_hvm_payment(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation)
            .map_err(|_| "Agent HVM reconciliation encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// The parked rollback-anchor witness decision for one HVM operation, or
/// `null`.
///
/// This is the read half of the one question in the whole L2 design that a
/// person has to answer rather than a check. A Hub that has stopped using a
/// witness which signed an earlier bill on this channel looks exactly like a
/// Hub whose witness operator changed, and exactly like a Hub trying to
/// re-spend a serial: nothing in the protocol can tell them apart, so nothing
/// pretends to.
#[tauri::command]
pub async fn agent_wallet_hvm_anchor_decision(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let pending = require_manager(&state)?
            .lock()
            .await
            .pending_hvm_anchor_decision(&wallet_id, &operation_id)
            .map_err(public_error)?;
        Ok(pending.as_ref().map_or(Value::Null, anchor_change_evidence))
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// Ask the Hub to re-anchor this channel's existing head under the witness it
/// is answering with now, and adjudicate the answer here.
///
/// This is the read half above with the one thing it cannot do added: it works
/// on a channel that will never see another payment. A Hub has exactly one
/// rollback-anchor witness, and if that witness's durable store is replaced the
/// Hub refuses to co-sign anything from then on - so every other route into the
/// witness ratchet, all of which run on a *new* bill, is closed forever and the
/// parked decision this endpoint reads would never be raised at all.
///
/// Nothing new is signed to produce it: the declaration is the same serial and
/// the same bill commitment this wallet already holds. The answer is the same
/// two-way question as `agent_wallet_hvm_anchor_decision`, answered with
/// `agent_wallet_resolve_hvm_anchor_decision`, and `null` when the Hub's
/// witness still covers the head and there is nothing to decide.
#[tauri::command]
pub async fn agent_wallet_refresh_hvm_anchor_continuity(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let pending = require_manager(&state)?
            .lock()
            .await
            .refresh_hvm_anchor_continuity(&wallet_id, &operation_id)
            .await
            .map_err(public_error)?;
        Ok(pending.as_ref().map_or(Value::Null, anchor_change_evidence))
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// One parked witness-set change, shaped for a person.
///
/// Shared by the read half and the continuity refresh so the two cannot show
/// the same event two different ways.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn anchor_change_evidence(change: &hacash_wallet_core::l2_safety::AnchorWitnessChangeV1) -> Value {
    json!({
        "binding_commitment": change.binding_commitment,
        "serial": change.serial,
        "last_accepted_serial": change.last_accepted_serial,
        "zero_overlap": change.is_zero_overlap(),
        "headline": change.headline(),
        "dropped": change
            .dropped
            .iter()
            .map(anchor_witness_evidence)
            .collect::<Vec<Value>>(),
        "retained": change
            .retained
            .iter()
            .map(anchor_witness_evidence)
            .collect::<Vec<Value>>(),
        "offered": change
            .offered
            .iter()
            .map(anchor_witness_evidence)
            .collect::<Vec<Value>>(),
    })
}

/// The write half. Exactly two answers, and no third: `accept_new_witness_set`
/// or `close_channel`. There is no timeout that picks one and no configuration
/// default, because both of those are the silent accept this rule exists to
/// prevent.
#[tauri::command]
pub async fn agent_wallet_resolve_hvm_anchor_decision(
    wallet_id: String,
    operation_id: String,
    decision: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let decision = match decision.as_str() {
            "accept_new_witness_set" => {
                hacash_wallet_core::l2_safety::AnchorWitnessDecision::AcceptNewWitnessSet
            }
            "close_channel" => hacash_wallet_core::l2_safety::AnchorWitnessDecision::CloseChannel,
            _ => {
                return Err(
                    "The answer must be either accept_new_witness_set or close_channel.".to_owned(),
                );
            }
        };
        let _transition = state.transition.lock().await;
        require_manager(&state)?
            .lock()
            .await
            .resolve_hvm_anchor_decision(&wallet_id, &operation_id, decision)
            .map_err(public_error)?;
        Ok(json!({ "resolved": true }))
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, decision, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// One witness, described by what the ratchet actually keyed on.
///
/// `signer_address` is recovered from the receipt signature and is the half
/// that matters; `witness_id` is a label the Hub typed and is shown as such,
/// so a reader is never invited to treat a name as an identity.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn anchor_witness_evidence(record: &hacash_wallet_core::l2_safety::AnchorWitnessRecordV1) -> Value {
    json!({
        "signer_address": record.signer_address,
        "witness_instance_id": record.witness_instance_id,
        "hub_supplied_label": record.witness_id,
        "witness_epoch": record.witness_epoch,
        "first_seen_serial": record.first_seen_serial,
        "last_seen_serial": record.last_seen_serial,
    })
}

#[tauri::command]
pub async fn agent_wallet_retry_hvm_exact(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
        let _transition = state.transition.lock().await;
        let operation = require_manager(&state)?
            .lock()
            .await
            .retry_reconciled_hvm_payment(&wallet_id, &operation_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(operation).map_err(|_| "Agent HVM retry encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// How many chain transactions an ordinary exit sends: challenge, finalize,
/// and the Action 14 payout.
///
/// The screen names the same three in the same order
/// (`apps/desktop/src/agent/registryExit.ts`), so the count the owner reads
/// and the count this ceiling is built from are one number.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_CHAIN_TRANSACTION_COUNT: u64 = 3;

/// Everything an ordinary exit can take out of the owner's main balance.
///
/// # What this used to be, and why that was a false statement about money
///
/// It was `MAX_CHANNEL_NETWORK_FEE_ZHU * 3` — 3,000,000 zhu — on the reasoning
/// that the exit sends three ordinary L1 transactions and the channel builders
/// already refuse to exceed that fee per transaction. The fee half of that is
/// right. The rest was missing: a registry call is an HVM contract call, and
/// `Context::gas_initialize` in
/// `hacash-fullnodedev/protocol/src/context/gas.rs` takes the *entire* gas
/// budget's worth of burn out of the sender's main balance with `hac_sub`
/// before the call executes, refunding the unused part afterwards. None of
/// that appeared anywhere in the quote.
///
/// Measured on a real chain, a completed exit was charged 30,682,605 zhu
/// against a quote of 3,000,000, and the amount the owner had to hold while it
/// ran was larger again. An owner holding exactly the quoted figure saw the
/// affordability precondition go green and could not have paid for the first
/// transaction: `hac_sub` fails, the challenge dies, and they have already
/// pressed a two-step irreversible control.
///
/// So the quote is now fee plus reserve, per transaction, times the three
/// transactions an ordinary exit sends. Lease renewals are extra and the
/// screen says so separately, because they are conditional and this number is
/// the one an owner is asked to have in hand before pressing.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_FEE_CEILING_ZHU: u64 =
    agent_wallet_core::agent_registry_exit_transaction_ceiling_zhu() * EXIT_CHAIN_TRANSACTION_COUNT;

/// What the owner's own fullnode says about walking out of an HVM registry
/// channel without the provider.
///
/// **Nothing in here contacts the Hub.** The binding is read from this
/// wallet's own sealed state, the lease is read from the fullnode this wallet
/// is pinned to, and the readiness term is a measurement inside this
/// workspace. That is deliberate: this is the answer an owner needs precisely
/// when the provider has stopped answering, so a Hub round trip anywhere in it
/// would make the screen fail exactly when it matters.
///
/// The desktop renders this through `registryExitView`
/// (apps/desktop/src/agent/registryExit.ts) on the Security page.
#[tauri::command]
pub async fn agent_wallet_hvm_registry_exit_status(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let now = unix_now()?;
        let manager = require_manager(&state)?;
        let mut manager = manager.lock().await;
        let overview = manager
            .overview(&wallet_id, now)
            .await
            .map_err(public_error)?;
        // What this wallet's own durable record already says about an exit.
        // A wallet with no channel, or one that has never opened a step, has
        // nothing here and the screen speaks about starting; anything else and
        // it speaks about continuing. A read that fails is not allowed to take
        // the whole screen down with it, because this screen is read on the
        // day everything else is failing.
        let started_steps = manager
            .hvm_registry_exit_steps(&wallet_id, now)
            .unwrap_or_default();
        let overview = serde_json::to_value(overview)
            .map_err(|_| "Agent Wallet response encoding failed".to_owned())?;
        Ok(registry_exit_status_value(&overview, started_steps).await)
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// Starts the unilateral close of an HVM registry channel with the owner's own
/// key, through the owner's own fullnode.
///
/// **This is the thing a person presses.** For a long time it was not: this
/// command rendered the section, read the chain and then refused, because
/// nothing under `agent-wallet-core` could sign an exit transaction. That gap
/// is closed by `AgentTransactionSigner::sign_exact_registry_exit`, and this
/// command now runs the shipped driver,
/// `hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit`,
/// through [`agent_wallet_core::AgentWalletManager::advance_hvm_registry_exit`].
/// Until that call existed the driver's only caller in the whole tree was a
/// test, which is a shape this workspace has shipped twice and had caught
/// twice.
///
/// **What this command may not choose.** Neither the channel, nor the receipt,
/// nor the fee. The binding and the head bill are read from the wallet's own
/// encrypted state inside the manager, and the fee and gas ceilings are the
/// constants an owner is shown on the same screen. What is passed in from here
/// is a view of the owner's own pinned fullnode and nothing else.
///
/// **It is still bounded by the measurement.** The refusal above the drive is
/// unchanged and still reads
/// [`l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready`],
/// which is a constant a human sets *and* a probe that drives the real
/// builders with a real non-Hub key. Neither alone opens this command.
///
/// **One press, then honesty.** Each pass makes at most one unit of progress,
/// so one press drives as far as the chain will currently take it and then
/// returns what it is waiting for. Most of an exit is an objection window
/// measured in blocks, which no amount of pressing shortens; the returned
/// object names the block it ends at rather than spinning.
#[tauri::command]
pub async fn agent_wallet_start_hvm_registry_exit(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let manager = require_manager(&state)?;
        let mut manager = manager.lock().await;
        start_hvm_registry_exit(&mut manager, &wallet_id, unix_now()?).await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_start_hvm_registry_exit`] does once the shell has
/// been recognised and the wallet id parsed.
///
/// Split out for one reason: a Tauri command cannot be entered without a real
/// `Webview`, so a command whose whole body lives behind that attribute can
/// only ever be proven by a test that reimplements it — which is the same
/// "the only caller is a test" failure one layer up. Everything that decides
/// anything is here, and the on-chain proof enters through this function, so
/// the sequence a person triggers and the sequence a test drives are the same
/// code and not two copies of it.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn start_hvm_registry_exit(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> Result<Value, String> {
    let overview = manager
        .overview(wallet_id, now)
        .await
        .map_err(public_error)?;
    let overview = serde_json::to_value(overview)
        .map_err(|_| "Agent Wallet response encoding failed".to_owned())?;
    let Some(binding) = overview
        .get("hvm_registry_binding")
        .filter(|value| !value.is_null())
        .cloned()
    else {
        return Err("this Agent Wallet has no provider channel to close".to_owned());
    };
    let started_steps = manager
        .hvm_registry_exit_steps(wallet_id, now)
        .unwrap_or_default();
    let status = registry_exit_status_value(&overview, started_steps).await;
    if status["driver_ready"] != Value::Bool(true) {
        return Err(status["blocked_reason"]
            .as_str()
            .unwrap_or(USER_EXIT_DRIVER_MISSING)
            .to_owned());
    }
    let chain = registry_exit_chain(&overview, &binding)?;
    // One pass makes at most one unit of progress, so a single press would put
    // one transaction on the wire and stop, and an owner would have to press
    // once per step without ever being told that. Pressing therefore drives as
    // far as the chain will currently take it and stops at the genuine wait.
    //
    // The budget exists because a loop that only ends when a remote node says
    // so is a loop a remote node controls. Every pass that does not end the
    // loop has already put a transaction on the wire, so eight is more
    // transactions than a whole exit needs.
    let mut progress = manager
        .advance_hvm_registry_exit(wallet_id, &chain, now)
        .await
        .map_err(public_error)?;
    let mut passes = 1_u8;
    while progress.outcome == "stepped" && passes < EXIT_PASS_BUDGET {
        passes += 1;
        progress = manager
            .advance_hvm_registry_exit(wallet_id, &chain, now)
            .await
            .map_err(public_error)?;
    }
    serde_json::to_value(progress).map_err(|_| "Agent Wallet response encoding failed".to_owned())
}

/// How many driver passes one press of the exit control is allowed to make.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_PASS_BUDGET: u8 = 8;

/// The owner's own pinned fullnode, as the exit driver needs to see it.
///
/// Built from the same two places the lease read above uses — the wallet's
/// `node_url` and the stored binding — so the node this exit is driven against
/// is the node the screen reported on, and not a second one chosen here.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn registry_exit_chain(
    overview: &Value,
    binding: &Value,
) -> Result<crate::agent_registry_exit::FullnodeRegistryExitChain, String> {
    let node_url = overview
        .get("node_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "this wallet is not pinned to a fullnode yet".to_owned())?;
    let contract = binding
        .get("recovery_bundle")
        .and_then(|bundle| bundle.get("binding"))
        .cloned()
        .unwrap_or(Value::Null);
    let contract: l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2 =
        serde_json::from_value(contract)
            .map_err(|error| format!("stored channel binding is unreadable: {error}"))?;
    crate::agent_registry_exit::FullnodeRegistryExitChain::new(
        node_url,
        contract,
        binding
            .get("minimum_required_live_blocks")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        binding
            .get("minimum_required_recover_blocks")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

/// The one sentence an owner is given when their money is reachable on chain
/// and unreachable from this wallet.
///
/// It never says the money is lost, because it is not, and it never says the
/// provider is required, because the contract does not require one. It names
/// the missing piece as this software's own gap, which is what it is.
///
/// It used to name the wrong gap. It said the builders "still refuse any signer
/// that is not the provider", and that stopped being true: the exit now runs
/// end to end on a real chain, signed by the user's own key, with the Hub's
/// process aborted. Leaving that sentence up would have understated what the
/// owner has — their receipts are not merely valid, they are provably
/// sufficient — and misdirected anyone trying to help them.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const USER_EXIT_DRIVER_MISSING: &str = "This wallet cannot yet send a channel exit for you. What is missing is only this app's part: the exit itself is finished and tested, and it recovers your money with your own key while your provider is switched off. Your deposit is not lost, your receipts are still valid, and your provider cannot spend or block them. The one thing worth doing while you wait is keeping this channel's record on chain from expiring, because that is the only part of this that cannot be undone later.";

/// Builds the exit status from an already serialized overview.
///
/// Split out so both commands read exactly the same facts, and so the lease
/// read has one home rather than two that could drift.
#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn registry_exit_status_value(
    overview: &Value,
    started_steps: Vec<agent_wallet_core::AgentHvmRegistryExitStepProgress>,
) -> Value {
    let driver_ready = l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready();
    let binding = overview
        .get("hvm_registry_binding")
        .filter(|value| !value.is_null());
    let spendable_l1_zhu = overview
        .get("available_units")
        .and_then(Value::as_str)
        .and_then(|units| units.parse::<u64>().ok())
        .unwrap_or(0);
    let lease = match binding {
        Some(binding) => read_registry_lease(overview, binding).await,
        None => (None, "this wallet has no provider channel".to_owned()),
    };
    exit_status_json(driver_ready, spendable_l1_zhu, lease, started_steps)
}

/// The status object itself, with every input already resolved.
///
/// Separated from the read so the one rule that must never slip can be tested
/// without a chain: `blocked_reason` is empty exactly when `driver_ready` is
/// true. A status that says an exit is unavailable and gives no reason is the
/// failure this whole screen exists to end.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn exit_status_json(
    driver_ready: bool,
    spendable_l1_zhu: u64,
    (lease, lease_read_error): (Option<RegistryLease>, String),
    started_steps: Vec<agent_wallet_core::AgentHvmRegistryExitStepProgress>,
) -> Value {
    json!({
        "driver_ready": driver_ready,
        "blocked_reason": if driver_ready { "" } else { USER_EXIT_DRIVER_MISSING },
        "lease_blocks_remaining": lease.map(|lease| lease.live_blocks),
        "lease_recover_blocks_remaining": lease.map(|lease| lease.recover_blocks),
        "lease_read_error": lease_read_error,
        "fullnode_reachable": lease.is_some(),
        "spendable_l1_zhu": spendable_l1_zhu,
        "required_l1_fee_zhu": EXIT_FEE_CEILING_ZHU,
        // Broken out so the screen can say what one more transaction costs
        // without doing arithmetic of its own, and so the gas half is nameable
        // rather than folded invisibly into a single figure. A lease renewal
        // or a re-sent step is exactly one more of these.
        "chain_transaction_count": EXIT_CHAIN_TRANSACTION_COUNT,
        "per_transaction_ceiling_zhu":
            agent_wallet_core::agent_registry_exit_transaction_ceiling_zhu(),
        "per_transaction_network_fee_zhu": agent_wallet_core::AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU,
        "per_transaction_gas_reserve_zhu": agent_wallet_core::agent_registry_exit_gas_reserve_zhu(),
        // Empty exactly when no step of an exit has ever been opened for this
        // channel, which is the only case in which the screen may speak about
        // starting one. Read from this wallet's own durable record; no chain
        // and no provider is involved.
        "started_steps": started_steps,
    })
}

/// Both halves of a storage lease, because only both together decide whether a
/// deposit is still reachable.
///
/// `live_blocks` is how long the channel's keys stay *active*. When it runs out
/// they do not vanish: the contract buys every channel key a recovery buffer at
/// the moment it takes custody, so the record goes dormant and any address at
/// all can restore it by paying rent for `recover_blocks` more. Only when both
/// are exhausted is the record destroyed and the deposit unreachable by
/// everyone, forever.
///
/// Reporting only the first number - which is what this did - made the screen
/// say "cannot be recovered by anyone" roughly six and a half times sooner than
/// it is true. That is the wrong direction to be wrong in on the one screen a
/// person reads when they think their money is gone.
#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Clone, Copy)]
struct RegistryLease {
    live_blocks: u64,
    recover_blocks: u64,
}

/// The channel's remaining storage lease, straight from the fullnode.
///
/// This is the only number on the exit screen that decides whether money can
/// still be recovered at all: when a registry channel's contract keys expire
/// the deposit becomes unreachable for everyone, the owner and the provider
/// alike. So it is read rather than assumed, and a read that fails is reported
/// as a failed read rather than smoothed into a reassuring number.
///
/// The query behind `hvm_registry_runtime_snapshot` needs only the contract,
/// the deployment and the channel's left address, all of which are inside the
/// binding this wallet already holds.
#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn read_registry_lease(overview: &Value, binding: &Value) -> (Option<RegistryLease>, String) {
    let Some(node_url) = overview.get("node_url").and_then(Value::as_str) else {
        return (
            None,
            "this wallet is not pinned to a fullnode yet".to_owned(),
        );
    };
    let contract = binding
        .get("recovery_bundle")
        .and_then(|bundle| bundle.get("binding"))
        .cloned()
        .unwrap_or(Value::Null);
    let contract: l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2 =
        match serde_json::from_value(contract) {
            Ok(binding) => binding,
            Err(error) => {
                return (
                    None,
                    format!("stored channel binding is unreadable: {error}"),
                );
            }
        };
    let minimum_live = binding
        .get("minimum_required_live_blocks")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let minimum_recover = binding
        .get("minimum_required_recover_blocks")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let client = match l2_fast_pay_hub::node::NodeClient::new(node_url) {
        Ok(client) => client,
        Err(error) => return (None, error.to_string()),
    };
    match client
        .hvm_registry_runtime_snapshot(&contract, minimum_live, minimum_recover)
        .await
    {
        Ok(snapshot) => (
            Some(RegistryLease {
                live_blocks: snapshot.minimum_live_blocks,
                recover_blocks: snapshot.minimum_recover_blocks,
            }),
            String::new(),
        ),
        Err(error) => (None, error.to_string()),
    }
}

#[tauri::command]
pub async fn agent_wallet_list_pending_approvals(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Vec<PaymentOperationView>, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .list_pending_approvals_admin(&wallet_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_revoke_agent(
    wallet_id: String,
    agent_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let agent_id = AgentId::parse(agent_id).map_err(|error| error.to_string())?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .revoke_agent(&wallet_id, &agent_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_pending_approval(
    wallet_id: String,
    operation_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<ApprovalCommitment, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
    let manager = require_manager(&state)?;
    manager
        .lock()
        .await
        .pending_approval(&wallet_id, &operation_id, unix_now()?)
        .map_err(public_error)
}

#[tauri::command]
pub async fn agent_wallet_approve_desktop(
    wallet_id: String,
    approval: ApprovalCommitment,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    let operation = manager
        .lock()
        .await
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now()?)
        .await
        .map_err(public_error)?;
    serde_json::to_value(operation).map_err(|_| "Agent Wallet response encoding failed".into())
}

#[tauri::command]
pub async fn agent_wallet_reject(
    wallet_id: String,
    operation_id: String,
    approval_mode: ApprovalMode,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let operation_id = OperationId::parse(operation_id).map_err(|error| error.to_string())?;
    let manager = require_manager(&state)?;
    let operation = manager
        .lock()
        .await
        .reject_payment(&wallet_id, &operation_id, approval_mode, unix_now()?)
        .map_err(public_error)?;
    serde_json::to_value(operation).map_err(|_| "Agent Wallet response encoding failed".into())
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_status(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let offer = state
        .companion
        .pairing_status(&wallet_id, require_manager(&state)?)
        .await?;
    serde_json::to_value(offer).map_err(|_| "mobile pairing status encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_companion_devices(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let manager = require_manager(&state)?;
    let devices = manager
        .lock()
        .await
        .list_companion_devices(&wallet_id, unix_now()?)
        .map_err(public_error)?
        .into_iter()
        .filter(|record| record.role == DeviceRole::Mobile)
        .collect::<Vec<_>>();
    serde_json::to_value(devices).map_err(|_| "mobile device list encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_companion_revoke_device(
    wallet_id: String,
    device_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let device_id = DeviceId::parse(device_id).map_err(|error| error.to_string())?;
    let _transition = state.transition.lock().await;
    let manager = require_manager(&state)?;
    let is_active_mobile = manager
        .lock()
        .await
        .list_companion_devices(&wallet_id, unix_now()?)
        .map_err(public_error)?
        .into_iter()
        .any(|record| {
            record.device_id == device_id
                && record.role == DeviceRole::Mobile
                && !record.is_revoked()
        });
    if !is_active_mobile {
        return Err("active mobile companion device not found".to_owned());
    }
    state.companion.request_shutdown(&wallet_id)?;
    state.companion.stop(&wallet_id).await?;
    let _ = state
        .companion
        .cancel_pairing(&wallet_id, Arc::clone(&manager))
        .await;
    let revoked = manager
        .lock()
        .await
        .revoke_companion_device_locally(&wallet_id, &device_id, unix_now()?)
        .map_err(public_error)?;
    serde_json::to_value(revoked).map_err(|_| "mobile device response encoding failed".to_owned())
}

#[tauri::command]
pub fn agent_wallet_companion_pairing_suggest_endpoint(webview: Webview) -> Result<String, String> {
    require_wallet_shell(&webview)?;
    crate::companion_runtime::suggest_private_lan_endpoint().map(|endpoint| endpoint.to_string())
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_start(
    wallet_id: String,
    private_lan_endpoint: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let endpoint = LanEndpoint::parse(&private_lan_endpoint).map_err(|error| error.to_string())?;
    let offer = state
        .companion
        .start_pairing(wallet_id, endpoint, require_manager(&state)?)
        .await?;
    serde_json::to_value(offer).map_err(|_| "mobile pairing offer encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_rotation_candidate_pairing_start(
    wallet_id: String,
    rotation_id: String,
    private_lan_endpoint: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let endpoint =
            LanEndpoint::parse(&private_lan_endpoint).map_err(|error| error.to_string())?;
        let offer = state
            .companion
            .start_rotation_candidate_pairing(
                wallet_id,
                rotation_id,
                endpoint,
                require_manager(&state)?,
            )
            .await?;
        serde_json::to_value(offer)
            .map_err(|_| "rotation candidate offer encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, rotation_id, private_lan_endpoint, state);
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_accept_request(
    wallet_id: String,
    request: PairingRequest,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let confirmation = state
        .companion
        .accept_pairing_request(&wallet_id, request, require_manager(&state)?)
        .await?;
    serde_json::to_value(confirmation)
        .map_err(|_| "mobile pairing confirmation encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_rotation_candidate_pairing_accept_request(
    wallet_id: String,
    request: PairingRequest,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let (confirmation, ticket) = state
            .companion
            .accept_rotation_candidate_request(&wallet_id, request, require_manager(&state)?)
            .await?;
        Ok(json!({ "confirmation": confirmation, "ticket": ticket }))
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, request, state);
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_complete(
    wallet_id: String,
    encrypted_ack: EncryptedCompanionFrame,
    verification_code: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let record = state
        .companion
        .complete_pairing(
            &wallet_id,
            Some(&encrypted_ack),
            &verification_code,
            require_manager(&state)?,
        )
        .await?;
    serde_json::to_value(record).map_err(|_| "mobile device record encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_complete_automatic(
    wallet_id: String,
    verification_code: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let record = state
        .companion
        .complete_pairing(
            &wallet_id,
            None,
            &verification_code,
            require_manager(&state)?,
        )
        .await?;
    serde_json::to_value(record).map_err(|_| "mobile device record encoding failed".to_owned())
}

#[tauri::command]
pub async fn agent_wallet_rotation_candidate_pairing_complete(
    wallet_id: String,
    encrypted_ack: EncryptedCompanionFrame,
    verification_code: String,
    signed_acceptance: SignedRotationCandidateAcceptance,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let record = state
            .companion
            .complete_rotation_candidate_pairing(
                &wallet_id,
                &encrypted_ack,
                &verification_code,
                signed_acceptance,
                require_manager(&state)?,
            )
            .await?;
        serde_json::to_value(record)
            .map_err(|_| "rotation candidate record encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (
            wallet_id,
            encrypted_ack,
            verification_code,
            signed_acceptance,
            state,
        );
        Err("witness rotation is disabled in this build".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_cancel(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    state
        .companion
        .cancel_pairing(&wallet_id, require_manager(&state)?)
        .await
}

#[tauri::command]
pub async fn agent_wallet_companion_status(
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let status = state.companion.status().await;
    Ok(match status {
        Some(status) => json!({
            "enabled": true,
            "walletId": status.wallet_id,
            "localAddress": status.local_addr.to_string(),
            "phase": status.phase,
            "transport": "encrypted_private_lan",
        }),
        None => json!({
            "enabled": false,
            "walletId": Value::Null,
            "localAddress": Value::Null,
            "phase": "stopped",
            "transport": "encrypted_private_lan",
        }),
    })
}

#[tauri::command]
pub async fn agent_wallet_companion_start(
    wallet_id: String,
    private_lan_bind: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    let bind_addr = private_lan_bind
        .parse()
        .map_err(|_| "enter an exact private-LAN IP and port".to_owned())?;
    let status = state
        .companion
        .start(wallet_id, bind_addr, require_manager(&state)?)
        .await?;
    Ok(json!({
        "enabled": true,
        "walletId": status.wallet_id,
        "localAddress": status.local_addr.to_string(),
            "phase": status.phase,
        "transport": "encrypted_private_lan",
    }))
}

#[tauri::command]
pub async fn agent_wallet_companion_stop(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let wallet_id = parse_wallet_id(wallet_id)?;
    let _transition = state.transition.lock().await;
    state.companion.stop(&wallet_id).await
}
// Keep agent-created payment intents out of Tauri. The trusted desktop UI only
// approves or rejects intents received through the authenticated connector.
const _: Option<AgentPaymentRequest> = None;

fn manager_arc(
    state: &tauri::State<'_, AgentAppState>,
) -> Option<Arc<Mutex<agent_wallet_core::AgentWalletManager>>> {
    state.inner.as_ref().map(Arc::clone)
}

fn require_manager(
    state: &tauri::State<'_, AgentAppState>,
) -> Result<Arc<Mutex<agent_wallet_core::AgentWalletManager>>, String> {
    manager_arc(state)
        .ok_or_else(|| "Agent Wallet is unavailable; My Wallet remains available".into())
}

fn parse_wallet_id(raw: String) -> Result<AgentWalletId, String> {
    AgentWalletId::parse(raw).map_err(|error| error.to_string())
}

fn runtime_status_value(status: Option<(AgentWalletId, RuntimeStatus)>) -> Value {
    match status {
        Some((wallet_id, status)) => runtime_value(Some(wallet_id), status),
        None => runtime_value(None, RuntimeStatus::default()),
    }
}

fn runtime_value(wallet_id: Option<AgentWalletId>, status: RuntimeStatus) -> Value {
    json!({
        "phase": phase_name(status.phase),
        "walletId": wallet_id,
        "endpoint": status.endpoint,
        "lastError": status.last_error,
    })
}

const TRUSTED_DESKTOP_DEBUG_PORT: u16 = 1420;

fn require_wallet_shell(webview: &Webview) -> Result<(), String> {
    if webview.label() != "main" {
        return Err("command is restricted to the wallet UI".into());
    }
    let url = webview.url().map_err(|error| error.to_string())?;
    let local_shell = url.scheme() == "tauri"
        || url.host_str() == Some("tauri.localhost")
        || (cfg!(debug_assertions)
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
            && url.port() == Some(TRUSTED_DESKTOP_DEBUG_PORT));
    if !local_shell {
        return Err("wallet UI is not on a trusted local origin".into());
    }
    Ok(())
}

fn public_error(error: agent_wallet_core::AgentWalletError) -> String {
    error.to_string()
}

fn unix_now() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn tauri_surface_has_no_agent_raw_sign_or_personal_wallet_bridge() {
        let source = include_str!("agent_commands.rs");
        for forbidden in [
            "agent_wallet_sign_raw",
            "agent_wallet_export_private_key",
            "agent_wallet_send_raw",
            "agent_wallet_call_personal",
            "agent_wallet_open_channel",
            "agent_wallet_create_payment",
            "agent_wallet_register_agent",
        ] {
            assert!(!source.contains(&format!("fn {forbidden}")));
        }
    }

    #[test]
    fn lifecycle_transitions_share_one_cross_command_lock() {
        let source = include_str!("agent_commands.rs");
        for name in [
            "agent_wallet_runtime_start",
            "agent_wallet_runtime_stop",
            "agent_wallet_pairing_activate",
            "agent_wallet_pairing_approve",
            "agent_wallet_pairing_reject",
            "agent_wallet_create",
            "agent_wallet_unlock",
            "agent_wallet_lock",
            "agent_wallet_enable_payments",
            "agent_wallet_emergency_stop",
            "agent_wallet_companion_pairing_start",
            "agent_wallet_companion_pairing_accept_request",
            "agent_wallet_companion_pairing_complete",
            "agent_wallet_companion_pairing_complete_automatic",
            "agent_wallet_companion_pairing_cancel",
            "agent_wallet_companion_start",
            "agent_wallet_companion_stop",
            "agent_wallet_companion_revoke_device",
        ] {
            let start = source
                .find(&format!("pub async fn {name}("))
                .unwrap_or_else(|| panic!("missing lifecycle command {name}"));
            let tail = &source[start..];
            let end = tail.find("#[tauri::command]").unwrap_or(tail.len());
            assert!(
                tail[..end].contains("state.transition.lock().await"),
                "{name} must hold the shared Agent lifecycle transition lock"
            );
        }
    }
    #[test]
    fn desktop_debug_origin_matches_the_tauri_dev_url_exactly() {
        let source = include_str!("agent_commands.rs");
        let config = include_str!("../../../apps/desktop/src-tauri/tauri.conf.json");
        assert!(source.contains("const TRUSTED_DESKTOP_DEBUG_PORT: u16 = 1420;"));
        assert!(source.contains("url.port() == Some(TRUSTED_DESKTOP_DEBUG_PORT)"));
        assert!(config.contains("http://127.0.0.1:1420"));
    }
    #[test]
    fn every_tauri_agent_command_has_a_trusted_shell_guard() {
        let source = include_str!("agent_commands.rs");
        let command_count = source
            .lines()
            .filter(|line| line.trim() == "#[tauri::command]")
            .count();
        let guard_count = source
            .lines()
            .filter(|line| line.trim() == "require_wallet_shell(&webview)?;")
            .count();
        assert_eq!(guard_count, command_count);
    }

    /// The exit gate the desktop renders must be the project's own
    /// measurement, not a literal typed into the wallet shell.
    ///
    /// `measure_user_side_unilateral_exit_ready` drives the real registry
    /// transaction builders with a real non-Hub key. It cannot be satisfied by
    /// configuration or by an operator saying so, and the day the builders
    /// become role aware it starts answering `true` on its own. This test
    /// exists so that no one can quietly replace it with a constant.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn the_exit_gate_is_the_measurement_and_never_a_literal() {
        let measured = l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready();
        let status = super::exit_status_json(measured, 0, (None, String::new()), Vec::new());
        assert_eq!(status["driver_ready"], serde_json::json!(measured));
        // Today that measurement is false, because the only builders in this
        // workspace refuse every signer that is not the Hub. If this assertion
        // ever fails, the exit became buildable and this command's refusal is
        // the thing that now needs replacing with a real driver.
        assert!(!measured, "the user-side exit builders became available");
        let source = include_str!("agent_commands.rs");
        assert!(
            source.contains(
                "let driver_ready = l2_fast_pay_hub::readiness::measure_user_side_unilateral_exit_ready();"
            ),
            "the exit status must read the measurement directly"
        );
    }

    /// A refusal without a reason is what strands a person.
    ///
    /// Whenever the exit is unavailable the status has to carry the sentence
    /// the desktop then renders beside the withheld control, and that sentence
    /// has to say that the money is still there.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn an_unavailable_exit_always_carries_its_reason() {
        let blocked = super::exit_status_json(false, 0, (None, String::new()), Vec::new());
        let reason = blocked["blocked_reason"].as_str().expect("a reason");
        assert!(reason.len() > 80, "the reason must be a sentence");
        // It must reassure about the deposit and name the one thing that is
        // actually urgent, in words an owner reads rather than in ours.
        assert!(reason.contains("not lost"));
        assert!(reason.contains("expiring"));
        // And it must not blame the provider for this build's own gap. The
        // exit works; only this app's send path is missing.
        assert!(
            !reason.contains("refuses any signer"),
            "the builders are role aware and the exit is proven on chain; this sentence              must not still describe them as refusing the owner"
        );
        assert_eq!(blocked["fullnode_reachable"], serde_json::json!(false));

        let ready = super::exit_status_json(
            true,
            0,
            (
                Some(super::RegistryLease {
                    live_blocks: 9_999,
                    recover_blocks: 55_000,
                }),
                String::new(),
            ),
            Vec::new(),
        );
        assert_eq!(ready["blocked_reason"], serde_json::json!(""));
        assert_eq!(ready["lease_blocks_remaining"], serde_json::json!(9_999));
        assert_eq!(ready["fullnode_reachable"], serde_json::json!(true));
        // Both halves must reach the screen. Reporting only the live half made
        // the exit page tell owners their deposit was unrecoverable while it
        // still had a dormant-but-restorable window roughly six times longer
        // than the one that had just run out.
        assert_eq!(
            ready["lease_recover_blocks_remaining"],
            serde_json::json!(55_000)
        );
    }

    /// The start command must never reach the driver while the gate is closed.
    ///
    /// This is the shape of failure this project has shipped twice: a
    /// mechanism whose only caller was a test. Here the caller is the desktop
    /// Security page, and this pins the other end, so the refusal cannot be
    /// removed without also removing the measurement it reads.
    ///
    /// **What changed and why this is not weaker.** The command used to end in
    /// an unconditional `Err(USER_EXIT_DRIVER_MISSING)`, and this test pinned
    /// that literal. It no longer does, because the command now actually
    /// drives the exit — so the assertion moved from "the command always
    /// refuses" to the thing that statement was standing in for: **the
    /// measurement is read, and the refusal it produces comes strictly before
    /// anything that could sign.** A literal cannot satisfy that ordering, and
    /// deleting the gate does not make it pass.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn the_start_command_refuses_while_the_gate_is_closed() {
        let source = include_str!("agent_commands.rs");
        let command = source
            .split("pub async fn agent_wallet_start_hvm_registry_exit")
            .nth(1)
            .expect("the start command")
            .split("/// Everything [`agent_wallet_start_hvm_registry_exit`] does")
            .next()
            .expect("the command body");
        // The exit is irreversible, so it is serialised against every other
        // irreversible transition exactly as it always was.
        assert!(command.contains("state.transition.lock().await"));
        assert!(command.contains("start_hvm_registry_exit(&mut manager, &wallet_id"));

        let body = source
            .split("pub async fn start_hvm_registry_exit")
            .nth(1)
            .expect("the start body")
            .split("/// How many driver passes one press")
            .next()
            .expect("the start body");
        let gate = body
            .find("status[\"driver_ready\"] != Value::Bool(true)")
            .expect("the measured gate is read");
        let refusal = body
            .find("USER_EXIT_DRIVER_MISSING")
            .expect("a closed gate refuses in the owner's own words");
        let drive = body
            .find("advance_hvm_registry_exit")
            .expect("an open gate drives the shipped driver");
        assert!(
            gate < refusal && refusal < drive,
            "the measured gate and its refusal must both come before anything that can sign"
        );
        // The gate is measured from the same overview the screen was built
        // from, and never from a second read that could disagree with it.
        assert!(body.contains("registry_exit_status_value(&overview,"));
        assert!(
            !body.contains("build_signed_hvm_registry"),
            "the wallet shell must not grow its own transaction builder"
        );
    }

    #[test]
    fn emergency_route_is_marker_first_then_runtime_then_manager() {
        let source = include_str!("agent_commands.rs");
        let body = source
            .split("pub async fn agent_wallet_emergency_stop")
            .nth(1)
            .unwrap()
            .split("#[tauri::command]")
            .next()
            .unwrap();
        let marker = body.find("controller.request_stop()").unwrap();
        let runtime = body.find("state.runtime.request_shutdown").unwrap();
        let manager = body.find("require_manager(&state)").unwrap();
        assert!(marker < runtime && runtime < manager);
    }
}
