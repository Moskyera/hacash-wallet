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
    // Boxed so this state machine is on the heap rather than on the thread
    // that dispatches the IPC message. Unboxed it was 23,856 bytes, which the
    // release binary reserves about 836,000 bytes of stack for once the 24.1x
    // spawn plumbing and the dispatch frame are counted, out of 1,048,576.
    // Nothing below changed. See `agent_command_stack_budget.rs`.
    Box::pin(async move {
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
    })
    .await
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

/// Forget one channel-setup review that was never confirmed.
///
/// Owner-shell only, like the other three. There is deliberately no
/// companion or agent surface for this: a paired phone or an AI agent must
/// never be able to make the wallet forget a channel it may be opening.
#[tauri::command]
pub async fn agent_wallet_discard_fast_pay_channel_setup(
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
            .discard_unsigned_l2_channel_setup(
                &wallet_id,
                &operation_id,
                &review_commitment,
                unix_now()?,
            )
            .map_err(public_error)?;
        serde_json::to_value(review).map_err(|_| "Agent channel discard encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, review_commitment, state);
        Err("Agent channel setup is disabled in this build".to_owned())
    }
}

/// Retire one channel-setup review whose signed request is provably dead.
///
/// The companion to the discard, for the state the discard cannot touch: a
/// signature exists, its request envelope has closed, and nothing ever came
/// back from the Hub or the chain. Owner-shell only, for the same reason the
/// discard is: a paired phone or an AI agent must never be able to make the
/// wallet forget a channel it may be opening.
#[tauri::command]
pub async fn agent_wallet_abandon_dead_fast_pay_channel_setup(
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
            .abandon_dead_l2_channel_setup(
                &wallet_id,
                &operation_id,
                &review_commitment,
                unix_now()?,
            )
            .await
            .map_err(public_error)?;
        serde_json::to_value(review)
            .map_err(|_| "Agent channel abandonment encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, review_commitment, state);
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

/// The one countersigned delta-zero close this channel holds, if it holds one.
///
/// Read-only. It reaches no Hub and no node.
#[tauri::command]
pub async fn agent_wallet_fast_pay_channel_voucher(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let voucher = require_manager(&state)?
            .lock()
            .await
            .l2_channel_close_voucher(&wallet_id, unix_now()?)
            .map_err(public_error)?;
        serde_json::to_value(voucher).map_err(|_| "Agent channel exit encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent channel close is disabled in this build".to_owned())
    }
}

/// Ask the Hub for this channel's one close voucher, or resume asking.
///
/// Normally the channel open does this by itself the moment it confirms. This
/// is the retry for when that request did not get through, and it is the only
/// way to obtain a voucher: there is no refresh, and a channel that already
/// has one is served the same bytes rather than a second signed close.
#[tauri::command]
pub async fn agent_wallet_take_fast_pay_channel_voucher(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let voucher = require_manager(&state)?
            .lock()
            .await
            .take_l2_channel_close_voucher(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(voucher).map_err(|_| "Agent channel exit encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent channel close is disabled in this build".to_owned())
    }
}

/// Broadcast the held close voucher from the wallet's own node.
///
/// This path never contacts the Hub, for anything. It is what the voucher is
/// for: the Hub countersigned once, at the start, and after that the owner
/// does not need it again.
#[tauri::command]
pub async fn agent_wallet_broadcast_fast_pay_channel_voucher(
    wallet_id: String,
    webview: Webview,
    state: tauri::State<'_, AgentAppState>,
) -> Result<Value, String> {
    require_wallet_shell(&webview)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        let wallet_id = parse_wallet_id(wallet_id)?;
        let _transition = state.transition.lock().await;
        let voucher = require_manager(&state)?
            .lock()
            .await
            .broadcast_l2_channel_close_voucher(&wallet_id, unix_now()?)
            .await
            .map_err(public_error)?;
        serde_json::to_value(voucher).map_err(|_| "Agent channel exit encoding failed".to_owned())
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
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
    // Boxed so this state machine is on the heap rather than on the thread
    // that dispatches the IPC message. Unboxed it was 29,496 bytes, which the
    // release binary reserves about 972,000 bytes of stack for once the 24.1x
    // spawn plumbing and the dispatch frame are counted, out of 1,048,576:
    // 93% of the thread, on a path that signs a bill and then submits it.
    // Nothing below changed. See `agent_command_stack_budget.rs`.
    Box::pin(async move {
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            let wallet_id = parse_wallet_id(wallet_id)?;
            let operation_id =
                OperationId::parse(operation_id).map_err(|error| error.to_string())?;
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
    })
    .await
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

/// How many chain transactions opening a registry channel sends from the
/// owner's own balance: `init` and the funding transfer.
///
/// The deployment is the provider's, paid for by the provider, and is already
/// on chain before an owner ever sees this screen.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_CHAIN_TRANSACTION_COUNT: u64 = 2;

/// Everything opening a channel can take out of the owner's main balance on
/// top of the deposit.
///
/// Built from the same per-transaction ceiling the exit quotes, and for the
/// same reason: an `init` is an HVM contract call, and the chain takes the
/// whole gas budget out of the main balance with `hac_sub` before the call
/// runs, refunding the unused part afterwards. Quoting the network fee alone
/// understated a measured exit by a factor of ten, and an owner who holds
/// exactly a quote that is too small watches an affordability check go green
/// and then cannot pay for the first transaction.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_FEE_CEILING_ZHU: u64 =
    agent_wallet_core::agent_registry_exit_transaction_ceiling_zhu() * OPEN_CHAIN_TRANSACTION_COUNT;

/// What this wallet can see about opening a channel with one provider, before
/// anything is asked of that provider and before anything is signed.
///
/// It is a read. Nothing here signs, nothing here funds, and a failure of any
/// part of it costs the owner nothing, which is why the screen it feeds may
/// state a refusal plainly rather than hiding the control.
#[tauri::command]
pub async fn agent_wallet_hvm_registry_open_status(
    wallet_id: String,
    hub_url: String,
    deposit_zhu: u64,
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
        let overview =
            serde_json::to_value(overview).map_err(|_| "Agent Wallet response encoding failed")?;
        let in_progress = manager
            .hvm_registry_channel_open(&wallet_id, now)
            .map_err(public_error)?;
        Ok(
            registry_open_status_value(&overview, &hub_url, deposit_zhu, in_progress.as_ref())
                .await,
        )
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, deposit_zhu, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// Opens one provider channel: the wallet left-signs a bill returning its
/// entire deposit, the provider countersigns it, this wallet verifies that
/// countersignature against its own binding, and the whole thing is made
/// durable before any money is allowed anywhere near the channel.
///
/// **The order is the product, not a preference.** The chain cannot enforce it:
/// `PayableHAC` accepts a correctly sized transfer from the left address while
/// the channel is in FUNDING and has no view of any off-chain signature. So it
/// is enforced by there being no way to spell "funding" without first holding
/// a value that only a verified countersigned refund can produce. Both doors
/// carry that check on their first line:
/// [`agent_wallet_core::AgentWalletManager::hvm_registry_funding_authorization`],
/// whose only constructor is
/// `hacash_wallet_core::hvm_registry_open::authorize_registry_funding`, and
/// `l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_exact_funding`,
/// which derives the contract, the Hub and the amount from the bundle rather
/// than from its arguments.
///
/// **What this command may not choose.** Not the channel and not the amount.
/// The binding is the *wallet's* statement of the channel and the Hub gets no
/// field through which to restate any of it, and the deposit the owner typed is
/// compared with the deposit inside that binding here, before anything is
/// signed. A pasted channel description that quietly names a larger deposit
/// than the screen showed is refused by this command rather than by the owner's
/// attention.
///
/// **A provider that refuses costs nothing.** The whole exchange happens before
/// any funding transaction is built, so a refusal leaves no channel, no
/// reservation and no fee, and `RegistryOpenHubRefused` says so in those words.
#[tauri::command]
pub async fn agent_wallet_open_hvm_registry_channel(
    wallet_id: String,
    hub_url: String,
    binding: Value,
    deposit_zhu: u64,
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
        open_hvm_registry_channel(
            &mut manager,
            &wallet_id,
            &hub_url,
            binding,
            deposit_zhu,
            unix_now()?,
        )
        .await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, binding, deposit_zhu, state);
        Err("Agent HVM registry Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_open_hvm_registry_channel`] does once the shell
/// has been recognised and the wallet id parsed.
///
/// Split out for the same reason the exit is: a Tauri command cannot be entered
/// without a real `Webview`, so a command whose whole body lives behind that
/// attribute can only ever be proven by a test that reimplements it, which is
/// the "the only caller is a test" failure one layer up. Everything that
/// decides anything is here, so the sequence a person triggers and the sequence
/// a test drives are the same code and not two copies of it.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn open_hvm_registry_channel(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    hub_url: &str,
    binding: Value,
    deposit_zhu: u64,
    now: u64,
) -> Result<Value, String> {
    let binding: l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2 =
        serde_json::from_value(binding).map_err(|error| {
            format!(
                "{OPEN_CHANNEL_UNREADABLE} No channel was opened and no money has moved. ({error})"
            )
        })?;
    binding.validate().map_err(|error| {
        format!("{OPEN_CHANNEL_UNREADABLE} No channel was opened and no money has moved. ({error})")
    })?;
    // The owner typed an amount and the pasted channel carries one. They are
    // two independent statements of the same fact and this is the only place
    // they can be compared, because from here on the deposit is read out of the
    // binding by everything that touches it.
    if binding.left_deposit_zhu != deposit_zhu {
        return Err(OPEN_CHANNEL_DEPOSIT_MISMATCH.to_owned());
    }
    // The wallet's own pinned fullnode, and nothing the provider supplied.
    //
    // Everything the wallet is about to do turns on whether the contract this
    // channel names is really the reviewed registry, on this wallet's chain,
    // carrying this exact unfunded channel. Only a node can answer that, and
    // until this argument existed the answer was never asked for: a reviewer
    // took a full deposit through the gap, on chain, with an entirely honest
    // provider.
    let chain = registry_open_chain(manager, wallet_id, now).await?;
    let bundle = manager
        .open_hvm_registry_channel(wallet_id, hub_url, binding, &chain, now)
        .await
        .map_err(public_error)?;
    // Re-derived, never assumed. The value this returns is the only permission
    // to fund that exists anywhere in this tree, and asking for it here means
    // the answer this command reports is the same answer funding will get.
    let authorization = manager
        .hvm_registry_funding_authorization(wallet_id, &chain, now)
        .await
        .map_err(public_error)?;
    // Two facts, from two different places, about the money. The authorization
    // is derived from the stored bundle; the deposit is what the owner was
    // shown. A disagreement here is not something to report as a success.
    if authorization.amount_zhu() != deposit_zhu
        || authorization.contract_address() != bundle.binding.contract_address
        || authorization.hub_address() != bundle.binding.right_hub_address
    {
        return Err(OPEN_CHANNEL_DEPOSIT_MISMATCH.to_owned());
    }
    Ok(json!({
        "schema": "hpay-agent-registry-open-result/1",
        "binding_commitment": authorization.binding_commitment(),
        "hub_url": hub_url,
        "hub_address": authorization.hub_address(),
        "contract_address": authorization.contract_address(),
        "deposit_zhu": deposit_zhu,
        // Read out of the countersigned bill rather than echoed from the
        // request, so the screen reports what the provider actually signed.
        "refunded_zhu": bundle.initial_recovery_bill.left_balance_zhu,
        "refund_bill_commitment": authorization.refund_bill_commitment(),
        // True exactly when this wallet holds a refund that would authorise
        // funding. It is the fact the whole screen is about, and it is derived
        // rather than set.
        "refund_guaranteed": true,
    }))
}

/// The wallet's own pinned fullnode, as opening and funding need to see it.
///
/// Built from the wallet's own recorded `node_url` and network mode. The
/// manager does not take even this on trust: it compares the identity this
/// node reports with the block-1 fingerprint the wallet recorded when it was
/// created, so a node pointed somewhere else cannot supply evidence about
/// somewhere else.
#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn registry_open_chain(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> Result<crate::agent_registry_open::FullnodeRegistryOpenChain, String> {
    let overview = manager
        .overview(wallet_id, now)
        .await
        .map_err(public_error)?;
    let overview = serde_json::to_value(overview)
        .map_err(|_| "Agent Wallet response encoding failed".to_owned())?;
    let node_url = overview
        .get("node_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "this wallet is not pinned to a fullnode yet".to_owned())?;
    let network_mode = overview
        .get("network_mode")
        .and_then(Value::as_str)
        .unwrap_or("testnet");
    crate::agent_registry_open::FullnodeRegistryOpenChain::new(node_url, network_mode)
}

/// Put the deposit into the channel this wallet has already been guaranteed a
/// way out of.
///
/// # What one press does, and what it can never do
///
/// It re-derives funding permission from the stored countersigned refund and a
/// live reading of this wallet's own node, signs the exact transfer through
/// `AgentTransactionSigner::sign_exact_registry_funding`, makes those bytes
/// durable **before** any node sees them, and submits them. It cannot choose a
/// destination, an amount or a chain: all three come out of the refund bill the
/// provider signed, and the permission that reaches the signer has private
/// fields, no `Deserialize` and exactly one constructor.
///
/// Pressing again after a crash re-submits the same bytes and looks for them in
/// a block. It never signs a second transfer into one channel.
#[tauri::command]
pub async fn agent_wallet_fund_hvm_registry_channel(
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
        fund_hvm_registry_channel(&mut manager, &wallet_id, unix_now()?).await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent HVM registry Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_fund_hvm_registry_channel`] does once the shell is
/// recognised, split out for the same reason the open and the exit are: so the
/// sequence a person triggers and the sequence a test drives are the same code.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn fund_hvm_registry_channel(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> Result<Value, String> {
    fund_hvm_registry_channel_typed(manager, wallet_id, now)
        .await
        .map_err(|error| match error {
            FundingRefusal::Chain(message) => message,
            FundingRefusal::Wallet(error) => public_error(error),
        })
}

/// Why a funding attempt stopped, in a form a caller can branch on.
///
/// `fund_hvm_registry_channel` flattens this to a sentence for the screen. The
/// establish command must not: "the node refused these bytes" and "the bytes
/// are on the wire and not in a block yet" are the same shape in the durable
/// record and opposite facts about the owner's money, and the only thing that
/// separates them is which error the manager returned.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub enum FundingRefusal {
    /// The wallet could not reach or build against its own fullnode.
    Chain(String),
    /// The manager refused, with the reason it refused for.
    Wallet(agent_wallet_core::AgentWalletError),
}

/// Everything [`fund_hvm_registry_channel`] does, keeping the manager's own
/// error type instead of a sentence.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn fund_hvm_registry_channel_typed(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> Result<Value, FundingRefusal> {
    let chain = registry_open_chain(manager, wallet_id, now)
        .await
        .map_err(FundingRefusal::Chain)?;
    let funding = manager
        .fund_hvm_registry_channel(wallet_id, &chain, now)
        .await
        .map_err(FundingRefusal::Wallet)?;
    Ok(json!({
        "schema": "hpay-agent-registry-funding-result/1",
        "transaction_hash": funding.transaction_hash(),
        "contract_address": funding.contract_address(),
        "deposit_zhu": funding.amount_zhu(),
        "network_fee_zhu": funding.network_fee_zhu(),
        "confirmed": funding.is_confirmed(),
        "confirmed_block_height": funding.confirmed_block_height(),
    }))
}

/// Adopt the funded channel, **without asking the provider anything**.
///
/// # Why this exists at all
///
/// A reviewer drove the trap: an honest countersignature, an honest deposit,
/// and a provider that then vanished. The chain would have paid - the contract
/// accepts the very bill the wallet already stores - but the only writer of the
/// adopted binding needed the provider alive four times, and the exit refuses
/// without that binding. The wallet held the way out and had no path to the
/// chain with it.
///
/// Nothing here is weaker than the provider-assisted adoption: the bundle is
/// the wallet's own, the deposit is one this wallet signed and has seen in a
/// block, and the channel is held to `validate_open_binding`, which is stricter
/// than the runtime check the provider-assisted path applies.
#[tauri::command]
pub async fn agent_wallet_adopt_hvm_registry_channel(
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
        adopt_hvm_registry_channel(&mut manager, &wallet_id, unix_now()?).await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, state);
        Err("Agent HVM registry Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_adopt_hvm_registry_channel`] does once the shell
/// is recognised.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn adopt_hvm_registry_channel(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    now: u64,
) -> Result<Value, String> {
    let chain = registry_open_chain(manager, wallet_id, now).await?;
    let adopted = manager
        .adopt_hvm_registry_channel_from_chain(wallet_id, &chain, now)
        .await
        .map_err(public_error)?;
    Ok(json!({
        "schema": "hpay-agent-registry-adoption-result/1",
        "binding_commitment": adopted.binding_commitment(),
        "hub_address": adopted.hub_address(),
        "hub_url": adopted.hub_url(),
        // True from this moment on: the exit head was seeded in the same
        // journalled transition that wrote the binding.
        "exit_available": true,
    }))
}

/// ONE PRESS THAT TAKES A CHANNEL FROM NOTHING TO USABLE, AND CAN BE PRESSED
/// AGAIN.
///
/// # Why this exists on top of the three commands under it
///
/// Opening a usable channel is three chain-and-provider hops with a genuine
/// wait in the middle, and every one of them has to happen in order or the
/// owner's money is somewhere they cannot reach it. Three separate controls
/// put that ordering in a person's hands: the screen has to know that funding
/// is only legal after a countersigned refund, that adoption is only legal
/// after the deposit is in a block, and what to do when the app is closed
/// between any two of them. A wallet that leaves that to a renderer will
/// eventually get a wallet that funds a channel it cannot adopt.
///
/// So the ordering lives here, in Rust, next to the state that decides it.
///
/// # What one press does
///
/// It reads this wallet's own durable record and does the next thing that has
/// not been done, then keeps going until it either finishes or reaches a wait
/// nothing can shorten. There is exactly one such wait: the deposit being in a
/// block. Pressing again from any point continues from that point.
///
/// * no countersigned refund yet -> ask the provider for one (nothing is
///   funded, nothing is spent, and a provider that refuses costs nothing);
/// * refund held, no deposit in a block -> sign the deposit once, store the
///   bytes before the wire, submit, and report the wait;
/// * deposit in a block, no adopted binding -> adopt from the chain alone,
///   which needs no provider at all;
/// * adopted -> report that the channel is usable and the exit is available.
///
/// # What pressing again can never do
///
/// It can never open a second channel, and it can never sign a second deposit.
/// The first is refused by `begin_hvm_registry_channel_open` once a bundle is
/// countersigned and by this function before that, and the second by
/// `AgentWalletManager::fund_hvm_registry_channel`, which re-submits the exact
/// stored bytes rather than signing new ones. Both of those are proven where
/// they live; what this adds is that a resumed press does not go back to the
/// provider at all once the refund is held, because on the day this matters
/// the provider is the thing that has stopped answering.
///
/// # What it may not choose
///
/// Not the channel and not the amount. Both are compared against the record
/// this wallet already holds before anything continues: a second press
/// carrying a different channel, or the same channel with a different deposit,
/// is refused rather than reconciled.
#[tauri::command]
pub async fn agent_wallet_establish_hvm_registry_channel(
    wallet_id: String,
    hub_url: String,
    binding: Value,
    deposit_zhu: u64,
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
        establish_hvm_registry_channel(
            &mut manager,
            &wallet_id,
            &hub_url,
            binding,
            deposit_zhu,
            unix_now()?,
        )
        .await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, hub_url, binding, deposit_zhu, state);
        Err("Agent HVM registry Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_establish_hvm_registry_channel`] does once the
/// shell has been recognised and the wallet id parsed.
///
/// Split out for the same reason the open, the funding and the exit are: a
/// Tauri command cannot be entered without a real `Webview`, so a command whose
/// whole body lives behind that attribute can only ever be proven by a test
/// that reimplements it, which is the "the only caller is a test" failure one
/// layer up. Everything that decides anything is here, so the sequence a person
/// triggers and the sequence a test drives are the same code and not two copies
/// of it.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn establish_hvm_registry_channel(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    hub_url: &str,
    binding: Value,
    deposit_zhu: u64,
    now: u64,
) -> Result<Value, String> {
    let wanted: l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2 =
        serde_json::from_value(binding.clone()).map_err(|error| {
            format!(
                "{OPEN_CHANNEL_UNREADABLE} No channel was opened and no money has moved. ({error})"
            )
        })?;
    wanted.validate().map_err(|error| {
        format!("{OPEN_CHANNEL_UNREADABLE} No channel was opened and no money has moved. ({error})")
    })?;
    // The same comparison the open command makes, made here too. A gate on one
    // of two doors is this project's own recurring defect, and this is now a
    // second door onto the same irreversible spend.
    if wanted.left_deposit_zhu != deposit_zhu {
        return Err(OPEN_CHANNEL_DEPOSIT_MISMATCH.to_owned());
    }

    // ---- already finished? ----
    //
    // Asked first, because every other stage below would refuse over an
    // adopted channel and refusing is the wrong answer to "is my channel
    // ready". `hvm_registry_binding` is written in the same journalled
    // transition that seeds the exit head, so its presence is exactly the fact
    // the report is about.
    let overview = manager
        .overview(wallet_id, now)
        .await
        .map_err(public_error)?;
    let overview = serde_json::to_value(overview)
        .map_err(|_| "Agent Wallet response encoding failed".to_owned())?;
    if let Some(adopted) = overview
        .get("hvm_registry_binding")
        .filter(|value| !value.is_null())
    {
        let stored = manager
            .hvm_registry_channel_open(wallet_id, now)
            .map_err(public_error)?;
        let funding = stored.as_ref().and_then(|record| record.funding());
        return Ok(establish_progress_json(
            ESTABLISH_STAGE_READY,
            &wanted,
            adopted
                .get("hub_url")
                .and_then(Value::as_str)
                .unwrap_or(hub_url),
            true,
            funding,
        ));
    }

    // ---- stage one: the countersigned full refund ----
    //
    // Skipped entirely when one is already held. This is the resume that
    // matters: after the refund exists the provider has nothing left to do,
    // and on the day a person is pressing this twice the provider is usually
    // the thing that has stopped answering. Going back to it would turn a
    // recoverable channel into an error message.
    let stored = manager
        .hvm_registry_channel_open(wallet_id, now)
        .map_err(public_error)?;
    let held_refund = stored
        .as_ref()
        .and_then(|record| record.countersigned_bundle())
        .is_some();
    // A press that carries a different channel than the one this wallet is part
    // way through is refused rather than reconciled: continuing would fund the
    // stored channel while reporting the pasted one.
    //
    // Only once a refund is held, and deliberately not before. An ask nobody
    // countersigned has cost the owner nothing and may still be replaced, which
    // is the rule `begin_hvm_registry_channel_open` already applies; refusing
    // here as well would leave a person who pasted the wrong details with no
    // way to paste the right ones.
    if held_refund
        && stored
            .as_ref()
            .is_some_and(|record| record.request().binding != wanted)
    {
        return Err(ESTABLISH_DIFFERENT_CHANNEL.to_owned());
    }
    // The Hub this channel was actually opened with, once there is one. A
    // resumed press may not be redirected to a different provider by its own
    // arguments, and once the refund is held the provider's URL is a stored
    // fact rather than a caller's claim.
    let hub_url = match stored.as_ref().filter(|_| held_refund) {
        Some(record) => record.hub_url().to_owned(),
        None => hub_url.to_owned(),
    };
    if !held_refund {
        open_hvm_registry_channel(manager, wallet_id, &hub_url, binding, deposit_zhu, now).await?;
    }

    // ---- stage two: the deposit ----
    //
    // The one irreversible hop, and the one genuine wait. `fund_hvm_registry_channel`
    // signs at most once per channel for the life of the record: on a resume it
    // re-submits the exact stored bytes and looks for them in a block.
    let stored = manager
        .hvm_registry_channel_open(wallet_id, now)
        .map_err(public_error)?;
    let already_confirmed = stored
        .as_ref()
        .and_then(|record| record.funding())
        .is_some_and(|funding| funding.is_confirmed());
    if !already_confirmed
        && let Err(refusal) = fund_hvm_registry_channel_typed(manager, wallet_id, now).await
    {
        // What kind of refusal this is, decided from the manager's own error
        // and *then* confirmed against the durable record. Both halves are
        // needed and neither is enough on its own.
        //
        // The record alone is not enough, and reading it alone was a real
        // defect here rather than a theoretical one. The funding bytes are
        // written durably *before* they are put on the wire, deliberately, so
        // that a crash cannot lose a signature. That means "a funding record
        // exists and is unconfirmed" is equally true of bytes travelling
        // normally and of bytes the node refused outright. Classifying on the
        // record alone reported a node that had rejected the transfer - a
        // balance too small for the deposit and its fee, say - as
        // "signed and sent ... nothing else will happen until it confirms",
        // over money that had not moved and a block that was never coming. The
        // shipped funding command, over byte-identical state, refused honestly.
        // A single press that is less honest than the three commands it
        // replaces is worse than no single press.
        //
        // So the wait is exactly one error: `RegistryFundingNotConfirmed`,
        // which the manager returns only once the node has the bytes and has
        // not yet named a block. `NodeRejected` and everything else is a
        // failure and is reported as one, in the manager's own words.
        let waiting_on_a_block = matches!(
            refusal,
            FundingRefusal::Wallet(
                agent_wallet_core::AgentWalletError::RegistryFundingNotConfirmed
            )
        );
        let refusal = match refusal {
            FundingRefusal::Chain(message) => message,
            FundingRefusal::Wallet(error) => public_error(error),
        };
        if !waiting_on_a_block {
            return Err(refusal);
        }
        let after = manager
            .hvm_registry_channel_open(wallet_id, now)
            .map_err(public_error)?;
        return match after.as_ref().and_then(|record| record.funding()) {
            Some(funding) if !funding.is_confirmed() => Ok(establish_progress_json(
                ESTABLISH_STAGE_FUNDING,
                &wanted,
                &hub_url,
                false,
                Some(funding),
            )),
            _ => Err(refusal),
        };
    }

    // ---- stage three: adoption, which needs no provider ----
    adopt_hvm_registry_channel(manager, wallet_id, now).await?;
    let stored = manager
        .hvm_registry_channel_open(wallet_id, now)
        .map_err(public_error)?;
    Ok(establish_progress_json(
        ESTABLISH_STAGE_READY,
        &wanted,
        &hub_url,
        true,
        stored.as_ref().and_then(|record| record.funding()),
    ))
}

/// Waiting on the provider's countersignature. Nothing has been spent.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const ESTABLISH_STAGE_OPENING: &str = "opening";

/// The deposit is signed and on the wire and not yet in a block.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const ESTABLISH_STAGE_FUNDING: &str = "funding";

/// The channel is adopted, usable, and exitable without the provider.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const ESTABLISH_STAGE_READY: &str = "ready";

/// What an owner is told when they press with a channel that is not the one
/// this wallet is already part way through opening.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const ESTABLISH_DIFFERENT_CHANNEL: &str = "These are different channel details from the ones this wallet has already started opening, so nothing was continued and nothing was signed. Finish or close the channel already in progress before opening another one.";

/// The whole state of getting a channel open, in the terms a screen has to
/// speak in.
///
/// # Why every number here is derived
///
/// A screen that says money is at risk when it is not frightens people out of
/// a working product, and a screen that says nothing is at risk when a deposit
/// is in a contract is the more expensive of the two mistakes. So neither is a
/// judgement made here: `at_risk_zhu` is the deposit exactly when this wallet
/// has durably signed a transfer of it, and zero before that, and it stays
/// non-zero after the channel is ready because a funded channel's deposit is
/// only reachable through the exit.
///
/// `refund_guaranteed` is true from the moment the provider countersigns, which
/// is before any money moves, and that is the sentence the confirmation an
/// owner is shown has to lead with: the full refund is held from the moment the
/// channel opens.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn establish_progress_json(
    stage: &str,
    binding: &l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2,
    hub_url: &str,
    adopted: bool,
    funding: Option<&agent_wallet_core::AgentHvmRegistryFunding>,
) -> Value {
    let deposit_zhu = binding.left_deposit_zhu;
    // Signed and durable, whether or not a node has confirmed it. The money
    // has left the owner's balance from this point and the record is what
    // makes it recoverable, so this is the moment the screen must stop
    // describing the deposit as safe on the owner's side.
    let committed = funding.is_some();
    let confirmed = funding.is_some_and(|funding| funding.is_confirmed());
    let network_fee_zhu = funding.map_or(0, |funding| funding.network_fee_zhu());
    json!({
        "schema": "hpay-agent-registry-establish-progress/1",
        "stage": stage,
        // What pressing again will do, in the words a button can carry.
        "next_action": match stage {
            ESTABLISH_STAGE_READY => "",
            ESTABLISH_STAGE_FUNDING => "Check whether the deposit is in a block yet",
            _ => "Ask this provider to guarantee your refund",
        },
        // Empty exactly when nothing is being waited on, which is exactly when
        // the stage is `ready`. A screen that reports a wait with no subject is
        // the failure this object exists to end.
        "waiting_for": match stage {
            ESTABLISH_STAGE_READY => "",
            ESTABLISH_STAGE_FUNDING => "Your deposit transaction has been signed and sent, and this wallet has not yet seen it in a block. Nothing else will happen until it confirms.",
            _ => "This provider has not yet signed the bill that returns your whole deposit.",
        },
        "hub_url": hub_url,
        "hub_address": binding.right_hub_address,
        "contract_address": binding.contract_address,
        "channel_id": binding.channel_id,
        "deposit_zhu": deposit_zhu,
        "challenge_blocks": binding.challenge_blocks,
        // True from the countersignature onwards, which is strictly before any
        // money moves. The stages after `opening` cannot be reached without it.
        "refund_guaranteed": stage != ESTABLISH_STAGE_OPENING,
        // Everything this wallet has durably committed of the owner's balance.
        // Zero until the deposit transfer is signed, because until then a
        // refusal anywhere costs nothing at all.
        "spent_zhu": if committed { deposit_zhu.saturating_add(network_fee_zhu) } else { 0 },
        "network_fee_zhu": network_fee_zhu,
        // The deposit, once it is committed, for as long as the channel holds
        // it. It does not fall back to zero when the channel becomes ready:
        // a funded channel's deposit comes back through the exit and through
        // nothing else, which is the whole reason the exit exists.
        "at_risk_zhu": if committed { deposit_zhu } else { 0 },
        // What opening can still take out of the main balance from here, on
        // top of anything already spent. Read from the same per-transaction
        // ceiling the open screen quotes.
        "remaining_fee_ceiling_zhu": if committed { 0 } else { OPEN_FEE_CEILING_ZHU },
        "funding_transaction_hash": funding.map(agent_wallet_core::AgentHvmRegistryFunding::transaction_hash),
        "funding_confirmed": confirmed,
        "funding_confirmed_block_height": funding.and_then(agent_wallet_core::AgentHvmRegistryFunding::confirmed_block_height),
        // True exactly when this wallet holds an adopted binding, which is
        // written in the same journalled transition that seeds the exit head.
        "exit_available": adopted,
    })
}

/// What an owner is told when the channel they pasted cannot be read.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_CHANNEL_UNREADABLE: &str = "The channel details from your provider could not be read, so nothing was asked of it and nothing was signed.";

/// What an owner is told when the two statements of the deposit disagree.
///
/// It is refused rather than reconciled. One of the two numbers is the amount
/// the owner decided to risk and the other is the amount that would actually be
/// locked up, and there is no safe way to guess which one they meant.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_CHANNEL_DEPOSIT_MISMATCH: &str = "The deposit you entered is not the deposit these channel details would lock up, so this wallet refused to open it. No channel was opened, nothing was sent to the network and no money has moved. Check the amount with your provider before trying again.";

/// The open screen's facts, with every input already resolved.
///
/// Separated from the read so the rule that must never slip can be tested
/// without a chain or a provider: `blocked_reason` is empty exactly when
/// `open_ready` is true. A screen that withholds an irreversible control and
/// gives no reason is the failure the whole panel exists to end.
#[cfg(feature = "agent-wallet-testnet-pilot")]
// Every argument is a distinct fact the screen renders, and bundling them
// into a struct would only move the same list somewhere the caller fills in
// by name instead of by position.
#[allow(clippy::too_many_arguments)]
fn open_status_json(
    open_ready: bool,
    blocked_reason: &str,
    hub_url: &str,
    hub: (bool, String, String),
    fullnode_reachable: bool,
    spendable_l1_zhu: u64,
    deposit_zhu: u64,
    challenge_blocks: u64,
    channel_in_progress: Value,
) -> Value {
    let (hub_reachable, hub_address, hub_read_error) = hub;
    json!({
        "open_ready": open_ready,
        "blocked_reason": if open_ready { "" } else { blocked_reason },
        "hub_url": hub_url,
        "hub_address": hub_address,
        "hub_reachable": hub_reachable,
        "hub_read_error": hub_read_error,
        "fullnode_reachable": fullnode_reachable,
        "spendable_l1_zhu": spendable_l1_zhu,
        "deposit_zhu": deposit_zhu,
        "required_l1_fee_zhu": OPEN_FEE_CEILING_ZHU,
        "chain_transaction_count": OPEN_CHAIN_TRANSACTION_COUNT,
        "challenge_blocks": challenge_blocks,
        "channel_in_progress": channel_in_progress,
    })
}

/// A channel this wallet has begun and not finished, as the wallet itself
/// records it, or `null` when there is no such channel.
///
/// # Why this is on the status object
///
/// The desktop had no way to ask this question. The open status reported
/// `open_ready: true` over a wallet already holding a countersigned refund and
/// a confirmed deposit, and the overview carried no field for a half-open
/// channel, so the screen tracked its own progress in a note in
/// `window.localStorage`.
///
/// That note is one key for every Agent Wallet on the machine, it does not
/// follow a wallet restored somewhere else, and clearing browser data deletes
/// it. Losing it stranded real money: with the note gone and the provider
/// gone, the only control still on the screen was the open form, and the open
/// form asks the provider first and answers
/// "no channel was opened. Nothing was funded and nothing was spent" over a
/// deposit sitting in a block. The chain would have paid; nothing on the
/// screen could ask it to.
///
/// So the wallet answers it. Everything here is read from the wallet's own
/// sealed record, which survives a restore and belongs to one wallet, and
/// nothing here is a judgement: the two presses re-derive what they do from
/// that same record, and this only decides what an owner is shown.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn channel_in_progress_json(
    record: Option<&agent_wallet_core::AgentHvmRegistryChannelOpen>,
) -> Value {
    let Some(record) = record else {
        return Value::Null;
    };
    let bundle = record.countersigned_bundle();
    let funding = record.funding();
    json!({
        "schema": "hpay-agent-registry-channel-in-progress/1",
        // The countersigned full refund this wallet checked and saved. Until
        // this is true no deposit can be signed at all.
        "refund_held": bundle.is_some(),
        "deposit_zhu": bundle.map(|bundle| bundle.binding.left_deposit_zhu),
        // The deposit transaction, once this wallet has signed one. A channel
        // with a hash here has had money leave it, whatever the screen knows.
        "funding_transaction_hash": funding.map(|funding| funding.transaction_hash()),
        "funding_confirmed": funding.is_some_and(|funding| funding.is_confirmed()),
        "funding_confirmed_block_height": funding.and_then(|funding| funding.confirmed_block_height()),
        "network_fee_zhu": funding.map(|funding| funding.network_fee_zhu()),
    })
}

/// This wallet's spendable main balance, in the L1 chain's own zhu.
///
/// The overview publishes `available_units` in the Agent ledger's `HacUnits`,
/// which are 1e-6 HAC (`agent_wallet_core::HacUnits::PER_HAC == 1_000_000`).
/// Every registry amount beside it on those screens - the deposit, the fee
/// ceiling, the gas reserve - is in chain zhu, which is 1e-8 HAC
/// (`parse_fin_balance_zhu("1:248") == 100_000_000` in
/// `l2_fast_pay_hub::node`). Both were previously published under the name
/// `spendable_l1_zhu` without conversion, so the affordability precondition
/// compared a 1e-6 number against a 1e-8 total and demanded a hundred times
/// the balance it should have, and the sentence built from it put two scales
/// in one line.
///
/// Saturating rather than wrapping: this number gates a spend, and a balance
/// that overflows into a small one would open a door this exists to close.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn spendable_l1_zhu(overview: &Value) -> u64 {
    const ZHU_PER_HAC_UNIT: u64 = 100_000_000 / agent_wallet_core::HacUnits::PER_HAC;
    overview
        .get("available_units")
        .and_then(Value::as_str)
        .and_then(|units| units.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(ZHU_PER_HAC_UNIT)
}

/// Read the open screen's facts: this wallet's balance, its fullnode, and the
/// provider's own published identity.
///
/// The provider is asked one question and it is not a commitment: who are you,
/// and do you run the reviewed profile. It cannot fund anything, cannot sign
/// anything and cannot be charged for anything by being asked.
#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn registry_open_status_value(
    overview: &Value,
    hub_url: &str,
    deposit_zhu: u64,
    in_progress: Option<&agent_wallet_core::AgentHvmRegistryChannelOpen>,
) -> Value {
    let spendable_l1_zhu = spendable_l1_zhu(overview);
    let already_bound = overview
        .get("hvm_registry_binding")
        .is_some_and(|value| !value.is_null());
    // A deposit this wallet has already signed and handed to the network. Not
    // "a channel was started" - money has actually left - which is why this
    // withholds the open control rather than merely warning beside it.
    let deposit_in_flight = in_progress.is_some_and(|record| record.funding().is_some());
    let fullnode_reachable = match overview.get("node_url").and_then(Value::as_str) {
        Some(node_url) => match l2_fast_pay_hub::node::NodeClient::new(node_url) {
            Ok(client) => client.capabilities().await.is_ok(),
            Err(_) => false,
        },
        None => false,
    };
    let hub = read_open_hub_identity(hub_url).await;
    let (open_ready, blocked_reason) = if already_bound {
        (false, OPEN_ALREADY_BOUND)
    } else if deposit_in_flight {
        (false, OPEN_DEPOSIT_IN_FLIGHT)
    } else {
        (true, "")
    };
    open_status_json(
        open_ready,
        blocked_reason,
        hub_url,
        hub,
        fullnode_reachable,
        spendable_l1_zhu,
        deposit_zhu,
        l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_MAX_CHALLENGE_BLOCKS,
        channel_in_progress_json(in_progress),
    )
}

/// What an owner is told when this wallet already holds a channel.
///
/// One shared registry channel per wallet. A second one opened while the first
/// is live would put money behind a binding this wallet's exit record does not
/// name, and the exit is the reason any of this is safe.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_ALREADY_BOUND: &str = "This Agent Wallet already has a provider channel. Close that one first: the section below takes your money out of it without needing the provider's permission.";

/// Why the open control is withheld over a deposit that has already left.
///
/// This wallet has signed a deposit into a channel and handed it to the
/// network. Opening a second channel would ask for a second deposit while the
/// first is still out, and the money that is already gone comes back through
/// finishing this channel and through nothing else. Said as an instruction
/// rather than a refusal, because the owner is not stuck: the two controls
/// that finish it need no provider.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const OPEN_DEPOSIT_IN_FLIGHT: &str = "You have already sent a deposit into a channel with this wallet, and it has not finished opening. Finish that one below before opening another: your deposit comes back out of that channel, and the steps that finish it do not need the provider's help.";

/// The provider's own published identity, or the reason it could not be read.
#[cfg(feature = "agent-wallet-testnet-pilot")]
async fn read_open_hub_identity(hub_url: &str) -> (bool, String, String) {
    let client = hacash_wallet_core::l2_hub::L2HubClient::new_for_wallet_policy(
        hub_url.to_owned(),
        "testnet",
        false,
    );
    match client.health().await {
        Ok(health) => {
            let address = health.hub_address.clone().unwrap_or_default();
            if !health.ok || health.version < 7 || address.is_empty() {
                return (
                    false,
                    address,
                    "This provider answered but does not run the reviewed provider profile."
                        .to_owned(),
                );
            }
            (true, address, String::new())
        }
        Err(error) => (false, String::new(), error.to_string()),
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
        let manager = require_manager(&state)?;
        let mut manager = manager.lock().await;
        execute_approved_hvm_payment(&mut manager, &wallet_id, &operation_id, unix_now()?).await
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    {
        let _ = (wallet_id, operation_id, state);
        Err("Agent HVM Fast Pay is disabled in this build".to_owned())
    }
}

/// Everything [`agent_wallet_execute_approved_hvm`] does once the shell has
/// been recognised and its two identifiers parsed.
///
/// Split out for the same reason `open`, `fund`, `adopt`, `establish` and the
/// exit are: a Tauri command cannot be entered without a real `Webview`, so a
/// command whose whole body lives behind that attribute can only ever be
/// proven by a test that reimplements it, which is the "the only caller is a
/// test" failure one layer up.
///
/// This one was the last hop of the journey with no such body. A reviewer
/// trying to drive the whole circle - open, fund, **pay**, lose the provider,
/// exit, get paid - could enter at every hop except this one, so the payment
/// in the middle could not be demonstrated through the surface a person uses
/// at all. Nothing about the payment changes here; it becomes enterable.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn execute_approved_hvm_payment(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    now: u64,
) -> Result<Value, String> {
    let operation = manager
        .execute_approved_hvm_payment(wallet_id, operation_id, now)
        .await
        .map_err(public_error)?;
    serde_json::to_value(operation).map_err(|_| "Agent HVM result encoding failed".to_owned())
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
///
/// Read from the priced list rather than typed, so the count on the screen and
/// the steps the quote is summed over cannot drift apart.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_CHAIN_TRANSACTION_COUNT: u64 =
    hacash_wallet_core::hvm_registry_exit_cost::EXIT_RUN_STEPS.len() as u64;

/// The fee one exit transaction carries, and therefore the fee every figure
/// below is priced at.
///
/// The same constant the driver signs with
/// (`agent_wallet_core::AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU`, handed to the
/// driver as `HvmRegistryExitTermsV1::network_fee_zhu`), because a quote
/// priced at one fee and a transaction signed at another is the screen telling
/// the owner a different number than the chain will charge.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_NETWORK_FEE_ZHU: u64 = agent_wallet_core::AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU;

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
/// So the quote is fee plus reserve. What it no longer is, is *one* reserve
/// applied to all three.
///
/// # Why the flat version was still wrong
///
/// The reserve is `ceil(budget * purity_fee / billing_size)`, so it moves with
/// the size of the transaction, and a **smaller** transaction reserves
/// **more**. The first fix quoted the single smallest transaction observed
/// anywhere in a measured run — a lease renewal, 187 billing bytes, rounded
/// down to 160 — and applied it to every step. That over-stated the
/// requirement by about 17% on the smallest step of the run and about 2.6x on
/// the largest, and an over-quote is not free: it turns the affordability
/// precondition red, and withholds the exit control beside it, from an owner
/// who could have finished.
///
/// So each step is now priced at its own measured size.
/// `hacash_wallet_core::hvm_registry_exit_cost` holds the floors and
/// `crates/wallet-core/tests/exit_fee_quote_per_step.rs` is where they come
/// from: it builds every one of the six exit transactions with the shipped
/// builder and reads `billing_size()` off the signed bytes. Nothing here is
/// estimated, and every floor sits at or below the size that was measured, so
/// the remaining error is an over-quote and never an under-quote.
///
/// # Why this is the whole press and not the ordinary run
///
/// The first per-step version of this constant was `exit_run_ceiling_zhu` — the
/// three ordinary steps — and that was a second under-quote in the same place
/// as the first. A press is not always three transactions:
/// `plan_user_exit_step` renews the registry lease when it is short, then the
/// channel lease, before it challenges at all, and it can plan a response. Each
/// is a real transaction out of the same balance.
///
/// Walked one transaction at a time at full burn, an owner holding exactly the
/// three-step quote with a short registry lease clears the renewal
/// (609,211,957) and the challenge (275,291,667) and then cannot pay for
/// `finalize` — stranded part-way through an irreversible press with the
/// objection window already running. The flat quote this replaced happened to
/// have enough accidental slack to cover one renewal; it did not cover two.
/// Neither number was ever designed to.
///
/// So this is `exit_worst_press_ceiling_zhu`: every step one press can send,
/// each still priced at its own measured size. The tightening GAP 1 asked for
/// is not undone — the ordinary run is still quoted at 1,353,358,975 rather
/// than the flat 2,101,331,250, and it is published beside this one as
/// `ordinary_run_ceiling_zhu` — but the number the affordability precondition
/// gates on is now the number a press can actually need.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_FEE_CEILING_ZHU: u64 =
    hacash_wallet_core::hvm_registry_exit_cost::exit_worst_press_ceiling_zhu(EXIT_NETWORK_FEE_ZHU);

/// What the three ordinary steps cost, published beside the press ceiling so a
/// screen can name both without doing arithmetic of its own.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const EXIT_ORDINARY_RUN_CEILING_ZHU: u64 =
    hacash_wallet_core::hvm_registry_exit_cost::exit_run_ceiling_zhu(EXIT_NETWORK_FEE_ZHU);

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
        // BOTH LOCKS ARE HELD FOR THE WHOLE DRIVE, AND THAT IS THE INTENDED
        // BEHAVIOUR RATHER THAN AN ACCIDENT OF WHERE THE `await`s FELL.
        //
        // Today the brake is down and the body below returns after one refusal,
        // so this costs nothing and nobody has felt it. When the brake lifts,
        // one press drives up to the pass budget's worth of chain
        // transactions, each with a round trip, and every other Agent Wallet
        // command queues behind these two locks for the duration.
        //
        // That is the trade taken deliberately: an exit is the one operation
        // where a second concurrent command could sign against state this one
        // is midway through changing, and a frozen screen is a cheaper failure
        // than two presses racing over the same channel. The durable record is
        // what makes it safe to be interrupted — `kill_mid_exit_on_chain`
        // proves a half-finished drive resumes — so the cost of holding is
        // bounded and the cost of not holding is not.
        //
        // If this is ever revisited, the thing to change is what the owner
        // sees while it is held, not whether it is held.
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
    // Not `unwrap_or_default()`. A failed read of the started-steps ledger is
    // not the same fact as an empty one, and folding them together tells an
    // owner "nothing has been sent yet" about a wallet whose record of what
    // has been sent could not be opened. Every way this can fail once the
    // overview above has succeeded — an unverifiable state file, an L2 store
    // that will not open — is a reason to stop rather than a reason to report
    // no progress. The binding is known to exist here: the null check above
    // reads it from the same state.
    let started_steps = manager
        .hvm_registry_exit_steps(wallet_id, now)
        .map_err(public_error)?;
    let status = registry_exit_status_value(&overview, started_steps).await;
    if status["driver_ready"] != Value::Bool(true) {
        return Err(status["blocked_reason"]
            .as_str()
            .unwrap_or(USER_EXIT_DRIVER_MISSING)
            .to_owned());
    }
    drive_hvm_registry_exit(manager, wallet_id, &overview, &binding, now).await
}

/// Everything the press does once the gate has already said yes.
///
/// # Why this is a separate function
///
/// It is the half that signs, and until it was split out it had never
/// executed. `start_hvm_registry_exit` refuses unless
/// `measure_user_side_unilateral_exit_ready()` is true, and that measurement
/// reads a constant a human sets - so the run that would justify setting it
/// could not happen without setting it first. Nothing about the driver was
/// unproven; what was unproven was reaching it from the command an owner
/// presses.
///
/// This is not a way around the gate. There is no flag here, no argument that
/// skips a check, and the shipped path still refuses before it ever gets here.
/// What changed is that "may I" and "do it" are two functions instead of one,
/// so a test can drive the second without pretending the first said yes. The
/// ordering guard in this file was rewritten to be stricter about it than the
/// version that covered the single function: it pins the gate before the call
/// AND that this function has exactly one caller in shipped source, which
/// nothing asserted while the two were joined.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub async fn drive_hvm_registry_exit(
    manager: &mut agent_wallet_core::AgentWalletManager,
    wallet_id: &AgentWalletId,
    overview: &Value,
    binding: &Value,
    now: u64,
) -> Result<Value, String> {
    let chain = registry_exit_chain(overview, binding)?;
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
    let spendable_l1_zhu = spendable_l1_zhu(overview);
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
        // Every step one press can send, each at its own measured size. Not
        // the three ordinary ones: the planner renews a short lease before it
        // challenges, and an owner holding only the three-step figure would
        // clear the renewal and the challenge and then be unable to pay for
        // `finalize`, stranded mid-press with the objection window running.
        "required_l1_fee_zhu": EXIT_FEE_CEILING_ZHU,
        // What the ordinary path costs when nothing conditional happens, which
        // is what usually happens. Published so the screen can name the likely
        // number as well as the number that must be available.
        "ordinary_run_ceiling_zhu": EXIT_ORDINARY_RUN_CEILING_ZHU,
        // Broken out so the screen can say what one more transaction costs
        // without doing arithmetic of its own, and so the gas half is nameable
        // rather than folded invisibly into a single figure. A lease renewal
        // or a re-sent step is exactly one more of these.
        //
        // The ceiling is taken over *every* step an exit can send, not only
        // the three an ordinary run sends, because the screen offers this
        // number for exactly the conditional ones: "if this channel's record
        // is close to expiring it is extended first ... each of those is one
        // more transaction at the same ceiling". The most expensive step is a
        // registry lease renewal - the shortest transaction of the six, and
        // therefore the one that reserves the most gas - so quoting the run's
        // own largest here would understate the step the sentence is about.
        "chain_transaction_count": EXIT_CHAIN_TRANSACTION_COUNT,
        "per_transaction_ceiling_zhu":
            hacash_wallet_core::hvm_registry_exit_cost::exit_largest_step_ceiling_zhu(
                EXIT_NETWORK_FEE_ZHU,
            ),
        "per_transaction_network_fee_zhu": EXIT_NETWORK_FEE_ZHU,
        "per_transaction_gas_reserve_zhu":
            hacash_wallet_core::hvm_registry_exit_cost::exit_largest_step_ceiling_zhu(
                EXIT_NETWORK_FEE_ZHU,
            ) - EXIT_NETWORK_FEE_ZHU,
        // Every step, priced at its own measured size, so a surface can show
        // the owner where the number came from instead of asking them to trust
        // one total. `billing_floor_bytes` is the measurement each line is
        // computed from; the run total above is the sum of the three lines
        // whose `in_ordinary_run` is true.
        "exit_step_costs": exit_step_costs_json(),
        // Empty exactly when no step of an exit has ever been opened for this
        // channel, which is the only case in which the screen may speak about
        // starting one. Read from this wallet's own durable record; no chain
        // and no provider is involved.
        "started_steps": started_steps,
    })
}

/// What each step of an exit can take from the owner's main balance, one line
/// per step.
///
/// The screen has always had to say "up to" about a number it could not break
/// down, which is the shape of sentence people stop believing. These are the
/// pieces: the measured size the step encodes to, the fee it carries, and the
/// gas the chain holds while it runs. Nothing is computed here — every figure
/// comes from `hacash_wallet_core::hvm_registry_exit_cost`, whose floors are
/// measured by `crates/wallet-core/tests/exit_fee_quote_per_step.rs`.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn exit_step_costs_json() -> Value {
    use hacash_wallet_core::hvm_registry_exit_cost as cost;
    Value::Array(
        cost::EXIT_ALL_STEPS
            .iter()
            .map(|step| {
                json!({
                    "step": step.slug(),
                    "billing_floor_bytes": cost::exit_step_billing_floor_bytes(*step),
                    "network_fee_zhu": EXIT_NETWORK_FEE_ZHU,
                    "gas_reserve_zhu": cost::exit_step_gas_reserve_zhu(*step, EXIT_NETWORK_FEE_ZHU),
                    "ceiling_zhu": cost::exit_step_ceiling_zhu(*step, EXIT_NETWORK_FEE_ZHU),
                    "in_ordinary_run": cost::EXIT_RUN_STEPS.contains(step),
                })
            })
            .collect(),
    )
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
        // This assertion used to read `!measured`, and its note said that if it
        // ever failed, the exit had become buildable and the refusal was the
        // thing needing replacement. That is exactly what happened: the
        // builders are role aware, the driver ships, and the refusal is gone.
        // So it now asserts the other direction. The property this test exists
        // for is unchanged and is the line above and the lines below - the
        // rendered gate is the measurement, never a literal - and pinning the
        // measurement's value in both eras is what makes a silent flip back to
        // a constant fail here rather than pass quietly.
        assert!(
            measured,
            "the user-side exit builders are available and the driver ships"
        );
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
            .find("drive_hvm_registry_exit(manager, wallet_id")
            .expect("an open gate hands off to the shipped driver");
        assert!(
            gate < refusal && refusal < drive,
            "the measured gate and its refusal must both come before anything that can sign"
        );
        // Stricter than the version that covered one joined function. While
        // the driving lived inside the body, nothing asserted that no OTHER
        // production path reached it; splitting it out makes that checkable,
        // so it is checked. The declaration and this one call are the only
        // mentions shipped source may hold.
        let shipped = source
            .split("#[cfg(test)]")
            .next()
            .expect("source before the test module");
        assert_eq!(
            shipped.matches("drive_hvm_registry_exit").count(),
            2,
            "the driver is declared once and called once, by the gate that guards it"
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

    /// THE EXIT QUOTE IS PRICED PER STEP, AND STILL REFUSES A RUN THE OWNER
    /// CANNOT PAY FOR.
    ///
    /// # What was wrong
    ///
    /// The quote applied one assumed transaction size - the smallest
    /// transaction seen anywhere in a whole exit - to every transaction of the
    /// run. The chain reserves gas as `budget * purity_fee / billing_size`
    /// (`GasCounter::calc_burn_amount`,
    /// `hacash-fullnodedev/protocol/src/context/gas.rs:124`), so a smaller
    /// assumed size means a larger assumed reserve, and the flat assumption
    /// over-stated the requirement by about 17% on the smallest step of the
    /// run and about 2.6x on the largest. Wrong in the safe direction, but
    /// wrong: an over-quote shows a red affordability precondition, and the
    /// exit control beside it stays withheld, from an owner who could in fact
    /// have completed the exit.
    ///
    /// # What this pins
    ///
    /// Both edges, because only one of them is cheap to get wrong.
    ///
    /// * The quote is never below what the chain can actually take at the
    ///   sizes these transactions were **measured** at. That is the edge that
    ///   walks somebody into a two-step irreversible press whose first
    ///   transaction cannot execute.
    /// * The quote is below the flat assumption it replaced, and an owner
    ///   holding 14 HAC - enough for the whole run at the measured sizes, and
    ///   not enough under the flat assumption - is no longer refused.
    ///
    /// The reserve arithmetic below is written out again rather than imported,
    /// on purpose: it is the chain's rule stated independently of the model
    /// under test, so this checks the quote against the chain and not against
    /// itself. The measured sizes it is evaluated at come from
    /// `crates/wallet-core/tests/exit_fee_quote_per_step.rs`, which builds
    /// each of these transactions with the shipped builder and reads
    /// `billing_size()` off the signed bytes.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn the_exit_quote_is_priced_per_step_and_still_refuses_what_cannot_be_afforded() {
        /// `ceil(budget * max(raw_fee, floor * size) / size)`, in whole zhu.
        fn chain_gas_reserve_zhu(billing_size_bytes: u64, network_fee_zhu: u64) -> u64 {
            const GAS_BUDGET: u64 = 111_911;
            const LOWEST_FEE_PURITY_UNIT238: u64 = 50_000;
            const UNIT238_PER_ZHU: u64 = 100;
            let raw_fee_238 = network_fee_zhu * UNIT238_PER_ZHU;
            let floor_fee_238 = LOWEST_FEE_PURITY_UNIT238 * billing_size_bytes;
            let purity_fee_238 = raw_fee_238.max(floor_fee_238);
            (GAS_BUDGET * purity_fee_238)
                .div_ceil(billing_size_bytes)
                .div_ceil(UNIT238_PER_ZHU)
        }
        const NETWORK_FEE_ZHU: u64 = 1_000_000;
        // The measured minimum billing size of each transaction an ordinary
        // run sends: challenge, finalize, and the Action 14 claim.
        let true_run_cost = [414_u64, 210, 209]
            .into_iter()
            .map(|size| NETWORK_FEE_ZHU + chain_gas_reserve_zhu(size, NETWORK_FEE_ZHU))
            .sum::<u64>();
        assert_eq!(true_run_cost, 1_341_685_281);
        // What the flat assumption quoted for the same three transactions.
        let flat_quote = 3 * (NETWORK_FEE_ZHU + chain_gas_reserve_zhu(160, NETWORK_FEE_ZHU));
        assert_eq!(flat_quote, 2_101_331_250);

        let status = |spendable_l1_zhu: u64| {
            super::exit_status_json(true, spendable_l1_zhu, (None, String::new()), Vec::new())
        };
        let quote = status(0)["required_l1_fee_zhu"]
            .as_u64()
            .expect("the exit quote is a number");
        let ordinary_run = status(0)["ordinary_run_ceiling_zhu"]
            .as_u64()
            .expect("the ordinary run ceiling is a number");

        assert!(
            quote >= true_run_cost,
            "the quote {quote} is below the {true_run_cost} the chain can take at the sizes \
             these transactions were measured at, so an owner could pass the affordability \
             precondition and be unable to execute the first transaction"
        );
        // The tightening GAP 1 asked for, checked where it is claimed: the
        // *ordinary run* is priced from the six measured sizes and is well
        // under the flat smallest-transaction assumption it replaced.
        assert!(
            ordinary_run >= true_run_cost && ordinary_run < flat_quote,
            "the ordinary run {ordinary_run} is either below what the chain can take \
             ({true_run_cost}) or still the flat assumption ({flat_quote}) applied to every step"
        );

        // But the number the precondition gates on is not the ordinary run,
        // and this is the hole a verifier found after the first fix. The
        // planner renews a short registry lease *before* it challenges
        // (`crates/wallet-core/src/hvm_registry_exit.rs`), so the press can be
        // four transactions, or five with the channel lease too. Walked one
        // transaction at a time at full burn — before each one the balance must
        // cover that transaction's own fee and whole reserve, and what the
        // earlier ones took is gone — the quote has to survive the longest
        // sequence, not the shortest.
        let ceiling = |size: u64| NETWORK_FEE_ZHU + chain_gas_reserve_zhu(size, NETWORK_FEE_ZHU);
        // Measured sizes: registry renewal 187, channel renewal 214, challenge
        // 414, finalize 210, claim 209.
        let renewal_then_run = [187_u64, 214, 414, 210, 209];
        let mut spent = 0;
        let mut needed = 0;
        for size in renewal_then_run {
            needed = std::cmp::max(needed, spent + ceiling(size));
            spent += ceiling(size);
        }
        assert!(
            ordinary_run < needed,
            "this test claims the three-step quote could strand a press; if it now covers \
             {needed} the claim is stale and must be re-derived rather than deleted"
        );
        assert!(
            quote >= needed,
            "the quote {quote} does not cover a press that renews a short lease first, which \
             needs {needed} held up front: an owner would clear the renewal and the challenge \
             and then be unable to pay for finalize, stranded part-way through an irreversible \
             press with the objection window already running"
        );

        // The precondition the desktop applies, verbatim from
        // `apps/desktop/src/agent/registryExit.ts`:
        //   `status.spendable_l1_zhu >= status.required_l1_fee_zhu`.
        let affordable = |spendable_l1_zhu: u64| {
            let status = status(spendable_l1_zhu);
            status["spendable_l1_zhu"].as_u64().unwrap()
                >= status["required_l1_fee_zhu"].as_u64().unwrap()
        };
        // It still refuses. An owner who cannot cover the run at its measured
        // cost is told so, exactly as before.
        assert!(!affordable(true_run_cost - 1));
        assert!(!affordable(quote - 1));
        assert!(affordable(quote));

        // And it refuses the case that was the whole point of the second fix:
        // 14 HAC covers the three ordinary transactions at their measured
        // sizes, and does not cover a press that has to renew a short lease
        // first. The earlier, three-step version of this quote let that owner
        // through. It must not.
        assert!(1_400_000_000 > true_run_cost && 1_400_000_000 < needed);
        assert!(
            !affordable(1_400_000_000),
            "an owner holding 1400000000 zhu cannot pay for a press that renews a short lease \
             before it challenges, and must not be told they can"
        );

        // Said plainly, because it is the uncomfortable half: this quote is
        // *larger* than the flat assumption it replaced, not smaller. The flat
        // assumption was not a safe over-quote that got tightened; it was
        // 2.6x too high on the steps it priced and still too low for a press
        // that renews a lease, which is a shape of wrongness no single number
        // can be talked out of. What the measurement bought is not a smaller
        // gate but a true one, and the two figures beside it are where the
        // tightening shows: the ordinary run and the per-transaction ceiling
        // are both below what the flat assumption claimed for them.
        assert!(quote > flat_quote);
        assert!(ordinary_run < flat_quote);

        // One more transaction - a response, or a lease renewal - is quoted at
        // the per-transaction ceiling the same screen shows. A registry lease
        // renewal is the *shortest* transaction an exit can send, measured at
        // 187 billing bytes, so it reserves the most gas of any step; the
        // ceiling has to cover that one and not merely the run's own largest.
        let per_transaction = status(0)["per_transaction_ceiling_zhu"]
            .as_u64()
            .expect("the per-transaction ceiling is a number");
        assert!(
            per_transaction >= NETWORK_FEE_ZHU + chain_gas_reserve_zhu(187, NETWORK_FEE_ZHU),
            "the per-transaction ceiling {per_transaction} does not cover a lease renewal, \
             which the screen tells the owner to expect as one more transaction at this ceiling"
        );
        assert!(
            per_transaction < NETWORK_FEE_ZHU + chain_gas_reserve_zhu(160, NETWORK_FEE_ZHU),
            "the per-transaction ceiling {per_transaction} is still the flat \
             smallest-transaction assumption rather than the measured registry renewal"
        );
    }
}

/// The registry open screen's money facts, which are the ones that were wrong.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
mod registry_open_status_tests {
    use serde_json::json;

    /// The overview counts in the Agent ledger's units; the screen counts in
    /// the chain's zhu. They differ by a hundred, and publishing one under the
    /// other's name made the affordability precondition demand a hundred times
    /// the balance it should have.
    #[test]
    fn the_spendable_balance_is_published_in_chain_zhu_and_not_in_agent_units() {
        // `available_units` is 1e-6 HAC. One HAC is 1_000_000 of them, and it
        // is 100_000_000 chain zhu.
        let overview = json!({ "available_units": "1000000" });
        assert_eq!(super::spendable_l1_zhu(&overview), 100_000_000);

        // A hundred HAC, which is the balance a reviewer was refused a five
        // HAC channel on.
        let overview = json!({ "available_units": "100000000" });
        assert_eq!(super::spendable_l1_zhu(&overview), 10_000_000_000);

        // Missing or unreadable reads as nothing, never as plenty.
        assert_eq!(super::spendable_l1_zhu(&json!({})), 0);
        assert_eq!(
            super::spendable_l1_zhu(&json!({ "available_units": "not a number" })),
            0
        );

        // A balance large enough to overflow the conversion must not wrap into
        // a small one: this number gates a spend.
        let overview = json!({ "available_units": u64::MAX.to_string() });
        assert_eq!(super::spendable_l1_zhu(&overview), u64::MAX);
    }

    /// A deposit that has left is reported, so the screen can finish the
    /// channel without a note in browser storage.
    #[test]
    fn an_unfinished_channel_is_reported_from_the_wallets_own_record() {
        // No record at all is `null`, and not an object full of falsehoods.
        assert!(super::channel_in_progress_json(None).is_null());
    }

    /// The open control is withheld while a deposit is in flight, with a
    /// reason, and the reason points at the controls that finish the channel.
    #[test]
    fn opening_a_second_channel_is_withheld_while_a_deposit_is_out() {
        let withheld = super::open_status_json(
            false,
            super::OPEN_DEPOSIT_IN_FLIGHT,
            "http://127.0.0.1:8790",
            (true, "1ADDRESS".to_owned(), String::new()),
            true,
            10_000_000_000,
            500_000_000,
            8,
            serde_json::Value::Null,
        );
        assert_eq!(withheld["open_ready"], serde_json::Value::Bool(false));
        let reason = withheld["blocked_reason"].as_str().unwrap_or_default();
        assert!(
            !reason.is_empty(),
            "a withheld irreversible control must always carry a reason"
        );
        // The owner is not stuck, and the sentence has to say so: the two
        // controls that finish the channel need no provider.
        assert!(reason.contains("Finish that one below"), "{reason}");
        assert!(reason.contains("do not need the provider"), "{reason}");

        // And the rule the whole panel rests on: a reason exactly when the
        // control is withheld.
        let ready = super::open_status_json(
            true,
            super::OPEN_DEPOSIT_IN_FLIGHT,
            "http://127.0.0.1:8790",
            (true, "1ADDRESS".to_owned(), String::new()),
            true,
            10_000_000_000,
            500_000_000,
            8,
            serde_json::Value::Null,
        );
        assert_eq!(
            ready["blocked_reason"],
            serde_json::Value::String(String::new())
        );
        assert_eq!(ready["channel_in_progress"], serde_json::Value::Null);
    }
}
