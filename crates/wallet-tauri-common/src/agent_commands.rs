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
    AgentId, AgentPaymentRequest, AgentPolicy, AgentRecord, AgentWalletId, ApprovalCommitment,
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
