#[cfg(all(feature = "agent-wallet-testnet-pilot", not(target_os = "windows")))]
compile_error!(
    "The AI Agent Wallet testnet pilot is Windows-only until the Linux glib 0.18.5 blocker is resolved. Build Linux without agent-wallet-testnet-pilot."
);

mod platform;

use hacash_wallet_core::WalletService;
use hacash_wallet_core::hip23::{BalanceFloorInput, HeightScopeInput, Type3CheckInput};
use tauri::{Manager, RunEvent};
use wallet_tauri_common::{AgentAppState, AppState};

#[tauri::command]
fn wallet_list_bills(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    serde_json::to_value(svc.list_bills()).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_validate_hip23(
    universal: Type3CheckInput,
    p2: Option<HeightScopeInput>,
    p3: Option<BalanceFloorInput>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    let checks = svc.validate_hip23_patterns(universal, p2, p3);
    serde_json::to_value(checks).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_platform_security_status() -> Result<serde_json::Value, String> {
    serde_json::to_value(platform::platform_security_status()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_confirm_biometric_native(
    operation_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let challenge = {
        let mut svc = state.inner.lock().await;
        svc.begin_prepared_native_authorization(&operation_id)
            .map_err(|e| e.to_string())?
    };
    // The OS consent prompt blocks until the user answers and needs a live
    // message pump. Run it off the UI thread, and never hold the wallet mutex
    // across it, so the window stays responsive while the dialog is up.
    let message = challenge.message.clone();
    tauri::async_runtime::spawn_blocking(move || platform::verify_native_biometric(&message))
        .await
        .map_err(|error| format!("biometric prompt task failed: {error}"))??;
    let mut svc = state.inner.lock().await;
    svc.finish_prepared_native_authorization(&operation_id, &challenge.nonce)
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let node_override = std::env::var("HACASH_WALLET_NODE_URL")
                .ok()
                .filter(|url| !url.trim().is_empty());
            wallet_tauri_common::backup_commands::recover_interrupted_restore()
                .map_err(|error| format!("backup restore recovery: {error}"))?;
            let mut svc = WalletService::new(node_override, None).map_err(|e| e.to_string())?;
            svc.warm_vault_cache().map_err(|e| e.to_string())?;
            app.manage(AppState::new(svc));
            let agent_root = hacash_wallet_core::paths::wallet_data_root().join("agent-wallets");
            app.manage(AgentAppState::open(agent_root));
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) =
                    wallet_tauri_common::desktop_relay::sync_managed_relay(&handle).await
                {
                    tracing::warn!(error = %e, "DUST Whisper relay auto-start skipped");
                }
            });
            Ok(())
        })
        // Backup files and WebAuthn are desktop-only. The Android Downloads helper is not
        // registered until mobile exposes that flow.
        .invoke_handler(wallet_tauri_common::wallet_invoke_handler![
            wallet_tauri_common::backup_commands::wallet_export_backup,
            wallet_tauri_common::backup_commands::wallet_preview_backup,
            wallet_tauri_common::backup_commands::wallet_import_backup,
            wallet_tauri_common::security_commands::wallet_webauthn_register_begin,
            wallet_tauri_common::security_commands::wallet_webauthn_register_finish,
            wallet_tauri_common::security_commands::wallet_webauthn_auth_begin,
            wallet_tauri_common::security_commands::wallet_webauthn_auth_finish,
            wallet_tauri_common::security_commands::wallet_webauthn_replacement_begin,
            wallet_tauri_common::security_commands::wallet_webauthn_replacement_finish,
            wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop,
            wallet_list_bills,
            wallet_validate_hip23,
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
            wallet_tauri_common::update_commands::wallet_install_desktop_update,
            wallet_tauri_common::agent_commands::agent_wallet_runtime_status,
            wallet_tauri_common::agent_commands::agent_wallet_pilot_diagnostics_preview,
            wallet_tauri_common::agent_commands::agent_wallet_pilot_diagnostics_export,
            wallet_tauri_common::agent_commands::agent_wallet_witness_rotation_prepare,
            wallet_tauri_common::agent_commands::agent_wallet_witness_rotation_status,
            wallet_tauri_common::agent_commands::agent_wallet_witness_rotation_cancel,
            wallet_tauri_common::agent_commands::agent_wallet_witness_rotation_controls,
            wallet_tauri_common::agent_commands::agent_wallet_witness_rotation_retarget,
            wallet_tauri_common::agent_commands::agent_wallet_stranded_witness,
            wallet_tauri_common::agent_commands::agent_wallet_reconciliation_required,
            wallet_tauri_common::agent_commands::agent_wallet_reconcile_broadcast,
            wallet_tauri_common::agent_commands::agent_wallet_abandon_stranded_witness,
            wallet_tauri_common::agent_commands::agent_wallet_release_dead_witness_anchor,
            wallet_tauri_common::agent_commands::agent_wallet_runtime_start,
            wallet_tauri_common::agent_commands::agent_wallet_runtime_stop,
            wallet_tauri_common::agent_commands::agent_wallet_pairing_activate,
            wallet_tauri_common::agent_commands::agent_wallet_pairing_pending,
            wallet_tauri_common::agent_commands::agent_wallet_pairing_approve,
            wallet_tauri_common::agent_commands::agent_wallet_pairing_reject,
            wallet_tauri_common::agent_commands::agent_wallet_create,
            wallet_tauri_common::agent_commands::agent_wallet_backup_warnings,
            wallet_tauri_common::agent_commands::agent_wallet_backup_create,
            wallet_tauri_common::agent_commands::agent_wallet_backup_preview,
            wallet_tauri_common::agent_commands::agent_wallet_backup_restore,
            wallet_tauri_common::agent_commands::agent_wallet_unlock,
            wallet_tauri_common::agent_commands::agent_wallet_lock,
            wallet_tauri_common::agent_commands::agent_wallet_overview,
            wallet_tauri_common::agent_commands::agent_wallet_l2_probe,
            wallet_tauri_common::agent_commands::agent_wallet_l2_pin,
            wallet_tauri_common::agent_commands::agent_wallet_enable_payments,
            wallet_tauri_common::agent_commands::agent_wallet_emergency_stop,
            wallet_tauri_common::agent_commands::agent_wallet_list_agents,
            wallet_tauri_common::agent_commands::agent_wallet_get_policy,
            wallet_tauri_common::agent_commands::agent_wallet_update_policy,
            wallet_tauri_common::agent_commands::agent_wallet_list_activity,
            wallet_tauri_common::agent_commands::agent_wallet_list_pending_approvals,
            wallet_tauri_common::agent_commands::agent_wallet_revoke_agent,
            wallet_tauri_common::agent_commands::agent_wallet_pending_approval,
            wallet_tauri_common::agent_commands::agent_wallet_approve_desktop,
            wallet_tauri_common::agent_commands::agent_wallet_reject,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_status,
            wallet_tauri_common::agent_commands::agent_wallet_companion_devices,
            wallet_tauri_common::agent_commands::agent_wallet_companion_revoke_device,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_suggest_endpoint,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_start,
            wallet_tauri_common::agent_commands::agent_wallet_rotation_candidate_pairing_start,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_accept_request,
            wallet_tauri_common::agent_commands::agent_wallet_rotation_candidate_pairing_accept_request,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_complete,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_complete_automatic,
            wallet_tauri_common::agent_commands::agent_wallet_rotation_candidate_pairing_complete,
            wallet_tauri_common::agent_commands::agent_wallet_companion_pairing_cancel,
            wallet_tauri_common::agent_commands::agent_wallet_companion_status,
            wallet_tauri_common::agent_commands::agent_wallet_companion_start,
            wallet_tauri_common::agent_commands::agent_wallet_companion_stop,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AgentAppState>()
                    && let Err(error) =
                        tauri::async_runtime::block_on(state.companion.shutdown_for_exit())
                {
                    tracing::error!(%error, "Agent companion shutdown failed during exit");
                }
                if let Some(state) = app.try_state::<AgentAppState>()
                    && let Err(error) = state.runtime.shutdown_for_exit()
                {
                    tracing::error!(%error, "Agent Wallet runtime shutdown failed during exit");
                }
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = wallet_tauri_common::desktop_relay::stop_managed_relay(&state);
                }
            }
        });
}
