mod platform;

use hacash_wallet_core::WalletService;
use hacash_wallet_core::hip23::{BalanceFloorInput, HeightScopeInput, Type3CheckInput};
use tauri::{Manager, RunEvent};
use wallet_tauri_common::AppState;

#[tauri::command]
fn wallet_list_bills(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.list_bills()).map_err(|e| e.to_string())?)
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
    Ok(serde_json::to_value(platform::platform_security_status()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_confirm_biometric_native(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let nonce = {
        let mut svc = state.inner.blocking_lock();
        svc.begin_native_biometric().map_err(|e| e.to_string())?
    };
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&message)?;
    let mut svc = state.inner.blocking_lock();
    svc.finish_native_biometric(&nonce)
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
            let mut svc = WalletService::new(node_override, None).map_err(|e| e.to_string())?;
            svc.warm_vault_cache().map_err(|e| e.to_string())?;
            app.manage(AppState::new(svc));
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
        .invoke_handler(wallet_tauri_common::wallet_invoke_handler![
            wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop,
            wallet_list_bills,
            wallet_validate_hip23,
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_start,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_stop,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_status,
            wallet_tauri_common::update_commands::wallet_install_desktop_update,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = wallet_tauri_common::desktop_relay::stop_managed_relay(&state);
                    tauri::async_runtime::block_on(async {
                        let _ = wallet_tauri_common::dapp_bridge::stop_dapp_bridge(&state).await;
                    });
                }
            }
        });
}
