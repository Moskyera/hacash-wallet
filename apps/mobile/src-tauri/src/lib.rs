mod platform;

use hacash_wallet_core::WalletService;
use tauri::Manager;
use wallet_tauri_common::AppState;

#[tauri::command]
fn wallet_platform_security_status(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    Ok(serde_json::to_value(platform::platform_security_status(&app)).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_confirm_biometric_native(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let nonce = {
        let mut svc = state.inner.blocking_lock();
        svc.begin_native_biometric().map_err(|e| e.to_string())?
    };
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&app, &message)?;
    let mut svc = state.inner.blocking_lock();
    svc.finish_native_biometric(&nonce)
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
struct BiometricUnlockStatus {
    enabled: bool,
    configured: bool,
}

#[tauri::command]
fn wallet_biometric_unlock_status(state: tauri::State<'_, AppState>) -> Result<BiometricUnlockStatus, String> {
    let svc = state.inner.blocking_lock();
    Ok(BiometricUnlockStatus {
        enabled: svc.get_settings().biometric_unlock_enabled,
        configured: svc.biometric_unlock_configured(),
    })
}

#[tauri::command]
fn wallet_enable_biometric_unlock(
    app: tauri::AppHandle,
    passphrase: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    platform::verify_native_biometric(&app, "Enable biometric unlock for Hacash Wallet")?;
    let mut svc = state.inner.blocking_lock();
    svc.enable_biometric_unlock(&passphrase)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_disable_biometric_unlock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.disable_biometric_unlock().map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_unlock_biometric(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    platform::verify_native_biometric(&app, "Unlock Hacash Wallet")?;
    let passphrase = {
        let svc = state.inner.blocking_lock();
        svc.unlock_passphrase_for_biometric()
            .map_err(|e| e.to_string())?
    };
    let mut svc = state.inner.blocking_lock();
    svc.unlock(&passphrase).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    builder
        .setup(|app| {
            // Android/iOS: dirs::data_dir() is not app-writable; use internal app storage.
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
                std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
                // SAFETY: called once on the main thread during app setup, before wallet I/O.
                unsafe { std::env::set_var("HACASH_WALLET_DATA", &data_dir) };
            }
            let mut svc = WalletService::new(None, None).map_err(|e| e.to_string())?;
            if svc.status().has_wallet {
                if let Err(e) = svc.warm_vault_cache() {
                    tracing::warn!("vault cache warm skipped: {e}");
                }
            }
            app.manage(AppState::new(svc));
            Ok(())
        })
        .invoke_handler(wallet_tauri_common::wallet_invoke_handler_mobile![
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
            wallet_biometric_unlock_status,
            wallet_enable_biometric_unlock,
            wallet_disable_biometric_unlock,
            wallet_unlock_biometric,
            wallet_tauri_common::whisper_commands::wallet_update_dust_whisper_settings,
            wallet_tauri_common::update_commands::wallet_install_mobile_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while building mobile tauri application");
}