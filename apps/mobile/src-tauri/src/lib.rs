mod biometric_store;
mod platform;

use hacash_wallet_core::WalletService;
use tauri::Manager;
use wallet_tauri_common::AppState;
use zeroize::Zeroizing;

#[tauri::command]
async fn wallet_platform_security_status(
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    serde_json::to_value(platform::platform_security_status(&app).await).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_confirm_biometric_native(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let nonce = {
        let mut svc = state.inner.lock().await;
        svc.begin_native_biometric().map_err(|e| e.to_string())?
    };
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&app, &message).await?;
    let mut svc = state.inner.lock().await;
    svc.finish_native_biometric(&nonce)
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
struct BiometricUnlockStatus {
    enabled: bool,
    configured: bool,
}

#[tauri::command]
async fn wallet_biometric_unlock_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<BiometricUnlockStatus, String> {
    let enabled = {
        let svc = state.inner.lock().await;
        svc.get_settings().biometric_unlock_enabled
    };
    let configured = biometric_store::is_configured(&app).await?;
    Ok(BiometricUnlockStatus {
        enabled,
        configured,
    })
}

#[tauri::command]
async fn wallet_enable_biometric_unlock(
    app: tauri::AppHandle,
    passphrase: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let passphrase = Zeroizing::new(passphrase);
    {
        let mut svc = state.inner.lock().await;
        svc.verify_wallet_passphrase(&passphrase)
            .map_err(|e| e.to_string())?;
    }
    platform::verify_native_biometric(&app, "Enable biometric unlock for Hacash Wallet").await?;
    biometric_store::store(&app, &passphrase).await?;
    let settings_result = {
        let mut svc = state.inner.lock().await;
        svc.set_biometric_unlock_enabled(true)
    };
    if let Err(error) = settings_result {
        let _ = biometric_store::clear(&app).await;
        return Err(error.to_string());
    }
    Ok(())
}

#[tauri::command]
async fn wallet_disable_biometric_unlock(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    biometric_store::clear(&app).await?;
    let mut svc = state.inner.lock().await;
    svc.set_biometric_unlock_enabled(false)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_unlock_biometric(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    platform::verify_native_biometric(&app, "Unlock Hacash Wallet").await?;
    let passphrase = Zeroizing::new(biometric_store::load(&app).await?);
    let mut svc = state.inner.lock().await;
    svc.unlock(&passphrase).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(target_os = "ios")]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(wallet_tauri_common::android_native::init());
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
            if svc.biometric_unlock_configured() {
                tracing::warn!(
                    "removing legacy biometric cache that stored its wrapping key on disk"
                );
                if let Err(error) = svc.disable_biometric_unlock() {
                    tracing::warn!("legacy biometric cache removal failed: {error}");
                }
            }

            if svc.status().has_wallet
                && let Err(e) = svc.warm_vault_cache()
            {
                tracing::warn!("vault cache warm skipped: {e}");
            }
            app.manage(AppState::new(svc));
            Ok(())
        })
        // Plain Tauri handler only. Never catch_unwind around IPC on Android.
        // JNI Rust_ipc is nounwind; unwind/abort there crashes the app (SIGABRT).
        .invoke_handler(wallet_tauri_common::wallet_invoke_handler![
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
