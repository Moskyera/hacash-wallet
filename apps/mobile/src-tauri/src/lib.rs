mod agent_companion;
#[cfg(target_os = "android")]
pub mod agent_companion_identity;
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
    operation_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let challenge = {
        let mut svc = state.inner.lock().await;
        svc.begin_prepared_native_authorization(&operation_id)
            .map_err(|e| e.to_string())?
    };
    platform::verify_native_biometric(&app, &challenge.message).await?;
    let mut svc = state.inner.lock().await;
    svc.finish_prepared_native_authorization(&operation_id, &challenge.nonce)
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BiometricUnlockStatus {
    enabled: bool,
    configured: bool,
    key_security_level: String,
    hardware_backed: bool,
    strong_box_backed: bool,
    authentication_enforced_by_secure_hardware: bool,
    auth_per_use: bool,
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
    let native = biometric_store::status(&app).await?;
    Ok(BiometricUnlockStatus {
        enabled,
        configured: native.configured,
        key_security_level: native.key_security_level,
        hardware_backed: native.hardware_backed,
        strong_box_backed: native.strong_box_backed,
        authentication_enforced_by_secure_hardware: native
            .authentication_enforced_by_secure_hardware,
        auth_per_use: native.auth_per_use,
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
        if svc.get_settings().hardware_signing_mode == "airgap_only" {
            return Err(
                "Cold Vault forbids biometric unlock; use the passphrase on the offline signer"
                    .into(),
            );
        }
        svc.verify_wallet_passphrase(&passphrase)
            .map_err(|e| e.to_string())?;
    }
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
    let (enabled, signing_policy) = {
        let svc = state.inner.lock().await;
        let settings = svc.get_settings();
        (
            settings.biometric_unlock_enabled,
            settings.hardware_signing_mode,
        )
    };
    if signing_policy == "airgap_only" {
        let _ = biometric_store::clear(&app).await;
        return Err(
            "Cold Vault can only be unlocked with its passphrase on the offline signer".into(),
        );
    }
    if !enabled {
        return Err("biometric unlock is disabled in wallet settings".into());
    }
    // biometric_store::load presents the sole CryptoObject-bound prompt. A
    // separate generic prompt would not authorize this exact decrypt operation.
    let passphrase = biometric_store::load(&app).await?;
    let mut svc = state.inner.lock().await;
    svc.unlock(&passphrase).map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentCompanionIdentityView {
    platform_supported: bool,
    configured: bool,
    ready: bool,
    key_security_level: String,
    hardware_backed: bool,
    strong_box_backed: bool,
    authentication_enforced_by_secure_hardware: bool,
    auth_per_use: bool,
}

impl AgentCompanionIdentityView {
    #[cfg(target_os = "android")]
    fn from_android(status: agent_companion_identity::AndroidCompanionIdentityStatus) -> Self {
        let ready = status.configured
            && status.hardware_backed
            && status.authentication_enforced_by_secure_hardware
            && status.auth_per_use;
        Self {
            platform_supported: true,
            configured: status.configured,
            ready,
            key_security_level: status.key_security_level,
            hardware_backed: status.hardware_backed,
            strong_box_backed: status.strong_box_backed,
            authentication_enforced_by_secure_hardware: status
                .authentication_enforced_by_secure_hardware,
            auth_per_use: status.auth_per_use,
        }
    }

    #[cfg(not(target_os = "android"))]
    fn unsupported() -> Self {
        Self {
            platform_supported: false,
            configured: false,
            ready: false,
            key_security_level: "unavailable".to_owned(),
            hardware_backed: false,
            strong_box_backed: false,
            authentication_enforced_by_secure_hardware: false,
            auth_per_use: false,
        }
    }
}

#[tauri::command]
async fn agent_wallet_companion_identity_status(
    webview: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<AgentCompanionIdentityView, String> {
    agent_companion::require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        let status = agent_companion_identity::status(&app).await?;
        Ok(AgentCompanionIdentityView::from_android(status))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Ok(AgentCompanionIdentityView::unsupported())
    }
}

#[tauri::command]
async fn agent_wallet_companion_create_identity(
    webview: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<AgentCompanionIdentityView, String> {
    agent_companion::require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        drop(agent_companion_identity::create(&app).await?);
        let status = agent_companion_identity::status(&app).await?;
        Ok(AgentCompanionIdentityView::from_android(status))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err(
            "Mobile companion identity creation is available only on supported Android devices"
                .to_owned(),
        )
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(agent_companion::companion_lifecycle_plugin());
    #[cfg(target_os = "ios")]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    #[cfg(target_os = "android")]
    let builder = builder
        .plugin(wallet_tauri_common::android_native::init())
        .plugin(agent_companion_identity::init());
    builder
        .setup(|app| {
            let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
            // Android/iOS: dirs::data_dir() is not app-writable; use internal app storage.
            #[cfg(any(target_os = "android", target_os = "ios"))]
            // SAFETY: called once on the main thread during app setup, before wallet I/O.
            unsafe {
                std::env::set_var("HACASH_WALLET_DATA", &data_dir);
            }
            wallet_tauri_common::backup_commands::recover_interrupted_restore()
                .map_err(|error| format!("backup restore recovery: {error}"))?;
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
            app.manage(agent_companion::AgentCompanionMobileState::open(&data_dir));
            Ok(())
        })
        // Plain Tauri handler only. Never catch_unwind around IPC on Android.
        // JNI Rust_ipc is nounwind; unwind/abort there crashes the app (SIGABRT).
        .invoke_handler(wallet_tauri_common::wallet_invoke_handler![
            agent_wallet_companion_identity_status,
            agent_wallet_companion_create_identity,
            agent_companion::commands::agent_wallet_companion_pairing_start,
            agent_companion::commands::agent_wallet_companion_pairing_retry_request,
            agent_companion::commands::agent_wallet_rotation_candidate_pairing_start,
            agent_companion::commands::agent_wallet_companion_pairing_confirm,
            agent_companion::commands::agent_wallet_companion_pairing_deliver_ack,
            agent_companion::commands::agent_wallet_rotation_candidate_pairing_confirm,
            agent_companion::commands::agent_wallet_companion_pairing_cancel,
            agent_companion::commands::agent_wallet_companion_state,
            agent_companion::commands::agent_wallet_companion_connect,
            agent_companion::commands::agent_wallet_companion_sync,
            agent_companion::commands::agent_wallet_companion_ping,
            agent_companion::pilot::agent_wallet_companion_pending_fast_pay,
            agent_companion::pilot::agent_wallet_companion_decide_fast_pay,
            agent_companion::pilot::agent_wallet_companion_pending_hvm_fast_pay,
            agent_companion::pilot::agent_wallet_companion_decide_hvm_fast_pay,
            agent_companion::pilot::agent_wallet_companion_decide_payment,
            agent_companion::pilot::agent_wallet_companion_witness_anchor,
            agent_companion::pilot::agent_wallet_companion_witness_pending,
            agent_companion::pilot::agent_wallet_companion_rotation_step,
            agent_companion::commands::agent_wallet_companion_close_activity,
            agent_companion::commands::agent_wallet_companion_lifecycle,
            agent_companion::commands::agent_wallet_companion_discard_consent,
            agent_companion::commands::agent_wallet_companion_reset,
            agent_companion::commands::agent_wallet_companion_disconnect,
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
