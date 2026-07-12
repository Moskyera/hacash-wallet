//! Desktop-only IPC (relay auto-start, platform security).

use hacash_wallet_core::DustWhisperSettings;
use tauri::{AppHandle, State};

use crate::state::AppState;

#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_update_dust_whisper_settings_desktop(
    dust_whisper: DustWhisperSettings,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    {
        let mut svc = state.inner.lock().await;
        svc.update_dust_whisper_settings(dust_whisper)
            .map_err(|e| e.to_string())?;
    }
    crate::desktop_relay::sync_managed_relay(&app).await?;
    Ok(())
}

#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_dapp_bridge_start(state: State<'_, AppState>) -> Result<u16, String> {
    crate::dapp_bridge::start_dapp_bridge(&state).await
}

#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_dapp_bridge_stop(state: State<'_, AppState>) -> Result<(), String> {
    crate::dapp_bridge::stop_dapp_bridge(&state).await
}

#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_dapp_bridge_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    crate::dapp_bridge::bridge_status(&state).await
}