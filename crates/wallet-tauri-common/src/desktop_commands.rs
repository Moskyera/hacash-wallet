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