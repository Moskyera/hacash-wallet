//! Desktop-only IPC (relay auto-start, platform security).

use hacash_wallet_core::DustWhisperSettings;
use tauri::{AppHandle, Runtime, State};

use crate::state::AppState;

/// Save the relay settings and bring the managed relay into line with them.
///
/// Generic over the Tauri runtime on purpose. Written as a bare `AppHandle` it
/// is `AppHandle<Wry>`, and Wry needs a real window server, so the press that
/// starts somebody's relay could not be entered by any test: the only way in
/// was the helper underneath it. `crates/wallet-tauri-common/tests/
/// messenger_two_wallets_one_relay.rs` starts the relay two wallets then talk
/// through by calling this, which is the same code the desktop Settings screen
/// runs.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_update_dust_whisper_settings_desktop<R: Runtime>(
    dust_whisper: DustWhisperSettings,
    state: State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), String> {
    {
        let mut svc = state.inner.lock().await;
        svc.update_dust_whisper_settings(dust_whisper)
            .map_err(|e| e.to_string())?;
    }
    crate::desktop_relay::sync_managed_relay(&app).await?;
    Ok(())
}
