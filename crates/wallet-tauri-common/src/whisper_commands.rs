//! DUST Whisper + messenger IPC.

use hacash_wallet_core::{ChatMessage, ChatThread, DustWhisperSettings};
use tauri::State;

use crate::state::AppState;

fn require_unlocked(svc: &hacash_wallet_core::WalletService) -> Result<(), String> {
    if svc.status().locked {
        return Err("wallet locked".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn wallet_whisper_relay_health(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let health = svc.whisper_relay_health().await;
    serde_json::to_value(health).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_update_dust_whisper_settings(
    dust_whisper: DustWhisperSettings,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.update_dust_whisper_settings(dust_whisper)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn messenger_threads(state: State<'_, AppState>) -> Result<Vec<ChatThread>, String> {
    let svc = state.inner.blocking_lock();
    require_unlocked(&svc)?;
    svc.messenger_threads().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn messenger_messages(
    peer: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChatMessage>, String> {
    let svc = state.inner.blocking_lock();
    require_unlocked(&svc)?;
    svc.messenger_messages(&peer).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn messenger_mark_read(peer: String, state: State<'_, AppState>) -> Result<(), String> {
    let svc = state.inner.blocking_lock();
    require_unlocked(&svc)?;
    svc.messenger_mark_read(&peer).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn messenger_send(
    peer: String,
    body: String,
    peer_pubkey: Option<String>,
    state: State<'_, AppState>,
) -> Result<ChatMessage, String> {
    let svc = state.inner.lock().await;
    require_unlocked(&svc)?;
    svc.messenger_send(&peer, &body, peer_pubkey.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn messenger_poll_inbox(state: State<'_, AppState>) -> Result<u32, String> {
    let svc = state.inner.lock().await;
    require_unlocked(&svc)?;
    svc.messenger_poll_inbox().await.map_err(|e| e.to_string())
}
