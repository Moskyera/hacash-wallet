//! dApp / MoneyNex bridge commands and webview helpers.

use tauri::{AppHandle, Manager, State};

use crate::state::AppState;

#[tauri::command]
pub fn wallet_bump_activity(state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.bump_unlock_activity();
    Ok(())
}

#[tauri::command]
pub fn wallet_dapp_connect(origin: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    svc.dapp_connect(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_dapp_wallet(origin: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    svc.dapp_wallet(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_dapp_heartbeat(origin: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    svc.dapp_heartbeat(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_transfer(
    origin: String,
    txobj: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    svc.dapp_transfer(&origin, &txobj)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_sign_tx(
    origin: String,
    txbody: String,
    autosubmit: Option<bool>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    svc.dapp_sign_tx(&origin, &txbody, autosubmit.unwrap_or(false))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_dapp_chain(
    origin: String,
    chain_id: Option<u64>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    svc.dapp_chain_status(&origin, chain_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_webview_eval(
    app: AppHandle,
    label: String,
    script: String,
) -> Result<(), String> {
    let webview = app
        .get_webview(&label)
        .ok_or_else(|| format!("webview '{label}' not found"))?;
    webview.eval(&script).map_err(|e| e.to_string())
}