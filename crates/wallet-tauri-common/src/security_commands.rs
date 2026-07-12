//! WebAuthn and air-gap signing commands shared by desktop and mobile shells.

use hacash_wallet_core::{AirgapSigned, AirgapUnsigned};
use tauri::State;

use crate::state::AppState;

#[tauri::command]
pub fn wallet_webauthn_register_begin(
    client_origin: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_register_begin(client_origin.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_webauthn_register_finish(
    credential_json: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.webauthn_register_finish(&credential_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_webauthn_auth_begin(
    client_origin: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_auth_begin(client_origin.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_webauthn_auth_finish(
    assertion_json: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.webauthn_auth_finish(&assertion_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_airgap_prepare_send(
    to: String,
    amount_mei: f64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .prepare_airgap_l1_send(&to, amount_mei)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_airgap_sign_unsigned(
    unsigned: AirgapUnsigned,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc
        .sign_airgap_unsigned(&unsigned)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_airgap_broadcast_signed(
    signed: AirgapSigned,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .broadcast_airgap_signed(&signed)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_airgap_parse_qr(
    text: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc.parse_airgap_qr(&text).map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_airgap_parse_qr_batch(
    parts: Vec<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc
        .parse_airgap_qr_batch(&parts)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}