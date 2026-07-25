//! Exact prepared-operation commands. Execution accepts only an opaque id;
//! transaction bytes and economic fields remain in wallet-core memory.

use tauri::State;

use crate::state::AppState;

#[tauri::command]
pub async fn wallet_prepare_send_hac(
    to: String,
    amount_mei: f64,
    send_options: Option<hacash_wallet_core::SendOptions>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let options = send_options.unwrap_or_else(|| {
        hacash_wallet_core::SendOptions::from_preferences(&service.get_settings().send)
    });
    let prepared = service
        .prepare_send_hac(&to, amount_mei, options)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_hac(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let result = service
        .execute_prepared_hac(&operation_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_prepare_send_hacd(
    to: String,
    diamond_names: Vec<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_send_hacd(&to, &diamond_names)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_hacd(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let result = service
        .execute_prepared_hacd(&operation_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_prepare_send_btc(
    to: String,
    satoshi: u64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_send_btc(&to, satoshi)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_btc(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let result = service
        .execute_prepared_btc(&operation_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_prepare_channel_open(
    hub_address: String,
    user_deposit_mei: f64,
    hub_deposit_mei: f64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_channel_open(&hub_address, user_deposit_mei, hub_deposit_mei)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_channel_open(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut service = state.inner.lock().await;
    service
        .execute_prepared_channel_open(&operation_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_prepare_channel_close(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_channel_close()
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_channel_close(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut service = state.inner.lock().await;
    service
        .execute_prepared_channel_close(&operation_id)
        .await
        .map_err(|error| error.to_string())
}
#[tauri::command]
pub fn wallet_prepare_airgap_sign(
    unsigned: hacash_wallet_core::AirgapUnsigned,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.blocking_lock();
    let prepared = service
        .prepare_airgap_sign(&unsigned)
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn wallet_execute_prepared_airgap_sign(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.blocking_lock();
    let result = service
        .execute_prepared_airgap_sign(&operation_id)
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}
