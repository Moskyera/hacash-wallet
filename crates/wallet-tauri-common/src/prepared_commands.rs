//! Exact prepared-operation commands. Execution accepts only an opaque id;
//! transaction bytes and economic fields remain in wallet-core memory.

use std::sync::Arc;

use tauri::{AppHandle, State};
use zeroize::Zeroizing;

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
pub async fn wallet_prepare_send_native_asset(
    to: String,
    serial: String,
    amount: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_send_native_asset(&to, &serial, &amount)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_execute_prepared_native_asset(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let result = service
        .execute_prepared_native_asset(&operation_id)
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
    user_deposit_mei: String,
    hub_deposit_mei: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_channel_open(&hub_address, &user_deposit_mei, &hub_deposit_mei)
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
pub async fn wallet_recover_channel_open(state: State<'_, AppState>) -> Result<String, String> {
    let mut service = state.inner.lock().await;
    service
        .recover_channel_open()
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
pub async fn wallet_recover_channel_close(state: State<'_, AppState>) -> Result<String, String> {
    let mut service = state.inner.lock().await;
    service
        .recover_channel_close()
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

#[tauri::command]
pub async fn wallet_prepare_cold_vault_activation(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut service = state.inner.lock().await;
    let prepared = service
        .prepare_cold_vault_activation()
        .map_err(|error| error.to_string())?;
    serde_json::to_value(prepared).map_err(|error| error.to_string())
}

/// Irreversible. Runs only after the platform ceremony has approved this exact
/// activation ticket.
#[tauri::command]
pub async fn wallet_execute_prepared_cold_vault_activation(
    operation_id: String,
    current_passphrase: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let current_passphrase = Zeroizing::new(current_passphrase);
    // Gate the shell-side pre-step on the ceremony having really happened, so a
    // hostile renderer cannot delete the OS unlock secret on its own.
    {
        let service = state.inner.lock().await;
        if !service.cold_vault_activation_is_authorized(&operation_id) {
            return Err(
                "no freshly authorized cold vault activation is pending for this operation".into(),
            );
        }
    }
    // Remove the OS-keystore passphrase before committing Cold Vault. A failed
    // migration may require biometric setup again, but must never leave a local
    // unlock shortcut behind an air-gap-only policy.
    crate::commands::clear_native_biometric_secret(&app).await?;
    // Activation re-encrypts the vault, which means three Argon2id derivations,
    // one of them at the paranoid cost. That is seconds of pure CPU, so it must
    // not run on an async runtime thread: doing so blocks every other command,
    // including the status poll, and the window looks frozen.
    let inner = Arc::clone(&state.inner);
    tauri::async_runtime::spawn_blocking(move || {
        let mut service = inner.blocking_lock();
        service
            .execute_prepared_cold_vault_activation(&operation_id, &current_passphrase)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("cold vault activation task failed: {error}"))?
}
