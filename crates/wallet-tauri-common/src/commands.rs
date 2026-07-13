//! Shared Tauri commands backed by `hacash-wallet-core`.

use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::{PrivacySettings, WalletSettings};
use tauri::State;

use crate::state::AppState;

#[tauri::command]
pub fn wallet_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.status()).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn wallet_create(passphrase: String, state: State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.create_wallet(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_import(
    seed: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.import_wallet(&seed, &passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_unlock(passphrase: String, state: State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.unlock(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_lock(state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.lock();
    Ok(())
}

#[tauri::command]
pub async fn wallet_balance(state: State<'_, AppState>) -> Result<f64, String> {
    let mut svc = state.inner.lock().await;
    svc.balance_mei().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_asset_summary(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let summary = svc.asset_summary().await.map_err(|e| e.to_string())?;
    serde_json::to_value(summary).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_get_settings(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.get_settings()).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn wallet_update_settings(
    settings: WalletSettings,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.update_settings(settings).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_reset(state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.reset_wallet().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_tx_history(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.tx_history()).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub async fn wallet_fast_pay_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let status = svc.fast_pay_status().await.map_err(|e| e.to_string())?;
    serde_json::to_value(status).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_enable_fast_pay(
    deposit_mei: Option<f64>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let status = svc
        .enable_fast_pay(deposit_mei)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(status).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_ping_node(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let url = svc.get_settings().node_url.clone();
    svc.ping_node()
        .await
        .map_err(|e| format!("{e} (node: {url})"))
        .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn wallet_ping_node_url(
    node_url: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use hacash_wallet_core::node::NodeClient;
    use hacash_wallet_core::settings::sanitize_node_url;

    let url = node_url
        .map(|u| sanitize_node_url(&u))
        .unwrap_or_else(|| {
            let svc = state.inner.blocking_lock();
            svc.get_settings().node_url.clone()
        });
    NodeClient::new(url.clone())
        .ping()
        .await
        .map_err(|e| format!("{e} (node: {url})"))
        .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn wallet_hub_health(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    match svc.hub_health().await.map_err(|e| e.to_string())? {
        Some(h) => serde_json::to_value(h).map_err(|e| e.to_string()),
        None => Ok(serde_json::Value::Null),
    }
}

#[tauri::command]
pub async fn wallet_discover_hubs(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let report = svc.discover_hubs().await.map_err(|e| e.to_string())?;
    serde_json::to_value(report).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_export_backup(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.export_backup(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_export_private_key(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.export_private_key(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_change_passphrase(
    old_passphrase: String,
    new_passphrase: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.change_passphrase(&old_passphrase, &new_passphrase)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_clear_tx_history(state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.clear_tx_history().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_list_bill_summaries(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    let summaries = svc.list_bill_summaries().map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(summaries).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn wallet_export_all_bills_json(state: State<'_, AppState>) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.export_all_bills_json().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_get_bill_hex(
    payment_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.get_bill_hex(&payment_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_export_bill_json(
    payment_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.export_bill_json(&payment_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_update_privacy_settings(
    privacy: PrivacySettings,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.update_privacy_settings(privacy)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_preview_send(
    to: String,
    amount_mei: f64,
    send_options: Option<hacash_wallet_core::SendOptions>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let options = send_options.unwrap_or_else(|| {
        hacash_wallet_core::SendOptions::from_preferences(&svc.get_settings().send)
    });
    let preview = svc
        .preview_send(&to, amount_mei, &options)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_send_hac(
    to: String,
    amount_mei: f64,
    send_options: Option<hacash_wallet_core::SendOptions>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let options = send_options.unwrap_or_else(|| {
        hacash_wallet_core::SendOptions::from_preferences(&svc.get_settings().send)
    });
    let result = svc
        .send_hac(&to, amount_mei, options)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_platform_info() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "mobile": cfg!(any(target_os = "android", target_os = "ios")),
    }))
}

#[tauri::command]
pub async fn wallet_query_diamond(name: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let info = svc
        .query_diamond(&name)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(info).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_list_owned_diamonds(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let svc = state.inner.lock().await;
    svc.list_owned_diamonds().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_preview_send_hacd(
    to: String,
    diamond_names: Vec<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let preview = svc
        .preview_send_hacd(&to, &diamond_names)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_send_hacd(
    to: String,
    diamond_names: Vec<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .send_hacd(&to, &diamond_names)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_channel_info(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let info = svc.channel_info().await.map_err(|e| e.to_string())?;
    serde_json::to_value(info).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_preview_channel_open(
    hub_address: String,
    user_deposit_mei: f64,
    hub_deposit_mei: f64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let preview = svc
        .preview_channel_open(&hub_address, user_deposit_mei, hub_deposit_mei)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_open_channel(
    hub_address: String,
    user_deposit_mei: f64,
    hub_deposit_mei: f64,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut svc = state.inner.lock().await;
    svc.open_channel(&hub_address, user_deposit_mei, hub_deposit_mei)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_close_channel(state: State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.lock().await;
    svc.close_channel().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_import_watch_only(address: String, state: State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.import_watch_only(&address).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_open_watch_only(state: State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.open_watch_only().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_set_security_profile(profile: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    let profile = match profile.as_str() {
        "paranoid" => SecurityProfile::paranoid(),
        _ => SecurityProfile::default(),
    };
    svc.set_security_profile(profile).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_set_hardware_mode(mode: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    let hw = HardwareSigningMode::from_name(&mode);
    svc.set_hardware_signing_mode(hw)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_preview_send_btc(
    to: String,
    satoshi: u64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let preview = svc
        .preview_send_btc(&to, satoshi)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_send_btc(
    to: String,
    satoshi: u64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc.send_btc(&to, satoshi).await.map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}