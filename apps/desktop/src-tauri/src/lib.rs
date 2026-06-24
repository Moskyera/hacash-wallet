mod platform;
mod state;

use hacash_wallet_core::hip23::{BalanceFloorInput, HeightScopeInput, Type3CheckInput};
use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::{PrivacySettings, WalletService, WalletSettings};
use state::AppState;
use tauri::Manager;

#[tauri::command]
fn wallet_status(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.status()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_create(passphrase: String, state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.create_wallet(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_import(
    seed: String,
    passphrase: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.import_wallet(&seed, &passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_export_backup(
    passphrase: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.export_backup(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_change_passphrase(
    old_passphrase: String,
    new_passphrase: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.change_passphrase(&old_passphrase, &new_passphrase)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_unlock(passphrase: String, state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.unlock(&passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_lock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.lock();
    Ok(())
}

#[tauri::command]
async fn wallet_balance(state: tauri::State<'_, AppState>) -> Result<f64, String> {
    let mut svc = state.inner.lock().await;
    svc.balance_mei().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_get_settings(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.get_settings()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_update_settings(
    settings: WalletSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.update_settings(settings).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_webauthn_register_begin(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_register_begin().map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_webauthn_register_finish(
    credential_json: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.webauthn_register_finish(&credential_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_webauthn_auth_begin(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_auth_begin().map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_webauthn_auth_finish(
    assertion_json: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.webauthn_auth_finish(&assertion_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_hub_health(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    let health = svc.hub_health().await.map_err(|e| e.to_string())?;
    serde_json::to_value(health).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_list_bills(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.list_bills()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_tx_history(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.tx_history()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_validate_hip23(
    universal: Type3CheckInput,
    p2: Option<HeightScopeInput>,
    p3: Option<BalanceFloorInput>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    let checks = svc.validate_hip23_patterns(universal, p2, p3);
    serde_json::to_value(checks).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_channel_info(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let info = svc.channel_info().await.map_err(|e| e.to_string())?;
    serde_json::to_value(info).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_preview_channel_open(
    hub_address: String,
    user_deposit_mei: f64,
    hub_deposit_mei: f64,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let preview = svc
        .preview_channel_open(&hub_address, user_deposit_mei, hub_deposit_mei)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_open_channel(
    hub_address: String,
    user_deposit_mei: f64,
    hub_deposit_mei: f64,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mut svc = state.inner.lock().await;
    svc.open_channel(&hub_address, user_deposit_mei, hub_deposit_mei)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_close_channel(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.lock().await;
    svc.close_channel().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_preview_send(
    to: String,
    amount_mei: f64,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let preview = svc.preview_send(&to, amount_mei).await.map_err(|e| e.to_string())?;
    serde_json::to_value(preview).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_platform_security_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::to_value(platform::platform_security_status()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_confirm_biometric_native(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    let nonce = svc.begin_native_biometric().map_err(|e| e.to_string())?;
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&message)?;
    svc.finish_native_biometric(&nonce)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_import_watch_only(
    address: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.import_watch_only(&address).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_open_watch_only(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut svc = state.inner.blocking_lock();
    svc.open_watch_only().map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_set_hardware_mode(
    mode: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    let hw = HardwareSigningMode::from_name(&mode);
    svc.set_hardware_signing_mode(hw)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_airgap_prepare_send(
    to: String,
    amount_mei: f64,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .prepare_airgap_l1_send(&to, amount_mei)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_airgap_sign_unsigned(
    unsigned: hacash_wallet_core::AirgapUnsigned,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc
        .sign_airgap_unsigned(&unsigned)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_airgap_broadcast_signed(
    signed: hacash_wallet_core::AirgapSigned,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .broadcast_airgap_signed(&signed)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_airgap_parse_qr(
    text: String,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc.parse_airgap_qr(&text).map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_airgap_parse_qr_batch(
    parts: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.blocking_lock();
    let result = svc
        .parse_airgap_qr_batch(&parts)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_update_privacy_settings(
    privacy: PrivacySettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.update_privacy_settings(privacy)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_clear_tx_history(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    svc.clear_tx_history().map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_send_hac(
    to: String,
    amount_mei: f64,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let result = svc
        .send_hac(&to, amount_mei)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

#[tauri::command]
fn wallet_set_security_profile(
    profile: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut svc = state.inner.blocking_lock();
    let profile = match profile.as_str() {
        "paranoid" => SecurityProfile::paranoid(),
        _ => SecurityProfile::default(),
    };
    svc.set_security_profile(profile).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let mut svc = WalletService::new(None, None).map_err(|e| e.to_string())?;
            svc.warm_vault_cache().map_err(|e| e.to_string())?;
            app.manage(AppState::new(svc));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_status,
            wallet_create,
            wallet_import,
            wallet_export_backup,
            wallet_change_passphrase,
            wallet_unlock,
            wallet_lock,
            wallet_balance,
            wallet_get_settings,
            wallet_update_settings,
            wallet_webauthn_register_begin,
            wallet_webauthn_register_finish,
            wallet_webauthn_auth_begin,
            wallet_webauthn_auth_finish,
            wallet_hub_health,
            wallet_list_bills,
            wallet_tx_history,
            wallet_validate_hip23,
            wallet_channel_info,
            wallet_preview_channel_open,
            wallet_open_channel,
            wallet_close_channel,
            wallet_preview_send,
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
            wallet_import_watch_only,
            wallet_open_watch_only,
            wallet_set_hardware_mode,
            wallet_airgap_prepare_send,
            wallet_airgap_sign_unsigned,
            wallet_airgap_broadcast_signed,
            wallet_airgap_parse_qr,
            wallet_airgap_parse_qr_batch,
            wallet_update_privacy_settings,
            wallet_clear_tx_history,
            wallet_send_hac,
            wallet_set_security_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}