mod commands;
mod platform;

use hacash_wallet_core::hip23::{BalanceFloorInput, HeightScopeInput, Type3CheckInput};
use hacash_wallet_core::hardware::HardwareSigningMode;
use hacash_wallet_core::security::SecurityProfile;
use hacash_wallet_core::WalletService;
use tauri::{Manager, RunEvent};
use wallet_tauri_common::AppState;

#[tauri::command]
fn wallet_webauthn_register_begin(
    client_origin: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_register_begin(client_origin.as_deref())
        .map_err(|e| e.to_string())
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
fn wallet_webauthn_auth_begin(
    client_origin: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let svc = state.inner.blocking_lock();
    svc.webauthn_auth_begin(client_origin.as_deref())
        .map_err(|e| e.to_string())
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
fn wallet_list_bills(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.blocking_lock();
    Ok(serde_json::to_value(svc.list_bills()).map_err(|e| e.to_string())?)
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
fn wallet_platform_security_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::to_value(platform::platform_security_status()).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_confirm_biometric_native(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let nonce = {
        let mut svc = state.inner.blocking_lock();
        svc.begin_native_biometric().map_err(|e| e.to_string())?
    };
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&message)?;
    let mut svc = state.inner.blocking_lock();
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
fn wallet_set_hardware_mode(mode: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
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
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = wallet_tauri_common::desktop_relay::sync_managed_relay(&handle).await
                {
                    tracing::warn!(error = %e, "DUST Whisper relay auto-start skipped");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_tauri_common::commands::wallet_status,
            wallet_tauri_common::commands::wallet_create,
            wallet_tauri_common::commands::wallet_import,
            wallet_tauri_common::commands::wallet_export_backup,
            wallet_tauri_common::commands::wallet_change_passphrase,
            wallet_tauri_common::commands::wallet_unlock,
            wallet_tauri_common::commands::wallet_lock,
            wallet_tauri_common::commands::wallet_balance,
            wallet_tauri_common::commands::wallet_asset_summary,
            wallet_tauri_common::commands::wallet_get_settings,
            wallet_tauri_common::commands::wallet_update_settings,
            wallet_tauri_common::commands::wallet_tx_history,
            wallet_tauri_common::commands::wallet_clear_tx_history,
            wallet_tauri_common::commands::wallet_fast_pay_status,
            wallet_tauri_common::commands::wallet_enable_fast_pay,
            wallet_tauri_common::commands::wallet_hub_health,
            wallet_tauri_common::commands::wallet_discover_hubs,
            wallet_tauri_common::commands::wallet_export_private_key,
            wallet_tauri_common::commands::wallet_list_bill_summaries,
            wallet_tauri_common::commands::wallet_export_bill_json,
            wallet_tauri_common::commands::wallet_export_all_bills_json,
            wallet_tauri_common::commands::wallet_get_bill_hex,
            wallet_tauri_common::commands::wallet_update_privacy_settings,
            wallet_tauri_common::commands::wallet_preview_send,
            wallet_tauri_common::commands::wallet_send_hac,
            wallet_tauri_common::commands::wallet_query_diamond,
            wallet_tauri_common::commands::wallet_list_owned_diamonds,
            wallet_tauri_common::commands::wallet_preview_send_hacd,
            wallet_tauri_common::commands::wallet_send_hacd,
            wallet_tauri_common::commands::wallet_preview_send_btc,
            wallet_tauri_common::commands::wallet_send_btc,
            wallet_tauri_common::commands::wallet_channel_info,
            wallet_tauri_common::commands::wallet_preview_channel_open,
            wallet_tauri_common::commands::wallet_open_channel,
            wallet_tauri_common::commands::wallet_close_channel,
            wallet_tauri_common::commands::wallet_import_watch_only,
            wallet_tauri_common::commands::wallet_open_watch_only,
            wallet_tauri_common::commands::wallet_set_security_profile,
            wallet_tauri_common::commands::wallet_set_hardware_mode,
            wallet_tauri_common::commands::wallet_platform_info,
            wallet_tauri_common::whisper_commands::wallet_whisper_relay_health,
            wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop,
            wallet_tauri_common::whisper_commands::messenger_threads,
            wallet_tauri_common::whisper_commands::messenger_messages,
            wallet_tauri_common::whisper_commands::messenger_mark_read,
            wallet_tauri_common::whisper_commands::messenger_send,
            wallet_tauri_common::whisper_commands::messenger_poll_inbox,
            wallet_tauri_common::quantum_commands::quantum_get_settings,
            wallet_tauri_common::quantum_commands::quantum_set_mode,
            wallet_tauri_common::quantum_commands::quantum_create_pqc,
            wallet_tauri_common::quantum_commands::quantum_create_hybrid,
            wallet_tauri_common::quantum_commands::quantum_import_keystore_v3,
            wallet_tauri_common::quantum_commands::quantum_export_keystore_v3,
            wallet_tauri_common::quantum_commands::quantum_preview_keystore,
            wallet_tauri_common::quantum_commands::quantum_send_type4,
            wallet_tauri_common::quantum_commands::quantum_send_test_tx,
            wallet_tauri_common::quantum_commands::quantum_node_ping,
            wallet_tauri_common::quantum_commands::quantum_balance,
            wallet_tauri_common::quantum_commands::quantum_preflight_type4,
            wallet_webauthn_register_begin,
            wallet_webauthn_register_finish,
            wallet_webauthn_auth_begin,
            wallet_webauthn_auth_finish,
            wallet_list_bills,
            wallet_validate_hip23,
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
            wallet_airgap_prepare_send,
            wallet_airgap_sign_unsigned,
            wallet_airgap_broadcast_signed,
            wallet_airgap_parse_qr,
            wallet_airgap_parse_qr_batch,
            commands::quantum_create_hybrid_from_privakey,
            commands::quantum_prepare_airgap_type4,
            commands::quantum_airgap_sign_type4,
            wallet_tauri_common::dapp_commands::wallet_bump_activity,
            wallet_tauri_common::dapp_commands::wallet_dapp_connect,
            wallet_tauri_common::dapp_commands::wallet_dapp_wallet,
            wallet_tauri_common::dapp_commands::wallet_dapp_heartbeat,
            wallet_tauri_common::dapp_commands::wallet_dapp_transfer,
            wallet_tauri_common::dapp_commands::wallet_dapp_sign_tx,
            wallet_tauri_common::dapp_commands::wallet_dapp_chain,
            wallet_tauri_common::dapp_commands::wallet_webview_eval,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_start,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_stop,
            wallet_tauri_common::desktop_commands::wallet_dapp_bridge_status,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = wallet_tauri_common::desktop_relay::stop_managed_relay(&state);
                    tauri::async_runtime::block_on(async {
                        let _ = wallet_tauri_common::dapp_bridge::stop_dapp_bridge(&state).await;
                    });
                }
            }
        });
}