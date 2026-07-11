mod platform;

use hacash_wallet_core::WalletService;
use tauri::Manager;
use wallet_tauri_common::AppState;

#[tauri::command]
fn wallet_platform_security_status(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    Ok(serde_json::to_value(platform::platform_security_status(&app)).map_err(|e| e.to_string())?)
}

#[tauri::command]
fn wallet_confirm_biometric_native(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let nonce = {
        let mut svc = state.inner.blocking_lock();
        svc.begin_native_biometric().map_err(|e| e.to_string())?
    };
    let message = format!("Authorize Hacash Wallet transaction\nReference: {nonce}");
    platform::verify_native_biometric(&app, &message)?;
    let mut svc = state.inner.blocking_lock();
    svc.finish_native_biometric(&nonce)
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    let builder = tauri::Builder::default().plugin(tauri_plugin_deep_link::init());
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    builder
        .setup(|app| {
            let mut svc = WalletService::new(None, None).map_err(|e| e.to_string())?;
            svc.warm_vault_cache().map_err(|e| e.to_string())?;
            app.manage(AppState::new(svc));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_tauri_common::commands::wallet_status,
            wallet_tauri_common::commands::wallet_create,
            wallet_tauri_common::commands::wallet_import,
            wallet_tauri_common::commands::wallet_unlock,
            wallet_tauri_common::commands::wallet_lock,
            wallet_tauri_common::commands::wallet_balance,
            wallet_tauri_common::commands::wallet_asset_summary,
            wallet_tauri_common::commands::wallet_get_settings,
            wallet_tauri_common::commands::wallet_update_settings,
            wallet_tauri_common::commands::wallet_tx_history,
            wallet_tauri_common::commands::wallet_fast_pay_status,
            wallet_tauri_common::commands::wallet_enable_fast_pay,
            wallet_tauri_common::commands::wallet_hub_health,
            wallet_tauri_common::commands::wallet_export_backup,
            wallet_tauri_common::commands::wallet_change_passphrase,
            wallet_tauri_common::commands::wallet_clear_tx_history,
            wallet_tauri_common::commands::wallet_list_bill_summaries,
            wallet_tauri_common::commands::wallet_export_all_bills_json,
            wallet_tauri_common::commands::wallet_export_bill_json,
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
            wallet_tauri_common::security_commands::wallet_webauthn_register_begin,
            wallet_tauri_common::security_commands::wallet_webauthn_register_finish,
            wallet_tauri_common::security_commands::wallet_webauthn_auth_begin,
            wallet_tauri_common::security_commands::wallet_webauthn_auth_finish,
            wallet_tauri_common::security_commands::wallet_airgap_prepare_send,
            wallet_tauri_common::security_commands::wallet_airgap_sign_unsigned,
            wallet_tauri_common::security_commands::wallet_airgap_broadcast_signed,
            wallet_tauri_common::security_commands::wallet_airgap_parse_qr,
            wallet_tauri_common::security_commands::wallet_airgap_parse_qr_batch,
            wallet_platform_security_status,
            wallet_confirm_biometric_native,
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
            wallet_tauri_common::quantum_commands::quantum_prepare_airgap_type4,
            wallet_tauri_common::quantum_commands::quantum_airgap_sign_type4,
            wallet_tauri_common::whisper_commands::wallet_whisper_relay_health,
            wallet_tauri_common::whisper_commands::wallet_update_dust_whisper_settings,
            wallet_tauri_common::whisper_commands::messenger_threads,
            wallet_tauri_common::whisper_commands::messenger_messages,
            wallet_tauri_common::whisper_commands::messenger_mark_read,
            wallet_tauri_common::whisper_commands::messenger_send,
            wallet_tauri_common::whisper_commands::messenger_poll_inbox,
        ])
        .run(tauri::generate_context!())
        .expect("error while building mobile tauri application");
}