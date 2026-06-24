mod state;

use hacash_wallet_core::security::{SecurityProfile, UnlockContext};
use hacash_wallet_core::WalletService;
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
async fn wallet_send_hac(
    to: String,
    amount_mei: f64,
    biometric_ok: bool,
    yubikey_ok: bool,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut svc = state.inner.lock().await;
    let ctx = UnlockContext {
        biometric_ok,
        yubikey_ok,
    };
    let result = svc
        .send_hac(&to, amount_mei, ctx)
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
    svc.set_security_profile(profile);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            app.manage(AppState::new(WalletService::new(None, None)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_status,
            wallet_create,
            wallet_unlock,
            wallet_lock,
            wallet_balance,
            wallet_preview_send,
            wallet_send_hac,
            wallet_set_security_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}