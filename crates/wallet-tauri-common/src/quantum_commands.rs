//! Quantum / Type-4 IPC. shared by desktop and mobile Tauri apps.

use std::sync::Arc;

use hacash_wallet_core::WalletService;
use hacash_wallet_core::airgap::{AirgapPrepareResult, AirgapSignResult, AirgapUnsigned};
use hacash_wallet_core::quantum::{
    QuantumAccountInfo, QuantumPreflight, QuantumSendResult, QuantumSettings, QuantumTestResult,
};
use tauri::State;
use tokio::sync::Mutex;

use crate::state::AppState;

fn with_unlocked<F, T>(svc: &mut WalletService, f: F) -> Result<T, String>
where
    F: FnOnce(&mut WalletService) -> hacash_wallet_core::WalletResult<T>,
{
    if svc.status().locked {
        return Err("wallet locked".into());
    }
    svc.bump_unlock_activity();
    f(svc).map_err(|e| e.to_string())
}

async fn run_wallet_task<F, T>(inner: Arc<Mutex<WalletService>>, f: F) -> Result<T, String>
where
    F: FnOnce(&mut WalletService) -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut svc = inner.blocking_lock();
        f(&mut svc)
    })
    .await
    .map_err(|e| format!("quantum task failed: {e}"))?
}

#[tauri::command]
pub fn quantum_get_settings(state: State<'_, AppState>) -> Result<QuantumSettings, String> {
    let svc = state.inner.blocking_lock();
    Ok(svc.quantum_settings())
}

#[tauri::command]
pub async fn quantum_set_mode(enabled: bool, state: State<'_, AppState>) -> Result<(), String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| s.set_quantum_mode(enabled))
    })
    .await
}

#[tauri::command]
pub async fn quantum_create_pqc(
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<QuantumAccountInfo, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| s.quantum_create_pqc(&keystore_password))
    })
    .await
}

#[tauri::command]
pub async fn quantum_create_hybrid(
    keystore_password: String,
    legacy_prikey_hex: Option<String>,
    state: State<'_, AppState>,
) -> Result<QuantumAccountInfo, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| {
            s.quantum_create_hybrid(&keystore_password, legacy_prikey_hex.as_deref())
        })
    })
    .await
}

#[tauri::command]
pub async fn quantum_create_hybrid_from_privakey(
    legacy_prikey_hex: String,
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<QuantumAccountInfo, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| {
            s.quantum_create_hybrid_from_privakey(&legacy_prikey_hex, &keystore_password)
        })
    })
    .await
}

#[tauri::command]
pub async fn quantum_import_keystore_v3(
    json: String,
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<QuantumAccountInfo, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| {
            s.quantum_import_keystore(&json, &keystore_password)
        })
    })
    .await
}

#[tauri::command]
pub async fn quantum_export_keystore_v3(
    keystore_password: String,
    new_password: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        if svc.status().locked {
            return Err("wallet locked".into());
        }
        svc.bump_unlock_activity();
        svc.quantum_export_keystore(&keystore_password, new_password.as_deref())
            .map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn quantum_preview_keystore(
    json: String,
    keystore_password: String,
) -> Result<QuantumAccountInfo, String> {
    let pass = keystore_password;
    tokio::task::spawn_blocking(move || {
        hacash_wallet_core::quantum::preview_keystore(&json, &pass).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("preview task failed: {e}"))?
}

#[tauri::command]
pub async fn quantum_send_type4(
    to_address: String,
    amount_hacash: String,
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<QuantumSendResult, String> {
    let mut svc = state.inner.lock().await;
    if svc.status().locked {
        return Err("wallet locked".into());
    }
    svc.bump_unlock_activity();
    svc.quantum_send_type4(&to_address, &amount_hacash, &keystore_password)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_send_test_tx(
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<QuantumTestResult, String> {
    let mut svc = state.inner.lock().await;
    if svc.status().locked {
        return Err("wallet locked".into());
    }
    svc.bump_unlock_activity();
    svc.quantum_send_test_tx(&keystore_password)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_node_ping(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let svc = state.inner.lock().await;
    svc.quantum_node_metrics().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_balance(state: State<'_, AppState>) -> Result<f64, String> {
    let svc = state.inner.lock().await;
    svc.quantum_balance_mei().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_preflight_type4(
    to_address: String,
    amount_hacash: String,
    state: State<'_, AppState>,
) -> Result<QuantumPreflight, String> {
    let svc = state.inner.lock().await;
    svc.quantum_preflight_type4(&to_address, &amount_hacash)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_prepare_airgap_type4(
    to_address: String,
    amount_hacash: String,
    state: State<'_, AppState>,
) -> Result<AirgapPrepareResult, String> {
    let mut svc = state.inner.lock().await;
    if svc.status().locked {
        return Err("wallet locked".into());
    }
    svc.bump_unlock_activity();
    svc.prepare_airgap_type4(&to_address, &amount_hacash)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_airgap_sign_type4(
    unsigned: AirgapUnsigned,
    keystore_password: String,
    state: State<'_, AppState>,
) -> Result<AirgapSignResult, String> {
    run_wallet_task(Arc::clone(&state.inner), move |svc| {
        with_unlocked(svc, |s| {
            s.quantum_airgap_sign_type4(&unsigned, &keystore_password)
        })
    })
    .await
}
