use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

mod bundle;

use crate::state::AppState;

#[tauri::command]
pub async fn wallet_export_backup(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    let mut svc = state.inner.lock().await;
    bundle::export_bundle(&mut svc, &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_export_backup_to_downloads(
    passphrase: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    let json = Zeroizing::new({
        let mut svc = state.inner.lock().await;
        bundle::export_bundle(&mut svc, &passphrase).map_err(|error| error.to_string())?
    });
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let filename = format!("hacash-full-backup-v1-{stamp}.json");
    let cache_dir = app.path().cache_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;
    let cache_path = cache_dir.join(&filename);
    if json.len() > bundle::MAX_BACKUP_ENVELOPE_BYTES {
        return Err("backup file exceeds the safe size limit".into());
    }
    hacash_wallet_core::paths::secure_write(&cache_path, json.as_bytes())
        .map_err(|error| format!("write encrypted backup cache: {error}"))?;
    let path = cache_path.to_string_lossy().into_owned();

    #[cfg(target_os = "android")]
    let result = crate::backup_android::copy_backup_file_to_downloads(&app, &path, &filename).await;
    #[cfg(not(target_os = "android"))]
    let result = {
        let _ = (&app, &path, &filename);
        Err("Downloads export is only supported on Android".into())
    };

    if let Err(error) = hacash_wallet_core::paths::secure_delete_backup_file(&cache_path) {
        tracing::warn!("temporary backup cache cleanup failed: {error}");
    }
    result
}

#[tauri::command]
pub fn wallet_preview_backup(json: String) -> Result<serde_json::Value, String> {
    let preview = bundle::preview(json.trim()).map_err(|error| error.to_string())?;
    serde_json::to_value(preview).map_err(|error| error.to_string())
}

pub fn recover_interrupted_restore() -> Result<(), String> {
    bundle::recover_interrupted_restore().map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn wallet_import_backup(
    json: String,
    passphrase: String,
    delete_source: Option<String>,
    allow_legacy: Option<bool>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let json = Zeroizing::new(json);
    let passphrase = Zeroizing::new(passphrase);
    // External backup deletion is deliberately user-controlled. An IPC caller must never gain
    // arbitrary .json/content-URI deletion authority merely by completing a restore.
    let _ = delete_source;
    let address = {
        let mut svc = state.inner.lock().await;
        bundle::restore(
            &mut svc,
            json.trim(),
            &passphrase,
            allow_legacy.unwrap_or(false),
        )
        .map_err(|error| error.to_string())?
    };
    Ok(address)
}
