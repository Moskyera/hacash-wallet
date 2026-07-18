use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::state::AppState;

#[tauri::command]
pub async fn wallet_export_backup_to_downloads(
    passphrase: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    let json = Zeroizing::new({
        let svc = state.inner.lock().await;
        svc.export_backup(&passphrase).map_err(|e| e.to_string())?
    });
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let filename = format!("hacash-backup-{stamp}.json");
    let cache_dir = app.path().cache_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;
    let cache_path = cache_dir.join(&filename);
    std::fs::write(&cache_path, json.as_bytes()).map_err(|e| e.to_string())?;
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
pub fn wallet_preview_backup(json: String) -> Result<String, String> {
    hacash_wallet_core::vault::EncryptedVault::backup_address_from_json(json.trim())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_import_backup(
    json: String,
    passphrase: String,
    delete_source: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let json = Zeroizing::new(json);
    let passphrase = Zeroizing::new(passphrase);
    let delete_source = delete_source.map(Zeroizing::new);
    let address = {
        let mut svc = state.inner.lock().await;
        svc.import_backup(json.trim(), &passphrase)
            .map_err(|e| e.to_string())?
    };

    if let Some(source) = delete_source.as_ref() {
        let trimmed = source.trim();
        if !trimmed.is_empty() {
            let delete_result = if trimmed.starts_with("content://") {
                #[cfg(target_os = "android")]
                {
                    crate::backup_android::delete_backup_source(&app, trimmed).await
                }
                #[cfg(not(target_os = "android"))]
                {
                    let _ = &app;
                    Err("content URI delete requires Android".into())
                }
            } else {
                let _ = &app;
                hacash_wallet_core::paths::secure_delete_backup_file(std::path::Path::new(trimmed))
            };
            if let Err(msg) = delete_result {
                tracing::warn!("backup source not deleted after import: {msg}");
            }
        }
    }

    Ok(address)
}
