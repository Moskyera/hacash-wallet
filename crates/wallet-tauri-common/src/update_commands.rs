use crate::update::{check_app_update, download_update_file, run_windows_installer, AppUpdateInfo};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[tauri::command]
pub async fn wallet_check_app_update(
    channel: String,
    current_version: String,
) -> Result<AppUpdateInfo, String> {
    check_app_update(&channel, &current_version).await
}

#[tauri::command]
pub async fn wallet_download_app_update(
    app: AppHandle,
    url: String,
    filename: String,
) -> Result<String, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| e.to_string())?;
    let dest = dir.join(filename);
    download_update_file(&url, &dest).await?;
    Ok(dest.to_string_lossy().to_string())
}

#[tauri::command]
pub fn wallet_install_desktop_update(path: String) -> Result<(), String> {
    run_windows_installer(PathBuf::from(path).as_path())
}

#[tauri::command]
pub fn wallet_install_mobile_update(app: AppHandle, path: String) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        return crate::update_android::install_apk(&app, &path);
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        let _ = path;
        Err("in-app APK install is only supported on Android".to_string())
    }
}