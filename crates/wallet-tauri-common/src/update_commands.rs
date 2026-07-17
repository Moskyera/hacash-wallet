use crate::update::{AppUpdateInfo, check_app_update, download_update_file, run_windows_installer};
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
    sha256: String,
    expected_size: u64,
) -> Result<String, String> {
    if filename.is_empty()
        || filename.len() > 160
        || !filename.starts_with("hacash-wallet-")
        || !filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("invalid update asset filename".into());
    }
    let extension = std::path::Path::new(&filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "apk" | "exe" | "msi") {
        return Err("unsupported update asset type".into());
    }

    let base = app.path().app_cache_dir().map_err(|e| e.to_string())?;
    let dir = base.join("updates");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(filename);
    download_update_file(&url, &dest, &sha256, expected_size).await?;
    Ok(dest.to_string_lossy().to_string())
}

#[tauri::command]
pub fn wallet_install_desktop_update(app: AppHandle, path: String) -> Result<(), String> {
    let path = checked_cached_update(&app, &path, &["exe", "msi"])?;
    run_windows_installer(&path)?;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(700));
        app.exit(0);
    });
    Ok(())
}

#[tauri::command]
pub fn wallet_install_mobile_update(app: AppHandle, path: String) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let path = checked_cached_update(&app, &path, &["apk"])?;
        return crate::update_android::install_apk(&app, &path.to_string_lossy());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        let _ = path;
        Err("in-app APK install is only supported on Android".to_string())
    }
}

fn checked_cached_update(
    app: &AppHandle,
    raw_path: &str,
    allowed_extensions: &[&str],
) -> Result<std::path::PathBuf, String> {
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|e| e.to_string())?
        .join("updates");
    std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let cache = cache
        .canonicalize()
        .map_err(|e| format!("update cache path: {e}"))?;
    let path = std::path::PathBuf::from(raw_path)
        .canonicalize()
        .map_err(|e| format!("update path: {e}"))?;
    if !path.starts_with(&cache) {
        return Err("update installer is outside the app cache".into());
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !allowed_extensions.contains(&extension.as_str()) {
        return Err("unexpected update installer type".into());
    }
    crate::update::validate_downloaded_update(&path)?;
    Ok(path)
}
