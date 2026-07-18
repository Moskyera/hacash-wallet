#[cfg(any(target_os = "windows", target_os = "android"))]
use std::path::Path;
use std::path::PathBuf;

use tauri::{AppHandle, Manager, State};

use crate::state::AppState;
#[cfg(target_os = "windows")]
use crate::update::run_windows_installer;
use crate::update::{
    AppUpdateInfo, TrustedUpdate, UpdateTarget, check_app_update, download_update_file,
};
#[cfg(any(target_os = "windows", target_os = "android"))]
use crate::update::{UpdateChannel, verify_downloaded_update};

#[tauri::command]
pub async fn wallet_check_app_update(
    current_version: String,
    state: State<'_, AppState>,
) -> Result<AppUpdateInfo, String> {
    check_app_update(&current_version, &state.updates).await
}

#[tauri::command]
pub async fn wallet_download_app_update(
    app: AppHandle,
    offer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let target = UpdateTarget::current();
    if !target.supports_automatic_install() {
        return Err("automatic update downloads are unavailable on this operating system or architecture; use the exact official release page".into());
    }

    let offer = state.updates.begin_download(&offer_id)?;
    if offer.channel != target.channel() {
        state.updates.download_failed(&offer_id);
        return Err("update offer belongs to a different operating system".into());
    }

    let result = download_offer(&app, &offer_id, &offer).await;
    match result {
        Ok(path) => {
            if let Err(error) = state.updates.download_complete(&offer_id, path.clone()) {
                let _ = std::fs::remove_file(path);
                state.updates.download_failed(&offer_id);
                return Err(error);
            }
            Ok(())
        }
        Err(error) => {
            state.updates.download_failed(&offer_id);
            Err(error)
        }
    }
}

async fn download_offer(
    app: &AppHandle,
    offer_id: &str,
    offer: &TrustedUpdate,
) -> Result<PathBuf, String> {
    let base = app.path().app_cache_dir().map_err(|e| e.to_string())?;
    let dir = base.join("updates").join(offer_id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(&offer.asset_name);
    download_update_file(
        &offer.download_url,
        &dest,
        &offer.sha256,
        offer.download_size,
    )
    .await?;
    Ok(dest)
}

#[tauri::command]
pub fn wallet_install_desktop_update(
    app: AppHandle,
    offer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let (offer, path) = state
            .updates
            .downloaded(&offer_id, UpdateChannel::Desktop)?;
        let path = checked_cached_update(&app, &path, &offer)?;
        run_windows_installer(&path)?;
        // The verified installer must be able to replace the running wallet
        // executable. Only exit after process creation succeeds; failures keep
        // the current session open so the user can retry safely.
        app.exit(0);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        let _ = offer_id;
        let _ = state;
        Err("automatic desktop install is only supported on Windows; use the exact official release page".to_string())
    }
}

#[tauri::command]
pub async fn wallet_install_mobile_update(
    app: AppHandle,
    offer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let (offer, path) = state.updates.downloaded(&offer_id, UpdateChannel::Mobile)?;
        let path = checked_cached_update(&app, &path, &offer)?;
        let install_path = path.to_string_lossy().into_owned();
        crate::update_android::install_apk(&app, &install_path).await?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        let _ = offer_id;
        let _ = state;
        Err("in-app APK install is only supported on Android".to_string())
    }
}

#[cfg(any(target_os = "windows", target_os = "android"))]
fn checked_cached_update(
    app: &AppHandle,
    stored_path: &Path,
    offer: &TrustedUpdate,
) -> Result<PathBuf, String> {
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|e| e.to_string())?
        .join("updates");
    std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let cache = cache
        .canonicalize()
        .map_err(|e| format!("update cache path: {e}"))?;
    let path = stored_path
        .canonicalize()
        .map_err(|e| format!("update path: {e}"))?;
    if !path.starts_with(&cache) {
        return Err("update installer is outside the app cache".into());
    }
    if path.file_name().and_then(|value| value.to_str()) != Some(offer.asset_name.as_str()) {
        return Err("cached installer does not match the trusted update offer".into());
    }
    verify_downloaded_update(&path, &offer.sha256, offer.download_size)?;
    Ok(path)
}
