#[cfg(target_os = "android")]
pub async fn install_apk(app: &tauri::AppHandle, path: &str) -> Result<(), String> {
    crate::android_native::install_apk(app, path).await
}

#[cfg(not(target_os = "android"))]
pub async fn install_apk(_app: &tauri::AppHandle, _path: &str) -> Result<(), String> {
    Err("not android".to_string())
}
