#[cfg(target_os = "android")]
pub async fn store(app: &tauri::AppHandle, passphrase: &str) -> Result<(), String> {
    wallet_tauri_common::android_native::biometric_store(app, passphrase).await
}

#[cfg(target_os = "android")]
pub async fn load(app: &tauri::AppHandle) -> Result<String, String> {
    wallet_tauri_common::android_native::biometric_load(app).await
}

#[cfg(target_os = "android")]
pub async fn is_configured(app: &tauri::AppHandle) -> Result<bool, String> {
    wallet_tauri_common::android_native::biometric_is_configured(app).await
}

#[cfg(target_os = "android")]
pub async fn clear(app: &tauri::AppHandle) -> Result<(), String> {
    wallet_tauri_common::android_native::biometric_clear(app).await
}

#[cfg(not(target_os = "android"))]
pub async fn store(_app: &tauri::AppHandle, _passphrase: &str) -> Result<(), String> {
    Err("secure biometric unlock storage is not available on this platform".into())
}

#[cfg(not(target_os = "android"))]
pub async fn load(_app: &tauri::AppHandle) -> Result<String, String> {
    Err("secure biometric unlock storage is not available on this platform".into())
}

#[cfg(not(target_os = "android"))]
pub async fn is_configured(_app: &tauri::AppHandle) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "android"))]
pub async fn clear(_app: &tauri::AppHandle) -> Result<(), String> {
    Ok(())
}
