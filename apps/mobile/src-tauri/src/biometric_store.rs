#[cfg(target_os = "android")]
pub async fn store(app: &tauri::AppHandle, passphrase: &str) -> Result<(), String> {
    wallet_tauri_common::android_native::biometric_store(app, passphrase).await
}

#[cfg(target_os = "android")]
pub async fn load(app: &tauri::AppHandle) -> Result<zeroize::Zeroizing<String>, String> {
    wallet_tauri_common::android_native::biometric_load(app).await
}

#[derive(Clone, Debug)]
pub struct Status {
    pub configured: bool,
    pub key_security_level: String,
    pub hardware_backed: bool,
    pub strong_box_backed: bool,
    pub authentication_enforced_by_secure_hardware: bool,
    pub auth_per_use: bool,
}

#[cfg(target_os = "android")]
pub async fn status(app: &tauri::AppHandle) -> Result<Status, String> {
    let status = wallet_tauri_common::android_native::biometric_status(app).await?;
    Ok(Status {
        configured: status.configured,
        key_security_level: status.key_security_level,
        hardware_backed: status.hardware_backed,
        strong_box_backed: status.strong_box_backed,
        authentication_enforced_by_secure_hardware: status
            .authentication_enforced_by_secure_hardware,
        auth_per_use: status.auth_per_use,
    })
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
pub async fn load(_app: &tauri::AppHandle) -> Result<zeroize::Zeroizing<String>, String> {
    Err("secure biometric unlock storage is not available on this platform".into())
}

#[cfg(not(target_os = "android"))]
pub async fn status(_app: &tauri::AppHandle) -> Result<Status, String> {
    Ok(Status {
        configured: false,
        key_security_level: "unavailable".into(),
        hardware_backed: false,
        strong_box_backed: false,
        authentication_enforced_by_secure_hardware: false,
        auth_per_use: false,
    })
}

#[cfg(not(target_os = "android"))]
pub async fn clear(_app: &tauri::AppHandle) -> Result<(), String> {
    Ok(())
}
