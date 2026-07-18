#[cfg(target_os = "android")]
pub async fn copy_backup_file_to_downloads(
    app: &tauri::AppHandle,
    source_path: &str,
    display_name: &str,
) -> Result<String, String> {
    crate::android_native::copy_backup_to_downloads(app, source_path, display_name).await
}

#[cfg(target_os = "android")]
pub async fn delete_backup_source(app: &tauri::AppHandle, source: &str) -> Result<(), String> {
    crate::android_native::delete_backup_source(app, source).await
}

#[cfg(not(target_os = "android"))]
pub async fn copy_backup_file_to_downloads(
    _app: &tauri::AppHandle,
    _source_path: &str,
    _display_name: &str,
) -> Result<String, String> {
    Err("Downloads export is only supported on Android".into())
}

#[cfg(not(target_os = "android"))]
pub async fn delete_backup_source(_app: &tauri::AppHandle, _source: &str) -> Result<(), String> {
    Err("content URI delete is only supported on Android".to_string())
}
