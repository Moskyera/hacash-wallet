#[cfg(target_os = "android")]
fn copy_backup_file_jni(source_path: &str, display_name: &str) -> Result<String, String> {
    use jni::JavaVM;
    use jni::objects::{JString, JValue};

    let ctx = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;

    let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let source_j = env
        .new_string(source_path)
        .map_err(|e| format!("jstring source: {e}"))?;
    let name_j = env
        .new_string(display_name)
        .map_err(|e| format!("jstring name: {e}"))?;

    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BackupExportHelper",
        "copyFileToDownloads",
        "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        &[
            JValue::Object(&activity),
            JValue::Object(&source_j),
            JValue::Object(&name_j),
        ],
    );

    if env
        .exception_check()
        .map_err(|e| format!("exception_check: {e}"))?
    {
        env.exception_clear()
            .map_err(|e| format!("exception_clear: {e}"))?;
        return Err(result
            .err()
            .map(|e| format!("BackupExportHelper.copyFileToDownloads: {e}"))
            .unwrap_or_else(|| "BackupExportHelper.copyFileToDownloads failed".to_string()));
    }

    let j_obj = result
        .map_err(|e| format!("BackupExportHelper.copyFileToDownloads: {e}"))?
        .l()
        .map_err(|e| format!("string result: {e}"))?;
    let j_str = unsafe { JString::from_raw(j_obj.into_raw()) };
    env.get_string(&j_str)
        .map_err(|e| format!("read jstring: {e}"))
        .map(|s| s.into())
}

#[cfg(target_os = "android")]
pub fn copy_backup_file_to_downloads(
    app: &tauri::AppHandle,
    source_path: &str,
    display_name: &str,
) -> Result<String, String> {
    let _ = app;
    copy_backup_file_jni(source_path, display_name)
}

#[cfg(target_os = "android")]
fn delete_backup_source_jni(source: &str) -> Result<(), String> {
    use jni::JavaVM;
    use jni::objects::JValue;

    let ctx = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;

    let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let source_j = env
        .new_string(source)
        .map_err(|e| format!("jstring: {e}"))?;

    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BackupFileHelper",
        "deleteBackupSource",
        "(Landroid/app/Activity;Ljava/lang/String;)Z",
        &[JValue::Object(&activity), JValue::Object(&source_j)],
    );

    if env
        .exception_check()
        .map_err(|e| format!("exception_check: {e}"))?
    {
        env.exception_clear()
            .map_err(|e| format!("exception_clear: {e}"))?;
        return Err(result
            .err()
            .map(|e| format!("BackupFileHelper.deleteBackupSource: {e}"))
            .unwrap_or_else(|| "BackupFileHelper.deleteBackupSource failed".to_string()));
    }

    let deleted = result
        .map_err(|e| format!("BackupFileHelper.deleteBackupSource: {e}"))?
        .z()
        .map_err(|e| format!("bool result: {e}"))?;
    if deleted {
        Ok(())
    } else {
        Err("backup file could not be deleted. remove it manually from Downloads".into())
    }
}

#[cfg(target_os = "android")]
pub fn delete_backup_source(app: &tauri::AppHandle, source: &str) -> Result<(), String> {
    let _ = app;
    delete_backup_source_jni(source)
}

#[cfg(not(target_os = "android"))]
pub fn copy_backup_file_to_downloads(
    _app: &tauri::AppHandle,
    _source_path: &str,
    _display_name: &str,
) -> Result<String, String> {
    Err("Downloads export is only supported on Android".into())
}

#[cfg(not(target_os = "android"))]
pub fn delete_backup_source(_app: &tauri::AppHandle, _source: &str) -> Result<(), String> {
    Err("content URI delete is only supported on Android".to_string())
}
