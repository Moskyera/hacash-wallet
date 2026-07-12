#[cfg(target_os = "android")]
fn delete_backup_source_on_main(source: &str) -> Result<(), String> {
    use jni::objects::JValue;
    use jni::JavaVM;

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

    if env.exception_check().map_err(|e| format!("exception_check: {e}"))? {
        env.exception_clear()
            .map_err(|e| format!("exception_clear: {e}"))?;
        return Err(
            result
                .err()
                .map(|e| format!("BackupFileHelper.deleteBackupSource: {e}"))
                .unwrap_or_else(|| "BackupFileHelper.deleteBackupSource failed".to_string()),
        );
    }

    let deleted = result
        .map_err(|e| format!("BackupFileHelper.deleteBackupSource: {e}"))?
        .z()
        .map_err(|e| format!("bool result: {e}"))?;
    if deleted {
        Ok(())
    } else {
        Err("backup file could not be deleted — remove it manually from Downloads".into())
    }
}

#[cfg(target_os = "android")]
pub fn delete_backup_source(app: &tauri::AppHandle, source: &str) -> Result<(), String> {
    use std::sync::mpsc::sync_channel;

    let source = source.to_string();
    let (tx, rx) = sync_channel(1);
    app.run_on_main_thread(move || {
        let _ = tx.send(delete_backup_source_on_main(&source));
    })
    .map_err(|e| e.to_string())?;
    rx.recv().map_err(|e| e.to_string())?
}

#[cfg(not(target_os = "android"))]
pub fn delete_backup_source(_app: &tauri::AppHandle, _source: &str) -> Result<(), String> {
    Err("content URI delete is only supported on Android".to_string())
}

