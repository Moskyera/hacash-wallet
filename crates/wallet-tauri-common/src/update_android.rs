#[cfg(target_os = "android")]
fn install_apk_on_main(path: &str) -> Result<(), String> {
    use jni::JavaVM;
    use jni::objects::{JObject, JValue};

    let ctx = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;

    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
    let path_j = env.new_string(path).map_err(|e| format!("jstring: {e}"))?;

    let result = env.call_static_method(
        "org/hacash/wallet/mobile/ApkInstaller",
        "install",
        "(Landroid/app/Activity;Ljava/lang/String;)V",
        &[JValue::Object(&activity), JValue::Object(&path_j)],
    );

    if env
        .exception_check()
        .map_err(|e| format!("exception_check: {e}"))?
    {
        env.exception_clear()
            .map_err(|e| format!("exception_clear: {e}"))?;
        return Err(result
            .err()
            .map(|e| format!("ApkInstaller.install: {e}"))
            .unwrap_or_else(|| "ApkInstaller.install failed".to_string()));
    }

    result.map_err(|e| format!("ApkInstaller.install: {e}"))?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn install_apk(_app: &tauri::AppHandle, path: &str) -> Result<(), String> {
    // ApkInstaller.install() marshals to the UI thread internally (see Kotlin).
    install_apk_on_main(path)
}

#[cfg(not(target_os = "android"))]
pub fn install_apk(_app: &tauri::AppHandle, _path: &str) -> Result<(), String> {
    Err("not android".to_string())
}
