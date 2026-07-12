#[cfg(target_os = "android")]
fn install_apk_on_main(path: &str) -> Result<(), String> {
    use jni::objects::{JObject, JValue};
    use jni::JavaVM;

    let ctx = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;

    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
    let path_j = env.new_string(path).map_err(|e| format!("jstring: {e}"))?;

    env.call_static_method(
        "org/hacash/wallet/mobile/ApkInstaller",
        "install",
        "(Landroid/app/Activity;Ljava/lang/String;)V",
        &[JValue::Object(&activity), JValue::Object(&path_j)],
    )
    .map_err(|e| format!("ApkInstaller.install: {e}"))?;
    Ok(())
}

#[cfg(target_os = "android")]
pub fn install_apk(app: &tauri::AppHandle, path: &str) -> Result<(), String> {
    use std::sync::mpsc::sync_channel;

    let path = path.to_string();
    let (tx, rx) = sync_channel(1);
    app.run_on_main_thread(move || {
        let _ = tx.send(install_apk_on_main(&path));
    })
    .map_err(|e| e.to_string())?;
    rx.recv().map_err(|e| e.to_string())?
}

#[cfg(not(target_os = "android"))]
pub fn install_apk(_app: &tauri::AppHandle, _path: &str) -> Result<(), String> {
    Err("not android".to_string())
}