#[cfg(target_os = "android")]
fn android_context() -> Result<(jni::JavaVM, jni::objects::JObject<'static>), String> {
    let context = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }
        .map_err(|e| format!("JavaVM: {e}"))?;
    let activity = unsafe { jni::objects::JObject::from_raw(context.context().cast()) };
    Ok((vm, activity))
}

#[cfg(target_os = "android")]
fn clear_java_exception(env: &mut jni::JNIEnv<'_>, operation: &str) -> Result<(), String> {
    if env
        .exception_check()
        .map_err(|e| format!("exception check: {e}"))?
    {
        env.exception_clear()
            .map_err(|e| format!("exception clear: {e}"))?;
        return Err(format!(
            "{operation} failed; authenticate again or re-enable biometric unlock"
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
pub fn store(_app: &tauri::AppHandle, passphrase: &str) -> Result<(), String> {
    use jni::objects::JValue;
    let (vm, activity) = android_context()?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;
    let secret = env
        .new_string(passphrase)
        .map_err(|e| format!("passphrase string: {e}"))?;
    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BiometricSecretStore",
        "store",
        "(Landroid/app/Activity;Ljava/lang/String;)V",
        &[JValue::Object(&activity), JValue::Object(&secret)],
    );
    clear_java_exception(&mut env, "Android Keystore store")?;
    result
        .map_err(|e| format!("Android Keystore store: {e}"))?
        .v()
        .map_err(|e| format!("Android Keystore store result: {e}"))
}

#[cfg(target_os = "android")]
pub fn load(_app: &tauri::AppHandle) -> Result<String, String> {
    use jni::objects::{JString, JValue};
    let (vm, activity) = android_context()?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;
    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BiometricSecretStore",
        "load",
        "(Landroid/app/Activity;)Ljava/lang/String;",
        &[JValue::Object(&activity)],
    );
    clear_java_exception(&mut env, "Android Keystore load")?;
    let object = result
        .map_err(|e| format!("Android Keystore load: {e}"))?
        .l()
        .map_err(|e| format!("Android Keystore load result: {e}"))?;
    let secret = JString::from(object);
    env.get_string(&secret)
        .map(|value| value.into())
        .map_err(|e| format!("Android Keystore secret: {e}"))
}

#[cfg(target_os = "android")]
pub fn is_configured(_app: &tauri::AppHandle) -> Result<bool, String> {
    use jni::objects::JValue;
    let (vm, activity) = android_context()?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;
    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BiometricSecretStore",
        "isConfigured",
        "(Landroid/app/Activity;)Z",
        &[JValue::Object(&activity)],
    );
    clear_java_exception(&mut env, "Android Keystore status")?;
    result
        .map_err(|e| format!("Android Keystore status: {e}"))?
        .z()
        .map_err(|e| format!("Android Keystore status result: {e}"))
}

#[cfg(target_os = "android")]
pub fn clear(_app: &tauri::AppHandle) -> Result<(), String> {
    use jni::objects::JValue;
    let (vm, activity) = android_context()?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|e| format!("attach thread: {e}"))?;
    let result = env.call_static_method(
        "org/hacash/wallet/mobile/BiometricSecretStore",
        "clear",
        "(Landroid/app/Activity;)V",
        &[JValue::Object(&activity)],
    );
    clear_java_exception(&mut env, "Android Keystore clear")?;
    result
        .map_err(|e| format!("Android Keystore clear: {e}"))?
        .v()
        .map_err(|e| format!("Android Keystore clear result: {e}"))
}

#[cfg(not(target_os = "android"))]
pub fn store(_app: &tauri::AppHandle, _passphrase: &str) -> Result<(), String> {
    Err("secure biometric unlock storage is not available on this platform".into())
}

#[cfg(not(target_os = "android"))]
pub fn load(_app: &tauri::AppHandle) -> Result<String, String> {
    Err("secure biometric unlock storage is not available on this platform".into())
}

#[cfg(not(target_os = "android"))]
pub fn is_configured(_app: &tauri::AppHandle) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "android"))]
pub fn clear(_app: &tauri::AppHandle) -> Result<(), String> {
    Ok(())
}
