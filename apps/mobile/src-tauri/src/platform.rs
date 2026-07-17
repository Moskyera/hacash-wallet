//! OS-native security: Windows Hello (desktop preview), Face ID / fingerprint (Android/iOS).

use tauri::AppHandle;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformSecurityStatus {
    pub native_biometric_available: bool,
    pub platform: String,
    pub biometric_kind: Option<String>,
}

pub fn platform_security_status(app: &AppHandle) -> PlatformSecurityStatus {
    let (available, kind) = native_biometric_status(app);
    PlatformSecurityStatus {
        native_biometric_available: available,
        platform: std::env::consts::OS.into(),
        biometric_kind: kind,
    }
}

pub fn native_biometric_available(app: &AppHandle) -> bool {
    #[cfg(windows)]
    {
        let _ = app;
        windows_hello_available()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        mobile_biometric_available(app)
    }
    #[cfg(not(any(windows, target_os = "android", target_os = "ios")))]
    {
        let _ = app;
        false
    }
}

pub fn verify_native_biometric(app: &AppHandle, message: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = app;
        windows_hello_verify(message)
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        mobile_biometric_verify(app, message)
    }
    #[cfg(not(any(windows, target_os = "android", target_os = "ios")))]
    {
        let _ = (app, message);
        Err("native biometric verification is not available on this platform".into())
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn native_biometric_status(app: &AppHandle) -> (bool, Option<String>) {
    use tauri_plugin_biometric::BiometricExt;
    match app.biometric().status() {
        Ok(s) => {
            let kind = if s.is_available {
                Some(format!("{:?}", s.biometry_type))
            } else {
                None
            };
            (s.is_available, kind)
        }
        Err(_) => (false, None),
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn mobile_biometric_available(app: &AppHandle) -> bool {
    native_biometric_status(app).0
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn native_biometric_status(_app: &AppHandle) -> (bool, Option<String>) {
    (native_biometric_available(_app), None)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn mobile_biometric_verify(app: &AppHandle, message: &str) -> Result<(), String> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    app.biometric()
        .authenticate(message.to_string(), AuthOptions::default())
        .map_err(|e| e.to_string())
}

#[cfg(windows)]
fn windows_hello_available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    UserConsentVerifier::CheckAvailabilityAsync()
        .ok()
        .and_then(|op| {
            wait_async_operation(&op)
                .ok()
                .map(|a| a == UserConsentVerifierAvailability::Available)
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn windows_hello_verify(message: &str) -> Result<(), String> {
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows::core::HSTRING;
    let op = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
        .map_err(|e| e.to_string())?;
    let result = wait_async_operation(&op).map_err(|e| e.to_string())?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else {
        Err("biometric verification cancelled or failed".into())
    }
}

#[cfg(windows)]
fn wait_async_operation<T>(op: &windows::Foundation::IAsyncOperation<T>) -> windows::core::Result<T>
where
    T: windows::core::RuntimeType,
{
    use std::time::Duration;
    use windows::Foundation::AsyncStatus;
    loop {
        match op.Status()? {
            AsyncStatus::Completed => return op.GetResults(),
            AsyncStatus::Error => {
                return Err(windows::core::Error::new(
                    windows::core::HRESULT(-1),
                    "async operation failed",
                ));
            }
            AsyncStatus::Canceled => {
                return Err(windows::core::Error::new(
                    windows::core::HRESULT(0x800704C7u32 as i32),
                    "async operation canceled",
                ));
            }
            AsyncStatus::Started | _ => {
                std::thread::sleep(Duration::from_millis(40));
            }
        }
    }
}
