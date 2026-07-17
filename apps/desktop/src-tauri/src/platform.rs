//! OS-native security integrations (Windows Hello user consent).

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformSecurityStatus {
    pub native_biometric_available: bool,
    pub platform: String,
}

pub fn platform_security_status() -> PlatformSecurityStatus {
    PlatformSecurityStatus {
        native_biometric_available: native_biometric_available(),
        platform: std::env::consts::OS.into(),
    }
}

pub fn native_biometric_available() -> bool {
    #[cfg(windows)]
    {
        windows_hello_available()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Prompt Windows Hello / PIN. must succeed before wallet core accepts biometric 2FA.
pub fn verify_native_biometric(message: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_hello_verify(message)
    }
    #[cfg(not(windows))]
    {
        let _ = message;
        Err("native biometric verification is only available on Windows".into())
    }
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
            AsyncStatus::Started => {
                std::thread::sleep(Duration::from_millis(40));
            }
            _ => {
                std::thread::sleep(Duration::from_millis(40));
            }
        }
    }
}
