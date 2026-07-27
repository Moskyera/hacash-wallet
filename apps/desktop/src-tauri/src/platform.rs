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
///
/// MUST NOT be called on the UI thread. The OS consent dialog is delivered through
/// the calling thread's message pump, and this call blocks until it resolves, so
/// running it on the UI thread prevents the dialog from ever completing and hangs
/// the window. Callers use `spawn_blocking`.
pub fn verify_native_biometric(message: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        in_com_apartment(|| windows_hello_verify(message))
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

/// Join a COM apartment for the duration of `f`.
///
/// Worker threads are not COM-initialized, and every WinRT activation fails with
/// `CO_E_NOTINITIALIZED` without this. `RPC_E_CHANGED_MODE` means the thread is
/// already in a different apartment, which is fine: we simply do not own it and
/// must not uninitialize it.
#[cfg(windows)]
fn in_com_apartment<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};

    // SAFETY: every early return below is after the owned/not-owned decision, and
    // CoUninitialize runs exactly once when this call performed the init.
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if hr.is_err() && hr != RPC_E_CHANGED_MODE {
        return Err(format!("COM apartment init failed: {hr:?}"));
    }
    let owned = hr.is_ok();
    let result = f();
    if owned {
        // SAFETY: balances the successful CoInitializeEx above on this thread.
        unsafe { CoUninitialize() };
    }
    result
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

/// Upper bound on any WinRT wait.
///
/// The consent dialog is driven by the caller's message pump. If this wait ever
/// runs on a thread that cannot pump, the operation stays `Started` forever, so a
/// bug here used to freeze the whole window. Time out instead: a clear error is
/// always better than an unresponsive wallet holding a prepared operation open.
#[cfg(windows)]
const WINRT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(windows)]
fn wait_async_operation<T>(op: &windows::Foundation::IAsyncOperation<T>) -> windows::core::Result<T>
where
    T: windows::core::RuntimeType,
{
    use std::time::{Duration, Instant};
    use windows::Foundation::AsyncStatus;
    let deadline = Instant::now() + WINRT_WAIT_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            let _ = op.Cancel();
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x800705B4u32 as i32), // ERROR_TIMEOUT
                "the OS consent prompt did not complete in time",
            ));
        }
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
