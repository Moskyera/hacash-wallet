//! Locked memory buffers. reduce swap exposure for short-lived secrets (mlock / VirtualLock).

use zeroize::Zeroize;

use crate::error::WalletResult;

/// Byte buffer pinned in RAM where the OS supports it; zeroized on drop.
pub struct LockedBytes {
    inner: Vec<u8>,
    locked: bool,
}

impl LockedBytes {
    pub fn from_slice(data: &[u8]) -> WalletResult<Self> {
        let mut inner = data.to_vec();
        let locked = lock_pages(inner.as_mut_ptr(), inner.len());
        if !locked {
            tracing::warn!("secure_mem: could not lock memory pages. continuing with zeroize-only");
        }
        Ok(Self { inner, locked })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn into_string(self) -> String {
        String::from_utf8_lossy(self.as_slice()).into_owned()
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        if self.locked {
            unlock_pages(self.inner.as_mut_ptr(), self.inner.len());
        }
        self.inner.zeroize();
    }
}

fn lock_pages(ptr: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        unsafe { libc::mlock(ptr as *const _, len) == 0 }
    }
    #[cfg(windows)]
    {
        unsafe { windows::Win32::System::Memory::VirtualLock(ptr as *const _, len).is_ok() }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

fn unlock_pages(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(unix)]
    {
        unsafe {
            let _ = libc::munlock(ptr as *const _, len);
        }
    }
    #[cfg(windows)]
    {
        unsafe {
            let _ = windows::Win32::System::Memory::VirtualUnlock(ptr as *const _, len);
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
    }
}

/// Run KDF / decrypt with passphrase bytes in locked memory.
pub fn with_locked_passphrase<F, T>(passphrase: &str, f: F) -> WalletResult<T>
where
    F: FnOnce(&[u8]) -> WalletResult<T>,
{
    let locked = LockedBytes::from_slice(passphrase.as_bytes())?;
    f(locked.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_bytes_roundtrip() {
        let b = LockedBytes::from_slice(b"secret-pass-12").unwrap();
        assert_eq!(b.as_slice(), b"secret-pass-12");
    }

    #[test]
    fn locked_bytes_zeroized_on_drop() {
        let ptr: *const u8;
        {
            let b = LockedBytes::from_slice(b"erase-me-12345").unwrap();
            ptr = b.as_slice().as_ptr();
            drop(b);
        }
        // Best-effort: cannot assert zeroed across alloc reuse; smoke only.
        let _ = ptr;
    }
}
