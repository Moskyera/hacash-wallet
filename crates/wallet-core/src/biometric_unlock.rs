//! Migration helper for the retired v1 biometric cache.
//!
//! The old format stored its wrapping key beside the ciphertext. Production code can only detect
//! and delete that file; biometric secrets now belong to the operating-system keystore.

use crate::error::{WalletError, WalletResult};
use crate::paths::biometric_unlock_path;

pub(crate) fn is_configured() -> bool {
    biometric_unlock_path().exists()
}

pub(crate) fn clear() -> WalletResult<()> {
    let path = biometric_unlock_path();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    Ok(())
}
