use std::path::Path;

use crate::error::{WalletError, WalletResult};

const MAX_WALLET_SCOPE_BYTES: usize = 256;

/// Validate the caller-owned boundary used by scoped L2 stores.
///
/// The root is selected only by trusted wallet-service code. Untrusted
/// identities never become path components; each store hashes them before it
/// appends a directory below this root.
pub(crate) fn validate_scoped_l2_storage(
    trusted_l2_root: &Path,
    wallet_scope: &str,
) -> WalletResult<()> {
    if trusted_l2_root.as_os_str().is_empty() {
        return Err(WalletError::L2(
            "scoped L2 storage root must not be empty".into(),
        ));
    }
    if wallet_scope.is_empty()
        || wallet_scope.len() > MAX_WALLET_SCOPE_BYTES
        || wallet_scope.chars().any(char::is_control)
    {
        return Err(WalletError::L2(
            "scoped L2 wallet scope is empty, oversized, or contains control characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_storage_rejects_invalid_scope_and_empty_root() {
        let root = std::path::PathBuf::from("trusted-l2-root");
        assert!(validate_scoped_l2_storage(Path::new(""), "agent_wallet:one").is_err());
        assert!(validate_scoped_l2_storage(&root, "").is_err());
        assert!(validate_scoped_l2_storage(&root, "agent_wallet:\none").is_err());
        assert!(validate_scoped_l2_storage(&root, &"a".repeat(257)).is_err());
        assert!(validate_scoped_l2_storage(&root, "agent_wallet:one").is_ok());
    }
}
