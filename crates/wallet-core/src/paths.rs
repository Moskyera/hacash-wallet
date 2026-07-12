use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Root directory for all wallet local state (vault, settings, history, bills).
pub fn wallet_data_root() -> PathBuf {
    if let Ok(dir) = std::env::var("HACASH_WALLET_DATA") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("HacashWallet")
}

pub fn vault_path() -> PathBuf {
    wallet_data_root().join("vault.json")
}

pub fn settings_path() -> PathBuf {
    wallet_data_root().join("settings.json")
}

pub fn bills_path() -> PathBuf {
    wallet_data_root().join("l2_bills.json")
}

pub fn history_path() -> PathBuf {
    wallet_data_root().join("tx_history.json")
}

pub fn messenger_path() -> PathBuf {
    wallet_data_root().join("messenger.json")
}

pub fn quantum_keystore_path() -> PathBuf {
    wallet_data_root().join("quantum.keystore.enc")
}

pub fn biometric_unlock_path() -> PathBuf {
    wallet_data_root().join("biometric_unlock.enc")
}

/// Atomic write with restrictive permissions (0o600 on Unix).
pub fn secure_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    restrict_permissions(path);
    Ok(())
}

fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        let _ = (path,);
    }
}