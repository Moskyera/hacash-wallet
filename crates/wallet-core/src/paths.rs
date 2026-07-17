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
/// Delete a user-owned backup `.json` after one-time import. Never deletes wallet data under [`wallet_data_root`].
pub fn secure_delete_backup_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("backup file not found".into());
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext != "json" {
        return Err("only .json backup files can be deleted".into());
    }
    if path.file_name().and_then(|s| s.to_str()) == Some("vault.json") {
        return Err("refusing to delete active wallet vault".into());
    }

    let wallet_root = wallet_data_root()
        .canonicalize()
        .unwrap_or_else(|_| wallet_data_root());
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("backup path: {e}"))?;
    if canonical.starts_with(&wallet_root) {
        return Err("refusing to delete files inside wallet data directory".into());
    }

    std::fs::remove_file(&canonical).map_err(|e| format!("failed to delete backup file: {e}"))?;
    Ok(())
}

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
