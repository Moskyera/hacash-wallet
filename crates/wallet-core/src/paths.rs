use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
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

/// Atomically replace a wallet state file without ever creating a
/// world-readable or predictable temporary file.
pub fn secure_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wallet path has no parent"))?;
    fs::create_dir_all(parent)?;
    reject_symlink(parent, "wallet data directory")?;
    restrict_directory_permissions(parent)?;
    reject_symlink(path, "wallet state file")?;

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wallet path has no filename"))?
        .to_string_lossy();
    let temp_path = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // No other process may read a partially written secret file.
            options.share_mode(0);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        restrict_file_permissions(&temp_path)?;
        drop(file);

        // Refuse a target that changed into a symlink while bytes were written.
        reject_symlink(path, "wallet state file")?;
        fs::rename(&temp_path, path)?;
        restrict_file_permissions(path)?;
        sync_parent_directory(parent)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn reject_symlink(path: &Path, label: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must not be a symlink"),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn restrict_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        apply_private_windows_acl(path, false)?;
    }
    Ok(())
}

fn restrict_directory_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        apply_private_windows_acl(path, true)?;
    }
    Ok(())
}

#[cfg(windows)]
fn apply_private_windows_acl(path: &Path, directory: bool) -> io::Result<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };
    use windows::core::{PCWSTR, w};

    // Protect the DACL from inheritance and grant full control only to the
    // object's owner and LocalSystem. Directory ACEs inherit to all children.
    let sddl = if directory {
        w!("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)")
    } else {
        w!("D:P(A;;FA;;;OW)(A;;FA;;;SY)")
    };
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(windows_acl_error)?;
    }

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let result = unsafe {
        SetFileSecurityW(
            PCWSTR(wide_path.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok()
        .map_err(windows_acl_error)
    };
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    result
}

#[cfg(windows)]
fn windows_acl_error(error: windows::core::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("wallet ACL: {error}"),
    )
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(windows)]
    {
        let _ = (path,);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_write_replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        secure_write(&path, b"first secret").unwrap();
        secure_write(&path, b"replacement secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement secret");
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    #[test]
    fn secure_write_sets_private_unix_permissions_and_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        secure_write(&path, b"secret").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let real = dir.path().join("real.json");
        fs::write(&real, b"do not overwrite").unwrap();
        let link = dir.path().join("linked.json");
        symlink(&real, &link).unwrap();
        assert!(secure_write(&link, b"attacker controlled").is_err());
        assert_eq!(fs::read(&real).unwrap(), b"do not overwrite");
    }
}
