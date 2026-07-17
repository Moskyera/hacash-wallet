use serde::{Deserialize, Serialize};

/// GitHub releases source for in-app updates (desktop + mobile).
pub const GITHUB_REPO: &str = "Moskyera/hacash-wallet";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub download_url: Option<String>,
    pub release_notes: Option<String>,
    pub asset_name: Option<String>,
    pub download_size: Option<u64>,
    pub sha256: Option<String>,
    pub release_page: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
    state: String,
}

pub fn parse_semver_triplet(raw: &str) -> Option<(u32, u32, u32)> {
    let base = raw.trim().trim_start_matches('v').split('-').next()?;
    let mut parts = base.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

fn is_newer(latest: (u32, u32, u32), current: (u32, u32, u32)) -> bool {
    latest > current
}

pub async fn check_app_update(
    channel: &str,
    current_version: &str,
) -> Result<AppUpdateInfo, String> {
    let suffix = match channel {
        "desktop" => "-desktop",
        "mobile" => "-mobile",
        other => return Err(format!("unknown update channel: {other}")),
    };

    let current_triplet = parse_semver_triplet(current_version)
        .ok_or_else(|| format!("invalid current version: {current_version}"))?;

    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=40");
    let client = reqwest::Client::builder()
        .user_agent("hacash-wallet-updater")
        .build()
        .map_err(|e| e.to_string())?;
    let releases: Vec<GhRelease> = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;

    let mut best: Option<(GhRelease, (u32, u32, u32))> = None;
    for release in releases {
        if release.draft || release.prerelease || !release.tag_name.ends_with(suffix) {
            continue;
        }
        let ver_str = release
            .tag_name
            .trim_start_matches('v')
            .trim_end_matches(suffix);
        let Some(triplet) = parse_semver_triplet(ver_str) else {
            continue;
        };
        if best.as_ref().map(|(_, v)| triplet > *v).unwrap_or(true) {
            best = Some((release, triplet));
        }
    }

    let Some((release, latest_triplet)) = best else {
        return Ok(AppUpdateInfo {
            current_version: current_version.to_string(),
            latest_version: current_version.to_string(),
            update_available: false,
            download_url: None,
            release_notes: None,
            release_page: None,
            asset_name: None,
            download_size: None,
            sha256: None,
        });
    };

    let latest_version = format!(
        "v{}.{}.{}",
        latest_triplet.0, latest_triplet.1, latest_triplet.2
    );
    let update_available = is_newer(latest_triplet, current_triplet);

    let asset_hint = if channel == "mobile" {
        "hacash-wallet-mobile"
    } else {
        "hacash-wallet-desktop"
    };
    let candidate =
        if channel == "mobile" {
            release
                .assets
                .iter()
                .find(|asset| asset.name.contains(asset_hint) && asset.name.ends_with(".apk"))
        } else {
            release
                .assets
                .iter()
                .find(|asset| asset.name.contains(asset_hint) && asset.name.ends_with("-setup.exe"))
                .or_else(|| {
                    release.assets.iter().find(|asset| {
                        asset.name.contains(asset_hint) && asset.name.ends_with(".exe")
                    })
                })
                .or_else(|| {
                    release.assets.iter().find(|asset| {
                        asset.name.contains(asset_hint) && asset.name.ends_with(".msi")
                    })
                })
        };
    let max_size = max_update_size(channel)?;
    let trusted_asset = candidate.filter(|asset| {
        asset.state == "uploaded"
            && (100_000..=max_size).contains(&asset.size)
            && normalized_asset_digest(asset).is_some()
            && validate_release_download_url(&asset.browser_download_url).is_ok()
    });
    let download_url = trusted_asset.map(|asset| asset.browser_download_url.clone());

    Ok(AppUpdateInfo {
        current_version: current_version.to_string(),
        latest_version,
        update_available,
        download_url,
        release_notes: release.body.clone().or(release.name.clone()),
        release_page: release.html_url.clone(),
        asset_name: trusted_asset.as_ref().map(|asset| asset.name.clone()),
        download_size: trusted_asset.as_ref().map(|asset| asset.size),
        sha256: trusted_asset
            .as_ref()
            .and_then(|asset| normalized_asset_digest(asset)),
    })
}

const MAX_APK_BYTES: u64 = 300 * 1024 * 1024;
const MAX_DESKTOP_INSTALLER_BYTES: u64 = 600 * 1024 * 1024;

fn max_update_size(channel: &str) -> Result<u64, String> {
    match channel {
        "mobile" => Ok(MAX_APK_BYTES),
        "desktop" => Ok(MAX_DESKTOP_INSTALLER_BYTES),
        other => Err(format!("unknown update channel: {other}")),
    }
}

fn normalized_asset_digest(asset: &GhAsset) -> Option<String> {
    let digest = asset.digest.as_deref()?.strip_prefix("sha256:")?;
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(digest.to_ascii_lowercase())
    } else {
        None
    }
}

pub fn validate_release_download_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid update URL: {e}"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("update URL is not a trusted GitHub release URL".into());
    }
    let prefix = format!("/{GITHUB_REPO}/releases/download/");
    if !url.path().starts_with(&prefix) {
        return Err("update URL points outside the pinned wallet repository".into());
    }
    Ok(url)
}

fn trusted_redirect_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some(
                "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
}

/// APK downloads must live under a path exposed by Android FileProvider (`cache-path` / `files-path`).
pub fn validate_apk_file(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;

    let meta = std::fs::metadata(path).map_err(|e| format!("apk metadata: {e}"))?;
    if !meta.is_file() {
        return Err("download is not a file".into());
    }
    if meta.len() < 100_000 {
        return Err(format!(
            "downloaded APK too small ({} bytes). download may have failed",
            meta.len()
        ));
    }
    let mut magic = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|e| format!("apk read: {e}"))?;
    if magic != [0x50, 0x4B] {
        return Err("downloaded file is not a valid APK archive".into());
    }
    Ok(())
}

pub fn validate_windows_exe(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;

    let meta = std::fs::metadata(path).map_err(|e| format!("exe metadata: {e}"))?;
    if !meta.is_file() {
        return Err("download is not a file".into());
    }
    if meta.len() < 500_000 {
        return Err(format!(
            "downloaded installer too small ({} bytes). download may have failed",
            meta.len()
        ));
    }
    let mut magic = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|e| format!("exe read: {e}"))?;
    if magic != [0x4D, 0x5A] {
        return Err("downloaded file is not a valid Windows installer (EXE)".into());
    }
    Ok(())
}

pub fn validate_windows_msi(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;

    let meta = std::fs::metadata(path).map_err(|e| format!("msi metadata: {e}"))?;
    if !meta.is_file() {
        return Err("download is not a file".into());
    }
    if meta.len() < 500_000 {
        return Err(format!(
            "downloaded MSI too small ({} bytes). download may have failed",
            meta.len()
        ));
    }
    let mut magic = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|e| format!("msi read: {e}"))?;
    // OLE compound document header (standard MSI container).
    if magic != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Err("downloaded file is not a valid Windows installer (MSI)".into());
    }
    Ok(())
}

pub fn validate_downloaded_update(path: &std::path::Path) -> Result<(), String> {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "apk" => validate_apk_file(path),
        "exe" => validate_windows_exe(path),
        "msi" => validate_windows_msi(path),
        other => Err(format!("unsupported update file type: .{other}")),
    }
}

pub async fn download_update_file(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let parsed_url = validate_release_download_url(url)?;
    let expected_sha256 = expected_sha256.to_ascii_lowercase();
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("update SHA-256 is missing or invalid".into());
    }
    let extension = dest
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let max_size = match extension.as_str() {
        "apk" => MAX_APK_BYTES,
        "exe" | "msi" => MAX_DESKTOP_INSTALLER_BYTES,
        other => return Err(format!("unsupported update file type: .{other}")),
    };
    if !(100_000..=max_size).contains(&expected_size) {
        return Err("update size is outside the allowed range".into());
    }

    let parent = dest
        .parent()
        .ok_or_else(|| "update destination has no parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut part_name = dest.as_os_str().to_os_string();
    part_name.push(".part");
    let part_path = std::path::PathBuf::from(part_name);
    let _ = std::fs::remove_file(&part_path);

    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error(std::io::Error::other("too many update redirects"));
        }
        if trusted_redirect_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.error(std::io::Error::other("untrusted update redirect"))
        }
    });
    let client = reqwest::Client::builder()
        .user_agent("hacash-wallet-updater")
        .redirect(redirect)
        .build()
        .map_err(|e| e.to_string())?;

    let result: Result<(), String> = async {
        let mut response = client
            .get(parsed_url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        if !trusted_redirect_url(response.url()) {
            return Err("update download ended on an untrusted host".into());
        }
        if let Some(length) = response.content_length() {
            if length != expected_size || length > max_size {
                return Err(format!(
                    "update size mismatch: expected {expected_size}, server reported {length}"
                ));
            }
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .map_err(|e| format!("create update file: {e}"))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            total = total
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| "update size overflow".to_string())?;
            if total > expected_size || total > max_size {
                return Err("update exceeded the trusted size".into());
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .map_err(|e| format!("write update file: {e}"))?;
        }
        file.flush()
            .map_err(|e| format!("flush update file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("sync update file: {e}"))?;
        drop(file);

        if total != expected_size {
            return Err(format!(
                "update size mismatch: expected {expected_size}, downloaded {total}"
            ));
        }
        let actual_sha256 = format!("{:x}", hasher.finalize());
        if actual_sha256 != expected_sha256 {
            return Err("update SHA-256 verification failed".into());
        }
        match extension.as_str() {
            "apk" => validate_apk_file(&part_path)?,
            "exe" => validate_windows_exe(&part_path)?,
            "msi" => validate_windows_msi(&part_path)?,
            _ => unreachable!(),
        }
        if dest.exists() {
            std::fs::remove_file(dest).map_err(|e| format!("replace cached update: {e}"))?;
        }
        std::fs::rename(&part_path, dest).map_err(|e| format!("commit update file: {e}"))?;
        Ok(())
    }
    .await;

    if result.is_err() {
        let _ = std::fs::remove_file(&part_path);
    }
    result
}

#[cfg(target_os = "windows")]
pub fn run_windows_installer(path: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x00000008;
    let path_str = path.to_string_lossy().to_string();
    if path.extension().and_then(|s| s.to_str()) == Some("exe") {
        std::process::Command::new(&path_str)
            .creation_flags(DETACHED_PROCESS)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    std::process::Command::new("msiexec")
        .args(["/i", &path_str])
        .creation_flags(DETACHED_PROCESS)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_installer(_path: &std::path::Path) -> Result<(), String> {
    Err("desktop installer launch is only supported on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_apk_rejects_tiny_or_non_zip() {
        let dir = tempfile::tempdir().unwrap();
        let tiny = dir.path().join("tiny.apk");
        std::fs::write(&tiny, b"x").unwrap();
        assert!(validate_apk_file(&tiny).is_err());

        let bad = dir.path().join("bad.apk");
        std::fs::write(&bad, vec![0u8; 200_000]).unwrap();
        assert!(validate_apk_file(&bad).is_err());
    }

    #[test]
    fn validate_apk_accepts_zip_header() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.apk");
        let mut f = std::fs::File::create(&ok).unwrap();
        f.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
        f.write_all(&vec![0u8; 200_000]).unwrap();
        assert!(validate_apk_file(&ok).is_ok());
    }

    #[test]
    fn validate_windows_exe_accepts_mz_header() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("setup.exe");
        let mut f = std::fs::File::create(&ok).unwrap();
        f.write_all(b"MZ").unwrap();
        f.write_all(&vec![0u8; 600_000]).unwrap();
        assert!(validate_windows_exe(&ok).is_ok());
    }

    #[test]
    fn validate_downloaded_update_routes_by_extension() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("u.exe");
        let mut f = std::fs::File::create(&exe).unwrap();
        f.write_all(b"MZ").unwrap();
        f.write_all(&vec![0u8; 600_000]).unwrap();
        assert!(validate_downloaded_update(&exe).is_ok());

        let apk = dir.path().join("u.apk");
        let mut f = std::fs::File::create(&apk).unwrap();
        f.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
        f.write_all(&vec![0u8; 200_000]).unwrap();
        assert!(validate_downloaded_update(&apk).is_ok());
    }

    #[test]
    fn semver_parsing_for_update_channel() {
        assert_eq!(parse_semver_triplet("0.1.30"), Some((0, 1, 30)));
        assert_eq!(parse_semver_triplet("v0.1.30-mobile"), Some((0, 1, 30)));
    }

    #[test]
    fn release_url_is_pinned_to_exact_repository() {
        assert!(validate_release_download_url(
            "https://github.com/Moskyera/hacash-wallet/releases/download/v1/hacash-wallet-mobile.apk"
        )
        .is_ok());
        assert!(
            validate_release_download_url(
                "https://github.com/Moskyera/hacash-wallet.evil/releases/download/v1/update.apk"
            )
            .is_err()
        );
        assert!(
            validate_release_download_url(
                "https://github.com/other/repo/releases/download/v1/update.apk"
            )
            .is_err()
        );
        assert!(
            validate_release_download_url(
                "http://github.com/Moskyera/hacash-wallet/releases/download/v1/update.apk"
            )
            .is_err()
        );
    }

    #[test]
    fn github_asset_digest_requires_sha256() {
        let asset = GhAsset {
            name: "hacash-wallet-mobile.apk".into(),
            browser_download_url:
                "https://github.com/Moskyera/hacash-wallet/releases/download/v1/update.apk".into(),
            size: 200_000,
            digest: Some(format!("sha256:{}", "A".repeat(64))),
            state: "uploaded".into(),
        };
        assert_eq!(normalized_asset_digest(&asset), Some("a".repeat(64)));
    }
}
