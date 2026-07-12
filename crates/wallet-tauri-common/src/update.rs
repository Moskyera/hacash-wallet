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
    pub release_page: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: Option<String>,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
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

pub async fn check_app_update(channel: &str, current_version: &str) -> Result<AppUpdateInfo, String> {
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
        if !release.tag_name.ends_with(suffix) {
            continue;
        }
        let ver_str = release.tag_name.trim_start_matches('v').trim_end_matches(suffix);
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
    let download_url = release
        .assets
        .iter()
        .find(|a| a.name.contains(asset_hint) && (a.name.ends_with(".apk") || a.name.ends_with(".exe")))
        .map(|a| a.browser_download_url.clone())
        .or_else(|| {
            release
                .assets
                .iter()
                .find(|a| a.name.ends_with(".msi"))
                .map(|a| a.browser_download_url.clone())
        });

    Ok(AppUpdateInfo {
        current_version: current_version.to_string(),
        latest_version,
        update_available,
        download_url,
        release_notes: release.body.clone().or(release.name.clone()),
        release_page: release.html_url.clone(),
    })
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
            "downloaded APK too small ({} bytes) — download may have failed",
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

pub async fn download_update_file(url: &str, dest: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let client = reqwest::Client::builder()
        .user_agent("hacash-wallet-updater")
        .build()
        .map_err(|e| e.to_string())?;
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;
    std::fs::write(dest, &bytes).map_err(|e| e.to_string())?;
    validate_apk_file(dest)?;
    Ok(())
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
    fn semver_parsing_for_update_channel() {
        assert_eq!(parse_semver_triplet("0.1.30"), Some((0, 1, 30)));
        assert_eq!(parse_semver_triplet("v0.1.30-mobile"), Some((0, 1, 30)));
    }
}