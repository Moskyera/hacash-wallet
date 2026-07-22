use std::time::Duration;

use super::{GITHUB_REPO, valid_asset_filename};
const MAX_APK_BYTES: u64 = 300 * 1024 * 1024;
const MAX_DESKTOP_INSTALLER_BYTES: u64 = 600 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownloadTimeouts {
    connect: Duration,
    read: Duration,
    overall: Duration,
}

const DOWNLOAD_TIMEOUTS: DownloadTimeouts = DownloadTimeouts {
    connect: Duration::from_secs(15),
    // Abort a stalled body while allowing slow downloads that keep making progress.
    read: Duration::from_secs(30),
    // A 600 MB desktop installer still has a finite end-to-end deadline.
    overall: Duration::from_secs(30 * 60),
};

pub(super) fn max_update_size(channel: &str) -> Result<u64, String> {
    match channel {
        "mobile" => Ok(MAX_APK_BYTES),
        "desktop" => Ok(MAX_DESKTOP_INSTALLER_BYTES),
        other => Err(format!("unknown update channel: {other}")),
    }
}

pub fn validate_release_download_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|error| format!("invalid update URL: {error}"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
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

pub(super) fn validate_release_asset_url(
    raw: &str,
    tag: &str,
    asset_name: &str,
) -> Result<reqwest::Url, String> {
    if !valid_asset_filename(asset_name) {
        return Err("invalid release asset filename".into());
    }
    let url = validate_release_download_url(raw)?;
    let expected_path = format!("/{GITHUB_REPO}/releases/download/{tag}/{asset_name}");
    if url.path() != expected_path {
        return Err("release asset URL does not match its tag and filename".into());
    }
    Ok(url)
}

pub(super) fn trusted_redirect_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(
            url.host_str(),
            Some(
                "api.github.com"
                    | "github.com"
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

pub(crate) fn validate_downloaded_update_as(
    path: &std::path::Path,
    extension: &str,
) -> Result<(), String> {
    match extension {
        "apk" => validate_apk_file(path),
        "exe" => validate_windows_exe(path),
        "msi" => validate_windows_msi(path),
        other => Err(format!("unsupported update file type: .{other}")),
    }
}

pub fn validate_downloaded_update(path: &std::path::Path) -> Result<(), String> {
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    validate_downloaded_update_as(path, &extension)
}
pub fn verify_downloaded_update(
    path: &std::path::Path,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let expected_sha256 = expected_sha256.to_ascii_lowercase();
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("update SHA-256 is missing or invalid".into());
    }
    let metadata = std::fs::metadata(path).map_err(|error| format!("update metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(format!(
            "update size mismatch: expected {expected_size}, found {}",
            metadata.len()
        ));
    }
    validate_downloaded_update(path)?;

    let mut file = std::fs::File::open(path).map_err(|error| format!("update read: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("update read: {error}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual_sha256 = format!("{:x}", hasher.finalize());
    if actual_sha256 != expected_sha256 {
        return Err("update SHA-256 verification failed".into());
    }
    Ok(())
}

fn download_http_client(timeouts: DownloadTimeouts) -> Result<reqwest::Client, String> {
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
    reqwest::Client::builder()
        .connect_timeout(timeouts.connect)
        .read_timeout(timeouts.read)
        .timeout(timeouts.overall)
        .user_agent(concat!(
            "HacashWallet/",
            env!("CARGO_PKG_VERSION"),
            " updater"
        ))
        .redirect(redirect)
        .build()
        .map_err(|error| format!("update download HTTP client: {error}"))
}

fn format_download_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "update download timed out".into()
    } else {
        error.to_string()
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

    let client = download_http_client(DOWNLOAD_TIMEOUTS)?;

    let result: Result<(), String> = async {
        let mut response = client
            .get(parsed_url)
            .send()
            .await
            .map_err(format_download_error)?
            .error_for_status()
            .map_err(format_download_error)?;
        if !trusted_redirect_url(response.url()) {
            return Err("update download ended on an untrusted host".into());
        }
        if let Some(length) = response.content_length()
            && (length != expected_size || length > max_size)
        {
            return Err(format!(
                "update size mismatch: expected {expected_size}, server reported {length}"
            ));
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .map_err(|e| format!("create update file: {e}"))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(format_download_error)? {
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
        // The temporary file deliberately ends in `.part`. Validate its bytes
        // against the already allowlisted destination type instead of trusting
        // the temporary suffix.
        validate_downloaded_update_as(&part_path, &extension)?;
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
mod timeout_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use super::{DOWNLOAD_TIMEOUTS, DownloadTimeouts, download_http_client};

    fn spawn_stalling_server(send_headers: bool) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind timeout test server");
        let address = listener.local_addr().expect("timeout test server address");
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept timeout test request");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set request read timeout");
            let mut request = [0u8; 2048];
            let _ = socket.read(&mut request);
            if send_headers {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx",
                    )
                    .expect("write timeout response headers");
                socket.flush().expect("flush timeout response headers");
            }
            std::thread::sleep(Duration::from_millis(300));
        });
        (format!("http://{address}/update"), handle)
    }

    #[test]
    fn production_download_policy_has_all_three_deadlines() {
        assert_eq!(DOWNLOAD_TIMEOUTS.connect, Duration::from_secs(15));
        assert_eq!(DOWNLOAD_TIMEOUTS.read, Duration::from_secs(30));
        assert_eq!(DOWNLOAD_TIMEOUTS.overall, Duration::from_secs(30 * 60));
        assert!(DOWNLOAD_TIMEOUTS.connect < DOWNLOAD_TIMEOUTS.overall);
        assert!(DOWNLOAD_TIMEOUTS.read < DOWNLOAD_TIMEOUTS.overall);
    }

    #[tokio::test]
    async fn stalled_body_hits_read_timeout() {
        let (url, server) = spawn_stalling_server(true);
        let client = download_http_client(DownloadTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_millis(40),
            overall: Duration::from_secs(2),
        })
        .expect("timeout test client");
        let response = client.get(url).send().await.expect("response headers");
        let started = Instant::now();
        let error = response.bytes().await.expect_err("body must time out");
        assert!(error.is_timeout(), "unexpected body error: {error}");
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().expect("timeout test server");
    }

    #[tokio::test]
    async fn stalled_headers_hit_overall_timeout() {
        let (url, server) = spawn_stalling_server(false);
        let client = download_http_client(DownloadTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(2),
            overall: Duration::from_millis(40),
        })
        .expect("timeout test client");
        let started = Instant::now();
        let error = client
            .get(url)
            .send()
            .await
            .expect_err("request must time out");
        assert!(error.is_timeout(), "unexpected request error: {error}");
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().expect("timeout test server");
    }
}
