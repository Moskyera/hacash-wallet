use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use hacash_wallet_core::dust_whisper::{
    is_local_relay_url, listen_addr_from_relay_url, DustWhisperSettings,
};
use hacash_wallet_core::paths::wallet_data_root;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

pub struct RelayProcess {
    child: Mutex<Option<Child>>,
    managed: Mutex<bool>,
}

impl RelayProcess {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            managed: Mutex::new(false),
        }
    }
}

pub fn stop_managed_relay(state: &AppState) -> Result<(), String> {
    let managed = *state.relay.managed.lock().map_err(|e| e.to_string())?;
    if !managed {
        return Ok(());
    }
    if let Some(mut child) = state.relay.child.lock().map_err(|e| e.to_string())?.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    *state.relay.managed.lock().map_err(|e| e.to_string())? = false;
    Ok(())
}

pub async fn sync_managed_relay(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();

    let (settings, node_url) = {
        let svc = state.inner.lock().await;
        (
            svc.dust_whisper_settings(),
            svc.status().node_url,
        )
    };

    if !should_manage_relay(&settings) {
        stop_managed_relay(&state)?;
        return Ok(());
    }

    let local_url = settings
        .relay_urls
        .iter()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .find(|u| !u.is_empty() && is_local_relay_url(u))
        .ok_or_else(|| "No local relay URL configured for auto-start".to_string())?;

    let listen = listen_addr_from_relay_url(&local_url)
        .ok_or_else(|| format!("Invalid relay listen address in {local_url}"))?;

    // Always restart so wallet picks up rebuilt relay binaries (dev builds go stale easily).
    stop_managed_relay(&state)?;
    kill_listener_on_port(&listen)?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let binary = find_relay_binary()?;
    let key_file = wallet_data_root().join("relay.key");

    tracing::info!(relay = %binary.display(), listen = %listen, "starting managed DUST Whisper relay");

    let child = Command::new(&binary)
        .arg("--listen")
        .arg(&listen)
        .arg("--node-url")
        .arg(&node_url)
        .arg("--key-file")
        .arg(&key_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start dust-whisper-relay ({binary:?}): {e}"))?;

    *state.relay.child.lock().map_err(|e| e.to_string())? = Some(child);
    *state.relay.managed.lock().map_err(|e| e.to_string())? = true;

    tokio::time::sleep(Duration::from_millis(600)).await;
    Ok(())
}

fn should_manage_relay(settings: &DustWhisperSettings) -> bool {
    settings.enabled
        && settings.auto_start_relay
        && settings
            .relay_urls
            .iter()
            .any(|u| is_local_relay_url(u))
}

fn kill_listener_on_port(listen: &str) -> Result<(), String> {
    let port = listen
        .rsplit(':')
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("invalid listen address: {listen}"))?;

    #[cfg(windows)]
    {
        let output = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .map_err(|e| format!("netstat failed: {e}"))?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if !line.contains("LISTENING") {
                continue;
            }
            if !line.contains(&format!(":{port}")) {
                continue;
            }
            if let Some(pid) = line.split_whitespace().last() {
                if pid.chars().all(|c| c.is_ascii_digit()) && pid != "0" {
                    let _ = Command::new("taskkill")
                        .args(["/F", "/PID", pid])
                        .output();
                }
            }
        }
    }

    #[cfg(unix)]
    {
        let _ = Command::new("fuser")
            .args(["-k", &format!("{port}/tcp")])
            .output();
    }

    Ok(())
}

fn find_relay_binary() -> Result<PathBuf, String> {
    let name = if cfg!(windows) {
        "dust-whisper-relay.exe"
    } else {
        "dust-whisper-relay"
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["release", "debug"] {
        let candidate = manifest_dir
            .join("../../../target")
            .join(profile)
            .join(name);
        if candidate.is_file() {
            return Ok(candidate.canonicalize().unwrap_or(candidate));
        }
    }

    Err(format!(
        "Could not find {name}. Build it with: cargo build -p dust-whisper --bin dust-whisper-relay --features relay --release"
    ))
}