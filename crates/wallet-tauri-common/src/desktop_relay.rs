//! Desktop-only managed DUST Whisper relay process.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use hacash_wallet_core::dust_whisper::{
    DustWhisperSettings, is_local_relay_url, listen_addr_from_relay_url,
};
use hacash_wallet_core::paths::wallet_data_root;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

pub struct RelayProcess {
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    managed: Mutex<bool>,
}

impl RelayProcess {
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
            managed: Mutex::new(false),
        }
    }
}

impl Default for RelayProcess {
    fn default() -> Self {
        Self::new()
    }
}

pub fn stop_managed_relay(state: &AppState) -> Result<(), String> {
    let managed = *state.relay.managed.lock().map_err(|e| e.to_string())?;
    if !managed {
        return Ok(());
    }
    if let Some(task) = state.relay.task.lock().map_err(|e| e.to_string())?.take() {
        task.abort();
    }
    *state.relay.managed.lock().map_err(|e| e.to_string())? = false;
    Ok(())
}

pub async fn sync_managed_relay(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();

    let (settings, node_url) = {
        let mut svc = state.inner.lock().await;
        (svc.dust_whisper_settings(), svc.status().node_url)
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

    stop_managed_relay(&state)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let key_file = wallet_data_root().join("relay.key");
    let secret = dust_whisper::relay::load_or_create_secret_key(&key_file)?;
    let socket: SocketAddr = listen
        .parse()
        .map_err(|error| format!("Invalid relay listen address {listen}: {error}"))?;
    let listener = tokio::net::TcpListener::bind(socket)
        .await
        .map_err(|error| {
            format!(
                "Cannot start the local DUST relay at {listen}. The port is already in use: {error}"
            )
        })?;
    let relay_state = dust_whisper::relay::relay_state_from_secret(secret, node_url.clone());
    tracing::info!(%listen, %node_url, "starting embedded DUST Whisper relay");
    let task = tauri::async_runtime::spawn(async move {
        if let Err(error) = dust_whisper::relay::serve_listener(listener, relay_state).await {
            tracing::error!(%error, "embedded DUST Whisper relay stopped");
        }
    });

    *state.relay.task.lock().map_err(|e| e.to_string())? = Some(task);
    *state.relay.managed.lock().map_err(|e| e.to_string())? = true;

    tokio::time::sleep(Duration::from_millis(600)).await;
    Ok(())
}

fn should_manage_relay(settings: &DustWhisperSettings) -> bool {
    cfg!(not(any(target_os = "android", target_os = "ios")))
        && settings.enabled
        && settings.auto_start_relay
        && settings.relay_urls.iter().any(|u| is_local_relay_url(u))
}
