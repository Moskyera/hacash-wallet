//! Desktop-only IPC (relay auto-start, platform security).

use hacash_wallet_core::DustWhisperSettings;
use tauri::{AppHandle, Runtime, State};

use crate::state::AppState;

/// Save the relay settings and bring the managed relay into line with them.
///
/// Generic over the Tauri runtime on purpose. Written as a bare `AppHandle` it
/// is `AppHandle<Wry>`, and Wry needs a real window server, so the press that
/// starts somebody's relay could not be entered by any test: the only way in
/// was the helper underneath it. `crates/wallet-tauri-common/tests/
/// messenger_two_wallets_one_relay.rs` starts the relay two wallets then talk
/// through by calling this, which is the same code the desktop Settings screen
/// runs.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_update_dust_whisper_settings_desktop<R: Runtime>(
    dust_whisper: DustWhisperSettings,
    state: State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), String> {
    {
        let mut svc = state.inner.lock().await;
        svc.update_dust_whisper_settings(dust_whisper)
            .map_err(|e| e.to_string())?;
    }
    crate::desktop_relay::sync_managed_relay(&app).await?;
    Ok(())
}

/// The address this wallet's own relay is serving on, and whether anybody else
/// can reach it.
///
/// Read-only. It starts nothing, stops nothing and changes no setting: the
/// bind is only ever moved by a saved settings change, which is
/// `wallet_update_dust_whisper_settings_desktop` above.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_relay_endpoint<R: Runtime>(
    app: AppHandle<R>,
) -> Result<crate::desktop_relay::RelayEndpointReport, String> {
    crate::desktop_relay::relay_endpoint(&app).await
}

/// What the supervised Hacash node is doing, and whose it is.
///
/// Read-only, and polled rather than returned once: a cold sync took about
/// seven minutes on the machine this was built against, so the interesting
/// state lasts minutes and a converge function's return value cannot carry it.
/// This starts nothing, stops nothing and writes no config.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_node_supervisor_status(
    state: State<'_, AppState>,
) -> Result<crate::desktop_node::NodeSupervisorReport, String> {
    crate::desktop_node::node_supervisor_status(&state.node).await
}

/// Bring the world into line with "this wallet should be running a node".
///
/// A converge function, not a command, in the shape of `sync_managed_relay`:
/// a live child of ours means there is nothing to do, so a second press changes
/// nothing. Every refusal is recorded rather than returned as an error, so the
/// next status poll still says why instead of falling back to silence.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_node_supervisor_start(
    state: State<'_, AppState>,
) -> Result<crate::desktop_node::NodeSupervisorReport, String> {
    crate::desktop_node::sync_managed_node(&state.node).await?;
    crate::desktop_node::node_supervisor_status(&state.node).await
}

/// Stop the node this wallet started, and nothing else.
///
/// A node the wallet did not start has no stop button on the screen and no
/// path to one here: `stop_managed_node` can only reach a `Child` this process
/// is holding.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_node_supervisor_stop(
    state: State<'_, AppState>,
) -> Result<crate::desktop_node::NodeSupervisorReport, String> {
    // The stop blocks for up to the graceful budget while the child flushes a
    // multi-gigabyte store, so it must not run on a thread the window is also
    // waiting on. The supervisor is behind an `Arc` precisely so this hand-off
    // needs no unsafety.
    let node = state.node.clone();
    tauri::async_runtime::spawn_blocking(move || {
        crate::desktop_node::stop_managed_node(&node, crate::desktop_node::GRACEFUL_STOP_BUDGET)
    })
    .await
    .map_err(|error| format!("stop task failed: {error}"))??;
    crate::desktop_node::node_supervisor_status(&state.node).await
}

/// Point the wallet at a fullnode that is already on this computer.
///
/// The path is confirmed by running the binary against a config path that does
/// not exist, which errors before anything binds a port, resolves a folder or
/// opens a database. A filename is never taken as evidence of anything.
#[cfg(feature = "desktop")]
#[tauri::command]
pub async fn wallet_node_supervisor_set_binary(
    path: Option<String>,
    state: State<'_, AppState>,
) -> Result<crate::desktop_node::NodeSupervisorReport, String> {
    // PERSISTED, not just held. The pick used to live in a `Mutex` that died
    // with the process, so the next launch had none and the search list fell
    // through to a hardcoded `C:/hpay/fullnode.exe` that any account on the
    // machine could overwrite and the supervisor would run. Writing it down is
    // what allowed that path to be removed, so the write is not a convenience.
    let chosen = match path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        None => {
            state.node.set_picked_binary(None);
            None
        }
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            crate::desktop_node::probe_node_binary(&path)
                .map_err(|reason| format!("{}: {reason}", path.display()))?;
            state.node.set_picked_binary(Some(path.clone()));
            Some(path.to_string_lossy().into_owned())
        }
    };
    // After the probe, so a path that does not run is never written down.
    state
        .inner
        .lock()
        .await
        .set_node_binary_path(chosen)
        .map_err(|error| error.to_string())?;
    crate::desktop_node::node_supervisor_status(&state.node).await
}
