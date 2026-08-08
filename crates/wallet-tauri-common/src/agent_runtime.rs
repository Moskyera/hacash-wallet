//! Desktop supervisor for the local-only Agent Wallet connector.
//!
//! The supervisor never opens Agent storage. It wraps the exact manager owned
//! by [`crate::state::AgentAppState`], retains every worker after a bounded
//! shutdown timeout, and exposes a lock-independent emergency-stop path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agent_wallet_core::{
    AgentEmergencyController, AgentPolicy, AgentRecord, AgentWalletId, AgentWalletManager,
};
use agent_wallet_runtime::{
    AgentWalletRuntime, CanonicalTransportBindingFactory, LocalEndpoint, PairingActivation,
    PendingPairingView, RuntimeConfig, RuntimePhase, RuntimeStatus,
};
use rand::RngCore;
use tokio::sync::Mutex;

const PAIRING_TTL_SECS: u64 = 5 * 60;
const PAIRING_MAX_ATTEMPTS: u8 = 3;

struct RuntimeSlot {
    wallet_id: AgentWalletId,
    runtime: Arc<AgentWalletRuntime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopDisposition {
    Complete,
    ClearRecovered,
    RetainTimeout,
}

fn stop_disposition(
    result: &Result<(), agent_wallet_runtime::RuntimeError>,
    phase: RuntimePhase,
) -> StopDisposition {
    match result {
        Ok(()) => StopDisposition::Complete,
        Err(agent_wallet_runtime::RuntimeError::NotRunning) if phase == RuntimePhase::Stopped => {
            StopDisposition::Complete
        }
        Err(agent_wallet_runtime::RuntimeError::ShutdownTimeout) => StopDisposition::RetainTimeout,
        Err(_) => StopDisposition::ClearRecovered,
    }
}

/// Owns the desktop connector lifecycle. `slot` is deliberately synchronous:
/// emergency-stop can request worker shutdown without waiting for async wallet
/// operations. Potentially blocking start/stop work runs off the UI thread.
pub struct AgentRuntimeSupervisor {
    root: PathBuf,
    lifecycle: Mutex<()>,
    slot: StdMutex<Option<RuntimeSlot>>,
    emergency: StdMutex<BTreeMap<String, AgentEmergencyController>>,
}

impl AgentRuntimeSupervisor {
    pub fn new(root: impl AsRef<Path>, manager: &AgentWalletManager) -> Self {
        let supervisor = Self::unavailable(root.as_ref().to_path_buf());
        if let Ok(wallets) = manager.list_wallets() {
            let mut cache = supervisor
                .emergency
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for wallet in wallets {
                if let Ok(controller) = manager.emergency_controller(&wallet.wallet_id) {
                    cache.insert(wallet.wallet_id.as_str().to_owned(), controller);
                }
            }
        }
        supervisor
    }

    pub fn unavailable(root: PathBuf) -> Self {
        Self {
            root,
            lifecycle: Mutex::new(()),
            slot: StdMutex::new(None),
            emergency: StdMutex::new(BTreeMap::new()),
        }
    }

    pub fn cache_emergency_controller(
        &self,
        wallet_id: &AgentWalletId,
        controller: AgentEmergencyController,
    ) {
        self.emergency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(wallet_id.as_str().to_owned(), controller);
    }

    pub fn emergency_controller(
        &self,
        wallet_id: &AgentWalletId,
    ) -> Option<AgentEmergencyController> {
        self.emergency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(wallet_id.as_str())
            .cloned()
    }

    pub fn status(&self) -> Option<(AgentWalletId, RuntimeStatus)> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|slot| (slot.wallet_id.clone(), slot.runtime.status()))
    }

    pub async fn start(
        &self,
        wallet_id: AgentWalletId,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<RuntimeStatus, String> {
        let _lifecycle = self.lifecycle.lock().await;
        if let Some((active_wallet, status)) = self.status() {
            if active_wallet != wallet_id {
                return Err(
                    "stop the active Agent connector before selecting another wallet".into(),
                );
            }
            if status.phase != RuntimePhase::Stopped {
                return Err(format!(
                    "Agent connector must be stopped before start; current phase is {}",
                    phase_name(status.phase)
                ));
            }
        }

        let (desktop_instance_id, server_identity_key, emergency_controller) = {
            let mut guard = manager.lock().await;
            let (desktop_instance_id, server_identity_key) = guard
                .connector_server_identity(&wallet_id, unix_now()?)
                .map_err(|error| error.to_string())?;
            let emergency_controller = guard
                .emergency_controller(&wallet_id)
                .map_err(|error| error.to_string())?;
            (
                desktop_instance_id,
                server_identity_key,
                emergency_controller,
            )
        };
        self.cache_emergency_controller(&wallet_id, emergency_controller);

        let runtime = if let Some(runtime) = self.runtime_for(&wallet_id) {
            runtime
        } else {
            let config = production_config(&self.root, &wallet_id, desktop_instance_id)?;
            let runtime = Arc::new(
                AgentWalletRuntime::new_shared(
                    manager,
                    wallet_id.clone(),
                    config,
                    server_identity_key,
                    Arc::new(CanonicalTransportBindingFactory),
                )
                .await
                .map_err(|error| error.to_string())?,
            );
            *self
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(RuntimeSlot {
                wallet_id,
                runtime: Arc::clone(&runtime),
            });
            runtime
        };

        let start_runtime = Arc::clone(&runtime);
        tauri::async_runtime::spawn_blocking(move || start_runtime.start())
            .await
            .map_err(|_| "Agent connector start task failed".to_owned())?
            .map_err(|error| error.to_string())?;
        Ok(runtime.status())
    }

    pub async fn stop(&self, wallet_id: &AgentWalletId) -> Result<RuntimeStatus, String> {
        let _lifecycle = self.lifecycle.lock().await;
        let Some(runtime) = self.runtime_for(wallet_id) else {
            return Ok(RuntimeStatus::default());
        };
        let initial = runtime.status();
        if initial.phase == RuntimePhase::Stopped {
            return Ok(initial);
        }
        runtime
            .request_shutdown()
            .map_err(|error| error.to_string())?;
        let stop_runtime = Arc::clone(&runtime);
        let result = tauri::async_runtime::spawn_blocking(move || stop_runtime.stop())
            .await
            .map_err(|_| "Agent connector stop task failed".to_owned())?;
        let phase = runtime.status().phase;
        match stop_disposition(&result, phase) {
            StopDisposition::Complete => Ok(runtime.status()),
            StopDisposition::ClearRecovered => {
                let error = result
                    .expect_err("clear-recovered disposition always carries an error")
                    .to_string();
                self.clear_runtime(wallet_id, &runtime);
                Ok(RuntimeStatus {
                    phase: RuntimePhase::Stopped,
                    endpoint: None,
                    last_error: Some(error),
                })
            }
            StopDisposition::RetainTimeout => {
                // Keep the runtime and JoinHandle owned. A later explicit stop
                // or process-exit pass can reap it.
                Err(agent_wallet_runtime::RuntimeError::ShutdownTimeout.to_string())
            }
        }
    }

    pub fn request_shutdown(&self, wallet_id: &AgentWalletId) -> Result<(), String> {
        if let Some(runtime) = self.runtime_for(wallet_id) {
            runtime
                .request_shutdown()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub async fn activate_pairing(
        &self,
        wallet_id: AgentWalletId,
    ) -> Result<PairingActivation, String> {
        self.runtime_for(&wallet_id)
            .ok_or_else(|| "Agent connector is not running for this wallet".to_owned())?
            .activate_pairing(wallet_id, PAIRING_TTL_SECS, PAIRING_MAX_ATTEMPTS)
            .await
            .map_err(|error| error.to_string())
    }

    pub fn pending_pairing(
        &self,
        wallet_id: &AgentWalletId,
    ) -> Result<Option<PendingPairingView>, String> {
        self.runtime_for(wallet_id)
            .ok_or_else(|| "Agent connector is not running for this wallet".to_owned())?
            .pending_pairing()
            .map_err(|error| error.to_string())
    }

    pub async fn approve_pairing(
        &self,
        wallet_id: &AgentWalletId,
        pairing_id: &str,
        expected_submission_commitment: &hpay_agent_connector::PairingSubmissionCommitment,
        policy: AgentPolicy,
    ) -> Result<AgentRecord, String> {
        self.runtime_for(wallet_id)
            .ok_or_else(|| "Agent connector is not running for this wallet".to_owned())?
            .approve_pairing(pairing_id, expected_submission_commitment, policy)
            .await
            .map_err(|error| error.to_string())
    }

    pub fn reject_pairing(
        &self,
        wallet_id: &AgentWalletId,
        pairing_id: &str,
        expected_submission_commitment: &hpay_agent_connector::PairingSubmissionCommitment,
    ) -> Result<(), String> {
        self.runtime_for(wallet_id)
            .ok_or_else(|| "Agent connector is not running for this wallet".to_owned())?
            .reject_pairing(pairing_id, expected_submission_commitment)
            .map_err(|error| error.to_string())
    }

    /// Process-exit path. Every stop is bounded by the runtime configuration.
    /// A timeout deliberately retains ownership; runtime Drop will retry and
    /// abort rather than detach a live signing worker.
    pub fn shutdown_for_exit(&self) -> Result<(), String> {
        let runtime = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|slot| Arc::clone(&slot.runtime));
        let Some(runtime) = runtime else {
            return Ok(());
        };
        runtime
            .request_shutdown()
            .map_err(|error| error.to_string())?;
        match runtime.stop() {
            Ok(()) => Ok(()),
            Err(agent_wallet_runtime::RuntimeError::NotRunning)
                if runtime.status().phase == RuntimePhase::Stopped =>
            {
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn clear_runtime(&self, wallet_id: &AgentWalletId, runtime: &Arc<AgentWalletRuntime>) {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = slot.as_ref().is_some_and(|current| {
            &current.wallet_id == wallet_id && Arc::ptr_eq(&current.runtime, runtime)
        });
        if matches {
            *slot = None;
        }
    }

    fn runtime_for(&self, wallet_id: &AgentWalletId) -> Option<Arc<AgentWalletRuntime>> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|slot| &slot.wallet_id == wallet_id)
            .map(|slot| Arc::clone(&slot.runtime))
    }
}

fn production_config(
    _root: &Path,
    _wallet_id: &AgentWalletId,
    desktop_instance_id: String,
) -> Result<RuntimeConfig, String> {
    let mut random = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut random);
    let suffix = hex::encode(random);
    let endpoint = {
        #[cfg(windows)]
        {
            LocalEndpoint::WindowsNamedPipe {
                instance_suffix: suffix,
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let runtime_dir = _root.join("runtime");
            std::fs::create_dir_all(&runtime_dir)
                .map_err(|_| "could not create the private Agent runtime directory".to_owned())?;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "could not secure the private Agent runtime directory".to_owned())?;
            LocalEndpoint::UnixDomainSocket {
                socket_path: runtime_dir.join(format!("{}-{suffix}.sock", _wallet_id.as_str())),
            }
        }
    };
    let config = RuntimeConfig {
        desktop_instance_id,
        endpoint,
        max_frame_bytes: hpay_agent_connector::MAX_FRAME_BYTES,
        accept_timeout: Duration::from_millis(100),
        read_timeout: Duration::from_secs(1),
        write_timeout: Duration::from_secs(1),
        dispatch_timeout: Duration::from_secs(5),
        startup_timeout: Duration::from_secs(3),
        shutdown_timeout: Duration::from_secs(6),
    };
    config.validate().map_err(|error| error.to_string())?;
    Ok(config)
}

pub fn phase_name(phase: RuntimePhase) -> &'static str {
    match phase {
        RuntimePhase::Stopped => "stopped",
        RuntimePhase::Starting => "starting",
        RuntimePhase::Running => "running",
        RuntimePhase::Stopping => "stopping",
        RuntimePhase::Failed => "failed",
    }
}

fn unix_now() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_status_phase_names_are_stable_wire_values() {
        assert_eq!(phase_name(RuntimePhase::Stopped), "stopped");
        assert_eq!(phase_name(RuntimePhase::Failed), "failed");
    }

    #[test]
    fn production_runtime_timeouts_are_bounded() {
        assert!(Duration::from_secs(6) <= Duration::from_secs(30));
        assert!(Duration::from_secs(3) <= Duration::from_secs(30));
    }

    #[test]
    fn failed_start_without_a_worker_is_cleared_for_recovery() {
        assert_eq!(
            stop_disposition(
                &Err(agent_wallet_runtime::RuntimeError::NotRunning),
                RuntimePhase::Failed,
            ),
            StopDisposition::ClearRecovered
        );
    }

    #[test]
    fn shutdown_timeout_never_discards_runtime_ownership() {
        assert_eq!(
            stop_disposition(
                &Err(agent_wallet_runtime::RuntimeError::ShutdownTimeout),
                RuntimePhase::Failed,
            ),
            StopDisposition::RetainTimeout
        );
    }

    #[test]
    fn an_already_stopped_runtime_is_an_idempotent_success() {
        assert_eq!(
            stop_disposition(
                &Err(agent_wallet_runtime::RuntimeError::NotRunning),
                RuntimePhase::Stopped,
            ),
            StopDisposition::Complete
        );
    }
}
