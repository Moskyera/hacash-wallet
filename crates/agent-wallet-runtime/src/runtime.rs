use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use agent_wallet_core::{AgentPolicy, AgentRecord, AgentWalletId, AgentWalletManager};
use hpay_agent_connector::{
    PAIRING_COMPLETION_TTL_SECS, PairingSubmissionCommitment, PinnedServerIdentity,
    ServerIdentityKey,
};
use tokio::sync::Mutex;

use crate::config::{RuntimeConfig, TransportBindingFactory};
use crate::error::{RuntimeError, RuntimeResult};
use crate::pairing::{
    PairingActivation, PairingRuntimeState, PendingPairingView, SharedPairingState,
    commit_approved_pairing, unix_now,
};
use crate::worker::{self, WorkerInputs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePhase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub phase: RuntimePhase,
    pub endpoint: Option<String>,
    pub last_error: Option<String>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            phase: RuntimePhase::Stopped,
            endpoint: None,
            last_error: None,
        }
    }
}

struct WorkerHandle {
    shutdown: Arc<AtomicBool>,
    completion: mpsc::Receiver<RuntimeResult<()>>,
    completion_result: Option<RuntimeResult<()>>,
    join: Option<JoinHandle<()>>,
}

impl WorkerHandle {
    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Reaps only after the worker has both reported completion and the OS
    /// thread is observably finished. A timeout retains the JoinHandle, so no
    /// worker is detached and a later stop call can retry the bounded reap.
    fn reap_within(&mut self, timeout: Duration) -> RuntimeResult<Option<RuntimeResult<()>>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(RuntimeError::InvalidConfiguration)?;
        if self.completion_result.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.completion.recv_timeout(remaining) {
                Ok(result) => self.completion_result = Some(result),
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.completion_result = Some(Err(RuntimeError::WorkerPanicked));
                }
            }
        }

        let join = self.join.as_ref().ok_or(RuntimeError::WorkerPanicked)?;
        while !join.is_finished() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        let join = self.join.take().ok_or(RuntimeError::WorkerPanicked)?;
        join.join().map_err(|_| RuntimeError::WorkerPanicked)?;
        Ok(self.completion_result.take())
    }
}

fn record_worker_result(
    current: &mut RuntimeStatus,
    shutdown_requested: bool,
    result: &RuntimeResult<()>,
) {
    if shutdown_requested && result.is_ok() {
        current.endpoint = None;
        if current.phase != RuntimePhase::Failed {
            // Only stop()/bounded reap may publish Stopped. This prevents a
            // late worker completion from erasing a prior ShutdownTimeout.
            current.phase = RuntimePhase::Stopping;
            current.last_error = None;
        }
    } else if let Err(error) = result {
        current.phase = RuntimePhase::Failed;
        current.endpoint = None;
        current.last_error = Some(error.to_string());
    }
}

pub struct AgentWalletRuntime {
    wallet_id: AgentWalletId,
    manager: Arc<Mutex<AgentWalletManager>>,
    config: RuntimeConfig,
    server_identity_key: Arc<ServerIdentityKey>,
    binding_factory: Arc<dyn TransportBindingFactory>,
    pairing_state: SharedPairingState,
    status: Arc<StdMutex<RuntimeStatus>>,
    worker: StdMutex<Option<WorkerHandle>>,
}

impl AgentWalletRuntime {
    pub fn new(
        mut manager: AgentWalletManager,
        wallet_id: AgentWalletId,
        config: RuntimeConfig,
        server_identity_key: ServerIdentityKey,
        binding_factory: Arc<dyn TransportBindingFactory>,
    ) -> RuntimeResult<Self> {
        config.validate()?;
        Self::verify_manager_identity(&mut manager, &wallet_id, &config, &server_identity_key)?;
        Ok(Self::from_verified_manager(
            Arc::new(Mutex::new(manager)),
            wallet_id,
            config,
            server_identity_key,
            binding_factory,
        ))
    }

    /// Builds the runtime around the exact manager already owned by the
    /// trusted desktop UI. This prevents a second Agent Wallet storage lock,
    /// duplicate unlocked session, or divergent policy state.
    pub async fn new_shared(
        manager: Arc<Mutex<AgentWalletManager>>,
        wallet_id: AgentWalletId,
        config: RuntimeConfig,
        server_identity_key: ServerIdentityKey,
        binding_factory: Arc<dyn TransportBindingFactory>,
    ) -> RuntimeResult<Self> {
        config.validate()?;
        {
            let mut guard = manager.lock().await;
            Self::verify_manager_identity(&mut guard, &wallet_id, &config, &server_identity_key)?;
        }
        Ok(Self::from_verified_manager(
            manager,
            wallet_id,
            config,
            server_identity_key,
            binding_factory,
        ))
    }

    fn verify_manager_identity(
        manager: &mut AgentWalletManager,
        wallet_id: &AgentWalletId,
        config: &RuntimeConfig,
        server_identity_key: &ServerIdentityKey,
    ) -> RuntimeResult<()> {
        let now_unix = unix_now()?;
        let (vault_desktop_instance_id, vault_identity_key) = manager
            .connector_server_identity(wallet_id, now_unix)
            .map_err(|_| RuntimeError::AgentWalletUnavailable)?;
        let vault_identity = vault_identity_key
            .pinned_identity(vault_desktop_instance_id.clone())
            .map_err(RuntimeError::from)?;
        let injected_identity = server_identity_key
            .pinned_identity(config.desktop_instance_id.clone())
            .map_err(RuntimeError::from)?;
        if vault_desktop_instance_id != config.desktop_instance_id
            || vault_identity != injected_identity
        {
            return Err(RuntimeError::ServerIdentityMismatch);
        }
        Ok(())
    }

    fn from_verified_manager(
        manager: Arc<Mutex<AgentWalletManager>>,
        wallet_id: AgentWalletId,
        config: RuntimeConfig,
        server_identity_key: ServerIdentityKey,
        binding_factory: Arc<dyn TransportBindingFactory>,
    ) -> Self {
        Self {
            wallet_id,
            manager,
            config,
            server_identity_key: Arc::new(server_identity_key),
            binding_factory,
            pairing_state: Arc::new(StdMutex::new(PairingRuntimeState::default())),
            status: Arc::new(StdMutex::new(RuntimeStatus::default())),
            worker: StdMutex::new(None),
        }
    }

    pub fn manager(&self) -> Arc<Mutex<AgentWalletManager>> {
        Arc::clone(&self.manager)
    }

    pub fn pinned_server_identity(&self) -> RuntimeResult<PinnedServerIdentity> {
        self.server_identity_key
            .pinned_identity(self.config.desktop_instance_id.clone())
            .map_err(RuntimeError::from)
    }

    pub fn status(&self) -> RuntimeStatus {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Requests shutdown without waiting for the worker or the Agent Wallet
    /// manager. Emergency-stop and auto-lock paths can therefore fail closed
    /// immediately even while a network operation is still unwinding.
    pub fn request_shutdown(&self) -> RuntimeResult<()> {
        let requested = {
            let worker_slot = self
                .worker
                .lock()
                .map_err(|_| RuntimeError::WorkerPanicked)?;
            if let Some(worker) = worker_slot.as_ref() {
                worker.request_shutdown();
                true
            } else {
                false
            }
        };
        self.pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .disable_and_clear();
        if requested {
            self.set_status(RuntimePhase::Stopping, self.status().endpoint, None);
        }
        Ok(())
    }

    pub async fn activate_pairing(
        &self,
        wallet_id: AgentWalletId,
        ttl_secs: u64,
        max_attempts: u8,
    ) -> RuntimeResult<PairingActivation> {
        if self.status().phase != RuntimePhase::Running {
            return Err(RuntimeError::NotRunning);
        }
        if wallet_id != self.wallet_id {
            return Err(RuntimeError::AgentWalletUnavailable);
        }
        let now_unix = unix_now()?;
        self.manager
            .lock()
            .await
            .unlocked_status(&wallet_id, now_unix)
            .map_err(|_| RuntimeError::AgentWalletUnavailable)?;
        let server_identity = self.pinned_server_identity()?;
        self.pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .activate(wallet_id, server_identity, now_unix, ttl_secs, max_attempts)
    }

    pub fn pending_pairing(&self) -> RuntimeResult<Option<PendingPairingView>> {
        let now_unix = unix_now()?;
        Ok(self
            .pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .pending(now_unix))
    }

    pub async fn approve_pairing(
        &self,
        pairing_id: &str,
        expected_submission_commitment: &PairingSubmissionCommitment,
        policy: AgentPolicy,
    ) -> RuntimeResult<AgentRecord> {
        if self.status().phase != RuntimePhase::Running {
            return Err(RuntimeError::NotRunning);
        }
        let now_unix = unix_now()?;
        let mut session = self
            .pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .take(pairing_id, expected_submission_commitment, now_unix)?;
        let paired = session.approve(
            now_unix,
            expected_submission_commitment,
            policy.permissions.clone(),
        )?;
        let completion_expires_at = now_unix
            .checked_add(PAIRING_COMPLETION_TTL_SECS)
            .ok_or(RuntimeError::InvalidConfiguration)?;
        commit_approved_pairing(
            self.manager.as_ref(),
            paired,
            policy,
            pairing_id,
            expected_submission_commitment.clone(),
            completion_expires_at,
            now_unix,
        )
        .await
    }

    pub fn reject_pairing(
        &self,
        pairing_id: &str,
        expected_submission_commitment: &PairingSubmissionCommitment,
    ) -> RuntimeResult<()> {
        if self.status().phase != RuntimePhase::Running {
            return Err(RuntimeError::NotRunning);
        }
        let now_unix = unix_now()?;
        let mut session = self
            .pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .take(pairing_id, expected_submission_commitment, now_unix)?;
        session
            .reject(now_unix, expected_submission_commitment)
            .map_err(Into::into)
    }

    pub fn start(&self) -> RuntimeResult<()> {
        if !cfg!(feature = "listener") {
            return Err(RuntimeError::ListenerDisabled);
        }
        let mut worker_slot = self
            .worker
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?;
        if worker_slot.is_some() {
            return Err(RuntimeError::AlreadyRunning);
        }
        self.pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .enable();
        self.set_status(RuntimePhase::Starting, None, None);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let inputs = WorkerInputs {
            wallet_id: self.wallet_id.clone(),
            manager: Arc::clone(&self.manager),
            config: self.config.clone(),
            server_identity_key: Arc::clone(&self.server_identity_key),
            binding_factory: Arc::clone(&self.binding_factory),
            pairing_state: Arc::clone(&self.pairing_state),
            shutdown: Arc::clone(&shutdown),
            startup: startup_tx,
        };
        let status = Arc::clone(&self.status);
        let observed_shutdown = Arc::clone(&shutdown);
        let worker_pairing_state = Arc::clone(&self.pairing_state);
        let join = thread::Builder::new()
            .name("hpay-agent-wallet-runtime".to_owned())
            .spawn(move || {
                let result = worker::run(inputs);
                if let Ok(mut pairing_state) = worker_pairing_state.lock() {
                    pairing_state.disable_and_clear();
                }
                let mut current = status
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                record_worker_result(
                    &mut current,
                    observed_shutdown.load(Ordering::Acquire),
                    &result,
                );
                drop(current);
                // This is deliberately the final observable action. A stop
                // caller still confirms JoinHandle::is_finished before join.
                let _ = completion_tx.send(result);
            })
            .map_err(|_| RuntimeError::WorkerPanicked)?;

        let mut worker = WorkerHandle {
            shutdown,
            completion: completion_rx,
            completion_result: None,
            join: Some(join),
        };
        match startup_rx.recv_timeout(self.config.startup_timeout) {
            Ok(Ok(endpoint)) => {
                *worker_slot = Some(worker);
                self.set_status(RuntimePhase::Running, Some(endpoint), None);
                Ok(())
            }
            Ok(Err(error)) => {
                worker.request_shutdown();
                if !matches!(
                    worker.reap_within(self.config.shutdown_timeout),
                    Ok(Some(_))
                ) {
                    *worker_slot = Some(worker);
                }
                self.set_status(RuntimePhase::Failed, None, Some(error.to_string()));
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                worker.request_shutdown();
                let worker_error = match worker.reap_within(self.config.shutdown_timeout) {
                    Ok(Some(result)) => result.err().unwrap_or(RuntimeError::WorkerPanicked),
                    Ok(None) => {
                        *worker_slot = Some(worker);
                        RuntimeError::WorkerPanicked
                    }
                    Err(error) => error,
                };
                self.set_status(RuntimePhase::Failed, None, Some(worker_error.to_string()));
                Err(worker_error)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                worker.request_shutdown();
                if !matches!(
                    worker.reap_within(self.config.shutdown_timeout),
                    Ok(Some(_))
                ) {
                    *worker_slot = Some(worker);
                }
                self.set_status(
                    RuntimePhase::Failed,
                    None,
                    Some(RuntimeError::StartupTimeout.to_string()),
                );
                Err(RuntimeError::StartupTimeout)
            }
        }
    }

    pub fn stop(&self) -> RuntimeResult<()> {
        let mut worker_slot = self
            .worker
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?;
        let worker = worker_slot.as_mut().ok_or(RuntimeError::NotRunning)?;
        self.set_status(RuntimePhase::Stopping, self.status().endpoint, None);
        self.pairing_state
            .lock()
            .map_err(|_| RuntimeError::WorkerPanicked)?
            .disable_and_clear();

        worker.request_shutdown();
        match worker.reap_within(self.config.shutdown_timeout) {
            Ok(Some(result)) => {
                worker_slot.take();
                match result {
                    Ok(()) => {
                        self.set_status(RuntimePhase::Stopped, None, None);
                        Ok(())
                    }
                    Err(error) => {
                        self.set_status(RuntimePhase::Failed, None, Some(error.to_string()));
                        Err(error)
                    }
                }
            }
            Ok(None) => {
                // Keep the worker and JoinHandle owned by this runtime.
                // Pairing is disabled and start() refuses while it remains.
                self.set_status(
                    RuntimePhase::Failed,
                    None,
                    Some(RuntimeError::ShutdownTimeout.to_string()),
                );
                Err(RuntimeError::ShutdownTimeout)
            }
            Err(error) => {
                worker_slot.take();
                self.set_status(RuntimePhase::Failed, None, Some(error.to_string()));
                Err(error)
            }
        }
    }

    fn set_status(
        &self,
        phase: RuntimePhase,
        endpoint: Option<String>,
        last_error: Option<String>,
    ) {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *status = RuntimeStatus {
            phase,
            endpoint,
            last_error,
        };
    }
}

impl Drop for AgentWalletRuntime {
    fn drop(&mut self) {
        let running = self
            .worker
            .get_mut()
            .map(|slot| slot.is_some())
            .unwrap_or(false);
        if !running {
            return;
        }

        let first = self.stop();
        let unresolved = self
            .worker
            .get_mut()
            .map(|slot| slot.is_some())
            .unwrap_or(true);
        if unresolved {
            // One bounded retry covers a worker that completed exactly on the
            // first deadline. Never silently drop a live JoinHandle carrying
            // access to Agent Wallet state.
            let second = self.stop();
            let still_unresolved = self
                .worker
                .get_mut()
                .map(|slot| slot.is_some())
                .unwrap_or(true);
            if still_unresolved {
                eprintln!(
                    "fatal: Agent Wallet runtime worker could not be stopped: first={first:?}, second={second:?}"
                );
                std::process::abort();
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn delayed_worker(delay: Duration) -> WorkerHandle {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            thread::sleep(delay);
            let _ = completion_tx.send(Ok(()));
        });
        WorkerHandle {
            shutdown,
            completion: completion_rx,
            completion_result: None,
            join: Some(join),
        }
    }

    /// A worker that cannot finish until it is released.
    ///
    /// This is what lets the bounded reap below be checked without a stopwatch:
    /// while the gate is shut there is no completion to observe, so a reap that
    /// returns at all is one that stopped at its own deadline.
    fn gated_worker() -> (WorkerHandle, Arc<AtomicBool>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let join = thread::spawn(move || {
            while !worker_release.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            let _ = completion_tx.send(Ok(()));
        });
        (
            WorkerHandle {
                shutdown,
                completion: completion_rx,
                completion_result: None,
                join: Some(join),
            },
            release,
        )
    }

    /// `reap_within` is bounded by its own deadline, not by how long the worker
    /// takes, and a reap that gives up keeps the `JoinHandle` so a later stop
    /// can retry it.
    ///
    /// The bound is asserted structurally rather than with elapsed wall clock.
    /// A stopwatch here would not be measuring this code: `reap_within` can
    /// guarantee only that it stops *asking* at its deadline, and the gap
    /// between that and the caller regaining the CPU belongs to the OS
    /// scheduler. Under load that gap grows without limit, so any absolute
    /// millisecond ceiling fails on a busy machine while the code under test is
    /// behaving perfectly - a false red that says nothing about the runtime.
    ///
    /// Gating the worker instead makes the real property decidable and makes it
    /// a stronger claim: while the gate is shut the worker never completes, so
    /// only an implementation that honours its deadline can return here at all.
    /// One that waited on the worker would hang outright rather than merely
    /// look slow, and no amount of machine load can turn a correct
    /// implementation into a failure.
    #[test]
    fn timed_out_reap_retains_ownership_and_a_later_retry_joins() {
        let (mut worker, release) = gated_worker();
        worker.request_shutdown();

        assert_eq!(
            worker.reap_within(Duration::from_millis(2)).unwrap(),
            None,
            "a reap must give up at its own deadline, not wait for the worker"
        );
        assert!(worker.join.is_some(), "timeout must retain the JoinHandle");
        assert!(
            !worker.join.as_ref().unwrap().is_finished(),
            "the reap returned while the worker was still running, which is the \
             whole claim: it stopped at its deadline instead of outlasting the worker"
        );

        // Released, the retained handle is reaped and joined exactly once. The
        // generous bound here is a hang detector, not a promptness measure:
        // nothing is asserted about how much of it is used.
        release.store(true, Ordering::Release);
        assert_eq!(
            worker.reap_within(Duration::from_secs(10)).unwrap(),
            Some(Ok(()))
        );
        assert!(
            worker.join.is_none(),
            "completed retry must join exactly once"
        );
    }

    /// The deadline a reap is given is the deadline it uses.
    ///
    /// This is the one claim about `reap_within` that nothing but a clock can
    /// see: honouring 2ms and quietly honouring some larger constant differ in
    /// elapsed time and in nothing else. A single sample cannot carry it, and
    /// trying was what made this module flaky - machine load can delay any one
    /// sample without limit, so an absolute ceiling on one reading goes red on
    /// a busy machine while the code is behaving perfectly.
    ///
    /// The *minimum* over many samples does carry it, and is not a loosened
    /// tolerance but a sounder estimator: load can only ever make a sample
    /// slower, never faster. An implementation that honours a 2ms deadline
    /// produces at least one fast sample among many however busy the machine
    /// gets; one that floors the deadline at a larger constant produces none,
    /// however idle it is.
    #[test]
    fn a_bounded_reap_uses_the_deadline_it_was_given() {
        const SAMPLES: usize = 25;
        const CEILING: Duration = Duration::from_millis(60);
        const DEADLINE: Duration = Duration::from_millis(2);

        let mut fastest = Duration::MAX;
        for _ in 0..SAMPLES {
            let (mut worker, release) = gated_worker();
            worker.request_shutdown();
            let started = Instant::now();
            assert_eq!(
                worker.reap_within(DEADLINE).unwrap(),
                None,
                "the gate is shut, so there is nothing to reap"
            );
            fastest = fastest.min(started.elapsed());
            // Release and drain, so no sample leaves a live thread behind.
            release.store(true, Ordering::Release);
            let _ = worker.reap_within(Duration::from_secs(10));
        }

        assert!(
            fastest < CEILING,
            "every one of {SAMPLES} reaps given a {DEADLINE:?} deadline took at \
             least {fastest:?}, so the deadline being used is not the one passed in"
        );
    }

    #[test]
    fn late_completion_cannot_erase_a_shutdown_timeout() {
        let mut status = RuntimeStatus {
            phase: RuntimePhase::Failed,
            endpoint: None,
            last_error: Some(RuntimeError::ShutdownTimeout.to_string()),
        };
        record_worker_result(&mut status, true, &Ok(()));
        assert_eq!(status.phase, RuntimePhase::Failed);
        assert_eq!(
            status.last_error.as_deref(),
            Some("agent wallet runtime shutdown timed out")
        );
    }

    #[test]
    fn completed_worker_is_joined_without_an_unbounded_wait() {
        let mut worker = delayed_worker(Duration::ZERO);
        assert_eq!(
            worker.reap_within(Duration::from_secs(1)).unwrap(),
            Some(Ok(()))
        );
        assert!(worker.join.is_none());
    }
}
