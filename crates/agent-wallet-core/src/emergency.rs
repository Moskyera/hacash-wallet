//! Durable, per-wallet emergency-stop interlock.
//!
//! The marker is deliberately outside the encrypted state document. This lets
//! a supervisor stop signing immediately, before it can acquire the manager
//! lock and persist the authenticated state transition. A marker can only be
//! cleared after the caller confirms that the authenticated state was already
//! persisted with payments enabled.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::storage::AgentWalletPaths;
use crate::types::AgentWalletId;

const MARKER_FILE: &str = ".emergency-stop-v1";
const MARKER_DOMAIN: &[u8] = b"HPAY_AGENT_WALLET_EMERGENCY_STOP_V1\n";
const MAX_MARKER_BYTES: u64 = 256;
const INITIAL_GENERATION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyMarkerHealth {
    Absent,
    Present,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEmergencyStatus {
    pub stopped: bool,
    pub marker_health: EmergencyMarkerHealth,
    pub authenticated_state_suspended: bool,
    pub generation: u64,
}

struct EmergencyInner {
    wallet_id: AgentWalletId,
    wallet_root: PathBuf,
    marker_path: PathBuf,
    requested: AtomicBool,
    generation: AtomicU64,
    transition: Mutex<()>,
}

/// Process-local controller backed by a durable marker under one exact Agent
/// Wallet root.
///
/// Clones share the same stop flag and generation. Applications should create
/// one controller per wallet and give clones to the Tauri supervisor, runtime,
/// and manager checkpoints.
#[derive(Clone)]
pub struct AgentEmergencyController {
    inner: Arc<EmergencyInner>,
}

impl std::fmt::Debug for AgentEmergencyController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentEmergencyController")
            .field("wallet_id", &self.inner.wallet_id)
            .field("wallet_root", &self.inner.wallet_root)
            .field("requested", &self.inner.requested.load(Ordering::SeqCst))
            .field("generation", &self.inner.generation.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// A generation-bound authorization to enter one sensitive payment stage.
///
/// The permit is intentionally not clonable. It must be checked again at every
/// irreversible checkpoint. A stop request invalidates all outstanding
/// permits, even if durable state persistence is still waiting for a manager
/// lock.
pub struct AgentSafetyPermit {
    inner: Arc<EmergencyInner>,
    generation: u64,
}

/// Holds the emergency transition lock across one irreversible local action.
/// A stop requested before this guard is acquired fails closed; a stop that
/// arrives afterwards waits until the action and its immediate durable write
/// have left the protected boundary.
#[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
pub(crate) struct AgentIrreversibleGuard<'a> {
    _transition: MutexGuard<'a, ()>,
}

/// A generation-bound authorization for companion connectivity only.
///
/// Unlike `AgentSafetyPermit`, this permit deliberately ignores the
/// authenticated `payments_suspended` flag. It is still invalidated by the
/// independent emergency marker, the process-local stop latch, or a generation
/// change. Holding this permit never authorizes payment creation or signing.
pub(crate) struct AgentConnectivityPermit {
    inner: AgentSafetyPermit,
}

/// A single-use authorization to finish one local, authenticated enable
/// transition.
///
/// It is issued before the authenticated state is changed. Any intervening
/// marker-first stop advances the generation and makes this permit unusable,
/// so an older enable can never clear a newer stop marker.
pub(crate) struct AgentEnablePermit {
    inner: Arc<EmergencyInner>,
    generation: u64,
}

impl std::fmt::Debug for AgentSafetyPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentSafetyPermit")
            .field("wallet_id", &self.inner.wallet_id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl AgentEmergencyController {
    pub fn new(paths: &AgentWalletPaths, wallet_id: &AgentWalletId) -> AgentWalletResult<Self> {
        validate_exact_wallet_root(paths.wallet_root(), wallet_id)?;
        let wallet_root = paths
            .wallet_root()
            .canonicalize()
            .map_err(|_| AgentWalletError::PersistenceFailed)?;
        validate_private_directory(&wallet_root)?;
        let marker_path = wallet_root.join(MARKER_FILE);
        let marker_health = inspect_marker(&wallet_root, &marker_path, wallet_id);
        Ok(Self {
            inner: Arc::new(EmergencyInner {
                wallet_id: wallet_id.clone(),
                wallet_root,
                marker_path,
                requested: AtomicBool::new(marker_health != EmergencyMarkerHealth::Absent),
                generation: AtomicU64::new(INITIAL_GENERATION),
                transition: Mutex::new(()),
            }),
        })
    }

    pub fn wallet_id(&self) -> &AgentWalletId {
        &self.inner.wallet_id
    }

    pub fn marker_path(&self) -> &Path {
        &self.inner.marker_path
    }

    /// Reconcile the independent marker with the authenticated state at
    /// startup. A suspended encrypted state creates/restores the marker. A
    /// marker with enabled encrypted state remains stopped until a local,
    /// authenticated enable transition explicitly clears it.
    pub fn reconcile_startup(
        &self,
        authenticated_state_suspended: bool,
    ) -> AgentWalletResult<AgentEmergencyStatus> {
        if authenticated_state_suspended {
            self.request_stop()?;
        }
        let status = self.status(authenticated_state_suspended);
        if status.marker_health == EmergencyMarkerHealth::Unsafe {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(status)
    }

    pub fn status(&self, authenticated_state_suspended: bool) -> AgentEmergencyStatus {
        let marker_health = inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        );
        let requested = self.inner.requested.load(Ordering::SeqCst);
        AgentEmergencyStatus {
            stopped: authenticated_state_suspended
                || requested
                || marker_health != EmergencyMarkerHealth::Absent,
            marker_health,
            authenticated_state_suspended,
            generation: self.inner.generation.load(Ordering::SeqCst),
        }
    }

    /// Immediately invalidate outstanding permits, then durably create the
    /// stop marker. The caller must invoke this before waiting for the manager
    /// lock that persists `payments_suspended = true`.
    pub fn request_stop(&self) -> AgentWalletResult<()> {
        // Serialize stop and enable so enable can never overwrite a newer stop
        // request's in-memory latch after it removes the marker.
        let _transition = self.transition_lock()?;
        self.inner.requested.store(true, Ordering::SeqCst);
        self.advance_generation()?;
        match inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        ) {
            EmergencyMarkerHealth::Present => return Ok(()),
            EmergencyMarkerHealth::Unsafe => return Err(AgentWalletError::RecoveryRequired),
            EmergencyMarkerHealth::Absent => {}
        }

        validate_private_directory(&self.inner.wallet_root)?;
        let bytes = marker_bytes(&self.inner.wallet_id)?;
        if hacash_wallet_core::paths::secure_write(&self.inner.marker_path, &bytes).is_err() {
            // Another process is not expected because AgentStorage owns an
            // exclusive root lock. Still accept an exact concurrently-created
            // marker and fail closed for every other outcome.
            return match inspect_marker(
                &self.inner.wallet_root,
                &self.inner.marker_path,
                &self.inner.wallet_id,
            ) {
                EmergencyMarkerHealth::Present => Ok(()),
                EmergencyMarkerHealth::Absent => Err(AgentWalletError::PersistenceFailed),
                EmergencyMarkerHealth::Unsafe => Err(AgentWalletError::RecoveryRequired),
            };
        }
        match inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        ) {
            EmergencyMarkerHealth::Present => Ok(()),
            EmergencyMarkerHealth::Absent => Err(AgentWalletError::PersistenceFailed),
            EmergencyMarkerHealth::Unsafe => Err(AgentWalletError::RecoveryRequired),
        }
    }

    /// Capture the exact emergency generation before the manager changes
    /// authenticated state. The resulting permit is invalidated by any newer
    /// marker-first stop.
    pub(crate) fn issue_authenticated_enable_permit(&self) -> AgentWalletResult<AgentEnablePermit> {
        let _transition = self.transition_lock()?;
        if inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        ) == EmergencyMarkerHealth::Unsafe
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(AgentEnablePermit {
            inner: Arc::clone(&self.inner),
            generation: self.inner.generation.load(Ordering::SeqCst),
        })
    }

    /// Clear the marker only after the manager has durably persisted and
    /// reloaded the authenticated `payments_suspended = false` transition.
    ///
    /// Failure leaves the in-memory interlock engaged. If a parent-directory
    /// sync fails after removal, the marker is recreated before returning an
    /// error whenever possible.
    pub(crate) fn clear_after_authenticated_enable(
        &self,
        permit: AgentEnablePermit,
        authenticated_state_suspended: bool,
    ) -> AgentWalletResult<()> {
        if authenticated_state_suspended {
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        let _transition = self.transition_lock()?;
        if !Arc::ptr_eq(&self.inner, &permit.inner)
            || self.inner.generation.load(Ordering::SeqCst) != permit.generation
        {
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        // Invalidate all pre-enable permits while the durable marker still
        // exists. Overflow therefore cannot remove the last durable stop.
        self.advance_generation()?;
        match inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        ) {
            EmergencyMarkerHealth::Unsafe => return Err(AgentWalletError::RecoveryRequired),
            EmergencyMarkerHealth::Present => {
                fs::remove_file(&self.inner.marker_path)
                    .map_err(|_| AgentWalletError::PersistenceFailed)?;
                if sync_directory(&self.inner.wallet_root).is_err() {
                    let bytes = marker_bytes(&self.inner.wallet_id)?;
                    let _ =
                        hacash_wallet_core::paths::secure_write(&self.inner.marker_path, &bytes);
                    return Err(AgentWalletError::PersistenceFailed);
                }
            }
            EmergencyMarkerHealth::Absent => {}
        }
        if inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        ) != EmergencyMarkerHealth::Absent
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.inner.requested.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn issue_safety_permit(
        &self,
        authenticated_state_suspended: bool,
    ) -> AgentWalletResult<AgentSafetyPermit> {
        let _transition = self.transition_lock()?;
        let status = self.status(authenticated_state_suspended);
        require_running(status)?;
        Ok(AgentSafetyPermit {
            inner: Arc::clone(&self.inner),
            generation: status.generation,
        })
    }

    pub(crate) fn issue_connectivity_permit(&self) -> AgentWalletResult<AgentConnectivityPermit> {
        Ok(AgentConnectivityPermit {
            inner: self.issue_safety_permit(false)?,
        })
    }

    fn transition_lock(&self) -> AgentWalletResult<MutexGuard<'_, ()>> {
        self.inner
            .transition
            .lock()
            .map_err(|_| AgentWalletError::RecoveryRequired)
    }

    fn advance_generation(&self) -> AgentWalletResult<u64> {
        self.inner
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                self.inner.requested.store(true, Ordering::SeqCst);
                AgentWalletError::IntegerOverflow
            })
    }
}

impl AgentSafetyPermit {
    pub fn checkpoint(&self, authenticated_state_suspended: bool) -> AgentWalletResult<()> {
        let current = self.inner.generation.load(Ordering::SeqCst);
        if current != self.generation {
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        let marker_health = inspect_marker(
            &self.inner.wallet_root,
            &self.inner.marker_path,
            &self.inner.wallet_id,
        );
        let status = AgentEmergencyStatus {
            stopped: authenticated_state_suspended
                || self.inner.requested.load(Ordering::SeqCst)
                || marker_health != EmergencyMarkerHealth::Absent,
            marker_health,
            authenticated_state_suspended,
            generation: current,
        };
        require_running(status)?;
        if self.inner.generation.load(Ordering::SeqCst) != self.generation {
            return Err(AgentWalletError::AgentPaymentsSuspended);
        }
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(any(test, feature = "agent-wallet-testnet-pilot"))]
    pub(crate) fn irreversible_checkpoint(
        &self,
        authenticated_state_suspended: bool,
    ) -> AgentWalletResult<AgentIrreversibleGuard<'_>> {
        let transition = self
            .inner
            .transition
            .lock()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        self.checkpoint(authenticated_state_suspended)?;
        Ok(AgentIrreversibleGuard {
            _transition: transition,
        })
    }
}

impl AgentConnectivityPermit {
    pub(crate) fn checkpoint(&self) -> AgentWalletResult<()> {
        self.inner.checkpoint(false)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.inner.generation()
    }
}

fn require_running(status: AgentEmergencyStatus) -> AgentWalletResult<()> {
    if status.marker_health == EmergencyMarkerHealth::Unsafe {
        Err(AgentWalletError::RecoveryRequired)
    } else if status.stopped {
        Err(AgentWalletError::AgentPaymentsSuspended)
    } else {
        Ok(())
    }
}

fn marker_bytes(wallet_id: &AgentWalletId) -> AgentWalletResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(MARKER_DOMAIN.len() + wallet_id.as_str().len() + 16);
    bytes.extend_from_slice(MARKER_DOMAIN);
    bytes.extend_from_slice(b"wallet_id=");
    bytes.extend_from_slice(wallet_id.as_str().as_bytes());
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(AgentWalletError::InvalidIdentifier);
    }
    Ok(bytes)
}

fn inspect_marker(
    wallet_root: &Path,
    marker_path: &Path,
    wallet_id: &AgentWalletId,
) -> EmergencyMarkerHealth {
    let metadata = match fs::symlink_metadata(marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return EmergencyMarkerHealth::Absent;
        }
        Err(_) => return EmergencyMarkerHealth::Unsafe,
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MARKER_BYTES
        || validate_private_directory(wallet_root).is_err()
    {
        return EmergencyMarkerHealth::Unsafe;
    }
    let canonical = match marker_path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => return EmergencyMarkerHealth::Unsafe,
    };
    if canonical.parent() != Some(wallet_root) {
        return EmergencyMarkerHealth::Unsafe;
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = match options.open(marker_path) {
        Ok(file) => file,
        Err(_) => return EmergencyMarkerHealth::Unsafe,
    };
    let open_metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return EmergencyMarkerHealth::Unsafe,
    };
    if !open_metadata.file_type().is_file()
        || open_metadata.len() == 0
        || open_metadata.len() > MAX_MARKER_BYTES
        || validate_private_file(&open_metadata).is_err()
    {
        return EmergencyMarkerHealth::Unsafe;
    }
    let mut bytes = Vec::with_capacity(open_metadata.len() as usize);
    if file
        .by_ref()
        .take(MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_MARKER_BYTES
    {
        return EmergencyMarkerHealth::Unsafe;
    }
    match marker_bytes(wallet_id) {
        Ok(expected) if bytes == expected => EmergencyMarkerHealth::Present,
        _ => EmergencyMarkerHealth::Unsafe,
    }
}

fn validate_exact_wallet_root(
    wallet_root: &Path,
    wallet_id: &AgentWalletId,
) -> AgentWalletResult<()> {
    let expected_name = wallet_id.as_str();
    if wallet_root.file_name().and_then(|name| name.to_str()) != Some(expected_name)
        || wallet_root
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("wallets")
    {
        return Err(AgentWalletError::InvalidWalletScope);
    }
    validate_private_directory(wallet_root)
}

fn validate_private_directory(path: &Path) -> AgentWalletResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| AgentWalletError::PersistenceFailed)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(AgentWalletError::RecoveryRequired);
    }
    validate_private_metadata(&metadata, true)
}

fn validate_private_file(metadata: &fs::Metadata) -> AgentWalletResult<()> {
    validate_private_metadata(metadata, false)
}

#[cfg(unix)]
fn validate_private_metadata(metadata: &fs::Metadata, directory: bool) -> AgentWalletResult<()> {
    use std::os::unix::fs::MetadataExt;

    let expected_mode = if directory { 0o700 } else { 0o600 };
    let actual_mode = metadata.mode() & 0o777;
    // SAFETY: geteuid has no preconditions and returns the effective uid of
    // this process.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || actual_mode & !expected_mode != 0 {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_metadata(metadata: &fs::Metadata, _directory: bool) -> AgentWalletResult<()> {
    // On Windows the storage root and files are created by `secure_write`,
    // which installs a protected owner+SYSTEM DACL. We still reject
    // reparse-point/symlink paths before opening and treat every unreadable or
    // malformed existing marker as a durable stop.
    if metadata.permissions().readonly() {
        return Err(AgentWalletError::RecoveryRequired);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::AgentStorage;

    fn controller() -> (
        tempfile::TempDir,
        AgentStorage,
        AgentWalletId,
        AgentEmergencyController,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let storage = AgentStorage::open(temp.path()).unwrap();
        let wallet_id = AgentWalletId::new();
        let paths = storage.ensure_wallet_layout(&wallet_id).unwrap();
        let controller = AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        (temp, storage, wallet_id, controller)
    }

    #[test]
    fn marker_survives_crash_and_reconciles_authenticated_state() {
        let (_temp, storage, wallet_id, first) = controller();
        let permit = first.issue_safety_permit(false).unwrap();
        first.request_stop().unwrap();
        assert_eq!(
            permit.checkpoint(false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
        drop(first);

        let paths = storage.paths(&wallet_id).unwrap();
        let restarted = AgentEmergencyController::new(&paths, &wallet_id).unwrap();
        let status = restarted.reconcile_startup(false).unwrap();
        assert!(status.stopped);
        assert_eq!(status.marker_health, EmergencyMarkerHealth::Present);
        assert!(matches!(
            restarted.issue_safety_permit(false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        ));
    }

    #[test]
    fn corrupt_marker_fails_closed_and_cannot_be_cleared() {
        let (_temp, _storage, _wallet_id, controller) = controller();
        controller.request_stop().unwrap();
        let permit = controller.issue_authenticated_enable_permit().unwrap();
        hacash_wallet_core::paths::secure_write(controller.marker_path(), b"corrupt").unwrap();
        assert_eq!(
            controller.status(false).marker_health,
            EmergencyMarkerHealth::Unsafe
        );
        assert!(matches!(
            controller.issue_safety_permit(false),
            Err(AgentWalletError::RecoveryRequired)
        ));
        assert_eq!(
            controller.clear_after_authenticated_enable(permit, false),
            Err(AgentWalletError::RecoveryRequired)
        );
        assert!(controller.marker_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_marker_fails_closed_and_is_not_deleted_by_enable() {
        use std::os::unix::fs::symlink;

        let (_temp, _storage, _wallet_id, controller) = controller();
        let permit = controller.issue_authenticated_enable_permit().unwrap();
        let outside = controller
            .marker_path()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("outside-stop");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, controller.marker_path()).unwrap();
        assert_eq!(
            controller.status(false).marker_health,
            EmergencyMarkerHealth::Unsafe
        );
        assert_eq!(
            controller.clear_after_authenticated_enable(permit, false),
            Err(AgentWalletError::RecoveryRequired)
        );
        assert!(
            fs::symlink_metadata(controller.marker_path())
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn enable_failure_keeps_marker_and_stop_requested() {
        let (_temp, _storage, _wallet_id, controller) = controller();
        controller.request_stop().unwrap();
        let permit = controller.issue_authenticated_enable_permit().unwrap();
        assert_eq!(
            controller.clear_after_authenticated_enable(permit, true),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
        assert!(controller.marker_path().exists());
        assert!(controller.status(true).stopped);
    }

    #[test]
    fn stop_invalidates_every_older_safety_generation() {
        let (_temp, _storage, _wallet_id, controller) = controller();
        let first = controller.issue_safety_permit(false).unwrap();
        let generation = first.generation();
        controller.request_stop().unwrap();
        assert!(controller.status(true).generation > generation);
        assert_eq!(
            first.checkpoint(false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
        assert!(first.irreversible_checkpoint(false).is_err());
        let enable = controller.issue_authenticated_enable_permit().unwrap();
        controller
            .clear_after_authenticated_enable(enable, false)
            .unwrap();
        let second = controller.issue_safety_permit(false).unwrap();
        assert!(second.generation() > generation);
        second.checkpoint(false).unwrap();
    }

    #[test]
    fn irreversible_checkpoint_serializes_key_use_with_emergency_stop() {
        use std::sync::{Barrier, mpsc};
        use std::time::Duration;

        let (_temp, _storage, _wallet_id, controller) = controller();
        let permit = controller.issue_safety_permit(false).unwrap();
        let guard = permit.irreversible_checkpoint(false).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker_controller = controller.clone();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            finished_tx.send(worker_controller.request_stop()).unwrap();
        });

        barrier.wait();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(guard);
        assert_eq!(
            finished_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Ok(())
        );
        worker.join().unwrap();
        assert_eq!(
            permit.checkpoint(false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
    }

    #[test]
    fn newer_stop_invalidates_older_authenticated_enable() {
        let (_temp, _storage, _wallet_id, controller) = controller();
        controller.request_stop().unwrap();
        let enable = controller.issue_authenticated_enable_permit().unwrap();
        let generation = controller.status(true).generation;
        let stopping_controller = controller.clone();

        std::thread::spawn(move || stopping_controller.request_stop().unwrap())
            .join()
            .unwrap();

        assert!(controller.status(false).generation > generation);
        assert_eq!(
            controller.clear_after_authenticated_enable(enable, false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        );
        assert!(controller.marker_path().exists());
        assert!(controller.status(false).stopped);
        assert!(matches!(
            controller.issue_safety_permit(false),
            Err(AgentWalletError::AgentPaymentsSuspended)
        ));
    }

    #[test]
    fn suspended_authenticated_state_restores_missing_marker() {
        let (_temp, _storage, _wallet_id, controller) = controller();
        assert!(!controller.marker_path().exists());
        let status = controller.reconcile_startup(true).unwrap();
        assert!(status.stopped);
        assert_eq!(status.marker_health, EmergencyMarkerHealth::Present);
    }
}
