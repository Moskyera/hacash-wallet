//! Fail-closed Android companion foundation with an explicit pilot-only approval/witness surface.
//!
//! Stores only public pairing/replay/witness state. It exposes no wallet key, generic
//! send, admin signing, public listener, HTTP, or relay.

pub(crate) mod commands;
mod lifecycle;
mod network;
#[cfg(target_os = "android")]
mod pairing;
pub(crate) mod pilot;
mod session;
mod storage;

#[cfg(any(target_os = "android", test))]
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
#[cfg(any(target_os = "android", test))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, watch};
#[cfg(target_os = "android")]
use tokio::time::Instant;

pub(crate) use commands::require_agent_companion_webview;
pub(crate) use lifecycle::init as companion_lifecycle_plugin;
use storage::{CompanionStateStore, FileCompanionStateStore, SharedCompanionState};

const STATE_VERSION: u64 = 1;
const MAX_STATE_BYTES: usize = 1024 * 1024;

pub struct AgentCompanionMobileState {
    shared: Arc<SharedCompanionState>,
    lifecycle: Mutex<()>,
    #[cfg(target_os = "android")]
    rotation: Mutex<()>,
    /// Held for the whole of an approval or witness flow, from the durable
    /// consent write to the desktop's final answer.
    ///
    /// The automatic sweep retires a consent record the desktop has stopped
    /// listing, and inside a healthy flow an operation legitimately leaves that
    /// list for a moment. Without this the sweep could delete the owner's
    /// consent between two chained anchors and strand the payment it was trying
    /// to protect. The sweep never waits for this lock; it simply does nothing
    /// while a flow owns it.
    #[cfg(any(target_os = "android", test))]
    consent_flow: Mutex<()>,
    lifecycle_cancel: watch::Sender<u64>,
    #[cfg(target_os = "android")]
    pending: Mutex<Option<pairing::PendingPairing>>,
    #[cfg(target_os = "android")]
    active: Mutex<Option<session::ActiveSession>>,
    #[cfg(target_os = "android")]
    lease_deadline: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for AgentCompanionMobileState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentCompanionMobileState")
            .field("shared", &self.shared)
            .field("pending", &"<memory-only-pairing-attempt>")
            .field("active", &"<owned-outbound-session>")
            .field("lifecycle_cancel", &"<generation>")
            .field("rotation", &"<serialized-biometric-operation>")
            .finish()
    }
}

impl AgentCompanionMobileState {
    pub fn open(app_data_dir: &Path) -> Self {
        Self::with_store(Arc::new(FileCompanionStateStore::new(
            app_data_dir.join("agent-companion").join("state.json"),
        )))
    }

    fn with_store(store: Arc<dyn CompanionStateStore>) -> Self {
        let (lifecycle_cancel, _) = watch::channel(0);
        Self {
            shared: Arc::new(SharedCompanionState::open(store)),
            lifecycle: Mutex::new(()),
            #[cfg(target_os = "android")]
            rotation: Mutex::new(()),
            #[cfg(any(target_os = "android", test))]
            consent_flow: Mutex::new(()),
            lifecycle_cancel,
            #[cfg(target_os = "android")]
            pending: Mutex::new(None),
            #[cfg(target_os = "android")]
            active: Mutex::new(None),
            #[cfg(target_os = "android")]
            lease_deadline: Mutex::new(None),
        }
    }

    pub(super) fn signal_lifecycle_cancel(&self) {
        self.lifecycle_cancel.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    #[cfg(any(target_os = "android", test))]
    pub(super) async fn run_guarded<T, F>(
        &self,
        limit: Duration,
        timeout_message: &'static str,
        operation: F,
    ) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>>,
    {
        let _lifecycle = self.lifecycle.lock().await;
        let mut cancellation = self.lifecycle_cancel.subscribe();
        tokio::select! {
            result = tokio::time::timeout(limit, operation) => {
                result.map_err(|_| timeout_message.to_owned())?
            }
            changed = cancellation.changed() => {
                let _ = changed;
                Err("Agent companion operation was cancelled by lifecycle transition".to_owned())
            }
        }
    }

    /// Runs an operation that is already bound to an Android BiometricPrompt
    /// CryptoObject. Some Android vendors temporarily suspend the host webview
    /// while their system biometric UI is visible. Treating that suspension as
    /// an app-background cancellation drops the Rust future before the native
    /// one-shot signature can return.
    ///
    /// The lifecycle mutex still serializes close/reset, the native plugin
    /// rejects when its Agent Activity is destroyed, and the hard timeout keeps
    /// the operation bounded. This exception is for hardware-bound signing
    /// only; network/session operations must continue to use `run_guarded`.
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn run_biometric_guarded<T, F>(
        &self,
        limit: Duration,
        timeout_message: &'static str,
        operation: F,
    ) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>>,
    {
        let _lifecycle = self.lifecycle.lock().await;
        tokio::time::timeout(limit, operation)
            .await
            .map_err(|_| timeout_message.to_owned())?
    }

    /// Retires a consent record the desktop, or time, has proved obsolete.
    ///
    /// `desktop_awaiting` carries the operation ids an authenticated status
    /// snapshot listed as awaiting this phone's witness, or `None` when no
    /// statement is available - a transport failure must never be passed here
    /// as an empty list, because "the desktop did not answer" is not "the
    /// desktop does not want this".
    ///
    /// Does nothing at all while an approval or witness flow holds
    /// [`Self::consent_flow`], and never blocks waiting for it.
    #[cfg(any(target_os = "android", test))]
    async fn sweep_obsolete_consent(
        &self,
        desktop_awaiting: Option<&[String]>,
    ) -> Result<Option<storage::MobileDiscardedConsent>, String> {
        let Ok(_flow) = self.consent_flow.try_lock() else {
            return Ok(None);
        };
        self.shared
            .sweep_obsolete_consent(desktop_awaiting, unix_now()?)
            .await
    }

    #[cfg(target_os = "android")]
    pub(super) async fn renew_session_lease(&self) {
        *self.lease_deadline.lock().await = Some(Instant::now() + Duration::from_secs(20));
    }

    pub(super) async fn close_native_session(&self) {
        self.signal_lifecycle_cancel();
        let _lifecycle = self.lifecycle.lock().await;
        #[cfg(target_os = "android")]
        {
            *self.lease_deadline.lock().await = None;
            drop(self.active.lock().await.take());
            drop(self.pending.lock().await.take());
        }
    }

    #[cfg(target_os = "android")]
    pub(super) async fn expire_session_lease(&self) {
        let expired = self
            .lease_deadline
            .lock()
            .await
            .is_some_and(|deadline| deadline <= Instant::now());
        if expired {
            self.close_native_session().await;
        }
    }

    #[cfg(not(target_os = "android"))]
    pub(super) async fn expire_session_lease(&self) {}
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "System clock is before Unix epoch".to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn lifecycle_cancel_wins_over_delayed_publish() {
        let root = std::env::temp_dir().join(format!(
            "hpay-companion-lifecycle-test-{}",
            std::process::id()
        ));
        let state = Arc::new(AgentCompanionMobileState::open(&root));
        let published = Arc::new(AtomicBool::new(false));
        let task = {
            let state = Arc::clone(&state);
            let published = Arc::clone(&published);
            tokio::spawn(async move {
                state
                    .run_guarded(
                        Duration::from_secs(5),
                        "delayed operation timed out",
                        async move {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            published.store(true, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        state.close_native_session().await;
        assert!(task.await.unwrap().is_err());
        assert!(!published.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir(root.join("agent-companion"));
        let _ = std::fs::remove_dir(root);
    }

    #[tokio::test]
    async fn lifecycle_signal_does_not_drop_an_active_hardware_biometric_result() {
        let root = std::env::temp_dir().join(format!(
            "hpay-companion-biometric-lifecycle-test-{}",
            std::process::id()
        ));
        let state = Arc::new(AgentCompanionMobileState::open(&root));
        let task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                state
                    .run_biometric_guarded(
                        Duration::from_secs(1),
                        "biometric operation timed out",
                        async {
                            tokio::time::sleep(Duration::from_millis(40)).await;
                            Ok("signed")
                        },
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        state.signal_lifecycle_cancel();
        assert_eq!(task.await.unwrap().unwrap(), "signed");
        let _ = std::fs::remove_dir(root.join("agent-companion"));
        let _ = std::fs::remove_dir(root);
    }

    /// The sweep must never delete a consent record out from under the flow
    /// that is using it.
    ///
    /// Inside a healthy witness lifecycle the operation legitimately leaves the
    /// desktop's offered set for a moment - between the receipt being accepted
    /// and the next chained anchor arriving. A sweep landing in that window
    /// would retire the owner's consent mid-payment and strand the very thing
    /// it exists to unstick. It never waits for the flow, it simply does
    /// nothing while one is running.
    #[tokio::test]
    async fn a_flow_in_progress_is_never_swept_from_under_itself() {
        let root = std::env::temp_dir().join(format!(
            "hpay-companion-consent-flow-test-{}",
            std::process::id()
        ));
        let state = AgentCompanionMobileState::open(&root);
        let flow = state.consent_flow.lock().await;
        assert_eq!(
            state.sweep_obsolete_consent(Some(&[])).await.unwrap(),
            None,
            "a running approval or witness flow suspends the sweep entirely"
        );
        drop(flow);
        // Unpaired, so there is still nothing to retire - but the sweep ran.
        assert_eq!(state.sweep_obsolete_consent(Some(&[])).await.unwrap(), None);
        let _ = std::fs::remove_dir(root.join("agent-companion"));
        let _ = std::fs::remove_dir(root);
    }

    #[test]
    fn companion_modules_expose_only_feature_gated_typed_pilot_authority() {
        let source = concat!(
            include_str!("mod.rs"),
            include_str!("commands.rs"),
            include_str!("lifecycle.rs"),
            include_str!("pairing.rs"),
            include_str!("session.rs"),
            include_str!("storage.rs")
        );
        for forbidden in [
            concat!("wallet_", "send_hac"),
            concat!("wallet_", "send_btc"),
            concat!("wallet_", "send_hacd"),
            concat!("export_", "private_key"),
            concat!("Desktop", "LanServer"),
            concat!("Tcp", "Listener"),
            concat!("req", "west"),
            concat!("Admin", "Command"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden companion surface: {forbidden}"
            );
        }
        assert!(source.contains("cfg!(feature = \"agent-wallet-testnet-pilot\")"));
        assert!(source.contains("CompanionPayload::ApprovalDecision"));
        assert!(source.contains("CompanionPayload::AgentFastPayApprovalPoll"));
        assert!(source.contains("CompanionPayload::AgentFastPayApprovalRequest"));
        assert!(source.contains("CompanionPayload::AgentFastPayApprovalDecision"));
        assert!(source.contains("CompanionPayload::RecoverPendingWitness"));
        assert!(source.contains("CompanionPayload::WitnessReceipt"));
    }
}
