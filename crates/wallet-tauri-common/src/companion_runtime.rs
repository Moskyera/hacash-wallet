//! Desktop lifecycle owner for the opt-in mobile companion private-LAN server.
//!
//! This is separate from the local AI connector. It never binds a wildcard,
//! loopback or public address and cannot start without an unlocked Agent Wallet
//! and at least one active paired mobile device.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use agent_wallet_core::{AgentCompanionPairingAttempt, AgentWalletId, AgentWalletManager};
use hpay_companion_lan_runtime::{
    DEFAULT_COMPANION_PORT, DesktopLanServer, DesktopPairingBackend, DesktopSessionBackend,
    LanRuntimeConfig, LanRuntimeError, PairingLanServer, RuntimeFuture, RuntimeGateController,
    RuntimeStartupGate,
};
use hpay_companion_protocol::{
    DevicePublicRecord, DeviceRole, EncryptedCompanionFrame, LanEndpoint, PairingConfirmation,
    PairingOffer, PairingRequest,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hpay_companion_protocol::{SignedRotationCandidateAcceptance, SignedRotationPairingTicket};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::companion_backend::AgentCompanionBackend;

struct CompanionSlot {
    wallet_id: AgentWalletId,
    local_addr: SocketAddr,
    server: DesktopLanServer,
    gate: RuntimeGateController,
    backend: Arc<dyn DesktopSessionBackend>,
}

/// A session server that gave the private-LAN port back so a phone pairing
/// could bind it.
///
/// The already validated gate is carried over instead of being rebuilt: a lock,
/// a device revoke or an emergency stop closes that gate, and
/// `DesktopLanServer::start` refuses to bind a closed gate, so a suspended
/// session can never come back with more authority than it had.
struct SuspendedSession {
    wallet_id: AgentWalletId,
    bind_addr: SocketAddr,
    gate: RuntimeGateController,
    backend: Arc<dyn DesktopSessionBackend>,
}

struct PairingSlot {
    wallet_id: AgentWalletId,
    attempt: AgentCompanionPairingAttempt,
    purpose: PairingSlotPurpose,
    confirmation: Option<PairingConfirmation>,
    accepted_request: Option<PairingRequest>,
    accepted_ack: Option<EncryptedCompanionFrame>,
}

struct AgentPairingTransportBackend {
    wallet_id: AgentWalletId,
    pairing: Arc<Mutex<Option<PairingSlot>>>,
    manager: Arc<Mutex<AgentWalletManager>>,
}

impl DesktopPairingBackend for AgentPairingTransportBackend {
    fn accept_request<'a>(
        &'a self,
        request: PairingRequest,
    ) -> RuntimeFuture<'a, PairingConfirmation> {
        Box::pin(async move {
            let mut pairing = self.pairing.lock().await;
            let slot = pairing
                .as_mut()
                .filter(|slot| slot.wallet_id == self.wallet_id)
                .ok_or(LanRuntimeError::Backend)?;
            if slot.purpose != PairingSlotPurpose::General
                || !pairing_request_matches_offer(&request, slot.attempt.offer())
            {
                return Err(LanRuntimeError::Backend);
            }
            if let Some(cached_confirmation) = cached_confirmation_for_exact_request(
                slot.accepted_request.as_ref(),
                slot.confirmation.as_ref(),
                &request,
            )
            .map_err(|_| LanRuntimeError::Backend)?
            {
                return Ok(cached_confirmation);
            }
            let accepted_request = request.clone();
            let confirmation = self
                .manager
                .lock()
                .await
                .accept_companion_pairing_request(
                    &self.wallet_id,
                    &mut slot.attempt,
                    request,
                    unix_now().map_err(|_| LanRuntimeError::Backend)?,
                )
                .await
                .map_err(|_| LanRuntimeError::Backend)?;
            slot.accepted_request = Some(accepted_request);
            slot.confirmation = Some(confirmation.clone());
            Ok(confirmation)
        })
    }

    fn accept_ack<'a>(&'a self, ack: EncryptedCompanionFrame) -> RuntimeFuture<'a, ()> {
        Box::pin(async move {
            let mut pairing = self.pairing.lock().await;
            let slot = pairing
                .as_mut()
                .filter(|slot| slot.wallet_id == self.wallet_id)
                .ok_or(LanRuntimeError::Backend)?;
            if slot.purpose != PairingSlotPurpose::General || slot.confirmation.is_none() {
                return Err(LanRuntimeError::Backend);
            }
            if exact_ack_was_already_accepted(slot.accepted_ack.as_ref(), &ack)
                .map_err(|_| LanRuntimeError::Backend)?
            {
                return Ok(());
            }
            let accepted_ack = ack.clone();
            self.manager
                .lock()
                .await
                .accept_companion_pairing_ack(
                    &self.wallet_id,
                    &mut slot.attempt,
                    &ack,
                    unix_now().map_err(|_| LanRuntimeError::Backend)?,
                )
                .map_err(|_| LanRuntimeError::Backend)?;
            slot.accepted_ack = Some(accepted_ack);

            Ok(())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PairingSlotPurpose {
    General,
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    RotationCandidate {
        rotation_id: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingProgress {
    pub offer: PairingOffer,
    pub confirmation: Option<PairingConfirmation>,
    pub ack_received: bool,
    /// Signed phone requests this pairing has already answered.
    ///
    /// The budget is bounded and spending it destroys the pairing, so the
    /// trusted UI has to be able to show it before the last try is gone. These
    /// are counters only: no code, nonce, key or device identifier.
    pub attempts_used: u8,
    /// Tries left before this pairing is destroyed.
    pub attempts_remaining: u8,
    /// Total tries this pairing will ever answer.
    pub max_attempts: u8,
}

#[derive(Debug, Clone)]
pub struct CompanionRuntimeStatus {
    pub wallet_id: AgentWalletId,
    pub local_addr: SocketAddr,
    pub phase: &'static str,
}

/// Owns the single private-LAN port shared by the pairing transport and the
/// session transport.
///
/// Lock order is `lifecycle` -> (`pairing` | `pairing_server` | `slot`) ->
/// `manager`. Every helper whose name ends in `_locked` assumes the caller
/// already holds `lifecycle` and must never take it again.
pub struct AgentCompanionSupervisor {
    lifecycle: Mutex<()>,
    slot: Mutex<Option<CompanionSlot>>,
    pairing: Arc<Mutex<Option<PairingSlot>>>,
    pairing_server: Mutex<Option<PairingLanServer>>,
    active_gate: StdMutex<Option<(AgentWalletId, RuntimeGateController)>>,
    suspended: StdMutex<Option<SuspendedSession>>,
}

impl Default for AgentCompanionSupervisor {
    fn default() -> Self {
        Self {
            lifecycle: Mutex::new(()),
            slot: Mutex::new(None),
            pairing: Arc::new(Mutex::new(None)),
            pairing_server: Mutex::new(None),
            active_gate: StdMutex::new(None),
            suspended: StdMutex::new(None),
        }
    }
}

const CLOSED_GATE: RuntimeStartupGate = RuntimeStartupGate {
    agent_space_active: false,
    connectivity_enabled: false,
    active_paired_devices: 0,
};

const PAIRING_OWNS_THE_PORT: &str =
    "finish or cancel phone pairing before starting the phone connection";

impl AgentCompanionSupervisor {
    pub async fn start_pairing(
        &self,
        wallet_id: AgentWalletId,
        endpoint: LanEndpoint,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<PairingOffer, String> {
        // The pairing transport and the session transport share one private-LAN
        // port and cannot both own it. Holding `lifecycle` for the whole start
        // keeps `start`/`stop` out while the port changes hands, so the owner
        // never has to press anything in a hidden order.
        let _lifecycle = self.lifecycle.lock().await;
        let now = unix_now()?;
        let expired = {
            let mut pairing = self.pairing.lock().await;
            if pairing
                .as_ref()
                .is_some_and(|slot| slot.attempt.offer().expires_at <= now)
            {
                pairing.take()
            } else {
                None
            }
        };
        if let Some(expired) = expired {
            let cancel_result = manager
                .lock()
                .await
                .cancel_companion_pairing(&expired.wallet_id, expired.attempt)
                .map_err(|error| error.to_string());
            self.stop_pairing_server().await;
            cancel_result?;
        }
        if self.pairing.lock().await.is_some() {
            return Err("cancel the active mobile pairing before starting another".to_owned());
        }

        let bind_addr = SocketAddr::new(endpoint.ip(), endpoint.port());
        let config = LanRuntimeConfig::production(bind_addr).map_err(|error| error.to_string())?;
        let attempt = manager
            .lock()
            .await
            .start_companion_pairing(&wallet_id, vec![endpoint], now, 5 * 60)
            .map_err(|error| error.to_string())?;
        let offer = attempt.offer().clone();
        *self.pairing.lock().await = Some(PairingSlot {
            wallet_id: wallet_id.clone(),
            attempt,
            purpose: PairingSlotPurpose::General,
            confirmation: None,
            accepted_request: None,
            accepted_ack: None,
        });

        let backend = Arc::new(AgentPairingTransportBackend {
            wallet_id: wallet_id.clone(),
            pairing: Arc::clone(&self.pairing),
            manager: Arc::clone(&manager),
        });
        // Hand the port over before binding. `stop` is not usable here: it takes
        // `lifecycle`, which this function already holds, so it would deadlock
        // the whole wallet.
        self.suspend_session_for_pairing_locked().await;
        match PairingLanServer::start(config, backend).await {
            Ok(server) => {
                *self.pairing_server.lock().await = Some(server);
                Ok(offer)
            }
            Err(error) => {
                // `cancel_pairing` is a public entry point that takes
                // `lifecycle`; unwind inline instead and give the port back.
                let abandoned = self.pairing.lock().await.take();
                if let Some(abandoned) = abandoned {
                    let _ = manager
                        .lock()
                        .await
                        .cancel_companion_pairing(&abandoned.wallet_id, abandoned.attempt);
                }
                self.stop_pairing_server().await;
                self.resume_suspended_session_locked().await;
                Err(format!(
                    "Private-LAN phone pairing could not start: {error}"
                ))
            }
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub async fn start_rotation_candidate_pairing(
        &self,
        wallet_id: AgentWalletId,
        rotation_id: String,
        endpoint: LanEndpoint,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<PairingOffer, String> {
        let now = unix_now()?;
        let mut pairing = self.pairing.lock().await;
        if pairing.is_some() {
            return Err("cancel the active mobile pairing before starting another".to_owned());
        }
        let mut manager = manager.lock().await;
        let attempt = manager
            .start_rotation_candidate_pairing(&wallet_id, &rotation_id, vec![endpoint], now, 5 * 60)
            .map_err(|error| error.to_string())?;
        let offer = attempt.offer().clone();
        *pairing = Some(PairingSlot {
            wallet_id,
            attempt,
            purpose: PairingSlotPurpose::RotationCandidate { rotation_id },
            confirmation: None,
            accepted_request: None,
            accepted_ack: None,
        });
        Ok(offer)
    }

    pub async fn pairing_status(
        &self,
        wallet_id: &AgentWalletId,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<Option<PairingProgress>, String> {
        let now = unix_now()?;
        let server_running = self
            .pairing_server
            .lock()
            .await
            .as_ref()
            .is_some_and(PairingLanServer::is_running);
        let (finished, transport_failed) = {
            let mut pairing = self.pairing.lock().await;
            let Some(slot) = pairing.as_ref() else {
                return Ok(None);
            };
            if &slot.wallet_id != wallet_id {
                return Err("a different Agent Wallet owns the active mobile pairing".to_owned());
            }
            let transport_failed = slot.purpose == PairingSlotPurpose::General && !server_running;
            if slot.attempt.offer().expires_at <= now || transport_failed {
                (pairing.take(), transport_failed)
            } else {
                let budget = slot.attempt.attempt_budget();
                return Ok(Some(PairingProgress {
                    offer: slot.attempt.offer().clone(),
                    confirmation: slot.confirmation.clone(),
                    ack_received: slot.accepted_ack.is_some(),
                    attempts_used: budget.used(),
                    attempts_remaining: budget.remaining(),
                    max_attempts: budget.max(),
                }));
            }
        };
        let cancel_result = if let Some(finished) = finished {
            manager
                .lock()
                .await
                .cancel_companion_pairing(&finished.wallet_id, finished.attempt)
                .map_err(|error| error.to_string())
        } else {
            Ok(())
        };
        self.stop_pairing_server().await;
        self.resume_suspended_session().await;
        cancel_result?;
        if transport_failed {
            return Err("Phone pairing connection stopped. Start pairing again.".to_owned());
        }
        Ok(None)
    }

    pub async fn accept_pairing_request(
        &self,
        wallet_id: &AgentWalletId,
        request: PairingRequest,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<PairingConfirmation, String> {
        let mut pairing = self.pairing.lock().await;
        let slot = pairing
            .as_mut()
            .filter(|slot| &slot.wallet_id == wallet_id)
            .ok_or_else(|| "no active mobile pairing for this Agent Wallet".to_owned())?;
        if slot.purpose != PairingSlotPurpose::General {
            return Err("active pairing is reserved for witness rotation".to_owned());
        }
        if !pairing_request_matches_offer(&request, slot.attempt.offer()) {
            return Err("mobile pairing request does not match the active offer".to_owned());
        }
        if let Some(cached_confirmation) = cached_confirmation_for_exact_request(
            slot.accepted_request.as_ref(),
            slot.confirmation.as_ref(),
            &request,
        )
        .map_err(|_| "a different mobile pairing request was already accepted".to_owned())?
        {
            return Ok(cached_confirmation);
        }
        let accepted_request = request.clone();
        let confirmation = manager
            .lock()
            .await
            .accept_companion_pairing_request(wallet_id, &mut slot.attempt, request, unix_now()?)
            .await
            .map_err(|error| error.to_string())?;
        slot.accepted_request = Some(accepted_request);
        slot.confirmation = Some(confirmation.clone());
        Ok(confirmation)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub async fn accept_rotation_candidate_request(
        &self,
        wallet_id: &AgentWalletId,
        request: PairingRequest,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<(PairingConfirmation, SignedRotationPairingTicket), String> {
        let mut pairing = self.pairing.lock().await;
        let slot = pairing
            .as_mut()
            .filter(|slot| &slot.wallet_id == wallet_id)
            .ok_or_else(|| "no active rotation candidate pairing".to_owned())?;
        if !matches!(slot.purpose, PairingSlotPurpose::RotationCandidate { .. }) {
            return Err("active pairing is not a rotation candidate pairing".to_owned());
        }
        manager
            .lock()
            .await
            .accept_rotation_candidate_pairing_request(
                wallet_id,
                &mut slot.attempt,
                request,
                unix_now()?,
            )
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn complete_pairing(
        &self,
        wallet_id: &AgentWalletId,
        encrypted_ack: Option<&EncryptedCompanionFrame>,
        verification_code: &str,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<DevicePublicRecord, String> {
        let mut pairing = self.pairing.lock().await;
        let slot = pairing
            .as_mut()
            .filter(|slot| &slot.wallet_id == wallet_id)
            .ok_or_else(|| "no active mobile pairing for this Agent Wallet".to_owned())?;
        if slot.purpose != PairingSlotPurpose::General {
            return Err("active pairing is reserved for witness rotation".to_owned());
        }
        if slot.confirmation.is_none() {
            return Err("the phone has not completed the signed pairing request".to_owned());
        }
        let mut manager_guard = manager.lock().await;
        let now = unix_now()?;
        if slot.accepted_ack.is_none() {
            let ack = encrypted_ack
                .ok_or_else(|| "the phone has not confirmed the pairing code".to_owned())?;
            let accepted_ack = ack.clone();
            manager_guard
                .accept_companion_pairing_ack(wallet_id, &mut slot.attempt, ack, now)
                .map_err(|error| error.to_string())?;
            slot.accepted_ack = Some(accepted_ack);
        }
        let completed = manager_guard
            .complete_companion_pairing_code(wallet_id, &mut slot.attempt, verification_code, now)
            .map_err(|error| error.to_string())?;
        let record = completed.mobile_device_record().clone();
        drop(manager_guard);
        *pairing = None;
        drop(pairing);
        self.stop_pairing_server().await;
        self.resume_suspended_session().await;
        Ok(record)
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub async fn complete_rotation_candidate_pairing(
        &self,
        wallet_id: &AgentWalletId,
        encrypted_ack: &EncryptedCompanionFrame,
        verification_code: &str,
        signed_acceptance: SignedRotationCandidateAcceptance,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<DevicePublicRecord, String> {
        let mut pairing = self.pairing.lock().await;
        let slot = pairing
            .as_mut()
            .filter(|slot| &slot.wallet_id == wallet_id)
            .ok_or_else(|| "no active rotation candidate pairing".to_owned())?;
        if !matches!(slot.purpose, PairingSlotPurpose::RotationCandidate { .. }) {
            return Err("active pairing is not a rotation candidate pairing".to_owned());
        }
        let mut manager = manager.lock().await;
        let now = unix_now()?;
        manager
            .accept_companion_pairing_ack(wallet_id, &mut slot.attempt, encrypted_ack, now)
            .map_err(|error| error.to_string())?;
        let record = manager
            .complete_rotation_candidate_pairing_code(
                wallet_id,
                &mut slot.attempt,
                verification_code,
                signed_acceptance,
                now,
            )
            .map_err(|error| error.to_string())?;
        *pairing = None;
        Ok(record)
    }

    pub async fn cancel_pairing(
        &self,
        wallet_id: &AgentWalletId,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<(), String> {
        let slot = {
            let mut pairing = self.pairing.lock().await;
            match pairing.take() {
                Some(slot) if &slot.wallet_id == wallet_id => Some(slot),
                Some(slot) => {
                    *pairing = Some(slot);
                    return Err(
                        "a different Agent Wallet owns the active mobile pairing".to_owned()
                    );
                }
                None => None,
            }
        };
        let result = if let Some(slot) = slot {
            manager
                .lock()
                .await
                .cancel_companion_pairing(wallet_id, slot.attempt)
                .map_err(|error| error.to_string())
        } else {
            Ok(())
        };
        self.stop_pairing_server().await;
        self.resume_suspended_session().await;
        result
    }

    async fn stop_pairing_server(&self) {
        if let Some(server) = self.pairing_server.lock().await.take() {
            let _ = server.shutdown().await;
        }
    }

    /// True while the pairing transport owns, or is about to own, the port.
    ///
    /// Witness-rotation pairings never bind the port, so they deliberately do
    /// not block the session transport.
    async fn pairing_owns_the_port(&self) -> bool {
        let server_running = self
            .pairing_server
            .lock()
            .await
            .as_ref()
            .is_some_and(PairingLanServer::is_running);
        if server_running {
            return true;
        }
        self.pairing
            .lock()
            .await
            .as_ref()
            .is_some_and(|slot| slot.purpose == PairingSlotPurpose::General)
    }

    fn active_gate_is_open(&self, wallet_id: &AgentWalletId) -> bool {
        self.active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|(active_wallet, _)| active_wallet == wallet_id)
            .is_some_and(|(_, gate)| gate.current().validate().is_ok())
    }

    fn clear_active_gate(&self, wallet_id: &AgentWalletId) {
        let mut gate = self
            .active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if gate
            .as_ref()
            .is_some_and(|(active_wallet, _)| active_wallet == wallet_id)
        {
            *gate = None;
        }
    }

    /// Drops a suspended session and closes its gate so it can never resume.
    /// `None` discards whichever wallet is suspended.
    fn discard_suspended_session(&self, wallet_id: Option<&AgentWalletId>) {
        let mut suspended = self
            .suspended
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = match (wallet_id, suspended.as_ref()) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(requested), Some(session)) => &session.wallet_id == requested,
        };
        if matches && let Some(session) = suspended.take() {
            let _ = session.gate.update(CLOSED_GATE);
        }
    }

    /// Frees the private-LAN port so a phone pairing can bind it.
    ///
    /// The caller MUST already hold `self.lifecycle`; this helper never takes
    /// that lock, which is why `start_pairing` can use it where `stop` would
    /// deadlock.
    async fn suspend_session_for_pairing_locked(&self) {
        let Some(slot) = self.slot.lock().await.take() else {
            return;
        };
        let CompanionSlot {
            wallet_id,
            local_addr,
            server,
            gate,
            backend,
        } = slot;
        // The listener is joined (or aborted) before this returns, so the port
        // is free by the time the pairing server binds it.
        let _ = server.shutdown().await;
        self.clear_active_gate(&wallet_id);
        *self
            .suspended
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(SuspendedSession {
            wallet_id,
            bind_addr: local_addr,
            gate,
            backend,
        });
    }

    /// Gives the port back to the session transport once a pairing has ended.
    async fn resume_suspended_session(&self) {
        let _lifecycle = self.lifecycle.lock().await;
        self.resume_suspended_session_locked().await;
    }

    /// Caller MUST already hold `self.lifecycle`.
    async fn resume_suspended_session_locked(&self) {
        if self.pairing_owns_the_port().await {
            return;
        }
        let suspended = self
            .suspended
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(suspended) = suspended else {
            return;
        };
        // Anything that keeps the session from coming back leaves its gate
        // closed, so a stale controller can never authorize a later listener.
        if self.slot.lock().await.is_some() {
            let _ = suspended.gate.update(CLOSED_GATE);
            return;
        }
        let Ok(config) = LanRuntimeConfig::production(suspended.bind_addr) else {
            let _ = suspended.gate.update(CLOSED_GATE);
            return;
        };
        // A closed gate (lock, revoke, emergency stop) makes this fail, which is
        // the wanted fail-closed outcome: the session simply stays stopped.
        let Ok(server) = DesktopLanServer::start(
            config,
            suspended.gate.clone(),
            Arc::clone(&suspended.backend),
        )
        .await
        else {
            let _ = suspended.gate.update(CLOSED_GATE);
            return;
        };
        let local_addr = server.local_addr();
        *self
            .active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((suspended.wallet_id.clone(), suspended.gate.clone()));
        *self.slot.lock().await = Some(CompanionSlot {
            wallet_id: suspended.wallet_id,
            local_addr,
            server,
            gate: suspended.gate,
            backend: suspended.backend,
        });
    }

    pub async fn start(
        &self,
        wallet_id: AgentWalletId,
        bind_addr: SocketAddr,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<CompanionRuntimeStatus, String> {
        let _lifecycle = self.lifecycle.lock().await;
        self.start_session_locked(wallet_id, bind_addr, manager)
            .await
    }

    /// Caller MUST already hold `self.lifecycle`.
    async fn start_session_locked(
        &self,
        wallet_id: AgentWalletId,
        bind_addr: SocketAddr,
        manager: Arc<Mutex<AgentWalletManager>>,
    ) -> Result<CompanionRuntimeStatus, String> {
        let running = {
            let slot = self.slot.lock().await;
            slot.as_ref().map(|slot| {
                (
                    slot.wallet_id.clone(),
                    slot.local_addr,
                    slot.server.is_running(),
                )
            })
        };
        if let Some((active_wallet, local_addr, is_running)) = running {
            // The desktop calls this again right after a pairing completes, and
            // a pairing may already have brought the same session back. Report
            // the live listener instead of an error the owner cannot act on.
            if active_wallet == wallet_id
                && local_addr == bind_addr
                && is_running
                && self.active_gate_is_open(&wallet_id)
            {
                return Ok(CompanionRuntimeStatus {
                    wallet_id,
                    local_addr,
                    phase: "listening",
                });
            }
            return Err("stop the active mobile companion before starting another".to_owned());
        }
        // Never steal the port from a pairing that is already on screen.
        if self.pairing_owns_the_port().await {
            return Err(PAIRING_OWNS_THE_PORT.to_owned());
        }

        let now = unix_now()?;
        let mut manager_guard = manager.lock().await;
        let active_paired_devices = manager_guard
            .list_companion_devices(&wallet_id, now)
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|record| record.role == DeviceRole::Mobile && !record.is_revoked())
            .count();
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        let restricted_rotation_candidate = manager_guard
            .has_restricted_rotation_candidate(&wallet_id, now)
            .map_err(|error| error.to_string())?;
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        let restricted_rotation_candidate = false;
        drop(manager_guard);
        if active_paired_devices == 0 && !restricted_rotation_candidate {
            return Err(
                "pair and authorize a mobile companion before enabling private-LAN access"
                    .to_owned(),
            );
        }

        let config = LanRuntimeConfig::production(bind_addr).map_err(|error| error.to_string())?;
        let open = RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: active_paired_devices
                .max(usize::from(restricted_rotation_candidate)),
        };
        let gate = RuntimeGateController::new(open);
        let backend: Arc<dyn DesktopSessionBackend> = Arc::new(AgentCompanionBackend::new(
            wallet_id.clone(),
            Arc::clone(&manager),
        ));
        let server = DesktopLanServer::start(config, gate.clone(), Arc::clone(&backend))
            .await
            .map_err(|error| error.to_string())?;
        let local_addr = server.local_addr();
        *self
            .active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((wallet_id.clone(), gate.clone()));
        *self.slot.lock().await = Some(CompanionSlot {
            wallet_id: wallet_id.clone(),
            local_addr,
            server,
            gate,
            backend,
        });
        Ok(CompanionRuntimeStatus {
            wallet_id,
            local_addr,
            phase: "listening",
        })
    }

    pub async fn status(&self) -> Option<CompanionRuntimeStatus> {
        let slot = self.slot.lock().await;
        let slot = slot.as_ref()?;
        let gate_open = self.active_gate_is_open(&slot.wallet_id);
        let phase = if !slot.server.is_running() {
            "failed"
        } else if !gate_open {
            "stopping"
        } else {
            "listening"
        };
        Some(CompanionRuntimeStatus {
            wallet_id: slot.wallet_id.clone(),
            local_addr: slot.local_addr,
            phase,
        })
    }

    pub fn request_shutdown(&self, wallet_id: &AgentWalletId) -> Result<(), String> {
        let gate = self
            .active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|(active_wallet, _)| active_wallet == wallet_id)
            .map(|(_, gate)| gate.clone());
        if let Some(gate) = gate {
            let _ = gate.update(CLOSED_GATE);
        }
        // A session suspended for phone pairing must never come back after a
        // lock, a device revoke or an emergency stop.
        self.discard_suspended_session(Some(wallet_id));
        Ok(())
    }

    pub async fn stop(&self, wallet_id: &AgentWalletId) -> Result<(), String> {
        let _lifecycle = self.lifecycle.lock().await;
        self.stop_session_locked(wallet_id).await
    }

    /// Caller MUST already hold `self.lifecycle`.
    async fn stop_session_locked(&self, wallet_id: &AgentWalletId) -> Result<(), String> {
        self.request_shutdown(wallet_id)?;
        let slot = {
            let mut guard = self.slot.lock().await;
            if guard
                .as_ref()
                .is_some_and(|slot| &slot.wallet_id != wallet_id)
            {
                return Err("a different Agent Wallet owns the active mobile companion".to_owned());
            }
            guard.take()
        };
        let shutdown_result = if let Some(slot) = slot {
            slot.server
                .shutdown()
                .await
                .map_err(|error| error.to_string())
        } else {
            Ok(())
        };
        self.clear_active_gate(wallet_id);
        shutdown_result
    }

    pub async fn shutdown_for_exit(&self) -> Result<(), String> {
        self.stop_pairing_server().await;
        let _lifecycle = self.lifecycle.lock().await;
        self.discard_suspended_session(None);
        let wallet_id = self
            .slot
            .lock()
            .await
            .as_ref()
            .map(|slot| slot.wallet_id.clone());
        match wallet_id {
            Some(wallet_id) => self.stop_session_locked(&wallet_id).await,
            None => Ok(()),
        }
    }
}

fn pairing_request_matches_offer(request: &PairingRequest, offer: &PairingOffer) -> bool {
    request.protocol_version == offer.protocol_version
        && request.pairing_id == offer.pairing_id
        && request.agent_wallet_id == offer.agent_wallet_id
        && request.desktop_device_id == offer.desktop_device_id
        && request.pairing_nonce == offer.pairing_nonce
        && request.issued_at >= offer.issued_at
        && request.expires_at <= offer.expires_at
        && request.issued_at < request.expires_at
}
fn cached_confirmation_for_exact_request(
    accepted_request: Option<&PairingRequest>,
    confirmation: Option<&PairingConfirmation>,
    request: &PairingRequest,
) -> Result<Option<PairingConfirmation>, ()> {
    match (accepted_request, confirmation) {
        (None, None) => Ok(None),
        (Some(accepted), Some(cached_confirmation)) if accepted == request => {
            Ok(Some(cached_confirmation.clone()))
        }
        _ => Err(()),
    }
}

fn exact_ack_was_already_accepted(
    accepted_ack: Option<&EncryptedCompanionFrame>,
    ack: &EncryptedCompanionFrame,
) -> Result<bool, ()> {
    match accepted_ack {
        None => Ok(false),
        Some(accepted) if accepted == ack => Ok(true),
        Some(_) => Err(()),
    }
}
pub fn suggest_private_lan_endpoint() -> Result<LanEndpoint, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|_| "Private network detection is unavailable".to_owned())?;
    socket
        .connect("192.0.2.1:80")
        .map_err(|_| "Connect this desktop to the same Wi-Fi as the phone".to_owned())?;
    let ip = socket
        .local_addr()
        .map_err(|_| "Private network detection is unavailable".to_owned())?
        .ip();
    LanEndpoint::parse(&format!("hpay-lan://{ip}:{DEFAULT_COMPANION_PORT}"))
        .map_err(|_| "No private desktop Wi-Fi address was detected".to_owned())
}

fn unix_now() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, TcpListener as StdTcpListener, UdpSocket};
    use std::time::Duration;

    use agent_wallet_core::CreateAgentWallet;
    use hpay_companion_protocol::{DeviceId, FRAME_VERSION};

    use super::*;

    const TEST_PASSPHRASE: &str = "companion runtime shared port passphrase";
    const TESTNET_ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
    /// Every await in these tests is bounded: a lock-order regression must fail
    /// the run instead of hanging it.
    const NO_DEADLOCK: Duration = Duration::from_secs(20);

    fn unlocked_manager() -> (
        tempfile::TempDir,
        Arc<Mutex<AgentWalletManager>>,
        AgentWalletId,
    ) {
        // The unlocked session is checked against the wall clock, so the wallet
        // has to be created and unlocked at a real timestamp.
        let now = unix_now().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut manager = AgentWalletManager::open(root.path()).unwrap();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: TEST_PASSPHRASE.to_owned(),
                    network_mode: "testnet".to_owned(),
                    node_url: "http://127.0.0.1:18081".to_owned(),
                    block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
                },
                now,
            )
            .unwrap();
        let wallet_id = created.wallet_id;
        manager.unlock(&wallet_id, TEST_PASSPHRASE, now).unwrap();
        (root, Arc::new(Mutex::new(manager)), wallet_id)
    }

    /// A private-LAN address this host can really bind, plus a free port on it.
    ///
    /// `LanRuntimeConfig::production` rejects loopback on purpose, so tests that
    /// need two servers to contend for one real socket cannot fake it.
    fn bindable_private_lan_addr() -> Option<SocketAddr> {
        let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
        probe.connect("192.0.2.1:80").ok()?;
        let IpAddr::V4(ip) = probe.local_addr().ok()?.ip() else {
            return None;
        };
        if !(ip.is_private() || ip.is_link_local()) {
            return None;
        }
        let listener = StdTcpListener::bind(SocketAddr::from((ip, 0))).ok()?;
        let addr = listener.local_addr().ok()?;
        drop(listener);
        Some(addr)
    }

    /// Installs a live session server the way `start` does, minus the paired
    /// device gate, which would otherwise need a full pairing handshake first.
    async fn install_running_session(
        supervisor: &AgentCompanionSupervisor,
        wallet_id: &AgentWalletId,
        manager: &Arc<Mutex<AgentWalletManager>>,
        bind_addr: SocketAddr,
    ) {
        let gate = RuntimeGateController::new(RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: 1,
        });
        let backend: Arc<dyn DesktopSessionBackend> = Arc::new(AgentCompanionBackend::new(
            wallet_id.clone(),
            Arc::clone(manager),
        ));
        let server = DesktopLanServer::start(
            LanRuntimeConfig::production(bind_addr).unwrap(),
            gate.clone(),
            Arc::clone(&backend),
        )
        .await
        .unwrap();
        let local_addr = server.local_addr();
        *supervisor
            .active_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((wallet_id.clone(), gate.clone()));
        *supervisor.slot.lock().await = Some(CompanionSlot {
            wallet_id: wallet_id.clone(),
            local_addr,
            server,
            gate,
            backend,
        });
    }

    #[tokio::test]
    async fn a_phone_pairing_takes_the_shared_port_from_a_running_session_server() {
        let Some(bind_addr) = bindable_private_lan_addr() else {
            eprintln!("skipped: this host has no bindable private-LAN address");
            return;
        };
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        install_running_session(&supervisor, &wallet_id, &manager, bind_addr).await;
        assert_eq!(supervisor.status().await.unwrap().phase, "listening");
        assert!(
            StdTcpListener::bind(bind_addr).is_err(),
            "the session server must be holding the shared port"
        );

        // The owner presses "Pair your phone" with the connector already up.
        // Nothing else was pressed first, and this has to just work.
        let endpoint = LanEndpoint::parse(&format!("hpay-lan://{bind_addr}")).unwrap();
        let offer = tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start_pairing(wallet_id.clone(), endpoint, Arc::clone(&manager)),
        )
        .await
        .expect("start_pairing deadlocked")
        .expect("pairing must bind the port the session server was holding");
        assert_eq!(offer.agent_wallet_id, wallet_id.to_string());
        assert!(
            supervisor.status().await.is_none(),
            "the session server must have released the port"
        );
        assert!(
            supervisor
                .pairing_server
                .lock()
                .await
                .as_ref()
                .is_some_and(PairingLanServer::is_running)
        );
        assert!(StdTcpListener::bind(bind_addr).is_err());

        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.cancel_pairing(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("cancel_pairing deadlocked")
        .unwrap();

        let restored = supervisor
            .status()
            .await
            .expect("the session server must come back after pairing ends");
        assert_eq!(restored.wallet_id, wallet_id);
        assert_eq!(restored.local_addr, bind_addr);
        assert_eq!(restored.phase, "listening");
        assert!(StdTcpListener::bind(bind_addr).is_err());

        // What the desktop does right after pairing: this must not error now
        // that the session is already back.
        let restarted = tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start(wallet_id.clone(), bind_addr, Arc::clone(&manager)),
        )
        .await
        .expect("start deadlocked")
        .expect("restarting an already running session must be a no-op");
        assert_eq!(restarted.phase, "listening");

        supervisor.shutdown_for_exit().await.unwrap();
        assert!(supervisor.status().await.is_none());
        assert!(StdTcpListener::bind(bind_addr).is_ok());
    }

    /// The port handover added for the 42492 conflict shuts a live session
    /// server down between `start_companion_pairing` (which captures the
    /// emergency generation into the attempt) and the owner pressing "Yes, the
    /// codes match". If that shutdown reached `request_stop`, every completion
    /// would fail the `safety.generation() != attempt.emergency_generation`
    /// check in `validate_pairing_attempt`. It does not, and this pins that.
    #[tokio::test]
    async fn the_shared_port_handover_never_advances_the_emergency_generation() {
        let Some(bind_addr) = bindable_private_lan_addr() else {
            eprintln!("skipped: this host has no bindable private-LAN address");
            return;
        };
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        install_running_session(&supervisor, &wallet_id, &manager, bind_addr).await;
        let before = manager
            .lock()
            .await
            .emergency_controller(&wallet_id)
            .unwrap()
            .status(false);

        let endpoint = LanEndpoint::parse(&format!("hpay-lan://{bind_addr}")).unwrap();
        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start_pairing(wallet_id.clone(), endpoint, Arc::clone(&manager)),
        )
        .await
        .expect("start_pairing deadlocked")
        .expect("pairing must bind the port the session server was holding");

        let after_handover = manager
            .lock()
            .await
            .emergency_controller(&wallet_id)
            .unwrap()
            .status(false);
        assert_eq!(
            before, after_handover,
            "freeing the shared port must not move the emergency interlock"
        );

        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.cancel_pairing(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("cancel_pairing deadlocked")
        .unwrap();
        let after_resume = manager
            .lock()
            .await
            .emergency_controller(&wallet_id)
            .unwrap()
            .status(false);
        assert_eq!(
            before, after_resume,
            "giving the shared port back must not move the emergency interlock"
        );
        supervisor.shutdown_for_exit().await.unwrap();
    }

    /// The retry budget the desktop polls. It was already bounded and already
    /// spent silently; this is what lets the wizard say "Attempt 2 of 5"
    /// instead of turning the sixth press into a pairing that stopped
    /// answering.
    #[tokio::test]
    async fn the_pairing_status_reports_the_bounded_retry_budget() {
        let (_root, manager, wallet_id) = unlocked_manager();
        let attempt = manager
            .lock()
            .await
            .start_companion_pairing(&wallet_id, Vec::new(), unix_now().unwrap(), 300)
            .unwrap();
        let budget = attempt.attempt_budget();
        let progress = PairingProgress {
            offer: attempt.offer().clone(),
            confirmation: None,
            ack_received: false,
            attempts_used: budget.used(),
            attempts_remaining: budget.remaining(),
            max_attempts: budget.max(),
        };
        assert_eq!(progress.attempts_used, 0);
        assert_eq!(progress.attempts_remaining, 5);
        assert_eq!(progress.max_attempts, 5);

        // The desktop reads this as camelCase JSON, and it must carry counters
        // only: no pairing secret ever travels on this status.
        let json = serde_json::to_value(&progress).unwrap();
        assert_eq!(json["attemptsUsed"], 0);
        assert_eq!(json["attemptsRemaining"], 5);
        assert_eq!(json["maxAttempts"], 5);
        manager
            .lock()
            .await
            .cancel_companion_pairing(&wallet_id, attempt)
            .unwrap();
    }

    /// The same counters, but through the live status the panel actually calls.
    #[tokio::test]
    async fn a_live_pairing_status_carries_the_retry_budget_to_the_desktop() {
        let Some(bind_addr) = bindable_private_lan_addr() else {
            eprintln!("skipped: this host has no bindable private-LAN address");
            return;
        };
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        let endpoint = LanEndpoint::parse(&format!("hpay-lan://{bind_addr}")).unwrap();
        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start_pairing(wallet_id.clone(), endpoint, Arc::clone(&manager)),
        )
        .await
        .expect("start_pairing deadlocked")
        .unwrap();

        let progress = tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.pairing_status(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("pairing_status deadlocked")
        .unwrap()
        .expect("a live pairing must report a status");
        assert_eq!(progress.max_attempts, 5);
        assert_eq!(progress.attempts_used, 0);
        assert_eq!(progress.attempts_remaining, 5);

        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.cancel_pairing(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("cancel_pairing deadlocked")
        .unwrap();
        supervisor.shutdown_for_exit().await.unwrap();
    }

    #[tokio::test]
    async fn a_session_start_never_steals_the_port_from_a_pairing_in_flight() {
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        let attempt = manager
            .lock()
            .await
            .start_companion_pairing(&wallet_id, Vec::new(), unix_now().unwrap(), 300)
            .unwrap();
        *supervisor.pairing.lock().await = Some(PairingSlot {
            wallet_id: wallet_id.clone(),
            attempt,
            purpose: PairingSlotPurpose::General,
            confirmation: None,
            accepted_request: None,
            accepted_ack: None,
        });

        let error = tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start(
                wallet_id.clone(),
                "192.168.77.77:42492".parse().unwrap(),
                Arc::clone(&manager),
            ),
        )
        .await
        .expect("start deadlocked")
        .unwrap_err();
        assert_eq!(
            error,
            "finish or cancel phone pairing before starting the phone connection"
        );
        assert!(supervisor.status().await.is_none());
        assert!(
            supervisor.pairing.lock().await.is_some(),
            "the pairing on screen must survive the refused session start"
        );
    }

    #[tokio::test]
    async fn starting_a_pairing_never_deadlocks_on_the_lifecycle_lock() {
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        // `start_pairing` holds `lifecycle` while it frees the shared port, so
        // reaching for `stop` (or any other public entry point) from in there
        // would hang the whole wallet. Every await below is bounded.
        let endpoint = LanEndpoint::parse("hpay-lan://10.255.255.254:42492").unwrap();
        let started = tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start_pairing(wallet_id.clone(), endpoint, Arc::clone(&manager)),
        )
        .await
        .expect("start_pairing deadlocked while freeing the shared port");

        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.cancel_pairing(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("cancel_pairing deadlocked")
        .unwrap();
        tokio::time::timeout(NO_DEADLOCK, supervisor.stop(&wallet_id))
            .await
            .expect("stop deadlocked after a pairing start")
            .unwrap();
        assert!(supervisor.pairing.lock().await.is_none());
        drop(started);
        supervisor.shutdown_for_exit().await.unwrap();
    }

    #[tokio::test]
    async fn an_emergency_stop_keeps_a_suspended_session_from_coming_back() {
        let Some(bind_addr) = bindable_private_lan_addr() else {
            eprintln!("skipped: this host has no bindable private-LAN address");
            return;
        };
        let (_root, manager, wallet_id) = unlocked_manager();
        let supervisor = AgentCompanionSupervisor::default();
        install_running_session(&supervisor, &wallet_id, &manager, bind_addr).await;
        let endpoint = LanEndpoint::parse(&format!("hpay-lan://{bind_addr}")).unwrap();
        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.start_pairing(wallet_id.clone(), endpoint, Arc::clone(&manager)),
        )
        .await
        .expect("start_pairing deadlocked")
        .unwrap();

        // Same order as `agent_wallet_emergency_stop`: close the gates first.
        supervisor.request_shutdown(&wallet_id).unwrap();
        tokio::time::timeout(
            NO_DEADLOCK,
            supervisor.cancel_pairing(&wallet_id, Arc::clone(&manager)),
        )
        .await
        .expect("cancel_pairing deadlocked")
        .unwrap();

        assert!(
            supervisor.status().await.is_none(),
            "an emergency stop must not be undone by a suspended session"
        );
        assert!(StdTcpListener::bind(bind_addr).is_ok());
    }

    fn offer() -> PairingOffer {
        PairingOffer {
            protocol_version: 1,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            desktop_ephemeral_public_key: "11".repeat(32),
            desktop_identity_public_key: format!("04{}", "22".repeat(64)),
            desktop_identity_fingerprint: "33".repeat(32),
            lan_endpoints: Vec::new(),
            pairing_nonce: "44".repeat(32),
            issued_at: 100,
            expires_at: 200,
        }
    }

    fn request() -> PairingRequest {
        PairingRequest {
            protocol_version: 1,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
            mobile_ephemeral_public_key: "55".repeat(32),
            mobile_identity_public_key: format!("04{}", "66".repeat(64)),
            mobile_identity_fingerprint: "77".repeat(32),
            pairing_nonce: "44".repeat(32),
            mobile_challenge: "88".repeat(32),
            issued_at: 101,
            expires_at: 200,
            identity_signature: "99".repeat(64),
        }
    }

    fn confirmation() -> PairingConfirmation {
        PairingConfirmation {
            protocol_version: 1,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
            desktop_challenge: "aa".repeat(32),
            verification_code: "123456".to_owned(),
            session_id: "session_one".to_owned(),
            issued_at: 102,
            expires_at: 200,
            desktop_identity_signature: "bb".repeat(64),
        }
    }

    fn ack() -> EncryptedCompanionFrame {
        EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "session_one".to_owned(),
            sender_device_id: DeviceId::parse("mobile_one").unwrap(),
            recipient_device_id: DeviceId::parse("desktop_one").unwrap(),
            sequence: 1,
            issued_at: 103,
            expires_at: 200,
            nonce_hex: "cc".repeat(12),
            ciphertext_hex: "dd".repeat(32),
        }
    }

    #[test]
    fn exact_duplicates_are_idempotent_but_different_payloads_fail() {
        let request = request();
        let cached_confirmation = confirmation();
        assert_eq!(
            cached_confirmation_for_exact_request(None, None, &request).unwrap(),
            None
        );
        assert_eq!(
            cached_confirmation_for_exact_request(
                Some(&request),
                Some(&cached_confirmation),
                &request,
            )
            .unwrap(),
            Some(cached_confirmation)
        );
        let mut changed_request = request.clone();
        changed_request.identity_signature = "ee".repeat(64);
        assert!(
            cached_confirmation_for_exact_request(
                Some(&request),
                Some(&confirmation()),
                &changed_request,
            )
            .is_err()
        );

        let ack = ack();
        assert!(!exact_ack_was_already_accepted(None, &ack).unwrap());
        assert!(exact_ack_was_already_accepted(Some(&ack), &ack).unwrap());
        let mut changed_ack = ack.clone();
        changed_ack.ciphertext_hex = "ff".repeat(32);
        assert!(exact_ack_was_already_accepted(Some(&ack), &changed_ack).is_err());
    }

    #[test]
    fn blind_requests_do_not_match_the_active_public_transcript() {
        let offer = offer();
        let request = request();
        assert!(pairing_request_matches_offer(&request, &offer));

        let mut wrong_nonce = request.clone();
        wrong_nonce.pairing_nonce = "00".repeat(32);
        assert!(!pairing_request_matches_offer(&wrong_nonce, &offer));

        let mut wrong_wallet = request;
        wrong_wallet.agent_wallet_id = "wallet_other".to_owned();
        assert!(!pairing_request_matches_offer(&wrong_wallet, &offer));
    }
}
