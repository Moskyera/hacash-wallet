use std::net::SocketAddr;
use std::time::Duration;

use hpay_companion_lan_runtime::MobilePairingTransport;
use hpay_companion_protocol::{
    DeviceRegistry, LanEndpoint, MobilePairingAttempt, PairingConfirmation, PairingOffer,
    PairingRequest, ReplayGuard, RotationCandidateAcceptance, SignedRotationCandidateAcceptance,
    SignedRotationPairingTicket,
};
use tauri::AppHandle;

use crate::agent_companion_identity;

use super::commands::PairingCompletionView;
use super::storage::MobileCompanionDurableState;
use super::{AgentCompanionMobileState, STATE_VERSION, unix_now};

const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) struct PendingPairing {
    attempt: MobilePairingAttempt,
    endpoints: Vec<LanEndpoint>,
    rotation_candidate: bool,
}

impl AgentCompanionMobileState {
    pub(super) async fn start_pairing(
        &self,
        app: &AppHandle,
        offer: PairingOffer,
    ) -> Result<PairingRequest, String> {
        self.start_pairing_with_purpose(app, offer, false).await
    }

    pub(super) async fn start_rotation_candidate_pairing(
        &self,
        app: &AppHandle,
        offer: PairingOffer,
    ) -> Result<PairingRequest, String> {
        self.start_pairing_with_purpose(app, offer, true).await
    }

    async fn start_pairing_with_purpose(
        &self,
        app: &AppHandle,
        offer: PairingOffer,
        rotation_candidate: bool,
    ) -> Result<PairingRequest, String> {
        self.run_biometric_guarded(
            PAIRING_TIMEOUT,
            "Mobile pairing signature timed out",
            async {
                if offer.lan_endpoints.is_empty() {
                    return Err("Pairing offer has no private-LAN endpoint".to_owned());
                }
                if self.shared.current().await?.is_some() {
                    return Err(
                        "This phone is already paired; explicit reset is required".to_owned()
                    );
                }
                if self.pending.lock().await.is_some() {
                    return Err("A mobile pairing attempt is already active".to_owned());
                }
                let signer = agent_companion_identity::open(app).await?.ok_or_else(|| {
                    "Create the hardware companion identity before pairing".to_owned()
                })?;
                let endpoints = offer.lan_endpoints.clone();
                tracing::info!("mobile companion pairing stage: signing pairing request");
                let attempt = MobilePairingAttempt::start(offer, &signer, unix_now()?)
                    .await
                    .map_err(|error| {
                        tracing::warn!("mobile companion pairing request signing failed: {error}");
                        format!(
                            "Android hardware signing failed while creating the mobile pairing request: {error}"
                        )
                    })?;
                let request = attempt.request().clone();
                *self.pending.lock().await = Some(PendingPairing {
                    attempt,
                    endpoints,
                    rotation_candidate,
                });
                Ok(request)
            },
        )
        .await
    }

    #[cfg(target_os = "android")]
    pub(super) async fn deliver_pairing_request(
        &self,
        request: &PairingRequest,
    ) -> Result<PairingConfirmation, String> {
        let endpoints = self
            .pending
            .lock()
            .await
            .as_ref()
            .map(|pending| pending.endpoints.clone())
            .filter(|endpoints| !endpoints.is_empty())
            .ok_or_else(|| "The desktop private-LAN pairing address is unavailable".to_owned())?;
        let mut last_error = "The desktop could not be reached".to_owned();
        for endpoint in endpoints {
            match MobilePairingTransport::submit_request(
                SocketAddr::new(endpoint.ip(), endpoint.port()),
                request,
            )
            .await
            {
                Ok(confirmation) => return Ok(confirmation),
                Err(error) => last_error = error.to_string(),
            }
        }
        Err(format!(
            "The phone could not reach HPAY desktop on the same Wi-Fi: {last_error}"
        ))
    }

    #[cfg(target_os = "android")]
    pub(super) async fn retry_pairing_request(&self) -> Result<PairingConfirmation, String> {
        let request = self
            .pending
            .lock()
            .await
            .as_ref()
            .filter(|pending| !pending.rotation_candidate)
            .map(|pending| pending.attempt.request().clone())
            .ok_or_else(|| "No normal phone pairing request is waiting".to_owned())?;
        self.deliver_pairing_request(&request).await
    }
    #[cfg(target_os = "android")]
    pub(super) async fn deliver_pending_pairing_ack(&self) -> Result<(), String> {
        let state = self
            .shared
            .current()
            .await?
            .ok_or_else(|| "The phone pairing state is unavailable".to_owned())?;
        let ack = state
            .pending_pairing_ack
            .as_ref()
            .ok_or_else(|| "No pairing confirmation is waiting to be sent".to_owned())?;
        let mut last_error = "The desktop could not be reached".to_owned();
        for endpoint in &state.endpoints {
            match MobilePairingTransport::submit_ack(
                SocketAddr::new(endpoint.ip(), endpoint.port()),
                ack,
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error.to_string(),
            }
        }
        Err(format!(
            "The phone could not return confirmation to HPAY desktop: {last_error}"
        ))
    }
    pub(super) async fn confirm_pairing(
        &self,
        app: &AppHandle,
        confirmation: PairingConfirmation,
        human_code: String,
    ) -> Result<PairingCompletionView, String> {
        self.run_biometric_guarded(
            PAIRING_TIMEOUT,
            "Mobile pairing confirmation timed out",
            async {
                let pending = self
                    .pending
                    .lock()
                    .await
                    .take()
                    .ok_or_else(|| "No mobile pairing attempt is active".to_owned())?;
                if pending.rotation_candidate {
                    return Err("Use the restricted rotation confirmation flow".to_owned());
                }
                let signer = agent_companion_identity::open(app)
                    .await?
                    .ok_or_else(|| "Hardware companion identity is unavailable".to_owned())?;
                tracing::info!("mobile companion pairing stage: signing mobile proof");
                let (encrypted_ack, result) = pending
                    .attempt
                    .confirm(&confirmation, &human_code, &signer, unix_now()?)
                    .await
                    .map_err(|error| {
                        tracing::warn!("mobile companion confirmation rejected: {error}");
                        format!("Read-only pairing confirmation was rejected: {error}")
                    })?;

                let mut registry = DeviceRegistry::new();
                registry
                    .register(result.desktop_device_record.clone())
                    .map_err(|error| error.to_string())?;
                registry
                    .register(result.mobile_device_record.clone())
                    .map_err(|error| error.to_string())?;
                let state = MobileCompanionDurableState {
                    state_version: STATE_VERSION,
                    agent_wallet_id: result.agent_wallet_id.clone(),
                    desktop_device_id: result.desktop_device_id.clone(),
                    mobile_device_id: result.mobile_device_id.clone(),
                    endpoints: pending.endpoints,
                    registry,
                    replay: ReplayGuard::new()
                        .snapshot(unix_now()?)
                        .map_err(|error| error.to_string())?,
                    response_sequence: 0,
                    approval_sequence: 0,
                    pending_pairing_ack: Some(encrypted_ack.clone()),
                    pending_approval: None,
                    pending_witness: None,
                    discarded_consents: Vec::new(),
                    discarded_consents_dropped: 0,
                    witness: None,
                    rotation_phase: hpay_companion_protocol::WitnessRotationPhase::Stable,
                    pending_rotation_authorization: None,
                    pending_rotation_baseline: None,
                    rotation_ticket: None,
                    rotation_candidate_acceptance: None,
                };
                // Durable state publication is inside the lifecycle guard. A
                // concurrent reset first cancels this operation, then clears state.
                self.shared.install_new(state).await?;
                let view = PairingCompletionView {
                    encrypted_ack,
                    agent_wallet_id: result.agent_wallet_id.clone(),
                    desktop_device_id: result.desktop_device_id.clone(),
                    mobile_device_id: result.mobile_device_id.clone(),
                };
                drop(result);
                Ok(view)
            },
        )
        .await
    }

    pub(super) async fn confirm_rotation_candidate_pairing(
        &self,
        app: &AppHandle,
        confirmation: PairingConfirmation,
        ticket: SignedRotationPairingTicket,
        human_code: String,
    ) -> Result<(PairingCompletionView, SignedRotationCandidateAcceptance), String> {
        self.run_biometric_guarded(
            PAIRING_TIMEOUT,
            "Rotation candidate confirmation timed out",
            async {
                let pending = self
                    .pending
                    .lock()
                    .await
                    .take()
                    .ok_or_else(|| "No rotation candidate pairing is active".to_owned())?;
                if !pending.rotation_candidate {
                    return Err("Active pairing is not a rotation candidate flow".to_owned());
                }
                let signer = agent_companion_identity::open(app)
                    .await?
                    .ok_or_else(|| "Hardware companion identity is unavailable".to_owned())?;
                tracing::info!("mobile companion pairing stage: signing mobile proof");
                let (encrypted_ack, result) = pending
                    .attempt
                    .confirm(&confirmation, &human_code, &signer, unix_now()?)
                    .await
                    .map_err(|error| {
                        tracing::warn!("mobile companion confirmation rejected: {error}");
                        format!("Read-only pairing confirmation was rejected: {error}")
                    })?;
                let now = unix_now()?;
                let ticket_hash = ticket
                    .verify(&result.desktop_device_record, now)
                    .map_err(|error| error.to_string())?;
                if ticket.ticket.pairing_id != confirmation.pairing_id
                    || ticket.ticket.agent_wallet_id != result.agent_wallet_id
                    || ticket.ticket.desktop_device_id != result.desktop_device_id
                    || ticket.ticket.expected_candidate_device_id != result.mobile_device_id
                    || ticket.ticket.expected_candidate_identity_fingerprint
                        != result.mobile_device_record.identity_fingerprint
                    || ticket_hash
                        != ticket
                            .ticket
                            .canonical_sha256_hex()
                            .map_err(|error| error.to_string())?
                {
                    return Err("Rotation ticket does not match the pairing transcript".to_owned());
                }
                let acceptance = RotationCandidateAcceptance::for_ticket(&ticket.ticket, now)
                    .map_err(|error| error.to_string())?;
                let signed_acceptance =
                    SignedRotationCandidateAcceptance::sign(acceptance, &signer)
                        .await
                        .map_err(|error| error.to_string())?;

                let mut registry = DeviceRegistry::new();
                registry
                    .register(result.desktop_device_record.clone())
                    .map_err(|error| error.to_string())?;
                registry
                    .register(result.mobile_device_record.clone())
                    .map_err(|error| error.to_string())?;
                signed_acceptance
                    .verify(&ticket, &result.mobile_device_record, now)
                    .map_err(|error| error.to_string())?;
                let state = MobileCompanionDurableState {
                    state_version: STATE_VERSION,
                    agent_wallet_id: result.agent_wallet_id.clone(),
                    desktop_device_id: result.desktop_device_id.clone(),
                    mobile_device_id: result.mobile_device_id.clone(),
                    endpoints: pending.endpoints,
                    registry,
                    replay: ReplayGuard::new()
                        .snapshot(now)
                        .map_err(|error| error.to_string())?,
                    response_sequence: 0,
                    approval_sequence: 0,
                    pending_pairing_ack: None,
                    pending_approval: None,
                    pending_witness: None,
                    discarded_consents: Vec::new(),
                    discarded_consents_dropped: 0,
                    witness: None,
                    rotation_phase:
                        hpay_companion_protocol::WitnessRotationPhase::CandidatePairedRestricted,
                    pending_rotation_authorization: None,
                    pending_rotation_baseline: None,
                    rotation_ticket: Some(ticket),
                    rotation_candidate_acceptance: Some(signed_acceptance.clone()),
                };
                self.shared.install_new(state).await?;
                let view = PairingCompletionView {
                    encrypted_ack,
                    agent_wallet_id: result.agent_wallet_id.clone(),
                    desktop_device_id: result.desktop_device_id.clone(),
                    mobile_device_id: result.mobile_device_id.clone(),
                };
                drop(result);
                Ok((view, signed_acceptance))
            },
        )
        .await
    }
}
