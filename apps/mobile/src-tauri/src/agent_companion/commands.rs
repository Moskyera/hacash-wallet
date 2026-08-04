#[cfg(target_os = "android")]
use hpay_companion_protocol::CompanionPayload;
use hpay_companion_protocol::{
    ActivitySummary, AgentPolicySummary, AgentSummary, ApprovalCommitment, CompanionMessage,
    CompanionStatus, DeviceId, EncryptedCompanionFrame, PairingConfirmation, PairingOffer,
    PairingRequest, SignedRotationCandidateAcceptance, SignedRotationPairingTicket,
    WitnessRotationPhase,
};
use serde::{Deserialize, Serialize};
use tauri::Webview;

use super::AgentCompanionMobileState;

const AGENT_COMPANION_WEBVIEW: &str = "agent-companion";
const RESET_CONFIRMATION: &str = "RESET COMPANION";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingStartView {
    pub request: PairingRequest,
    pub confirmation: Option<PairingConfirmation>,
    pub automatic_transport: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingAckDeliveryView {
    pub delivered: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCompletionView {
    pub(super) encrypted_ack: EncryptedCompanionFrame,
    pub(super) agent_wallet_id: String,
    pub(super) desktop_device_id: DeviceId,
    pub(super) mobile_device_id: DeviceId,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationCandidatePairingCompletionView {
    encrypted_ack: EncryptedCompanionFrame,
    agent_wallet_id: String,
    desktop_device_id: DeviceId,
    mobile_device_id: DeviceId,
    signed_acceptance: SignedRotationCandidateAcceptance,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionSessionView {
    connected: bool,
    session_id: String,
    local_device_id: DeviceId,
    remote_device_id: DeviceId,
    established_at_unix: String,
    expires_at_unix: String,
}

impl CompanionSessionView {
    #[cfg(target_os = "android")]
    pub(super) fn from_connection(
        connection: &hpay_companion_protocol::CompanionConnection,
        connected: bool,
    ) -> Self {
        Self {
            connected,
            session_id: connection.session_id.clone(),
            local_device_id: connection.local_device_id.clone(),
            remote_device_id: connection.remote_device_id.clone(),
            established_at_unix: connection.established_at.to_string(),
            expires_at_unix: connection.expires_at.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionStoredStateView {
    configured: bool,
    connected: bool,
    agent_wallet_id: Option<String>,
    desktop_device_id: Option<DeviceId>,
    mobile_device_id: Option<DeviceId>,
    endpoints: Vec<String>,
    response_sequence: Option<String>,
    pending_pairing_finalization: bool,
    pilot_enabled: bool,
    controlled_rotation_required: bool,
    rotation_phase: Option<WitnessRotationPhase>,
    hardware_identity_retained_on_reset: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionMessageEnvelopeView {
    message_id: String,
    session_id: String,
    sender_device_id: DeviceId,
    recipient_device_id: DeviceId,
    sequence: String,
    issued_at_unix: String,
    expires_at_unix: String,
}

impl From<&CompanionMessage> for CompanionMessageEnvelopeView {
    fn from(message: &CompanionMessage) -> Self {
        Self {
            message_id: message.message_id.clone(),
            session_id: message.session_id.clone(),
            sender_device_id: message.sender_device_id.clone(),
            recipient_device_id: message.recipient_device_id.clone(),
            sequence: message.sequence.to_string(),
            issued_at_unix: message.issued_at.to_string(),
            expires_at_unix: message.expires_at.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionStatusSnapshotView {
    envelope: CompanionMessageEnvelopeView,
    status: CompanionStatus,
    agents: Vec<AgentSummary>,
    policies: Vec<AgentPolicySummary>,
    approvals: Vec<ApprovalCommitment>,
    activity: Vec<ActivitySummary>,
}

impl CompanionStatusSnapshotView {
    #[cfg(target_os = "android")]
    fn from_message(message: CompanionMessage) -> Result<Self, String> {
        let envelope = CompanionMessageEnvelopeView::from(&message);
        let CompanionPayload::StatusSnapshot {
            status,
            agents,
            policies,
            approvals,
            activity,
        } = message.payload
        else {
            return Err("Desktop returned an unexpected sync response".to_owned());
        };
        Ok(Self {
            envelope,
            status,
            agents,
            policies,
            approvals,
            activity,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionPongView {
    envelope: CompanionMessageEnvelopeView,
    pong: bool,
}

impl CompanionPongView {
    #[cfg(target_os = "android")]
    fn from_message(message: CompanionMessage) -> Result<Self, String> {
        if !matches!(message.payload, CompanionPayload::Pong) {
            return Err("Desktop returned an unexpected ping response".to_owned());
        }
        Ok(Self {
            envelope: CompanionMessageEnvelopeView::from(&message),
            pong: true,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionPairingCancelView {
    pairing_cancelled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionDisconnectView {
    disconnected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionLifecycleEvent {
    ForegroundHeartbeat,
    WebviewClosing,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionLifecycleRequest {
    event: CompanionLifecycleEvent,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionLifecycleView {
    session_allowed_in_background: bool,
    native_disconnect_enforced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionIdentityResetChoice {
    RetainHardwareIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionResetRequest {
    confirmation: String,
    identity: CompanionIdentityResetChoice,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionResetView {
    reset: bool,
    disconnected: bool,
    pairing_cancelled: bool,
    hardware_identity_retained: bool,
    requires_new_pairing: bool,
}

pub(crate) fn require_agent_companion_webview(webview: &Webview) -> Result<(), String> {
    let url = webview.url().map_err(|error| error.to_string())?;
    require_agent_companion_origin(webview.label(), url.scheme(), url.host_str(), url.port())
}

fn require_agent_companion_origin(
    label: &str,
    scheme: &str,
    host: Option<&str>,
    port: Option<u16>,
) -> Result<(), String> {
    if label != AGENT_COMPANION_WEBVIEW {
        return Err("command is restricted to the Agent companion UI".to_owned());
    }
    let bundled = scheme == "tauri"
        || (matches!(scheme, "http" | "https") && host == Some("tauri.localhost"));
    let dev = cfg!(debug_assertions)
        && scheme == "http"
        && matches!(host, Some("127.0.0.1" | "localhost"))
        && port == Some(1421);
    if !bundled && !dev {
        return Err("Agent companion UI is not on a trusted local origin".to_owned());
    }
    Ok(())
}

impl AgentCompanionMobileState {
    async fn status_view(&self) -> Result<CompanionStoredStateView, String> {
        let state = self.shared.current().await?;
        #[cfg(target_os = "android")]
        let connected = self.active.lock().await.is_some();
        #[cfg(not(target_os = "android"))]
        let connected = false;
        Ok(CompanionStoredStateView {
            configured: state.is_some(),
            connected,
            agent_wallet_id: state.as_ref().map(|value| value.agent_wallet_id.clone()),
            desktop_device_id: state.as_ref().map(|value| value.desktop_device_id.clone()),
            mobile_device_id: state.as_ref().map(|value| value.mobile_device_id.clone()),
            endpoints: state
                .as_ref()
                .map(|value| value.endpoints.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            response_sequence: state
                .as_ref()
                .map(|value| value.response_sequence.to_string()),
            pending_pairing_finalization: state
                .as_ref()
                .is_some_and(|value| value.pending_pairing_ack.is_some()),
            pilot_enabled: cfg!(feature = "agent-wallet-testnet-pilot"),
            controlled_rotation_required: state
                .as_ref()
                .is_some_and(|value| value.requires_controlled_rotation()),
            rotation_phase: state.as_ref().map(|value| value.rotation_phase),
            hardware_identity_retained_on_reset: true,
        })
    }

    async fn cancel_pending_pairing(&self) -> Result<CompanionPairingCancelView, String> {
        self.signal_lifecycle_cancel();
        let _lifecycle = self.lifecycle.lock().await;
        if self.shared.current().await?.is_some() {
            return Err("Pairing is already configured; use explicit companion reset".to_owned());
        }
        #[cfg(target_os = "android")]
        drop(self.pending.lock().await.take());
        Ok(CompanionPairingCancelView {
            pairing_cancelled: true,
        })
    }

    async fn reset_companion(
        &self,
        request: CompanionResetRequest,
    ) -> Result<CompanionResetView, String> {
        if request.confirmation != RESET_CONFIRMATION
            || request.identity != CompanionIdentityResetChoice::RetainHardwareIdentity
        {
            return Err(
                "Explicit RESET COMPANION confirmation with retained hardware identity is required"
                    .to_owned(),
            );
        }
        let _lifecycle = self.lifecycle.lock().await;
        self.shared.reset_before_witness_rotation().await?;
        self.signal_lifecycle_cancel();
        #[cfg(target_os = "android")]
        {
            // Dropping the owned outbound socket is local and immediate. Reset must
            // never wait for, or trust, the remote desktop.
            *self.lease_deadline.lock().await = None;
            drop(self.active.lock().await.take());
            drop(self.pending.lock().await.take());
        }
        Ok(CompanionResetView {
            reset: true,
            disconnected: true,
            pairing_cancelled: true,
            hardware_identity_retained: true,
            requires_new_pairing: true,
        })
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_start(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    offer: PairingOffer,
) -> Result<PairingStartView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        let request = state.start_pairing(&app, offer).await?;
        let confirmation = match state.deliver_pairing_request(&request).await {
            Ok(confirmation) => Some(confirmation),
            Err(error) => {
                tracing::warn!("automatic mobile pairing request delivery failed: {error}");
                None
            }
        };
        Ok(PairingStartView {
            request,
            confirmation,
            automatic_transport: true,
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, offer);
        Err("Mobile companion pairing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_retry_request(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<PairingConfirmation, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        state.retry_pairing_request().await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = state;
        Err("Mobile companion pairing is available only on Android".to_owned())
    }
}
#[tauri::command]
pub async fn agent_wallet_rotation_candidate_pairing_start(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    offer: PairingOffer,
) -> Result<PairingStartView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        Ok(PairingStartView {
            request: state.start_rotation_candidate_pairing(&app, offer).await?,
            confirmation: None,
            automatic_transport: false,
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, offer);
        Err("Rotation candidate pairing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_confirm(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    confirmation: PairingConfirmation,
    human_code: String,
) -> Result<PairingCompletionView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        state.confirm_pairing(&app, confirmation, human_code).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, confirmation, human_code);
        Err("Mobile companion pairing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_deliver_ack(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<PairingAckDeliveryView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        state.deliver_pending_pairing_ack().await?;
        Ok(PairingAckDeliveryView { delivered: true })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = state;
        Err("Mobile companion pairing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_rotation_candidate_pairing_confirm(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    confirmation: PairingConfirmation,
    ticket: SignedRotationPairingTicket,
    human_code: String,
) -> Result<RotationCandidatePairingCompletionView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        let (completion, signed_acceptance) = state
            .confirm_rotation_candidate_pairing(&app, confirmation, ticket, human_code)
            .await?;
        Ok(RotationCandidatePairingCompletionView {
            encrypted_ack: completion.encrypted_ack,
            agent_wallet_id: completion.agent_wallet_id,
            desktop_device_id: completion.desktop_device_id,
            mobile_device_id: completion.mobile_device_id,
            signed_acceptance,
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, confirmation, ticket, human_code);
        Err("Rotation candidate pairing is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_pairing_cancel(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionPairingCancelView, String> {
    require_agent_companion_webview(&webview)?;
    state.cancel_pending_pairing().await
}

#[tauri::command]
pub async fn agent_wallet_companion_state(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionStoredStateView, String> {
    require_agent_companion_webview(&webview)?;
    state.expire_session_lease().await;
    state.status_view().await
}

#[tauri::command]
pub async fn agent_wallet_companion_connect(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionSessionView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        state.connect(app).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state);
        Err("Mobile companion LAN sessions are available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_sync(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionStatusSnapshotView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        let message = state
            .exchange_with_reconnect(app, super::session::OutboundKind::Sync)
            .await?;
        CompanionStatusSnapshotView::from_message(message)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state);
        Err("Mobile companion LAN sessions are available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_ping(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionPongView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        let message = state
            .exchange_with_reconnect(app, super::session::OutboundKind::Ping)
            .await?;
        CompanionPongView::from_message(message)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state);
        Err("Mobile companion LAN sessions are available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_disconnect(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionDisconnectView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    state.disconnect().await?;
    #[cfg(not(target_os = "android"))]
    let _ = state;
    Ok(CompanionDisconnectView { disconnected: true })
}

#[tauri::command]
pub async fn agent_wallet_companion_lifecycle(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionLifecycleRequest,
) -> Result<CompanionLifecycleView, String> {
    require_agent_companion_webview(&webview)?;
    match request.event {
        CompanionLifecycleEvent::ForegroundHeartbeat => {
            #[cfg(target_os = "android")]
            state.renew_session_lease().await;
        }
        CompanionLifecycleEvent::WebviewClosing => {
            state.close_native_session().await;
        }
    }
    Ok(CompanionLifecycleView {
        session_allowed_in_background: false,
        native_disconnect_enforced: true,
    })
}

#[tauri::command]
pub async fn agent_wallet_companion_reset(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionResetRequest,
) -> Result<CompanionResetView, String> {
    require_agent_companion_webview(&webview)?;
    state.reset_companion(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_must_be_isolated_local_agent_companion_webview() {
        assert!(require_agent_companion_origin("agent-companion", "tauri", None, None).is_ok());
        assert!(require_agent_companion_origin("main", "tauri", None, None).is_err());
        assert!(
            require_agent_companion_origin(
                "agent-companion",
                "https",
                Some("evil.example"),
                Some(443)
            )
            .is_err()
        );
        if cfg!(debug_assertions) {
            assert!(
                require_agent_companion_origin(
                    "agent-companion",
                    "http",
                    Some("127.0.0.1"),
                    Some(1421)
                )
                .is_ok()
            );
            assert!(
                require_agent_companion_origin(
                    "agent-companion",
                    "http",
                    Some("127.0.0.1"),
                    Some(3000)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn reset_requires_exact_confirmation_and_retains_identity_choice() {
        let valid: CompanionResetRequest = serde_json::from_value(serde_json::json!({
            "confirmation": "RESET COMPANION",
            "identity": "retain_hardware_identity"
        }))
        .unwrap();
        assert_eq!(valid.confirmation, RESET_CONFIRMATION);
        assert_eq!(
            valid.identity,
            CompanionIdentityResetChoice::RetainHardwareIdentity
        );
        assert!(
            serde_json::from_value::<CompanionResetRequest>(serde_json::json!({
                "confirmation": "yes",
                "identity": "delete_hardware_identity"
            }))
            .is_err()
        );
    }
}
