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
/// The separate words for the reset that runs while witness state exists.
///
/// It is a different sentence from `RESET COMPANION` on purpose: the two resets
/// are not interchangeable, and one of them is only ever correct on a handset
/// whose companion key is already gone.
const ORPHANED_RESET_CONFIRMATION: &str = "RETIRE THIS PAIRING";
/// The words for discarding a consent record this phone is still holding.
///
/// A third, separate sentence. It is not a reset and not a retire: it deletes
/// no pairing and no witness memory, it ends only this phone's intent to sign
/// one exact payment, and it must never be reachable by the wording of either
/// of the other two.
#[cfg(any(target_os = "android", test))]
const DISCARD_CONSENT_CONFIRMATION: &str = "DISCARD THIS CONFIRMATION";

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

/// How the Android identity this phone holds right now relates to the pairing
/// stored on it.
///
/// Only `Replaced` and `Absent` mean the durable witness state is unenforceable
/// and may be retired. Everything else - including any failure to read the
/// Keystore - is `Unknown`, which offers nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
// Off Android there is no Keystore to read, so only `NotPaired` and `Unknown`
// are ever produced. The other three are the Android answers.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub enum PairingIdentityState {
    /// No pairing is stored, so the question does not arise.
    NotPaired,
    /// The live companion key is exactly the one this pairing is bound to.
    Matches,
    /// A live companion key exists, but it is a different device id.
    Replaced,
    /// This phone has no usable companion key at all: deleted, or invalidated in
    /// hardware by a new biometric enrolment.
    Absent,
    /// The Keystore could not be read. Nothing is concluded from a failure.
    Unknown,
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
    /// What `reset_before_witness_rotation` would refuse with right now.
    ///
    /// `controlled_rotation_required` only reads `rotation_phase`, but the
    /// storage layer refuses on the wider `rotation_blocking_phase()`, which
    /// also covers a pending pilot approval and any witness record. The phone
    /// could not see those two facts, so it offered a reset that could only
    /// refuse - and the refusal durably replaced the reset section for good.
    reset_blocking_phase: Option<WitnessRotationPhase>,
    /// Whether this phone still holds the key its stored pairing is bound to.
    pairing_identity: PairingIdentityState,
    hardware_identity_retained_on_reset: bool,
    /// The one payment this phone is still holding a consent record for.
    ///
    /// Until this existed the record was invisible: it blocked the reset,
    /// blocked pairing and blocked every other payment, and the only screen
    /// that could reach it was the witness card - which disappears the moment
    /// the desktop stops offering the operation. The owner has to be able to
    /// read what they are holding before they can be asked to discard it.
    pending_consent: Option<CompanionPendingConsentView>,
    /// Every consent record this phone stopped holding, newest first.
    ///
    /// This was one record, so a second discard erased the first one's receipt
    /// before the owner could ever read it. It is now the bounded history the
    /// phone actually keeps, in the order the screen shows it.
    discarded_consents: Vec<CompanionDiscardedConsentView>,
    /// How many older receipts the cap has pushed out of that history.
    ///
    /// Reported as a decimal string, like every other count that crosses this
    /// boundary, and shown to the owner rather than swallowed: a receipt that
    /// silently disappears is the defect this history exists to fix.
    discarded_consents_dropped: String,
}

/// A consent record this phone is holding right now.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionPendingConsentView {
    kind: String,
    operation_id: String,
    amount_units: String,
    recipient: String,
    recorded_at_unix: String,
}

/// A consent record this phone stopped holding.
///
/// This is a receipt, not a witness. It proves nothing about whether the
/// payment was signed, broadcast or committed, and it is never consulted when
/// a rollback anchor is admitted.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionDiscardedConsentView {
    kind: String,
    operation_id: String,
    amount_units: String,
    recipient: String,
    recorded_at_unix: String,
    discarded_at_unix: String,
    reason: String,
}

impl From<&super::storage::MobileDiscardedConsent> for CompanionDiscardedConsentView {
    fn from(record: &super::storage::MobileDiscardedConsent) -> Self {
        Self {
            kind: record.kind.clone(),
            operation_id: record.operation_id.clone(),
            amount_units: record.amount_units.clone(),
            recipient: record.recipient.clone(),
            recorded_at_unix: record.confirmed_at.clone(),
            discarded_at_unix: record.discarded_at.clone(),
            reason: record.reason.clone(),
        }
    }
}

fn pending_consent_view(
    state: &super::storage::MobileCompanionDurableState,
) -> Option<CompanionPendingConsentView> {
    if let Some(pending) = &state.pending_witness {
        return Some(CompanionPendingConsentView {
            kind: super::storage::DISCARDED_WITNESS_CONFIRMATION.to_owned(),
            operation_id: pending.operation_id.clone(),
            amount_units: pending.amount_units.clone(),
            recipient: pending.recipient.clone(),
            recorded_at_unix: pending.confirmed_at.clone(),
        });
    }
    state
        .pending_approval
        .as_ref()
        .map(|pending| CompanionPendingConsentView {
            kind: super::storage::DISCARDED_PILOT_APPROVAL.to_owned(),
            operation_id: pending.decision.operation_id.clone(),
            amount_units: pending.decision.amount_units.to_string(),
            recipient: pending.decision.recipient.clone(),
            recorded_at_unix: pending.decision.issued_at.to_string(),
        })
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
    /// The ordinary pairing-only reset. Keeps the Android identity, and is
    /// refused once a pilot approval or witness record exists.
    RetainHardwareIdentity,
    /// Retire a pairing whose Android identity this phone no longer holds.
    ///
    /// Only ever accepted when the live Keystore identity is missing or is a
    /// different device id; see `reset_orphaned_pairing`.
    ReplacedHardwareIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionResetRequest {
    confirmation: String,
    identity: CompanionIdentityResetChoice,
}

/// The owner's explicit discard of one consent record.
///
/// The operation id has to be the one this phone is actually holding, so the
/// screen has to have shown the payment before the press rather than after it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionDiscardConsentRequest {
    confirmation: String,
    operation_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionDiscardConsentView {
    discarded: CompanionDiscardedConsentView,
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

/// The operation ids a status snapshot lists as awaiting this phone's rollback
/// witness.
///
/// Derived from `WITNESS_PENDING_ACTIVITY_STATUSES`, the same set the desktop
/// discloses under and the same set the witness card offers from, so the sweep
/// can never retire a record for an operation the phone is still being offered.
#[cfg(any(target_os = "android", test))]
fn witness_pending_operation_ids(activity: &[ActivitySummary]) -> Vec<String> {
    activity
        .iter()
        .filter(|item| {
            hpay_companion_protocol::WITNESS_PENDING_ACTIVITY_STATUSES
                .contains(&item.status.as_str())
        })
        .map(|item| item.activity_id.clone())
        .collect()
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
    /// The live companion device id, or `None` when this phone has no usable
    /// companion key.
    ///
    /// A Keystore read that fails is an error, never `None`: "no identity" and
    /// "could not look" must not collapse into the same answer, because the
    /// first one unlocks a reset and the second one must not.
    #[cfg(target_os = "android")]
    async fn live_companion_device_id(
        &self,
        app: &tauri::AppHandle,
    ) -> Result<Option<DeviceId>, String> {
        use hpay_companion_protocol::PlatformDeviceSigner;

        Ok(crate::agent_companion_identity::open(app)
            .await?
            .map(|signer| signer.identity().device_id().clone()))
    }

    async fn pairing_identity_state(
        &self,
        app: &tauri::AppHandle,
        state: Option<&super::storage::MobileCompanionDurableState>,
    ) -> PairingIdentityState {
        let Some(state) = state else {
            return PairingIdentityState::NotPaired;
        };
        #[cfg(target_os = "android")]
        {
            match self.live_companion_device_id(app).await {
                Ok(Some(device_id)) if device_id == state.mobile_device_id => {
                    PairingIdentityState::Matches
                }
                Ok(Some(_)) => PairingIdentityState::Replaced,
                Ok(None) => PairingIdentityState::Absent,
                Err(_) => PairingIdentityState::Unknown,
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (app, state);
            PairingIdentityState::Unknown
        }
    }

    async fn status_view(
        &self,
        app: &tauri::AppHandle,
    ) -> Result<CompanionStoredStateView, String> {
        // Age alone can retire a consent record, and this is the one call the
        // screen makes unconditionally, so a phone that can never reach its
        // desktop again still gets out on its own. No desktop statement is
        // available here, so nothing else can be concluded. A failed sweep is
        // never allowed to take the status read down with it.
        #[cfg(any(target_os = "android", test))]
        if let Err(error) = self.sweep_obsolete_consent(None).await {
            tracing::warn!("agent companion consent sweep failed: {error}");
        }
        let state = self.shared.current().await?;
        let pairing_identity = self.pairing_identity_state(app, state.as_ref()).await;
        #[cfg(target_os = "android")]
        let connected = self.active.lock().await.is_some();
        #[cfg(not(target_os = "android"))]
        let connected = false;
        Ok(CompanionStoredStateView {
            reset_blocking_phase: state
                .as_ref()
                .and_then(|value| value.rotation_blocking_phase()),
            pairing_identity,
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
            pending_consent: state.as_ref().and_then(pending_consent_view),
            // Newest first: the storage layer appends, and the receipt the
            // owner most likely came looking for is the last one written.
            discarded_consents: state
                .as_ref()
                .map(|value| {
                    value
                        .discarded_consents
                        .iter()
                        .rev()
                        .map(CompanionDiscardedConsentView::from)
                        .collect()
                })
                .unwrap_or_default(),
            discarded_consents_dropped: state
                .as_ref()
                .map(|value| value.discarded_consents_dropped.to_string())
                .unwrap_or_else(|| "0".to_owned()),
        })
    }

    /// Ends this phone's intent to sign one exact payment the owner named.
    ///
    /// It discards a consent record and nothing else. No pairing is deleted, no
    /// witness memory is touched, nothing is un-signed and no payment is
    /// cancelled on the desktop - and because
    /// `require_authorized_witness_binding` refuses any anchor with no matching
    /// record, discarding can only ever make witnessing harder, never easier.
    #[cfg(any(target_os = "android", test))]
    async fn discard_consent(
        &self,
        request: CompanionDiscardConsentRequest,
    ) -> Result<CompanionDiscardConsentView, String> {
        if request.confirmation != DISCARD_CONSENT_CONFIRMATION {
            return Err(
                "Explicit DISCARD THIS CONFIRMATION wording is required to discard a payment confirmation"
                    .to_owned(),
            );
        }
        let _flow = self.consent_flow.lock().await;
        let discarded = self
            .shared
            .discard_consent_by_owner(&request.operation_id, super::unix_now()?)
            .await?;
        Ok(CompanionDiscardConsentView {
            discarded: CompanionDiscardedConsentView::from(&discarded),
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
        app: &tauri::AppHandle,
        request: CompanionResetRequest,
    ) -> Result<CompanionResetView, String> {
        let _lifecycle = self.lifecycle.lock().await;
        match request.identity {
            CompanionIdentityResetChoice::RetainHardwareIdentity => {
                if request.confirmation != RESET_CONFIRMATION {
                    return Err(
                        "Explicit RESET COMPANION confirmation with retained hardware identity is required"
                            .to_owned(),
                    );
                }
                self.shared.reset_before_witness_rotation().await?;
            }
            CompanionIdentityResetChoice::ReplacedHardwareIdentity => {
                if request.confirmation != ORPHANED_RESET_CONFIRMATION {
                    return Err(
                        "Explicit RETIRE THIS PAIRING confirmation is required to retire a pairing whose secure identity is gone"
                            .to_owned(),
                    );
                }
                // The Keystore is read here, not trusted from the UI, and a
                // failed read is an error rather than a licence to erase.
                #[cfg(target_os = "android")]
                {
                    let live = self.live_companion_device_id(app).await?;
                    self.shared.reset_orphaned_pairing(live.as_ref()).await?;
                }
                #[cfg(not(target_os = "android"))]
                {
                    let _ = app;
                    return Err(
                        "Retiring a companion pairing is available only on Android".to_owned(),
                    );
                }
            }
        }
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
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
) -> Result<CompanionStoredStateView, String> {
    require_agent_companion_webview(&webview)?;
    state.expire_session_lease().await;
    state.status_view(&app).await
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
        let view = CompanionStatusSnapshotView::from_message(message)?;
        // The snapshot is the desktop's own authenticated statement of which
        // operations are waiting on this phone's rollback witness. A consent
        // record naming anything else is one the desktop will not accept a
        // receipt for, so it is retired here rather than left to block the
        // phone for ever. Only a snapshot that actually arrived is used: a
        // transport failure returns above and states nothing.
        let awaiting = witness_pending_operation_ids(&view.activity);
        if let Err(error) = state.sweep_obsolete_consent(Some(&awaiting)).await {
            tracing::warn!("agent companion consent sweep failed: {error}");
        }
        Ok(view)
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

/// Discards one consent record this phone is holding, by exact operation id.
///
/// The last exit, and the only one that cannot be derived from desktop state:
/// a phone whose desktop is revoked, unreachable or gone can be told by nobody
/// that the payment is over. It is deliberately the owner's own act, behind its
/// own wording, and it ends only the phone's local intent to sign. It advances
/// no witness, completes no payment and cancels nothing on the desktop.
#[tauri::command]
pub async fn agent_wallet_companion_discard_consent(
    webview: Webview,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionDiscardConsentRequest,
) -> Result<CompanionDiscardConsentView, String> {
    require_agent_companion_webview(&webview)?;
    #[cfg(target_os = "android")]
    {
        state.discard_consent(request).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let CompanionDiscardConsentRequest {
            confirmation,
            operation_id,
        } = request;
        let _ = (state, confirmation, operation_id);
        Err("Discarding a payment confirmation is available only on Android".to_owned())
    }
}

#[tauri::command]
pub async fn agent_wallet_companion_reset(
    webview: Webview,
    app: tauri::AppHandle,
    state: tauri::State<'_, AgentCompanionMobileState>,
    request: CompanionResetRequest,
) -> Result<CompanionResetView, String> {
    require_agent_companion_webview(&webview)?;
    state.reset_companion(&app, request).await
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

    /// The escape out of dead end 4 is a separate request with separate words.
    ///
    /// The two resets must never be reachable by the same typed sentence: one
    /// is the ordinary pairing-only reset, the other only ever applies to a
    /// handset whose companion key is already gone.
    #[test]
    fn retiring_an_orphaned_pairing_is_a_distinct_choice_with_distinct_words() {
        let retire: CompanionResetRequest = serde_json::from_value(serde_json::json!({
            "confirmation": "RETIRE THIS PAIRING",
            "identity": "replaced_hardware_identity"
        }))
        .unwrap();
        assert_eq!(retire.confirmation, ORPHANED_RESET_CONFIRMATION);
        assert_eq!(
            retire.identity,
            CompanionIdentityResetChoice::ReplacedHardwareIdentity
        );
        assert_ne!(ORPHANED_RESET_CONFIRMATION, RESET_CONFIRMATION);
    }

    /// Discarding a payment confirmation is a third choice with third words.
    ///
    /// It is neither of the two resets: it deletes no pairing and no witness
    /// memory. The wording must not overlap either of theirs, and the request
    /// must name the exact operation, so the screen has to have shown the
    /// payment before the press rather than after it.
    #[tokio::test]
    async fn discarding_a_confirmation_is_a_distinct_typed_act_naming_one_payment() {
        let discard: CompanionDiscardConsentRequest = serde_json::from_value(serde_json::json!({
            "confirmation": "DISCARD THIS CONFIRMATION",
            "operationId": "operation_one"
        }))
        .unwrap();
        assert_eq!(discard.confirmation, DISCARD_CONSENT_CONFIRMATION);
        assert_eq!(discard.operation_id, "operation_one");
        assert_ne!(DISCARD_CONSENT_CONFIRMATION, RESET_CONFIRMATION);
        assert_ne!(DISCARD_CONSENT_CONFIRMATION, ORPHANED_RESET_CONFIRMATION);
        // No operation id, no discard: this can never be a "clear whatever is
        // there" button.
        assert!(
            serde_json::from_value::<CompanionDiscardConsentRequest>(serde_json::json!({
                "confirmation": "DISCARD THIS CONFIRMATION"
            }))
            .is_err()
        );

        let root = std::env::temp_dir().join(format!(
            "hpay-companion-discard-words-test-{}",
            std::process::id()
        ));
        let state = AgentCompanionMobileState::open(&root);
        let refused = state
            .discard_consent(CompanionDiscardConsentRequest {
                confirmation: "RESET COMPANION".to_owned(),
                operation_id: "operation_one".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(refused.contains("DISCARD THIS CONFIRMATION"));
        // The exact wording gets past the gate and is then judged on the state
        // itself, which here holds nothing.
        let empty = state
            .discard_consent(CompanionDiscardConsentRequest {
                confirmation: DISCARD_CONSENT_CONFIRMATION.to_owned(),
                operation_id: "operation_one".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(empty.contains("not paired"));
        let _ = std::fs::remove_dir(root.join("agent-companion"));
        let _ = std::fs::remove_dir(root);
    }

    /// The sweep is driven by the same status set the witness card is offered
    /// from, so it can never retire a record for an operation the phone is
    /// still being told to witness.
    #[test]
    fn the_sweep_reads_exactly_the_statuses_the_witness_card_is_offered_from() {
        let activity = |activity_id: &str, status: &str| ActivitySummary {
            activity_id: activity_id.to_owned(),
            description: "Awaiting your rollback witness".to_owned(),
            asset: "HAC".to_owned(),
            recipient: "1NewDeveloper".to_owned(),
            amount_units: 50_000_000,
            occurred_at: 1,
            status: status.to_owned(),
        };
        for status in hpay_companion_protocol::WITNESS_PENDING_ACTIVITY_STATUSES {
            assert_eq!(
                witness_pending_operation_ids(&[activity("operation_one", status)]),
                vec!["operation_one".to_owned()],
                "{status} is still awaiting this phone"
            );
        }
        for status in ["committed", "cancelled", "rejected", "reconciliation_required"] {
            assert!(
                witness_pending_operation_ids(&[activity("operation_one", status)]).is_empty(),
                "{status} is not awaiting this phone"
            );
        }
        assert!(witness_pending_operation_ids(&[]).is_empty());
    }

    /// A read that failed, or a platform with no Keystore, must never look like
    /// "this phone has no identity".
    #[test]
    fn unknown_identity_is_serialized_distinctly_from_an_absent_one() {
        let names = [
            (PairingIdentityState::NotPaired, "not_paired"),
            (PairingIdentityState::Matches, "matches"),
            (PairingIdentityState::Replaced, "replaced"),
            (PairingIdentityState::Absent, "absent"),
            (PairingIdentityState::Unknown, "unknown"),
        ];
        for (value, expected) in names {
            assert_eq!(serde_json::to_value(value).unwrap(), expected);
        }
    }
}
