use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hpay_companion_protocol::{
    DeviceId, DevicePublicRecord, DeviceRegistry, DeviceRole, EncryptedCompanionFrame,
    FRAME_VERSION, LanEndpoint, MobileApprovalDecision, MobileWitnessState, ReplayGuard,
    ReplayGuardSnapshot, ReplayHighWaterMark, ReplayNonceRecord, SignedRotationCandidateAcceptance,
    SignedRotationPairingTicket, SignedWitnessRotationAuthorization,
    SignedWitnessRotationBaselineReceipt, WitnessReconciliationStatus, WitnessRotationPhase,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{MAX_STATE_BYTES, STATE_VERSION, unix_now};

const RESET_MARKER: &[u8] = br#"{"stateVersion":"reset"}"#;

pub(super) trait CompanionStateStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String>;
}

#[derive(Debug)]
pub(super) struct FileCompanionStateStore {
    path: PathBuf,
}

impl FileCompanionStateStore {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn reject_symlink(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err("Agent companion state must not be a symlink".to_owned())
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Agent companion state metadata: {error}")),
        }
    }
}

impl CompanionStateStore for FileCompanionStateStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        Self::reject_symlink(&self.path)?;
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read Agent companion state: {error}")),
        };
        if bytes == RESET_MARKER {
            let _ = fs::remove_file(&self.path);
            return Ok(None);
        }
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err("Agent companion state has an invalid size".to_owned());
        }
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String> {
        Self::reject_symlink(&self.path)?;
        match bytes {
            Some(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
                    return Err("Agent companion state has an invalid size".to_owned());
                }
                hacash_wallet_core::paths::secure_write(&self.path, bytes)
                    .map_err(|error| format!("persist Agent companion state: {error}"))
            }
            None => {
                // Atomic logical deletion: first replace the scoped public state with a
                // non-sensitive reset marker. Physical removal is best effort; a crash or
                // removal failure still leaves no wallet/device/replay/endpoint material.
                hacash_wallet_core::paths::secure_write(&self.path, RESET_MARKER)
                    .map_err(|error| format!("reset Agent companion state: {error}"))?;
                let _ = fs::remove_file(&self.path);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MobilePendingApproval {
    pub(super) state_version: String,
    pub(super) commitment_hash: String,
    pub(super) decision: MobileApprovalDecision,
}

impl MobilePendingApproval {
    pub(super) fn validate(&self) -> Result<(), String> {
        let binding = self
            .decision
            .network_binding
            .as_ref()
            .ok_or_else(|| "Pending pilot approval has no network binding".to_owned())?;
        self.decision
            .canonical_bytes()
            .map_err(|error| error.to_string())?;
        if self.state_version != "1"
            || self.decision.decision_version != 3
            || self.commitment_hash.len() != 64
            || !self
                .commitment_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || binding.network_id != "testnet"
            || binding.chain_id == 0
            || binding.transaction_format_version != 2
        {
            return Err("Pending pilot approval binding is invalid".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MobileCompanionDurableState {
    pub(super) state_version: u64,
    pub(super) agent_wallet_id: String,
    pub(super) desktop_device_id: DeviceId,
    pub(super) mobile_device_id: DeviceId,
    pub(super) endpoints: Vec<LanEndpoint>,
    pub(super) registry: DeviceRegistry,
    pub(super) replay: ReplayGuardSnapshot,
    pub(super) response_sequence: u64,
    pub(super) approval_sequence: u64,
    pub(super) pending_pairing_ack: Option<EncryptedCompanionFrame>,
    pub(super) pending_approval: Option<MobilePendingApproval>,
    pub(super) witness: Option<MobileWitnessState>,
    pub(super) rotation_phase: WitnessRotationPhase,
    pub(super) pending_rotation_authorization: Option<SignedWitnessRotationAuthorization>,
    pub(super) pending_rotation_baseline: Option<SignedWitnessRotationBaselineReceipt>,
    pub(super) rotation_ticket: Option<SignedRotationPairingTicket>,
    pub(super) rotation_candidate_acceptance: Option<SignedRotationCandidateAcceptance>,
}

impl MobileCompanionDurableState {
    pub(super) fn validate_at(&self, now: u64) -> Result<(), String> {
        if self.state_version != STATE_VERSION
            || self.agent_wallet_id.is_empty()
            || self.endpoints.is_empty()
        {
            return Err("Agent companion state scope is invalid".to_owned());
        }
        let unique = self
            .endpoints
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        if unique.len() != self.endpoints.len() {
            return Err("Agent companion state contains duplicate endpoints".to_owned());
        }
        self.registry
            .validate()
            .map_err(|error| error.to_string())?;
        validate_record(
            &self.registry,
            &self.desktop_device_id,
            &self.agent_wallet_id,
            DeviceRole::Desktop,
        )?;
        validate_record(
            &self.registry,
            &self.mobile_device_id,
            &self.agent_wallet_id,
            DeviceRole::Mobile,
        )?;
        ReplayGuard::from_snapshot(self.replay.clone(), now).map_err(|error| error.to_string())?;
        if let Some(ack) = &self.pending_pairing_ack {
            if ack.frame_version != FRAME_VERSION
                || ack.session_id.is_empty()
                || ack.sender_device_id != self.mobile_device_id
                || ack.recipient_device_id != self.desktop_device_id
                || ack.sequence != 1
                || ack.expires_at <= ack.issued_at
                || ack.nonce_hex.len() != 24
                || !ack.nonce_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                || ack.ciphertext_hex.len() < 32
                || !ack.ciphertext_hex.len().is_multiple_of(2)
                || !ack
                    .ciphertext_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("Pending mobile pairing acknowledgement is invalid".to_owned());
            }
        }
        if let Some(pending) = &self.pending_approval {
            pending.validate()?;
            if pending.decision.agent_wallet_id != self.agent_wallet_id
                || pending.decision.desktop_device_id != self.desktop_device_id
                || pending.decision.mobile_device_id != self.mobile_device_id
                || pending.decision.approval_sequence != self.approval_sequence
            {
                return Err(
                    "Pending pilot approval scope does not match companion state".to_owned(),
                );
            }
        }
        if let Some(witness) = &self.witness {
            witness.validate().map_err(|error| error.to_string())?;
            if witness.agent_wallet_id != self.agent_wallet_id
                || witness.desktop_device_id != self.desktop_device_id
                || witness.mobile_device_id != self.mobile_device_id
            {
                return Err("Mobile witness scope does not match companion state".to_owned());
            }
        }
        if self.pending_rotation_authorization.is_some() && self.pending_rotation_baseline.is_some()
        {
            return Err("Mobile rotation cannot hold two signing roles".to_owned());
        }
        if let Some(signed) = &self.pending_rotation_authorization {
            signed
                .rotation
                .canonical_bytes()
                .map_err(|error| error.to_string())?;
            if signed.rotation.agent_wallet_id != self.agent_wallet_id
                || signed.rotation.desktop_device_id != self.desktop_device_id
                || signed.rotation.old_mobile_device_id != self.mobile_device_id
                || !is_signature(&signed.signature_hex)
            {
                return Err("Pending rotation authorization scope is invalid".to_owned());
            }
        }
        if let Some(signed) = &self.pending_rotation_baseline {
            signed
                .receipt
                .canonical_bytes()
                .map_err(|error| error.to_string())?;
            if signed.receipt.agent_wallet_id != self.agent_wallet_id
                || signed.receipt.new_mobile_device_id != self.mobile_device_id
                || !is_signature(&signed.signature_hex)
            {
                return Err("Pending rotation baseline scope is invalid".to_owned());
            }
        }
        match (&self.rotation_ticket, &self.rotation_candidate_acceptance) {
            (None, None) => {}
            (Some(ticket), Some(acceptance)) => {
                let desktop = validate_record(
                    &self.registry,
                    &self.desktop_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Desktop,
                )?;
                let candidate = validate_record(
                    &self.registry,
                    &self.mobile_device_id,
                    &self.agent_wallet_id,
                    DeviceRole::Mobile,
                )?;
                ticket
                    .verify(&desktop, acceptance.acceptance.accepted_at)
                    .map_err(|error| error.to_string())?;
                acceptance
                    .verify(ticket, &candidate, acceptance.acceptance.accepted_at)
                    .map_err(|error| error.to_string())?;
                if !matches!(
                    self.rotation_phase,
                    WitnessRotationPhase::CandidatePairedRestricted
                        | WitnessRotationPhase::CandidateBaselineVerified
                        | WitnessRotationPhase::AwaitingOldDeviceRevocation
                        | WitnessRotationPhase::AwaitingCompletionAnchor
                        | WitnessRotationPhase::AwaitingRotationCompletionAnchor
                        | WitnessRotationPhase::Completed
                ) {
                    return Err("Restricted rotation candidate phase is invalid".to_owned());
                }
            }
            _ => return Err("Rotation candidate ticket state is incomplete".to_owned()),
        }
        Ok(())
    }

    pub(super) fn requires_controlled_rotation(&self) -> bool {
        !matches!(
            self.rotation_phase,
            WitnessRotationPhase::Stable | WitnessRotationPhase::Completed
        )
    }

    fn rotation_blocking_phase(&self) -> Option<WitnessRotationPhase> {
        if self.pending_approval.is_some() {
            return Some(WitnessRotationPhase::BlockedByPendingApproval);
        }
        self.witness.as_ref().map(|witness| {
            if witness
                .last_transaction_state
                .as_ref()
                .is_some_and(|transaction| {
                    !matches!(
                        transaction.reconciliation_status,
                        WitnessReconciliationStatus::Confirmed
                            | WitnessReconciliationStatus::Rejected
                    )
                })
            {
                WitnessRotationPhase::BlockedByUnresolvedSignedOperation
            } else {
                WitnessRotationPhase::RotationRequired
            }
        })
    }
}

fn is_signature(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_record(
    registry: &DeviceRegistry,
    device_id: &DeviceId,
    wallet_id: &str,
    role: DeviceRole,
) -> Result<DevicePublicRecord, String> {
    let record = registry
        .records()
        .find(|record| &record.device_id == device_id)
        .ok_or_else(|| "Agent companion state is missing a paired device".to_owned())?;
    record.validate().map_err(|error| error.to_string())?;
    if record.is_revoked() || record.agent_wallet_id != wallet_id || record.role != role {
        return Err("Agent companion device scope does not match durable state".to_owned());
    }
    Ok(record.clone())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableStateDocument {
    state_version: String,
    agent_wallet_id: String,
    desktop_device_id: DeviceId,
    mobile_device_id: DeviceId,
    endpoints: Vec<LanEndpoint>,
    registry: DeviceRegistry,
    replay: DurableReplayDocument,
    response_sequence: String,
    #[serde(default = "decimal_zero")]
    approval_sequence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_pairing_ack: Option<EncryptedCompanionFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_approval: Option<MobilePendingApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness: Option<MobileWitnessState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_phase: Option<WitnessRotationPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rotation_authorization: Option<SignedWitnessRotationAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rotation_baseline: Option<SignedWitnessRotationBaselineReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_ticket: Option<SignedRotationPairingTicket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_candidate_acceptance: Option<SignedRotationCandidateAcceptance>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableReplayDocument {
    snapshot_version: String,
    high_water_marks: Vec<DurableHighWaterMark>,
    used_nonces: Vec<DurableNonceRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableHighWaterMark {
    context: String,
    sender_device_id: DeviceId,
    last_sequence: String,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableNonceRecord {
    context: String,
    sender_device_id: DeviceId,
    nonce: String,
    issued_at: String,
    expires_at: String,
}

impl From<&MobileCompanionDurableState> for DurableStateDocument {
    fn from(state: &MobileCompanionDurableState) -> Self {
        Self {
            state_version: state.state_version.to_string(),
            agent_wallet_id: state.agent_wallet_id.clone(),
            desktop_device_id: state.desktop_device_id.clone(),
            mobile_device_id: state.mobile_device_id.clone(),
            endpoints: state.endpoints.clone(),
            registry: state.registry.clone(),
            replay: DurableReplayDocument {
                snapshot_version: state.replay.snapshot_version.to_string(),
                high_water_marks: state
                    .replay
                    .high_water_marks
                    .iter()
                    .map(|mark| DurableHighWaterMark {
                        context: mark.context.clone(),
                        sender_device_id: mark.sender_device_id.clone(),
                        last_sequence: mark.last_sequence.to_string(),
                        expires_at: mark.expires_at.to_string(),
                    })
                    .collect(),
                used_nonces: state
                    .replay
                    .used_nonces
                    .iter()
                    .map(|record| DurableNonceRecord {
                        context: record.context.clone(),
                        sender_device_id: record.sender_device_id.clone(),
                        nonce: record.nonce.clone(),
                        issued_at: record.issued_at.to_string(),
                        expires_at: record.expires_at.to_string(),
                    })
                    .collect(),
            },
            response_sequence: state.response_sequence.to_string(),
            approval_sequence: state.approval_sequence.to_string(),
            pending_pairing_ack: state.pending_pairing_ack.clone(),
            pending_approval: state.pending_approval.clone(),
            witness: state.witness.clone(),
            rotation_phase: Some(state.rotation_phase),
            pending_rotation_authorization: state.pending_rotation_authorization.clone(),
            pending_rotation_baseline: state.pending_rotation_baseline.clone(),
            rotation_ticket: state.rotation_ticket.clone(),
            rotation_candidate_acceptance: state.rotation_candidate_acceptance.clone(),
        }
    }
}

impl TryFrom<DurableStateDocument> for MobileCompanionDurableState {
    type Error = String;

    fn try_from(document: DurableStateDocument) -> Result<Self, Self::Error> {
        let rotation_phase = document
            .rotation_phase
            .unwrap_or(WitnessRotationPhase::Stable);
        Ok(Self {
            state_version: parse_decimal_u64(&document.state_version)?,
            agent_wallet_id: document.agent_wallet_id,
            desktop_device_id: document.desktop_device_id,
            mobile_device_id: document.mobile_device_id,
            endpoints: document.endpoints,
            registry: document.registry,
            replay: ReplayGuardSnapshot {
                snapshot_version: parse_decimal_u64(&document.replay.snapshot_version)?,
                high_water_marks: document
                    .replay
                    .high_water_marks
                    .into_iter()
                    .map(|mark| {
                        Ok(ReplayHighWaterMark {
                            context: mark.context,
                            sender_device_id: mark.sender_device_id,
                            last_sequence: parse_decimal_u64(&mark.last_sequence)?,
                            expires_at: parse_decimal_u64(&mark.expires_at)?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
                used_nonces: document
                    .replay
                    .used_nonces
                    .into_iter()
                    .map(|record| {
                        Ok(ReplayNonceRecord {
                            context: record.context,
                            sender_device_id: record.sender_device_id,
                            nonce: record.nonce,
                            issued_at: parse_decimal_u64(&record.issued_at)?,
                            expires_at: parse_decimal_u64(&record.expires_at)?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
            },
            response_sequence: parse_decimal_u64(&document.response_sequence)?,
            approval_sequence: parse_decimal_u64(&document.approval_sequence)?,
            pending_pairing_ack: document.pending_pairing_ack,
            pending_approval: document.pending_approval,
            witness: document.witness,
            rotation_phase,
            pending_rotation_authorization: document.pending_rotation_authorization,
            pending_rotation_baseline: document.pending_rotation_baseline,
            rotation_ticket: document.rotation_ticket,
            rotation_candidate_acceptance: document.rotation_candidate_acceptance,
        })
    }
}

fn decimal_zero() -> String {
    "0".to_owned()
}

fn parse_decimal_u64(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("u64 state values must be strict decimal strings".to_owned());
    }
    value
        .parse::<u64>()
        .map_err(|_| "u64 state value is out of range".to_owned())
}

pub(super) fn encode_state(state: &MobileCompanionDurableState) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&DurableStateDocument::from(state)).map_err(|error| error.to_string())
}

fn decode_state(bytes: &[u8], now: u64) -> Result<MobileCompanionDurableState, String> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err("Agent companion state has an invalid size".to_owned());
    }
    let document: DurableStateDocument =
        serde_json::from_slice(bytes).map_err(|error| format!("decode Agent state: {error}"))?;
    let state = MobileCompanionDurableState::try_from(document)?;
    state.validate_at(now)?;
    Ok(state)
}

pub(super) struct SharedCompanionState {
    store: Arc<dyn CompanionStateStore>,
    pub(super) state: Mutex<Option<MobileCompanionDurableState>>,
    initialization_error: RwLock<Option<String>>,
}

impl std::fmt::Debug for SharedCompanionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedCompanionState")
            .field("state", &"<public-pairing-and-replay-state>")
            .field(
                "initialization_error",
                &self.initialization_error.read().map(|value| value.clone()),
            )
            .finish()
    }
}

impl SharedCompanionState {
    pub(super) fn open(store: Arc<dyn CompanionStateStore>) -> Self {
        let loaded = store.load().and_then(|bytes| {
            bytes
                .map(|bytes| decode_state(&bytes, unix_now()?))
                .transpose()
        });
        match loaded {
            Ok(state) => Self {
                store,
                state: Mutex::new(state),
                initialization_error: RwLock::new(None),
            },
            Err(error) => Self {
                store,
                state: Mutex::new(None),
                initialization_error: RwLock::new(Some(error)),
            },
        }
    }

    pub(super) fn require_available(&self) -> Result<(), String> {
        let error = self
            .initialization_error
            .read()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())?;
        if let Some(error) = error.as_ref() {
            return Err(format!(
                "Agent companion is disabled because durable state is invalid: {error}"
            ));
        }
        Ok(())
    }

    pub(super) async fn current(&self) -> Result<Option<MobileCompanionDurableState>, String> {
        self.require_available()?;
        Ok(self.state.lock().await.clone())
    }

    #[cfg(target_os = "android")]
    pub(super) async fn clear_pending_pairing_ack(&self) -> Result<(), String> {
        self.require_available()?;
        let mut slot = self.state.lock().await;
        let Some(current) = slot.as_ref() else {
            return Ok(());
        };
        if current.pending_pairing_ack.is_none() {
            return Ok(());
        }
        let mut next = current.clone();
        next.pending_pairing_ack = None;
        self.persist_locked(&next)?;
        *slot = Some(next);
        Ok(())
    }
    #[cfg(any(target_os = "android", test))]
    pub(super) async fn install_new(
        &self,
        state: MobileCompanionDurableState,
    ) -> Result<(), String> {
        self.require_available()?;
        state.validate_at(unix_now()?)?;
        let bytes = encode_state(&state)?;
        let mut slot = self.state.lock().await;
        if slot.is_some() {
            return Err("This phone is already paired; explicit reset is required".to_owned());
        }
        self.store.replace(Some(&bytes))?;
        *slot = Some(state);
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub(super) fn persist_locked(&self, state: &MobileCompanionDurableState) -> Result<(), String> {
        self.require_available()?;
        state.validate_at(unix_now()?)?;
        self.store.replace(Some(&encode_state(state)?))
    }

    pub(super) async fn reset_before_witness_rotation(&self) -> Result<(), String> {
        let mut slot = self.state.lock().await;
        if let Some(current) = slot.as_ref()
            && let Some(phase) = current.rotation_blocking_phase()
        {
            let mut next = current.clone();
            next.rotation_phase = phase;
            let bytes = encode_state(&next)?;
            self.store.replace(Some(&bytes))?;
            *slot = Some(next);
            return Err(
                "Companion reset is blocked after pilot approval or witness initialization; controlled desktop/mobile witness rotation is required"
                    .to_owned(),
            );
        }
        self.store.replace(None)?;
        *slot = None;
        *self
            .initialization_error
            .write()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())? = None;
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn reset(&self) -> Result<(), String> {
        let mut slot = self.state.lock().await;
        self.store.replace(None)?;
        *slot = None;
        *self
            .initialization_error
            .write()
            .map_err(|_| "Agent companion initialization state is unavailable".to_owned())? = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use hpay_companion_protocol::{
        CompanionError, DevicePermission, ReplayMetadata, SoftwareDeviceIdentity,
    };

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        bytes: StdMutex<Option<Vec<u8>>>,
        fail_replace: AtomicBool,
    }

    impl MemoryStore {
        fn with_bytes(bytes: Vec<u8>) -> Self {
            Self {
                bytes: StdMutex::new(Some(bytes)),
                fail_replace: AtomicBool::new(false),
            }
        }
    }

    impl CompanionStateStore for MemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.bytes.lock().unwrap().clone())
        }

        fn replace(&self, bytes: Option<&[u8]>) -> Result<(), String> {
            if self.fail_replace.load(Ordering::SeqCst) {
                return Err("injected persistence failure".to_owned());
            }
            *self.bytes.lock().unwrap() = bytes.map(ToOwned::to_owned);
            Ok(())
        }
    }

    fn state_fixture(now: u64) -> MobileCompanionDurableState {
        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), now - 1)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                mobile
                    .public_record(
                        "wallet_one",
                        BTreeSet::from([DevicePermission::ViewAgentWalletStatus]),
                        now - 1,
                    )
                    .unwrap(),
            )
            .unwrap();
        MobileCompanionDurableState {
            state_version: STATE_VERSION,
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            mobile_device_id: mobile.device_id().clone(),
            endpoints: vec![LanEndpoint::parse("hpay-lan://192.168.1.8:42492").unwrap()],
            registry,
            replay: ReplayGuard::new().snapshot(now).unwrap(),
            response_sequence: 0,
            approval_sequence: 0,
            pending_pairing_ack: None,
            pending_approval: None,
            witness: None,
            rotation_phase: WitnessRotationPhase::Stable,
            pending_rotation_authorization: None,
            pending_rotation_baseline: None,
            rotation_ticket: None,
            rotation_candidate_acceptance: None,
        }
    }

    #[test]
    fn pending_pairing_ack_roundtrips_and_old_state_defaults_to_none() {
        let now = 1_000;
        let mut state = state_fixture(now);
        let ack = EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "pairing_session_one".to_owned(),
            sender_device_id: state.mobile_device_id.clone(),
            recipient_device_id: state.desktop_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: now + 120,
            nonce_hex: "11".repeat(12),
            ciphertext_hex: "22".repeat(32),
        };
        state.pending_pairing_ack = Some(ack.clone());
        let encoded = encode_state(&state).unwrap();
        let decoded = decode_state(&encoded, now).unwrap();
        assert_eq!(decoded.pending_pairing_ack, Some(ack));

        let mut old_document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        old_document
            .as_object_mut()
            .unwrap()
            .remove("pending_pairing_ack");
        let old_encoded = serde_json::to_vec(&old_document).unwrap();
        assert!(
            decode_state(&old_encoded, now)
                .unwrap()
                .pending_pairing_ack
                .is_none()
        );
    }
    #[test]
    fn durable_json_uses_only_decimal_strings_for_u64_values() {
        let state = state_fixture(1_000);
        let encoded = encode_state(&state).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        fn assert_no_numbers(value: &serde_json::Value) {
            match value {
                serde_json::Value::Number(number) => panic!("numeric JSON leaked: {number}"),
                serde_json::Value::Array(values) => values.iter().for_each(assert_no_numbers),
                serde_json::Value::Object(values) => values.values().for_each(assert_no_numbers),
                _ => {}
            }
        }
        assert_no_numbers(&value);
        let mut numeric = value;
        numeric["response_sequence"] = serde_json::json!(0);
        assert!(decode_state(&serde_json::to_vec(&numeric).unwrap(), 1_000).is_err());
        for invalid in ["", "00", "+1", "-1", "1.0", "18446744073709551616"] {
            assert!(parse_decimal_u64(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn corrupt_state_disables_companion_fail_closed() {
        let store = Arc::new(MemoryStore::with_bytes(
            br#"{"state_version":"1"}"#.to_vec(),
        ));
        let shared = SharedCompanionState::open(store);
        assert!(shared.current().await.unwrap_err().contains("disabled"));
    }

    #[tokio::test]
    async fn reset_recovers_from_corrupt_durable_state() {
        let store = Arc::new(MemoryStore::with_bytes(b"corrupt".to_vec()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        assert!(shared.current().await.unwrap_err().contains("disabled"));
        shared.reset().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert!(store.bytes.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn persistence_failure_never_publishes_pairing_or_reset() {
        let store = Arc::new(MemoryStore::default());
        store.fail_replace.store(true, Ordering::SeqCst);
        let shared = SharedCompanionState::open(store);
        assert!(shared.install_new(state_fixture(1_000)).await.is_err());
        assert!(shared.current().await.unwrap().is_none());

        let store = Arc::new(MemoryStore::default());
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        shared.install_new(state_fixture(1_000)).await.unwrap();
        store.fail_replace.store(true, Ordering::SeqCst);
        assert!(shared.reset().await.is_err());
        assert!(shared.current().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn file_reset_removes_only_companion_state_and_preserves_personal_sentinel() {
        let now = unix_now().unwrap();
        let root = std::env::temp_dir().join(format!(
            "hpay-mobile-companion-reset-{}-{now}",
            std::process::id()
        ));
        let personal = root.join("personal").join("vault.json");
        let companion = root.join("agent-companion").join("state.json");
        hacash_wallet_core::paths::secure_write(&personal, b"personal-sentinel").unwrap();
        let shared =
            SharedCompanionState::open(Arc::new(FileCompanionStateStore::new(companion.clone())));
        shared.install_new(state_fixture(now)).await.unwrap();
        assert!(companion.exists());

        shared.reset().await.unwrap();
        assert!(shared.current().await.unwrap().is_none());
        assert_eq!(fs::read(&personal).unwrap(), b"personal-sentinel");
        if companion.exists() {
            assert_eq!(fs::read(&companion).unwrap(), RESET_MARKER);
        }

        let _ = fs::remove_file(&companion);
        let _ = fs::remove_file(&personal);
        let _ = fs::remove_dir(root.join("agent-companion"));
        let _ = fs::remove_dir(root.join("personal"));
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn persisted_replay_rejects_duplicate_after_restart() {
        let now = 1_000;
        let mut state = state_fixture(now);
        let replay = ReplayMetadata {
            context: "companion-message:session_one".to_owned(),
            sender_device_id: state.desktop_device_id.clone(),
            sequence: 1,
            nonce: "0123456789abcdef01234567".to_owned(),
            issued_at: now,
            expires_at: now + 60,
        };
        let mut guard = ReplayGuard::from_snapshot(state.replay.clone(), now).unwrap();
        let permit = guard.check(&replay, now).unwrap();
        guard.commit(permit, now).unwrap();
        state.replay = guard.snapshot(now).unwrap();
        let restored = decode_state(&encode_state(&state).unwrap(), now).unwrap();
        let restarted = ReplayGuard::from_snapshot(restored.replay, now).unwrap();
        assert_eq!(
            restarted.check(&replay, now),
            Err(CompanionError::SequenceReplay)
        );
    }

    #[test]
    fn durable_state_rejects_cross_wallet_and_cross_device_records() {
        let now = 1_000;
        let state = state_fixture(now);
        let mut wrong_wallet = state.clone();
        wrong_wallet.agent_wallet_id = "wallet_two".to_owned();
        assert!(wrong_wallet.validate_at(now).is_err());

        let mut wrong_devices = state;
        std::mem::swap(
            &mut wrong_devices.desktop_device_id,
            &mut wrong_devices.mobile_device_id,
        );
        assert!(wrong_devices.validate_at(now).is_err());
    }

    #[tokio::test]
    async fn initialized_zero_sequence_witness_blocks_reset_without_mutation() {
        let now = unix_now().unwrap();
        let mut state = state_fixture(now);
        state.witness = Some(
            MobileWitnessState::new(
                state.agent_wallet_id.clone(),
                state.desktop_device_id.clone(),
                state.mobile_device_id.clone(),
                "testnet".to_owned(),
                "11".repeat(32),
                1,
                1,
                1,
            )
            .unwrap(),
        );
        assert_eq!(state.witness.as_ref().unwrap().last_anchor_sequence, 0);
        assert!(!state.requires_controlled_rotation());
        state.validate_at(now).unwrap();

        let encoded = encode_state(&state).unwrap();
        let store = Arc::new(MemoryStore::with_bytes(encoded.clone()));
        let shared = SharedCompanionState::open(Arc::clone(&store) as Arc<dyn CompanionStateStore>);
        let before = shared.current().await.unwrap();

        let error = shared.reset_before_witness_rotation().await.unwrap_err();
        assert!(error.contains("controlled desktop/mobile witness rotation"));
        let after = shared.current().await.unwrap().unwrap();
        assert_eq!(after.rotation_phase, WitnessRotationPhase::RotationRequired);
        assert!(after.requires_controlled_rotation());
        assert_ne!(Some(after), before);
        assert_ne!(
            store.bytes.lock().unwrap().as_deref(),
            Some(encoded.as_slice())
        );
    }
}
