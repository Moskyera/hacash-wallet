use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::admin::{AdminCommand, SignedAdminCommand};
use crate::approval::{ApprovalCommitment, MobileApprovalDecision, SignedApprovalDecision};
use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::DeviceId;
use crate::pairing::MobilePairingProof;
use crate::replay::MAX_CLOCK_SKEW_SECS;
use crate::rotation::{
    SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt, WitnessRotationRecord,
};
use crate::witness::{SignedRollbackAnchor, SignedWitnessReceipt};

pub const PROTOCOL_VERSION: u64 = 3;
const MESSAGE_DOMAIN: &[u8] = b"HPAY/COMPANION/MESSAGE/V3";
const MAX_MESSAGE_LIFETIME_SECS: u64 = 15 * 60;
const MAX_POLICY_RECIPIENTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionStatus {
    pub agent_wallet_id: String,
    pub address: String,
    #[serde(with = "crate::serde_decimal_u64::option")]
    pub available_units: Option<u64>,
    pub node_status: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub reserved_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub spent_today_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub spent_month_units: u64,
    pub paused: bool,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationState {
    Authorized,
    Disabled,
    Revoked,
}

impl AgentAuthorizationState {
    fn tag(self) -> u8 {
        match self {
            Self::Authorized => 1,
            Self::Disabled => 2,
            Self::Revoked => 3,
        }
    }

    fn from_tag(tag: u8) -> CompanionResult<Self> {
        match tag {
            1 => Ok(Self::Authorized),
            2 => Ok(Self::Disabled),
            3 => Ok(Self::Revoked),
            _ => Err(CompanionError::MalformedMessage),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSummary {
    pub agent_id: String,
    pub display_name: String,
    pub authorization: AgentAuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicySummary {
    pub agent_id: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub max_per_payment_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub max_daily_units: u64,
    pub max_pending_operations: u16,
    pub approval_mode: String,
    pub permissions: Vec<String>,
    pub allowed_recipients: Vec<String>,
    pub blocked_recipients: Vec<String>,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivitySummary {
    pub activity_id: String,
    pub description: String,
    pub asset: String,
    pub recipient: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub amount_units: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub occurred_at: u64,
    pub status: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CompanionPayload {
    ApprovalRequest(ApprovalCommitment),
    ApprovalDecision(SignedApprovalDecision),
    StatusSnapshot {
        status: CompanionStatus,
        agents: Vec<AgentSummary>,
        policies: Vec<AgentPolicySummary>,
        approvals: Vec<ApprovalCommitment>,
        activity: Vec<ActivitySummary>,
    },
    AdminCommand(SignedAdminCommand),
    AdminAck {
        command_id: String,
        accepted: bool,
        detail: String,
    },
    SyncRequest {
        #[serde(with = "crate::serde_decimal_u64")]
        since_sequence: u64,
    },
    RecoverPendingWitness {
        operation_id: String,
    },
    WitnessRotationPoll {
        rotation_id: Option<String>,
    },
    WitnessRotationProposal(WitnessRotationRecord),
    WitnessRotationAuthorization(SignedWitnessRotationAuthorization),
    WitnessRotationBaseline(SignedWitnessRotationBaselineReceipt),
    Ping,
    Pong,
    Disconnect {
        reason: String,
    },
    PairingMobileProof(MobilePairingProof),
    RollbackAnchorProposal(SignedRollbackAnchor),
    WitnessReceipt(SignedWitnessReceipt),
    WitnessAck {
        anchor_id: String,
        accepted: bool,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionMessage {
    #[serde(with = "crate::serde_decimal_u64")]
    pub protocol_version: u64,
    pub message_id: String,
    pub session_id: String,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub payload: CompanionPayload,
}

impl CompanionMessage {
    pub fn to_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, MESSAGE_DOMAIN)
    }

    pub fn from_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, MESSAGE_DOMAIN)?;
        let protocol_version = decoder.read_u64()?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(CompanionError::UnsupportedVersion);
        }
        let value = Self {
            protocol_version,
            message_id: decoder.read_string()?,
            session_id: decoder.read_string()?,
            sender_device_id: DeviceId::parse(decoder.read_string()?)?,
            recipient_device_id: DeviceId::parse(decoder.read_string()?)?,
            sequence: decoder.read_u64()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
            payload: CompanionPayload::decode(&mut decoder)?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    /// Freshness of one authenticated frame against the local clock.
    ///
    /// `expires_at <= now` keeps its absolute, unbudgeted refusal. The peer's
    /// own `issued_at` carries the same bounded, forward-only
    /// [`MAX_CLOCK_SKEW_SECS`] the replay guard grants the identical stamps on
    /// the identical frame (`EncryptedCompanionFrame::replay_metadata`, checked
    /// immediately before this in `SessionCipher::decrypt`). Without it a
    /// handshake between two devices a second apart establishes and then every
    /// frame from the device that is ahead is refused, which is the same defect
    /// as the handshake one, one layer up.
    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        self.validate_shape()?;
        if self.expires_at <= now {
            return Err(CompanionError::Expired);
        }
        if self.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || self.expires_at.saturating_sub(self.issued_at) > MAX_MESSAGE_LIFETIME_SECS
        {
            return Err(CompanionError::InvalidIssuedAt);
        }
        Ok(())
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.message_id.is_empty()
            || self.session_id.is_empty()
            || self.sequence == 0
            || self.expires_at <= self.issued_at
        {
            return Err(CompanionError::MalformedMessage);
        }
        self.payload.validate()
    }
}

impl CanonicalEncode for CompanionMessage {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.protocol_version);
        encoder.push_string(&self.message_id)?;
        encoder.push_string(&self.session_id)?;
        encoder.push_string(self.sender_device_id.as_str())?;
        encoder.push_string(self.recipient_device_id.as_str())?;
        encoder.push_u64(self.sequence);
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        self.payload.encode(encoder)
    }
}

impl CompanionPayload {
    pub fn validate_for_wallet(&self, wallet_id: &str) -> CompanionResult<()> {
        self.validate()?;
        if wallet_id.is_empty() {
            return Err(CompanionError::WalletScopeMismatch);
        }
        match self {
            Self::ApprovalRequest(value) if value.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::ApprovalDecision(value) if value.decision.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::StatusSnapshot { status, .. } if status.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::AdminCommand(value) if value.command.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::PairingMobileProof(value) if value.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::RollbackAnchorProposal(value) if value.anchor.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::WitnessReceipt(value) if value.receipt.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::WitnessRotationProposal(value) if value.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::WitnessRotationAuthorization(value)
                if value.rotation.agent_wallet_id != wallet_id =>
            {
                Err(CompanionError::WalletScopeMismatch)
            }
            Self::WitnessRotationBaseline(value) if value.receipt.agent_wallet_id != wallet_id => {
                Err(CompanionError::WalletScopeMismatch)
            }
            _ => Ok(()),
        }
    }

    fn validate(&self) -> CompanionResult<()> {
        match self {
            Self::ApprovalRequest(value) => {
                value.canonical_bytes()?;
            }
            Self::ApprovalDecision(value) => {
                value.decision.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::StatusSnapshot {
                status,
                agents,
                policies,
                approvals,
                activity,
            } => {
                if status.agent_wallet_id.is_empty()
                    || status.address.is_empty()
                    || status.node_status.is_empty()
                    || status.policy_epoch == 0
                    || agents.len() > 4096
                    || policies.len() > 4096
                    || approvals.len() > 4096
                    || activity.len() > 4096
                {
                    return Err(CompanionError::MalformedMessage);
                }
                let mut agent_ids = BTreeSet::new();
                for agent in agents {
                    if agent.agent_id.is_empty()
                        || agent.display_name.is_empty()
                        || !agent_ids.insert(agent.agent_id.as_str())
                    {
                        return Err(CompanionError::MalformedMessage);
                    }
                }
                let mut policy_agents = BTreeSet::new();
                for policy in policies {
                    let approval_mode_ok = matches!(
                        policy.approval_mode.as_str(),
                        "desktop_manual" | "mobile_manual" | "either_trusted_device"
                    );
                    let recipients_bounded = policy.allowed_recipients.len()
                        <= MAX_POLICY_RECIPIENTS
                        && policy.blocked_recipients.len() <= MAX_POLICY_RECIPIENTS;
                    let permissions_valid =
                        policy.permissions.iter().all(|value| !value.is_empty());
                    let recipients_valid = policy
                        .allowed_recipients
                        .iter()
                        .chain(policy.blocked_recipients.iter())
                        .all(|value| !value.is_empty());
                    let allowed: BTreeSet<_> = policy.allowed_recipients.iter().collect();
                    let blocked: BTreeSet<_> = policy.blocked_recipients.iter().collect();
                    if policy.agent_id.is_empty()
                        || policy.policy_epoch == 0
                        || !agent_ids.contains(policy.agent_id.as_str())
                        || !policy_agents.insert(policy.agent_id.as_str())
                        || !approval_mode_ok
                        || !recipients_bounded
                        || !permissions_valid
                        || !recipients_valid
                        || allowed.len() != policy.allowed_recipients.len()
                        || blocked.len() != policy.blocked_recipients.len()
                        || !allowed.is_disjoint(&blocked)
                    {
                        return Err(CompanionError::MalformedMessage);
                    }
                }
                for approval in approvals {
                    approval.canonical_bytes()?;
                    if approval.agent_wallet_id != status.agent_wallet_id
                        || approval.policy_epoch != status.policy_epoch
                    {
                        return Err(CompanionError::WalletScopeMismatch);
                    }
                }
                for item in activity {
                    if item.activity_id.is_empty()
                        || item.description.is_empty()
                        || item.asset.is_empty()
                        || item.recipient.is_empty()
                        || item.amount_units == 0
                        || item.occurred_at == 0
                        || item.status.is_empty()
                    {
                        return Err(CompanionError::MalformedMessage);
                    }
                }
            }
            Self::AdminCommand(value) => {
                value.command.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::AdminAck {
                command_id, detail, ..
            } => {
                if command_id.is_empty() || detail.len() > 16 * 1024 {
                    return Err(CompanionError::MalformedMessage);
                }
            }
            Self::SyncRequest { .. } | Self::Ping | Self::Pong => {}
            Self::RecoverPendingWitness { operation_id } => {
                if operation_id.is_empty() || operation_id.len() > 256 {
                    return Err(CompanionError::MalformedMessage);
                }
            }
            Self::WitnessRotationPoll { rotation_id } => {
                if rotation_id
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || value.len() > 256)
                {
                    return Err(CompanionError::MalformedMessage);
                }
            }
            Self::WitnessRotationProposal(value) => {
                value.canonical_bytes()?;
            }
            Self::WitnessRotationAuthorization(value) => {
                value.rotation.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::WitnessRotationBaseline(value) => {
                value.receipt.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::Disconnect { reason } if reason.len() > 1024 => {
                return Err(CompanionError::MalformedMessage);
            }
            Self::Disconnect { .. } => {}
            Self::PairingMobileProof(value) => {
                value.to_bytes()?;
            }
            Self::RollbackAnchorProposal(value) => {
                value.anchor.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::WitnessReceipt(value) => {
                value.receipt.canonical_bytes()?;
                validate_signature(&value.signature_hex)?;
            }
            Self::WitnessAck {
                anchor_id, detail, ..
            } => {
                if anchor_id.is_empty() || detail.len() > 16 * 1024 {
                    return Err(CompanionError::MalformedMessage);
                }
            }
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        match self {
            Self::ApprovalRequest(value) => {
                encoder.push_u8(1);
                encoder.push_bytes(&value.canonical_bytes()?)?;
            }
            Self::ApprovalDecision(value) => {
                encoder.push_u8(2);
                encoder.push_bytes(&value.decision.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
            Self::StatusSnapshot {
                status,
                agents,
                policies,
                approvals,
                activity,
            } => {
                encoder.push_u8(3);
                encode_status(encoder, status)?;
                push_len(encoder, agents.len())?;
                for item in agents {
                    encoder.push_string(&item.agent_id)?;
                    encoder.push_string(&item.display_name)?;
                    encoder.push_u8(item.authorization.tag());
                }
                push_len(encoder, policies.len())?;
                for item in policies {
                    encoder.push_string(&item.agent_id)?;
                    encoder.push_u64(item.max_per_payment_units);
                    encoder.push_u64(item.max_daily_units);
                    encoder.push_u32(u32::from(item.max_pending_operations));
                    encoder.push_string(&item.approval_mode)?;
                    push_len(encoder, item.permissions.len())?;
                    for permission in &item.permissions {
                        encoder.push_string(permission)?;
                    }
                    push_len(encoder, item.allowed_recipients.len())?;
                    for recipient in &item.allowed_recipients {
                        encoder.push_string(recipient)?;
                    }
                    push_len(encoder, item.blocked_recipients.len())?;
                    for recipient in &item.blocked_recipients {
                        encoder.push_string(recipient)?;
                    }
                    encoder.push_u64(item.policy_epoch);
                }
                push_len(encoder, approvals.len())?;
                for item in approvals {
                    encoder.push_bytes(&item.canonical_bytes()?)?;
                }
                push_len(encoder, activity.len())?;
                for item in activity {
                    encoder.push_string(&item.activity_id)?;
                    encoder.push_string(&item.description)?;
                    encoder.push_string(&item.asset)?;
                    encoder.push_string(&item.recipient)?;
                    encoder.push_u64(item.amount_units);
                    encoder.push_u64(item.occurred_at);
                    encoder.push_string(&item.status)?;
                }
            }
            Self::AdminCommand(value) => {
                encoder.push_u8(4);
                encoder.push_bytes(&value.command.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
            Self::AdminAck {
                command_id,
                accepted,
                detail,
            } => {
                encoder.push_u8(5);
                encoder.push_string(command_id)?;
                encoder.push_bool(*accepted);
                encoder.push_string(detail)?;
            }
            Self::SyncRequest { since_sequence } => {
                encoder.push_u8(6);
                encoder.push_u64(*since_sequence);
            }
            Self::Ping => encoder.push_u8(7),
            Self::Pong => encoder.push_u8(8),
            Self::Disconnect { reason } => {
                encoder.push_u8(9);
                encoder.push_string(reason)?;
            }
            Self::PairingMobileProof(value) => {
                encoder.push_u8(10);
                encoder.push_bytes(&value.to_bytes()?)?;
            }
            Self::RollbackAnchorProposal(value) => {
                encoder.push_u8(11);
                encoder.push_bytes(&value.anchor.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
            Self::WitnessReceipt(value) => {
                encoder.push_u8(12);
                encoder.push_bytes(&value.receipt.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
            Self::WitnessAck {
                anchor_id,
                accepted,
                detail,
            } => {
                encoder.push_u8(13);
                encoder.push_string(anchor_id)?;
                encoder.push_bool(*accepted);
                encoder.push_string(detail)?;
            }
            Self::RecoverPendingWitness { operation_id } => {
                encoder.push_u8(14);
                encoder.push_string(operation_id)?;
            }
            Self::WitnessRotationPoll { rotation_id } => {
                encoder.push_u8(15);
                encoder.push_bool(rotation_id.is_some());
                if let Some(rotation_id) = rotation_id {
                    encoder.push_string(rotation_id)?;
                }
            }
            Self::WitnessRotationProposal(value) => {
                encoder.push_u8(16);
                encoder.push_bytes(&value.canonical_bytes()?)?;
            }
            Self::WitnessRotationAuthorization(value) => {
                encoder.push_u8(17);
                encoder.push_bytes(&value.rotation.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
            Self::WitnessRotationBaseline(value) => {
                encoder.push_u8(18);
                encoder.push_bytes(&value.receipt.canonical_bytes()?)?;
                encoder.push_string(&value.signature_hex)?;
            }
        }
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> CompanionResult<Self> {
        match decoder.read_u8()? {
            1 => Ok(Self::ApprovalRequest(
                ApprovalCommitment::from_canonical_bytes(decoder.read_bytes()?)?,
            )),
            2 => Ok(Self::ApprovalDecision(SignedApprovalDecision {
                decision: MobileApprovalDecision::from_canonical_bytes(decoder.read_bytes()?)?,
                signature_hex: decoder.read_string()?,
            })),
            3 => {
                let status = decode_status(decoder)?;
                let agents = decode_list(decoder, |decoder| {
                    Ok(AgentSummary {
                        agent_id: decoder.read_string()?,
                        display_name: decoder.read_string()?,
                        authorization: AgentAuthorizationState::from_tag(decoder.read_u8()?)?,
                    })
                })?;
                let policies = decode_list(decoder, |decoder| {
                    Ok(AgentPolicySummary {
                        agent_id: decoder.read_string()?,
                        max_per_payment_units: decoder.read_u64()?,
                        max_daily_units: decoder.read_u64()?,
                        max_pending_operations: u16::try_from(decoder.read_u32()?)
                            .map_err(|_| CompanionError::MalformedMessage)?,
                        approval_mode: decoder.read_string()?,
                        permissions: decode_list(decoder, |decoder| decoder.read_string())?,
                        allowed_recipients: decode_list(decoder, |decoder| decoder.read_string())?,
                        blocked_recipients: decode_list(decoder, |decoder| decoder.read_string())?,
                        policy_epoch: decoder.read_u64()?,
                    })
                })?;
                let approvals = decode_list(decoder, |decoder| {
                    ApprovalCommitment::from_canonical_bytes(decoder.read_bytes()?)
                })?;
                let activity = decode_list(decoder, |decoder| {
                    Ok(ActivitySummary {
                        activity_id: decoder.read_string()?,
                        description: decoder.read_string()?,
                        asset: decoder.read_string()?,
                        recipient: decoder.read_string()?,
                        amount_units: decoder.read_u64()?,
                        occurred_at: decoder.read_u64()?,
                        status: decoder.read_string()?,
                    })
                })?;
                Ok(Self::StatusSnapshot {
                    status,
                    agents,
                    policies,
                    approvals,
                    activity,
                })
            }
            4 => Ok(Self::AdminCommand(SignedAdminCommand {
                command: AdminCommand::from_canonical_bytes(decoder.read_bytes()?)?,
                signature_hex: decoder.read_string()?,
            })),
            5 => Ok(Self::AdminAck {
                command_id: decoder.read_string()?,
                accepted: decoder.read_bool()?,
                detail: decoder.read_string()?,
            }),
            6 => Ok(Self::SyncRequest {
                since_sequence: decoder.read_u64()?,
            }),
            7 => Ok(Self::Ping),
            8 => Ok(Self::Pong),
            9 => Ok(Self::Disconnect {
                reason: decoder.read_string()?,
            }),
            10 => Ok(Self::PairingMobileProof(MobilePairingProof::from_bytes(
                decoder.read_bytes()?,
            )?)),
            11 => Ok(Self::RollbackAnchorProposal(SignedRollbackAnchor {
                anchor: crate::witness::RollbackAnchor::from_canonical_bytes(
                    decoder.read_bytes()?,
                )?,
                signature_hex: decoder.read_string()?,
            })),
            12 => Ok(Self::WitnessReceipt(SignedWitnessReceipt {
                receipt: crate::witness::WitnessReceipt::from_canonical_bytes(
                    decoder.read_bytes()?,
                )?,
                signature_hex: decoder.read_string()?,
            })),
            13 => Ok(Self::WitnessAck {
                anchor_id: decoder.read_string()?,
                accepted: decoder.read_bool()?,
                detail: decoder.read_string()?,
            }),
            14 => Ok(Self::RecoverPendingWitness {
                operation_id: decoder.read_string()?,
            }),
            15 => Ok(Self::WitnessRotationPoll {
                rotation_id: if decoder.read_bool()? {
                    Some(decoder.read_string()?)
                } else {
                    None
                },
            }),
            16 => Ok(Self::WitnessRotationProposal(
                WitnessRotationRecord::from_canonical_bytes(decoder.read_bytes()?)?,
            )),
            17 => Ok(Self::WitnessRotationAuthorization(
                SignedWitnessRotationAuthorization {
                    rotation: WitnessRotationRecord::from_canonical_bytes(decoder.read_bytes()?)?,
                    signature_hex: decoder.read_string()?,
                },
            )),
            18 => Ok(Self::WitnessRotationBaseline(
                SignedWitnessRotationBaselineReceipt {
                    receipt: crate::rotation::WitnessRotationBaselineReceipt::from_canonical_bytes(
                        decoder.read_bytes()?,
                    )?,
                    signature_hex: decoder.read_string()?,
                },
            )),
            _ => Err(CompanionError::UnsupportedVersion),
        }
    }
}

fn validate_signature(value: &str) -> CompanionResult<()> {
    if value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CompanionError::InvalidSignature)
    }
}

fn push_len(encoder: &mut Encoder, len: usize) -> CompanionResult<()> {
    if len > 4096 {
        return Err(CompanionError::MessageTooLarge);
    }
    encoder.push_u32(u32::try_from(len).map_err(|_| CompanionError::MessageTooLarge)?);
    Ok(())
}

fn decode_list<T>(
    decoder: &mut Decoder<'_>,
    mut read: impl FnMut(&mut Decoder<'_>) -> CompanionResult<T>,
) -> CompanionResult<Vec<T>> {
    let len = usize::try_from(decoder.read_u32()?).map_err(|_| CompanionError::MalformedMessage)?;
    if len > 4096 {
        return Err(CompanionError::MessageTooLarge);
    }
    (0..len).map(|_| read(decoder)).collect()
}

fn encode_status(encoder: &mut Encoder, value: &CompanionStatus) -> CompanionResult<()> {
    encoder.push_string(&value.agent_wallet_id)?;
    encoder.push_string(&value.address)?;
    encoder.push_bool(value.available_units.is_some());
    if let Some(available_units) = value.available_units {
        encoder.push_u64(available_units);
    }
    encoder.push_string(&value.node_status)?;
    encoder.push_u64(value.reserved_units);
    encoder.push_u64(value.spent_today_units);
    encoder.push_u64(value.spent_month_units);
    encoder.push_bool(value.paused);
    encoder.push_u64(value.policy_epoch);
    Ok(())
}

fn decode_status(decoder: &mut Decoder<'_>) -> CompanionResult<CompanionStatus> {
    Ok(CompanionStatus {
        agent_wallet_id: decoder.read_string()?,
        address: decoder.read_string()?,
        available_units: decoder
            .read_bool()?
            .then(|| decoder.read_u64())
            .transpose()?,
        node_status: decoder.read_string()?,
        reserved_units: decoder.read_u64()?,
        spent_today_units: decoder.read_u64()?,
        spent_month_units: decoder.read_u64()?,
        paused: decoder.read_bool()?,
        policy_epoch: decoder.read_u64()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceRole;

    fn message() -> CompanionMessage {
        CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "message_1".to_owned(),
            session_id: "session_1".to_owned(),
            sender_device_id: DeviceId::random(DeviceRole::Desktop),
            recipient_device_id: DeviceId::random(DeviceRole::Mobile),
            sequence: 1,
            issued_at: 100,
            expires_at: 200,
            payload: CompanionPayload::StatusSnapshot {
                status: CompanionStatus {
                    agent_wallet_id: "wallet_one".to_owned(),
                    address: "1AgentWalletAddress".to_owned(),
                    available_units: Some(100),
                    node_status: "verified".to_owned(),
                    reserved_units: 5,
                    spent_today_units: 3,
                    spent_month_units: 30,
                    paused: false,
                    policy_epoch: 2,
                },
                agents: vec![AgentSummary {
                    agent_id: "agent_one".to_owned(),
                    display_name: "Local Assistant".to_owned(),
                    authorization: AgentAuthorizationState::Authorized,
                }],
                policies: vec![AgentPolicySummary {
                    agent_id: "agent_one".to_owned(),
                    max_per_payment_units: 50_000,
                    max_daily_units: 100_000,
                    max_pending_operations: 2,
                    approval_mode: "mobile_manual".to_owned(),
                    permissions: vec!["create_payment_intent".to_owned()],
                    allowed_recipients: vec!["1Recipient".to_owned()],
                    blocked_recipients: Vec::new(),
                    policy_epoch: 2,
                }],
                approvals: Vec::new(),
                activity: Vec::new(),
            },
        }
    }

    fn approval() -> ApprovalCommitment {
        let desktop = crate::identity::SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        ApprovalCommitment {
            approval_version: 2,
            approval_id: "approval_1".to_owned(),
            operation_id: "operation_1".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            agent_id: "agent_one".to_owned(),
            desktop_device_id: desktop.device_id().clone(),
            transaction_commitment: "ab".repeat(32),
            amount_units: 10_000,
            fee_units: 1_000,
            wallet_fee_units: 0,
            total_debit_units: 11_000,
            recipient: "1Recipient".to_owned(),
            policy_epoch: 2,
            challenge_nonce: "cd".repeat(16),
            issued_at: 100,
            expires_at: 200,
            network_binding: None,
        }
    }

    #[test]
    fn canonical_message_roundtrip_is_stable() {
        let value = message();
        let bytes = value.to_bytes().unwrap();
        assert_eq!(CompanionMessage::from_bytes(&bytes).unwrap(), value);
        assert_eq!(
            CompanionMessage::from_bytes(&bytes)
                .unwrap()
                .to_bytes()
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn recover_pending_witness_roundtrips_and_rejects_empty_operation() {
        let mut value = message();
        value.payload = CompanionPayload::RecoverPendingWitness {
            operation_id: "op_recover_one".to_owned(),
        };
        let bytes = value.to_bytes().unwrap();
        assert_eq!(CompanionMessage::from_bytes(&bytes).unwrap(), value);

        value.payload = CompanionPayload::RecoverPendingWitness {
            operation_id: String::new(),
        };
        assert_eq!(value.to_bytes(), Err(CompanionError::MalformedMessage));
    }

    #[test]
    fn witness_rotation_poll_roundtrips_and_rejects_ambiguous_id() {
        let mut value = message();
        value.payload = CompanionPayload::WitnessRotationPoll {
            rotation_id: Some("rotation_one".to_owned()),
        };
        let bytes = value.to_bytes().unwrap();
        assert_eq!(CompanionMessage::from_bytes(&bytes).unwrap(), value);

        value.payload = CompanionPayload::WitnessRotationPoll {
            rotation_id: Some(String::new()),
        };
        assert_eq!(value.to_bytes(), Err(CompanionError::MalformedMessage));
    }
    #[test]
    fn status_snapshot_carries_full_commitment_and_fails_closed() {
        let mut value = message();
        let CompanionPayload::StatusSnapshot { approvals, .. } = &mut value.payload else {
            unreachable!();
        };
        approvals.push(approval());
        let bytes = value.to_bytes().unwrap();
        assert_eq!(CompanionMessage::from_bytes(&bytes).unwrap(), value);

        let CompanionPayload::StatusSnapshot { approvals, .. } = &mut value.payload else {
            unreachable!();
        };
        approvals[0].wallet_fee_units = 1;
        approvals[0].total_debit_units += 1;
        assert_eq!(value.to_bytes(), Err(CompanionError::MalformedMessage));

        let mut wrong_scope = message();
        let CompanionPayload::StatusSnapshot { approvals, .. } = &mut wrong_scope.payload else {
            unreachable!();
        };
        let mut other_wallet = approval();
        other_wallet.agent_wallet_id = "wallet_two".to_owned();
        approvals.push(other_wallet);
        assert_eq!(
            wrong_scope.to_bytes(),
            Err(CompanionError::WalletScopeMismatch)
        );
    }

    #[test]
    fn malformed_trailing_oversized_and_version_fail_closed() {
        let value = message();
        let mut trailing = value.to_bytes().unwrap();
        trailing.push(0);
        assert_eq!(
            CompanionMessage::from_bytes(&trailing),
            Err(CompanionError::MalformedMessage)
        );
        assert_eq!(
            CompanionMessage::from_bytes(&vec![0; 256 * 1024 + 1]),
            Err(CompanionError::MessageTooLarge)
        );
        let mut wrong_version = value;
        wrong_version.protocol_version = 2;
        assert_eq!(
            wrong_version.to_bytes(),
            Err(CompanionError::UnsupportedVersion)
        );
    }

    #[test]
    fn serde_rejects_unknown_fields() {
        let mut json = serde_json::to_value(message()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("private_key".to_owned(), serde_json::json!("forbidden"));
        assert!(serde_json::from_value::<CompanionMessage>(json).is_err());
    }
}
