//! The external rollback anchor wire protocol.
//!
//! Shape, domain separation and commitments-only discipline are lifted from
//! `crates/companion-protocol/src/witness.rs`, which is proven and in
//! production use for the Agent Wallet. What differs is the transport and the
//! liveness model: a Hub is a server that signs unattended, not a phone with a
//! biometric prompt on a private LAN.
//!
//! Every message here carries commitments and positions only. No balances, no
//! bill bodies, no signatures over money, no keys.
//!
//! Full design: `docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md`.
//! Operator procedure: `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`.

use basis::method::verify_signature;
use field::{Hash, Serialize as FieldSerialize, Sign};
use serde::{Deserialize, Serialize};
use sys::Account;

use super::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{HubError, HubResult};
use crate::hvm_channel::{parse_address, parse_signature};

pub const ANCHOR_REQUEST_DOMAIN: &[u8] = b"HPAY/HUB/ROLLBACK-ANCHOR/V1";
pub const WITNESS_RECEIPT_DOMAIN: &[u8] = b"HPAY/HUB/WITNESS-RECEIPT/V1";
pub const WITNESS_REFUSAL_DOMAIN: &[u8] = b"HPAY/HUB/WITNESS-REFUSAL/V1";
pub const WITNESS_STATUS_DOMAIN: &[u8] = b"HPAY/HUB/WITNESS-STATUS/V1";
pub const WITNESS_ATTESTATION_DOMAIN: &[u8] = b"HPAY/HUB/WITNESS-ATTESTATION/V1";

/// A Hub is a server. Nothing on this path waits for a human, so the request
/// lifetime is bounded far below the ten minutes the companion anchor allows
/// for someone to pick up a phone. A window wider than the signing path needs
/// is a window in which a stockpiled request is useful.
pub const MAX_ANCHOR_LIFETIME_SECS: u64 = 120;
/// How stale a signed witness message may be before the Hub stops treating it
/// as evidence of a live witness.
pub const MAX_WITNESS_MESSAGE_AGE_SECS: u64 = 120;

/// Refusal identifiers. These are the exact strings the Hub prints and the
/// exact strings `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` indexes its procedures
/// by, so the code and the operator document cannot drift apart.
pub const REFUSAL_HUB_BEHIND_WITNESS: &str = "rollback_anchor_hub_behind_witness";
pub const REFUSAL_FORK_AT_SERIAL: &str = "rollback_anchor_fork_at_serial";
pub const REFUSAL_COUNTER_SKIPPED: &str = "rollback_anchor_counter_skipped";
pub const REFUSAL_WITNESS_BEHIND_HUB: &str = "rollback_anchor_witness_behind_hub";
pub const REFUSAL_WITNESS_INSTANCE_CHANGED: &str = "rollback_anchor_witness_instance_changed";
pub const REFUSAL_WITNESS_UNREACHABLE: &str = "rollback_anchor_witness_unreachable";
pub const REFUSAL_WITNESS_IS_NOT_EXTERNAL: &str = "rollback_anchor_witness_is_not_external";
pub const REFUSAL_ATTESTATION_MISSING_OR_EXPIRED: &str =
    "rollback_anchor_attestation_missing_or_expired";
pub const REFUSAL_RECEIPT_NOT_BOUND: &str = "rollback_anchor_receipt_not_bound_to_request";
pub const REFUSAL_REPLAY_MISMATCH: &str = "rollback_anchor_replay_mismatch";
pub const REFUSAL_KEY_CUSTODY_NOT_DISTINCT: &str =
    "rollback_anchor_witness_key_custody_is_not_distinct";
pub const REFUSAL_EPOCH_MISMATCH: &str = "rollback_anchor_witness_epoch_mismatch";
pub const REFUSAL_EXPIRED: &str = "rollback_anchor_request_expired";
pub const REFUSAL_UNKNOWN_HUB: &str = "rollback_anchor_unknown_hub";
pub const REFUSAL_MALFORMED_REQUEST: &str = "rollback_anchor_malformed_request";

/// Does this refusal mean the anchor and the Hub disagree about history?
///
/// Only these justify latching a channel, and the distinction is operational
/// rather than cosmetic. A rollback is a durable, human-resolved condition:
/// the channel must not sign again until someone has followed
/// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`. An unreachable witness, a timed-out
/// request or a malformed answer refuses *this* signature and nothing more.
/// Latching on those would mean one dropped packet permanently condemns a
/// channel, which is exactly the kind of anchor an operator disables at 3am.
pub fn refusal_condemns_the_channel(message: &str) -> bool {
    [
        REFUSAL_HUB_BEHIND_WITNESS,
        REFUSAL_FORK_AT_SERIAL,
        REFUSAL_COUNTER_SKIPPED,
        REFUSAL_WITNESS_BEHIND_HUB,
        REFUSAL_WITNESS_INSTANCE_CHANGED,
        REFUSAL_REPLAY_MISMATCH,
    ]
    .iter()
    .any(|identifier| message.contains(identifier))
}

fn malformed(what: &str) -> HubError {
    HubError::Node(format!("rollback anchor {what} is malformed"))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn sign_canonical(account: &Account, bytes: &[u8]) -> String {
    let hash = Hash::from(sys::sha2(bytes));
    hex::encode(Sign::create_by(account, &hash).serialize())
}

fn verify_canonical(address: &str, bytes: &[u8], signature_hex: &str) -> HubResult<()> {
    let address = parse_address(address, "rollback anchor signer")?;
    let signature = parse_signature(signature_hex)?;
    let hash = Hash::from(sys::sha2(bytes));
    if !verify_signature(&hash, &address, &signature) {
        return Err(HubError::Node(
            "rollback anchor signature does not verify against the pinned key".into(),
        ));
    }
    Ok(())
}

/// Where the witness runs, relative to the Hub operator. There is deliberately
/// no `SameHost` value: a configuration that wants it cannot express it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPosture {
    Counterparty,
    NeutralThirdParty,
    SameOperatorSeparateInfrastructure,
}

impl WitnessPosture {
    fn tag(self) -> u8 {
        match self {
            Self::Counterparty => 1,
            Self::NeutralThirdParty => 2,
            Self::SameOperatorSeparateInfrastructure => 3,
        }
    }

    fn from_tag(tag: u8) -> HubResult<Self> {
        match tag {
            1 => Ok(Self::Counterparty),
            2 => Ok(Self::NeutralThirdParty),
            3 => Ok(Self::SameOperatorSeparateInfrastructure),
            _ => Err(malformed("attestation posture")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Counterparty => "counterparty",
            Self::NeutralThirdParty => "neutral_third_party",
            Self::SameOperatorSeparateInfrastructure => "same_operator_separate_infrastructure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRefusalReason {
    HubBehindWitness,
    ForkAtSerial,
    CounterSkipped,
    MalformedRequest,
    UnknownHub,
    UnknownChannel,
    EpochMismatch,
    Expired,
    ReplayMismatch,
    WitnessBehindHub,
}

impl WitnessRefusalReason {
    fn tag(self) -> u8 {
        match self {
            Self::HubBehindWitness => 1,
            Self::ForkAtSerial => 2,
            Self::CounterSkipped => 3,
            Self::MalformedRequest => 4,
            Self::UnknownHub => 5,
            Self::UnknownChannel => 6,
            Self::EpochMismatch => 7,
            Self::Expired => 8,
            Self::ReplayMismatch => 9,
            Self::WitnessBehindHub => 10,
        }
    }

    fn from_tag(tag: u8) -> HubResult<Self> {
        match tag {
            1 => Ok(Self::HubBehindWitness),
            2 => Ok(Self::ForkAtSerial),
            3 => Ok(Self::CounterSkipped),
            4 => Ok(Self::MalformedRequest),
            5 => Ok(Self::UnknownHub),
            6 => Ok(Self::UnknownChannel),
            7 => Ok(Self::EpochMismatch),
            8 => Ok(Self::Expired),
            9 => Ok(Self::ReplayMismatch),
            10 => Ok(Self::WitnessBehindHub),
            _ => Err(malformed("refusal reason")),
        }
    }

    /// The operator-facing identifier. Every one of these is a heading in
    /// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`.
    pub fn identifier(self) -> &'static str {
        match self {
            Self::HubBehindWitness => REFUSAL_HUB_BEHIND_WITNESS,
            Self::ForkAtSerial => REFUSAL_FORK_AT_SERIAL,
            Self::CounterSkipped => REFUSAL_COUNTER_SKIPPED,
            Self::MalformedRequest => REFUSAL_MALFORMED_REQUEST,
            Self::UnknownHub | Self::UnknownChannel => REFUSAL_UNKNOWN_HUB,
            Self::EpochMismatch => REFUSAL_EPOCH_MISMATCH,
            Self::Expired => REFUSAL_EXPIRED,
            Self::ReplayMismatch => REFUSAL_REPLAY_MISMATCH,
            Self::WitnessBehindHub => REFUSAL_WITNESS_BEHIND_HUB,
        }
    }

    /// What the operator has to understand, in the words of the threat rather
    /// than the words of the protocol. A refusal that says only "invalid" is
    /// the refusal that gets overridden at 3am.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::HubBehindWitness => {
                "this Hub's durable state is BEHIND the external rollback anchor: the witness has \
                 already recorded a later position for this channel than the Hub is asking to \
                 sign. This is what a restored-from-backup Hub looks like. Signing here would \
                 co-sign a serial the Hub has already signed once, with different balances, and \
                 both signatures would be valid to the contract"
            }
            Self::ForkAtSerial => {
                "the witness holds a DIFFERENT bill at this exact serial: the Hub is proposing to \
                 sign a second, different bill at a ledger position it has already signed. This \
                 is the double-signature the anchor exists to prevent"
            }
            Self::CounterSkipped => {
                "the witness's global counter is not where this Hub believes it is: reservations \
                 this Hub does not account for have been consumed. A second live Hub sharing this \
                 identity, or a shared counter namespace, is the usual cause"
            }
            Self::MalformedRequest => {
                "the anchor request did not decode or failed shape validation"
            }
            Self::UnknownHub => "the witness does not serve this Hub identity",
            Self::UnknownChannel => "the witness does not hold a record for this channel",
            Self::EpochMismatch => "the witness key generation does not match the pinned epoch",
            Self::Expired => "the anchor request was outside its bounded lifetime",
            Self::ReplayMismatch => {
                "a request bearing a known request id arrived with a DIFFERENT commitment. That is \
                 an equivocation attempt, not a retry"
            }
            Self::WitnessBehindHub => {
                "the witness is behind this Hub: it has no record of positions the Hub has already \
                 signed. Either the witness store was restored, re-created, or replaced. An anchor \
                 that has forgotten is not an anchor"
            }
        }
    }
}

/// Everything the Hub asks the witness to record before it uses its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubAnchorRequestV1 {
    pub request_version: u64,
    pub request_id: String,
    pub hub_identity: String,
    pub witness_id: String,
    pub witness_epoch: u64,
    pub settlement_profile: String,
    pub network_instance_id: String,
    pub binding_commitment: String,
    pub channel_id: String,
    pub reuse_version: u32,
    pub serial: u64,
    pub previous_bill_commitment: String,
    pub proposed_bill_commitment: String,
    pub counter_value: u64,
    pub hub_journal_sequence: u64,
    pub hub_journal_head_hash: String,
    pub hub_state_commitment: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl CanonicalEncode for HubAnchorRequestV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
        encoder.push_u64(self.request_version);
        encoder.push_string(&self.request_id)?;
        encoder.push_string(&self.hub_identity)?;
        encoder.push_string(&self.witness_id)?;
        encoder.push_u64(self.witness_epoch);
        encoder.push_string(&self.settlement_profile)?;
        encoder.push_string(&self.network_instance_id)?;
        encoder.push_string(&self.binding_commitment)?;
        encoder.push_string(&self.channel_id)?;
        encoder.push_u32(self.reuse_version);
        encoder.push_u64(self.serial);
        encoder.push_string(&self.previous_bill_commitment)?;
        encoder.push_string(&self.proposed_bill_commitment)?;
        encoder.push_u64(self.counter_value);
        encoder.push_u64(self.hub_journal_sequence);
        encoder.push_string(&self.hub_journal_head_hash)?;
        encoder.push_string(&self.hub_state_commitment)?;
        encoder.push_u64(self.created_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

impl HubAnchorRequestV1 {
    pub fn validate_shape(&self) -> HubResult<()> {
        if self.request_version != 1
            || !is_identifier(&self.request_id)
            || !is_identifier(&self.hub_identity)
            || !is_identifier(&self.witness_id)
            || self.witness_epoch == 0
            || !is_identifier(&self.settlement_profile)
            || !is_identifier(&self.network_instance_id)
            || !is_hash(&self.binding_commitment)
            || !is_identifier(&self.channel_id)
            || self.serial == 0
            || !is_hash(&self.previous_bill_commitment)
            || !is_hash(&self.proposed_bill_commitment)
            || self.proposed_bill_commitment == self.previous_bill_commitment
            || self.counter_value == 0
            || !is_hash(&self.hub_journal_head_hash)
            || !is_hash(&self.hub_state_commitment)
            || self.created_at == 0
            || self.expires_at <= self.created_at
            || self.expires_at.saturating_sub(self.created_at) > MAX_ANCHOR_LIFETIME_SECS
        {
            return Err(malformed("anchor request"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> HubResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, ANCHOR_REQUEST_DOMAIN)
    }

    pub fn commitment(&self) -> HubResult<String> {
        self.validate_shape()?;
        CanonicalEncode::canonical_sha256_hex(self, ANCHOR_REQUEST_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> HubResult<Self> {
        let mut decoder = Decoder::new(bytes, ANCHOR_REQUEST_DOMAIN)?;
        let value = Self {
            request_version: decoder.read_u64()?,
            request_id: decoder.read_string()?,
            hub_identity: decoder.read_string()?,
            witness_id: decoder.read_string()?,
            witness_epoch: decoder.read_u64()?,
            settlement_profile: decoder.read_string()?,
            network_instance_id: decoder.read_string()?,
            binding_commitment: decoder.read_string()?,
            channel_id: decoder.read_string()?,
            reuse_version: decoder.read_u32()?,
            serial: decoder.read_u64()?,
            previous_bill_commitment: decoder.read_string()?,
            proposed_bill_commitment: decoder.read_string()?,
            counter_value: decoder.read_u64()?,
            hub_journal_sequence: decoder.read_u64()?,
            hub_journal_head_hash: decoder.read_string()?,
            hub_state_commitment: decoder.read_string()?,
            created_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHubAnchorRequestV1 {
    pub request: HubAnchorRequestV1,
    pub signature_hex: String,
}

impl SignedHubAnchorRequestV1 {
    /// Signed with the same account that will sign the bill, deliberately: a
    /// receipt must authorise *the key that will sign*. Cross-protocol
    /// confusion is prevented by the domain being inside the hashed preimage
    /// and by the bill hash using `HPAY/HVM-CHANNEL-REGISTRY/V2` under sha3.
    pub fn sign(request: HubAnchorRequestV1, account: &Account) -> HubResult<Self> {
        let bytes = request.canonical_bytes()?;
        Ok(Self {
            signature_hex: sign_canonical(account, &bytes),
            request,
        })
    }

    /// Verifies the Hub's own signature against the identity the request
    /// claims. Returns the request commitment.
    pub fn verify(&self) -> HubResult<String> {
        let bytes = self.request.canonical_bytes()?;
        verify_canonical(&self.request.hub_identity, &bytes, &self.signature_hex)?;
        Ok(hex::encode(sys::sha2(&bytes)))
    }
}

/// Returned only after the witness has durably recorded the reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubWitnessReceiptV1 {
    pub receipt_version: u64,
    pub request_id: String,
    pub request_commitment: String,
    pub witness_id: String,
    pub witness_epoch: u64,
    pub witness_instance_id: String,
    pub witness_boot_id: String,
    pub hub_identity: String,
    pub binding_commitment: String,
    pub serial: u64,
    pub proposed_bill_commitment: String,
    pub previous_counter_value: u64,
    pub counter_value: u64,
    pub accepted_at: u64,
    pub receipt_expires_at: u64,
}

impl CanonicalEncode for HubWitnessReceiptV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
        encoder.push_u64(self.receipt_version);
        encoder.push_string(&self.request_id)?;
        encoder.push_string(&self.request_commitment)?;
        encoder.push_string(&self.witness_id)?;
        encoder.push_u64(self.witness_epoch);
        encoder.push_string(&self.witness_instance_id)?;
        encoder.push_string(&self.witness_boot_id)?;
        encoder.push_string(&self.hub_identity)?;
        encoder.push_string(&self.binding_commitment)?;
        encoder.push_u64(self.serial);
        encoder.push_string(&self.proposed_bill_commitment)?;
        encoder.push_u64(self.previous_counter_value);
        encoder.push_u64(self.counter_value);
        encoder.push_u64(self.accepted_at);
        encoder.push_u64(self.receipt_expires_at);
        Ok(())
    }
}

impl HubWitnessReceiptV1 {
    pub fn validate_shape(&self) -> HubResult<()> {
        if self.receipt_version != 1
            || !is_identifier(&self.request_id)
            || !is_hash(&self.request_commitment)
            || !is_identifier(&self.witness_id)
            || self.witness_epoch == 0
            || !is_hash(&self.witness_instance_id)
            || !is_hash(&self.witness_boot_id)
            || !is_identifier(&self.hub_identity)
            || !is_hash(&self.binding_commitment)
            || self.serial == 0
            || !is_hash(&self.proposed_bill_commitment)
            || self.counter_value == 0
            || self.previous_counter_value >= self.counter_value
            || self.accepted_at == 0
            || self.receipt_expires_at <= self.accepted_at
            || self.receipt_expires_at.saturating_sub(self.accepted_at) > MAX_ANCHOR_LIFETIME_SECS
        {
            return Err(malformed("witness receipt"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> HubResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, WITNESS_RECEIPT_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> HubResult<Self> {
        let mut decoder = Decoder::new(bytes, WITNESS_RECEIPT_DOMAIN)?;
        let value = Self {
            receipt_version: decoder.read_u64()?,
            request_id: decoder.read_string()?,
            request_commitment: decoder.read_string()?,
            witness_id: decoder.read_string()?,
            witness_epoch: decoder.read_u64()?,
            witness_instance_id: decoder.read_string()?,
            witness_boot_id: decoder.read_string()?,
            hub_identity: decoder.read_string()?,
            binding_commitment: decoder.read_string()?,
            serial: decoder.read_u64()?,
            proposed_bill_commitment: decoder.read_string()?,
            previous_counter_value: decoder.read_u64()?,
            counter_value: decoder.read_u64()?,
            accepted_at: decoder.read_u64()?,
            receipt_expires_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHubWitnessReceiptV1 {
    pub receipt: HubWitnessReceiptV1,
    pub signature_hex: String,
}

impl SignedHubWitnessReceiptV1 {
    pub fn sign(receipt: HubWitnessReceiptV1, account: &Account) -> HubResult<Self> {
        let bytes = receipt.canonical_bytes()?;
        Ok(Self {
            signature_hex: sign_canonical(account, &bytes),
            receipt,
        })
    }

    pub fn verify_against_pinned_key(&self, receipt_address: &str) -> HubResult<()> {
        let bytes = self.receipt.canonical_bytes()?;
        verify_canonical(receipt_address, &bytes, &self.signature_hex)
    }
}

/// A refusal is signed. It is the primary evidence artefact in the recovery
/// procedure, and it is what distinguishes "the witness said no" from "the
/// network dropped the packet". An unreachable witness produces no refusal,
/// and the Hub must never treat silence as a refusal or a refusal as silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubWitnessRefusalV1 {
    pub refusal_version: u64,
    pub request_id: String,
    pub request_commitment: String,
    pub witness_id: String,
    pub witness_epoch: u64,
    pub witness_instance_id: String,
    pub hub_identity: String,
    pub binding_commitment: String,
    pub reason: WitnessRefusalReason,
    pub observed_counter_value: u64,
    pub observed_serial: u64,
    pub observed_bill_commitment: String,
    pub refused_at: u64,
}

impl CanonicalEncode for HubWitnessRefusalV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
        encoder.push_u64(self.refusal_version);
        encoder.push_string(&self.request_id)?;
        encoder.push_string(&self.request_commitment)?;
        encoder.push_string(&self.witness_id)?;
        encoder.push_u64(self.witness_epoch);
        encoder.push_string(&self.witness_instance_id)?;
        encoder.push_string(&self.hub_identity)?;
        encoder.push_string(&self.binding_commitment)?;
        encoder.push_u8(self.reason.tag());
        encoder.push_u64(self.observed_counter_value);
        encoder.push_u64(self.observed_serial);
        encoder.push_string(&self.observed_bill_commitment)?;
        encoder.push_u64(self.refused_at);
        Ok(())
    }
}

impl HubWitnessRefusalV1 {
    pub fn validate_shape(&self) -> HubResult<()> {
        if self.refusal_version != 1
            || !is_identifier(&self.request_id)
            || !is_hash(&self.request_commitment)
            || !is_identifier(&self.witness_id)
            || self.witness_epoch == 0
            || !is_hash(&self.witness_instance_id)
            || !is_identifier(&self.hub_identity)
            || !is_hash(&self.binding_commitment)
            || !is_hash(&self.observed_bill_commitment)
            || self.refused_at == 0
        {
            return Err(malformed("witness refusal"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> HubResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, WITNESS_REFUSAL_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> HubResult<Self> {
        let mut decoder = Decoder::new(bytes, WITNESS_REFUSAL_DOMAIN)?;
        let value = Self {
            refusal_version: decoder.read_u64()?,
            request_id: decoder.read_string()?,
            request_commitment: decoder.read_string()?,
            witness_id: decoder.read_string()?,
            witness_epoch: decoder.read_u64()?,
            witness_instance_id: decoder.read_string()?,
            hub_identity: decoder.read_string()?,
            binding_commitment: decoder.read_string()?,
            reason: WitnessRefusalReason::from_tag(decoder.read_u8()?)?,
            observed_counter_value: decoder.read_u64()?,
            observed_serial: decoder.read_u64()?,
            observed_bill_commitment: decoder.read_string()?,
            refused_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHubWitnessRefusalV1 {
    pub refusal: HubWitnessRefusalV1,
    pub signature_hex: String,
}

impl SignedHubWitnessRefusalV1 {
    pub fn sign(refusal: HubWitnessRefusalV1, account: &Account) -> HubResult<Self> {
        let bytes = refusal.canonical_bytes()?;
        Ok(Self {
            signature_hex: sign_canonical(account, &bytes),
            refusal,
        })
    }

    pub fn verify_against_pinned_key(&self, receipt_address: &str) -> HubResult<()> {
        let bytes = self.refusal.canonical_bytes()?;
        verify_canonical(receipt_address, &bytes, &self.signature_hex)
    }
}

/// The witness's signed answer to a liveness and position probe.
///
/// This advances nothing. It exists because the anti-rollback check proper is
/// a comparison of positions at startup, and because a readiness flag that
/// claims a live witness has to have something signed and fresh to point at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubWitnessStatusV1 {
    pub status_version: u64,
    pub witness_id: String,
    pub witness_epoch: u64,
    pub witness_instance_id: String,
    pub witness_boot_id: String,
    pub hub_identity: String,
    /// Echoed from the request. A status without the caller's nonce is a
    /// recording, not a liveness proof.
    pub nonce: String,
    pub counter_value: u64,
    /// `(binding_commitment, highest recorded serial, bill commitment at it)`,
    /// for every channel this witness holds for this Hub, sorted by binding.
    pub channels: Vec<HubWitnessChannelPositionV1>,
    pub observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubWitnessChannelPositionV1 {
    pub binding_commitment: String,
    pub serial: u64,
    pub bill_commitment: String,
}

impl CanonicalEncode for HubWitnessStatusV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
        encoder.push_u64(self.status_version);
        encoder.push_string(&self.witness_id)?;
        encoder.push_u64(self.witness_epoch);
        encoder.push_string(&self.witness_instance_id)?;
        encoder.push_string(&self.witness_boot_id)?;
        encoder.push_string(&self.hub_identity)?;
        encoder.push_string(&self.nonce)?;
        encoder.push_u64(self.counter_value);
        encoder.push_u32(u32::try_from(self.channels.len()).map_err(|_| malformed("status"))?);
        for channel in &self.channels {
            encoder.push_string(&channel.binding_commitment)?;
            encoder.push_u64(channel.serial);
            encoder.push_string(&channel.bill_commitment)?;
        }
        encoder.push_u64(self.observed_at);
        Ok(())
    }
}

impl HubWitnessStatusV1 {
    pub fn validate_shape(&self) -> HubResult<()> {
        let channels_sorted = self
            .channels
            .windows(2)
            .all(|pair| pair[0].binding_commitment < pair[1].binding_commitment);
        let channels_valid = self.channels.iter().all(|channel| {
            is_hash(&channel.binding_commitment)
                && channel.serial > 0
                && is_hash(&channel.bill_commitment)
        });
        if self.status_version != 1
            || !is_identifier(&self.witness_id)
            || self.witness_epoch == 0
            || !is_hash(&self.witness_instance_id)
            || !is_hash(&self.witness_boot_id)
            || !is_identifier(&self.hub_identity)
            || !is_hash(&self.nonce)
            || !channels_sorted
            || !channels_valid
            || self.observed_at == 0
        {
            return Err(malformed("witness status"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> HubResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, WITNESS_STATUS_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> HubResult<Self> {
        let mut decoder = Decoder::new(bytes, WITNESS_STATUS_DOMAIN)?;
        let status_version = decoder.read_u64()?;
        let witness_id = decoder.read_string()?;
        let witness_epoch = decoder.read_u64()?;
        let witness_instance_id = decoder.read_string()?;
        let witness_boot_id = decoder.read_string()?;
        let hub_identity = decoder.read_string()?;
        let nonce = decoder.read_string()?;
        let counter_value = decoder.read_u64()?;
        let count = decoder.read_u32()?;
        let mut channels = Vec::new();
        for _ in 0..count {
            channels.push(HubWitnessChannelPositionV1 {
                binding_commitment: decoder.read_string()?,
                serial: decoder.read_u64()?,
                bill_commitment: decoder.read_string()?,
            });
        }
        let value = Self {
            status_version,
            witness_id,
            witness_epoch,
            witness_instance_id,
            witness_boot_id,
            hub_identity,
            nonce,
            counter_value,
            channels,
            observed_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn channel(&self, binding_commitment: &str) -> Option<&HubWitnessChannelPositionV1> {
        self.channels
            .iter()
            .find(|channel| channel.binding_commitment == binding_commitment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHubWitnessStatusV1 {
    pub status: HubWitnessStatusV1,
    pub signature_hex: String,
}

impl SignedHubWitnessStatusV1 {
    pub fn sign(status: HubWitnessStatusV1, account: &Account) -> HubResult<Self> {
        let bytes = status.canonical_bytes()?;
        Ok(Self {
            signature_hex: sign_canonical(account, &bytes),
            status,
        })
    }

    pub fn verify_against_pinned_key(&self, receipt_address: &str) -> HubResult<()> {
        let bytes = self.status.canonical_bytes()?;
        verify_canonical(receipt_address, &bytes, &self.signature_hex)
    }
}

/// Signed by the witness's **offline** authorisation key, never the online
/// receipt key.
///
/// Cryptographically this proves nothing about where the witness runs: an
/// attestation is a statement, not evidence. Its entire value is that the weak
/// configuration now requires a named person to sign a document saying they
/// chose it, and to re-sign when it expires rather than setting it once and
/// forgetting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDeploymentAttestationV1 {
    pub attestation_version: u64,
    pub witness_id: String,
    pub witness_instance_id: String,
    pub hub_identity: String,
    pub posture: WitnessPosture,
    pub witness_operator: String,
    pub separation_statement: String,
    pub attested_at: u64,
    pub expires_at: u64,
}

impl CanonicalEncode for WitnessDeploymentAttestationV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
        encoder.push_u64(self.attestation_version);
        encoder.push_string(&self.witness_id)?;
        encoder.push_string(&self.witness_instance_id)?;
        encoder.push_string(&self.hub_identity)?;
        encoder.push_u8(self.posture.tag());
        encoder.push_string(&self.witness_operator)?;
        encoder.push_string(&self.separation_statement)?;
        encoder.push_u64(self.attested_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

impl WitnessDeploymentAttestationV1 {
    pub fn validate_shape(&self) -> HubResult<()> {
        if self.attestation_version != 1
            || !is_identifier(&self.witness_id)
            || !is_hash(&self.witness_instance_id)
            || !is_identifier(&self.hub_identity)
            || !is_identifier(&self.witness_operator)
            || self.separation_statement.trim().is_empty()
            || self.separation_statement.len() > 2048
            || self.attested_at == 0
            || self.expires_at <= self.attested_at
        {
            return Err(malformed("deployment attestation"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> HubResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, WITNESS_ATTESTATION_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> HubResult<Self> {
        let mut decoder = Decoder::new(bytes, WITNESS_ATTESTATION_DOMAIN)?;
        let value = Self {
            attestation_version: decoder.read_u64()?,
            witness_id: decoder.read_string()?,
            witness_instance_id: decoder.read_string()?,
            hub_identity: decoder.read_string()?,
            posture: WitnessPosture::from_tag(decoder.read_u8()?)?,
            witness_operator: decoder.read_string()?,
            separation_statement: decoder.read_string()?,
            attested_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessDeploymentAttestationV1 {
    pub attestation: WitnessDeploymentAttestationV1,
    pub signature_hex: String,
}

impl SignedWitnessDeploymentAttestationV1 {
    pub fn sign(
        attestation: WitnessDeploymentAttestationV1,
        authorisation_account: &Account,
    ) -> HubResult<Self> {
        let bytes = attestation.canonical_bytes()?;
        Ok(Self {
            signature_hex: sign_canonical(authorisation_account, &bytes),
            attestation,
        })
    }

    /// Verified against the **offline** authorisation key, never the receipt
    /// key. Collapsing the two would make the recovery authorisation
    /// decorative: compromising the running witness would be enough to forge
    /// both a resynchronisation and the statement about where it runs.
    pub fn verify_against_pinned_key(&self, authorisation_address: &str) -> HubResult<()> {
        let bytes = self.attestation.canonical_bytes()?;
        verify_canonical(authorisation_address, &bytes, &self.signature_hex)
    }
}

/// What the witness sends back for a reservation attempt: exactly one of a
/// signed receipt or a signed refusal. Silence is neither, and the Hub must
/// treat silence as an unreachable witness rather than as a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubWitnessAnswerV1 {
    Receipt(Box<SignedHubWitnessReceiptV1>),
    Refusal(Box<SignedHubWitnessRefusalV1>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubWitnessStatusRequestV1 {
    pub hub_identity: String,
    pub witness_id: String,
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn request() -> HubAnchorRequestV1 {
        HubAnchorRequestV1 {
            request_version: 1,
            request_id: "op-1".into(),
            hub_identity: "1HubAddress".into(),
            witness_id: "witness-alpha".into(),
            witness_epoch: 1,
            settlement_profile: "hpay-hvm-shared-registry-v2".into(),
            network_instance_id: "11".repeat(32),
            binding_commitment: "aa".repeat(32),
            channel_id: "0123456789abcdef".into(),
            reuse_version: 1,
            serial: 4,
            previous_bill_commitment: "bb".repeat(32),
            proposed_bill_commitment: "cc".repeat(32),
            counter_value: 9,
            hub_journal_sequence: 12,
            hub_journal_head_hash: "dd".repeat(32),
            hub_state_commitment: "ee".repeat(32),
            created_at: 1_700_000_000,
            expires_at: 1_700_000_060,
        }
    }

    #[test]
    fn the_request_round_trips_and_every_field_changes_the_commitment() {
        let base = request();
        let bytes = base.canonical_bytes().unwrap();
        assert_eq!(
            HubAnchorRequestV1::from_canonical_bytes(&bytes).unwrap(),
            base
        );

        let baseline = base.commitment().unwrap();
        let mut serial_moved = base.clone();
        serial_moved.serial += 1;
        assert_ne!(serial_moved.commitment().unwrap(), baseline);

        let mut bill_moved = base.clone();
        bill_moved.proposed_bill_commitment = "ff".repeat(32);
        assert_ne!(bill_moved.commitment().unwrap(), baseline);

        let mut counter_moved = base.clone();
        counter_moved.counter_value += 1;
        assert_ne!(counter_moved.commitment().unwrap(), baseline);
    }

    #[test]
    fn a_request_lifetime_wider_than_the_bounded_window_is_refused() {
        let mut wide = request();
        wide.expires_at = wide.created_at + MAX_ANCHOR_LIFETIME_SECS + 1;
        assert!(wide.validate_shape().is_err());
        assert!(wide.canonical_bytes().is_err());
    }

    #[test]
    fn a_signed_request_verifies_only_against_the_identity_it_names() {
        let account = Account::create_by("rollback-anchor-request-signer").unwrap();
        let other = Account::create_by("rollback-anchor-other-signer").unwrap();
        let mut base = request();
        base.hub_identity = account.readable().to_owned();
        let signed = SignedHubAnchorRequestV1::sign(base.clone(), &account).unwrap();
        signed.verify().unwrap();

        let mut impostor = signed.clone();
        impostor.request.hub_identity = other.readable().to_owned();
        assert!(impostor.verify().is_err());
    }

    #[test]
    fn the_refusal_reason_identifiers_match_the_recovery_document() {
        assert_eq!(
            WitnessRefusalReason::HubBehindWitness.identifier(),
            "rollback_anchor_hub_behind_witness"
        );
        assert_eq!(
            WitnessRefusalReason::ForkAtSerial.identifier(),
            "rollback_anchor_fork_at_serial"
        );
        assert_eq!(
            WitnessRefusalReason::CounterSkipped.identifier(),
            "rollback_anchor_counter_skipped"
        );
        assert_eq!(
            WitnessRefusalReason::WitnessBehindHub.identifier(),
            "rollback_anchor_witness_behind_hub"
        );
        for reason in [
            WitnessRefusalReason::HubBehindWitness,
            WitnessRefusalReason::ForkAtSerial,
            WitnessRefusalReason::WitnessBehindHub,
        ] {
            let tag = reason.tag();
            assert_eq!(WitnessRefusalReason::from_tag(tag).unwrap(), reason);
        }
    }

    #[test]
    fn a_message_of_one_type_cannot_be_read_as_another() {
        let request_bytes = request().canonical_bytes().unwrap();
        assert!(
            HubWitnessReceiptV1::from_canonical_bytes(&request_bytes).is_err(),
            "domain separation must stop a request being verified as a receipt"
        );
    }
}

#[cfg(test)]
mod latching_tests {
    use super::*;

    /// A rollback is a durable, human-resolved condition and condemns the
    /// channel. A dropped packet is not. Getting this wrong in either
    /// direction is dangerous: latch too little and a rolled-back Hub keeps
    /// signing, latch too much and one network blip permanently retires a
    /// channel, which is how an anchor gets switched off at 3am.
    #[test]
    fn only_a_disagreement_about_history_condemns_a_channel() {
        for condemning in [
            REFUSAL_HUB_BEHIND_WITNESS,
            REFUSAL_FORK_AT_SERIAL,
            REFUSAL_COUNTER_SKIPPED,
            REFUSAL_WITNESS_BEHIND_HUB,
            REFUSAL_WITNESS_INSTANCE_CHANGED,
            REFUSAL_REPLAY_MISMATCH,
        ] {
            assert!(
                refusal_condemns_the_channel(&format!("{condemning}: something happened")),
                "{condemning} is a disagreement about history"
            );
        }
        for transient in [
            REFUSAL_WITNESS_UNREACHABLE,
            REFUSAL_EXPIRED,
            REFUSAL_MALFORMED_REQUEST,
            REFUSAL_RECEIPT_NOT_BOUND,
        ] {
            assert!(
                !refusal_condemns_the_channel(&format!("{transient}: something happened")),
                "{transient} refuses this signature, not the channel"
            );
        }
    }
}
