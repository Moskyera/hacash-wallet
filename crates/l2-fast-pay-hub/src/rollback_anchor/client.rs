//! The Hub's witness client, and the degradation guard that keeps it from
//! quietly becoming a file on the Hub's own disk.
//!
//! This is the **only** witness client. There is no in-process witness, no
//! `file://` backend and no local mode; see the note at the top of
//! `witness.rs`.
//!
//! Every verification here fails closed. An unreachable witness is not
//! evidence, a malformed receipt is not a receipt, and a counter behind the
//! Hub's own record is a refusal, never a warning.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::protocol::{
    HubAnchorRequestV1, HubWitnessAnswerV1, HubWitnessStatusRequestV1, HubWitnessStatusV1,
    MAX_WITNESS_MESSAGE_AGE_SECS, REFUSAL_ATTESTATION_MISSING_OR_EXPIRED,
    REFUSAL_KEY_CUSTODY_NOT_DISTINCT, REFUSAL_RECEIPT_NOT_BOUND, REFUSAL_WITNESS_BEHIND_HUB,
    REFUSAL_WITNESS_INSTANCE_CHANGED, REFUSAL_WITNESS_IS_NOT_EXTERNAL, REFUSAL_WITNESS_UNREACHABLE,
    SignedHubAnchorRequestV1, SignedHubWitnessReceiptV1, SignedHubWitnessStatusV1,
    SignedWitnessDeploymentAttestationV1, WitnessPosture,
};
use crate::error::{HubError, HubResult};
use crate::readiness::is_mainnet_pilot_profile;

/// Where the configured witness endpoint sits relative to this host.
///
/// Honest naming: this is a **configuration lint, not a security boundary**.
/// It catches an operator who pointed the Hub at a witness on the same box. It
/// is defeated by a port forward or by a container on the same physical host
/// with a routable address, and no check in this protocol can prove the
/// witness is outside the Hub's failure domain. What it does buy is that the
/// weak configuration cannot be reached by accident on a mainnet profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessEndpointPosture {
    /// A remote host over TLS. The configuration this design is for.
    External,
    /// Loopback, link-local, unspecified, or plaintext transport. Permitted
    /// only off the mainnet profiles, and **published** wherever it holds so
    /// that nobody reads the anchor flag without also reading this.
    SameHostOrPlaintext,
}

impl WitnessEndpointPosture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::SameHostOrPlaintext => "same_host_or_plaintext",
        }
    }

    pub fn is_local(self) -> bool {
        self == Self::SameHostOrPlaintext
    }
}

/// Absent or malformed configuration reads as *no witness*, which reads as
/// `external_rollback_anchor_ready = false`. It never reads as "anchor not
/// required".
#[derive(Debug, Clone)]
pub struct RollbackAnchorConfig {
    pub witness_url: String,
    pub witness_id: String,
    pub witness_epoch: u64,
    /// Pinned online key. Verifies receipts, refusals and status probes.
    pub witness_receipt_address: String,
    /// Pinned offline key. Verifies deployment attestations and, when it is
    /// built, resynchronisation authorisation.
    pub witness_authorisation_address: String,
    pub attestation: SignedWitnessDeploymentAttestationV1,
    pub request_timeout: Duration,
}

/// A signed witness status the Hub has verified against its pinned key and its
/// own durable position.
#[derive(Debug, Clone)]
pub struct VerifiedWitnessStatus {
    pub status: HubWitnessStatusV1,
    pub verified_unix: u64,
}

/// A signed reservation receipt the Hub has verified against the exact request
/// it durably persisted before sending.
#[derive(Debug, Clone)]
pub struct VerifiedAnchorReceipt {
    pub receipt: super::protocol::HubWitnessReceiptV1,
    pub verified_unix: u64,
}

/// What the Hub durably knows about its witness. This is the Hub's half of the
/// anchor: the counter it last recorded, so that "at least what it last
/// recorded" is a comparison against durable state rather than memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackAnchorPin {
    #[serde(default)]
    pub witness_id: String,
    /// Pinned on first contact, exactly as `MobileWitnessState` pins
    /// `node_profile_id` and `genesis_identifier`. A change means a re-created
    /// store, which is the cheapest attack on this whole design.
    #[serde(default)]
    pub witness_instance_id: String,
    #[serde(default)]
    pub highest_counter_value: u64,
    #[serde(default)]
    pub updated_unix: u64,
}

/// The published, measured evidence behind `external_rollback_anchor_ready`.
///
/// A guarantee whose strength depends on who holds a key should not be
/// reported as a single boolean with the key holder hidden, so the posture and
/// the operator travel with the flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackAnchorEvidenceV1 {
    pub schema: String,
    pub witness_id: String,
    pub witness_instance_id: String,
    pub witness_boot_id: String,
    pub witness_operator: String,
    pub witness_posture: String,
    pub witness_endpoint_posture: String,
    pub witness_endpoint_is_local: bool,
    pub attestation_valid: bool,
    pub attestation_expires_unix: u64,
    pub key_custody_distinct: bool,
    pub instance_pin_holds: bool,
    pub counter_never_decreased: bool,
    pub startup_probe_agreed: bool,
    pub counter_value: u64,
    pub verified_unix: u64,
    pub channels_latched_in_refusal: u64,
}

pub const ROLLBACK_ANCHOR_EVIDENCE_SCHEMA: &str = "hpay-hub-rollback-anchor-evidence/1";

fn unreachable(detail: &str) -> HubError {
    HubError::Node(format!(
        "{REFUSAL_WITNESS_UNREACHABLE}: the external rollback anchor witness could not be reached \
         ({detail}). An unreachable oracle is not evidence: refusing rather than signing"
    ))
}

fn endpoint_is_local(url: &reqwest::Url) -> bool {
    url.host_str().is_none_or(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host.parse::<std::net::IpAddr>().is_ok_and(|address| {
                address.is_loopback()
                    || address.is_unspecified()
                    || match address {
                        std::net::IpAddr::V4(v4) => v4.is_link_local(),
                        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
                    }
            })
    })
}

pub struct RollbackAnchorClient {
    config: RollbackAnchorConfig,
    http: reqwest::Client,
    hub_identity: String,
    endpoint_posture: WitnessEndpointPosture,
    reserve_url: String,
    status_url: String,
}

impl RollbackAnchorClient {
    /// Builds the client and runs every hard refusal that does not need the
    /// network. No I/O happens here, so a configured-but-unreachable witness
    /// is a live client whose probes fail — which is exactly what the
    /// readiness measurement must be able to observe.
    pub fn connect(
        config: RollbackAnchorConfig,
        hub_identity: &str,
        hub_signing_address: &str,
        deployment_profile: &str,
    ) -> HubResult<Self> {
        if config.witness_id.trim().is_empty() || config.witness_epoch == 0 {
            return Err(HubError::State(
                "rollback anchor witness id and epoch must be pinned".into(),
            ));
        }
        // Hard refusal 2: distinct key custody. Weak - defeated by generating
        // a second key on the same host - but the mistake it catches is real.
        if config.witness_receipt_address.trim() == config.witness_authorisation_address.trim()
            || config.witness_receipt_address.trim() == hub_signing_address.trim()
            || config.witness_authorisation_address.trim() == hub_signing_address.trim()
        {
            return Err(HubError::State(format!(
                "{REFUSAL_KEY_CUSTODY_NOT_DISTINCT}: the witness receipt key, the witness \
                 authorisation key and the Hub signing key must be three distinct keys"
            )));
        }
        // Hard refusal 5: the attestation must be present and verify against
        // the pinned offline key before anything else is attempted.
        config
            .attestation
            .verify_against_pinned_key(&config.witness_authorisation_address)
            .map_err(|error| {
                HubError::State(format!(
                    "{REFUSAL_ATTESTATION_MISSING_OR_EXPIRED}: the witness deployment attestation \
                     does not verify against the pinned offline authorisation key: {error}"
                ))
            })?;
        let attestation = &config.attestation.attestation;
        if attestation.witness_id != config.witness_id
            || attestation.hub_identity.trim() != hub_identity.trim()
        {
            return Err(HubError::State(format!(
                "{REFUSAL_ATTESTATION_MISSING_OR_EXPIRED}: the witness deployment attestation is \
                 bound to a different witness or Hub"
            )));
        }

        let url = reqwest::Url::parse(&config.witness_url)
            .map_err(|_| HubError::State("rollback anchor witness URL is invalid".into()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HubError::State(
                "rollback anchor witness URL must not carry credentials".into(),
            ));
        }
        let local_or_plaintext = endpoint_is_local(&url) || url.scheme() != "https";
        // Hard refusal 1 on the profiles where this flag gates money. Off
        // those profiles the deviation is recorded and published rather than
        // silently tolerated - see `RollbackAnchorEvidenceV1`.
        if local_or_plaintext && is_mainnet_pilot_profile(deployment_profile) {
            return Err(HubError::State(format!(
                "{REFUSAL_WITNESS_IS_NOT_EXTERNAL}: a mainnet profile requires a witness reached \
                 over HTTPS at a host that is not this one. A witness on this host shares the \
                 filesystem, the backup set and the restore with the state it is supposed to \
                 guard, which is the option this design rejected"
            )));
        }
        let endpoint_posture = if local_or_plaintext {
            WitnessEndpointPosture::SameHostOrPlaintext
        } else {
            WitnessEndpointPosture::External
        };

        let http = reqwest::Client::builder()
            .connect_timeout(config.request_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("HPAYFastPayHubAnchor/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                HubError::State(format!(
                    "cannot create rollback anchor HTTP client: {error}"
                ))
            })?;
        let base = config.witness_url.trim_end_matches('/').to_owned();
        Ok(Self {
            reserve_url: format!("{base}{}", super::ANCHOR_RESERVE_PATH),
            status_url: format!("{base}{}", super::ANCHOR_STATUS_PATH),
            config,
            http,
            hub_identity: hub_identity.trim().to_owned(),
            endpoint_posture,
        })
    }

    pub fn witness_id(&self) -> &str {
        &self.config.witness_id
    }

    pub fn witness_epoch(&self) -> u64 {
        self.config.witness_epoch
    }

    pub fn hub_identity(&self) -> &str {
        &self.hub_identity
    }

    pub fn endpoint_posture(&self) -> WitnessEndpointPosture {
        self.endpoint_posture
    }

    pub fn posture(&self) -> WitnessPosture {
        self.config.attestation.attestation.posture
    }

    pub fn witness_operator(&self) -> &str {
        &self.config.attestation.attestation.witness_operator
    }

    pub fn attestation_expires_unix(&self) -> u64 {
        self.config.attestation.attestation.expires_at
    }

    /// The attestation is a statement with a bounded life. Expired means the
    /// operator has to sign it again rather than set it once and forget.
    pub fn attestation_is_valid_at(&self, now_unix: u64) -> bool {
        let attestation = &self.config.attestation.attestation;
        attestation.attested_at <= now_unix.saturating_add(5) && attestation.expires_at > now_unix
    }

    /// Live, signed liveness and position probe. Advances nothing.
    pub async fn probe(
        &self,
        pin: &RollbackAnchorPin,
        now_unix: u64,
    ) -> HubResult<VerifiedWitnessStatus> {
        let nonce = hex::encode(sys::sha2(uuid::Uuid::new_v4().as_bytes()));
        let request = HubWitnessStatusRequestV1 {
            hub_identity: self.hub_identity.clone(),
            witness_id: self.config.witness_id.clone(),
            nonce: nonce.clone(),
        };
        let response = self
            .http
            .post(&self.status_url)
            .json(&request)
            .send()
            .await
            .map_err(|error| unreachable(&error.to_string()))?;
        if !response.status().is_success() {
            return Err(unreachable(&format!("HTTP {}", response.status())));
        }
        let signed: SignedHubWitnessStatusV1 = response
            .json()
            .await
            .map_err(|error| unreachable(&format!("unreadable answer: {error}")))?;
        self.verify_status(&signed, &nonce, pin, now_unix)
    }

    fn verify_status(
        &self,
        signed: &SignedHubWitnessStatusV1,
        nonce: &str,
        pin: &RollbackAnchorPin,
        now_unix: u64,
    ) -> HubResult<VerifiedWitnessStatus> {
        signed.verify_against_pinned_key(&self.config.witness_receipt_address)?;
        let status = &signed.status;
        if status.witness_id != self.config.witness_id
            || status.witness_epoch != self.config.witness_epoch
            || status.hub_identity != self.hub_identity
            || status.nonce != nonce
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: the witness status is not bound to this Hub, this \
                 witness epoch, or this probe"
            )));
        }
        if now_unix.saturating_sub(status.observed_at) > MAX_WITNESS_MESSAGE_AGE_SECS
            || status.observed_at > now_unix.saturating_add(MAX_WITNESS_MESSAGE_AGE_SECS)
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_WITNESS_UNREACHABLE}: the witness status is outside the freshness window"
            )));
        }
        // Hard refusal 3: pinned store identity. This does not detect
        // co-location; it detects the effect an attacker actually wants, which
        // is a counter that was reset.
        if !pin.witness_instance_id.is_empty()
            && pin.witness_instance_id != status.witness_instance_id
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_WITNESS_INSTANCE_CHANGED}: the witness is answering from a different \
                 durable store than the one this Hub pinned. A fresh store agrees with \
                 everything, which is amnesia rather than agreement"
            )));
        }
        if self.config.attestation.attestation.witness_instance_id != status.witness_instance_id {
            return Err(HubError::Node(format!(
                "{REFUSAL_ATTESTATION_MISSING_OR_EXPIRED}: the deployment attestation describes a \
                 different witness store than the one answering"
            )));
        }
        // Hard refusal 4: the counter is never observed to decrease.
        if status.counter_value < pin.highest_counter_value {
            return Err(HubError::Node(format!(
                "{REFUSAL_WITNESS_BEHIND_HUB}: the witness counter is {} but this Hub has already \
                 recorded {}. The anchor has gone backwards: it has no record of positions this \
                 Hub has already signed. Do not resynchronise the witness to the Hub; see \
                 docs/l2/ROLLBACK-ANCHOR-RECOVERY.md",
                status.counter_value, pin.highest_counter_value
            )));
        }
        Ok(VerifiedWitnessStatus {
            status: status.clone(),
            verified_unix: now_unix,
        })
    }

    /// Reserve one exact bill position. The request must already be durable on
    /// the Hub before this is called.
    pub async fn reserve(
        &self,
        signed_request: &SignedHubAnchorRequestV1,
        pin: &RollbackAnchorPin,
        now_unix: u64,
    ) -> HubResult<VerifiedAnchorReceipt> {
        let request_commitment = signed_request.request.commitment()?;
        let response = self
            .http
            .post(&self.reserve_url)
            .json(signed_request)
            .send()
            .await
            .map_err(|error| unreachable(&error.to_string()))?;
        if !response.status().is_success() {
            return Err(unreachable(&format!("HTTP {}", response.status())));
        }
        let answer: HubWitnessAnswerV1 = response
            .json()
            .await
            .map_err(|error| unreachable(&format!("unreadable answer: {error}")))?;
        match answer {
            HubWitnessAnswerV1::Receipt(receipt) => self.verify_receipt(
                &receipt,
                &signed_request.request,
                &request_commitment,
                pin,
                now_unix,
            ),
            HubWitnessAnswerV1::Refusal(refusal) => {
                refusal.verify_against_pinned_key(&self.config.witness_receipt_address)?;
                let refusal = &refusal.refusal;
                if refusal.witness_id != self.config.witness_id
                    || refusal.hub_identity != self.hub_identity
                    || refusal.request_id != signed_request.request.request_id
                {
                    return Err(HubError::Node(format!(
                        "{REFUSAL_RECEIPT_NOT_BOUND}: the witness refusal is not bound to this \
                         Hub's request"
                    )));
                }
                Err(HubError::State(format!(
                    "{identifier}: {explanation}. Witness {witness} instance {instance} holds \
                     counter {counter} and serial {serial} for this channel with bill commitment \
                     {bill}; this Hub asked to sign serial {asked} at counter {asked_counter}. \
                     Follow docs/l2/ROLLBACK-ANCHOR-RECOVERY.md and do NOT re-sign the gap",
                    identifier = refusal.reason.identifier(),
                    explanation = refusal.reason.explanation(),
                    witness = refusal.witness_id,
                    instance = refusal.witness_instance_id,
                    counter = refusal.observed_counter_value,
                    serial = refusal.observed_serial,
                    bill = refusal.observed_bill_commitment,
                    asked = signed_request.request.serial,
                    asked_counter = signed_request.request.counter_value,
                )))
            }
        }
    }

    fn verify_receipt(
        &self,
        signed: &SignedHubWitnessReceiptV1,
        request: &HubAnchorRequestV1,
        request_commitment: &str,
        pin: &RollbackAnchorPin,
        now_unix: u64,
    ) -> HubResult<VerifiedAnchorReceipt> {
        // 1. Signature against the pinned receipt key.
        signed.verify_against_pinned_key(&self.config.witness_receipt_address)?;
        let receipt = &signed.receipt;
        // 2. Witness identity and key generation.
        if receipt.witness_id != self.config.witness_id
            || receipt.witness_epoch != self.config.witness_epoch
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: the receipt names a different witness or epoch than \
                 the pinned configuration"
            )));
        }
        // 3. Pinned durable store.
        if !pin.witness_instance_id.is_empty()
            && pin.witness_instance_id != receipt.witness_instance_id
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_WITNESS_INSTANCE_CHANGED}: the receipt came from a different witness \
                 store than the one this Hub pinned"
            )));
        }
        // 4. and 5. The receipt must match the exact request this Hub
        // persisted before sending. A receipt harvested from the wire matches
        // nothing.
        if receipt.request_id != request.request_id
            || receipt.request_commitment != request_commitment
            || receipt.hub_identity != request.hub_identity
            || receipt.binding_commitment != request.binding_commitment
            || receipt.serial != request.serial
            || receipt.proposed_bill_commitment != request.proposed_bill_commitment
            || receipt.counter_value != request.counter_value
        {
            return Err(HubError::Node(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: the receipt does not restate the exact request this \
                 Hub persisted. A receipt authorises one exact bill at one exact serial, and this \
                 one does not"
            )));
        }
        // 6. previous + 1 == counter. Anything else means reservations this
        // Hub does not account for.
        if receipt.previous_counter_value.saturating_add(1) != receipt.counter_value {
            return Err(HubError::State(format!(
                "{}: the witness reports the counter moved from {} to {}, so reservations this \
                 Hub does not account for were consumed. A second live Hub sharing this identity \
                 is the usual cause",
                super::protocol::REFUSAL_COUNTER_SKIPPED,
                receipt.previous_counter_value,
                receipt.counter_value
            )));
        }
        // A receipt that *advances* the counter must start from at least where
        // this Hub already is. A receipt whose counter the Hub has already
        // recorded is a re-attestation of a reservation it already holds - the
        // honest retry after a crash - and its `previous_counter_value` is
        // rightly the historical one. The two are distinguished rather than
        // conflated, because refusing the retry would strand the operation and
        // refusing nothing would let an amnesiac witness through. A re-record
        // at a different position cannot reach here: the receipt has already
        // been required to restate this request's exact `counter_value`.
        if receipt.counter_value > pin.highest_counter_value
            && receipt.previous_counter_value < pin.highest_counter_value
        {
            return Err(HubError::State(format!(
                "{REFUSAL_WITNESS_BEHIND_HUB}: the witness believes the counter was {} before \
                 this reservation, but this Hub has durably recorded {}",
                receipt.previous_counter_value, pin.highest_counter_value
            )));
        }
        // 7. Freshness, re-read from the wall clock by the caller immediately
        // before key use.
        if receipt.accepted_at < request.created_at || receipt.receipt_expires_at <= now_unix {
            return Err(HubError::Node(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: the receipt is outside the bounded window of the \
                 request it answers"
            )));
        }
        Ok(VerifiedAnchorReceipt {
            receipt: receipt.clone(),
            verified_unix: now_unix,
        })
    }

    /// Assemble the published evidence from one live probe.
    pub fn evidence_from(
        &self,
        status: &VerifiedWitnessStatus,
        startup_probe_agreed: bool,
        channels_latched_in_refusal: u64,
        now_unix: u64,
    ) -> RollbackAnchorEvidenceV1 {
        RollbackAnchorEvidenceV1 {
            schema: ROLLBACK_ANCHOR_EVIDENCE_SCHEMA.into(),
            witness_id: status.status.witness_id.clone(),
            witness_instance_id: status.status.witness_instance_id.clone(),
            witness_boot_id: status.status.witness_boot_id.clone(),
            witness_operator: self.witness_operator().to_owned(),
            witness_posture: self.posture().as_str().to_owned(),
            witness_endpoint_posture: self.endpoint_posture.as_str().to_owned(),
            witness_endpoint_is_local: self.endpoint_posture.is_local(),
            attestation_valid: self.attestation_is_valid_at(now_unix),
            attestation_expires_unix: self.attestation_expires_unix(),
            key_custody_distinct: true,
            instance_pin_holds: true,
            counter_never_decreased: true,
            startup_probe_agreed,
            counter_value: status.status.counter_value,
            verified_unix: status.verified_unix,
            channels_latched_in_refusal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_link_local_and_unspecified_endpoints_are_all_recognised_as_local() {
        for url in [
            "http://127.0.0.1:9000",
            "https://localhost:9000",
            "https://[::1]:9000",
            "https://169.254.10.4:9000",
            "https://[fe80::1]:9000",
            "https://0.0.0.0:9000",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                endpoint_is_local(&parsed),
                "{url} must be recognised as this host"
            );
        }
        for url in ["https://witness.example.org", "https://203.0.113.9:9000"] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(!endpoint_is_local(&parsed), "{url} is not this host");
        }
    }
}
