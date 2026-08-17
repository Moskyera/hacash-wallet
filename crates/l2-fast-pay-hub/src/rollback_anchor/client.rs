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

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
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
/// Honest naming: this is a **configuration lint, not a security boundary**,
/// and it is decided from the URL string alone — see [`endpoint_is_local`]. It
/// catches an operator who *wrote down* this host: a loopback or link-local
/// literal, the unspecified address, a `localhost` name, or plaintext
/// transport. It does not catch a hostname that resolves here, because nothing
/// resolves it. It is further defeated by a port forward or by a container on
/// the same physical host with a routable address, and no check in this
/// protocol can prove the witness is outside the Hub's failure domain. What it
/// does buy is that the *written-down* weak configuration cannot be reached by
/// accident on a mainnet profile.
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
///
/// The **signed** form is kept, not the bare receipt. The Hub is not the only
/// party that has to be convinced by this receipt: it travels on with the
/// co-signed bill to the counterparty wallet, which recovers the signing
/// address from the signature and remembers it. Discarding the signature here
/// and keeping only `HubWitnessReceiptV1` would leave the wallet with a witness
/// identity the Hub merely *typed* - `witness_id` is a plain `String` the Hub
/// fills in - and an overlap rule enforced on a string the Hub controls is
/// defeated in one line.
#[derive(Debug, Clone)]
pub struct VerifiedAnchorReceipt {
    pub signed: SignedHubWitnessReceiptV1,
    pub verified_unix: u64,
}

impl VerifiedAnchorReceipt {
    pub fn receipt(&self) -> &super::protocol::HubWitnessReceiptV1 {
        &self.signed.receipt
    }
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
/// the operator travel with the flag. This whole document is published on
/// `/v1/readiness/mainnet` beside the flag it explains - see
/// [`crate::readiness::MainnetReadinessV1::rollback_anchor`].
///
/// It separates two questions a wallet has to be able to answer independently:
///
/// * **Who** holds the witness key - `witness_posture` and `witness_operator`,
///   both taken from the signed deployment attestation. An attestation is a
///   statement, not proof, and is labelled as one.
/// * **Where** the witness sits relative to this Hub - `witness_endpoint_is_local`,
///   `witness_store_in_hub_state_tree` and the derived `witness_co_located`.
///   These are measured by the Hub itself, not attested by anyone.
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
    /// A witness durable store was found inside or beside this Hub's own state
    /// tree, so it is in the backup set that gets restored with the Hub. This
    /// is ADR-001 Option B, which defends against nothing.
    #[serde(default)]
    pub witness_store_in_hub_state_tree: bool,
    /// The verdict: either signal above is enough. `true` means the anchor is
    /// not outside the failure domain it exists to guard, whatever the attested
    /// posture says.
    #[serde(default)]
    pub witness_co_located: bool,
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

/// Bounds on the co-location scan. A guard that costs an unbounded traversal
/// at every start is a guard someone deletes, so it is deliberately shallow,
/// counted, and finished in milliseconds.
const MAX_SCANNED_ENTRIES: usize = 4_096;
const MAX_SCAN_DEPTH: usize = 2;
/// Only the first line of a candidate is ever read, and only this much of it.
const WITNESS_LOG_HEADER_PROBE_BYTES: u64 = 4_096;

/// Is this file a witness durable store?
///
/// Recognised by content, never by name: a store renamed to `notes.txt` is
/// still in the backup set, and a check that can be defeated by `mv` is not a
/// check. Every witness store opens with one header line carrying
/// [`super::WITNESS_LOG_SCHEMA`], written at store creation by
/// `WitnessStore::open`.
fn is_witness_store(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut reader = BufReader::new(file.take(WITNESS_LOG_HEADER_PROBE_BYTES));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    let Ok(record) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
        return false;
    };
    record.get("record").and_then(serde_json::Value::as_str) == Some("header")
        && record.get("schema").and_then(serde_json::Value::as_str)
            == Some(super::WITNESS_LOG_SCHEMA)
}

/// Look for a witness durable store **inside or beside** the Hub's own state
/// tree, and return the first one found.
///
/// # What this proves, and what it does not
///
/// ADR-001 rejected Option B - a counter in the Hub's own filesystem - because
/// it "shares the filesystem, the same backup set, and the same restore as the
/// state it is supposed to guard". Option C degrades into exactly that the
/// moment the witness's store is written into the directory tree that gets
/// snapshotted with the Hub. `key_custody_distinct` cannot see it: that check
/// compares three *addresses*, and Option B built with three freshly generated
/// keys passes it with room to spare. This is the missing half.
///
/// It proves one narrow thing: **a witness durable store is in this Hub's
/// backup set.** That is a fact about the Hub's own failure domain, verified
/// locally, needing no cooperation from the witness and unaffected by anything
/// the witness says - which is precisely why it is done this way rather than by
/// asking the witness where its store lives. A witness that reported its own
/// path would be trusted to incriminate itself.
///
/// It does not prove that the store found is *the* store this Hub's witness is
/// answering from, and it cannot: a store moved one directory further out, onto
/// a second disk on the same host, or into a container volume mounted from the
/// same snapshot is invisible here. A determined operator defeats it in one
/// `mv`. The goal is not impossibility. The goal is that the weak configuration
/// cannot be reached by accident, cannot be reached by drift, and on a mainnet
/// profile cannot be reached at all without moving the file the refusal names.
///
/// # Where it looks, and where it deliberately stops
///
/// **Inside**: the state directory and [`MAX_SCAN_DEPTH`] levels beneath it.
/// Everything there is the Hub's own and is in its backup set by definition.
///
/// **Beside**: files sitting *directly* in the state directory's parent, and no
/// deeper. This is the shape the live gap took - one deployment directory
/// holding the Hub state, the witness store and every secret key.
///
/// It does **not** sweep sibling directories under the parent, and that is a
/// deliberate trade rather than an oversight. A Hub whose state lives in a
/// shared or shallow parent - a temp directory, a user profile, a drive root -
/// would otherwise drag unrelated trees into a check whose mainnet verdict is a
/// hard startup refusal. Refusing a correct deployment over an unrelated file is
/// how a guard gets switched off at 3am, and this section's own advice is that
/// the weak configuration should be loud, not that every configuration should
/// be suspect. The cost is a real blind spot: a witness store in a *sibling*
/// directory of the Hub's state is very likely in the same backup set and is
/// not seen here. The endpoint check catches it whenever that witness is also
/// reached on this host, which is the overwhelmingly common case, and the
/// published posture tells the truth either way.
pub fn witness_store_in_hub_state_tree(hub_state_path: &Path) -> Option<PathBuf> {
    let state_directory = hub_state_path.parent()?;
    let mut budget = MAX_SCANNED_ENTRIES;
    if let Some(found) = scan_for_witness_store(state_directory, MAX_SCAN_DEPTH, &mut budget) {
        return Some(found);
    }
    state_directory
        .parent()
        .and_then(|parent| scan_for_witness_store(parent, 0, &mut budget))
}

/// `remaining_depth` of `0` means "the files directly in this directory, and no
/// subdirectory".
fn scan_for_witness_store(
    directory: &Path,
    remaining_depth: usize,
    budget: &mut usize,
) -> Option<PathBuf> {
    if *budget == 0 {
        return None;
    }
    let entries = std::fs::read_dir(directory).ok()?;
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        // `file_type` does not follow symlinks, so a link to a directory is
        // never descended into and the walk cannot loop.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if remaining_depth > 0 {
                directories.push(entry.path());
            }
        } else if file_type.is_file() && is_witness_store(&entry.path()) {
            return Some(entry.path());
        }
    }
    directories
        .into_iter()
        .find_map(|child| scan_for_witness_store(&child, remaining_depth - 1, budget))
}

/// Is this *literal* address one of the forms that names this host?
///
/// The IPv4-in-IPv6 forms are unwrapped because `::ffff:127.0.0.1` and
/// `::127.0.0.1` are loopback written a different way, while
/// `Ipv6Addr::is_loopback` is true only for `::1`. Without the unwrapping a
/// mapped literal reads as an ordinary routable v6 address, which is the
/// document's own "loopback or link-local" claim failing on a spelling.
fn address_is_local(address: std::net::IpAddr) -> bool {
    fn v4_is_local(v4: std::net::Ipv4Addr) -> bool {
        v4.is_loopback() || v4.is_unspecified() || v4.is_link_local()
    }
    match address {
        std::net::IpAddr::V4(v4) => v4_is_local(v4),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4().is_some_and(v4_is_local)
        }
    }
}

/// RFC 6761 section 6.3 reserves `localhost` and every name beneath it, and
/// requires them to resolve to loopback. `witness.localhost` is therefore this
/// host by definition rather than by lookup, which is the only kind of "by
/// definition" this function is allowed to use.
///
/// The rightmost label is what decides it, so `localhost.example.org` — an
/// ordinary registrable name — is not caught.
fn host_is_localhost_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .eq_ignore_ascii_case("localhost")
}

/// Hard refusal 1, and **it reads the URL string and nothing else.**
///
/// It performs no DNS resolution and enumerates no local interface. So
/// `https://witness.example.org/` with an `A` record of `127.0.0.1` is
/// classified [`WitnessEndpointPosture::External`] here and is not refused on a
/// mainnet profile. That is a deliberate limit, not an oversight, and
/// `docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md` section 10 states it in the same words
/// under "Why refusal 1 is lexical": a resolver in
/// [`RollbackAnchorClient::connect`] would put DNS on a startup path that
/// ADR-001 gives no legal way to fail open, would be recomputed against records
/// that change under a running process, and would buy very little over a check
/// that a port forward already defeats.
///
/// What covers the gap instead is refusal 1b (a witness store inside this Hub's
/// own backup set, measured from the filesystem and blind to hostnames),
/// refusal 3 (the pinned `witness_instance_id`, which catches the reset counter
/// a co-located witness is actually used for) and refusal 5 (a named person
/// signing what separates the two failure domains).
fn endpoint_is_local(url: &reqwest::Url) -> bool {
    url.host_str().is_none_or(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host_is_localhost_name(host) || host.parse::<std::net::IpAddr>().is_ok_and(address_is_local)
    })
}

pub struct RollbackAnchorClient {
    config: RollbackAnchorConfig,
    http: reqwest::Client,
    hub_identity: String,
    endpoint_posture: WitnessEndpointPosture,
    /// The witness store found inside or beside this Hub's state tree, if any.
    /// Measured once at construction, from the Hub's own filesystem.
    co_located_store: Option<PathBuf>,
    reserve_url: String,
    status_url: String,
}

impl RollbackAnchorClient {
    /// Builds the client and runs every hard refusal that does not need the
    /// network. No *network* I/O happens here, so a configured-but-unreachable
    /// witness is a live client whose probes fail — which is exactly what the
    /// readiness measurement must be able to observe.
    ///
    /// `hub_state_path` is this Hub's own durable state file, or `None` for a
    /// Hub with no durable storage (which cannot settle at all, so it has
    /// nothing for an anchor to protect). It is read to scan for a witness
    /// store in the Hub's own backup set; that is local filesystem I/O, and it
    /// belongs here precisely so a degraded configuration is a startup fact
    /// rather than a surprise on the first payment.
    pub fn connect(
        config: RollbackAnchorConfig,
        hub_identity: &str,
        hub_signing_address: &str,
        deployment_profile: &str,
        hub_state_path: Option<&Path>,
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

        // Hard refusal 1b: the witness's durable store must not be in this
        // Hub's backup set. Independent of the endpoint check above and not
        // subsumed by it - a witness reached over HTTPS at a routable address
        // can still be writing its counter into the directory that gets
        // restored with this Hub, which is the port-forward case the endpoint
        // check openly admits it cannot see.
        let co_located_store = hub_state_path.and_then(witness_store_in_hub_state_tree);
        if let Some(store) = co_located_store.as_ref()
            && is_mainnet_pilot_profile(deployment_profile)
        {
            return Err(HubError::State(format!(
                "{REFUSAL_WITNESS_IS_NOT_EXTERNAL}: a witness durable store is inside or beside \
                 this Hub's own state tree, at {}. That store shares this Hub's filesystem, its \
                 backup set and its restore, so restoring the Hub restores the counter with it and \
                 the anchor has nothing left to say. Move the witness store onto infrastructure \
                 that is genuinely separate from this Hub's failure domain and re-attest; see \
                 docs/l2/ROLLBACK-ANCHOR-RECOVERY.md section 7",
                store.display()
            )));
        }

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
            co_located_store,
        })
    }

    pub fn witness_id(&self) -> &str {
        &self.config.witness_id
    }

    pub fn witness_epoch(&self) -> u64 {
        self.config.witness_epoch
    }

    /// The durable store the *currently configured* deployment attestation
    /// describes.
    ///
    /// This is the store the witness must be answering from - [`Self::
    /// verify_status`] refuses any status naming a different one - so comparing
    /// it against `RollbackAnchorPin::witness_instance_id` detects a witness
    /// identity change without a single network round trip, and therefore
    /// works when the replacement is itself unreachable.
    pub fn attested_witness_instance_id(&self) -> &str {
        &self.config.attestation.attestation.witness_instance_id
    }

    pub fn hub_identity(&self) -> &str {
        &self.hub_identity
    }

    pub fn endpoint_posture(&self) -> WitnessEndpointPosture {
        self.endpoint_posture
    }

    /// The witness store found in this Hub's own state tree, if any.
    pub fn co_located_store(&self) -> Option<&Path> {
        self.co_located_store.as_deref()
    }

    /// Is the anchor inside the failure domain it exists to guard?
    ///
    /// Either signal is enough on its own: an endpoint that is this host, or a
    /// witness store in this Hub's backup set. Neither can be proven absent -
    /// see [`witness_store_in_hub_state_tree`] and
    /// [`WitnessEndpointPosture`] for what each one is and is not worth - so
    /// this is a `true` that must be believed and a `false` that must not.
    pub fn is_co_located(&self) -> bool {
        self.endpoint_posture.is_local() || self.co_located_store.is_some()
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
        // And it has to be an attestation that is still in force.
        //
        // `attestation_is_valid_at` used to have exactly one caller,
        // `evidence_from`, which only fills in the published document -
        // `connect` verifies the attestation's signature and binding and never
        // looks at `expires_at`. So a Hub whose attestation had lapsed probed
        // happily and went on co-signing on it. The attestation is the only
        // statement of *who runs this witness* and it is deliberately given a
        // bounded life so that the operator has to re-affirm it rather than set
        // it once; letting it lapse silently on the signing path gives away the
        // whole point of the bound. On the full mainnet profile readiness
        // already refused to call the anchor ready without it, so this only
        // aligns the gate with what the document said; on the bounded pilot
        // profile that blocker is waived, and this is the gap.
        if !self.attestation_is_valid_at(now_unix) {
            return Err(HubError::Node(format!(
                "{REFUSAL_ATTESTATION_MISSING_OR_EXPIRED}: the witness deployment attestation was \
                 valid until {} and it is now {now_unix}. Re-attest with the witness operator's \
                 offline authorisation key; the anchor does not vouch on a lapsed statement of who \
                 runs the witness",
                self.config.attestation.attestation.expires_at
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
            signed: signed.clone(),
            verified_unix: now_unix,
        })
    }

    /// The pinned online key every receipt, refusal and status must verify
    /// against. Exposed so a receipt reloaded from this Hub's own durable state
    /// can be re-verified before it is handed on, rather than trusted because
    /// it came off the local disk.
    pub fn witness_receipt_address(&self) -> &str {
        &self.config.witness_receipt_address
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
            // The path itself is deliberately not published: the verdict is
            // everyone's business, the Hub's disk layout is not.
            witness_store_in_hub_state_tree: self.co_located_store.is_some(),
            witness_co_located: self.is_co_located(),
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

    /// Loopback and link-local written in their IPv4-in-IPv6 forms, and the
    /// names RFC 6761 reserves for loopback, are the same host as `127.0.0.1`
    /// and `localhost`. A lint that only recognises one spelling of an address
    /// it names is not honest about the class it claims to cover.
    #[test]
    fn ipv4_in_ipv6_loopback_and_localhost_subdomains_are_this_host() {
        for url in [
            // `Ipv6Addr::is_loopback` is true only for `::1`, so these two read
            // as routable v6 addresses unless the embedded v4 is unwrapped.
            "https://[::ffff:127.0.0.1]:9000",
            "https://[::ffff:169.254.10.4]:9000",
            "https://[::127.0.0.1]:9000",
            // RFC 6761 section 6.3 reserves `localhost` and everything under
            // it, and requires it to resolve to loopback.
            "https://witness.localhost:9000",
            "https://a.b.localhost:9000",
            "https://LOCALHOST.:9000",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                endpoint_is_local(&parsed),
                "{url} must be recognised as this host"
            );
        }
        // The unwrapping must not drag routable addresses in with it, and a
        // registrable name that merely contains the label is not reserved.
        for url in [
            "https://[::ffff:203.0.113.9]:9000",
            "https://[2001:db8::1]:9000",
            "https://localhost.example.org:9000",
            "https://notlocalhost:9000",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(!endpoint_is_local(&parsed), "{url} is not this host");
        }
    }

    /// The check reads the URL and nothing else. Pinned as a test because the
    /// document now says so out loud, and because a future "improvement" that
    /// adds a resolver would put DNS on a startup path that has no legal way
    /// to fail open.
    #[test]
    fn the_protocol_document_does_not_promise_a_resolution_the_code_does_not_do() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md"),
        )
        .expect("the protocol document this module implements must be readable");
        // Wrapping is a typesetting choice, so match on the prose rather than
        // on where the lines happen to break.
        let document = source.split_whitespace().collect::<Vec<_>>().join(" ");

        for promise in [
            "resolves to loopback",
            "any address bound to a local interface",
            "Must not resolve to this host",
        ] {
            assert!(
                !document.contains(promise),
                "ROLLBACK-ANCHOR-PROTOCOL.md still promises {promise:?}, but endpoint_is_local \
                 inspects the URL string and never resolves it"
            );
        }
        assert!(
            document.contains("performs no DNS resolution and enumerates no local interfaces"),
            "section 10 must say outright that refusal 1 is lexical"
        );
        assert!(
            document.contains("is classified `External` by this Hub"),
            "section 10 must say what an operator can therefore still do by accident"
        );
    }

    fn write_witness_store(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            format!(
                "{{\"record\":\"header\",\"schema\":\"{}\",\"witness_id\":\"w\",\
                 \"witness_instance_id\":\"{}\",\"created_unix\":1}}\n",
                super::super::WITNESS_LOG_SCHEMA,
                "ab".repeat(32)
            ),
        )
        .unwrap();
    }

    /// The co-location scan has to find a witness store in the places an
    /// operator actually puts one, and has to stay quiet everywhere else. A
    /// guard that never fires is decoration; a guard that always fires gets
    /// switched off.
    #[test]
    fn a_witness_store_is_found_inside_or_beside_the_hub_state_tree_and_nowhere_else() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("hub").join("hub-state.json");
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        std::fs::write(&state, "{}").unwrap();
        assert!(
            witness_store_in_hub_state_tree(&state).is_none(),
            "a clean state tree must not be accused of holding a witness"
        );

        // Beside: the parent directory holds both. This is the configuration
        // the live run built - one directory with the Hub state, the witness
        // store and every secret key.
        let beside = root.path().join("anchor.log");
        write_witness_store(&beside);
        assert_eq!(
            witness_store_in_hub_state_tree(&state).as_deref(),
            Some(beside.as_path())
        );
        std::fs::remove_file(&beside).unwrap();

        // Inside: in the state directory itself.
        let inside = state.parent().unwrap().join("witness").join("anchor.log");
        write_witness_store(&inside);
        assert_eq!(
            witness_store_in_hub_state_tree(&state).as_deref(),
            Some(inside.as_path())
        );
        std::fs::remove_file(&inside).unwrap();

        // Recognised by content, not by name: renaming the store does not
        // move it out of the backup set, so it must not move it out of view.
        let renamed = state.parent().unwrap().join("notes.txt");
        write_witness_store(&renamed);
        assert_eq!(
            witness_store_in_hub_state_tree(&state).as_deref(),
            Some(renamed.as_path())
        );
        std::fs::remove_file(&renamed).unwrap();

        // A file that merely looks like JSON is not a witness store, and the
        // Hub's own state file is not one either.
        std::fs::write(state.parent().unwrap().join("other.json"), "{\"a\":1}").unwrap();
        std::fs::write(
            state.parent().unwrap().join("empty.log"),
            "not json at all\n",
        )
        .unwrap();
        assert!(
            witness_store_in_hub_state_tree(&state).is_none(),
            "only the reviewed append-only witness header counts"
        );

        // The documented blind spot, pinned so it stays a decision rather than
        // becoming a surprise. A store in a *sibling* directory of the state
        // tree is not seen: the parent is searched one file deep and no
        // further, because a Hub whose state sits in a shared or shallow
        // parent must not be refused on mainnet over an unrelated tree.
        let sibling = root.path().join("unrelated").join("anchor.log");
        write_witness_store(&sibling);
        assert!(
            witness_store_in_hub_state_tree(&state).is_none(),
            "sibling directories under the parent are deliberately out of scope"
        );
    }
}
