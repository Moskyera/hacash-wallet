//! The witness service: a durable, append-only counter that only goes up.
//!
//! This is the anchor. Everything else in this module tree exists to get a
//! commitment to it before the Hub's key is used, and to get a signed answer
//! back.
//!
//! It is deliberately compiled behind the `rollback-witness` feature and is
//! **not** part of a default Hub build. The Hub's only witness client is a
//! network client: there is no in-process witness, no `file://` store backend
//! and no "local mode". A configuration that would collapse the anchor back
//! into a file on the Hub's own disk has to be *built*, not selected. That is
//! the strongest guard available here and it costs nothing, because it is an
//! absence of code.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sys::Account;

use super::protocol::HubWitnessReceiptV1;
use super::protocol::{
    HubAnchorRequestV1, HubWitnessAnswerV1, HubWitnessChannelPositionV1, HubWitnessRefusalV1,
    HubWitnessStatusRequestV1, HubWitnessStatusV1, MAX_ANCHOR_LIFETIME_SECS,
    SignedHubAnchorRequestV1, SignedHubWitnessReceiptV1, SignedHubWitnessRefusalV1,
    SignedHubWitnessStatusV1, SignedWitnessDeploymentAttestationV1, WitnessDeploymentAttestationV1,
    WitnessPosture, WitnessRefusalReason,
};
use crate::error::{HubError, HubResult};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const WITNESS_LOG_SCHEMA: &str = "hpay-hub-rollback-anchor-witness-log/1";
/// Matches `MAX_ACCEPTED_ANCHOR_IDS` in the companion witness. Bounded per Hub.
const MAX_REMEMBERED_REQUEST_IDS: usize = 4_096;

fn fresh_identifier() -> String {
    hex::encode(sys::sha2(uuid::Uuid::new_v4().as_bytes()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum WitnessLogRecordV1 {
    /// Written once, when the durable store is created. Losing it, or writing
    /// a second one, is a re-created store and the Hub's pinned
    /// `witness_instance_id` will refuse.
    Header {
        schema: String,
        witness_id: String,
        witness_instance_id: String,
        created_unix: u64,
    },
    Reservation {
        hub_identity: String,
        binding_commitment: String,
        channel_id: String,
        reuse_version: u32,
        serial: u64,
        previous_bill_commitment: String,
        proposed_bill_commitment: String,
        request_id: String,
        request_commitment: String,
        previous_counter_value: u64,
        counter_value: u64,
        accepted_unix: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelPosition {
    serial: u64,
    bill_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredReservation {
    request_commitment: String,
    binding_commitment: String,
    serial: u64,
    proposed_bill_commitment: String,
    previous_counter_value: u64,
    counter_value: u64,
    accepted_unix: u64,
}

/// The durable append-only counter store.
///
/// One global counter per Hub identity and one high-water serial per channel.
/// Every accepted reservation is appended and `fsync`ed **before** the caller
/// is answered. A witness that answers first and writes after can lose the
/// record of a signature that then gets made, which is the one failure this
/// service exists to prevent.
pub struct WitnessStore {
    path: PathBuf,
    file: File,
    witness_id: String,
    instance_id: String,
    counters: BTreeMap<String, u64>,
    channels: BTreeMap<(String, String), ChannelPosition>,
    requests: BTreeMap<(String, String), StoredReservation>,
    request_order: Vec<(String, String)>,
}

impl WitnessStore {
    /// Opens the store, replaying the whole append-only log. The replay *is*
    /// the restart-survival property: the refusal to accept a counter it has
    /// already passed is rebuilt from disk, not held in memory.
    pub fn open(path: impl Into<PathBuf>, witness_id: &str, now_unix: u64) -> HubResult<Self> {
        let path = path.into();
        if witness_id.trim().is_empty() {
            return Err(HubError::State("witness id is required".into()));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| HubError::State(error.to_string()))?;
        }
        let (instance_id, records) = Self::replay(&path, witness_id)?;
        let (instance_id, header) = match instance_id {
            Some(instance_id) => (instance_id, None),
            None => {
                let instance_id = fresh_identifier();
                let header = WitnessLogRecordV1::Header {
                    schema: WITNESS_LOG_SCHEMA.into(),
                    witness_id: witness_id.to_owned(),
                    witness_instance_id: instance_id.clone(),
                    created_unix: now_unix,
                };
                (instance_id, Some(header))
            }
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|error| HubError::State(format!("witness store cannot be opened: {error}")))?;
        let mut store = Self {
            path,
            file,
            witness_id: witness_id.to_owned(),
            instance_id,
            counters: BTreeMap::new(),
            channels: BTreeMap::new(),
            requests: BTreeMap::new(),
            request_order: Vec::new(),
        };
        if let Some(header) = header {
            store.append(&header)?;
        }
        for record in records {
            store.apply(record)?;
        }
        Ok(store)
    }

    fn replay(
        path: &Path,
        witness_id: &str,
    ) -> HubResult<(Option<String>, Vec<WitnessLogRecordV1>)> {
        if !path.exists() {
            return Ok((None, Vec::new()));
        }
        let file = File::open(path)
            .map_err(|error| HubError::State(format!("witness store cannot be read: {error}")))?;
        let mut instance_id = None;
        let mut records = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| {
                HubError::State(format!("witness store is unreadable: {error}"))
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let record: WitnessLogRecordV1 = serde_json::from_str(&line).map_err(|error| {
                HubError::State(format!(
                    "witness store contains an unreadable record: {error}"
                ))
            })?;
            match record {
                WitnessLogRecordV1::Header {
                    ref schema,
                    witness_id: ref stored_id,
                    ref witness_instance_id,
                    ..
                } => {
                    if schema != WITNESS_LOG_SCHEMA {
                        return Err(HubError::State(
                            "witness store schema is not the reviewed append-only log".into(),
                        ));
                    }
                    if stored_id != witness_id {
                        return Err(HubError::State(
                            "witness store belongs to a different witness id".into(),
                        ));
                    }
                    if instance_id.is_some() {
                        return Err(HubError::State(
                            "witness store contains a second header: the store was re-created \
                             underneath an existing log"
                                .into(),
                        ));
                    }
                    instance_id = Some(witness_instance_id.clone());
                }
                reservation => {
                    if instance_id.is_none() {
                        return Err(HubError::State(
                            "witness store has reservations before its header".into(),
                        ));
                    }
                    records.push(reservation);
                }
            }
        }
        Ok((instance_id, records))
    }

    fn apply(&mut self, record: WitnessLogRecordV1) -> HubResult<()> {
        let WitnessLogRecordV1::Reservation {
            hub_identity,
            binding_commitment,
            serial,
            proposed_bill_commitment,
            request_id,
            request_commitment,
            previous_counter_value,
            counter_value,
            accepted_unix,
            ..
        } = record
        else {
            return Ok(());
        };
        let counter = self.counters.entry(hub_identity.clone()).or_insert(0);
        if previous_counter_value != *counter || counter_value != counter.saturating_add(1) {
            return Err(HubError::State(
                "witness store counter does not advance by exactly one: the append-only log has \
                 been edited or truncated"
                    .into(),
            ));
        }
        *counter = counter_value;
        let channel_key = (hub_identity.clone(), binding_commitment.clone());
        if let Some(existing) = self.channels.get(&channel_key)
            && serial <= existing.serial
        {
            return Err(HubError::State(
                "witness store channel serial does not advance: the append-only log has been \
                 edited or reordered"
                    .into(),
            ));
        }
        self.channels.insert(
            channel_key,
            ChannelPosition {
                serial,
                bill_commitment: proposed_bill_commitment.clone(),
            },
        );
        let request_key = (hub_identity, request_id);
        self.requests.insert(
            request_key.clone(),
            StoredReservation {
                request_commitment,
                binding_commitment,
                serial,
                proposed_bill_commitment,
                previous_counter_value,
                counter_value,
                accepted_unix,
            },
        );
        self.request_order.push(request_key);
        self.trim_remembered_requests();
        Ok(())
    }

    fn trim_remembered_requests(&mut self) {
        while self.request_order.len() > MAX_REMEMBERED_REQUEST_IDS {
            let oldest = self.request_order.remove(0);
            self.requests.remove(&oldest);
        }
    }

    fn append(&mut self, record: &WitnessLogRecordV1) -> HubResult<()> {
        let mut line = serde_json::to_string(record).map_err(|error| {
            HubError::State(format!("witness record cannot be encoded: {error}"))
        })?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_all())
            .map_err(|error| {
                HubError::State(format!("witness record was not made durable: {error}"))
            })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn counter(&self, hub_identity: &str) -> u64 {
        self.counters.get(hub_identity).copied().unwrap_or(0)
    }

    fn position(&self, hub_identity: &str, binding_commitment: &str) -> Option<&ChannelPosition> {
        self.channels
            .get(&(hub_identity.to_owned(), binding_commitment.to_owned()))
    }

    pub fn positions(&self, hub_identity: &str) -> Vec<HubWitnessChannelPositionV1> {
        self.channels
            .iter()
            .filter(|((hub, _), _)| hub == hub_identity)
            .map(|((_, binding), position)| HubWitnessChannelPositionV1 {
                binding_commitment: binding.clone(),
                serial: position.serial,
                bill_commitment: position.bill_commitment.clone(),
            })
            .collect()
    }

    /// Record one reservation, or say exactly why not.
    ///
    /// The counter advances **before** this returns, and the record is on disk
    /// and `fsync`ed before it does.
    fn reserve(
        &mut self,
        request: &HubAnchorRequestV1,
        now_unix: u64,
    ) -> Result<StoredReservation, WitnessRefusalReason> {
        // Layer 2 idempotency, checked **before** the clock. An identical
        // request returns the identical reservation and does not advance the
        // counter, which is what makes the crash window between "the witness
        // recorded" and "the Hub persisted the receipt" recoverable. That
        // window can outlive the request's own bounded lifetime - a Hub that
        // crashed here may not restart for hours - so expiry must not be
        // allowed to hide a reservation the witness genuinely holds. Re-stating
        // a durable fact discloses nothing and moves nothing; the Hub still
        // refuses to sign on a receipt outside its own freshness window.
        //
        // A known id bearing a *different* commitment is an equivocation
        // attempt, not a retry, and is refused hard.
        let request_key = (request.hub_identity.clone(), request.request_id.clone());
        let request_commitment = request
            .commitment()
            .map_err(|_| WitnessRefusalReason::MalformedRequest)?;
        if let Some(existing) = self.requests.get(&request_key) {
            if existing.request_commitment == request_commitment {
                return Ok(existing.clone());
            }
            return Err(WitnessRefusalReason::ReplayMismatch);
        }
        // Only a *new* reservation is gated on the clock.
        if request.expires_at <= now_unix || request.created_at > now_unix.saturating_add(5) {
            return Err(WitnessRefusalReason::Expired);
        }

        let observed = self
            .position(&request.hub_identity, &request.binding_commitment)
            .cloned();
        if let Some(observed) = observed.as_ref() {
            if request.serial < observed.serial {
                return Err(WitnessRefusalReason::HubBehindWitness);
            }
            if request.serial == observed.serial {
                return Err(
                    if request.proposed_bill_commitment == observed.bill_commitment {
                        WitnessRefusalReason::HubBehindWitness
                    } else {
                        WitnessRefusalReason::ForkAtSerial
                    },
                );
            }
            if request.serial > observed.serial.saturating_add(1) {
                return Err(WitnessRefusalReason::WitnessBehindHub);
            }
            if request.previous_bill_commitment != observed.bill_commitment {
                return Err(WitnessRefusalReason::ForkAtSerial);
            }
        }

        let counter = self.counter(&request.hub_identity);
        if request.counter_value <= counter {
            return Err(WitnessRefusalReason::HubBehindWitness);
        }
        if request.counter_value != counter.saturating_add(1) {
            return Err(WitnessRefusalReason::CounterSkipped);
        }

        let record = WitnessLogRecordV1::Reservation {
            hub_identity: request.hub_identity.clone(),
            binding_commitment: request.binding_commitment.clone(),
            channel_id: request.channel_id.clone(),
            reuse_version: request.reuse_version,
            serial: request.serial,
            previous_bill_commitment: request.previous_bill_commitment.clone(),
            proposed_bill_commitment: request.proposed_bill_commitment.clone(),
            request_id: request.request_id.clone(),
            request_commitment,
            previous_counter_value: counter,
            counter_value: request.counter_value,
            accepted_unix: now_unix,
        };
        // Durable first, answer second. Never the other way round.
        self.append(&record)
            .map_err(|_| WitnessRefusalReason::MalformedRequest)?;
        self.apply(record)
            .map_err(|_| WitnessRefusalReason::MalformedRequest)?;
        self.requests
            .get(&request_key)
            .cloned()
            .ok_or(WitnessRefusalReason::MalformedRequest)
    }
}

/// How the witness process is configured. The receipt key is online and signs
/// unattended; the authorisation key is offline and never lives here.
pub struct WitnessServiceConfig {
    pub witness_id: String,
    pub witness_epoch: u64,
    pub store_path: PathBuf,
    pub receipt_account: Account,
}

pub struct WitnessService {
    witness_id: String,
    witness_epoch: u64,
    boot_id: String,
    receipt_account: Account,
    store: Mutex<WitnessStore>,
}

impl WitnessService {
    pub fn open(config: WitnessServiceConfig, now_unix: u64) -> HubResult<Self> {
        if config.witness_epoch == 0 {
            return Err(HubError::State("witness epoch must be positive".into()));
        }
        let store = WitnessStore::open(config.store_path, &config.witness_id, now_unix)?;
        Ok(Self {
            witness_id: config.witness_id,
            witness_epoch: config.witness_epoch,
            boot_id: fresh_identifier(),
            receipt_account: config.receipt_account,
            store: Mutex::new(store),
        })
    }

    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    pub fn witness_epoch(&self) -> u64 {
        self.witness_epoch
    }

    pub fn receipt_address(&self) -> &str {
        self.receipt_account.readable()
    }

    pub fn instance_id(&self) -> HubResult<String> {
        Ok(self.locked()?.instance_id().to_owned())
    }

    fn locked(&self) -> HubResult<std::sync::MutexGuard<'_, WitnessStore>> {
        self.store
            .lock()
            .map_err(|_| HubError::State("witness store lock poisoned".into()))
    }

    /// Verify, record durably, then answer. Exactly one of a signed receipt or
    /// a signed refusal comes back; the caller never sees a bare error that
    /// could be mistaken for either.
    pub fn reserve(
        &self,
        signed: &SignedHubAnchorRequestV1,
        now_unix: u64,
    ) -> HubResult<HubWitnessAnswerV1> {
        let request = &signed.request;
        let request_commitment = match signed.verify() {
            Ok(commitment) => commitment,
            Err(_) => {
                return self.refuse_unverified(request, WitnessRefusalReason::MalformedRequest);
            }
        };
        if request.witness_id != self.witness_id {
            return self.refuse(
                request,
                &request_commitment,
                WitnessRefusalReason::UnknownHub,
            );
        }
        if request.witness_epoch != self.witness_epoch {
            return self.refuse(
                request,
                &request_commitment,
                WitnessRefusalReason::EpochMismatch,
            );
        }
        let mut store = self.locked()?;
        match store.reserve(request, now_unix) {
            Ok(reservation) => {
                // For a fresh reservation this is exactly the moment it was
                // recorded. For an idempotent replay it is the moment the
                // witness re-attested a reservation it durably holds, which is
                // the true statement and the one the Hub can act on: a receipt
                // stamped hours ago would be refused by the Hub's own
                // freshness check and the honest retry would be unusable.
                let attested_at = now_unix.max(reservation.accepted_unix);
                let receipt = HubWitnessReceiptV1 {
                    receipt_version: 1,
                    request_id: request.request_id.clone(),
                    request_commitment,
                    witness_id: self.witness_id.clone(),
                    witness_epoch: self.witness_epoch,
                    witness_instance_id: store.instance_id().to_owned(),
                    witness_boot_id: self.boot_id.clone(),
                    hub_identity: request.hub_identity.clone(),
                    binding_commitment: reservation.binding_commitment.clone(),
                    serial: reservation.serial,
                    proposed_bill_commitment: reservation.proposed_bill_commitment.clone(),
                    previous_counter_value: reservation.previous_counter_value,
                    counter_value: reservation.counter_value,
                    accepted_at: attested_at,
                    receipt_expires_at: attested_at.saturating_add(MAX_ANCHOR_LIFETIME_SECS),
                };
                Ok(HubWitnessAnswerV1::Receipt(Box::new(
                    SignedHubWitnessReceiptV1::sign(receipt, &self.receipt_account)?,
                )))
            }
            Err(reason) => {
                let observed = store.position(&request.hub_identity, &request.binding_commitment);
                let refusal = HubWitnessRefusalV1 {
                    refusal_version: 1,
                    request_id: request.request_id.clone(),
                    request_commitment,
                    witness_id: self.witness_id.clone(),
                    witness_epoch: self.witness_epoch,
                    witness_instance_id: store.instance_id().to_owned(),
                    hub_identity: request.hub_identity.clone(),
                    binding_commitment: request.binding_commitment.clone(),
                    reason,
                    observed_counter_value: store.counter(&request.hub_identity),
                    observed_serial: observed.map_or(0, |position| position.serial),
                    observed_bill_commitment: observed
                        .map_or_else(|| ZERO_HASH.to_owned(), |p| p.bill_commitment.clone()),
                    refused_at: now_unix,
                };
                Ok(HubWitnessAnswerV1::Refusal(Box::new(
                    SignedHubWitnessRefusalV1::sign(refusal, &self.receipt_account)?,
                )))
            }
        }
    }

    fn refuse(
        &self,
        request: &HubAnchorRequestV1,
        request_commitment: &str,
        reason: WitnessRefusalReason,
    ) -> HubResult<HubWitnessAnswerV1> {
        let store = self.locked()?;
        let refusal = HubWitnessRefusalV1 {
            refusal_version: 1,
            request_id: request.request_id.clone(),
            request_commitment: request_commitment.to_owned(),
            witness_id: self.witness_id.clone(),
            witness_epoch: self.witness_epoch,
            witness_instance_id: store.instance_id().to_owned(),
            hub_identity: request.hub_identity.clone(),
            binding_commitment: request.binding_commitment.clone(),
            reason,
            observed_counter_value: store.counter(&request.hub_identity),
            observed_serial: 0,
            observed_bill_commitment: ZERO_HASH.to_owned(),
            refused_at: 0,
        };
        let mut refusal = refusal;
        refusal.refused_at = crate::node::now_unix();
        Ok(HubWitnessAnswerV1::Refusal(Box::new(
            SignedHubWitnessRefusalV1::sign(refusal, &self.receipt_account)?,
        )))
    }

    fn refuse_unverified(
        &self,
        request: &HubAnchorRequestV1,
        reason: WitnessRefusalReason,
    ) -> HubResult<HubWitnessAnswerV1> {
        // A request whose own signature does not verify has no trustworthy
        // commitment, so the refusal names the zero commitment rather than
        // echoing an attacker-chosen value.
        self.refuse(request, ZERO_HASH, reason)
    }

    pub fn status(
        &self,
        request: &HubWitnessStatusRequestV1,
        now_unix: u64,
    ) -> HubResult<SignedHubWitnessStatusV1> {
        if request.witness_id != self.witness_id {
            return Err(HubError::Node(
                "witness status was requested from a different witness id".into(),
            ));
        }
        let store = self.locked()?;
        let status = HubWitnessStatusV1 {
            status_version: 1,
            witness_id: self.witness_id.clone(),
            witness_epoch: self.witness_epoch,
            witness_instance_id: store.instance_id().to_owned(),
            witness_boot_id: self.boot_id.clone(),
            hub_identity: request.hub_identity.clone(),
            nonce: request.nonce.clone(),
            counter_value: store.counter(&request.hub_identity),
            channels: store.positions(&request.hub_identity),
            observed_at: now_unix,
        };
        SignedHubWitnessStatusV1::sign(status, &self.receipt_account)
    }

    /// Issue the deployment attestation. The offline authorisation account is
    /// passed in per call and is never held by the running service.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_attestation(
        &self,
        authorisation_account: &Account,
        hub_identity: &str,
        posture: WitnessPosture,
        witness_operator: &str,
        separation_statement: &str,
        attested_at: u64,
        validity_seconds: u64,
    ) -> HubResult<SignedWitnessDeploymentAttestationV1> {
        let attestation = WitnessDeploymentAttestationV1 {
            attestation_version: 1,
            witness_id: self.witness_id.clone(),
            witness_instance_id: self.instance_id()?,
            hub_identity: hub_identity.to_owned(),
            posture,
            witness_operator: witness_operator.to_owned(),
            separation_statement: separation_statement.to_owned(),
            attested_at,
            expires_at: attested_at.saturating_add(validity_seconds),
        };
        SignedWitnessDeploymentAttestationV1::sign(attestation, authorisation_account)
    }
}

/// The witness HTTP surface. Two routes, both of which answer with a signed
/// message or nothing at all.
pub fn router(service: Arc<WitnessService>) -> axum::Router {
    use axum::Json;
    use axum::extract::State;
    use axum::routing::post;

    async fn anchor(
        State(service): State<Arc<WitnessService>>,
        Json(signed): Json<SignedHubAnchorRequestV1>,
    ) -> Result<Json<HubWitnessAnswerV1>, axum::http::StatusCode> {
        service
            .reserve(&signed, crate::node::now_unix())
            .map(Json)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    async fn status(
        State(service): State<Arc<WitnessService>>,
        Json(request): Json<HubWitnessStatusRequestV1>,
    ) -> Result<Json<SignedHubWitnessStatusV1>, axum::http::StatusCode> {
        service
            .status(&request, crate::node::now_unix())
            .map(Json)
            .map_err(|_| axum::http::StatusCode::BAD_REQUEST)
    }

    axum::Router::new()
        .route(super::ANCHOR_RESERVE_PATH, post(anchor))
        .route(super::ANCHOR_STATUS_PATH, post(status))
        .with_state(service)
}

#[cfg(test)]
#[path = "witness/tests.rs"]
mod tests;
