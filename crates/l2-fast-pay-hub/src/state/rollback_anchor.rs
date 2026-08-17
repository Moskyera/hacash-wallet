//! The Hub side of the external monotonic rollback anchor.
//!
//! This sits on the signing path, before the key is used, alongside the
//! pre-use precondition re-verification that is already there. It does not
//! replace any of those checks: every one of them is enforced against the
//! Hub's own durable state, and this is the one check that is not, because the
//! threat is precisely that the durable state was restored.
//!
//! Ordering, which *is* the protocol:
//!
//! ```text
//! 1. probe the witness for its current counter and position   (live, signed)
//! 2. build the request from the exact proposed bill and
//!    persist it, durably, before it goes on the wire
//! 3. send it
//! 4. the witness advances its counter durably, THEN answers
//! 5. verify the receipt and persist it together with the
//!    advanced counter, in one authenticated write
//! 6. re-read the wall clock and re-validate freshness
//! 7. sign
//! ```
//!
//! A crash between 3 and 5 leaves a durable request and no receipt. On retry
//! the Hub replays the identical request and the witness's idempotency returns
//! the identical receipt, so there is no gap. A crash between 2 and 3 means
//! the witness never saw it, and the replay is equally safe.

use std::sync::atomic::Ordering;

use crate::error::{HubError, HubResult};
use crate::journal::{JournalEvent, JournalOperationType, JournalPhase};
use crate::rollback_anchor::continuity::{
    ANCHOR_CONTINUITY_DECLARATION_SCHEMA, AnchorContinuityDeclarationV1,
    CONTINUITY_REQUEST_ID_PREFIX, WitnessIdentityBreakV1, continuity_request_from_recorded_head,
    continuity_request_id,
};
use crate::rollback_anchor::protocol::{
    MAX_ANCHOR_LIFETIME_SECS, REFUSAL_ATTESTATION_MISSING_OR_EXPIRED, REFUSAL_COUNTER_SKIPPED,
    REFUSAL_FORK_AT_SERIAL, REFUSAL_HUB_BEHIND_WITNESS, REFUSAL_RECEIPT_NOT_BOUND,
    REFUSAL_REPLAY_MISMATCH, REFUSAL_WITNESS_BEHIND_HUB, REFUSAL_WITNESS_INSTANCE_CHANGED,
    REFUSAL_WITNESS_IS_NOT_EXTERNAL, REFUSAL_WITNESS_UNREACHABLE, refusal_condemns_the_channel,
};
use crate::rollback_anchor::{
    HubAnchorRequestV1, RollbackAnchorClient, RollbackAnchorConfig, RollbackAnchorEvidenceV1,
    RollbackAnchorPin, SignedHubAnchorRequestV1, SignedHubWitnessReceiptV1, VerifiedAnchorReceipt,
};
use crate::storage::{
    PersistedRollbackAnchorReservation, PersistedRollbackAnchorState, state_commitment,
    validate_hvm_state,
};

use super::HubState;

/// Did the witness refuse because the position asked for is not the position it
/// is at, rather than because anything about the request was wrong?
///
/// Used for exactly one decision - whether a continuity request that was
/// persisted but never receipted may be re-minted at the witness's current
/// counter - and deliberately narrow. A refusal of this kind is proof that the
/// witness holds no record of the request id, because a recorded id is replayed
/// before either the clock or the counter is consulted.
fn witness_refused_the_position(error: &HubError) -> bool {
    let text = error.to_string();
    text.contains(REFUSAL_HUB_BEHIND_WITNESS) || text.contains(REFUSAL_COUNTER_SKIPPED)
}

/// What a startup probe means for the **process**, which is a different
/// question from what it means for a **signature**.
///
/// The signature question is answered by `rollback_anchor_probe_agreed` and is
/// not softened anywhere: unless `agreed` is true, nothing signs. This type
/// exists so the boot path can act on the answer without the answer being an
/// error that kills the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackAnchorBootPosture {
    /// True only when the probe agreed with the witness on every channel this
    /// Hub holds. This is the exact bit the signing path gates on.
    pub agreed: bool,
    /// Which refusal this is, by the identifier
    /// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 indexes its procedures
    /// by. `None` when the probe agreed.
    pub refusal_identifier: Option<&'static str>,
    /// The refusal in full, for the log.
    pub refusal: Option<String>,
    /// Whether this refusal means the anchor and the Hub disagree about
    /// history, per
    /// [`crate::rollback_anchor::protocol::refusal_condemns_the_channel`].
    ///
    /// The distinction that function already draws is honoured here rather than
    /// re-invented: a condemning refusal is a durable, human-resolved condition
    /// and retrying it is pointless noise, while an unreachable witness or a
    /// timed-out request is transient and deliberately **not** condemning - the
    /// Hub resumes on its own the moment the witness answers, which is what
    /// `ROLLBACK-ANCHOR-RECOVERY.md` section 6 step 3 promises the operator.
    pub condemning: bool,
}

/// Which identifier from `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 a
/// probe refusal carries.
///
/// Every refusal in this subsystem is constructed with its identifier inside
/// the message precisely so the code and the operator document cannot drift, so
/// this reads the identifier back out. Condemning identifiers are matched first,
/// so a message that mentions more than one is classified by the worse.
///
/// A failure naming none of them is reachability by elimination - a dropped
/// packet, DNS, TLS, a timeout - which is exactly what section 2's closing line
/// already tells the operator to assume when the Hub said nothing at all.
fn probe_refusal_identifier(message: &str) -> &'static str {
    [
        REFUSAL_HUB_BEHIND_WITNESS,
        REFUSAL_FORK_AT_SERIAL,
        REFUSAL_COUNTER_SKIPPED,
        REFUSAL_WITNESS_BEHIND_HUB,
        REFUSAL_WITNESS_INSTANCE_CHANGED,
        REFUSAL_REPLAY_MISMATCH,
        REFUSAL_WITNESS_IS_NOT_EXTERNAL,
        REFUSAL_ATTESTATION_MISSING_OR_EXPIRED,
        REFUSAL_RECEIPT_NOT_BOUND,
        REFUSAL_WITNESS_UNREACHABLE,
    ]
    .into_iter()
    .find(|identifier| message.contains(identifier))
    .unwrap_or(REFUSAL_WITNESS_UNREACHABLE)
}

/// Everything the anchor needs to know about the exact bill about to be
/// signed. Commitments and positions only.
pub(super) struct RollbackAnchorSubject<'a> {
    pub operation_id: &'a str,
    pub settlement_profile: &'a str,
    pub network_instance_id: &'a str,
    pub binding_commitment: &'a str,
    pub channel_id: &'a str,
    pub reuse_version: u32,
    pub serial: u64,
    pub previous_bill_commitment: String,
    pub proposed_bill_commitment: String,
    pub payer: &'a str,
    pub recipient: &'a str,
    pub amount_units: u64,
    pub idempotency_key: &'a str,
}

impl HubState {
    /// Attach the anchor. Every hard refusal that does not need the network
    /// runs here, so a misconfiguration is a startup failure rather than a
    /// surprise on the first payment.
    pub fn with_rollback_anchor(mut self, config: RollbackAnchorConfig) -> HubResult<Self> {
        let signing_address = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| {
                HubError::State(
                    "the rollback anchor binds the key that signs bills, so a Hub signer is \
                     required before it can be attached"
                        .into(),
                )
            })?
            .address()
            .to_owned();
        // The Hub's own state file, so the client can look for a witness store
        // inside this Hub's backup set. A Hub with no durable storage cannot
        // settle at all, so there is nothing for an anchor to guard and nothing
        // to scan.
        let state_path = self
            .state_store
            .as_ref()
            .map(crate::sealed_state::StateStore::path)
            .map(std::path::Path::to_path_buf);
        self.rollback_anchor = Some(RollbackAnchorClient::connect(
            config,
            &self.hub_address,
            &signing_address,
            &self.deployment_profile,
            state_path.as_deref(),
        )?);
        Ok(self)
    }

    pub fn rollback_anchor_configured(&self) -> bool {
        self.rollback_anchor.is_some()
    }

    fn anchor_state(&self) -> HubResult<PersistedRollbackAnchorState> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        Ok(guard.rollback_anchor.clone().unwrap_or_default())
    }

    /// The durable condemnation for one channel, read from this Hub's own
    /// state file and from nowhere else.
    ///
    /// It deliberately does not consult `self.rollback_anchor`. A latch is
    /// written by the Hub into `hub-state.json`, it survives every restart,
    /// and it is the strongest refusal this subsystem can produce - so the one
    /// thing it must never depend on is whether a witness happens to be
    /// configured *now*. Removing the `--rollback-witness-*` flags removes the
    /// ability to reserve new positions; it does not, and must not, remove a
    /// condemnation that is already on disk.
    ///
    /// A Hub that has never had an anchor has no `rollback_anchor` record at
    /// all, so this reads `None` for every channel and changes nothing for it.
    fn latched_rollback_anchor_refusal(
        &self,
        binding_commitment: &str,
    ) -> HubResult<Option<String>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        Ok(guard
            .rollback_anchor
            .as_ref()
            .and_then(|anchor| anchor.latched_refusals.get(binding_commitment))
            .cloned())
    }

    /// How many channels this Hub holds condemned in anchor refusal, read from
    /// durable state without going near the witness.
    ///
    /// `RollbackAnchorEvidenceV1::channels_latched_in_refusal` carries the same
    /// number, but only when a live witness could be probed - so it goes to
    /// zero-by-absence exactly when the anchor client is removed, which is the
    /// moment the number matters most. This one cannot.
    pub(crate) fn latched_rollback_anchor_refusal_count(&self) -> u64 {
        let Ok(guard) = self.inner.read() else {
            // A poisoned lock is not evidence that nothing is latched.
            return u64::MAX;
        };
        guard
            .rollback_anchor
            .as_ref()
            .map_or(0, |anchor| anchor.latched_refusals.len())
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Every channel this Hub holds, in both settlement profiles, as
    /// `(binding, anchored serial, ledger head serial)`.
    ///
    /// The **anchored** serial is what the Hub has reserved with the witness,
    /// and it is what the witness is compared against. It is deliberately not
    /// the ledger head: a channel's initial recovery bill is signed by both
    /// parties when the channel opens, long before the anchor ever sees it, so
    /// a ledger head of 1 on a witness that has no record for the channel is
    /// an ordinary new channel rather than an amnesiac witness. Zero here
    /// means "this Hub has never reserved anything for this channel", and a
    /// witness that nonetheless holds a record for it means this Hub lost
    /// anchor state - which is a rollback.
    ///
    /// The ledger head travels alongside because it is the number the operator
    /// needs in order to compute the gap.
    fn anchor_channel_positions(&self) -> HubResult<Vec<(String, u64, u64)>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let anchor = guard.rollback_anchor.clone().unwrap_or_default();
        let mut positions = Vec::new();
        let ledgers = guard
            .hvm_registry_ledgers
            .iter()
            .map(|(binding, ledger)| (binding, ledger.latest_fully_signed_bill.serial))
            .chain(
                guard
                    .hvm_channel_ledgers
                    .iter()
                    .map(|(binding, ledger)| (binding, ledger.latest_fully_signed_bill.serial)),
            );
        for (binding, ledger_serial) in ledgers {
            let anchored = anchor.channel_serials.get(binding).copied().unwrap_or(0);
            let anchored = if anchored == 0 {
                0
            } else {
                anchored.max(ledger_serial)
            };
            positions.push((binding.clone(), anchored, ledger_serial));
        }
        Ok(positions)
    }

    /// The startup probe.
    ///
    /// This is the anti-rollback check proper: it compares the Hub's position
    /// against the witness's for every channel the Hub holds, before the money
    /// path serves anything. The per-signature reservation is the
    /// anti-equivocation check and is what actually advances the counter. Both
    /// are required - the startup check alone would miss a state file swapped
    /// underneath a running Hub, and the per-signature check alone would let a
    /// restored Hub serve reads and accept requests before refusing.
    ///
    /// The check itself is [`Self::rollback_anchor_startup_probe_check`] and is
    /// unchanged. This wrapper adds one thing and takes nothing away: it records
    /// *which* refusal the check produced, so a Hub that is refusing can name it
    /// on `/v1/readiness/mainnet` instead of only in a log line nobody kept. A
    /// probe that agrees clears the record.
    pub async fn run_rollback_anchor_startup_probe(&self) -> HubResult<()> {
        let result = self.rollback_anchor_startup_probe_check().await;
        self.record_rollback_anchor_probe_refusal(
            result
                .as_ref()
                .err()
                .map(|error| probe_refusal_identifier(&error.to_string())),
        );
        result
    }

    /// The startup probe, as the **process** must treat it.
    ///
    /// Refusing to SIGN without a witness is the anchor working and is not
    /// changed here, at all. Refusing to START is a different and worse thing: a
    /// Hub that will not start cannot serve a cooperative close, cannot answer
    /// readiness, and cannot tell anyone why. Under a systemd unit with
    /// `Restart=on-failure` it crash-loops, and the operator's instinct - restart
    /// it - makes things strictly worse while telling them nothing, which is the
    /// first thing `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` tells them not to do.
    ///
    /// So the process starts in every case, and this returns the posture instead
    /// of an error. **It cannot become a bypass and it changes no signature.** On
    /// any refusal `rollback_anchor_probe_agreed` stays false, which is the bit
    /// [`Self::reserve_rollback_anchor`] checks before it will reserve anything,
    /// and every channel latched by the check stays latched in the durable state.
    /// A bill that would not be signed before this existed is not signed after.
    pub async fn run_rollback_anchor_startup_probe_at_boot(&self) -> RollbackAnchorBootPosture {
        match self.run_rollback_anchor_startup_probe().await {
            Ok(()) => RollbackAnchorBootPosture {
                agreed: self.rollback_anchor_probe_agreed.load(Ordering::Acquire),
                refusal_identifier: None,
                refusal: None,
                condemning: false,
            },
            Err(error) => {
                let refusal = error.to_string();
                RollbackAnchorBootPosture {
                    agreed: false,
                    refusal_identifier: Some(probe_refusal_identifier(&refusal)),
                    condemning: refusal_condemns_the_channel(&refusal),
                    refusal: Some(refusal),
                }
            }
        }
    }

    /// The identifier of the most recent startup probe refusal, or `None` when
    /// the last probe agreed or none has run. Published, never gating.
    pub fn rollback_anchor_probe_refusal(&self) -> Option<&'static str> {
        self.rollback_anchor_probe_refusal
            .read()
            .ok()
            .and_then(|slot| *slot)
    }

    fn record_rollback_anchor_probe_refusal(&self, identifier: Option<&'static str>) {
        if let Ok(mut slot) = self.rollback_anchor_probe_refusal.write() {
            *slot = identifier;
        }
    }

    async fn rollback_anchor_startup_probe_check(&self) -> HubResult<()> {
        let Some(client) = self.rollback_anchor.as_ref() else {
            return Ok(());
        };
        let now_unix = crate::node::now_unix();
        let pin = self.anchor_state()?.pin;
        let status = client.probe(&pin, now_unix).await?;
        for (binding, anchored_serial, ledger_serial) in self.anchor_channel_positions()? {
            match status.status.channel(&binding) {
                Some(position) if position.serial > anchored_serial => {
                    return Err(self.latch_rollback_anchor_refusal(
                        &binding,
                        format!(
                            "{REFUSAL_HUB_BEHIND_WITNESS}: the witness has recorded serial {} for \
                             channel {binding} but this Hub's ledger head is serial \
                             {ledger_serial} and its anchor record reaches serial \
                             {anchored_serial}. This Hub's state went backwards - a restore from \
                             backup is the usual cause. The {} bill(s) in between were signed by \
                             this Hub's key and are held by the counterparty. Do NOT re-sign \
                             them: those serials already have signed bills, and signing new ones \
                             manufactures by hand the exact double signature this anchor exists \
                             to prevent. Follow docs/l2/ROLLBACK-ANCHOR-RECOVERY.md, Procedure A",
                            position.serial,
                            position.serial.saturating_sub(ledger_serial)
                        ),
                        now_unix,
                    ));
                }
                Some(position) if position.serial < anchored_serial => {
                    return Err(self.latch_rollback_anchor_refusal(
                        &binding,
                        format!(
                            "{REFUSAL_WITNESS_BEHIND_HUB}: the witness has recorded serial {} for \
                             channel {binding} but this Hub has already anchored serial \
                             {anchored_serial}. The anchor has forgotten positions this Hub has \
                             signed. Do NOT resynchronise the witness to the Hub; see \
                             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md, Procedure B",
                            position.serial
                        ),
                        now_unix,
                    ));
                }
                Some(_) => {}
                None if anchored_serial > 0 => {
                    return Err(self.latch_rollback_anchor_refusal(
                        &binding,
                        format!(
                            "{REFUSAL_WITNESS_BEHIND_HUB}: the witness holds no record at all for \
                             channel {binding}, yet this Hub has anchored serial \
                             {anchored_serial}. A fresh witness store agrees with everything, \
                             which is amnesia rather than agreement. See \
                             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md, Procedure B"
                        ),
                        now_unix,
                    ));
                }
                None => {}
            }
        }
        // Adopt the witness's identity and counter on first contact only.
        // Afterwards the pin is what the witness is measured against, and
        // `verify_status` has already refused any answer below it.
        let event = self.anchor_event(
            JournalPhase::RollbackAnchorReceiptPersisted,
            "rollback-anchor-startup-probe",
            &status.status.witness_id,
            &status.status.witness_instance_id,
            now_unix,
        );
        self.persist_rollback_anchor(event, |anchor| {
            if anchor.pin.witness_instance_id.is_empty() {
                anchor.pin.witness_id = status.status.witness_id.clone();
                anchor.pin.witness_instance_id = status.status.witness_instance_id.clone();
                anchor.pin.highest_counter_value = status.status.counter_value;
                anchor.pin.updated_unix = now_unix;
            }
            Ok(())
        })?;
        self.rollback_anchor_probe_agreed
            .store(true, Ordering::Release);
        Ok(())
    }

    /// Live, measured evidence for `external_rollback_anchor_ready`.
    ///
    /// `None` whenever no witness is configured, and `None` whenever a
    /// configured witness cannot be reached or its answer cannot be verified
    /// against the pinned keys and this Hub's own durable position. Both fail
    /// closed to the same place, because an unreachable oracle is not
    /// evidence.
    pub async fn rollback_anchor_evidence(&self) -> Option<RollbackAnchorEvidenceV1> {
        let client = self.rollback_anchor.as_ref()?;
        let now_unix = crate::node::now_unix();
        let anchor = self.anchor_state().ok()?;
        let status = client.probe(&anchor.pin, now_unix).await.ok()?;
        Some(client.evidence_from(
            &status,
            self.rollback_anchor_probe_agreed.load(Ordering::Acquire),
            u64::try_from(anchor.latched_refusals.len()).unwrap_or(u64::MAX),
            now_unix,
        ))
    }

    /// Is this Hub configured with a different witness store than the one it
    /// pinned? Measured from durable state and configuration, with no network.
    ///
    /// With exactly one witness (ADR-001, settled) any change of witness is a
    /// total change, so this is the single condition under which the anchor
    /// stops being a guard and becomes a permanent refusal: the startup probe
    /// can never agree again, `rollback_anchor_probe_agreed` stays false
    /// forever, and the only exit an operator has left is to delete the
    /// `--rollback-witness-*` flags - the anchor's failure mode being "turn it
    /// off".
    ///
    /// It is deliberately measured without a probe. A replacement witness that
    /// is itself slow or unreachable would otherwise present as
    /// `rollback_anchor_witness_unreachable`, which is the transient identifier
    /// and tells the operator to wait for something that is never coming back.
    /// The comparison is against the *attestation* rather than a live answer
    /// because [`RollbackAnchorClient::verify_status`] already refuses any
    /// status naming a store the attestation does not describe, so the attested
    /// store is the store this Hub can ever talk to.
    ///
    /// `Ok(None)` for a Hub with no anchor, for a Hub whose pin is still empty
    /// (it adopts on first contact), and for the ordinary case where the
    /// configured witness is the pinned one.
    ///
    /// `Err` when the durable pin cannot be read at all. That case used to be
    /// swallowed into `None` by an `.ok()?`, and `None` is the shape that means
    /// *healthy* here - so a Hub whose state lock was poisoned published a
    /// document with no blocker, no break and `payments_enabled` left true,
    /// which is the one reading it must never produce. An unreadable pin is not
    /// evidence of an intact pin.
    pub fn rollback_anchor_witness_identity_break(
        &self,
    ) -> HubResult<Option<WitnessIdentityBreakV1>> {
        let Some(client) = self.rollback_anchor.as_ref() else {
            return Ok(None);
        };
        let pin = self.anchor_state()?.pin;
        Ok(WitnessIdentityBreakV1::detect(
            &self.hub_address,
            &pin,
            client.witness_id(),
            client.witness_epoch(),
            client.attested_witness_instance_id(),
            crate::node::now_unix(),
        ))
    }

    /// The continuity declaration: the head the payer already holds,
    /// re-anchored under the witness answering now.
    ///
    /// # What it does not do
    ///
    /// It signs no bill. It moves no pin, sets no `rollback_anchor_probe_agreed`,
    /// advances no `channel_serials`, and clears no latch. A Hub that refuses to
    /// sign before this is called refuses to sign after it, for exactly the same
    /// reason and with exactly the same message. The only thing it produces is
    /// evidence, addressed to the one party that can judge it.
    ///
    /// # Why every refusal below is there
    ///
    /// * **No anchor, or no break.** A Hub in agreement with its pinned witness
    ///   has nothing to declare. Allowing a declaration there would let a
    ///   healthy Hub mint an out-of-band re-anchor of an old head, which is a
    ///   receipt an attacker would very much like to have.
    /// * **The probe agreed.** Same condition from the other side, checked
    ///   against the bit the signing path actually gates on, so the two cannot
    ///   disagree.
    /// * **The channel is latched.** A channel condemned for a real rollback
    ///   gets the operator procedure in `ROLLBACK-ANCHOR-RECOVERY.md`, not a
    ///   ceremony. Re-anchoring a condemned head at a fresh witness is the
    ///   attack, not the remedy.
    /// * **No stored receipt for the head.** The declaration re-anchors the
    ///   bill commitment the payer holds, which is the payer-signed,
    ///   Hub-*unsigned* commitment. The only place this Hub has that value is
    ///   the receipt it stored beside the head. Without it there is nothing to
    ///   re-anchor and this refuses rather than inventing a commitment.
    pub async fn rollback_anchor_continuity_declaration(
        &self,
        binding_commitment: &str,
        now_unix: u64,
    ) -> HubResult<AnchorContinuityDeclarationV1> {
        let client = self.rollback_anchor.as_ref().ok_or_else(|| {
            HubError::State(
                "this Hub has no external rollback anchor configured, so there is no witness \
                 identity break to declare"
                    .into(),
            )
        })?;
        let identity_break = self
            .rollback_anchor_witness_identity_break()?
            .ok_or_else(|| {
                HubError::State(
                "this Hub's configured witness is the witness it pinned. A continuity declaration \
                 re-anchors a head under a *replacement* witness and exists only while the anchor \
                 is refusing; there is nothing to declare"
                    .into(),
            )
            })?;
        if self.rollback_anchor_probe_agreed.load(Ordering::Acquire) {
            return Err(HubError::State(
                "the external rollback anchor startup probe has agreed, so this Hub is signing \
                 normally and has no break to declare"
                    .into(),
            ));
        }
        if let Some(reason) = self.latched_rollback_anchor_refusal(binding_commitment)? {
            return Err(HubError::State(format!(
                "this channel is latched in rollback anchor refusal and will not be re-anchored \
                 under a new witness. Follow docs/l2/ROLLBACK-ANCHOR-RECOVERY.md: {reason}"
            )));
        }

        // Everything below is a read-check-write across two `await` points, and
        // this route is a public `GET` that anyone who knows a binding
        // commitment can call. Unserialised, two simultaneous reads on
        // *different* channels each take the witness's current counter, each
        // mint a request at counter+1, and the one that loses is refused
        // `rollback_anchor_counter_skipped` - after which its persisted request
        // is replayed forever and that channel's payer can never be served a
        // declaration at all. One at a time is not a performance decision: a
        // channel's declaration is minted once and replayed from disk
        // afterwards, so the serialised path is walked once per channel per
        // witness.
        let _serialised = self.rollback_anchor_continuity_lock.lock().await;

        let anchor = self.anchor_state()?;
        let (serial, bill_commitment, head_request_id) =
            self.recorded_anchored_head(binding_commitment)?;
        let request_id = continuity_request_id(binding_commitment, serial);

        // A declaration already made for this exact head is replayed verbatim.
        // Without this, every read would mint a fresh reservation and burn a
        // position on the replacement witness, and two payers reading the same
        // channel would be shown two different declarations of one head.
        if let Some(existing) = anchor.reservations.get(&request_id)
            && let (Some(receipt), Some(signature_hex)) = (
                existing.receipt.as_ref(),
                existing.receipt_signature_hex.as_ref(),
            )
            && receipt.binding_commitment == binding_commitment
            && receipt.serial == serial
            && receipt.proposed_bill_commitment == bill_commitment
            && receipt.witness_instance_id == identity_break.attested_witness_instance_id
        {
            let signed = SignedHubWitnessReceiptV1 {
                receipt: receipt.clone(),
                signature_hex: signature_hex.clone(),
            };
            // Re-verified rather than trusted for having come off this Hub's
            // own disk, which is the thing this subsystem assumes was tampered
            // with.
            signed.verify_against_pinned_key(client.witness_receipt_address())?;
            return Ok(AnchorContinuityDeclarationV1 {
                schema: ANCHOR_CONTINUITY_DECLARATION_SCHEMA.to_owned(),
                hub_identity: self.hub_address.trim().to_owned(),
                binding_commitment: binding_commitment.to_owned(),
                serial,
                bill_commitment,
                witness_identity_break: identity_break,
                receipts: vec![signed],
                declared_at: now_unix,
            });
        }

        // A request persisted by an earlier attempt that did not get as far as
        // its receipt is replayed byte for byte, exactly as the signing path
        // replays one. Rebuilding it instead would pick up a counter the
        // witness has since moved, which changes the request commitment, and a
        // known request id bearing a different commitment is an equivocation
        // attempt to the witness rather than a retry - so it would be refused
        // `rollback_anchor_replay_mismatch` forever.
        let replayed = anchor
            .reservations
            .get(&request_id)
            .map(|reservation| reservation.request.clone());
        let replayed_from_disk = replayed.is_some();
        let mut request = match replayed {
            Some(request) => {
                if request.binding_commitment != binding_commitment
                    || request.serial != serial
                    || request.proposed_bill_commitment != bill_commitment
                {
                    return Err(HubError::State(format!(
                        "{REFUSAL_RECEIPT_NOT_BOUND}: the continuity reservation stored under this \
                         channel's head does not describe that head. Nothing is declared"
                    )));
                }
                request
            }
            None => {
                let recorded = anchor
                    .reservations
                    .get(&head_request_id)
                    .map(|reservation| reservation.request.clone())
                    .ok_or_else(|| {
                        HubError::State(
                            "this Hub no longer holds the anchor request that reserved this \
                             channel's head, so it cannot re-anchor that exact bill without \
                             inventing fields. Nothing is declared"
                                .into(),
                        )
                    })?;
                if recorded.binding_commitment != binding_commitment
                    || recorded.serial != serial
                    || recorded.proposed_bill_commitment != bill_commitment
                {
                    return Err(HubError::State(format!(
                        "{REFUSAL_RECEIPT_NOT_BOUND}: the stored anchor request for this channel's \
                         head does not describe the head. Nothing is declared"
                    )));
                }
                // The replacement witness is probed with a WAIVED pin, and that
                // is the one place this path deviates from the signing path. It
                // has to: a replacement store is by definition a different
                // `witness_instance_id` at a lower counter, so the pinned-
                // instance and counter gates would refuse every time and there
                // would be no declaration to make. Waiving them here is safe for
                // exactly one reason - nothing that follows signs, sets
                // `rollback_anchor_probe_agreed` or writes the pin, so the Hub
                // gains no authority from the answer. Every check that does not
                // depend on the pin still runs inside `verify_status`: the
                // receipt-key signature, the witness id, the epoch, this Hub's
                // identity, the probe nonce, freshness, and that the answering
                // store is the one the signed deployment attestation describes.
                let status = client
                    .probe(&RollbackAnchorPin::default(), now_unix)
                    .await?;
                if status.status.witness_instance_id == identity_break.pinned_witness_instance_id {
                    return Err(HubError::State(
                        "the witness answered from the store this Hub pinned after all, so there \
                         is no break to declare"
                            .into(),
                    ));
                }
                continuity_request_from_recorded_head(
                    &recorded,
                    client.witness_id(),
                    client.witness_epoch(),
                    status.status.counter_value.saturating_add(1),
                    now_unix,
                )?
            }
        };
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer is unavailable".into()))?;

        // A persisted request that never got a receipt may be re-minted at the
        // witness's current position **exactly once**, and only when the
        // witness itself says it has no record of it.
        //
        // Without this a single lost send is terminal for one channel. The
        // continuity request id is derived from (binding, serial) and the
        // serial can never move - the Hub cannot sign - so unlike the payment
        // path there is no fresh id to retry under; the stale counter is
        // replayed into `rollback_anchor_hub_behind_witness` forever, and the
        // operator is shown a *rollback accusation* about a Hub that did
        // nothing wrong.
        //
        // Re-minting under a known id is normally an equivocation attempt, and
        // the witness treats it as one. It is safe here for one reason: the
        // witness answers a request id it holds by replaying its recorded
        // receipt, *before* it looks at the clock or the counter
        // (`rollback_anchor/witness.rs`, layer 2 idempotency). A counter
        // refusal is therefore proof that this id was never recorded, so
        // nothing is being equivocated - there is no first answer to contradict.
        let mut remint_budget = u8::from(replayed_from_disk);
        let verified = loop {
            let request_commitment = request.commitment()?;
            let signed_request = SignedHubAnchorRequestV1::sign(request.clone(), signer.account())?;

            // Durable before the wire, the same ordering the signing path uses
            // and for the same reason: a request the Hub cannot prove it made
            // is a request it cannot safely replay.
            let event = self.anchor_event(
                JournalPhase::RollbackAnchorRequestPersisted,
                &request_id,
                binding_commitment,
                &request_commitment,
                now_unix,
            );
            let persisted_request = request.clone();
            self.persist_rollback_anchor(event, |anchor| {
                anchor.reservations.insert(
                    request_id.clone(),
                    PersistedRollbackAnchorReservation {
                        request: persisted_request,
                        request_commitment: request_commitment.clone(),
                        receipt: None,
                        receipt_signature_hex: None,
                        updated_unix: now_unix,
                    },
                );
                Ok(())
            })?;

            match client
                .reserve(&signed_request, &RollbackAnchorPin::default(), now_unix)
                .await
            {
                Ok(verified) => break verified,
                Err(error) if remint_budget > 0 && witness_refused_the_position(&error) => {
                    remint_budget -= 1;
                    let status = client
                        .probe(&RollbackAnchorPin::default(), now_unix)
                        .await?;
                    if status.status.witness_instance_id
                        == identity_break.pinned_witness_instance_id
                    {
                        return Err(HubError::State(
                            "the witness answered from the store this Hub pinned after all, so \
                             there is no break to declare"
                                .into(),
                        ));
                    }
                    request = continuity_request_from_recorded_head(
                        &request,
                        client.witness_id(),
                        client.witness_epoch(),
                        status.status.counter_value.saturating_add(1),
                        now_unix,
                    )?;
                }
                Err(error) => return Err(error),
            }
        };
        let receipt = verified.receipt().clone();
        let receipt_signature_hex = verified.signed.signature_hex.clone();
        let request_commitment = receipt.request_commitment.clone();
        if receipt.binding_commitment != binding_commitment
            || receipt.serial != serial
            || receipt.proposed_bill_commitment != bill_commitment
        {
            return Err(HubError::State(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: the replacement witness receipted a different bill \
                 than the head this Hub asked it to re-anchor. Nothing is declared"
            )));
        }
        // The store that answered has to be the store the configured
        // attestation describes, checked here on the way in and not only on the
        // replay path.
        //
        // `verify_receipt` was handed a waived pin, so the pinned-instance gate
        // it would normally apply did not run. Without this the mint path
        // accepts a receipt the replay path would then reject, which silently
        // loses the "a second read replays" property: every subsequent read
        // falls through, re-signs, re-persists and re-probes, unbounded, on a
        // Hub that is already in trouble.
        if receipt.witness_instance_id != identity_break.attested_witness_instance_id {
            return Err(HubError::State(format!(
                "{REFUSAL_ATTESTATION_MISSING_OR_EXPIRED}: the witness receipted this re-anchor \
                 from store {} while the configured deployment attestation describes store {}. \
                 Nothing is declared",
                receipt.witness_instance_id, identity_break.attested_witness_instance_id
            )));
        }
        // The receipt is stored so a second read replays it. Note what is NOT
        // written here and is written by `reserve_rollback_anchor`:
        // `anchor.pin` and `anchor.channel_serials`. Adopting the replacement
        // witness into the pin is precisely the move that would let a
        // rolled-back Hub launder itself, and this ceremony must leave the Hub
        // exactly as unable to sign as it found it.
        let event = self.anchor_event(
            JournalPhase::RollbackAnchorReceiptPersisted,
            &request_id,
            binding_commitment,
            &request_commitment,
            now_unix,
        );
        self.persist_rollback_anchor(event, |anchor| {
            let reservation = anchor.reservations.get_mut(&request_id).ok_or_else(|| {
                HubError::State(
                    "rollback anchor continuity reservation disappeared before its receipt".into(),
                )
            })?;
            reservation.receipt = Some(receipt.clone());
            reservation.receipt_signature_hex = Some(receipt_signature_hex.clone());
            reservation.updated_unix = now_unix;
            Ok(())
        })?;

        Ok(AnchorContinuityDeclarationV1 {
            schema: ANCHOR_CONTINUITY_DECLARATION_SCHEMA.to_owned(),
            hub_identity: self.hub_address.trim().to_owned(),
            binding_commitment: binding_commitment.to_owned(),
            serial,
            bill_commitment,
            witness_identity_break: identity_break,
            receipts: vec![verified.signed],
            declared_at: now_unix,
        })
    }

    /// The head of one channel as the *payer* knows it: `(serial, the
    /// payer-signed Hub-unsigned bill commitment, the reservation that
    /// anchored it)`.
    ///
    /// Read out of the receipt stored beside the ledger head rather than
    /// recomputed, because the commitment the payer recorded covers the bill
    /// *before* the Hub's signature was filled in, and the Hub keeps no other
    /// copy of that value. The serial is cross-checked against the ledger head
    /// so a stale receipt cannot pass itself off as the head.
    fn recorded_anchored_head(&self, binding_commitment: &str) -> HubResult<(u64, String, String)> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let head = guard
            .hvm_registry_ledgers
            .get(binding_commitment)
            .map(|ledger| {
                (
                    ledger.latest_fully_signed_bill.serial,
                    &ledger.latest_anchor_receipts,
                )
            })
            .or_else(|| {
                guard
                    .hvm_channel_ledgers
                    .get(binding_commitment)
                    .map(|ledger| {
                        (
                            ledger.latest_fully_signed_bill.serial,
                            &ledger.latest_anchor_receipts,
                        )
                    })
            });
        let Some((ledger_serial, receipts)) = head else {
            return Err(HubError::NotFound(format!("channel {binding_commitment}")));
        };
        let receipt = receipts
            .iter()
            .map(|signed| &signed.receipt)
            .find(|receipt| receipt.serial == ledger_serial)
            .ok_or_else(|| {
                HubError::State(
                    "this channel's head carries no witness receipt, so this Hub holds no record \
                     of the bill commitment the payer accepted and has nothing to re-anchor"
                        .into(),
                )
            })?;
        Ok((
            receipt.serial,
            receipt.proposed_bill_commitment.clone(),
            receipt.request_id.clone(),
        ))
    }

    /// Reserve the exact bill position with the witness, or refuse.
    ///
    /// Returns `Ok(None)` only when no anchor is configured at all **and** this
    /// channel carries no durable condemnation. When one is configured it is
    /// mandatory: an unreachable witness, a malformed receipt or a counter
    /// behind the state all refuse rather than sign.
    ///
    /// The latch check comes **first**, before the unconfigured-anchor exit,
    /// and that ordering is the point of it. A latch is written into this
    /// Hub's own `hub-state.json` when a rollback is caught; it is durable and
    /// only the operator procedure clears it. If it were read after the exit
    /// above, an operator could un-condemn a channel caught in a real rollback
    /// by deleting five command-line flags - no cryptography, no attack, a
    /// text editor - and the Hub would co-sign the already-signed serial a
    /// second time with different balances, which is the exact double
    /// signature this whole subsystem exists to prevent. Removing the anchor
    /// removes the ability to reserve new positions; it must never remove a
    /// condemnation already on disk.
    ///
    /// This is not a new refusal for Hubs that never had an anchor: they hold
    /// no `rollback_anchor` record, so there is nothing to latch on and they
    /// reach the `Ok(None)` exit exactly as before.
    pub(super) async fn reserve_rollback_anchor(
        &self,
        subject: RollbackAnchorSubject<'_>,
        now_unix: u64,
    ) -> HubResult<Option<VerifiedAnchorReceipt>> {
        if let Some(reason) = self.latched_rollback_anchor_refusal(subject.binding_commitment)? {
            return Err(HubError::State(reason));
        }
        let Some(client) = self.rollback_anchor.as_ref() else {
            return Ok(None);
        };
        // Continuity declarations share this durable reservation map, and a
        // payment is free to choose its own `operation_id`. A payment that
        // claimed the continuity namespace would collide with a declaration's
        // entry, so the namespace is refused by name rather than left to
        // whichever write landed second.
        if subject
            .operation_id
            .starts_with(CONTINUITY_REQUEST_ID_PREFIX)
        {
            return Err(HubError::State(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: `{CONTINUITY_REQUEST_ID_PREFIX}` is reserved for \
                 rollback anchor continuity declarations and cannot be used as a payment \
                 operation id"
            )));
        }
        if !self.rollback_anchor_probe_agreed.load(Ordering::Acquire) {
            return Err(HubError::State(
                "the external rollback anchor startup probe has not agreed with the witness, so \
                 the Hub does not know whether its state is current. Refusing to sign"
                    .into(),
            ));
        }
        let anchor = self.anchor_state()?;
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub signer is unavailable".into()))?;

        // Layer 3: only a request this Hub durably persisted is ever sent, and
        // a retry replays that exact request rather than minting a new one.
        let existing = anchor.reservations.get(subject.operation_id).cloned();
        let request = match existing {
            Some(existing) => {
                if existing.request.binding_commitment != subject.binding_commitment
                    || existing.request.serial != subject.serial
                    || existing.request.proposed_bill_commitment != subject.proposed_bill_commitment
                {
                    return Err(HubError::State(format!(
                        "{REFUSAL_RECEIPT_NOT_BOUND}: this operation already reserved a different \
                         bill with the witness. The anchor authorises one exact bill at one exact \
                         serial and this is not it"
                    )));
                }
                // The replay must reproduce the *signed* receipt, because the
                // receipt travels on to the counterparty wallet, which has no
                // reason to believe an unsigned one. A reservation persisted
                // before the signature was kept therefore falls through and
                // re-reserves with the witness rather than serving a bill whose
                // anchor evidence cannot be checked by its recipient. The
                // witness replays its own recorded receipt for a request
                // commitment it has already answered, so this costs a round
                // trip and moves nothing.
                if let (Some(receipt), Some(signature_hex)) = (
                    existing.receipt.as_ref(),
                    existing.receipt_signature_hex.as_ref(),
                ) && receipt.receipt_expires_at > now_unix
                {
                    let signed = SignedHubWitnessReceiptV1 {
                        receipt: receipt.clone(),
                        signature_hex: signature_hex.clone(),
                    };
                    // Re-verified rather than trusted for having come off this
                    // Hub's own disk. The disk is the thing this whole
                    // subsystem assumes may have been tampered with.
                    signed.verify_against_pinned_key(client.witness_receipt_address())?;
                    return Ok(Some(VerifiedAnchorReceipt {
                        signed,
                        verified_unix: now_unix,
                    }));
                }
                existing.request
            }
            None => {
                let status = client.probe(&anchor.pin, now_unix).await?;
                if let Some(position) = status.status.channel(subject.binding_commitment)
                    && position.serial >= subject.serial
                {
                    return Err(self.latch_rollback_anchor_refusal(
                        subject.binding_commitment,
                        format!(
                            "{REFUSAL_HUB_BEHIND_WITNESS}: the witness has already recorded \
                             serial {} for this channel and the Hub is proposing to sign serial \
                             {}. This Hub's durable state is behind the anchor, which is what a \
                             restored-from-backup Hub looks like. Signing here would co-sign a \
                             serial that is already signed, with different balances, and both \
                             signatures would be valid to the contract. Follow \
                             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md and do NOT re-sign the gap",
                            position.serial, subject.serial
                        ),
                        now_unix,
                    ));
                }
                let counter_value = status
                    .status
                    .counter_value
                    .max(anchor.pin.highest_counter_value)
                    .checked_add(1)
                    .ok_or_else(|| HubError::State("rollback anchor counter overflow".into()))?;
                self.build_anchor_request(&subject, client, counter_value, now_unix)?
            }
        };
        let request_commitment = request.commitment()?;
        let signed = SignedHubAnchorRequestV1::sign(request.clone(), signer.account())?;
        let event = self.anchor_subject_event(
            &subject,
            JournalPhase::RollbackAnchorRequestPersisted,
            &request_commitment,
            now_unix,
        );
        self.persist_rollback_anchor(event, |anchor| {
            anchor.reservations.insert(
                subject.operation_id.to_owned(),
                PersistedRollbackAnchorReservation {
                    request: request.clone(),
                    request_commitment: request_commitment.clone(),
                    receipt: None,
                    receipt_signature_hex: None,
                    updated_unix: now_unix,
                },
            );
            Ok(())
        })?;

        let pin = self.anchor_state()?.pin;
        let verified = match client.reserve(&signed, &pin, now_unix).await {
            Ok(verified) => verified,
            Err(error) => {
                // Neither a signed refusal nor silence is permission to sign,
                // so this signature is refused either way. What differs is
                // whether the channel is condemned: a rollback is a durable,
                // human-resolved condition and latches; a dropped packet or a
                // timed-out request refuses this attempt and nothing more.
                let message = error.to_string();
                if crate::rollback_anchor::protocol::refusal_condemns_the_channel(&message) {
                    return Err(self.latch_rollback_anchor_refusal(
                        subject.binding_commitment,
                        message,
                        now_unix,
                    ));
                }
                return Err(error);
            }
        };
        let receipt = verified.receipt().clone();
        let receipt_signature_hex = verified.signed.signature_hex.clone();
        let event = self.anchor_subject_event(
            &subject,
            JournalPhase::RollbackAnchorReceiptPersisted,
            &request_commitment,
            now_unix,
        );
        self.persist_rollback_anchor(event, |anchor| {
            anchor.pin.highest_counter_value =
                anchor.pin.highest_counter_value.max(receipt.counter_value);
            anchor.pin.witness_instance_id = receipt.witness_instance_id.clone();
            anchor.pin.witness_id = receipt.witness_id.clone();
            anchor.pin.updated_unix = now_unix;
            let serial = anchor
                .channel_serials
                .entry(receipt.binding_commitment.clone())
                .or_insert(0);
            *serial = (*serial).max(receipt.serial);
            let reservation = anchor
                .reservations
                .get_mut(subject.operation_id)
                .ok_or_else(|| {
                    HubError::State(
                        "rollback anchor reservation disappeared before its receipt".into(),
                    )
                })?;
            reservation.receipt = Some(receipt.clone());
            reservation.receipt_signature_hex = Some(receipt_signature_hex.clone());
            reservation.updated_unix = now_unix;
            Ok(())
        })?;
        Ok(Some(verified))
    }

    fn build_anchor_request(
        &self,
        subject: &RollbackAnchorSubject<'_>,
        client: &RollbackAnchorClient,
        counter_value: u64,
        now_unix: u64,
    ) -> HubResult<HubAnchorRequestV1> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let request = HubAnchorRequestV1 {
            request_version: 1,
            request_id: subject.operation_id.to_owned(),
            hub_identity: self.hub_address.trim().to_owned(),
            witness_id: client.witness_id().to_owned(),
            witness_epoch: client.witness_epoch(),
            settlement_profile: subject.settlement_profile.to_owned(),
            network_instance_id: subject.network_instance_id.to_owned(),
            binding_commitment: subject.binding_commitment.to_owned(),
            channel_id: subject.channel_id.to_owned(),
            reuse_version: subject.reuse_version,
            serial: subject.serial,
            previous_bill_commitment: subject.previous_bill_commitment.clone(),
            proposed_bill_commitment: subject.proposed_bill_commitment.clone(),
            counter_value,
            hub_journal_sequence: guard.journal_sequence,
            hub_journal_head_hash: normalize_hash(&guard.journal_head),
            hub_state_commitment: normalize_hash(&state_commitment(&guard)?),
            created_at: now_unix,
            expires_at: now_unix.saturating_add(MAX_ANCHOR_LIFETIME_SECS),
        };
        request.validate_shape()?;
        Ok(request)
    }

    /// A refused channel is latched durably. It will not sign again on this
    /// Hub without the operator procedure, and while any channel is latched
    /// `external_rollback_anchor_ready` reads false for the whole Hub.
    fn latch_rollback_anchor_refusal(
        &self,
        binding_commitment: &str,
        reason: String,
        now_unix: u64,
    ) -> HubError {
        let binding = binding_commitment.to_owned();
        let latched = reason.clone();
        let event = self.anchor_event(
            JournalPhase::RollbackAnchorRefused,
            &format!("rollback-anchor-latch-{binding_commitment}"),
            binding_commitment,
            binding_commitment,
            now_unix,
        );
        if let Err(error) = self.persist_rollback_anchor(event, move |anchor| {
            anchor.latched_refusals.entry(binding).or_insert(latched);
            Ok(())
        }) {
            return HubError::State(format!("{reason} (and the latch did not persist: {error})"));
        }
        HubError::State(reason)
    }

    fn persist_rollback_anchor(
        &self,
        event: JournalEvent,
        mutate: impl FnOnce(&mut PersistedRollbackAnchorState) -> HubResult<()>,
    ) -> HubResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut next_state = guard.clone();
        let mut anchor = next_state.rollback_anchor.clone().unwrap_or_default();
        mutate(&mut anchor)?;
        next_state.rollback_anchor = Some(anchor);
        validate_hvm_state(&next_state)?;
        // A Hub without authenticated durable storage cannot settle at all
        // (`settlement_ready`), so the anchor record has nowhere durable to
        // live and nothing to protect. Everywhere that can sign, this goes
        // through the same authenticated write as every other money-path
        // transition, so the state and the journal cannot drift apart.
        //
        // It is still worth saying out loud when a witness *is* configured,
        // because a pin held only in memory is re-adopted on first contact from
        // whichever store answers after a restart - so that Hub would publish
        // no identity break and report a probe that agreed. It is not refused
        // here: such a Hub is already blocked from payments for a strictly
        // stronger reason (`hub_operational_ready` is false without
        // authenticated storage, so nothing settles), and refusing here would
        // break the measurement path without protecting a signature that could
        // never happen. What it must not do is stay unsaid, so
        // `note_rollback_anchor_pin_is_not_durable` publishes it.
        if self.journal.is_none() || self.state_store.is_none() {
            *guard = next_state;
            return Ok(());
        }
        self.commit_authenticated_state(&mut guard, next_state, event)
    }

    fn anchor_event(
        &self,
        phase: JournalPhase,
        operation_id: &str,
        channel_id: &str,
        request_commitment: &str,
        now_unix: u64,
    ) -> JournalEvent {
        JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: channel_id.to_owned(),
            channel_reuse_version: 0,
            operation_id: operation_id.to_owned(),
            operation_type: JournalOperationType::HvmPayment,
            operation_phase: phase,
            amount_units: 0,
            sender: self.hub_address.trim().to_owned(),
            recipient: self.hub_address.trim().to_owned(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: operation_id.to_owned(),
            request_commitment: request_commitment.to_owned(),
            expected_bill_number: None,
            unsigned_state_commitment: Some(request_commitment.to_owned()),
            created_at: now_unix,
        }
    }

    fn anchor_subject_event(
        &self,
        subject: &RollbackAnchorSubject<'_>,
        phase: JournalPhase,
        request_commitment: &str,
        now_unix: u64,
    ) -> JournalEvent {
        JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: subject.channel_id.to_owned(),
            channel_reuse_version: u64::from(subject.reuse_version),
            operation_id: subject.operation_id.to_owned(),
            operation_type: JournalOperationType::HvmPayment,
            operation_phase: phase,
            amount_units: subject.amount_units,
            sender: subject.payer.to_owned(),
            recipient: subject.recipient.to_owned(),
            previous_state_commitment: String::new(),
            new_state_commitment: String::new(),
            idempotency_key: subject.idempotency_key.to_owned(),
            request_commitment: request_commitment.to_owned(),
            expected_bill_number: Some(subject.serial),
            unsigned_state_commitment: Some(subject.binding_commitment.to_owned()),
            created_at: now_unix,
        }
    }
}

fn normalize_hash(value: &str) -> String {
    if value.len() == 64 {
        value.to_owned()
    } else {
        hex::encode(sys::sha2(value.as_bytes()))
    }
}

/// Re-derive the anchor commitment of the bill about to be signed, and refuse
/// if it is not the exact bill the receipt authorises.
///
/// This is verification step 8: with the serial bound but not the bill, one
/// receipt at serial 4 would authorise *any* serial-4 bill - two different
/// balance splits, both signed, both valid. This is the check that makes the
/// receipt attest to a unique bill rather than to a position.
pub(super) fn require_receipt_authorises_bill(
    receipt: Option<&VerifiedAnchorReceipt>,
    bill_commitment: &str,
    serial: u64,
    now_unix: u64,
) -> HubResult<()> {
    let Some(verified) = receipt else {
        return Ok(());
    };
    if verified.receipt().proposed_bill_commitment != bill_commitment
        || verified.receipt().serial != serial
    {
        return Err(HubError::State(format!(
            "{REFUSAL_RECEIPT_NOT_BOUND}: the bill about to be signed is not the bill the witness \
             receipt authorises. Refusing to sign"
        )));
    }
    if verified.receipt().receipt_expires_at <= now_unix {
        return Err(HubError::State(format!(
            "{REFUSAL_RECEIPT_NOT_BOUND}: the witness receipt expired before the signing key was \
             reached. Refusing to sign"
        )));
    }
    Ok(())
}

/// The most receipts one co-signed bill may carry.
///
/// The Hub's witness client is single-witness today, so the honest count is
/// one; the cap exists so that a future multi-witness Hub, or a Hub trying to
/// bury the one receipt that matters under a hundred it minted itself, cannot
/// hand the counterparty an unbounded list to verify.
pub const MAX_ANCHOR_RECEIPTS_PER_BILL: usize = 8;

/// The last gate before a co-signed bill leaves this Hub.
///
/// # Why this exists at all
///
/// The counterparty's overlap rule is: every new bill must carry a receipt from
/// at least one witness that receipted the counterparty's most recently
/// accepted bill. That rule is what closes the circularity in the anchor - the
/// Hub chooses its own witnesses, so every Hub-side check is asked of a party
/// the Hub selected, but the counterparty's memory of *which* witnesses it has
/// already seen is on a different machine under a different key, and the Hub
/// cannot reach it.
///
/// None of which survives the receipt failing to leave the process. If an
/// anchored Hub could serve a bill with an empty receipt list, the counterparty
/// would read it as "this Hub shows me no anchor", which resets the ratchet to
/// whatever the Hub declares next - the rollback becomes free, with no
/// cryptography and no attack. An empty list and an absent field are the same
/// value to the wallet precisely so that omission is loud; this check is what
/// makes sure an honest Hub never produces that value by accident.
///
/// So: when an anchor is configured, a bill without its receipts is not served.
/// This is not a bypass with the sign flipped - there is no flag, no degraded
/// mode and no "skip if unavailable". A Hub whose witness is unreachable has
/// already refused to sign upstream of here, so no bill exists to serve.
pub(super) fn require_receipts_accompany_bill(
    anchor_configured: bool,
    receipts: &[SignedHubWitnessReceiptV1],
    proposed_bill_commitment: &str,
    serial: u64,
    binding_commitment: &str,
    hub_identity: &str,
) -> HubResult<()> {
    if anchor_configured && receipts.is_empty() {
        return Err(HubError::State(format!(
            "{REFUSAL_RECEIPT_NOT_BOUND}: this Hub has an external rollback anchor configured but \
             produced no witness receipt to serve with the bill. A counterparty reads a bill with \
             no receipts as a Hub with no anchor, which resets its witness ratchet. Refusing to \
             serve the bill"
        )));
    }
    if receipts.len() > MAX_ANCHOR_RECEIPTS_PER_BILL {
        return Err(HubError::State(format!(
            "{REFUSAL_RECEIPT_NOT_BOUND}: {} witness receipts for one bill exceeds the {} a \
             counterparty is asked to verify",
            receipts.len(),
            MAX_ANCHOR_RECEIPTS_PER_BILL
        )));
    }
    for signed in receipts {
        let receipt = &signed.receipt;
        receipt.validate_shape()?;
        if receipt.proposed_bill_commitment != proposed_bill_commitment
            || receipt.serial != serial
            || receipt.binding_commitment != binding_commitment
            || receipt.hub_identity != hub_identity
        {
            return Err(HubError::State(format!(
                "{REFUSAL_RECEIPT_NOT_BOUND}: a witness receipt about to be served is not bound to \
                 this bill, this channel and this Hub. Refusing to serve the bill"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod outbound_receipt_gate_tests {
    use super::{MAX_ANCHOR_RECEIPTS_PER_BILL, require_receipts_accompany_bill};
    use crate::rollback_anchor::{HubWitnessReceiptV1, SignedHubWitnessReceiptV1};

    const BILL: &str = "aa";
    const CHANNEL: &str = "bb";
    const HUB: &str = "1HubIdentityForTest";

    fn receipt() -> SignedHubWitnessReceiptV1 {
        SignedHubWitnessReceiptV1 {
            receipt: HubWitnessReceiptV1 {
                receipt_version: 1,
                request_id: "operation-1".into(),
                request_commitment: "cc".repeat(32),
                witness_id: "witness-1".into(),
                witness_epoch: 1,
                witness_instance_id: "dd".repeat(32),
                witness_boot_id: "ee".repeat(32),
                hub_identity: HUB.into(),
                binding_commitment: CHANNEL.repeat(32),
                serial: 2,
                proposed_bill_commitment: BILL.repeat(32),
                previous_counter_value: 0,
                counter_value: 1,
                accepted_at: 1_900_000_000,
                receipt_expires_at: 1_900_000_060,
            },
            // The gate does not verify the signature: by the time it runs, the
            // anchor client has already verified this receipt against the
            // pinned witness key. What the gate checks is that the receipt
            // exists and is bound to the bill about to be served.
            signature_hex: String::new(),
        }
    }

    fn check(anchored: bool, receipts: &[SignedHubWitnessReceiptV1]) -> Result<(), String> {
        require_receipts_accompany_bill(
            anchored,
            receipts,
            &BILL.repeat(32),
            2,
            &CHANNEL.repeat(32),
            HUB,
        )
        .map_err(|error| error.to_string())
    }

    /// The rule this whole subsystem is for. An anchored Hub that served a
    /// bill with no receipts would be read by the counterparty as a Hub with
    /// no anchor, which resets its witness ratchet to whatever the Hub
    /// declares next - the rollback becomes free, with no cryptography.
    #[test]
    fn an_anchored_hub_never_serves_a_bill_without_its_receipts() {
        let error = check(true, &[]).expect_err("an anchored Hub must not serve a bare bill");
        assert!(
            error.contains("rollback_anchor_receipt_not_bound_to_request"),
            "{error}"
        );
        assert!(error.contains("resets its witness ratchet"), "{error}");
    }

    /// And the honest case still passes, or the rule is just an outage.
    #[test]
    fn an_anchored_hub_serves_a_bill_bound_to_its_receipt() {
        check(true, &[receipt()]).unwrap();
    }

    /// A Hub with no anchor configured has nothing to attach and says so by
    /// attaching an empty list. That is the shipped default per ADR-001 and it
    /// must not be turned into an outage.
    #[test]
    fn a_hub_with_no_anchor_serves_an_empty_list_rather_than_failing() {
        check(false, &[]).unwrap();
    }

    /// Padding the set is how a Hub would try to bury the one receipt that
    /// matters. The counterparty is never asked to verify an unbounded list.
    #[test]
    fn more_receipts_than_a_counterparty_is_asked_to_verify_are_refused() {
        let padded = vec![receipt(); MAX_ANCHOR_RECEIPTS_PER_BILL + 1];
        let error = check(true, &padded).expect_err("a padded set must be refused");
        assert!(error.contains("exceeds the 8"), "{error}");
    }

    /// A receipt for some other bill, channel or Hub authorises nothing here,
    /// and serving one would hand the counterparty evidence that looks valid
    /// and proves nothing about this payment.
    #[test]
    fn a_receipt_bound_to_something_else_is_refused() {
        for mutate in [
            (|signed: &mut SignedHubWitnessReceiptV1| {
                signed.receipt.proposed_bill_commitment = "ff".repeat(32);
            }) as fn(&mut SignedHubWitnessReceiptV1),
            |signed| signed.receipt.serial = 3,
            |signed| signed.receipt.binding_commitment = "ff".repeat(32),
            |signed| signed.receipt.hub_identity = "1SomeOtherHub".into(),
        ] {
            let mut signed = receipt();
            mutate(&mut signed);
            let error = check(true, std::slice::from_ref(&signed))
                .expect_err("a receipt bound elsewhere must be refused");
            assert!(
                error.contains("rollback_anchor_receipt_not_bound_to_request"),
                "{error}"
            );
        }
    }
}
