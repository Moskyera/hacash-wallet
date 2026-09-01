//! Continuity: what a Hub says when its one witness is no longer the witness
//! it pinned.
//!
//! # Why this exists
//!
//! A Hub has exactly one witness (ADR-001, settled). Running one at all is
//! optional, but a Hub that has one is pinned to that witness's durable store
//! by `RollbackAnchorPin::witness_instance_id`. Lose the store - the witness
//! operator rebuilds it, or the operator has to move to a replacement witness -
//! and the pin no longer matches. From that moment:
//!
//! * the startup probe refuses `rollback_anchor_witness_instance_changed`,
//! * `rollback_anchor_probe_agreed` never becomes true,
//! * every channel stops signing, permanently.
//!
//! None of that is wrong. A fresh witness store agrees with everything, which
//! is amnesia rather than agreement, and there is no Hub-side check that can
//! tell an honest replacement apart from a rolled-back Hub shopping for a
//! witness with no memory - that is proven, in this repository, by
//! `a_joining_witness_cannot_be_told_apart_from_an_amnesiac_one`.
//!
//! What *is* wrong is the exit. With the anchor stuck refusing, the only way an
//! honest operator gets their Hub signing again is to delete the five
//! `--rollback-witness-*` flags, which is the anchor's failure mode being "turn
//! it off". And the party that could actually adjudicate the question - the
//! payer, whose memory of which witness signed its last bill lives on a
//! different machine under a different key and was in neither backup set - is
//! never told anything happened.
//!
//! # What this is
//!
//! A **declaration**: the head the payer already holds, re-anchored under the
//! witness that is answering now.
//!
//! Same channel, same serial, same bill commitment. **Nothing new is signed.**
//! That is the whole design constraint: a Hub that had to sign something in
//! order to prove itself would be signing under a witness it had just chosen,
//! which is the circle this subsystem exists to break. Re-anchoring a head the
//! counterparty already holds proves the new witness will vouch for the
//! position the payer already believes, and proves nothing else - which is
//! exactly the amount of evidence the payer needs to make a decision.
//!
//! The payer feeds it to `ClientL2Safety::accept_anchored_bill`, which takes
//! the re-affirmation path for its recorded head, sees the pinned witness
//! missing from the offered set, and parks
//! `ANCHOR_WITNESS_DECISION_REQUIRED` for a human - accept the new witness set,
//! or close the channel on the last accepted head. With one witness the change
//! is always a *total* swap, so the payer sees the strong zero-overlap
//! sentence rather than a mild one.
//!
//! # What this is not
//!
//! It is not a bypass and it does not restore signing. Producing a declaration
//! does not move the pin, does not set `rollback_anchor_probe_agreed`, does not
//! touch `channel_serials`, and does not clear a latch. A Hub that will not
//! sign before it serves one will not sign after. The only thing that changes
//! is that the break is now legible to the one party that can judge it.

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};

use super::protocol::{
    MAX_ANCHOR_LIFETIME_SECS, REFUSAL_WITNESS_INSTANCE_CHANGED, SignedHubWitnessReceiptV1,
};
use super::{HubAnchorRequestV1, RollbackAnchorPin};

pub const ANCHOR_CONTINUITY_DECLARATION_SCHEMA: &str =
    "hpay-hub-rollback-anchor-continuity-declaration/1";

pub const WITNESS_IDENTITY_BREAK_SCHEMA: &str = "hpay-hub-rollback-anchor-witness-identity-break/1";

/// The `request_id` namespace the continuity ceremony reserves.
///
/// Continuity reservations are persisted in the same durable map as ordinary
/// per-payment reservations, so that a repeated request replays the identical
/// reservation instead of burning a fresh position on the new witness at every
/// read. Sharing the map means sharing the key space, so the prefix is
/// reserved: [`crate::state::HubState::reserve_rollback_anchor`] refuses a
/// payment whose `operation_id` claims it.
pub const CONTINUITY_REQUEST_ID_PREFIX: &str = "rollback-anchor-continuity/";

/// The deterministic reservation id for one channel's continuity declaration.
///
/// Deterministic on purpose: it is what makes a second read replay the first
/// declaration rather than mint a second one.
pub fn continuity_request_id(binding_commitment: &str, serial: u64) -> String {
    format!("{CONTINUITY_REQUEST_ID_PREFIX}{binding_commitment}/{serial}")
}

/// The break itself, stated rather than inferred.
///
/// Measured entirely from this Hub's own durable pin and its own configuration:
/// no network, so it is publishable on `/v1/readiness/mainnet` whether or not
/// the replacement witness can be reached. `attested_witness_instance_id` is
/// the store the *currently configured* deployment attestation describes, which
/// is the store the witness must be answering from -
/// `RollbackAnchorClient::verify_status` refuses any other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessIdentityBreakV1 {
    pub schema: String,
    pub hub_identity: String,
    /// What this Hub pinned, from its own state file.
    pub pinned_witness_id: String,
    pub pinned_witness_instance_id: String,
    pub pinned_highest_counter_value: u64,
    /// What it is configured with now.
    pub configured_witness_id: String,
    pub configured_witness_epoch: u64,
    pub attested_witness_instance_id: String,
    /// The identifier `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 indexes
    /// its procedures by, so the published break and the probe refusal are one
    /// string rather than two that can drift.
    pub refusal_identifier: String,
    pub observed_at: u64,
}

impl WitnessIdentityBreakV1 {
    /// Is the witness this Hub is configured with a different durable store
    /// from the one it pinned?
    ///
    /// An empty pin is *not* a break: that is a Hub which has never completed a
    /// probe, and it adopts on first contact.
    pub fn detect(
        hub_identity: &str,
        pin: &RollbackAnchorPin,
        configured_witness_id: &str,
        configured_witness_epoch: u64,
        attested_witness_instance_id: &str,
        now_unix: u64,
    ) -> Option<Self> {
        if pin.witness_instance_id.is_empty() {
            return None;
        }
        if pin.witness_instance_id == attested_witness_instance_id {
            return None;
        }
        Some(Self {
            schema: WITNESS_IDENTITY_BREAK_SCHEMA.to_owned(),
            hub_identity: hub_identity.trim().to_owned(),
            pinned_witness_id: pin.witness_id.clone(),
            pinned_witness_instance_id: pin.witness_instance_id.clone(),
            pinned_highest_counter_value: pin.highest_counter_value,
            configured_witness_id: configured_witness_id.to_owned(),
            configured_witness_epoch,
            attested_witness_instance_id: attested_witness_instance_id.to_owned(),
            refusal_identifier: REFUSAL_WITNESS_INSTANCE_CHANGED.to_owned(),
            observed_at: now_unix,
        })
    }
}

/// The head the payer already holds, re-anchored under the witness answering
/// now.
///
/// `serial` and `bill_commitment` are read out of this Hub's durable ledger and
/// out of the receipt that authorised that head, so `bill_commitment` is the
/// payer-signed, Hub-UNSIGNED commitment - the same value
/// `ClientL2Safety::accept_anchored_bill` recorded as `accepted_bill_commitment`
/// when it accepted the bill. Anything else would not match the payer's memory
/// and would be adjudicated as a different bill rather than as a re-affirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorContinuityDeclarationV1 {
    pub schema: String,
    pub hub_identity: String,
    pub binding_commitment: String,
    pub serial: u64,
    pub bill_commitment: String,
    pub witness_identity_break: WitnessIdentityBreakV1,
    /// The receipts the witness answering now issued for that exact head.
    /// Never empty in a served declaration: an empty list would read to the
    /// payer as "this Hub shows me no anchor", which is the ratchet reset this
    /// whole subsystem exists to prevent.
    pub receipts: Vec<SignedHubWitnessReceiptV1>,
    pub declared_at: u64,
}

/// Rebuild the anchor request that produced a recorded head, addressed to a
/// different witness.
///
/// **Every field describing the bill is copied verbatim** from the request this
/// Hub durably persisted when it reserved that head: channel, serial, previous
/// and proposed bill commitments, settlement profile, network, and the journal
/// and state commitments as they stood then. Only the four fields that name the
/// *witness and the attempt* move: witness id, witness epoch, the counter
/// position on the new witness, and the request's own id and lifetime.
///
/// That split is the safety argument in one function. There is no input here
/// that lets a caller change what is being attested to - a re-anchor cannot
/// become a re-write, because the bill fields are not parameters.
pub fn continuity_request_from_recorded_head(
    recorded: &HubAnchorRequestV1,
    witness_id: &str,
    witness_epoch: u64,
    counter_value: u64,
    now_unix: u64,
) -> HubResult<HubAnchorRequestV1> {
    if counter_value == 0 {
        return Err(HubError::State(
            "a continuity re-anchor needs the position the answering witness is at".into(),
        ));
    }
    let request = HubAnchorRequestV1 {
        request_id: continuity_request_id(&recorded.binding_commitment, recorded.serial),
        witness_id: witness_id.to_owned(),
        witness_epoch,
        counter_value,
        created_at: now_unix,
        expires_at: now_unix.saturating_add(MAX_ANCHOR_LIFETIME_SECS),
        ..recorded.clone()
    };
    request.validate_shape()?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded() -> HubAnchorRequestV1 {
        HubAnchorRequestV1 {
            request_version: 1,
            request_id: "payment-7".into(),
            hub_identity: "1HubIdentityForTest".into(),
            witness_id: "witness-incumbent".into(),
            witness_epoch: 1,
            settlement_profile: "hpay-registry".into(),
            network_instance_id: "aa".repeat(32),
            binding_commitment: "bb".repeat(32),
            channel_id: "channel-1".into(),
            reuse_version: 0,
            serial: 4,
            previous_bill_commitment: "cc".repeat(32),
            proposed_bill_commitment: "dd".repeat(32),
            counter_value: 9,
            hub_journal_sequence: 12,
            hub_journal_head_hash: "ee".repeat(32),
            hub_state_commitment: "ff".repeat(32),
            created_at: 1_900_000_000,
            expires_at: 1_900_000_060,
        }
    }

    /// The rule the payer's whole adjudication rests on: the re-anchor is of
    /// the *same* bill at the *same* serial. If any of this could move, the
    /// ceremony would be a way to get a fresh witness to vouch for something
    /// the counterparty never saw.
    #[test]
    fn a_continuity_re_anchor_changes_the_witness_and_nothing_about_the_bill() {
        let recorded = recorded();
        let reanchored = continuity_request_from_recorded_head(
            &recorded,
            "witness-replacement",
            3,
            1,
            1_900_001_000,
        )
        .unwrap();

        assert_eq!(reanchored.binding_commitment, recorded.binding_commitment);
        assert_eq!(reanchored.channel_id, recorded.channel_id);
        assert_eq!(reanchored.reuse_version, recorded.reuse_version);
        assert_eq!(reanchored.serial, recorded.serial);
        assert_eq!(
            reanchored.previous_bill_commitment,
            recorded.previous_bill_commitment
        );
        assert_eq!(
            reanchored.proposed_bill_commitment,
            recorded.proposed_bill_commitment
        );
        assert_eq!(reanchored.settlement_profile, recorded.settlement_profile);
        assert_eq!(reanchored.network_instance_id, recorded.network_instance_id);
        assert_eq!(reanchored.hub_identity, recorded.hub_identity);
        assert_eq!(
            reanchored.hub_journal_sequence,
            recorded.hub_journal_sequence
        );
        assert_eq!(
            reanchored.hub_journal_head_hash,
            recorded.hub_journal_head_hash
        );
        assert_eq!(
            reanchored.hub_state_commitment,
            recorded.hub_state_commitment
        );

        assert_eq!(reanchored.witness_id, "witness-replacement");
        assert_eq!(reanchored.witness_epoch, 3);
        assert_eq!(reanchored.counter_value, 1);
        assert_eq!(reanchored.created_at, 1_900_001_000);
        assert_eq!(
            reanchored.request_id,
            continuity_request_id(&recorded.binding_commitment, 4)
        );
        assert!(
            reanchored
                .request_id
                .starts_with(CONTINUITY_REQUEST_ID_PREFIX)
        );
    }

    /// Deterministic, because a second read must replay the first declaration
    /// rather than advance the new witness a second time.
    #[test]
    fn two_re_anchors_of_one_head_carry_the_same_reservation_id() {
        let recorded = recorded();
        let first =
            continuity_request_from_recorded_head(&recorded, "w", 1, 1, 1_900_001_000).unwrap();
        let second =
            continuity_request_from_recorded_head(&recorded, "w", 1, 1, 1_900_009_000).unwrap();
        assert_eq!(first.request_id, second.request_id);
    }

    /// An empty pin is a Hub that has never completed a probe. It adopts on
    /// first contact; it is not broken, and declaring a break for it would be a
    /// blocker every unanchored Hub published forever.
    #[test]
    fn an_unpinned_hub_has_no_break_and_a_matching_one_has_none_either() {
        assert!(
            WitnessIdentityBreakV1::detect(
                "1Hub",
                &RollbackAnchorPin::default(),
                "witness-a",
                1,
                &"11".repeat(32),
                1_900_000_000,
            )
            .is_none()
        );
        let pin = RollbackAnchorPin {
            witness_id: "witness-a".into(),
            witness_instance_id: "11".repeat(32),
            highest_counter_value: 4,
            updated_unix: 1_899_000_000,
        };
        assert!(
            WitnessIdentityBreakV1::detect(
                "1Hub",
                &pin,
                "witness-a",
                1,
                &"11".repeat(32),
                1_900_000_000,
            )
            .is_none(),
            "a Hub whose configured witness is still the pinned store is not broken"
        );
        let broken = WitnessIdentityBreakV1::detect(
            "1Hub",
            &pin,
            "witness-b",
            1,
            &"22".repeat(32),
            1_900_000_000,
        )
        .expect("a different durable store is the break");
        assert_eq!(broken.pinned_witness_instance_id, "11".repeat(32));
        assert_eq!(broken.attested_witness_instance_id, "22".repeat(32));
        assert_eq!(
            broken.refusal_identifier,
            "rollback_anchor_witness_instance_changed"
        );
    }
}
