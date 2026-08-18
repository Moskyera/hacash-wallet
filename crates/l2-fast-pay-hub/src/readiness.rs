//! Authoritative, short-lived mainnet profile gate for the official Hacash
//! ChannelPay-compatible money path.

use field::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::amount::HacAmount;
use crate::error::{HubError, HubResult};
use crate::node::{
    ACTION_CHANNEL_OPEN, ACTION_COOPERATIVE_ORIGINAL_CLOSE, FullnodeCapabilitiesV1,
    HACASH_MAINNET_MIN_SAFE_HEIGHT,
};

pub const READINESS_SCHEMA: &str = "hpay-fast-pay-mainnet-readiness/1";
pub const MAINNET_PILOT_PROFILE: &str = "mainnet-pilot";
pub const MAINNET_BOUNDED_PILOT_PROFILE: &str = "mainnet-bounded-pilot";
/// Bounded mainnet pilot ceilings. Operators may configure lower values, but
/// no runtime flag can exceed these compile-time limits.
pub const MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU: u64 = 100_000_000;
pub const MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU: u64 = 1_000_000_000;
pub const MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU: u64 = 10_000_000_000;
pub const ZHU_PER_MILLIMEI: u64 = 100_000;
const READINESS_VALID_SECONDS: u64 = 60;
const ADMISSION_NOT_EVALUATED: &str = "mainnet_pilot_admission_policy_not_evaluated";
/// Published on `/v1/readiness/mainnet` while this Hub's durable state holds
/// any channel latched in external rollback anchor refusal, whether or not a
/// witness is configured. Indexed by `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`
/// section 2 like every other anchor identifier.
pub const ROLLBACK_ANCHOR_LATCHED_BLOCKER: &str = "rollback_anchor_channels_latched_in_refusal";
/// Published when this Hub cannot read its own durable rollback-anchor pin and
/// therefore cannot say whether the witness it is configured with is the
/// witness it pinned. Not the same claim as
/// `rollback_anchor_witness_instance_changed`, which asserts the pin *did*
/// move; this one asserts only that the question could not be answered, and
/// blocks payments for exactly that reason. Indexed by
/// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 like every other anchor
/// identifier.
pub const ROLLBACK_ANCHOR_IDENTITY_UNREADABLE_BLOCKER: &str =
    "rollback_anchor_witness_identity_unreadable";

pub fn is_mainnet_pilot_profile(profile: &str) -> bool {
    matches!(
        profile,
        MAINNET_PILOT_PROFILE | MAINNET_BOUNDED_PILOT_PROFILE
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainnetPilotAdmissionPolicy {
    allowed_user_addresses: BTreeSet<String>,
    max_aggregate_tvl_hac_zhu: u64,
}

impl MainnetPilotAdmissionPolicy {
    pub fn try_new<I, S>(
        allowed_user_addresses: I,
        max_aggregate_tvl_hac_zhu: u64,
    ) -> HubResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if max_aggregate_tvl_hac_zhu == 0
            || max_aggregate_tvl_hac_zhu > MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU
        {
            return Err(HubError::State(format!(
                "mainnet pilot aggregate TVL cap must be between 1 and {MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU} zhu"
            )));
        }
        let mut allowed = BTreeSet::new();
        for value in allowed_user_addresses {
            let readable = value.as_ref().trim();
            if readable.is_empty() {
                continue;
            }
            let address = Address::from_readable(readable).map_err(|error| {
                HubError::State(format!("invalid mainnet pilot allowlist address: {error}"))
            })?;
            allowed.insert(address.to_readable());
        }
        Ok(Self {
            allowed_user_addresses: allowed,
            max_aggregate_tvl_hac_zhu,
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.allowed_user_addresses.is_empty()
    }

    pub fn allows(&self, user_address: &str) -> bool {
        self.allowed_user_addresses.contains(user_address)
    }

    pub fn max_aggregate_tvl_hac_zhu(&self) -> u64 {
        self.max_aggregate_tvl_hac_zhu
    }
}

impl Default for MainnetPilotAdmissionPolicy {
    fn default() -> Self {
        Self {
            allowed_user_addresses: BTreeSet::new(),
            max_aggregate_tvl_hac_zhu: MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainnetReadinessV1 {
    pub schema: &'static str,
    pub evaluated_unix: u64,
    pub valid_until_unix: u64,
    pub profile: String,
    pub payments_enabled: bool,
    pub close_enabled: bool,
    pub mainnet_detected: Option<bool>,
    pub fullnode_capabilities: Option<FullnodeCapabilitiesV1>,
    /// The evidence behind `trustless_finality`'s anchor half, published in
    /// full beside the flag it explains.
    ///
    /// **Shape, and why.** This is the same shape `fullnode_capabilities`
    /// already uses one field above: the measured evidence for a guarantee
    /// travels as a nested document beside the boolean it produced, verbatim
    /// as measured, so the published posture and the enforced gate are read off
    /// one object and cannot drift into disagreeing. A hand-copied subset would
    /// be a second place to forget.
    ///
    /// `None` is itself the honest answer, and it means exactly one thing: this
    /// Hub has no verified live witness right now - none configured, or one
    /// that could not be reached, could not be verified against its pinned
    /// keys, or answered from a store this Hub did not pin. It never means
    /// "anchor not required". Before this field existed the *only* outward sign
    /// that an anchor existed at all was the absence of a blocker string, which
    /// made a same-operator loopback single-host witness indistinguishable over
    /// the API from a neutral third party on separate infrastructure.
    ///
    /// It is published whether or not the flag reads `true`, because the two
    /// answer different questions. A witness can be live, attested and pinned
    /// while a channel is latched in refusal: flag `false`, posture still worth
    /// reading. `ROLLBACK-ANCHOR-PROTOCOL.md` section 10.
    ///
    /// Deliberately not on `/v1/health`: that endpoint does no I/O by design
    /// and there is no evidence to publish there. Settled in `233c470` and not
    /// reopened.
    #[serde(default)]
    pub rollback_anchor: Option<crate::rollback_anchor::RollbackAnchorEvidenceV1>,
    /// The witness identity break, stated rather than left to be inferred.
    ///
    /// `rollback_anchor` above goes `None` the moment the configured witness
    /// cannot be verified, which is exactly what a replaced witness looks like -
    /// so on the one failure this field is about, the field that would have
    /// carried the evidence is empty. The blocker beside it names the refusal
    /// identifier; this names *which store was pinned and which one is
    /// configured now*, which is the difference between "the witness is down,
    /// wait" and "the witness is gone, this will never clear on its own".
    ///
    /// Measured from durable state and configuration with no network, so it is
    /// published whether or not the replacement can be reached.
    ///
    /// `None` for every Hub that has no anchor, has not yet pinned one, or is
    /// configured with the witness it pinned - which is every healthy Hub, so
    /// the field is skipped when absent and the document of a Hub that never
    /// had an anchor is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_anchor_witness_identity_break:
        Option<crate::rollback_anchor::WitnessIdentityBreakV1>,
    pub max_payment_hac_zhu: u64,
    pub max_channel_funding_hac_zhu: u64,
    pub allowlist_configured: bool,
    pub aggregate_tvl_within_limit: bool,
    pub max_aggregate_tvl_hac_zhu: u64,
    pub max_payment_satoshi: u64,
    pub wallet_fee_hac: &'static str,
    pub trustless_finality: bool,
    pub unilateral_l1_enforceable: bool,
    #[serde(default)]
    pub trusted_bounded_pilot: bool,
    pub settlement_model: &'static str,
    pub blockers: Vec<String>,
    pub close_blockers: Vec<String>,
    pub limitations: Vec<String>,
}

impl MainnetReadinessV1 {
    /// `anchor` is the very evidence `external_rollback_anchor_ready` was
    /// measured from, and is published verbatim. `capabilities` is likewise the
    /// evidence `l1_dispute_path_ready` was measured from.
    ///
    /// **Both booleans are claims, and this function does not take them on
    /// trust.** Each is re-measured here from the evidence that travels in the
    /// same document and kept only where the two agree:
    ///
    /// ```text
    /// published = caller_claim AND measured_from_the_published_evidence
    /// ```
    ///
    /// The production caller passes exactly these measurements already
    /// ([`crate::state::HubState::mainnet_readiness`] hands over
    /// [`HubHardGuarantees`] fields measured from this same probe), so nothing
    /// about a real Hub changes. What changes is what a *wrong* caller can
    /// produce. `evaluate` is `pub`, and before this it would publish
    /// `unilateral_l1_enforceable: true` and `trustless_finality: true` over a
    /// `fullnode_capabilities` block that carried no verified registry
    /// deployment at all, and over `rollback_anchor: null` — the document
    /// contradicting itself, in the direction of a guarantee. A false green is
    /// the one failure this project ranks worse than a permanent red, so the
    /// flags are now conjunctions that no argument list can widen: passing
    /// `true` can never make them `true`, it can only fail to make them
    /// `false`.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        profile: &str,
        max_payment_hac_zhu: u64,
        max_channel_funding_hac_zhu: u64,
        hub_operational_ready: bool,
        external_rollback_anchor_ready: bool,
        anchor: Option<&crate::rollback_anchor::RollbackAnchorEvidenceV1>,
        l1_dispute_path_ready: bool,
        capabilities: Result<FullnodeCapabilitiesV1, HubError>,
    ) -> Self {
        // Re-measure both claims against the evidence that will be published
        // beside them, before anything downstream reads either. Placed first so
        // the blocker list, `close_blockers`, `payments_enabled` and the two
        // guarantee flags all derive from one narrowed value and cannot
        // disagree with each other.
        let external_rollback_anchor_ready = external_rollback_anchor_ready
            && measure_external_rollback_anchor_ready(anchor, crate::node::now_unix());
        let node_reported_unilateral_exit =
            measure_node_reported_unilateral_exit(capabilities.as_ref().ok());
        let user_side_unilateral_exit_ready = measure_user_side_unilateral_exit_ready();
        let l1_dispute_path_ready = l1_dispute_path_ready
            && node_reported_unilateral_exit
            && user_side_unilateral_exit_ready;
        let mut blockers = Vec::new();
        if !hub_operational_ready {
            blockers.push("hub_signer_authenticated_storage_or_recovery_gate_is_not_ready".into());
        }
        let is_bounded_pilot = profile == MAINNET_BOUNDED_PILOT_PROFILE;
        if !external_rollback_anchor_ready && !is_bounded_pilot {
            blockers.push("external_monotonic_rollback_anchor_is_not_ready".into());
        }
        if !l1_dispute_path_ready && !is_bounded_pilot {
            blockers.push("unilateral_l1_dispute_path_is_not_ready".into());
            // Say which half is missing, because the two fail for very
            // different reasons and the reader deserves the one that is
            // actually true. The line above reads like "the chain is not
            // ready yet". This one says the chain is not the obstruction: no
            // wallet on any platform can build a challenge, respond, finalize
            // or claim transaction, so a user holding a perfectly valid
            // countersigned bill still has no instrument to present it with.
            if !user_side_unilateral_exit_ready {
                blockers.push("wallet_cannot_build_a_unilateral_exit_without_the_hub".into());
            }
        }
        let is_mainnet_pilot = is_mainnet_pilot_profile(profile);
        if is_mainnet_pilot {
            validate_cap(
                max_payment_hac_zhu,
                MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
                "mainnet payment cap",
                &mut blockers,
            );
            validate_cap(
                max_channel_funding_hac_zhu,
                MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
                "mainnet channel-funding cap",
                &mut blockers,
            );
            blockers.push(ADMISSION_NOT_EVALUATED.into());
        }

        let (mainnet_detected, fullnode_capabilities, evaluated_unix) = match capabilities {
            Ok(capabilities) => {
                if is_mainnet_pilot {
                    if !capabilities.mainnet {
                        blockers.push("mainnet_pilot_requires_hacash_mainnet_fullnode".into());
                    }
                    if capabilities.height < HACASH_MAINNET_MIN_SAFE_HEIGHT {
                        blockers.push(format!(
                            "fullnode_below_pinned_mainnet_checkpoint_{}",
                            HACASH_MAINNET_MIN_SAFE_HEIGHT
                        ));
                    }
                    if !capabilities.action_enabled(ACTION_CHANNEL_OPEN) {
                        blockers.push("fullnode_missing_required_channel_open_action_2".into());
                    }
                    if !capabilities.action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE) {
                        blockers
                            .push("fullnode_missing_required_cooperative_close_action_3".into());
                    }
                    if profile == MAINNET_PILOT_PROFILE && !node_reported_unilateral_exit {
                        blockers.push(
                            "fullnode_does_not_report_verified_registry_unilateral_exit".into(),
                        );
                    }
                } else if capabilities.mainnet {
                    blockers.push(
                        "mainnet_detected_but_deployment_profile_is_not_mainnet_pilot".into(),
                    );
                }
                let observed = capabilities.observed_unix;
                (Some(capabilities.mainnet), Some(capabilities), observed)
            }
            Err(error) => {
                blockers.push(format!("fullnode_capability_probe_failed: {error}"));
                (None, None, crate::node::now_unix())
            }
        };
        if !is_mainnet_pilot {
            blockers.push("official_channelpay_mainnet_profile_not_enabled".into());
        }

        let close_blockers = blockers
            .iter()
            .filter(|blocker| {
                blocker.as_str() != "fullnode_missing_required_channel_open_action_2"
                    && blocker.as_str() != ADMISSION_NOT_EVALUATED
                    && blocker.as_str() != "external_monotonic_rollback_anchor_is_not_ready"
                    && blocker.as_str() != "unilateral_l1_dispute_path_is_not_ready"
                    && blocker.as_str() != "wallet_cannot_build_a_unilateral_exit_without_the_hub"
                    && blocker.as_str()
                        != "fullnode_does_not_report_verified_registry_unilateral_exit"
                    && !blocker.starts_with("mainnet payment cap")
                    && !blocker.starts_with("mainnet channel-funding cap")
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut limitations = vec![
            "settled does not mean unilateral L1 finality".into(),
            "the active Hacash mainnet exposes cooperative original-funding close action 3".into(),
            "pilot exposure must remain inside the configured payment and channel caps".into(),
        ];
        // The posture in plain words as well as in the document, because a
        // nested boolean is easy to miss and this is the sentence a person
        // choosing a hub has to see. It is a limitation and not a blocker on
        // purpose: ADR-001 leaves who runs the witness to the owner, the
        // mainnet profiles refuse a co-located witness outright before this
        // point, and off those profiles co-location is legitimate for local
        // development and the Local Pilot - told truthfully rather than
        // forbidden.
        if let Some(anchor) = anchor {
            if anchor.witness_co_located {
                limitations.push(format!(
                    "the external rollback anchor witness is co-located with this Hub \
                     (endpoint on this host: {}; witness store inside this Hub's state tree: {}), \
                     so it shares the failure domain it exists to guard and a restore of this Hub \
                     may restore its counter with it",
                    anchor.witness_endpoint_is_local, anchor.witness_store_in_hub_state_tree
                ));
            }
            limitations.push(format!(
                "the external rollback anchor witness is attested as {} operated by {}; an \
                 attestation is a signed statement about where the witness runs, not proof of it",
                anchor.witness_posture, anchor.witness_operator
            ));
        }
        Self {
            schema: READINESS_SCHEMA,
            evaluated_unix,
            valid_until_unix: evaluated_unix.saturating_add(READINESS_VALID_SECONDS),
            profile: profile.to_string(),
            payments_enabled: blockers.is_empty(),
            close_enabled: close_blockers.is_empty(),
            mainnet_detected,
            fullnode_capabilities,
            rollback_anchor: anchor.cloned(),
            // Filled in by `note_rollback_anchor_witness_identity_break`, which
            // reads the Hub's durable pin. `evaluate` is given only the probe
            // evidence and has nothing to measure it from.
            rollback_anchor_witness_identity_break: None,
            max_payment_hac_zhu: if is_mainnet_pilot {
                max_payment_hac_zhu
            } else {
                0
            },
            max_channel_funding_hac_zhu: if is_mainnet_pilot {
                max_channel_funding_hac_zhu
            } else {
                0
            },
            allowlist_configured: false,
            aggregate_tvl_within_limit: false,
            max_aggregate_tvl_hac_zhu: 0,
            max_payment_satoshi: 0,
            wallet_fee_hac: "0",
            // Both shadowed values, already narrowed to the evidence published
            // in this very document. A reader can check either flag against the
            // `rollback_anchor` and `fullnode_capabilities` blocks beside it and
            // reach the same verdict, which is the only way a guarantee in a
            // document is worth anything.
            trustless_finality: external_rollback_anchor_ready && l1_dispute_path_ready,
            unilateral_l1_enforceable: l1_dispute_path_ready,
            trusted_bounded_pilot: is_bounded_pilot,
            settlement_model: "official Hacash ChannelPay bills with hub-coordinated bounded mainnet pilot",
            blockers,
            close_blockers,
            limitations,
        }
    }

    pub fn require_channel_funding_ready_zhu(&self, amount_zhu: u64) -> HubResult<()> {
        self.require_base_mainnet_ready("channel funding")?;
        if amount_zhu == 0 || amount_zhu > self.max_channel_funding_hac_zhu {
            return Err(HubError::Payment(format!(
                "mainnet channel-funding cap exceeded: requested {amount_zhu} zhu, cap {} zhu",
                self.max_channel_funding_hac_zhu
            )));
        }
        Ok(())
    }

    /// A durable anchor condemnation, published whether or not a witness is
    /// configured right now.
    ///
    /// `external_rollback_anchor_ready` already reads `false` while any channel
    /// is latched - but it learns that from
    /// [`crate::rollback_anchor::RollbackAnchorEvidenceV1`], which only exists
    /// when a live witness could be probed and verified. Remove the witness
    /// configuration and the evidence becomes `None`, taking the latch count
    /// with it: the number goes to zero-by-absence at exactly the moment it
    /// matters most. On the full mainnet pilot profile that is survivable,
    /// because a missing anchor is itself a blocker. On
    /// `MAINNET_BOUNDED_PILOT_PROFILE` it is not - that profile deliberately
    /// waives `external_monotonic_rollback_anchor_is_not_ready`, so without
    /// this a Hub holding a channel condemned for a real rollback would publish
    /// an empty blocker list and `payments_enabled: true` while its own state
    /// file says the channel must never sign again.
    ///
    /// `latched` is read from the Hub's own durable state
    /// ([`crate::state::HubState::latched_rollback_anchor_refusal_count`]), so
    /// it is `0` for a Hub that never had an anchor - such a Hub is entirely
    /// unaffected - and it cannot be edited away by changing command-line
    /// flags.
    ///
    /// Payments are blocked; **close is deliberately not**. A latch condemns
    /// the off-chain signing path, and `ROLLBACK-ANCHOR-RECOVERY.md` Procedure
    /// A ends either at a mutually verified position or with the channel
    /// closing through the L1 path, which needs close to stay available.
    pub fn block_on_latched_rollback_anchor_refusals(&mut self, latched: u64) {
        if latched == 0 {
            return;
        }
        // A fixed identifier, with the count in the limitation beside it, so an
        // operator can look this up in the recovery document by exact string
        // the way every other anchor refusal is looked up. A blocker whose name
        // carries the count is a blocker nobody can grep for.
        self.blockers
            .push(ROLLBACK_ANCHOR_LATCHED_BLOCKER.to_owned());
        self.payments_enabled = false;
        self.limitations.push(format!(
            "{latched} channel(s) are latched in external rollback anchor refusal in this Hub's \
             durable state and will not sign again until the operator procedure in \
             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md has been completed; removing the witness \
             configuration does not clear a latch"
        ));
    }

    /// Publish why the external rollback anchor startup probe has not agreed,
    /// by name.
    ///
    /// `identifier` is one of the refusal identifiers in
    /// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 -
    /// `rollback_anchor_witness_unreachable` for the reachability case - and
    /// `None` when the last probe agreed or none has run.
    ///
    /// **This publishes; it does not gate.** The gate is
    /// `rollback_anchor_probe_agreed`, checked in
    /// [`crate::state::HubState::reserve_rollback_anchor`] before any signature.
    /// That gate is untouched: a probe that has not agreed refuses every bill
    /// exactly as it did before this method existed. What this adds is that the
    /// refusal is now *legible from outside the process*.
    ///
    /// It exists because the Hub used to answer this question by not starting.
    /// Propagating the probe failure out of `main` meant a Hub whose witness was
    /// briefly unreachable did not merely refuse to sign - it did not boot, so
    /// it could not serve a cooperative close, could not answer this endpoint,
    /// and could not name the identifier that selects the operator procedure.
    /// Under `Restart=on-failure` that is a crash loop, and the operator's first
    /// instinct is the one thing the recovery document opens by forbidding.
    ///
    /// Payments are blocked; **close is deliberately not**, for the same reason
    /// as [`Self::block_on_latched_rollback_anchor_refusals`] above: an anchor
    /// that cannot answer must not stop a channel leaving through the L1 path.
    /// A Hub kept alive to serve close is the entire point of the change.
    pub fn note_rollback_anchor_probe_refusal(&mut self, identifier: Option<&str>) {
        let Some(identifier) = identifier else {
            return;
        };
        if !self.blockers.iter().any(|blocker| blocker == identifier) {
            self.blockers.push(identifier.to_owned());
        }
        self.payments_enabled = false;
        self.limitations.push(format!(
            "the external rollback anchor startup probe has not agreed with the witness \
             ({identifier}); this Hub is running and answering reads and cooperative close, and it \
             refuses to sign any bill until a probe agrees. Look the identifier up in \
             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md section 2 - do not restart the Hub in a loop and \
             do not reconfigure the anchor to restore signing"
        ));
    }

    /// Publish that this Hub's one witness is no longer the witness it pinned.
    ///
    /// `note_rollback_anchor_probe_refusal` above already publishes the
    /// identifier when a probe has run and failed. This is not that, and the
    /// difference is the whole point: a Hub whose replacement witness is also
    /// unreachable publishes `rollback_anchor_witness_unreachable`, the
    /// *transient* identifier, which tells an operator to wait for a witness
    /// that is never coming back. This measurement needs no probe, so the
    /// permanent condition is named even when nothing answers, and it carries
    /// the two store identities so a reader can see that the pin moved rather
    /// than guess.
    ///
    /// **This publishes; it does not gate**, exactly like the two methods above
    /// it. `rollback_anchor_probe_agreed` is what refuses signatures and is
    /// untouched. Payments are blocked here because a Hub in this state refuses
    /// every bill anyway and must not advertise otherwise; close is
    /// deliberately not blocked, because closing on the last accepted head is
    /// the honest exit this whole path exists to keep open.
    ///
    /// Takes the *result* of the measurement rather than its success value, so
    /// that a pin which cannot be read fails to the blocked side. `None` here
    /// is the shape that means "this Hub is healthy"; an unreadable durable
    /// state must never be able to produce it.
    pub fn note_rollback_anchor_witness_identity_break(
        &mut self,
        identity_break: HubResult<Option<crate::rollback_anchor::WitnessIdentityBreakV1>>,
    ) {
        let identity_break = match identity_break {
            Ok(Some(identity_break)) => identity_break,
            Ok(None) => return,
            Err(error) => {
                if !self
                    .blockers
                    .iter()
                    .any(|blocker| blocker == ROLLBACK_ANCHOR_IDENTITY_UNREADABLE_BLOCKER)
                {
                    self.blockers
                        .push(ROLLBACK_ANCHOR_IDENTITY_UNREADABLE_BLOCKER.to_owned());
                }
                self.payments_enabled = false;
                self.limitations.push(format!(
                    "this Hub could not read its own durable rollback-anchor pin, so it cannot \
                     say whether the witness it is configured with is the witness it pinned \
                     ({error}). That is not evidence the pin is intact, so payments are blocked \
                     until it can be read. Cooperative close is unaffected. See \
                     docs/l2/ROLLBACK-ANCHOR-RECOVERY.md section 2"
                ));
                return;
            }
        };
        if !self
            .blockers
            .iter()
            .any(|blocker| blocker == &identity_break.refusal_identifier)
        {
            self.blockers
                .push(identity_break.refusal_identifier.clone());
        }
        self.payments_enabled = false;
        self.limitations.push(format!(
            "the external rollback anchor witness this Hub pinned ({}) is not the witness it is \
             configured with now ({}); the startup probe cannot agree again and this Hub will \
             sign no bill on any channel, permanently. That is not a state an operator procedure \
             clears: the pin moves only through a signature and a signature happens only after \
             the pin has moved, and a Hub that could adopt a replacement witness by itself would \
             be the laundering path this anchor exists to refuse. What it can still do it is \
             doing - it is running, it answers reads and cooperative close, and it serves a \
             continuity declaration per channel at GET \
             /v2/hvm-registry/channel/{{binding_commitment}}/anchor-continuity: the channel's \
             existing head, same serial and same bill commitment, re-anchored under the witness \
             answering now. Nothing new is signed by it; the payer adjudicates, and the exit is \
             to close each channel on the head its payer already holds. See \
             docs/l2/ROLLBACK-ANCHOR-RECOVERY.md, Procedure B step 6",
            identity_break.pinned_witness_instance_id, identity_break.attested_witness_instance_id
        ));
        self.rollback_anchor_witness_identity_break = Some(identity_break);
    }

    /// Say so when the anchor's pin has nowhere durable to live.
    ///
    /// A Hub with no authenticated durable storage keeps its rollback-anchor
    /// record in memory, so the pin does not survive a restart and is re-adopted
    /// on first contact from whichever store answers next - which is the amnesia
    /// this subsystem refuses everywhere else, and it would show up as a probe
    /// that agreed and a break that was never published.
    ///
    /// A limitation rather than a blocker, deliberately: that Hub is already
    /// blocked from payments by `hub_operational_ready`, because without
    /// authenticated storage nothing settles at all. A second blocker for the
    /// same underlying fact would be noise; an unsaid one would be a lie.
    pub fn note_rollback_anchor_pin_is_not_durable(&mut self, pin_is_not_durable: bool) {
        if !pin_is_not_durable {
            return;
        }
        self.limitations.push(
            "this Hub has an external rollback anchor configured but no authenticated durable \
             storage, so the witness pin is held only in memory: it does not survive a restart, \
             and after one the Hub would adopt whichever witness store answers first rather than \
             detect that it changed. Nothing settles on this Hub in any case - see the \
             hub_signer_authenticated_storage_or_recovery_gate_is_not_ready blocker - and the \
             anchor measurement below must not be read as an anchor guarantee"
                .to_owned(),
        );
    }

    pub fn apply_mainnet_admission(
        &mut self,
        policy: &MainnetPilotAdmissionPolicy,
        aggregate_tvl_hac_zhu: HubResult<u64>,
    ) {
        if !is_mainnet_pilot_profile(&self.profile) {
            return;
        }
        self.blockers
            .retain(|blocker| blocker != ADMISSION_NOT_EVALUATED);
        self.allowlist_configured = policy.is_configured();
        self.max_aggregate_tvl_hac_zhu = policy.max_aggregate_tvl_hac_zhu();
        if !self.allowlist_configured {
            self.blockers
                .push("mainnet_pilot_user_allowlist_is_not_configured".into());
        }
        match aggregate_tvl_hac_zhu {
            Ok(current_tvl) => {
                self.aggregate_tvl_within_limit = current_tvl <= policy.max_aggregate_tvl_hac_zhu();
                if !self.aggregate_tvl_within_limit {
                    self.blockers
                        .push("mainnet_pilot_aggregate_tvl_limit_exceeded".into());
                }
            }
            Err(_) => self
                .blockers
                .push("mainnet_pilot_aggregate_tvl_could_not_be_verified".into()),
        }
        self.payments_enabled = self.blockers.is_empty();
        self.limitations.push(format!(
            "new channels require an allowlisted user and aggregate Hub TVL at or below {} zhu",
            policy.max_aggregate_tvl_hac_zhu()
        ));
    }

    pub fn require_payment_ready(&self, amount: HacAmount) -> HubResult<()> {
        self.require_base_mainnet_ready("payment")?;
        let amount_zhu = amount
            .as_millimeis()
            .checked_mul(ZHU_PER_MILLIMEI)
            .ok_or_else(|| HubError::Payment("payment amount exceeds mainnet limits".into()))?;
        if amount_zhu == 0 || amount_zhu > self.max_payment_hac_zhu {
            return Err(HubError::Payment(format!(
                "mainnet payment cap exceeded: requested {amount_zhu} zhu, cap {} zhu",
                self.max_payment_hac_zhu
            )));
        }
        Ok(())
    }

    pub fn require_cooperative_close_ready(
        &self,
        requires_principal_transfer: bool,
    ) -> HubResult<()> {
        if self.schema != READINESS_SCHEMA
            || !is_mainnet_pilot_profile(&self.profile)
            || !self.close_enabled
            || self.mainnet_detected != Some(true)
            || !self.close_blockers.is_empty()
            || self.wallet_fee_hac != "0"
        {
            return Err(HubError::State(format!(
                "mainnet cooperative channel close gate blocked: {}",
                self.close_blockers.join("; ")
            )));
        }
        if crate::node::now_unix() > self.valid_until_unix {
            return Err(HubError::State(
                "mainnet readiness expired before close signing".into(),
            ));
        }
        if requires_principal_transfer
            && !self
                .fullnode_capabilities
                .as_ref()
                .is_some_and(|capabilities| {
                    capabilities.action_enabled(crate::node::ACTION_HAC_FROM_TO_TRANSFER)
                })
        {
            return Err(HubError::State(
                "mainnet changed-balance close requires enabled Hacash Action 14".into(),
            ));
        }
        Ok(())
    }

    fn require_base_mainnet_ready(&self, operation: &str) -> HubResult<()> {
        if self.schema != READINESS_SCHEMA
            || !is_mainnet_pilot_profile(&self.profile)
            || !self.payments_enabled
            || self.mainnet_detected != Some(true)
            || (self.profile == MAINNET_PILOT_PROFILE
                && (!self.trustless_finality || !self.unilateral_l1_enforceable))
            || (self.profile == MAINNET_BOUNDED_PILOT_PROFILE && !self.trusted_bounded_pilot)
            || !self.blockers.is_empty()
            || self.wallet_fee_hac != "0"
        {
            return Err(HubError::State(format!(
                "mainnet {operation} gate blocked: {}",
                self.blockers.join("; ")
            )));
        }
        if crate::node::now_unix() > self.valid_until_unix {
            return Err(HubError::State(
                "mainnet readiness expired before signing".into(),
            ));
        }
        Ok(())
    }
}

fn validate_cap(cap: u64, hard_max: u64, label: &str, blockers: &mut Vec<String>) {
    if !(ZHU_PER_MILLIMEI..=hard_max).contains(&cap) {
        blockers.push(format!(
            "{label} must be between {ZHU_PER_MILLIMEI} and {hard_max} zhu"
        ));
    }
}

/// Measured readiness of the external monotonic rollback anchor.
///
/// An external anchor is a counter held *outside* the Hub's state directory,
/// beyond the reach of whoever can restore that directory, which can only ever
/// rise, which the Hub advances before it signs and re-reads at startup. See
/// `docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md`,
/// `docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md` and
/// `docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md`.
///
/// This is a conjunction over one live probe of the pinned witness, and it is
/// false if any part is missing. `evidence` is `None` whenever no witness is
/// configured **or** the configured witness could not be reached, could not be
/// verified against its pinned keys, or answered from a store the Hub did not
/// pin - all of which fail closed to the same `false`, because an unreachable
/// oracle is not evidence.
///
/// It is never a function of a witness URL being configured, of an operator
/// assertion, of a flag, or of a counter file on this same host. The doc
/// comment that used to stand here ruled all three out and they stay ruled
/// out: the only input is a signed, fresh, pinned-key-verified statement from
/// the witness, weighed against what this Hub durably recorded.
///
/// **What this deliberately does not gate on.** Neither half of the
/// co-location guard is a term here — not the witness *endpoint* posture
/// (whether the URL points at this host or at plaintext transport), and not
/// whether a witness durable store was found in this Hub's own state tree.
/// Both are refused outright by
/// [`crate::rollback_anchor::RollbackAnchorClient::connect`] on a mainnet
/// profile, so neither can reach this function in the configuration that
/// matters. Off the mainnet profiles both are allowed — local development and
/// the Local Pilot are legitimate and need them — but never silently: they are
/// published as `witness_endpoint_is_local`,
/// `witness_store_in_hub_state_tree` and the derived `witness_co_located` in
/// the [`crate::rollback_anchor::RollbackAnchorEvidenceV1`] document that
/// [`MainnetReadinessV1::rollback_anchor`] carries beside this flag, along with
/// the witness posture and the operating entity, because a guarantee whose
/// strength depends on who holds a key must not be reported as a lone boolean
/// with the key holder hidden.
///
/// Making co-location a term here would read `false` for every local
/// development Hub and every Local Pilot, which is how a flag stops being
/// consulted. The posture is published instead, and it is the profile gate —
/// not this measurement — that keeps the weak configuration off mainnet.
pub fn measure_external_rollback_anchor_ready(
    evidence: Option<&crate::rollback_anchor::RollbackAnchorEvidenceV1>,
    now_unix: u64,
) -> bool {
    evidence.is_some_and(|evidence| {
        evidence.schema == crate::rollback_anchor::ROLLBACK_ANCHOR_EVIDENCE_SCHEMA
            && !evidence.witness_id.trim().is_empty()
            && !evidence.witness_instance_id.trim().is_empty()
            && evidence.attestation_valid
            && evidence.attestation_expires_unix > now_unix
            && evidence.key_custody_distinct
            && evidence.instance_pin_holds
            && evidence.counter_never_decreased
            && evidence.startup_probe_agreed
            && evidence.channels_latched_in_refusal == 0
            && evidence.verified_unix
                <= now_unix
                    .saturating_add(crate::rollback_anchor::protocol::MAX_WITNESS_MESSAGE_AGE_SECS)
            && now_unix.saturating_sub(evidence.verified_unix)
                <= crate::rollback_anchor::protocol::MAX_WITNESS_MESSAGE_AGE_SECS
    })
}

/// Whether this software ships a way for a *user* to drive a unilateral exit.
///
/// Set by a human, never by configuration, and deliberately separate from the
/// probe below so that neither alone can turn the guarantee green.
///
/// It is `false`, and here is exactly what has to become true before anyone
/// may change it. All three, together:
///
/// 1. **A signer-agnostic builder.** ✅ **Met.**
///    [`crate::hvm_registry_watchtower::build_signed_hvm_registry_call_transaction`]
///    and its claim sibling are role aware: the Hub's rule is unchanged and the
///    channel's left party has its own. The whole sequence is proven on a real
///    chain against a real deployed contract, with the Hub's process aborted
///    and its socket verified closed, in
///    `crates/wallet-core/tests/dead_hub_user_exit_on_chain.rs` — the user
///    signs challenge, finalize and the Action 14 payout with their own key and
///    ends up richer by exactly the balance they were owed.
/// 2. **A user surface that reaches it.** ✅ **Met.**
///    `AgentTransactionSigner::sign_exact_registry_exit` signs the steps,
///    `AgentWalletManager::advance_hvm_registry_exit` is the production caller
///    of the driver, `FullnodeRegistryExitChain` answers it from the wallet's
///    own pinned fullnode, and `agent_wallet_start_hvm_registry_exit` drives
///    that chain instead of refusing. No hop in it is a test.
///
/// 4. **A channel for any of it to act on.** ❌ **Not met, and this is what
///    is now holding the flag down.** Adoption is the problem, not the exit.
///    `AgentWalletManager::verify_and_bind_hvm_registry` will only adopt a
///    bundle whose serial-1 refund bill is *fully signed*, which means signed
///    by the wallet's own address, and that signature can only be produced at
///    channel open. `agent-wallet-core` has no surface that produces it: the
///    five signing methods on `AgentTransactionSigner` are the two payment
///    signers, `sign_exact_channel_open`, `sign_exact_channel_close` and
///    `sign_exact_registry_exit`, and the registry payment signer needs an
///    `AgentHvmRegistryBinding` that only adoption can create. The only
///    builder of that signature in the tree, called from the operator CLI
///    `hpay-hvm-registry-local-pilot`, needs a raw `Account`, and an Agent
///    Wallet's key is generated by `WalletAccount::create_random` and never
///    leaves the vault.
///
///    So no real Agent Wallet can hold a registry binding, and the exit
///    control has nothing to act on for anybody. Turning this flag true today
///    would publish "you can walk out without your provider" over a channel
///    that cannot exist. The missing wire is the channel-open side; the exit
///    side is finished and proven on chain.
///
///    **What is no longer part of this gap.** The driver itself now exists as
///    shipped code —
///    `hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit` —
///    rather than as a loop written inside a test. It plans from the chain,
///    consults the durable per-step record, announces the signature before the
///    key is used, makes the exact bytes durable before any node sees them, and
///    resumes from disk after the process dies.
///    `crates/wallet-core/tests/kill_mid_exit_on_chain.rs`
///    (`the_shipped_driver_is_closed_mid_exit_and_the_user_is_still_paid`)
///    funds a channel, spends part of it, aborts the Hub, closes the wallet
///    twice mid-exit — once holding a durable signature no node had seen — and
///    ends with the user paid on chain, one signature and one transaction per
///    step. What is missing is strictly the signing surface above it and a
///    caller in the app, which is what the two checks below now demand.
/// 3. **The evidence in the user's hands.** Partly met. The wallet now keeps an
///    explicit monotone `hvm_registry_exit_head`, seeded at adoption from the
///    binding's own serial-1 refund bill and falling back to it when absent, so
///    the evidence cannot be lost with a pruned operation map; and funding is
///    unbuildable without a Hub-countersigned refund, so the serial-0 trap is
///    closed. What is missing is the export: `hvm_registry_exit_kit` has no
///    command and no CLI behind it, so a user cannot hand the kit to anyone.
///
/// Two further conditions decide whether an exit that can be *started* is
/// actually *survivable*, and they are named here so nobody flips this flag
/// believing 1–3 are the whole list.
///
/// * **The challenge window.** Fixed per channel, and a missed one settles
///   whatever split is standing. On the shipped one-directional rail a missed
///   window cannot cost a sleeping user principal, because every later bill
///   pays them *less* — but that is a property of two checks, not of this
///   code: `right_hub_deposit_zhu != 0` is refused in
///   [`crate::hvm_registry`], and the bill ledger only ever subtracts from the
///   left balance. Change either and this stops being true.
/// * **The storage lease.** Still the only path here that destroys a deposit
///   outright, though the cliff is further out than it looks: funding buys
///   every channel key a recovery buffer, so an expired record goes dormant and
///   restorable for months before it is destroyed. The driver renews before it
///   will start an exit, and renews *the half that is short* — the six shared
///   globals and the twelve channel keys are separate calls, and renewing the
///   wrong one is a fee spent to stand still.
pub const USER_SIDE_UNILATERAL_EXIT_DRIVER_READY: bool = false;

#[cfg(test)]
mod user_side_exit_readiness_tests {
    /// The flag stays down until a user can actually reach the driver.
    ///
    /// Condition 1 is met and measurably so — the probe below flips itself, and
    /// the on-chain proof exists. That is exactly the situation in which a flag
    /// is most likely to be flipped for the wrong reason, so this test states
    /// the remaining gap in a place that fails if the flag moves without it.
    #[test]
    fn the_flag_is_down_because_no_surface_can_sign_an_exit() {
        if !super::USER_SIDE_UNILATERAL_EXIT_DRIVER_READY {
            return;
        }
        let signer = include_str!("../../agent-wallet-core/src/signer.rs");
        assert!(
            signer.contains("sign_exact_registry_exit"),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while the wallet still has no \
             way to sign an exit. The builders work and the chain accepts them, but a user \
             cannot reach either, and a flag that reads true while a user is trapped is worse \
             than red forever."
        );
        // The signer alone was too narrow a tripwire. Adding
        // `sign_exact_registry_exit` and nothing else would let this flag go
        // true, render a pressable button, and land the owner on the
        // unconditional refusal at the end of
        // `agent_wallet_start_hvm_registry_exit` — a contradiction that reads
        // to a user as the app breaking rather than as the app being honest.
        //
        // So the second term is a *caller*: the shipped driver must actually be
        // driven from the command an owner presses. `advance_registry_exit` is
        // the only entry point into that loop.
        //
        // Naming it was too weak a way to demand it, and it is worth writing
        // down why rather than quietly fixing it. `contains` cannot tell
        // production code from prose: the name already appears in that file's
        // own doc comment and inside its `#[cfg(test)]` module, so this check
        // would have passed for a command that still refused unconditionally.
        // A tripwire that can be satisfied by describing the thing it demands
        // is a tripwire that will be.
        //
        // So the haystack is narrowed before it is searched: everything from
        // `#[cfg(test)]` onwards is cut off, every comment line is dropped, and
        // what must remain is the *call*, parenthesis included. A comment
        // cannot satisfy that, a test cannot, and neither can a helper nobody
        // calls.
        let commands = include_str!("../../wallet-tauri-common/src/agent_commands.rs");
        assert!(
            shipped_source(commands).contains(".advance_registry_exit(")
                || shipped_source(commands).contains(".advance_hvm_registry_exit("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while nothing an owner can \
             press reaches `hvm_registry_exit_driver::advance_registry_exit`. A driver whose \
             only caller is a test has shipped from this workspace twice; this assertion is \
             here so it cannot happen a third time behind a green flag."
        );

        // Third term: a channel for the button to act on.
        //
        // Both terms above are now satisfied, and the exit still cannot help
        // anybody, because no real Agent Wallet can hold a registry binding.
        // `verify_and_bind_hvm_registry` adopts only a bundle whose serial-1
        // refund bill carries the wallet's own left signature, that signature
        // can only be made at channel open, and `agent-wallet-core` has no
        // surface that makes it. The wallet's key never leaves its vault, so
        // the operator CLI that does build it cannot be handed one either.
        //
        // A flag that says "you can walk out without your provider" over a
        // channel that cannot exist is a worse lie than a red screen, so the
        // channel-open signer is named here the same way the exit signer was
        // named here before it existed.
        let signer_source = shipped_source(signer);
        assert!(
            signer_source.contains("sign_exact_registry_channel_open"),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while no Agent Wallet can \
             open a registry channel in the first place. Adoption needs the wallet's own left \
             signature on the serial-1 refund bill and nothing in `agent-wallet-core` produces \
             one, so every wallet reaching this screen is told it has no provider channel to \
             close. The exit is finished; the way in is not."
        );
    }

    /// Everything in a source file that a build actually ships: no comments,
    /// and nothing from the first `#[cfg(test)]` onwards.
    fn shipped_source(source: &str) -> String {
        source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The tripwire above must not be satisfiable by prose.
    ///
    /// It reads a real source file, so it is only as strong as the way it
    /// reads it. This states the weakness that was actually there, and fails
    /// if the narrowing that closed it is ever taken back out.
    #[test]
    fn naming_the_driver_in_a_comment_or_a_test_does_not_satisfy_the_tripwire() {
        let commands = include_str!("../../wallet-tauri-common/src/agent_commands.rs");
        assert!(
            commands.contains(
                "/// through [`agent_wallet_core::AgentWalletManager::advance_hvm_registry_exit`]."
            ),
            "this test is about a doc comment that a bare `contains` would match; if it has \
             moved, re-point this rather than deleting it"
        );
        let prose_and_tests = concat!(
            "//! advance_registry_exit\n",
            "/// advance_hvm_registry_exit\n",
            "fn nothing() {}\n",
            "#[cfg(test)]\n",
            "mod t { fn t() { x.advance_hvm_registry_exit(); } }"
        );
        let shipped = shipped_source(prose_and_tests);
        assert!(
            !shipped.contains(".advance_registry_exit(")
                && !shipped.contains(".advance_hvm_registry_exit("),
            "a file that only mentions the driver in comments and in its own tests would still \
             satisfy the flag's caller check"
        );
    }
}

/// Measured readiness of the *user's* side of the unilateral exit: not whether
/// the chain would permit an exit, but whether this software can put one in a
/// user's hands.
///
/// Both terms must hold. The constant is the human judgement that the surface,
/// the driver and the bill custody all exist. The probe is the machine check
/// that the exit transactions can actually be built by someone who is not the
/// Hub — it drives the real builders with a real non-Hub key and cannot be
/// satisfied by editing a literal, by configuration, or by an operator saying
/// so. Neither is sufficient alone, which is the point: this is the term that
/// makes a wrong guarantee take more than one careless edit.
pub fn measure_user_side_unilateral_exit_ready() -> bool {
    USER_SIDE_UNILATERAL_EXIT_DRIVER_READY
        && crate::hvm_registry_watchtower::user_key_can_build_registry_exit_transactions()
}

/// Measured readiness of the unilateral L1 dispute path.
///
/// True only when the connected fullnode both advertises the native
/// unilateral-exit capability *and* carries evidence of an exactly verified
/// mainnet deployment of the reviewed exit contract, *and* this software can
/// actually hand a user the exit transactions. Missing capabilities (an
/// unreachable or unparseable node), a `false` capability flag, or evidence
/// that fails `validate_candidate` each read `false`.
///
/// **Which contract.** The shared registry,
/// [`crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE`]. That has to be
/// said out loud, because for a long time it was not the one measured here.
/// This gate weighed [`crate::node::ChannelUnilateralExitEvidence`], which is
/// hard-bound to `hpay-hvm-channel-v1` — the per-channel V1 contract. The
/// registry V2 profile is what the wallet funds, what the bills are signed
/// under, what the watchtower renews and what the exit driver was proven
/// against on a real chain. Deploying V2 to Hacash mainnet would have left
/// this reading `false` forever, and a `true` from a V1 deployment would have
/// been a guarantee about a path nobody travels. Measuring a contract the
/// system does not use is not a conservative error; it is an unrelated one.
///
/// **Why the third term exists.** The first two are both statements made by
/// the fullnode about itself, in a different repository. Until this term was
/// added, `unilateral_l1_enforceable` — the guarantee a wallet reads before it
/// trusts this Hub with mainnet funds — could be published `true` by deploying
/// a contract and flipping one hardcoded literal in that other repository,
/// while every user still had no means whatsoever to build an exit
/// transaction. That is precisely the wrong guarantee this project ranks worse
/// than no guarantee: telling users they hold a claim on chain when what they
/// hold is a promise from the Hub. A node advertising a contract is evidence
/// about a node. It is not evidence that a user can get their money out, and
/// only the third term is about the user at all.
pub fn measure_l1_dispute_path_ready(capabilities: Option<&FullnodeCapabilitiesV1>) -> bool {
    measure_node_reported_unilateral_exit(capabilities) && measure_user_side_unilateral_exit_ready()
}

/// The fullnode half of the dispute-path measurement, on its own.
///
/// True when the connected node advertises the **shared registry V2**
/// unilateral-exit capability and carries evidence of an exactly verified
/// mainnet deployment of the reviewed registry contract. Missing capabilities
/// (an unreachable or unparseable node), a `false` capability flag, or evidence
/// that fails `validate_candidate` each read `false`.
///
/// Named and exported separately because it is exactly the part of the claim
/// that a node can speak to, and keeping it distinct is what stops it being
/// mistaken for the whole. On its own it never gates anything.
///
/// The V1 per-channel evidence, if the node still publishes it, is carried in
/// [`FullnodeCapabilitiesV1::channel_unilateral_exit_evidence`] and validated
/// on parse — but it is not a term here, because it is about a contract this
/// system does not settle on.
pub fn measure_node_reported_unilateral_exit(
    capabilities: Option<&FullnodeCapabilitiesV1>,
) -> bool {
    capabilities.is_some_and(|capabilities| {
        capabilities.channel_registry_unilateral_exit
            && capabilities
                .channel_registry_unilateral_exit_evidence
                .as_ref()
                .is_some_and(
                    crate::node::RegistryUnilateralExitEvidence::is_verified_mainnet_deployment,
                )
    })
}

/// The mainnet-grade guarantees the Hub publishes over `/health`, each derived
/// from evidence rather than asserted as a constant.
///
/// `HubHealth` is read by wallets to decide whether to trust this Hub with
/// mainnet funds, while `MainnetReadinessV1` gates the money path inside the
/// Hub. Both are computed from this one measurement so they cannot drift apart
/// and advertise a property the gate does not enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubHardGuarantees {
    pub external_rollback_anchor_ready: bool,
    pub l1_dispute_path_ready: bool,
    pub production_mainnet_ready: bool,
}

impl HubHardGuarantees {
    /// Weigh the evidence. `capabilities` is `None` whenever the fullnode
    /// could not be probed and `anchor` is `None` whenever the rollback anchor
    /// witness is unconfigured or could not be probed and verified. Either
    /// fails its measurement closed.
    pub fn measure(
        profile: &str,
        hub_operational_ready: bool,
        capabilities: Option<&FullnodeCapabilitiesV1>,
        anchor: Option<&crate::rollback_anchor::RollbackAnchorEvidenceV1>,
        now_unix: u64,
    ) -> Self {
        let external_rollback_anchor_ready =
            measure_external_rollback_anchor_ready(anchor, now_unix);
        let l1_dispute_path_ready = measure_l1_dispute_path_ready(capabilities);
        // The strongest claim the Hub makes: a full production mainnet
        // deployment with trustless finality. Every part must hold.
        let production_mainnet_ready = hub_operational_ready
            && external_rollback_anchor_ready
            && l1_dispute_path_ready
            && profile == MAINNET_PILOT_PROFILE
            && capabilities.is_some_and(|capabilities| {
                capabilities.mainnet && capabilities.height >= HACASH_MAINNET_MIN_SAFE_HEIGHT
            });
        Self {
            external_rollback_anchor_ready,
            l1_dispute_path_ready,
            production_mainnet_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> FullnodeCapabilitiesV1 {
        let now = crate::node::now_unix();
        FullnodeCapabilitiesV1 {
            observed_unix: now,
            api_version: 1,
            chain_id: 0,
            height: 900_000,
            next_height: 900_001,
            mainnet: true,
            network_kind: "mainnet".into(),
            node_profile_id: "hacash-mainnet".into(),
            block_1_hash: crate::node::HACASH_MAINNET_BLOCK_ONE_HASH.into(),
            network_instance_id: Some(crate::l1_channel::canonical_network_instance_id(
                "mainnet",
                0,
                true,
                crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
                "hacash-mainnet",
                2,
            )),
            transaction_format_version: 2,
            tip_timestamp_unix: now,
            tip_age_seconds: 0,
            registered_actions: vec![1, 2, 3, 0x0411],
            enabled_actions: vec![1, 2, 3, 0x0411],
            enabled_transactions: vec![2],
            transaction_submit_bound: true,
            hpay_channel_registry_query: true,
            channel_unilateral_exit: true,
            channel_unilateral_exit_evidence: Some(crate::node::ChannelUnilateralExitEvidence {
                schema: crate::node::HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA.to_owned(),
                manifest_valid: true,
                contract_name: crate::node::HPAY_CHANNEL_EXIT_CONTRACT_NAME.to_owned(),
                protocol_domain: crate::node::HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN.to_owned(),
                settlement_profile: crate::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
                source_sha256: "11".repeat(32),
                bytecode_sha3: crate::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
                required_action_kinds: crate::node::HPAY_CHANNEL_EXIT_ACTION_KINDS.to_vec(),
                funding_model: crate::node::ChannelUnilateralExitFundingModel {
                    left_deposit: "positive".to_owned(),
                    right_hub_deposit: "exactly_zero".to_owned(),
                },
                storage_key_count: crate::node::HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
                must_renew_every_storage_key: true,
                deployment: crate::node::ChannelUnilateralExitDeployment {
                    enabled: true,
                    contract_address: Some(
                        vm::ContractAddress::from_unchecked(field::Address::create_contract(
                            [7_u8; 20],
                        ))
                        .to_readable(),
                    ),
                    deployment_tx_hash: Some("22".repeat(32)),
                    deployment_height: Some(HACASH_MAINNET_MIN_SAFE_HEIGHT),
                    independently_verified: true,
                },
                on_chain_verification: crate::node::ChannelUnilateralExitOnChainVerification {
                    observed_height: Some(900_000),
                    confirmed_tx_height: Some(HACASH_MAINNET_MIN_SAFE_HEIGHT),
                    deployment_tx_confirmed: true,
                    contract_code_sha3: Some(
                        crate::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
                    ),
                    contract_code_matches: true,
                },
                deployment_verified: true,
            }),
            channel_registry_unilateral_exit: true,
            channel_registry_unilateral_exit_evidence: Some(registry_exit_evidence()),
        }
    }

    /// A fully verified **V2** evidence document, for the fixture only.
    ///
    /// It describes a mainnet deployment that does not exist, which is the
    /// whole point of a fixture: it lets the tests below prove that each term
    /// of the gate is load bearing without anything being deployed. The
    /// separate test file `honest_readiness_flags` proves the opposite
    /// direction — that the real Hub, against the real node, publishes false.
    fn registry_exit_evidence() -> crate::node::RegistryUnilateralExitEvidence {
        let network_instance = crate::l1_channel::canonical_network_instance_id(
            "mainnet",
            0,
            true,
            crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
            "hacash-mainnet",
            2,
        );
        crate::node::RegistryUnilateralExitEvidence {
            schema: crate::hvm_registry::HVM_REGISTRY_EXIT_EVIDENCE_SCHEMA.to_owned(),
            manifest_valid: true,
            contract_name: crate::hvm_registry::HPAY_REGISTRY_CONTRACT_NAME.to_owned(),
            protocol_domain: crate::hvm_registry::HPAY_REGISTRY_PROTOCOL_DOMAIN.to_owned(),
            settlement_profile: crate::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE.to_owned(),
            source_sha256: "33".repeat(32),
            bytecode_sha3: crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.to_owned(),
            required_action_kinds: crate::hvm_registry::HPAY_REGISTRY_REQUIRED_ACTION_KINDS
                .to_vec(),
            channel_model: crate::node::RegistryUnilateralExitChannelModel {
                left_deposit: "positive".to_owned(),
                right_hub_deposit: "exactly_zero".to_owned(),
                maximum_active_channels_per_left_address: 1,
                first_reuse: 0,
            },
            registry_key_count: crate::hvm_registry::HVM_REGISTRY_STORAGE_KEY_COUNT,
            channel_key_count: crate::hvm_registry::HVM_REGISTRY_CHANNEL_KEY_COUNT,
            must_renew_every_registry_key: true,
            must_renew_every_channel_key: true,
            maximum_renewal_step_periods: crate::hvm_registry::HPAY_REGISTRY_MAX_RENT_STEP,
            deployment: crate::node::RegistryUnilateralExitDeployment {
                enabled: true,
                contract_address: Some(
                    vm::ContractAddress::from_unchecked(field::Address::create_contract(
                        [9_u8; 20],
                    ))
                    .to_readable(),
                ),
                deployment_tx_hash: Some("44".repeat(32)),
                deployment_height: Some(HACASH_MAINNET_MIN_SAFE_HEIGHT),
                independently_verified: true,
                external_audit_complete: false,
            },
            on_chain_verification: crate::node::RegistryUnilateralExitOnChainVerification {
                observed_height: Some(900_000),
                confirmed_tx_height: Some(HACASH_MAINNET_MIN_SAFE_HEIGHT),
                deployment_tx_confirmed: true,
                contract_code_sha3: Some(
                    crate::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.to_owned(),
                ),
                contract_code_matches: true,
                deployment_action_verified: true,
                hub_address: Some(field::Address::create_contract([5_u8; 20]).to_readable()),
                constructor_network_instance_id: Some(network_instance.clone()),
                node_network_instance_id: Some(network_instance),
                network_binding_matches: true,
            },
            deployment_verified: true,
        }
    }

    /// The gate must be reading the contract this system settles on.
    ///
    /// This is the regression test for the defect: `measure_l1_dispute_path_
    /// ready` used to be satisfied by a verified **V1** per-channel document
    /// and to ignore V2 entirely. Strip the V2 evidence and leave the V1
    /// evidence fully green, and the node half must read `false`.
    #[test]
    fn the_node_half_measures_the_shared_registry_and_not_the_v1_channel_contract() {
        let green = capabilities();
        assert!(
            measure_node_reported_unilateral_exit(Some(&green)),
            "a node with verified registry V2 evidence is the case this gate is about"
        );

        let mut v1_only = capabilities();
        v1_only.channel_registry_unilateral_exit = false;
        v1_only.channel_registry_unilateral_exit_evidence = None;
        assert!(
            v1_only.channel_unilateral_exit
                && v1_only
                    .channel_unilateral_exit_evidence
                    .as_ref()
                    .is_some_and(
                        crate::node::ChannelUnilateralExitEvidence::is_verified_mainnet_deployment
                    ),
            "the V1 half of this fixture is deliberately fully verified"
        );
        assert!(
            !measure_node_reported_unilateral_exit(Some(&v1_only)),
            "a verified V1 per-channel deployment says nothing about the registry profile \
             this system settles on, and must never satisfy this gate"
        );

        let mut registry_only = capabilities();
        registry_only.channel_unilateral_exit = false;
        registry_only.channel_unilateral_exit_evidence = None;
        assert!(
            measure_node_reported_unilateral_exit(Some(&registry_only)),
            "V1 is not a term: a node that stopped publishing it entirely still answers \
             for the profile that is actually used"
        );

        let mut flag_down = capabilities();
        flag_down.channel_registry_unilateral_exit = false;
        assert!(!measure_node_reported_unilateral_exit(Some(&flag_down)));

        let mut evidence_gone = capabilities();
        evidence_gone.channel_registry_unilateral_exit_evidence = None;
        assert!(!measure_node_reported_unilateral_exit(Some(&evidence_gone)));
    }

    /// Every chain-derived term of the V2 document is load bearing, and the
    /// two V2-only bindings especially: a registry deployed by someone else,
    /// or constructed for another network, must never verify.
    #[test]
    fn registry_evidence_fails_closed_on_every_missing_derivation() {
        assert!(registry_exit_evidence().is_verified_mainnet_deployment());

        let mut wrong_profile = registry_exit_evidence();
        wrong_profile.settlement_profile =
            crate::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned();
        assert!(!wrong_profile.is_verified_mainnet_deployment());

        let mut wrong_bytecode = registry_exit_evidence();
        wrong_bytecode.bytecode_sha3 = "ff".repeat(32);
        assert!(!wrong_bytecode.is_verified_mainnet_deployment());

        let mut wrong_rent_step = registry_exit_evidence();
        wrong_rent_step.maximum_renewal_step_periods = 5_000;
        assert!(
            !wrong_rent_step.is_verified_mainnet_deployment(),
            "the V1 renewal step against a V2 contract aborts every renewal"
        );

        let mut below_floor = registry_exit_evidence();
        below_floor.deployment.deployment_height = Some(HACASH_MAINNET_MIN_SAFE_HEIGHT - 1);
        below_floor.on_chain_verification.confirmed_tx_height =
            Some(HACASH_MAINNET_MIN_SAFE_HEIGHT - 1);
        assert!(!below_floor.is_verified_mainnet_deployment());

        let mut no_action = registry_exit_evidence();
        no_action.on_chain_verification.deployment_action_verified = false;
        assert!(
            !no_action.is_verified_mainnet_deployment(),
            "code on chain is not proof that this transaction put it there"
        );

        let mut foreign_network = registry_exit_evidence();
        foreign_network
            .on_chain_verification
            .constructor_network_instance_id = Some("ab".repeat(32));
        foreign_network
            .on_chain_verification
            .network_binding_matches = false;
        assert!(!foreign_network.is_verified_mainnet_deployment());

        let mut lying_binding = registry_exit_evidence();
        lying_binding
            .on_chain_verification
            .constructor_network_instance_id = Some("ab".repeat(32));
        assert!(
            !lying_binding.is_verified_mainnet_deployment(),
            "a document may not assert network_binding_matches over bytes that do not match"
        );

        let mut no_hub = registry_exit_evidence();
        no_hub.on_chain_verification.hub_address = None;
        assert!(!no_hub.is_verified_mainnet_deployment());

        let mut wrong_live_code = registry_exit_evidence();
        wrong_live_code.on_chain_verification.contract_code_sha3 = Some("ff".repeat(32));
        assert!(!wrong_live_code.is_verified_mainnet_deployment());

        let mut claimed_without_deployment = registry_exit_evidence();
        claimed_without_deployment.deployment_verified = false;
        claimed_without_deployment.deployment.independently_verified = false;
        assert!(
            claimed_without_deployment.validate_candidate().is_err(),
            "an unverified candidate must not still be carrying deployment authority"
        );
    }

    #[test]
    fn mainnet_pilot_is_capped_and_explicitly_fee_free() {
        let policy = MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        )
        .unwrap();

        // The caps are `is_mainnet_pilot_profile` caps, identical on both
        // mainnet profiles. They are exercised here on the bounded one because
        // that is the only profile whose document can honestly reach
        // `payments_enabled` today — see the second half.
        let mut readiness = MainnetReadinessV1::evaluate(
            MAINNET_BOUNDED_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            false,
            None,
            false,
            Ok(capabilities()),
        );
        assert!(!readiness.payments_enabled);
        readiness.apply_mainnet_admission(&policy, Ok(0));
        assert!(readiness.payments_enabled);
        assert_eq!(readiness.wallet_fee_hac, "0");
        readiness
            .require_payment_ready(HacAmount::from_millimeis(1_000))
            .unwrap();
        assert!(
            readiness
                .require_payment_ready(HacAmount::from_millimeis(1_001))
                .is_err()
        );
        readiness
            .require_channel_funding_ready_zhu(MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU)
            .unwrap();
        assert!(
            readiness
                .require_channel_funding_ready_zhu(
                    MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU + 1,
                )
                .is_err()
        );

        // The full pilot profile publishes the same caps and is fee-free in the
        // same words, and is still shut - with a live witness, an admitted
        // allowlist, a fullnode reporting a verified registry deployment, and a
        // caller asserting both guarantees. Nothing in an argument list opens
        // it, because the part that is missing is a user who can leave without
        // the Hub.
        let anchor = anchor_evidence(crate::node::now_unix());
        let mut full = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            Some(&anchor),
            true,
            Ok(capabilities()),
        );
        full.apply_mainnet_admission(&policy, Ok(0));
        assert_eq!(
            full.max_payment_hac_zhu,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU
        );
        assert_eq!(
            full.max_channel_funding_hac_zhu,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU
        );
        assert_eq!(full.wallet_fee_hac, "0");
        assert!(!full.payments_enabled);
        assert!(!full.unilateral_l1_enforceable);
        assert!(!full.trustless_finality);
        assert!(
            full.blockers
                .iter()
                .any(|it| it == "wallet_cannot_build_a_unilateral_exit_without_the_hub")
        );
        assert!(
            full.require_payment_ready(HacAmount::from_millimeis(1))
                .is_err()
        );
    }

    /// No argument list may publish a guarantee the published evidence does
    /// not support.
    ///
    /// [`MainnetReadinessV1::evaluate`] is public and takes both guarantees as
    /// plain booleans. It used to write them straight into the document, so a
    /// caller could hand it `l1_dispute_path_ready: true` beside a
    /// `fullnode_capabilities` block with no registry evidence whatsoever, or
    /// `external_rollback_anchor_ready: true` beside `rollback_anchor: null`,
    /// and get `unilateral_l1_enforceable: true` and `trustless_finality: true`
    /// on the wire. The document would then be contradicting itself in the
    /// direction of a guarantee - the single failure this project ranks below a
    /// permanent red.
    #[test]
    fn no_argument_list_can_publish_a_guarantee_the_evidence_does_not_support() {
        let mut nothing_deployed = capabilities();
        nothing_deployed.channel_unilateral_exit = false;
        nothing_deployed.channel_unilateral_exit_evidence = None;
        nothing_deployed.channel_registry_unilateral_exit = false;
        nothing_deployed.channel_registry_unilateral_exit_evidence = None;

        let lied_to = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            None,
            true,
            Ok(nothing_deployed),
        );
        assert!(
            !lied_to.unilateral_l1_enforceable,
            "nothing is deployed and no anchor was supplied; the caller saying \
             otherwise must not reach the wire"
        );
        assert!(!lied_to.trustless_finality);
        assert!(!lied_to.payments_enabled);
        assert!(
            lied_to
                .blockers
                .iter()
                .any(|it| it == "external_monotonic_rollback_anchor_is_not_ready"),
            "the blocker list has to agree with the flags, or the document is \
             still self-contradictory"
        );
        assert!(
            lied_to
                .blockers
                .iter()
                .any(|it| it == "fullnode_does_not_report_verified_registry_unilateral_exit")
        );

        // Same lie with an unreachable fullnode: a probe that failed is not
        // evidence of anything, least of all of a verified deployment.
        let blind = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            None,
            true,
            Err(HubError::Node("offline".into())),
        );
        assert!(!blind.unilateral_l1_enforceable);
        assert!(!blind.trustless_finality);

        // And an anchor claim over evidence that fails its own measurement -
        // here a witness whose attestation has expired - is not an anchor.
        let mut expired = anchor_evidence(crate::node::now_unix());
        expired.attestation_expires_unix = 0;
        let stale_anchor = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            Some(&expired),
            true,
            Ok(capabilities()),
        );
        assert!(!stale_anchor.trustless_finality);
        assert!(
            stale_anchor
                .blockers
                .iter()
                .any(|it| it == "external_monotonic_rollback_anchor_is_not_ready")
        );
        assert_eq!(
            stale_anchor.rollback_anchor.as_ref(),
            Some(&expired),
            "the evidence that failed still travels, so a reader can see why"
        );
    }

    #[test]
    fn development_and_missing_capability_fail_closed() {
        let development = MainnetReadinessV1::evaluate(
            "development",
            0,
            0,
            false,
            false,
            None,
            false,
            Ok(capabilities()),
        );
        assert!(!development.payments_enabled);

        let operational_stop = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            false,
            true,
            None,
            true,
            Ok(capabilities()),
        );
        assert!(!operational_stop.payments_enabled);
        assert!(
            operational_stop
                .blockers
                .iter()
                .any(|blocker| blocker.contains("authenticated_storage_or_recovery"))
        );

        let missing = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            true,
            true,
            None,
            true,
            Err(HubError::Node("offline".into())),
        );
        assert!(!missing.payments_enabled);
    }

    #[test]
    fn missing_external_anchor_or_dispute_path_blocks_new_money_but_not_recovery_close() {
        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            true,
            false,
            None,
            false,
            Ok(capabilities()),
        );
        assert!(!readiness.payments_enabled);
        assert!(readiness.close_enabled);
        assert!(
            readiness
                .require_payment_ready(HacAmount::from_millimeis(1))
                .is_err()
        );
        readiness.require_cooperative_close_ready(false).unwrap();
        assert!(readiness.require_cooperative_close_ready(true).is_err());
    }

    #[test]
    fn operator_dispute_flag_cannot_override_missing_node_unilateral_exit() {
        let mut node = capabilities();
        node.channel_registry_unilateral_exit = false;
        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            true,
            true,
            None,
            true,
            Ok(node),
        );
        assert!(!readiness.payments_enabled);
        assert!(readiness.close_enabled);
        assert!(readiness.blockers.iter().any(|blocker| {
            blocker == "fullnode_does_not_report_verified_registry_unilateral_exit"
        }));

        let mut missing_evidence = capabilities();
        missing_evidence.channel_registry_unilateral_exit_evidence = None;
        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            true,
            true,
            None,
            true,
            Ok(missing_evidence),
        );
        assert!(!readiness.payments_enabled);
        assert!(readiness.blockers.iter().any(|blocker| {
            blocker == "fullnode_does_not_report_verified_registry_unilateral_exit"
        }));
    }

    /// A fullnode that reports everything perfectly is still not a user
    /// getting their money out.
    ///
    /// `capabilities()` is the fully green fixture:
    /// `channel_registry_unilateral_exit` true, an independently verified
    /// mainnet deployment of the shared registry, confirmed deployment
    /// transaction, matching code hash, constructor bound to this node's own
    /// network. Before the user-side term existed that combination alone
    /// published `unilateral_l1_enforceable: true`. It must not, because no
    /// wallet can build the exit transaction, and this test is what stops that
    /// combination from ever being enough again.
    #[test]
    fn a_perfect_fullnode_report_is_not_a_unilateral_exit() {
        let node = capabilities();
        assert!(
            node.channel_registry_unilateral_exit
                && node
                    .channel_registry_unilateral_exit_evidence
                    .as_ref()
                    .is_some_and(
                        crate::node::RegistryUnilateralExitEvidence::is_verified_mainnet_deployment
                    ),
            "the fixture must be the fully green fullnode report, or this proves nothing"
        );
        assert!(
            !measure_user_side_unilateral_exit_ready(),
            "no user-side exit driver ships today"
        );
        assert!(
            !measure_l1_dispute_path_ready(Some(&node)),
            "a node's report about itself must never be enough to publish the guarantee"
        );

        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            1_000_000,
            1_000_000,
            true,
            true,
            None,
            measure_l1_dispute_path_ready(Some(&node)),
            Ok(node),
        );
        assert!(!readiness.unilateral_l1_enforceable);
        assert!(
            readiness.blockers.iter().any(|blocker| {
                blocker == "wallet_cannot_build_a_unilateral_exit_without_the_hub"
            }),
            "the document must name the real reason, not only the generic one"
        );
        // Cooperative close is a different question and stays available: this
        // blocker is about getting out *without* the Hub.
        assert!(readiness.close_enabled);
    }

    #[test]
    fn explicit_bounded_profile_allows_only_capped_allowlisted_hub_trust() {
        let mut readiness = MainnetReadinessV1::evaluate(
            MAINNET_BOUNDED_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            false,
            None,
            false,
            Ok(capabilities()),
        );
        assert!(!readiness.payments_enabled);
        assert!(readiness.trusted_bounded_pilot);
        assert!(!readiness.trustless_finality);
        assert!(!readiness.unilateral_l1_enforceable);
        let policy = MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        )
        .unwrap();
        readiness.apply_mainnet_admission(&policy, Ok(0));
        assert!(readiness.payments_enabled);
        readiness
            .require_payment_ready(HacAmount::from_millimeis(1_000))
            .unwrap();

        readiness.profile = MAINNET_PILOT_PROFILE.into();
        assert!(
            readiness
                .require_payment_ready(HacAmount::from_millimeis(1))
                .is_err()
        );
    }

    /// The node half of the dispute-path measurement must follow the node's
    /// evidence in both directions, otherwise it is not a measurement.
    ///
    /// Both directions are still exercised here, against
    /// [`measure_node_reported_unilateral_exit`], because that is the term the
    /// node's evidence actually decides. The full
    /// [`measure_l1_dispute_path_ready`] cannot reach `true` from node
    /// evidence alone by design, and the last assertion pins that.
    #[test]
    fn the_dispute_path_flag_tracks_node_evidence_in_both_directions() {
        assert!(
            measure_node_reported_unilateral_exit(Some(&capabilities())),
            "verified evidence is present, so the node half must be true"
        );
        assert!(
            !measure_node_reported_unilateral_exit(None),
            "an unprobeable fullnode proves nothing"
        );

        let mut withdrawn = capabilities();
        withdrawn.channel_registry_unilateral_exit = false;
        assert!(!measure_node_reported_unilateral_exit(Some(&withdrawn)));

        let mut no_evidence = capabilities();
        no_evidence.channel_registry_unilateral_exit_evidence = None;
        assert!(!measure_node_reported_unilateral_exit(Some(&no_evidence)));

        let mut unverified = capabilities();
        if let Some(evidence) = unverified
            .channel_registry_unilateral_exit_evidence
            .as_mut()
        {
            evidence.deployment_verified = false;
        }
        assert!(
            !measure_node_reported_unilateral_exit(Some(&unverified)),
            "evidence that fails validation must not count"
        );

        assert!(
            !measure_l1_dispute_path_ready(Some(&capabilities())),
            "the node half is necessary but never sufficient: a user must also \
             be able to build the exit, and today none can"
        );
    }

    fn anchor_evidence(now: u64) -> crate::rollback_anchor::RollbackAnchorEvidenceV1 {
        crate::rollback_anchor::RollbackAnchorEvidenceV1 {
            schema: crate::rollback_anchor::ROLLBACK_ANCHOR_EVIDENCE_SCHEMA.into(),
            witness_id: "witness-alpha".into(),
            witness_instance_id: "ab".repeat(32),
            witness_boot_id: "cd".repeat(32),
            witness_operator: "Example Counterparty Ltd".into(),
            witness_posture: "counterparty".into(),
            witness_endpoint_posture: "external".into(),
            witness_endpoint_is_local: false,
            witness_store_in_hub_state_tree: false,
            witness_co_located: false,
            attestation_valid: true,
            attestation_expires_unix: now + 86_400,
            key_custody_distinct: true,
            instance_pin_holds: true,
            counter_never_decreased: true,
            startup_probe_agreed: true,
            counter_value: 42,
            verified_unix: now,
            channels_latched_in_refusal: 0,
        }
    }

    /// The flag must follow the evidence in both directions, and every part of
    /// the conjunction must be able to hold it false on its own. A flag that
    /// only ever reads one way is not a measurement.
    #[test]
    fn the_external_anchor_flag_is_a_conjunction_over_live_witness_evidence() {
        let now = 1_800_000_000;
        assert!(
            !measure_external_rollback_anchor_ready(None, now),
            "no witness configured, or an unreachable one, proves nothing"
        );
        assert!(
            measure_external_rollback_anchor_ready(Some(&anchor_evidence(now)), now),
            "a live witness with a verified, fresh, pinned answer must read true"
        );

        let stale = anchor_evidence(now);
        assert!(
            !measure_external_rollback_anchor_ready(
                Some(&stale),
                now + crate::rollback_anchor::protocol::MAX_WITNESS_MESSAGE_AGE_SECS + 1
            ),
            "evidence outside the freshness window is not evidence of a live witness"
        );

        for hold_false in [
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.attestation_valid = false;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.attestation_expires_unix = 0;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.key_custody_distinct = false;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.instance_pin_holds = false;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.counter_never_decreased = false;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.startup_probe_agreed = false;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.channels_latched_in_refusal = 1;
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.witness_instance_id = String::new();
            },
            |evidence: &mut crate::rollback_anchor::RollbackAnchorEvidenceV1| {
                evidence.schema = "something-else/1".into();
            },
        ] {
            let mut evidence = anchor_evidence(now);
            hold_false(&mut evidence);
            assert!(
                !measure_external_rollback_anchor_ready(Some(&evidence), now),
                "each part of the conjunction must hold the flag false on its own"
            );
        }
    }

    /// `production_mainnet_ready` must be held false by every one of its parts
    /// independently, and the anchor must be enough on its own.
    #[test]
    fn production_mainnet_ready_is_held_false_by_each_missing_part() {
        let now = crate::node::now_unix();
        let anchor = anchor_evidence(now);
        let best_available = HubHardGuarantees::measure(
            MAINNET_PILOT_PROFILE,
            true,
            Some(&capabilities()),
            None,
            now,
        );
        assert!(measure_node_reported_unilateral_exit(Some(&capabilities())));
        assert!(
            !best_available.l1_dispute_path_ready,
            "the node reports a verified deployment, but no user can build the \
             exit, so the dispute path is not ready"
        );
        assert!(!best_available.external_rollback_anchor_ready);
        assert!(
            !best_available.production_mainnet_ready,
            "the missing anchor alone must hold the strongest claim false"
        );

        // Everything this Hub can obtain is present here: a live witness, a
        // settling Hub, the mainnet-pilot profile, and a fullnode reporting a
        // verified mainnet deployment of the reviewed exit contract. The
        // strongest claim is still false, and the part that holds it false is
        // the one no Hub and no node can supply — a user who can get out
        // alone. That is the honest state of this system, and if this
        // assertion ever needs inverting it must be because
        // `USER_SIDE_UNILATERAL_EXIT_DRIVER_READY` was earned, not edited.
        let everything_a_hub_can_have = HubHardGuarantees::measure(
            MAINNET_PILOT_PROFILE,
            true,
            Some(&capabilities()),
            Some(&anchor),
            now,
        );
        assert!(everything_a_hub_can_have.external_rollback_anchor_ready);
        assert!(
            !everything_a_hub_can_have.production_mainnet_ready,
            "trustless finality must not be claimed while the user has no exit"
        );
        assert!(
            !measure_user_side_unilateral_exit_ready(),
            "and this is the part that is missing"
        );

        assert!(
            !HubHardGuarantees::measure(
                MAINNET_PILOT_PROFILE,
                false,
                Some(&capabilities()),
                Some(&anchor),
                now
            )
            .production_mainnet_ready,
            "a Hub that cannot settle is not production ready"
        );
        assert!(
            !HubHardGuarantees::measure(
                "development",
                true,
                Some(&capabilities()),
                Some(&anchor),
                now
            )
            .production_mainnet_ready,
            "a non-mainnet-pilot profile is not production ready"
        );

        let blind = HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, true, None, None, now);
        assert!(!blind.production_mainnet_ready);
        assert!(!blind.l1_dispute_path_ready);

        let mut below_checkpoint = capabilities();
        below_checkpoint.height = HACASH_MAINNET_MIN_SAFE_HEIGHT - 1;
        assert!(
            !HubHardGuarantees::measure(
                MAINNET_PILOT_PROFILE,
                true,
                Some(&below_checkpoint),
                Some(&anchor),
                now
            )
            .production_mainnet_ready
        );

        let mut not_mainnet = capabilities();
        not_mainnet.mainnet = false;
        assert!(
            !HubHardGuarantees::measure(
                MAINNET_PILOT_PROFILE,
                true,
                Some(&not_mainnet),
                Some(&anchor),
                now
            )
            .production_mainnet_ready
        );
    }

    /// The anchor input must change the verdict, so that a real anchor will
    /// actually flow through the gate instead of being reported decoratively.
    ///
    /// The verdict is the blocker list and `payments_enabled`, not
    /// `trustless_finality` — that flag is a conjunction with the dispute path,
    /// and the dispute path is held false by a term no anchor can supply (no
    /// wallet can build an exit). Reading it here would only ever have proved
    /// the anchor load bearing by way of a caller's assertion, which is exactly
    /// what stopped being possible.
    #[test]
    fn the_anchor_input_is_load_bearing_not_decorative() {
        let anchor_blocker = "external_monotonic_rollback_anchor_is_not_ready";
        let without = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            false,
            None,
            true,
            Ok(capabilities()),
        );
        assert!(!without.trustless_finality);
        assert!(without.blockers.iter().any(|it| it == anchor_blocker));

        // The same Hub, the same fullnode, one live verified witness added. The
        // anchor blocker has to disappear, or the witness is decoration.
        let anchor = anchor_evidence(crate::node::now_unix());
        let with = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            Some(&anchor),
            true,
            Ok(capabilities()),
        );
        assert!(
            !with.blockers.iter().any(|it| it == anchor_blocker),
            "a live, verified, fresh witness must clear its own blocker, got {:?}",
            with.blockers
        );
        assert_ne!(
            without.blockers, with.blockers,
            "the anchor input has to change the verdict"
        );

        // And what remains is the honest reason, named. `trustless_finality` is
        // still false with a perfect anchor and a perfect fullnode, because the
        // user still has no way out on their own.
        assert!(!with.trustless_finality);
        assert!(!with.unilateral_l1_enforceable);
        assert!(
            with.blockers
                .iter()
                .any(|it| it == "wallet_cannot_build_a_unilateral_exit_without_the_hub")
        );
    }

    /// The posture must reach the published document, and it must reach it
    /// whether or not the flag it explains reads `true`.
    ///
    /// Two guarantees of very different worth - a neutral third party on
    /// separate infrastructure, and a witness on this Hub's own host with its
    /// store in this Hub's own backup set - are the same single boolean. If the
    /// only thing that crosses the wire is that boolean, the two are
    /// indistinguishable to a wallet and to a person choosing a hub.
    #[test]
    fn the_published_document_carries_the_posture_and_not_just_the_flag() {
        let now = crate::node::now_unix();
        let neutral = anchor_evidence(now);
        let published = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            Some(&neutral),
            true,
            Ok(capabilities()),
        );
        assert_eq!(
            published.rollback_anchor.as_ref(),
            Some(&neutral),
            "the document must publish the exact evidence the flag was measured from"
        );
        assert!(
            published
                .limitations
                .iter()
                .any(|it| it.contains("counterparty")),
            "who runs the witness belongs in plain words too, got {:?}",
            published.limitations
        );
        assert!(
            !published
                .limitations
                .iter()
                .any(|it| it.contains("co-located")),
            "a witness on separate infrastructure must not be smeared as co-located"
        );

        // Same flag, same blockers, a materially weaker guarantee. The
        // difference has to be visible.
        let mut same_host = anchor_evidence(now);
        same_host.witness_posture = "same_operator_separate_infrastructure".into();
        same_host.witness_endpoint_is_local = true;
        same_host.witness_endpoint_posture = "same_host_or_plaintext".into();
        same_host.witness_store_in_hub_state_tree = true;
        same_host.witness_co_located = true;
        let weak = MainnetReadinessV1::evaluate(
            "local-pilot",
            0,
            0,
            true,
            true,
            Some(&same_host),
            true,
            Ok(capabilities()),
        );
        assert_eq!(weak.trustless_finality, published.trustless_finality);
        assert!(
            weak.limitations.iter().any(|it| it.contains("co-located")),
            "a witness inside this Hub's failure domain must say so, got {:?}",
            weak.limitations
        );
        assert_ne!(
            weak.rollback_anchor, published.rollback_anchor,
            "two guarantees of different worth must not publish identically"
        );

        // And a Hub with no witness says exactly that, rather than nothing.
        let none = MainnetReadinessV1::evaluate(
            "local-pilot",
            0,
            0,
            true,
            false,
            None,
            true,
            Ok(capabilities()),
        );
        assert!(none.rollback_anchor.is_none());
    }
}
