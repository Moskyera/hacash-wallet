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
/// Nobody answers the objection window while the owner is asleep.
///
/// A fixed identifier, used by every push and every filter that mentions this
/// condition, because it is now published from two different lists and a typo
/// in one of them would silently drop the item from the document rather than
/// fail to compile.
pub const OFFLINE_OWNER_UNDEFENDED_BLOCKER: &str = "no_watcher_answers_for_an_offline_owner";
/// The dispute path is not enforceable without the counterparty.
pub const UNILATERAL_DISPUTE_PATH_BLOCKER: &str = "unilateral_l1_dispute_path_is_not_ready";
/// No wallet on any platform can build the exit transaction.
pub const WALLET_CANNOT_EXIT_BLOCKER: &str =
    "wallet_cannot_build_a_unilateral_exit_without_the_hub";
/// No verified external monotonic rollback witness.
pub const EXTERNAL_ROLLBACK_ANCHOR_BLOCKER: &str =
    "external_monotonic_rollback_anchor_is_not_ready";

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

    /// Refuse to run a Hub that cannot honour the channel cap it publishes.
    ///
    /// A Hub whose aggregate TVL cap is below its per-channel funding cap
    /// advertises a channel size it will always refuse at admission: readiness
    /// publishes `max_channel_funding_hac_zhu: 1000000000` next to
    /// `max_aggregate_tvl_hac_zhu: 100000000`, a wallet reads the first, the
    /// person funds against it, and `require_pilot_channel_admission` refuses.
    /// The two numbers come from different flags and nothing compared them.
    ///
    /// This is a new refusal, not a relaxed one. It raises no cap: both remain
    /// bounded by their compile-time hard maxima, and an operator who wants a
    /// small aggregate gets it by lowering the channel cap to match, which is
    /// the configuration they were describing anyway. `install.sh` has enforced
    /// exactly this coherence rule since it was written; the binary did not.
    pub fn require_can_fund_channel_cap(&self, max_channel_funding_hac_zhu: u64) -> HubResult<()> {
        if max_channel_funding_hac_zhu > self.max_aggregate_tvl_hac_zhu {
            return Err(HubError::State(format!(
                "mainnet pilot aggregate TVL cap ({} zhu) is below the per-channel funding cap \
                 ({max_channel_funding_hac_zhu} zhu). This Hub would publish a channel cap it \
                 could never fund. Raise --mainnet-max-aggregate-tvl-hac-zhu to at least \
                 {max_channel_funding_hac_zhu}, or lower --mainnet-max-channel-funding-hac-zhu \
                 to at most {}.",
                self.max_aggregate_tvl_hac_zhu, self.max_aggregate_tvl_hac_zhu
            )));
        }
        Ok(())
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
    /// What this Hub's aggregate TVL actually is right now, in zhu.
    ///
    /// The document already carried the cap and a boolean saying the cap was
    /// not exceeded. It never carried the measurement, so there was no way to
    /// tell a Hub with the whole budget free from one with none of it free -
    /// both published `aggregate_tvl_within_limit: true`, because that field is
    /// `current <= cap` and equality is inside the cap.
    #[serde(default)]
    pub aggregate_tvl_hac_zhu: u64,
    /// Cap minus current: how much deposit a *new* channel could still bring.
    ///
    /// This is the number a person needs and the document did not have. A Hub
    /// sitting exactly on its cap is simultaneously within its limit and unable
    /// to admit anything, and for eight hours that state was indistinguishable
    /// from a healthy one on this endpoint.
    #[serde(default)]
    pub aggregate_tvl_headroom_hac_zhu: u64,
    /// Whether a new channel of any size can be admitted at all.
    ///
    /// Deliberately **not** a blocker and deliberately not folded into
    /// `payments_enabled`. A Hub at its cap is perfectly healthy for every
    /// channel it already has: payments settle, closes settle, nothing is
    /// wrong. The only thing it cannot do is take a new channel, and that is
    /// exactly what this one field says.
    #[serde(default)]
    pub new_channel_admission_available: bool,
    pub max_payment_satoshi: u64,
    pub wallet_fee_hac: &'static str,
    pub trustless_finality: bool,
    pub unilateral_l1_enforceable: bool,
    #[serde(default)]
    pub trusted_bounded_pilot: bool,
    pub settlement_model: &'static str,
    pub blockers: Vec<String>,
    pub close_blockers: Vec<String>,
    /// Conditions that are outstanding and true, and that this profile has
    /// deliberately decided not to gate on.
    ///
    /// **Why this field exists at all.** `blockers` and `close_blockers` are
    /// gates, and a profile that waives a gate used to waive the *sentence*
    /// with it: on `MAINNET_BOUNDED_PILOT_PROFILE` the whole dispute-path
    /// branch was skipped, so `no_watcher_answers_for_an_offline_owner` was
    /// never pushed anywhere and the served document read
    /// `"blockers":[],"close_blockers":[]`. To a person and to a script alike
    /// that says "nothing outstanding", while the single largest way to lose
    /// money on this system - a provider settling an old receipt during the
    /// objection window while the owner is offline - was outstanding and
    /// unmeasured. Waiving a gate is a legitimate product decision. Waiving
    /// the disclosure is not, and the two had no way to be told apart because
    /// the distinction lived in a comment instead of in the type.
    ///
    /// So this is the third list, and the invariant is stated rather than
    /// implied: **`blockers` and `disclosed_blockers` are disjoint, and their
    /// union is everything this Hub knows to be outstanding.** An item moves
    /// between them when the profile changes, never disappears. A reader who
    /// wants "is anything wrong" reads both; a script that wants "may I pay"
    /// reads `payments_enabled`; a script that wants "may I close" reads
    /// `close_enabled`. Nothing here changes what any of those three answer.
    ///
    /// Items filtered out of `close_blockers` are *not* repeated here: they are
    /// still in `blockers`, so they are already visible, and duplicating them
    /// would make the union stop meaning anything.
    ///
    /// `#[serde(default)]` so a wallet built before this field can still read a
    /// newer Hub. It defaults to empty, which is the safe direction for a list
    /// that nothing gates on.
    #[serde(default)]
    pub disclosed_blockers: Vec<String>,
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
        // The same three terms `measure_l1_dispute_path_ready` ANDs, plus the
        // fourth, re-derived here against the evidence this very document
        // publishes so a reader can check the flag against the blocks beside
        // it. Two places computing one property is how a term gets forgotten -
        // this one was, and lifting the driver constant published
        // `unilateral_l1_enforceable` through the gap while the sleeping owner
        // stayed exactly as exposed. Anything added to that function belongs
        // here too.
        let offline_user_defended = measure_offline_user_defended();
        let l1_dispute_path_ready = l1_dispute_path_ready
            && node_reported_unilateral_exit
            && user_side_unilateral_exit_ready
            && offline_user_defended;
        let mut blockers = Vec::new();
        // Outstanding and true, but not gating on this profile. See the field
        // doc on `disclosed_blockers`: a waived gate is a decision, a waived
        // sentence is a lie by omission, and this list is what keeps them apart.
        let mut disclosed_blockers: Vec<String> = Vec::new();
        if !hub_operational_ready {
            blockers.push("hub_signer_authenticated_storage_or_recovery_gate_is_not_ready".into());
        }
        let is_bounded_pilot = profile == MAINNET_BOUNDED_PILOT_PROFILE;
        // The bounded pilot waives these two gates on purpose - that waiver is
        // the whole point of the profile, and putting them back into `blockers`
        // would set `payments_enabled` false and wedge the profile shut. So the
        // waiver stays exactly as it was and only the *reporting* changes: the
        // identifiers still get computed, and they still get published, in the
        // list that says out loud that nothing is gating on them.
        if !external_rollback_anchor_ready {
            let sink = if is_bounded_pilot {
                &mut disclosed_blockers
            } else {
                &mut blockers
            };
            sink.push(EXTERNAL_ROLLBACK_ANCHOR_BLOCKER.into());
        }
        if !l1_dispute_path_ready {
            let sink = if is_bounded_pilot {
                &mut disclosed_blockers
            } else {
                &mut blockers
            };
            sink.push(UNILATERAL_DISPUTE_PATH_BLOCKER.into());
            // Say which half is missing, because the two fail for very
            // different reasons and the reader deserves the one that is
            // actually true. The line above reads like "the chain is not
            // ready yet". This one says the chain is not the obstruction: no
            // wallet on any platform can build a challenge, respond, finalize
            // or claim transaction, so a user holding a perfectly valid
            // countersigned bill still has no instrument to present it with.
            if !user_side_unilateral_exit_ready {
                sink.push(WALLET_CANNOT_EXIT_BLOCKER.into());
            }
            // And the half that stays missing after the wallet can leave: a
            // provider can settle an old receipt while the owner is offline,
            // and nothing here answers the window for them. Named separately
            // because it fails for a different reason than the two above and
            // is not fixed by either of them.
            if !offline_user_defended {
                sink.push(OFFLINE_OWNER_UNDEFENDED_BLOCKER.into());
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
                    && blocker.as_str() != EXTERNAL_ROLLBACK_ANCHOR_BLOCKER
                    && blocker.as_str() != UNILATERAL_DISPUTE_PATH_BLOCKER
                    && blocker.as_str() != WALLET_CANNOT_EXIT_BLOCKER
                    // Closing is the owner's way out and must never be the
                    // thing a missing guarantee takes away. A watcher answers
                    // a window during a dispute; it has nothing to do with
                    // whether a cooperative close may proceed, and blocking
                    // close over it would strand people to protect them.
                    //
                    // Filtered out of the *gate*, not out of the document: on
                    // every profile that reaches this filter the identifier is
                    // still sitting in `blockers` above, and on the bounded
                    // pilot it is in `disclosed_blockers`. It is never absent
                    // from both.
                    && blocker.as_str() != OFFLINE_OWNER_UNDEFENDED_BLOCKER
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
        // The identifier in `disclosed_blockers` is for scripts. This is the
        // same fact for a person, because an identifier nobody can expand is
        // only marginally better than an empty list.
        if !offline_user_defended {
            limitations.push(format!(
                "{OFFLINE_OWNER_UNDEFENDED_BLOCKER}: nobody answers the objection window on an \
                     offline owner's behalf, and nothing finalizes or claims for them either. On \
                     the shipped one-directional rail this cannot cost them principal, because a \
                     stale split pays the left party MORE and the driver deliberately declines to \
                     answer it; that rests on two checks (a refused non-zero hub deposit and a \
                     ledger that only subtracts from the left balance) rather than on the \
                     protocol. It is disclosed and it does not block closing"
            ));
        }
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
            aggregate_tvl_hac_zhu: 0,
            aggregate_tvl_headroom_hac_zhu: 0,
            new_channel_admission_available: false,
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
            disclosed_blockers,
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
                self.aggregate_tvl_hac_zhu = current_tvl;
                self.aggregate_tvl_headroom_hac_zhu = policy
                    .max_aggregate_tvl_hac_zhu()
                    .saturating_sub(current_tvl);
                self.new_channel_admission_available = self.aggregate_tvl_headroom_hac_zhu > 0;
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
        // A Hub sitting exactly on its cap satisfies every gate in this
        // document and refuses every new channel. `aggregate_tvl_within_limit`
        // is `current <= cap`, so it reads true at full utilisation, and
        // `blockers` stays empty because nothing is broken. Without this
        // sentence the served document says "healthy" and means "closed to new
        // channels", which is the difference between a person waiting five
        // minutes and a person losing an evening.
        if self.aggregate_tvl_within_limit && !self.new_channel_admission_available {
            self.limitations.push(format!(
                "this Hub is at its aggregate TVL cap ({} zhu of {} zhu) and will refuse every \
                 new channel until some of that budget is released. Existing channels are \
                 unaffected: payments and closes still settle",
                self.aggregate_tvl_hac_zhu, self.max_aggregate_tvl_hac_zhu
            ));
        }
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
pub const USER_SIDE_UNILATERAL_EXIT_DRIVER_READY: bool = true;

#[cfg(test)]
mod user_side_exit_readiness_tests {
    /// The flag stays down until a user can actually reach the driver.
    ///
    /// Condition 1 is met and measurably so — the probe below flips itself, and
    /// the on-chain proof exists. That is exactly the situation in which a flag
    /// is most likely to be flipped for the wrong reason, so this test states
    /// the remaining gap in a place that fails if the flag moves without it.
    /// One term of the tripwire: records the message when the term is unmet.
    ///
    /// Deliberately not `assert!`. A term that fails must be *collected* and
    /// not thrown, so that one missing capability cannot hide the other eleven
    /// behind the first panic, and so the terms can be measured while the flag
    /// is down without the measurement itself being a failure.
    macro_rules! term {
        ($unmet:ident, $condition:expr, $($message:tt)*) => {
            if !$condition {
                $unmet.push(format!($($message)*));
            }
        };
    }

    /// Every term, evaluated unconditionally, returning the ones that fail.
    ///
    /// Split out of the test below because the test used to begin with
    /// `if !USER_SIDE_UNILATERAL_EXIT_DRIVER_READY { return; }`, which meant
    /// that while the flag was down - which is the whole time it has ever
    /// existed - none of these terms was evaluated at all. The suite reported
    /// the tripwire green over a body that never ran, so the flag was held
    /// down by human restraint and this file got the credit.
    ///
    /// Now the terms are measured on every run whatever the flag says, the
    /// test below turns them into a failure only when the flag claims they
    /// hold, and `every_term_is_measured_and_reported` prints the standing of
    /// each one so the gap is visible before somebody decides to close it.
    fn unmet_user_side_exit_terms() -> Vec<String> {
        let mut unmet: Vec<String> = Vec::new();
        let signer = include_str!("../../agent-wallet-core/src/signer.rs");
        // Narrowed, like every other term. This one read the raw file long
        // after terms 3 and 4 were given the narrowing, so a single line
        // `// sign_exact_registry_exit` over a signer with the capability
        // deleted satisfied the first thing this tripwire asks.
        let signer_source = shipped_source(signer);
        term!(
            unmet,
            signer_source.contains("fn sign_exact_registry_exit("),
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
        term!(
            unmet,
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
        term!(
            unmet,
            signer_source.contains("fn sign_exact_registry_channel_open("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while no Agent Wallet can \
             open a registry channel in the first place. Adoption needs the wallet's own left \
             signature on the serial-1 refund bill and nothing in `agent-wallet-core` produces \
             one, so every wallet reaching this screen is told it has no provider channel to \
             close. The exit is finished; the way in is not."
        );

        // Fourth term: A CHANNEL WITH MONEY IN IT.
        //
        // Two reviewers, independently, reported the same thing about this
        // test: all three terms above now pass, and the capability they stand
        // for still did not exist. The guard that had caught this project three
        // times was spent, and the flag was held down only by human restraint.
        //
        // What was missing was the hop between the countersigned refund and a
        // channel: nothing shipped could put the deposit in. A refund for an
        // empty channel is not a way out of anything, and a flag that says a
        // user can walk out over a channel no shipped surface can fund is the
        // same lie in a new shape.
        //
        // So the funding signing boundary is named the way the exit signer and
        // the open signer were named here before they existed.
        term!(
            unmet,
            signer_source.contains("fn sign_exact_registry_funding("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while no Agent Wallet can put \
             money into the channel it opened. The refund exists, the permission exists, and \
             nothing shipped spends it, so every channel a user could exit is empty."
        );

        // Terms 3 and 4 name a *definition*, which is the right shape for a
        // signing boundary: the capability is that the method exists on the
        // signer. But a definition nobody calls signs nothing, and a reviewer
        // satisfied both terms with one `#[allow(dead_code)] fn` that returned
        // the names as strings. So each signing boundary must also be reached
        // from the service module that owns that hop, and reached with a call
        // rather than a mention.
        let open_service = shipped_source(include_str!(
            "../../agent-wallet-core/src/service/hvm_registry_open.rs"
        ));
        let exit_service = shipped_source(include_str!(
            "../../agent-wallet-core/src/service/hvm_registry.rs"
        ));
        for (source, module, method) in [
            (
                &open_service,
                "hvm_registry_open",
                "sign_exact_registry_channel_open(",
            ),
            (
                &open_service,
                "hvm_registry_open",
                "sign_exact_registry_funding(",
            ),
            (&exit_service, "hvm_registry", "sign_exact_registry_exit("),
        ] {
            term!(
                unmet,
                source.contains(&format!(".{method}")),
                "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while `{module}` never \
                 calls `{method}`. The signer can make these bytes and nothing asks it to, \
                 which is the same capability-with-no-caller shape as a driver whose only \
                 caller is a test - one layer further down, where the earlier terms cannot \
                 see it."
            );
        }

        // Fifth term: A PRESS THAT REACHES IT, and one that reaches the
        // provider-free adoption.
        //
        // Same failure the second term exists for, one hop further along. A
        // funding method whose only caller is a test funds nothing, and an
        // adopted binding is what the exit refuses without: a reviewer drove
        // the exact trap where an honest countersignature and an honest
        // deposit still left the owner stuck, because the only writer of the
        // adopted binding needed the provider alive four times and the
        // provider was gone. The chain would have paid.
        let shipped_commands = shipped_source(commands);
        term!(
            unmet,
            shipped_commands.contains(".fund_hvm_registry_channel("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while nothing an owner can \
             press puts the deposit into the channel. A funding method whose only caller is a \
             test is the shape this workspace has shipped three times."
        );
        term!(
            unmet,
            shipped_commands.contains(".adopt_hvm_registry_channel_from_chain("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while the only route to an \
             adopted binding needs the provider alive. The exit refuses without that binding, \
             so a provider that vanishes between the deposit and the adoption traps the owner \
             in a channel the chain would happily pay them out of."
        );

        // Sixth term: AND THE WAY IN IS SAFE.
        //
        // The five terms above are about reachability, and reachability alone
        // is what makes this flag dangerous rather than useful. A reviewer
        // deployed a contract of their own at the address a channel named,
        // published the reviewed bytecode digest beside it, had an entirely
        // honest Hub countersign the full refund, took the deposit on chain and
        // withdrew it - because nothing on the path from the owner's press to
        // the funding gate read a chain at all. Every check that would have
        // caught it lived in adoption, on the far side of the spend.
        //
        // A pressable, fundable, exitable channel that can be pointed at a
        // stranger's contract is worse than no channel, so the gate is required
        // to demand chain evidence in its own signature. Named as the
        // parameter, because a parameter cannot be satisfied by a comment and
        // cannot be forgotten by a caller.
        //
        // Naming `validate_prefunding_binding(` was not enough on its own,
        // and the comment above used to claim a parameter "cannot be forgotten
        // by a caller". It can, if nothing is required to call it: the bare
        // name would equally match a `fn validate_prefunding_binding(` that
        // nobody invokes, so the gate could be defined, never called, and this
        // term would still read true.
        //
        // What is demanded instead is the *method call*, leading dot included.
        // The gate is defined in another module; what this file has to do is
        // reach it, and `.validate_prefunding_binding(` is that fact and
        // cannot be satisfied by a definition.
        let open_gate = shipped_source(include_str!("../../wallet-core/src/hvm_registry_open.rs"));
        term!(
            unmet,
            open_gate.contains("chain: &HvmRegistryOpenChainEvidenceV1<'_>,")
                && open_gate.contains(".validate_prefunding_binding("),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while funding permission could \
             be produced without reading the wallet's own fullnode. A refund that names a \
             contract nobody checked is a refund for something that is not the registry, and a \
             reviewer took a whole deposit through that gap in real blocks."
        );

        // Seventh term: THE SHELL ACTUALLY CARRIES THE COMMANDS.
        //
        // The five reachability terms above all read `agent_commands.rs`, and
        // that file is a library. A `#[tauri::command]` in it is not reachable
        // by anybody until the desktop shell registers it in its invoke
        // handler and its capability allowlist; until then the button calls a
        // command the runtime has never heard of. That is the same
        // "only caller is a test" failure wearing the shape of a build
        // configuration, and it is the one shape the earlier terms could not
        // see - which is exactly how this tripwire came to have three terms
        // that all passed over a capability nobody had.
        //
        // So the shell is read too, and both halves of it: registration and
        // permission. Neither alone makes a command pressable.
        //
        // Both halves were read completely raw, which made this the cheapest
        // term in the file to forge: four Rust `//` lines and four TOML `#`
        // lines, over a shell that registered nothing and an allowlist that
        // permitted nothing, satisfied all eight assertions below. They are
        // narrowed now, each by the rules of its own language.
        let shell = shipped_source(include_str!("../../../apps/desktop/src-tauri/src/lib.rs"));
        let permissions = shipped_toml(include_str!(
            "../../../apps/desktop/src-tauri/permissions/wallet.toml"
        ));
        for command in [
            "agent_wallet_open_hvm_registry_channel",
            "agent_wallet_fund_hvm_registry_channel",
            "agent_wallet_adopt_hvm_registry_channel",
            "agent_wallet_start_hvm_registry_exit",
        ] {
            term!(
                unmet,
                shell.contains(&format!("wallet_tauri_common::agent_commands::{command},")),
                "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while the desktop shell \
                 does not register `{command}`. A Tauri command the invoke handler has never \
                 heard of is a button that returns an error, and every term above would still \
                 pass."
            );
            term!(
                unmet,
                permissions.contains(&format!("\"{command}\"")),
                "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while the desktop \
                 capability allowlist does not permit `{command}`. Registration without \
                 permission is a button that is denied rather than one that works."
            );
        }

        // Eighth term: A SCREEN.
        //
        // The seventh term closed the "registered but never called" hole one
        // layer down. This closes it one layer up, and it is the layer that
        // decides whether an ordinary person can do this at all: a command
        // that is registered, permitted and never invoked by the renderer is a
        // capability that exists for whoever reads the source and for nobody
        // else.
        //
        // Named as the `invoke` call rather than as a button, because a button
        // is a rendering detail and the invoke is the fact.
        //
        // Narrowed by TypeScript's rules and not by Rust's. `shipped_source`
        // deletes string literals, which is right for Rust - a symbol inside a
        // string does nothing - and exactly wrong here, because the command
        // name *is* a string literal and deleting it would make this term
        // impossible to satisfy rather than hard to forge. So comments go and
        // strings stay.
        let renderer = shipped_typescript(include_str!("../../../apps/desktop/src/agent/api.ts"));
        for command in [
            "agent_wallet_open_hvm_registry_channel",
            "agent_wallet_fund_hvm_registry_channel",
            "agent_wallet_adopt_hvm_registry_channel",
            "agent_wallet_start_hvm_registry_exit",
        ] {
            term!(
                unmet,
                renderer.contains(&format!("(\"{command}\",")),
                "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while nothing an owner can \
                 see calls `{command}`. Every term above can pass over a capability that only \
                 exists for someone reading the source, and this flag is a promise made to \
                 people who are not reading the source."
            );
        }

        // Ninth term: A SCREEN THAT RENDERS THE WRAPPER.
        //
        // Term 8 reads `api.ts` and nothing else, so an exported wrapper that
        // no component ever calls satisfies it. That is the same
        // "registered but never called" hole one final layer up, and it is the
        // layer an ordinary person actually touches: a renderer wrapper nobody
        // renders is a capability for whoever reads `api.ts`.
        //
        // So the admin surface is read too, and each wrapper must be called
        // from it. Named as the call on the API object, because that is the
        // fact; which button carries it is a rendering detail.
        let admin = shipped_typescript(include_str!(
            "../../../apps/desktop/src/agent/AgentAdminPages.tsx"
        ));
        for wrapper in [
            "openHvmRegistryChannel(",
            "fundHvmRegistryChannel(",
            "adoptHvmRegistryChannel(",
            "startHvmRegistryExit(",
        ] {
            term!(
                unmet,
                admin.contains(&format!("agentWalletApi.{wrapper}")),
                "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY was set true while no screen calls \
                 `{wrapper}`. The renderer wrapper exists and the command is registered and \
                 permitted, and an owner opening this app still cannot reach any of it."
            );
        }
        unmet
    }

    /// The tripwire itself: the flag may not be true over an unmet term.
    #[test]
    fn the_flag_is_down_because_no_surface_can_sign_an_exit() {
        let unmet = unmet_user_side_exit_terms();
        if !super::USER_SIDE_UNILATERAL_EXIT_DRIVER_READY {
            return;
        }
        assert!(
            unmet.is_empty(),
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY is true and {} term(s) of this tripwire do \
             not hold:\n\n{}",
            unmet.len(),
            unmet.join("\n\n")
        );
    }

    /// The terms are measured on every run, and their standing is printed.
    ///
    /// This test exists because the tripwire above is silent by construction
    /// while the flag is down: it has nothing to say until somebody sets the
    /// flag, and by then the person setting it is the person least likely to
    /// be told something they do not want to hear. Running the terms anyway
    /// turns "the flag is false" from an assertion nobody checks into a
    /// measurement anybody can read with `--nocapture`.
    ///
    /// It asserts only two things, and neither is the flag. First, that terms
    /// are actually being evaluated, so this cannot quietly become the empty
    /// check that the early return had already made it. Second, that a green
    /// term list and a false flag are allowed to coexist - because they must:
    /// every term here is a source-reachability check, and no arrangement of
    /// them can witness a person opening a channel, paying over it, losing
    /// their provider and walking out with their money. That run is the bar.
    /// These terms are the floor.
    #[test]
    fn every_term_is_measured_and_reported() {
        let unmet = unmet_user_side_exit_terms();
        println!(
            "USER_SIDE_UNILATERAL_EXIT_DRIVER_READY = {}",
            super::USER_SIDE_UNILATERAL_EXIT_DRIVER_READY
        );
        if unmet.is_empty() {
            println!("all terms hold");
        } else {
            println!("{} term(s) do not hold:", unmet.len());
            for reason in &unmet {
                println!("  UNMET: {reason}");
            }
        }
        // The measurement must be doing work. `unmet_user_side_exit_terms`
        // reads six real files; if any of them stopped containing the code
        // these terms are about, that is a finding and not a pass.
        let commands = shipped_source(include_str!(
            "../../wallet-tauri-common/src/agent_commands.rs"
        ));
        assert!(
            commands.contains("#[tauri::command]"),
            "the tripwire is reading a file that no longer holds Tauri commands, so its terms \
             are measuring nothing"
        );
    }

    /// Everything in a source file that a build actually ships: no comments of
    /// any kind, no string or character literals, and nothing from the first
    /// test-only `cfg` onwards.
    ///
    /// # Why each of these is here
    ///
    /// A reviewer reimplemented every term of this tripwire against mutated
    /// copies of the six real files, deleted the capability from all six, left
    /// only prose and dead code behind, and got every assertion to pass. Each
    /// clause below closes one of the routes they took, and the companion test
    /// `prose_dead_code_and_disabled_cfgs_do_not_satisfy_the_tripwire` drives
    /// all of them.
    ///
    /// * **Line comments.** Was the only filter. `// sign_exact_registry_exit`
    ///   satisfied any term that read a raw file.
    /// * **Block comments.** `/* ... */` was not filtered at all, so the same
    ///   sentence in different punctuation walked straight through the
    ///   narrowing that was supposed to stop it.
    /// * **String and character literals.** A term looking for a symbol is
    ///   asking whether the code *does* something. `let _ = "sign_exact_...";`
    ///   does nothing and matched.
    /// * **Test-only `cfg`s.** The split was on the exact literal
    ///   `#[cfg(test)]`, so `#[cfg(all(test, feature = "..."))]` - and any
    ///   `cfg` gated on a feature that is off in the shipped build - was
    ///   treated as shipped code.
    ///
    /// This is deliberately a lexical approximation and not a Rust parser. It
    /// errs towards *removing* text, which is the safe direction: removing too
    /// much can only make a term harder to satisfy, never easier.
    fn shipped_source(source: &str) -> String {
        // Everything from the first test-only `cfg` attribute onwards. Any
        // `cfg` whose predicate names the bare `test` identifier counts, not
        // just the exact literal `#[cfg(test)]`.
        //
        // `test` must be matched as a whole token and outside string literals,
        // and both halves of that are load-bearing rather than fussy. A
        // substring search truncates at
        // `#[cfg(feature = "agent-wallet-testnet-pilot")]` - "testnet"
        // contains "test" - which is the attribute guarding almost every
        // registry command and signing boundary in this workspace. Cutting
        // there silently removed the code every term is about and reported ten
        // capabilities missing that were present. A tripwire that fails closed
        // is right; one that fails closed for the wrong reason teaches people
        // to disbelieve it.
        let mut shipped = source;
        for (index, _) in source.match_indices("#[cfg(") {
            let tail = &source[index..];
            let Some(end) = tail.find(']') else { continue };
            if predicate_names_test(&tail[..end]) {
                shipped = &source[..index];
                break;
            }
        }

        // Strip comments and literals in one pass, so a construct cannot hide
        // inside another. Kept character by character because the alternative
        // is a regex that is wrong about `"//"` or `/* "unterminated */`.
        let bytes: Vec<char> = shipped.chars().collect();
        let mut out = String::with_capacity(shipped.len());
        let mut index = 0usize;
        while index < bytes.len() {
            let rest_is = |needle: &str| shipped_starts_with(&bytes, index, needle);
            if rest_is("//") {
                while index < bytes.len() && bytes[index] != '\n' {
                    index += 1;
                }
            } else if rest_is("/*") {
                index += 2;
                let mut depth = 1usize;
                while index < bytes.len() && depth > 0 {
                    if shipped_starts_with(&bytes, index, "/*") {
                        depth += 1;
                        index += 2;
                    } else if shipped_starts_with(&bytes, index, "*/") {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                // A comment separated two tokens; it must not join them.
                out.push(' ');
            } else if bytes[index] == '"' {
                index += 1;
                while index < bytes.len() && bytes[index] != '"' {
                    index += if bytes[index] == '\\' { 2 } else { 1 };
                }
                index += 1;
                out.push_str("\"\"");
            } else if bytes[index] == '\'' {
                // A lifetime is not a literal, and must survive.
                let closes = (1..=4).any(|ahead| {
                    bytes
                        .get(index + ahead)
                        .is_some_and(|character| *character == '\'')
                });
                if closes {
                    index += 1;
                    while index < bytes.len() && bytes[index] != '\'' {
                        index += if bytes[index] == '\\' { 2 } else { 1 };
                    }
                    index += 1;
                    out.push_str("''");
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        out
    }

    /// Whether a `cfg` predicate names the bare `test` identifier.
    ///
    /// Identifiers are taken outside string literals, so a *feature* called
    /// `agent-wallet-testnet-pilot` is not a test gate and neither is one
    /// called `test-utils`.
    fn predicate_names_test(predicate: &str) -> bool {
        // `any(test, ...)` is not a test-only gate: the code ships whenever any
        // other disjunct holds. `#[cfg(any(test, feature =
        // "agent-wallet-testnet-pilot"))]` guards the registry signing methods
        // themselves, and treating it as test-only cut all three of them out
        // of the shipped source and reported the wallet unable to sign.
        //
        // So disjunctions are removed before the bare `test` is looked for,
        // which leaves `#[cfg(test)]` and `#[cfg(all(test, ...))]` - the two
        // shapes that really do mean "not in a shipped build".
        let mut required = String::with_capacity(predicate.len());
        let mut rest = predicate;
        while let Some(at) = rest.find("any(") {
            required.push_str(&rest[..at]);
            let mut depth = 0usize;
            let mut end = None;
            for (offset, character) in rest[at + 3..].char_indices() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(at + 3 + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            match end {
                Some(end) => rest = &rest[end..],
                None => {
                    rest = "";
                    break;
                }
            }
        }
        required.push_str(rest);

        let mut identifier = String::new();
        let mut in_string = false;
        let mut names_test = false;
        for character in required.chars() {
            if character == '"' {
                in_string = !in_string;
                identifier.clear();
                continue;
            }
            if in_string {
                continue;
            }
            if character.is_alphanumeric() || character == '_' {
                identifier.push(character);
            } else {
                names_test |= identifier == "test";
                identifier.clear();
            }
        }
        names_test | (identifier == "test")
    }

    /// Whether `needle` begins at `index` in an already-decoded source.
    fn shipped_starts_with(source: &[char], index: usize, needle: &str) -> bool {
        needle
            .chars()
            .enumerate()
            .all(|(offset, character)| source.get(index + offset) == Some(&character))
    }

    /// The same narrowing for TypeScript: comments go, string literals stay.
    ///
    /// The renderer terms ask whether a command *name* appears in an `invoke`
    /// call, and that name is a string. Deleting literals the way the Rust
    /// narrowing does would make those terms unsatisfiable rather than
    /// unforgeable, so only comments are removed here. That is weaker than the
    /// Rust narrowing and deliberately so: a reviewer forged these terms with
    /// `/* invoke("...") is planned for a later release */`, which this stops,
    /// and the term that a real screen calls the wrapper is what carries the
    /// rest of the weight.
    fn shipped_typescript(source: &str) -> String {
        let characters: Vec<char> = source.chars().collect();
        let mut out = String::with_capacity(source.len());
        let mut index = 0usize;
        while index < characters.len() {
            if shipped_starts_with(&characters, index, "//") {
                while index < characters.len() && characters[index] != '\n' {
                    index += 1;
                }
            } else if shipped_starts_with(&characters, index, "/*") {
                index += 2;
                while index < characters.len() && !shipped_starts_with(&characters, index, "*/") {
                    index += 1;
                }
                index += 2;
                out.push(' ');
            } else {
                out.push(characters[index]);
                index += 1;
            }
        }
        out
    }

    /// The same narrowing for a TOML file, where a comment starts with `#`.
    ///
    /// The capability allowlist is TOML, and it was read completely raw: not
    /// even the line-comment filter ran on it, so four commented-out entries
    /// satisfied the term that says the desktop permits them.
    fn shipped_toml(source: &str) -> String {
        source
            .lines()
            .map(|line| match line.find('#') {
                // Only a `#` outside a string starts a comment. Counting quotes
                // before it is enough for an allowlist of quoted names.
                Some(at) if line[..at].matches('"').count() % 2 == 0 => &line[..at],
                _ => line,
            })
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

    /// Every route a reviewer actually used to forge this tripwire.
    ///
    /// The test above checked one pattern, for one term, against `//` and a
    /// bare `#[cfg(test)]`. A reviewer then reimplemented all of the terms
    /// against mutated copies of the six real files, deleted the capability
    /// from every one of them, and got 19 of 19 assertions to pass over source
    /// in which nothing worked. Each case below is one of the shapes they
    /// used. They are unit tests of the narrowing rather than of the terms,
    /// because the narrowing is the thing every term shares.
    #[test]
    fn prose_dead_code_and_disabled_cfgs_do_not_satisfy_the_tripwire() {
        // A line comment, which was the only case ever covered.
        assert!(
            !shipped_source("// sign_exact_registry_exit\n").contains("sign_exact_registry_exit")
        );

        // A block comment, which was not filtered at all.
        assert!(
            !shipped_source("/* the driver is reached at m.advance_hvm_registry_exit(w) */")
                .contains(".advance_hvm_registry_exit("),
            "a block comment still satisfies a caller term"
        );
        // Including a multi-line one, and one that nests.
        assert!(
            !shipped_source("/*\n .fund_hvm_registry_channel(\n /* .adopt_x( */\n */")
                .contains(".fund_hvm_registry_channel("),
            "a multi-line or nested block comment still satisfies a caller term"
        );

        // A string literal, which is a mention and not a call.
        assert!(
            !shipped_source("fn f() { let _ = \"sign_exact_registry_funding(\"; }")
                .contains("sign_exact_registry_funding("),
            "a string literal still satisfies a signing-boundary term"
        );

        // A `cfg` that is gated on `test` but is not the exact literal the
        // split used to look for.
        assert!(
            !shipped_source(
                "#[cfg(all(test, feature = \"never-enabled\"))]\nmod m { fn t() { \
                 m.adopt_hvm_registry_channel_from_chain(w); } }"
            )
            .contains(".adopt_hvm_registry_channel_from_chain("),
            "a test module behind a compound cfg is still treated as shipped code"
        );

        // ...but a feature whose *name* merely contains "test" is not a test
        // gate. `agent-wallet-testnet-pilot` guards nearly every registry
        // command and signing boundary in this workspace, and treating it as
        // one truncated every file at its first use and reported ten present
        // capabilities as missing.
        assert!(
            shipped_source(
                "#[cfg(feature = \"agent-wallet-testnet-pilot\")]\npub async fn f() { \
                 m.fund_hvm_registry_channel(w); }"
            )
            .contains(".fund_hvm_registry_channel("),
            "a feature name containing `test` was mistaken for a test gate, which cuts the \
             shipped code every term is about"
        );
        assert!(
            !predicate_names_test("#[cfg(feature = \"agent-wallet-testnet-pilot\")"),
            "`testnet` inside a feature name is not the `test` cfg"
        );
        assert!(
            predicate_names_test("#[cfg(test)"),
            "the bare test cfg must be recognised"
        );
        assert!(
            predicate_names_test("#[cfg(all(test, feature = \"x\"))"),
            "a compound test cfg must be recognised"
        );
        // `any(test, ...)` ships whenever another disjunct holds, and it is
        // what guards the registry signing methods themselves.
        assert!(
            !predicate_names_test("#[cfg(any(test, feature = \"agent-wallet-testnet-pilot\"))"),
            "`any(test, ...)` is not a test-only gate and cutting there removes shipped code"
        );
        assert!(
            shipped_source(
                "#[cfg(any(test, feature = \"agent-wallet-testnet-pilot\"))]\n\
                 pub(crate) fn sign_exact_registry_exit() {}"
            )
            .contains("fn sign_exact_registry_exit("),
            "an `any(test, feature)` gate hid a real signing boundary from its own term"
        );

        // The narrowing must not eat code it should keep: a lifetime is not a
        // character literal, and the term that reads a chain-evidence
        // parameter depends on one surviving.
        assert!(
            shipped_source("fn f(chain: &HvmRegistryOpenChainEvidenceV1<'_>,) {}")
                .contains("chain: &HvmRegistryOpenChainEvidenceV1<'_>,"),
            "the narrowing ate a lifetime, which would make a real term unsatisfiable"
        );

        // TOML comments, over an allowlist that was read completely raw.
        assert!(
            !shipped_toml("# \"agent_wallet_start_hvm_registry_exit\",")
                .contains("\"agent_wallet_start_hvm_registry_exit\""),
            "a commented-out allowlist entry still satisfies the permission term"
        );
        assert!(
            shipped_toml("  \"agent_wallet_start_hvm_registry_exit\", # kept")
                .contains("\"agent_wallet_start_hvm_registry_exit\""),
            "the TOML narrowing ate a real allowlist entry"
        );

        // TypeScript comments, over a renderer that invokes nothing.
        assert!(
            !shipped_typescript(
                "/* invoke(\"agent_wallet_start_hvm_registry_exit\", { walletId }) later */"
            )
            .contains("(\"agent_wallet_start_hvm_registry_exit\","),
            "a commented-out invoke still satisfies the renderer term"
        );
        assert!(
            shipped_typescript("invoke(\"agent_wallet_start_hvm_registry_exit\", { walletId });")
                .contains("(\"agent_wallet_start_hvm_registry_exit\","),
            "the TypeScript narrowing ate a real invoke"
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
    measure_node_reported_unilateral_exit(capabilities)
        && measure_user_side_unilateral_exit_ready()
        && measure_offline_user_defended()
}

/// Whether a user who is **asleep** is defended, which is a different question
/// from whether an awake one can leave.
///
/// The exit answers the provider that stops answering. It does not answer the
/// provider that acts while the owner is offline: a settlement can be started
/// and finished without them, and nothing here presses `finalize` or `claim`
/// on their behalf either.
///
/// # What this is NOT, because this comment used to get it backwards
///
/// It used to say a stale receipt settling costs the sleeping owner the
/// difference, and cited "300,000 zhu from a channel owing 900,000". No such
/// measurement exists, and the direction is wrong on the rail this build
/// ships. `HvmRegistryBindingV2::validate` refuses any binding with
/// `right_hub_deposit_zhu != 0`, and the bill ledger only ever subtracts from
/// the left balance, so every later bill pays the left party strictly LESS and
/// a stale one pays them MORE. Answering a stale challenge hands money back:
/// `decide_user_exit_action` returns `finish_whatever_is_standing` rather than
/// responding, and `registry_response_watch` refuses to sign the response at
/// all. The real measurement, in
/// `tests/registry_response_watch.rs::a_response_that_would_cost_the_user_money_is_refused`,
/// is a 1,000,000 zhu channel whose head bill pays 300,000 while the stale
/// challenge owes 950,000: a dutiful watcher cost its own user 650,000 zhu.
///
/// So the exposure this term names is not stolen principal. It is that the
/// ending does not happen by itself, and that the protection above is a
/// property of those two checks rather than of the protocol. Change either and
/// the stale-receipt attack becomes real, which is the reason this stays false
/// rather than being deleted as solved.
///
/// This is its own term because the two used to be one. Lifting the user-side
/// driver constant satisfied `l1_dispute_path_ready` and, through it, published
/// `trustless_finality` — while the sleeping owner was exactly as exposed as
/// before. Five readiness tests caught it the moment the constant moved, which
/// is what they are for.
///
/// It is **false**, and not as a placeholder. The owner chose disclosure and a
/// bounded amount over running watchtowers, so this gap is disclosed in the
/// consent the owner ticks rather than closed in the protocol. That is a
/// legitimate product decision and it is not trustless finality, so this
/// refuses to call it that.
///
/// What would make it true: a response watcher attested for this deployment, so
/// somebody answers the window while the owner sleeps. The watcher exists
/// (`hpay-registry-response-watch`) and is not wired to a readiness attestation,
/// because nobody has been asked to run one. When that exists, this reads it —
/// it does not become another constant somebody sets by hand.
pub const fn measure_offline_user_defended() -> bool {
    false
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

    /// A Hub must not start while advertising a channel it can never fund.
    ///
    /// This is the configuration the shipped binary default produces: the
    /// aggregate flag defaults to 100_000_000 zhu (1 HAC, character-for-
    /// character the per-PAYMENT hard maximum) while the operator doc has them
    /// set the channel cap to 1_000_000_000 (10 HAC). Readiness then published
    /// a 10 HAC channel cap next to a 1 HAC aggregate cap, and the first
    /// channel over 1 HAC was refused at admission by a Hub whose own
    /// published channel cap said it was fine.
    ///
    /// The fix is a refusal, not a raised cap: the aggregate default stays
    /// exactly where it is, and an operator who wants a small aggregate gets
    /// it by lowering the channel cap to match.
    #[test]
    fn a_hub_that_cannot_fund_its_published_channel_cap_refuses_to_start() {
        let shipped_default_aggregate = 100_000_000;
        let policy = MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            shipped_default_aggregate,
        )
        .unwrap();

        let error = policy
            .require_can_fund_channel_cap(MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU)
            .expect_err("an incoherent pair must refuse startup");
        let text = error.to_string();
        // Name both numbers and both remedies, so the operator can act.
        assert!(text.contains("100000000"), "{text}");
        assert!(text.contains("1000000000"), "{text}");
        assert!(
            text.contains("--mainnet-max-aggregate-tvl-hac-zhu"),
            "{text}"
        );
        assert!(
            text.contains("--mainnet-max-channel-funding-hac-zhu"),
            "{text}"
        );

        // Coherent pairs still start, including equality and the configuration
        // the operator doc and install.sh actually prescribe.
        policy
            .require_can_fund_channel_cap(shipped_default_aggregate)
            .expect("aggregate equal to the channel cap is coherent");
        MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        )
        .unwrap()
        .require_can_fund_channel_cap(MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU)
        .expect("the documented pilot configuration must still start");
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
                .any(|it| it == "no_watcher_answers_for_an_offline_owner")
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
        // The driver ships now, and this test's point survives that: a
        // perfect node report is still not a unilateral exit. What holds it is
        // the term below rather than the one above, and asserting both is what
        // keeps this honest the next time one of them moves.
        assert!(
            measure_user_side_unilateral_exit_ready(),
            "the wallet-side exit driver ships and is proven on chain"
        );
        assert!(
            !measure_offline_user_defended(),
            "an owner who is offline is still undefended, so this is not finality"
        );
        assert!(
            !measure_l1_dispute_path_ready(Some(&node)),
            "a fully green fullnode plus a shipped driver is still not a dispute path"
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
            readiness
                .blockers
                .iter()
                .any(|blocker| { blocker == "no_watcher_answers_for_an_offline_owner" }),
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

    /// The bounded pilot may waive the gate. It may not waive the sentence.
    ///
    /// This is the exact document the live mainnet Hub serves, and before this
    /// it went out as `"blockers":[],"close_blockers":[]` while the largest way
    /// to lose money on this system was outstanding: a provider that settles an
    /// old receipt during the objection window while the owner is offline. The
    /// waiver itself is correct and deliberately unchanged here - putting the
    /// identifier back into `blockers` would set `payments_enabled` false and
    /// wedge the profile that exists to allow bounded mainnet payments. What
    /// was wrong was that waiving the gate deleted the only outward sign the
    /// condition existed, so a green list and a genuinely clean Hub were
    /// indistinguishable on the wire.
    ///
    /// Every assertion below is therefore paired: the gate still opens, and
    /// the document still says what it opened over.
    #[test]
    fn the_bounded_pilot_publishes_the_offline_owner_gap_it_declines_to_gate_on() {
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
        let policy = MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        )
        .unwrap();
        readiness.apply_mainnet_admission(&policy, Ok(0));

        // The waiver, untouched: this is the fully admitted bounded pilot and
        // both gates are open. If either of these ever fails, the fix has
        // started blocking money instead of describing it.
        assert!(readiness.payments_enabled, "{:?}", readiness.blockers);
        assert!(readiness.close_enabled, "{:?}", readiness.close_blockers);
        assert!(readiness.blockers.is_empty(), "{:?}", readiness.blockers);
        assert!(
            readiness.close_blockers.is_empty(),
            "{:?}",
            readiness.close_blockers
        );

        // And the disclosure, which is the thing that did not exist.
        assert!(
            readiness
                .disclosed_blockers
                .iter()
                .any(|it| it == OFFLINE_OWNER_UNDEFENDED_BLOCKER),
            "an empty blocker list on this profile must not be the whole document, got {:?}",
            readiness.disclosed_blockers
        );
        assert!(
            readiness
                .disclosed_blockers
                .iter()
                .any(|it| it == UNILATERAL_DISPUTE_PATH_BLOCKER),
            "{:?}",
            readiness.disclosed_blockers
        );
        assert!(
            readiness
                .disclosed_blockers
                .iter()
                .any(|it| it == EXTERNAL_ROLLBACK_ANCHOR_BLOCKER),
            "the anchor waiver is disclosed on the same terms, got {:?}",
            readiness.disclosed_blockers
        );

        // Disjoint, so the union is the whole outstanding set and a reader can
        // rely on that rather than on a comment.
        for disclosed in &readiness.disclosed_blockers {
            assert!(
                !readiness.blockers.contains(disclosed),
                "{disclosed} is in both lists, so the union no longer means anything"
            );
        }

        // The same fact in words, because an identifier nobody can expand is
        // only marginally better than an empty list.
        let spelled_out = readiness
            .limitations
            .iter()
            .find(|it| it.contains(OFFLINE_OWNER_UNDEFENDED_BLOCKER))
            .unwrap_or_else(|| panic!("{:?}", readiness.limitations));
        assert!(spelled_out.contains("offline"));
        // And in the right DIRECTION. The first version of this sentence said
        // a stale settlement takes the difference from a sleeping owner, which
        // is backwards here: a non-zero hub deposit is refused at binding
        // validation and the ledger only subtracts from the left balance, so a
        // stale split pays the left party more and the driver declines to
        // answer it. Disclosing a loss that cannot happen on this rail is not
        // a safe error - it teaches an owner to distrust the disclosures that
        // are real, and it hides the exposure that actually exists.
        assert!(
            spelled_out.contains("cannot cost them principal"),
            "the disclosure must not invert the direction of the money: {spelled_out}"
        );
        assert!(
            spelled_out.contains("nothing finalizes or claims for them"),
            "the exposure that IS real must be named: {spelled_out}"
        );
        assert!(
            spelled_out.contains("rather than on the protocol"),
            "the protection is a property of two checks and must not read as a guarantee: \
             {spelled_out}"
        );

        // It survives serialisation, which is the only place any of this is
        // read from.
        let wire = serde_json::to_value(&readiness).unwrap();
        assert_eq!(wire["blockers"].as_array().unwrap().len(), 0);
        assert!(
            wire["disclosed_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|it| it == OFFLINE_OWNER_UNDEFENDED_BLOCKER),
            "{wire}"
        );
    }

    /// The full mainnet pilot profile is unchanged by the disclosure work.
    ///
    /// It never waived the dispute-path gate, so the identifier belongs in
    /// `blockers` there and must not be duplicated into the disclosure list -
    /// otherwise "outstanding" would be counted twice and the disjointness the
    /// field doc promises would be a lie on the profile that matters most.
    #[test]
    fn the_full_pilot_still_blocks_rather_than_discloses() {
        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            Some(&anchor_evidence(crate::node::now_unix())),
            true,
            Ok(capabilities()),
        );
        assert!(
            readiness
                .blockers
                .iter()
                .any(|it| it == OFFLINE_OWNER_UNDEFENDED_BLOCKER)
        );
        assert!(
            !readiness
                .disclosed_blockers
                .iter()
                .any(|it| it == OFFLINE_OWNER_UNDEFENDED_BLOCKER),
            "already visible in blockers, so disclosing it again breaks disjointness"
        );
        // Still not close-blocking. That was true before and stays true.
        assert!(readiness.close_enabled);
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
            !measure_offline_user_defended(),
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
        // still false with a perfect anchor, a perfect fullnode AND a shipped
        // exit driver, because an owner who is offline when a stale receipt
        // lands is still undefended. That is a different missing part from the
        // one this comment used to name, and naming the wrong one would be the
        // same wrong guarantee in a friendlier voice.
        assert!(!with.trustless_finality);
        assert!(!with.unilateral_l1_enforceable);
        assert!(
            with.blockers
                .iter()
                .any(|it| it == "no_watcher_answers_for_an_offline_owner")
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
