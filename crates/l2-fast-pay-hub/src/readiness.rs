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
    /// measured from, and is published verbatim. Passing `None` alongside a
    /// `true` flag is not expressible in the Hub - both come from one
    /// `HubHardGuarantees::measure` call over one probe - and `None` alongside
    /// `false` is the ordinary "no witness" case.
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
                    if profile == MAINNET_PILOT_PROFILE
                        && (!capabilities.channel_unilateral_exit
                            || !capabilities
                                .channel_unilateral_exit_evidence
                                .as_ref()
                                .is_some_and(
                                    crate::node::ChannelUnilateralExitEvidence::is_verified_mainnet_deployment,
                                ))
                    {
                        blockers.push(
                            "fullnode_does_not_report_verified_channel_unilateral_exit".into(),
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
                    && blocker.as_str()
                        != "fullnode_does_not_report_verified_channel_unilateral_exit"
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

/// Measured readiness of the unilateral L1 dispute path.
///
/// True only when the connected fullnode both advertises the native
/// unilateral-exit capability *and* carries evidence of an exactly verified
/// mainnet deployment of the reviewed exit contract. Missing capabilities (an
/// unreachable or unparseable node), a `false` capability flag, or evidence
/// that fails `validate_candidate` each read `false`.
pub fn measure_l1_dispute_path_ready(capabilities: Option<&FullnodeCapabilitiesV1>) -> bool {
    capabilities.is_some_and(|capabilities| {
        capabilities.channel_unilateral_exit
            && capabilities
                .channel_unilateral_exit_evidence
                .as_ref()
                .is_some_and(
                    crate::node::ChannelUnilateralExitEvidence::is_verified_mainnet_deployment,
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
        }
    }

    #[test]
    fn mainnet_pilot_is_capped_and_explicitly_fee_free() {
        let mut readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            None,
            true,
            Ok(capabilities()),
        );
        assert!(!readiness.payments_enabled);
        let policy = MainnetPilotAdmissionPolicy::try_new(
            ["1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW"],
            MAINNET_PILOT_MAX_AGGREGATE_TVL_HAC_ZHU,
        )
        .unwrap();
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
        node.channel_unilateral_exit = false;
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
            blocker == "fullnode_does_not_report_verified_channel_unilateral_exit"
        }));

        let mut missing_evidence = capabilities();
        missing_evidence.channel_unilateral_exit_evidence = None;
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
            blocker == "fullnode_does_not_report_verified_channel_unilateral_exit"
        }));
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

    /// The dispute-path flag must follow the node's evidence in both
    /// directions, otherwise it is not a measurement.
    #[test]
    fn the_dispute_path_flag_tracks_node_evidence_in_both_directions() {
        assert!(
            measure_l1_dispute_path_ready(Some(&capabilities())),
            "verified evidence is present, so the measurement must be true"
        );
        assert!(
            !measure_l1_dispute_path_ready(None),
            "an unprobeable fullnode proves nothing"
        );

        let mut withdrawn = capabilities();
        withdrawn.channel_unilateral_exit = false;
        assert!(!measure_l1_dispute_path_ready(Some(&withdrawn)));

        let mut no_evidence = capabilities();
        no_evidence.channel_unilateral_exit_evidence = None;
        assert!(!measure_l1_dispute_path_ready(Some(&no_evidence)));

        let mut unverified = capabilities();
        if let Some(evidence) = unverified.channel_unilateral_exit_evidence.as_mut() {
            evidence.deployment_verified = false;
        }
        assert!(
            !measure_l1_dispute_path_ready(Some(&unverified)),
            "evidence that fails validation must not count"
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
        assert!(best_available.l1_dispute_path_ready);
        assert!(!best_available.external_rollback_anchor_ready);
        assert!(
            !best_available.production_mainnet_ready,
            "the missing anchor alone must hold the strongest claim false"
        );

        assert!(
            HubHardGuarantees::measure(
                MAINNET_PILOT_PROFILE,
                true,
                Some(&capabilities()),
                Some(&anchor),
                now
            )
            .production_mainnet_ready,
            "with every part present, including a live witness, the claim must be reachable"
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

        let with = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU,
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU,
            true,
            true,
            None,
            true,
            Ok(capabilities()),
        );
        assert!(with.trustless_finality);
        assert!(!with.blockers.iter().any(|it| it == anchor_blocker));
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
