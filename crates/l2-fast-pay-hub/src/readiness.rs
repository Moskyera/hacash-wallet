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
    pub fn evaluate(
        profile: &str,
        max_payment_hac_zhu: u64,
        max_channel_funding_hac_zhu: u64,
        hub_operational_ready: bool,
        external_rollback_anchor_ready: bool,
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
        Self {
            schema: READINESS_SCHEMA,
            evaluated_unix,
            valid_until_unix: evaluated_unix.saturating_add(READINESS_VALID_SECONDS),
            profile: profile.to_string(),
            payments_enabled: blockers.is_empty(),
            close_enabled: close_blockers.is_empty(),
            mainnet_detected,
            fullnode_capabilities,
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
            limitations: vec![
                "settled does not mean unilateral L1 finality".into(),
                "the active Hacash mainnet exposes cooperative original-funding close action 3"
                    .into(),
                "pilot exposure must remain inside the configured payment and channel caps".into(),
            ],
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
/// `docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md`.
///
/// No such subsystem exists in this build. Nothing produces an anchor receipt,
/// so there is no evidence to weigh and the only truthful answer is `false`.
/// This is the measured absence of the anchor, not a policy switch, and it is
/// deliberately unreachable from configuration.
///
/// When the anchor is built this must become a function of a verified,
/// unexpired anchor receipt. It must never become a function of an anchor URL
/// being configured, an operator assertion, or a counter file on this same
/// host: `EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md` rules all three out, and a
/// flag derived from any of them would report a guarantee that does not exist.
pub fn measure_external_rollback_anchor_ready() -> bool {
    false
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
    /// could not be probed, which fails every measurement closed.
    pub fn measure(
        profile: &str,
        hub_operational_ready: bool,
        capabilities: Option<&FullnodeCapabilitiesV1>,
    ) -> Self {
        let external_rollback_anchor_ready = measure_external_rollback_anchor_ready();
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

    #[test]
    fn the_external_anchor_flag_is_false_because_no_anchor_subsystem_exists() {
        assert!(
            !measure_external_rollback_anchor_ready(),
            "no external anchor is implemented, so this must never read true"
        );
    }

    /// `production_mainnet_ready` must be held false by every one of its parts
    /// independently, and the anchor must be enough on its own.
    #[test]
    fn production_mainnet_ready_is_held_false_by_each_missing_part() {
        let best_available =
            HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, true, Some(&capabilities()));
        assert!(best_available.l1_dispute_path_ready);
        assert!(!best_available.external_rollback_anchor_ready);
        assert!(
            !best_available.production_mainnet_ready,
            "the missing anchor alone must hold the strongest claim false"
        );

        assert!(
            !HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, false, Some(&capabilities()))
                .production_mainnet_ready,
            "a Hub that cannot settle is not production ready"
        );
        assert!(
            !HubHardGuarantees::measure("development", true, Some(&capabilities()))
                .production_mainnet_ready,
            "a non-mainnet-pilot profile is not production ready"
        );

        let blind = HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, true, None);
        assert!(!blind.production_mainnet_ready);
        assert!(!blind.l1_dispute_path_ready);

        let mut below_checkpoint = capabilities();
        below_checkpoint.height = HACASH_MAINNET_MIN_SAFE_HEIGHT - 1;
        assert!(
            !HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, true, Some(&below_checkpoint))
                .production_mainnet_ready
        );

        let mut not_mainnet = capabilities();
        not_mainnet.mainnet = false;
        assert!(
            !HubHardGuarantees::measure(MAINNET_PILOT_PROFILE, true, Some(&not_mainnet))
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
            true,
            Ok(capabilities()),
        );
        assert!(with.trustless_finality);
        assert!(!with.blockers.iter().any(|it| it == anchor_blocker));
    }
}
