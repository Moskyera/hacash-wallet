//! Authoritative, short-lived mainnet-pilot gate for the official Hacash
//! ChannelPay-compatible money path.

use serde::{Deserialize, Serialize};

use crate::amount::HacAmount;
use crate::error::{HubError, HubResult};
use crate::node::{
    ACTION_COOPERATIVE_ORIGINAL_CLOSE, FullnodeCapabilitiesV1, HACASH_MAINNET_MIN_SAFE_HEIGHT,
};

pub const READINESS_SCHEMA: &str = "hpay-fast-pay-mainnet-readiness/1";
pub const MAINNET_PILOT_PROFILE: &str = "mainnet-pilot";
pub const MAINNET_PILOT_HARD_MAX_HAC_ZHU: u64 = 100_000_000;
pub const ZHU_PER_MILLIMEI: u64 = 100_000;
const READINESS_VALID_SECONDS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainnetReadinessV1 {
    pub schema: &'static str,
    pub evaluated_unix: u64,
    pub valid_until_unix: u64,
    pub profile: String,
    pub payments_enabled: bool,
    pub mainnet_detected: Option<bool>,
    pub fullnode_capabilities: Option<FullnodeCapabilitiesV1>,
    pub max_payment_hac_zhu: u64,
    pub max_channel_funding_hac_zhu: u64,
    pub max_payment_satoshi: u64,
    pub wallet_fee_hac: &'static str,
    pub trustless_finality: bool,
    pub unilateral_l1_enforceable: bool,
    pub settlement_model: &'static str,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

impl MainnetReadinessV1 {
    pub fn evaluate(
        profile: &str,
        max_payment_hac_zhu: u64,
        max_channel_funding_hac_zhu: u64,
        hub_operational_ready: bool,
        capabilities: Result<FullnodeCapabilitiesV1, HubError>,
    ) -> Self {
        let mut blockers = Vec::new();
        if !hub_operational_ready {
            blockers.push("hub_signer_authenticated_storage_or_recovery_gate_is_not_ready".into());
        }
        let is_mainnet_pilot = profile == MAINNET_PILOT_PROFILE;
        if is_mainnet_pilot {
            validate_cap(max_payment_hac_zhu, "mainnet payment cap", &mut blockers);
            validate_cap(
                max_channel_funding_hac_zhu,
                "mainnet channel-funding cap",
                &mut blockers,
            );
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
                    if !capabilities.action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE) {
                        blockers
                            .push("fullnode_missing_required_cooperative_close_action_3".into());
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

        Self {
            schema: READINESS_SCHEMA,
            evaluated_unix,
            valid_until_unix: evaluated_unix.saturating_add(READINESS_VALID_SECONDS),
            profile: profile.to_string(),
            payments_enabled: blockers.is_empty(),
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
            max_payment_satoshi: 0,
            wallet_fee_hac: "0",
            trustless_finality: false,
            unilateral_l1_enforceable: false,
            settlement_model: "official Hacash ChannelPay bills with hub-coordinated bounded mainnet pilot",
            blockers,
            limitations: vec![
                "settled does not mean unilateral L1 finality".into(),
                "the active Hacash mainnet exposes cooperative original-funding close action 3"
                    .into(),
                "pilot exposure must remain inside the configured payment and channel caps".into(),
            ],
        }
    }

    pub fn require_payment_ready(&self, amount: HacAmount) -> HubResult<()> {
        if self.schema != READINESS_SCHEMA
            || self.profile != MAINNET_PILOT_PROFILE
            || !self.payments_enabled
            || self.mainnet_detected != Some(true)
            || !self.blockers.is_empty()
            || self.wallet_fee_hac != "0"
        {
            return Err(HubError::State(format!(
                "mainnet payment gate blocked: {}",
                self.blockers.join("; ")
            )));
        }
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
        if crate::node::now_unix() > self.valid_until_unix {
            return Err(HubError::State(
                "mainnet readiness expired before signing".into(),
            ));
        }
        Ok(())
    }
}

fn validate_cap(cap: u64, label: &str, blockers: &mut Vec<String>) {
    if !(ZHU_PER_MILLIMEI..=MAINNET_PILOT_HARD_MAX_HAC_ZHU).contains(&cap) {
        blockers.push(format!(
            "{label} must be between {ZHU_PER_MILLIMEI} and {MAINNET_PILOT_HARD_MAX_HAC_ZHU} zhu"
        ));
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
            tip_timestamp_unix: now,
            tip_age_seconds: 0,
            registered_actions: vec![1, 2, 3],
            enabled_actions: vec![1, 2, 3],
        }
    }

    #[test]
    fn mainnet_pilot_is_capped_and_explicitly_fee_free() {
        let readiness = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            100_000_000,
            100_000_000,
            true,
            Ok(capabilities()),
        );
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
    }

    #[test]
    fn development_and_missing_capability_fail_closed() {
        let development =
            MainnetReadinessV1::evaluate("development", 0, 0, false, Ok(capabilities()));
        assert!(!development.payments_enabled);

        let operational_stop = MainnetReadinessV1::evaluate(
            MAINNET_PILOT_PROFILE,
            100_000_000,
            100_000_000,
            false,
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
            100_000_000,
            100_000_000,
            true,
            Err(HubError::Node("offline".into())),
        );
        assert!(!missing.payments_enabled);
    }
}
