//! Background lease maintenance for every activated HVM channel.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};
use crate::hvm_registry_watchtower::{
    HvmRegistryChainResponseV2, HvmRegistryWatchtowerSituationV2,
};
use crate::hvm_watchtower::{HVM_LEASE_RENEWAL_MAX_PERIODS, HvmWatchtowerResponseV1};
use crate::state::HubState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmLeaseSchedulerConfig {
    pub interval_seconds: u64,
    pub renew_when_live_blocks_at_or_below: u64,
    pub periods: u64,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmLeaseMaintenanceResult {
    pub binding_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HvmWatchtowerResponseV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryLeaseMaintenanceResult {
    pub binding_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HvmRegistryChainResponseV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryWatchtowerMaintenanceResult {
    pub binding_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HvmRegistryChainResponseV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HvmLeaseSchedulerConfig {
    pub fn validate(&self) -> HubResult<()> {
        if self.interval_seconds < 60
            || self.renew_when_live_blocks_at_or_below == 0
            || self.periods == 0
            || self.periods > HVM_LEASE_RENEWAL_MAX_PERIODS
            || self.network_fee_zhu == 0
            || self.gas_max == 0
        {
            return Err(HubError::State(
                "HVM lease scheduler configuration is unsafe".into(),
            ));
        }
        Ok(())
    }
}

pub async fn run_hvm_lease_scheduler(hub: Arc<HubState>, config: HvmLeaseSchedulerConfig) {
    if let Err(error) = config.validate() {
        tracing::error!(error = %error, "HVM lease scheduler disabled");
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match hub.hvm_lease_maintenance_tick(&config).await {
            Ok(results) => {
                for result in results {
                    match result.response {
                        Some(response) => tracing::info!(
                            binding_commitment = %result.binding_commitment,
                            operation_id = %response.operation_id,
                            status = %response.status,
                            "HVM lease maintenance"
                        ),
                        None => tracing::error!(
                            binding_commitment = %result.binding_commitment,
                            error = %result.error.unwrap_or_else(|| "unknown error".into()),
                            "HVM lease maintenance channel failed closed"
                        ),
                    }
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "HVM lease maintenance tick failed closed");
            }
        }
        match hub.hvm_registry_lease_maintenance_tick(&config).await {
            Ok(results) => {
                for result in results {
                    match result.response {
                        Some(response) => tracing::info!(
                            binding_commitment = %result.binding_commitment,
                            operation_id = %response.operation_id,
                            status = %response.status,
                            "shared HVM registry lease maintenance"
                        ),
                        None => tracing::error!(
                            binding_commitment = %result.binding_commitment,
                            error = %result.error.unwrap_or_else(|| "unknown error".into()),
                            "shared HVM registry lease maintenance failed closed"
                        ),
                    }
                }
            }
            Err(error) => tracing::error!(
                error = %error,
                "shared HVM registry lease maintenance tick failed closed"
            ),
        }
        // The registry watchtower rides the same tick as the two lease ticks
        // above. It needs no loop of its own: it is the same cadence, the same
        // fail-closed shape, and one channel refusing or erroring is recorded
        // against that channel while the rest of the pass continues.
        match hub.hvm_registry_watchtower_tick(&config).await {
            Ok(results) => {
                for result in results {
                    match result.response {
                        Some(response) => tracing::info!(
                            binding_commitment = %result.binding_commitment,
                            operation_id = %response.operation_id,
                            status = %response.status,
                            action = %response.action,
                            "shared HVM registry watchtower"
                        ),
                        None => tracing::error!(
                            binding_commitment = %result.binding_commitment,
                            error = %result.error.unwrap_or_else(|| "unknown error".into()),
                            "shared HVM registry watchtower channel failed closed"
                        ),
                    }
                }
            }
            Err(error) => tracing::error!(
                error = %error,
                "shared HVM registry watchtower tick failed closed"
            ),
        }
    }
}

pub(crate) fn operation_identity(binding_commitment: &str, unix: u64) -> (String, String) {
    let window = unix / 60;
    (
        format!("hvm-lease-{binding_commitment}-{window}"),
        format!("hvm-lease-idem-{binding_commitment}-{window}"),
    )
}

pub(crate) fn registry_operation_identity(binding_commitment: &str, unix: u64) -> (String, String) {
    let window = unix / 60;
    (
        format!("hvm-registry-lease-{binding_commitment}-{window}"),
        format!("hvm-registry-lease-idem-{binding_commitment}-{window}"),
    )
}

/// Everything the watchtower tick creates carries this prefix, and nothing
/// else does. It is how the tick tells the operations it owns from the ones a
/// human opened at the CLI: the tick drives its own to completion and refuses
/// to touch anybody else's.
pub const HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX: &str = "hvm-registry-watchtower-";
pub const HVM_REGISTRY_WATCHTOWER_IDEMPOTENCY_PREFIX: &str = "hvm-registry-watchtower-idem-";

/// Name an operation after the situation that calls for it.
///
/// The CLI takes a human-typed label; a scheduler has none, so the name is
/// derived from the durable facts instead. Two properties are load-bearing and
/// they pull in opposite directions:
///
/// * **A retry of the same situation must be the same operation.** Otherwise
///   the second tick opens a second record, `registry_chain_context` refuses
///   it because the first is still unresolved, and the tower never drives its
///   own in-flight response to confirmation — wedged, with a signed
///   transaction on the wire and nobody reconciling it.
/// * **A genuinely new situation must be a new operation.** Otherwise the tick
///   lands on a finished record, gets its old outcome handed back, and never
///   acts — wedged the other way. Every confirmed watchtower action moves at
///   least one field of the situation (a response moves `chain_serial`, a
///   finalize moves `status`, a claim moves `left_claimed`), so the next step
///   of the lifecycle always gets a fresh name.
pub(crate) fn registry_watchtower_operation_identity(
    binding_commitment: &str,
    situation: &HvmRegistryWatchtowerSituationV2,
) -> (String, String) {
    let digest = situation.digest(binding_commitment);
    (
        format!("{HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX}{digest}"),
        format!("{HVM_REGISTRY_WATCHTOWER_IDEMPOTENCY_PREFIX}{digest}"),
    )
}

pub type HvmLeaseMaintenanceResults = Vec<HvmLeaseMaintenanceResult>;
pub type HvmRegistryLeaseMaintenanceResults = Vec<HvmRegistryLeaseMaintenanceResult>;
pub type HvmRegistryWatchtowerMaintenanceResults = Vec<HvmRegistryWatchtowerMaintenanceResult>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_rejects_busy_loop_invalid_periods_fee_and_gas() {
        let valid = HvmLeaseSchedulerConfig {
            interval_seconds: 60,
            renew_when_live_blocks_at_or_below: 10_000,
            periods: 100,
            network_fee_zhu: 10_000,
            gas_max: u8::MAX,
        };
        valid.validate().unwrap();
        let mut boundary = valid.clone();
        boundary.periods = HVM_LEASE_RENEWAL_MAX_PERIODS;
        boundary.validate().unwrap();
        let mut invalid = valid.clone();
        invalid.interval_seconds = 59;
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.periods = HVM_LEASE_RENEWAL_MAX_PERIODS + 1;
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.network_fee_zhu = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = valid;
        invalid.gas_max = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn operation_identity_is_stable_only_inside_one_minute_window() {
        assert_eq!(operation_identity("aa", 120), operation_identity("aa", 179));
        assert_ne!(operation_identity("aa", 179), operation_identity("aa", 180));
        assert_eq!(
            registry_operation_identity("aa", 120),
            registry_operation_identity("aa", 179)
        );
        assert_ne!(
            operation_identity("aa", 120),
            registry_operation_identity("aa", 120)
        );
    }

    fn situation() -> HvmRegistryWatchtowerSituationV2 {
        HvmRegistryWatchtowerSituationV2 {
            status: 3,
            chain_serial: 0,
            left_balance_zhu: 600_000,
            hub_balance_zhu: 400_000,
            deadline: 900_012,
            left_claimed: false,
            durable_bill_serial: 1,
        }
    }

    /// The lease ticks name themselves after a clock window, which is right
    /// for work that simply repeats. A watchtower operation must not: a
    /// challenge does not restart every minute, and a retry that renames
    /// itself strands the response already on the wire.
    #[test]
    fn watchtower_identity_follows_the_situation_and_not_the_clock() {
        let commitment = "ab".repeat(32);
        let challenged = registry_watchtower_operation_identity(&commitment, &situation());
        assert_eq!(
            challenged,
            registry_watchtower_operation_identity(&commitment, &situation()),
            "the same situation is the same operation, whenever it is ticked"
        );
        assert!(
            challenged
                .0
                .starts_with(HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX)
        );
        assert!(
            challenged
                .1
                .starts_with(HVM_REGISTRY_WATCHTOWER_IDEMPOTENCY_PREFIX)
        );
        assert_ne!(challenged.0, challenged.1);
        assert!(
            challenged.0.len() <= 256 && challenged.1.len() <= 256,
            "the request validator caps both at 256 bytes"
        );

        // Walking the lifecycle: our response confirms, the deadline passes
        // and we finalize, the payout is claimed. Each step is a new name, so
        // each step gets its own operation instead of colliding with the
        // finished one before it.
        let mut responded = situation();
        responded.chain_serial = 1;
        responded.left_balance_zhu = 1_000_000;
        responded.hub_balance_zhu = 0;
        let mut finalized = responded;
        finalized.status = 4;
        let mut claimed = finalized;
        claimed.left_claimed = true;
        let names = [situation(), responded, finalized, claimed]
            .iter()
            .map(|step| registry_watchtower_operation_identity(&commitment, step).0)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 4, "every lifecycle step is its own operation");

        // A different channel in an identical state is a different operation.
        assert_ne!(
            registry_watchtower_operation_identity(&"cd".repeat(32), &situation()),
            challenged
        );
    }
}
