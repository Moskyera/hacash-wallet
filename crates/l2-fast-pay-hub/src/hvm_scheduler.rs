//! Background lease maintenance for every activated HVM channel.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};
use crate::hvm_registry_watchtower::{
    HvmRegistryChainResponseV2, HvmRegistryWatchtowerSituationV2,
};
use crate::hvm_watchtower::{
    HVM_LEASE_RENEWAL_MAX_PERIODS, HvmWatchtowerResponseV1, HvmWatchtowerSituationV1,
};
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
pub struct HvmWatchtowerMaintenanceResult {
    pub binding_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HvmWatchtowerResponseV1>,
    /// The channel was not evaluated this pass because its one operation slot
    /// is held by a lease renewal this same scheduler loop opened, and here is
    /// which one.
    ///
    /// This is a third outcome rather than an error on purpose, and the reason
    /// was measured rather than guessed. A channel permits exactly one
    /// unresolved chain operation, the lease tick runs first on this loop, and
    /// a renewal stays outstanding for as long as it takes to reach six
    /// confirmations, which was 29, 83 and 48 passes on the three renewals
    /// timed on chain 7. Reporting that as a failed-closed channel would put an
    /// `error!` line in the log on every one of those passes for a Hub that is
    /// working exactly as intended, and an operator who learns to scroll past
    /// this line will scroll past the one that matters.
    ///
    /// A record the *lease tick* did not open is a different thing entirely and
    /// stays an error: that is somebody's hand-opened operation, and the
    /// channel really is unwatched until a person resolves it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_to_lease_operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What one channel's watchtower pass came to.
pub enum HvmWatchtowerPass {
    Evaluated(HvmWatchtowerResponseV1),
    /// Named the lease renewal holding this channel's one operation slot, and
    /// left it strictly alone.
    DeferredToLease(String),
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

/// Does this status mean the pass ended with something an operator has to go
/// and resolve by hand?
///
/// This exists because of how the lease tick used to fail. Before the tick
/// learned to resume the operation it had opened in an earlier clock window, a
/// latched channel came back through the `None` arm of each match below and was
/// recorded at `error!` as "failed closed". Now the tick finds that operation,
/// names it, and returns it as an ordinary response, so the same wedged channel
/// would arrive at the `Some` arm and scroll past at `info!` in exactly the
/// shape of a healthy renewal. Severity therefore has to be read off the status
/// instead of off the shape of the result, or fixing the wedge would have cost
/// the alert that told anyone the wedge was there.
///
/// `recovery_required` is the one status the Hub cannot leave on its own: it is
/// cleared only by `hpay-hvm-local-pilot reconcile`. Every other non-terminal
/// status is a transaction the tick is still legitimately carrying.
fn operation_needs_an_operator(status: &str) -> bool {
    status == crate::storage::HvmChainOperationStatus::RecoveryRequired.as_str()
}

/// How long a transaction may sit `submitted` before the pass says so out loud.
///
/// On this chain a mined transaction reaches six confirmations in minutes, so
/// a quarter of an hour is far past "the next block is taking a while" and well
/// inside the window where a lease still has room to be renewed by hand.
const HVM_SUBMITTED_STALE_SECONDS: u64 = 900;

/// Has this operation been on the wire so long that "still submitted" has
/// stopped being good news?
///
/// A transaction dropped from the mempool and a transaction merely waiting for
/// a block give the fullnode the same answer — not found — so the tick reports
/// `submitted` for both, pass after pass, indefinitely. The durable record has
/// always carried `submitted_unix` and nothing read it, which is how a renewal
/// that will never land came to be indistinguishable from one that is about to.
///
/// This changes no decision and rebroadcasts nothing: a resubmission of signed
/// bytes is `reconcile --allow-exact-resubmit`, and it stays an operator's
/// call. What it does is stop the pass from being quietly reassuring while a
/// lease runs down behind it.
fn submission_has_gone_quiet(status: &str, submitted_unix: Option<u64>, now: u64) -> Option<u64> {
    if status != crate::storage::HvmChainOperationStatus::Submitted.as_str() {
        return None;
    }
    let age = now.checked_sub(submitted_unix?)?;
    (age >= HVM_SUBMITTED_STALE_SECONDS).then_some(age)
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
                        Some(response) if operation_needs_an_operator(&response.status) => {
                            tracing::error!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                "HVM lease maintenance needs an operator; leases stop advancing until this operation is reconciled"
                            )
                        }
                        Some(response)
                            if let Some(age) = submission_has_gone_quiet(
                                &response.status,
                                response.submitted_unix,
                                crate::node::now_unix(),
                            ) =>
                        {
                            tracing::warn!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                transaction_hash = response.transaction_hash.as_deref().unwrap_or(""),
                                submitted_seconds_ago = age,
                                "HVM lease renewal has been outstanding without confirming; the lease is not advancing while this stands"
                            )
                        }
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
        // The v1 watchtower rides the same tick, for the same reasons the
        // registry watchtower does — and because until it did, nothing in an
        // unattended Hub ever called `decide_watchtower_action` on this rail.
        // The claim arm existed, the money was releasable, and no running
        // process would ever reach for it: a person had to build a non-default
        // pilot binary and run it by hand at the right moment. That was the
        // remaining half of the stranded-payout defect.
        match hub.hvm_watchtower_tick(&config).await {
            Ok(results) => {
                for result in results {
                    match result.response {
                        Some(response) if operation_needs_an_operator(&response.status) => {
                            tracing::error!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                action = %response.action,
                                "HVM watchtower needs an operator; this channel is not being watched until the operation is reconciled"
                            )
                        }
                        Some(response)
                            if let Some(age) = submission_has_gone_quiet(
                                &response.status,
                                response.submitted_unix,
                                crate::node::now_unix(),
                            ) =>
                        {
                            tracing::warn!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                action = %response.action,
                                transaction_hash = response.transaction_hash.as_deref().unwrap_or(""),
                                submitted_seconds_ago = age,
                                "HVM watchtower action has been outstanding without confirming; this channel is not being acted on while this stands"
                            )
                        }
                        Some(response) => tracing::info!(
                            binding_commitment = %result.binding_commitment,
                            operation_id = %response.operation_id,
                            status = %response.status,
                            action = %response.action,
                            claim_payee = response.claim_payee.as_deref().unwrap_or(""),
                            claim_amount_zhu = response.claim_amount_zhu.unwrap_or_default(),
                            "HVM watchtower"
                        ),
                        None => match result.deferred_to_lease_operation {
                            Some(lease_operation) => tracing::debug!(
                                binding_commitment = %result.binding_commitment,
                                lease_operation_id = %lease_operation,
                                "HVM watchtower deferred: this channel's one operation slot is held by the lease renewal above"
                            ),
                            None => tracing::error!(
                                binding_commitment = %result.binding_commitment,
                                error = %result.error.unwrap_or_else(|| "unknown error".into()),
                                "HVM watchtower channel failed closed"
                            ),
                        },
                    }
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "HVM watchtower tick failed closed");
            }
        }
        match hub.hvm_registry_lease_maintenance_tick(&config).await {
            Ok(results) => {
                for result in results {
                    match result.response {
                        Some(response) if operation_needs_an_operator(&response.status) => {
                            tracing::error!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                "shared HVM registry lease maintenance needs an operator; leases stop advancing until this operation is reconciled"
                            )
                        }
                        Some(response)
                            if let Some(age) = submission_has_gone_quiet(
                                &response.status,
                                response.submitted_unix,
                                crate::node::now_unix(),
                            ) =>
                        {
                            tracing::warn!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                transaction_hash = response.transaction_hash.as_deref().unwrap_or(""),
                                submitted_seconds_ago = age,
                                "shared HVM registry lease renewal has been outstanding without confirming; the lease is not advancing while this stands"
                            )
                        }
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
                        Some(response) if operation_needs_an_operator(&response.status) => {
                            tracing::error!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                action = %response.action,
                                "shared HVM registry watchtower needs an operator; this channel is not being watched until the operation is reconciled"
                            )
                        }
                        Some(response)
                            if let Some(age) = submission_has_gone_quiet(
                                &response.status,
                                response.submitted_unix,
                                crate::node::now_unix(),
                            ) =>
                        {
                            tracing::warn!(
                                binding_commitment = %result.binding_commitment,
                                operation_id = %response.operation_id,
                                status = %response.status,
                                action = %response.action,
                                transaction_hash = response.transaction_hash.as_deref().unwrap_or(""),
                                submitted_seconds_ago = age,
                                "shared HVM registry watchtower action has been outstanding without confirming; this channel is not being acted on while this stands"
                            )
                        }
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

/// Everything the V1 lease tick opens carries this prefix pair, and nothing
/// else does. The CLI names its own lease renewals `pilot-lease-…`, its
/// watchtower operations `pilot-watch-…`, and the registry tick uses the
/// `hvm-registry-lease-` pair below, so a record under these two names was
/// opened by this tick and by nothing else.
///
/// That matters because of what the tick does with an operation it finds
/// outstanding: it drives it. Driving somebody else's in-flight transaction
/// would be the tick reaching outside its own work, so it checks the name
/// first and refuses anything it did not open.
pub const HVM_LEASE_OPERATION_PREFIX: &str = "hvm-lease-";
pub const HVM_LEASE_IDEMPOTENCY_PREFIX: &str = "hvm-lease-idem-";

/// The registry twin of the pair above, for the second lease tick.
pub const HVM_REGISTRY_LEASE_OPERATION_PREFIX: &str = "hvm-registry-lease-";
pub const HVM_REGISTRY_LEASE_IDEMPOTENCY_PREFIX: &str = "hvm-registry-lease-idem-";

/// Name a lease renewal after the clock window it was first attempted in.
///
/// Work that simply repeats is right to name itself after the clock: a lease
/// renewal is not a response to a situation, it is the same maintenance task
/// coming round again, and bucketing to a minute is what makes two passes
/// inside that minute one record rather than two.
///
/// What the window cannot do is name an operation that outlives it, and the
/// scheduler interval is at least sixty seconds, so *every* pass after the
/// first falls in a later window than the record it left behind. The name
/// alone therefore never finds outstanding work; the caller has to look for it
/// by binding before it asks the clock for a new name. See
/// [`crate::state::HubState::hvm_lease_channel_tick`].
pub(crate) fn operation_identity(binding_commitment: &str, unix: u64) -> (String, String) {
    let window = unix / 60;
    (
        format!("{HVM_LEASE_OPERATION_PREFIX}{binding_commitment}-{window}"),
        format!("{HVM_LEASE_IDEMPOTENCY_PREFIX}{binding_commitment}-{window}"),
    )
}

pub(crate) fn registry_operation_identity(binding_commitment: &str, unix: u64) -> (String, String) {
    let window = unix / 60;
    (
        format!("{HVM_REGISTRY_LEASE_OPERATION_PREFIX}{binding_commitment}-{window}"),
        format!("{HVM_REGISTRY_LEASE_IDEMPOTENCY_PREFIX}{binding_commitment}-{window}"),
    )
}

/// Was this record opened by the lease tick that is asking?
///
/// The idempotency prefix extends the operation prefix, so an operation id has
/// to be tested against both: `hvm-lease-idem-…` starts with `hvm-lease-` and
/// is not an operation id this tick ever minted.
pub(crate) fn lease_tick_owns(
    operation_id: &str,
    idempotency_key: &str,
    operation_prefix: &str,
    idempotency_prefix: &str,
) -> bool {
    operation_id.starts_with(operation_prefix)
        && !operation_id.starts_with(idempotency_prefix)
        && idempotency_key.starts_with(idempotency_prefix)
}

/// Everything the v1 watchtower tick creates carries this prefix, and nothing
/// else does. The CLI names its watchtower operations `pilot-watch-…`, so a
/// record under this name was opened by the tick and by nothing else — which
/// is what lets the tick drive its own in-flight response to confirmation
/// while leaving an operator's record strictly alone.
pub const HVM_WATCHTOWER_OPERATION_PREFIX: &str = "hvm-watchtower-";
pub const HVM_WATCHTOWER_IDEMPOTENCY_PREFIX: &str = "hvm-watchtower-idem-";

/// Name a v1 watchtower operation after the situation that calls for it. The
/// exact twin of [`registry_watchtower_operation_identity`]; see
/// [`HvmWatchtowerSituationV1`] for why the situation and not the clock is the
/// right name for work that answers a state rather than repeating on a timer.
pub(crate) fn watchtower_operation_identity(
    binding_commitment: &str,
    situation: &HvmWatchtowerSituationV1,
) -> (String, String) {
    let digest = situation.digest(binding_commitment);
    (
        format!("{HVM_WATCHTOWER_OPERATION_PREFIX}{digest}"),
        format!("{HVM_WATCHTOWER_IDEMPOTENCY_PREFIX}{digest}"),
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
pub type HvmWatchtowerMaintenanceResults = Vec<HvmWatchtowerMaintenanceResult>;
pub type HvmRegistryLeaseMaintenanceResults = Vec<HvmRegistryLeaseMaintenanceResult>;
pub type HvmRegistryWatchtowerMaintenanceResults = Vec<HvmRegistryWatchtowerMaintenanceResult>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The wedged status must be the only one that raises the alarm, and it
    /// must raise it. Every status the tick can legitimately be carrying has to
    /// stay quiet, or an operator learns to ignore the line; `recovery_required`
    /// has to be loud, because it is the one the Hub cannot leave by itself.
    #[test]
    fn only_the_status_an_operator_must_clear_is_logged_as_an_alert() {
        use crate::storage::HvmChainOperationStatus as Status;

        assert!(operation_needs_an_operator(
            Status::RecoveryRequired.as_str()
        ));
        for quiet in [
            Status::IntentPersisted,
            Status::SignatureMayExist,
            Status::Signed,
            Status::SubmissionStarted,
            Status::Submitted,
            Status::Confirmed,
            Status::Abandoned,
        ] {
            assert!(
                !operation_needs_an_operator(quiet.as_str()),
                "{} must not be logged as an operator alert",
                quiet.as_str()
            );
        }
        // Pinned against the literal, because this string is what the tick puts
        // on the wire and in the log and a rename must break this test rather
        // than silently stop alerting.
        assert!(operation_needs_an_operator("recovery_required"));
        assert!(!operation_needs_an_operator("submitted"));
    }

    /// The quiet-submission alarm has to fire on exactly one status, and only
    /// once the wait has stopped being ordinary. A pass that shouted on every
    /// `submitted` would be noise an operator learns to scroll past, which is
    /// the same failure as saying nothing.
    #[test]
    fn only_a_submission_that_has_stopped_being_ordinary_is_called_out() {
        use crate::storage::HvmChainOperationStatus as Status;

        let submitted = Status::Submitted.as_str();
        let now = 1_800_000_000;
        assert_eq!(
            submission_has_gone_quiet(submitted, Some(now - HVM_SUBMITTED_STALE_SECONDS), now),
            Some(HVM_SUBMITTED_STALE_SECONDS),
            "the boundary itself counts",
        );
        assert_eq!(
            submission_has_gone_quiet(submitted, Some(now - HVM_SUBMITTED_STALE_SECONDS + 1), now),
            None,
            "a transaction still inside the ordinary wait is not an alarm",
        );
        assert_eq!(
            submission_has_gone_quiet(submitted, None, now),
            None,
            "a record with no submission time makes no claim about one",
        );
        // A clock that moved backwards must not underflow into a huge age and
        // fire a false alarm.
        assert_eq!(
            submission_has_gone_quiet(submitted, Some(now + 60), now),
            None,
        );
        for other in [
            Status::IntentPersisted,
            Status::SignatureMayExist,
            Status::Signed,
            Status::SubmissionStarted,
            Status::Confirmed,
            Status::RecoveryRequired,
            Status::Abandoned,
        ] {
            assert_eq!(
                submission_has_gone_quiet(other.as_str(), Some(0), now),
                None,
                "{} is not a transaction waiting on the wire",
                other.as_str()
            );
        }
    }

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

    /// The tick drives what it opened and nothing else, so the ownership test
    /// has to survive the one string that looks like both: the idempotency
    /// prefix extends the operation prefix, and `hvm-lease-idem-…` is not an
    /// operation id this tick ever minted.
    #[test]
    fn lease_tick_ownership_is_not_fooled_by_the_overlapping_prefix() {
        let commitment = "ab".repeat(32);
        for (operation_id, idempotency_key) in [
            operation_identity(&commitment, 1_787_000_000),
            registry_operation_identity(&commitment, 1_787_000_000),
        ] {
            let (operation_prefix, idempotency_prefix) =
                if operation_id.starts_with(HVM_REGISTRY_LEASE_OPERATION_PREFIX) {
                    (
                        HVM_REGISTRY_LEASE_OPERATION_PREFIX,
                        HVM_REGISTRY_LEASE_IDEMPOTENCY_PREFIX,
                    )
                } else {
                    (HVM_LEASE_OPERATION_PREFIX, HVM_LEASE_IDEMPOTENCY_PREFIX)
                };
            assert!(lease_tick_owns(
                &operation_id,
                &idempotency_key,
                operation_prefix,
                idempotency_prefix
            ));
            // The two halves are not interchangeable in either direction.
            assert!(!lease_tick_owns(
                &idempotency_key,
                &idempotency_key,
                operation_prefix,
                idempotency_prefix
            ));
            assert!(!lease_tick_owns(
                &operation_id,
                &operation_id,
                operation_prefix,
                idempotency_prefix
            ));
        }

        // A CLI record, a watchtower record, and the other tick's record are
        // all somebody else's as far as the v1 lease tick is concerned.
        for (operation_id, idempotency_key) in [
            ("pilot-lease-operator-run", "pilot-lease-operator-run"),
            ("pilot-watch-4f39dab6", "pilot-watch-4f39dab6"),
            (
                "hvm-registry-lease-aa-29791749",
                "hvm-registry-lease-idem-aa-29791749",
            ),
            (
                "hvm-registry-watchtower-aa",
                "hvm-registry-watchtower-idem-aa",
            ),
        ] {
            assert!(
                !lease_tick_owns(
                    operation_id,
                    idempotency_key,
                    HVM_LEASE_OPERATION_PREFIX,
                    HVM_LEASE_IDEMPOTENCY_PREFIX
                ),
                "the v1 lease tick claimed {operation_id}"
            );
        }
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

    fn v1_situation() -> HvmWatchtowerSituationV1 {
        HvmWatchtowerSituationV1 {
            status: 3,
            chain_serial: 0,
            left_balance_zhu: 600_000,
            right_balance_zhu: 400_000,
            deadline: 900_012,
            left_claimed: false,
            durable_bill_serial: 1,
        }
    }

    /// The v1 twin of the test above, and it matters for the same reason: the
    /// v1 tick drives whatever it finds outstanding on the channel, so a retry
    /// that renamed itself would open a second record beside a signed
    /// transaction nobody is reconciling. That is precisely how the lease tick
    /// wedged.
    #[test]
    fn the_v1_watchtower_identity_follows_the_situation_and_not_the_clock() {
        let commitment = "ab".repeat(32);
        let challenged = watchtower_operation_identity(&commitment, &v1_situation());
        assert_eq!(
            challenged,
            watchtower_operation_identity(&commitment, &v1_situation()),
            "the same situation is the same operation, whenever it is ticked"
        );
        assert!(challenged.0.starts_with(HVM_WATCHTOWER_OPERATION_PREFIX));
        assert!(challenged.1.starts_with(HVM_WATCHTOWER_IDEMPOTENCY_PREFIX));
        assert_ne!(challenged.0, challenged.1);
        assert!(
            challenged.0.len() <= 256 && challenged.1.len() <= 256,
            "the request validator caps both at 256 bytes"
        );

        // Walking the lifecycle: our response confirms, the deadline passes
        // and we finalize, the payout is claimed. Each step is its own name.
        let mut responded = v1_situation();
        responded.chain_serial = 1;
        responded.left_balance_zhu = 1_000_000;
        responded.right_balance_zhu = 0;
        let mut finalized = responded;
        finalized.status = 4;
        let mut claimed = finalized;
        claimed.left_claimed = true;
        let names = [v1_situation(), responded, finalized, claimed]
            .iter()
            .map(|step| watchtower_operation_identity(&commitment, step).0)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 4, "every lifecycle step is its own operation");

        // A different channel in an identical state is a different operation.
        assert_ne!(
            watchtower_operation_identity(&"cd".repeat(32), &v1_situation()),
            challenged
        );

        // And the two rails never collide, in either direction.
        assert_ne!(
            challenged.0,
            registry_watchtower_operation_identity(&commitment, &situation()).0
        );
        assert!(
            !challenged
                .0
                .starts_with(HVM_REGISTRY_WATCHTOWER_OPERATION_PREFIX),
            "a v1 name must never be mistaken for a registry one"
        );
        assert!(
            !registry_watchtower_operation_identity(&commitment, &situation())
                .0
                .starts_with(HVM_WATCHTOWER_OPERATION_PREFIX),
            "nor a registry name for a v1 one"
        );
    }
}
