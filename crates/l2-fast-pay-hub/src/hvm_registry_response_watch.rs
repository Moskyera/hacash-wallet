//! Somebody has to be awake when the challenge lands.
//!
//! A shared-registry channel settles through an arbitration window. Either
//! party may `challenge` with a bill; the other party has `challenge_blocks`
//! to `respond` with a newer one; whatever stands when the window closes is
//! what gets paid. That window is measured in blocks, not in office hours,
//! and a user whose laptop is shut answers nothing.
//!
//! This module is the answer to that, and it is deliberately the smallest
//! thing that can be one: a pure decide-and-build core plus a poll loop, run
//! from a key that is neither the Hub nor the user, holding no key of the
//! user's at all.
//!
//! # Why this can exist without key custody
//!
//! Every step it takes is one the contract already grants to anybody:
//!
//! * `respond` and `finalize` carry no signer check
//!   (`vm/contracts/hpay_channel_registry_v2.fitsh`, the `respond` and
//!   `finalize` functions). The authority is the bill's own two signatures,
//!   which is why a responder needs the bill and nothing else.
//! * the Action 14 payout is authorised by the contract's `PermitHAC` hook,
//!   which pins the destination to the channel's left party and the amount to
//!   `c_left_balance_` to the zhu. `tx.main` pays the fee and decides nothing.
//!
//! Measured on a real chain rather than argued: a stranger holding only a
//! co-signed bill answered a hostile challenge, installed the correct serial,
//! finalised and paid the user out. The same stranger trying to pay *itself*
//! got `Arithmetic(90): cannot compare different types Nil and U8(4)`, and
//! trying a different amount got `HPAY_LEFT_PAYOUT_MISMATCH`.
//!
//! That is a strictly better trust profile than a Lightning watchtower, whose
//! justice transaction is a bearer instrument and therefore has to be handed
//! over encrypted. Here the worst a dishonest operator can do is learn your
//! channel balance, and the worst an absent one can do is nothing at all.
//!
//! # What it deliberately cannot do
//!
//! It cannot start a close. [`HvmRegistryResponseWatchStepV1`] has three
//! members and `challenge` is not one of them, so there is no argument, flag
//! or configuration that makes this process open an arbitration window
//! against a user who did not ask for one. A close is a control a person
//! presses; this only ever finishes one somebody else started.
//!
//! # The honest gap
//!
//! A poll loop protects nothing while it is not running. See
//! [`HvmRegistryResponseWatchCoverageV1`] and
//! [`response_watch_startup_notice`]: the size of the gap is computed from
//! the binding and printed in words at every start, because a watcher that
//! implies continuous cover it does not have is worse than no watcher.

use serde::{Deserialize, Serialize};
use sys::Account;

use crate::error::{HubError, HubResult};
use crate::hvm_registry::{HvmRegistryBillV2, HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2};
use crate::hvm_registry_watchtower::{
    HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS, HvmRegistryCallerRole, HvmRegistryWatchtowerDecisionV2,
    SignedHvmRegistryCallTransactionV2, build_signed_hvm_registry_call_transaction,
    build_signed_hvm_registry_claim_transaction, decide_user_exit_action,
    registry_claim_payout_source, registry_finalize_call_source, registry_respond_call_source,
    registry_response_window_blocks, registry_response_window_is_safe,
};

/// The Hacash block target, in seconds.
///
/// Used only to turn block counts into the hours and minutes a person
/// actually reasons in. Nothing safety-critical is decided from it; every
/// refusal in this module is decided in blocks.
pub const HACASH_BLOCK_TARGET_SECONDS: u64 = 300;

pub const HVM_REGISTRY_EXIT_KIT_SCHEMA: &str = "hpay-hvm-registry-exit-kit/1";

/// The shortest arbitration window a person could reasonably be expected to
/// answer without a machine standing in for them.
///
/// **OWNER DECISION, NOT ENGINEERING, AND NOT ENFORCED HERE.** Nothing in
/// this module refuses a binding for having a shorter window; this constant
/// is read only to decide how loudly [`response_watch_startup_notice`] says
/// that the window is not human-scale. Enforcing a floor is a change to
/// `HvmRegistryBindingV2::validate`, it invalidates channels already open at
/// the reviewed value of 12, and the number itself is a policy trade the
/// owner has to make: a wider window is also a longer wait, and a longer lock
/// on the user's own money during an honest exit.
///
/// 288 blocks is 24 hours at the block target — one sleep, one working day,
/// one flight. It is written down here so the decision has a name and a
/// default to argue with rather than being rediscovered later.
pub const HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS: u64 = 288;

/// Everything needed to answer a challenge on somebody's behalf, and nothing
/// else.
///
/// Same shape as `HvmRegistryRecoveryBundleV2` except that it carries the
/// user's *latest* fully-signed bill instead of the opening one. That single
/// difference is what makes it useful and what makes it perishable: a kit
/// that has fallen behind the user's real head installs an older split, and
/// on this one-directional rail an older split pays the Hub. A stale kit is a
/// mistake in the Hub's favour, so it must be refreshed after every payment.
///
/// It contains no private key and cannot be turned into one. Handing it to
/// somebody lets them finish this channel in the user's favour, lets them
/// learn the channel balance, and lets them do nothing else whatsoever.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryExitKitV1 {
    pub schema: String,
    pub binding: HvmRegistryBindingV2,
    pub latest_bill: HvmRegistryBillV2,
}

impl HvmRegistryExitKitV1 {
    pub fn validate_crypto(&self) -> HubResult<()> {
        if self.schema != HVM_REGISTRY_EXIT_KIT_SCHEMA {
            return Err(HubError::Node(
                "HVM registry exit kit schema is unsupported".into(),
            ));
        }
        self.binding.validate()?;
        self.latest_bill.validate_fully_signed(&self.binding)?;
        Ok(())
    }

    /// The user's own address. The only destination any money in this channel
    /// can reach, and the only one this software will build a payout to.
    pub fn beneficiary(&self) -> &str {
        &self.binding.left_address
    }
}

/// The three steps a responder is allowed to take.
///
/// There is no `Challenge`. Its absence is the guarantee that this process
/// cannot start a close, and it is enforced by the type rather than by a
/// flag, because a flag can be set by somebody who did not read this comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryResponseWatchStepV1 {
    /// A challenge is standing at an older serial than the kit's bill.
    /// Install the kit's bill before the window closes.
    Respond,
    /// The window has closed on the correct split. Lock it in. Permissionless
    /// by contract, and it cannot change who gets paid.
    Finalize,
    /// The channel is FINAL and the principal is still inside the contract.
    /// Action 14 to the channel's left party, for exactly the settled amount.
    ClaimLeftPayout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryResponseWatchActionV1 {
    /// Nothing to do, including the OPEN case: an open channel is the user's
    /// to close, never the watcher's.
    Nothing,
    Act(HvmRegistryResponseWatchStepV1),
    /// A response is needed and there is no longer enough window left for one
    /// to be mined in time. Spending a fee here buys a transaction the
    /// contract will refuse for being late while leaving the stale split
    /// standing, so nothing is signed and the operator is told the arithmetic.
    RefuseWindowTooShort {
        blocks_left: u64,
    },
    /// The chain is ahead of, or disagrees with, the kit. Stopping is the
    /// only safe move: acting on a kit the chain has passed installs an older
    /// split, and on this rail that pays the Hub.
    RecoveryRequired,
}

/// What to do, decided entirely by delegating to the Hub's own watchtower
/// rule and then subtracting the moves a responder may not make.
///
/// The delegation is the point. `decide_user_exit_action` takes a
/// binding, a bill and a snapshot; no Hub identity appears anywhere in it. A
/// second implementation of the same arithmetic is exactly how a watcher and
/// the party it is watching for come to disagree about whose bill is newer,
/// so there is not one.
///
/// The only divergence is subtractive: `Finalize` and `ClaimLeftPayout` pass
/// through, `RespondWithLatestBill` is gated on the response margin instead
/// of being attempted, and a `NoAction` on an OPEN channel stays `Nothing`
/// rather than becoming an opportunity to open one.
///
/// # Which chair this sits in
///
/// It asks [`decide_user_exit_action`], not the Hub's own monitor. That is not
/// cosmetic. The Hub's rule answers `RespondWithLatestBill` whenever the chain
/// carries an older serial, which is correct for the Hub and catastrophic for
/// a watcher acting on the user's behalf: on this rail a newer serial always
/// pays the user *less*, so a watcher that dutifully answered a hostile Hub's
/// stale challenge was measured taking 650,000 zhu off its own user. The
/// left-party rule carries [`registry_respond_defends_left_payout`], which
/// refuses to spend a fee on a response that lowers the user's payout, so that
/// arm now resolves to `Nothing` instead. The `OpenChallengeWithLatestBill`
/// arm below is the price of sitting in that chair, and it is mapped
/// explicitly to `Nothing` because opening a close is the user's decision.
pub fn decide_response_watch_action(
    snapshot: &HvmRegistryLiveSnapshotV2,
    kit: &HvmRegistryExitKitV1,
) -> HubResult<HvmRegistryResponseWatchActionV1> {
    kit.validate_crypto()?;
    let decision = decide_user_exit_action(snapshot, &kit.binding, &kit.latest_bill)?;
    Ok(match decision {
        HvmRegistryWatchtowerDecisionV2::NoAction => HvmRegistryResponseWatchActionV1::Nothing,
        // `decide_user_exit_action` returns this on every OPEN channel, so
        // this arm is reached on the common path and is load bearing. A
        // responder must not act on it: opening an arbitration window costs
        // somebody their working channel and their deposit's liquidity, and
        // that decision belongs to the person whose money it is. This is the
        // guarantee at the top of this module — a watcher can never start a
        // close — and it is enforced twice: here, and by
        // `HvmRegistryResponseWatchStepV1` having no Challenge member at all.
        // Mapped explicitly rather than wildcarded, so a future decision
        // variant stops the compiler here again.
        HvmRegistryWatchtowerDecisionV2::OpenChallengeWithLatestBill => {
            HvmRegistryResponseWatchActionV1::Nothing
        }
        HvmRegistryWatchtowerDecisionV2::RecoveryRequired => {
            HvmRegistryResponseWatchActionV1::RecoveryRequired
        }
        HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill
            if registry_response_window_is_safe(snapshot) =>
        {
            HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::Respond)
        }
        HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill => {
            HvmRegistryResponseWatchActionV1::RefuseWindowTooShort {
                blocks_left: registry_response_window_blocks(snapshot),
            }
        }
        HvmRegistryWatchtowerDecisionV2::Finalize => {
            HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::Finalize)
        }
        HvmRegistryWatchtowerDecisionV2::ClaimLeftPayout => {
            HvmRegistryResponseWatchActionV1::Act(HvmRegistryResponseWatchStepV1::ClaimLeftPayout)
        }
    })
}

/// Build the exact signed bytes for one step, from a key that is neither
/// party.
///
/// The call source is derived here from the kit and the live snapshot; the
/// caller supplies no source and no payee and no amount. That is what makes
/// the third-party role safe to expose: there is no parameter through which a
/// responder could point the money anywhere, because the destination comes
/// from `binding.left_address` and the amount comes from live contract
/// storage, both of which the contract re-checks anyway.
///
/// It re-decides before it signs. A step handed in by a caller that has gone
/// stale between the decision and the build is refused rather than paid for.
pub fn build_response_watch_transaction(
    signer: &Account,
    kit: &HvmRegistryExitKitV1,
    step: HvmRegistryResponseWatchStepV1,
    snapshot: &HvmRegistryLiveSnapshotV2,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<SignedHvmRegistryCallTransactionV2> {
    // These builders serialise real actions through the consensus codec
    // registry, which panics if it was never installed. A responder is a
    // standalone process that has never touched a chain, so install it here;
    // the call is idempotent.
    crate::protocol_registry::ensure_hacash_protocol_setup();
    kit.validate_crypto()?;
    match decide_response_watch_action(snapshot, kit)? {
        HvmRegistryResponseWatchActionV1::Act(current) if current == step => {}
        other => {
            return Err(HubError::State(format!(
                "registry response watch will not build {step:?}: the chain now says {other:?}"
            )));
        }
    }
    match step {
        HvmRegistryResponseWatchStepV1::Respond => build_signed_hvm_registry_call_transaction(
            signer,
            &kit.binding,
            HvmRegistryCallerRole::ThirdPartyFeePayer,
            registry_respond_call_source(&kit.binding, &kit.latest_bill)?,
            network_fee_zhu,
            timestamp,
            gas_max,
        ),
        HvmRegistryResponseWatchStepV1::Finalize => build_signed_hvm_registry_call_transaction(
            signer,
            &kit.binding,
            HvmRegistryCallerRole::ThirdPartyFeePayer,
            registry_finalize_call_source(&kit.binding)?,
            network_fee_zhu,
            timestamp,
            gas_max,
        ),
        HvmRegistryResponseWatchStepV1::ClaimLeftPayout => {
            // Read straight off live contract storage, never inferred:
            // `PermitHAC` rejects anything that is not exactly
            // `c_left_balance_`.
            let amount_zhu = snapshot.channel.left_balance.value;
            // Derived, not accepted. Building the source here as well as
            // inside the builder means the payee this software can express is
            // the binding's left address and there is no other spelling of it.
            registry_claim_payout_source(&kit.binding, kit.beneficiary(), amount_zhu)?;
            build_signed_hvm_registry_claim_transaction(
                signer,
                &kit.binding,
                HvmRegistryCallerRole::ThirdPartyFeePayer,
                kit.beneficiary(),
                amount_zhu,
                network_fee_zhu,
                timestamp,
                gas_max,
            )
        }
    }
}

/// How much of the arbitration window this watcher can actually cover, in the
/// units a person thinks in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HvmRegistryResponseWatchCoverageV1 {
    /// `binding.challenge_blocks`: the whole window, from the block the
    /// challenge lands in.
    pub answer_window_blocks: u64,
    /// What is left after the response margin the builder reserves for tip
    /// lag, the submission pipeline and inclusion.
    pub usable_window_blocks: u64,
    pub usable_window_seconds: u64,
    pub poll_interval_seconds: u64,
    /// How many times this loop would look at the chain inside the usable
    /// window. One is the bare minimum and means a single failed poll is a
    /// missed window.
    pub polls_inside_the_usable_window: u64,
    /// Whether the window is long enough for an unassisted person, per
    /// [`HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS`].
    pub window_is_human_answerable: bool,
}

pub fn response_watch_coverage(
    binding: &HvmRegistryBindingV2,
    poll_interval_seconds: u64,
) -> HubResult<HvmRegistryResponseWatchCoverageV1> {
    binding.validate()?;
    if poll_interval_seconds == 0 {
        return Err(HubError::State(
            "registry response watch poll interval must be positive".into(),
        ));
    }
    let usable_window_blocks = binding
        .challenge_blocks
        .saturating_sub(HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS);
    let usable_window_seconds = usable_window_blocks.saturating_mul(HACASH_BLOCK_TARGET_SECONDS);
    Ok(HvmRegistryResponseWatchCoverageV1 {
        answer_window_blocks: binding.challenge_blocks,
        usable_window_blocks,
        usable_window_seconds,
        poll_interval_seconds,
        polls_inside_the_usable_window: usable_window_seconds / poll_interval_seconds,
        window_is_human_answerable: challenge_window_is_human_answerable(binding),
    })
}

pub fn challenge_window_is_human_answerable(binding: &HvmRegistryBindingV2) -> bool {
    binding.challenge_blocks >= HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS
}

fn plain_duration(seconds: u64) -> String {
    if seconds < 90 {
        return format!("{seconds} seconds");
    }
    if seconds < 5_400 {
        return format!("{} minutes", seconds / 60);
    }
    if seconds < 172_800 {
        return format!("{} hours", seconds / 3_600);
    }
    format!("{} days", seconds / 86_400)
}

/// What this process protects, and what it does not, printed before it does
/// anything.
///
/// The witness binary sets the precedent and the reason is the same one: a
/// component whose whole value is a guarantee has to state the exact shape of
/// the guarantee where the operator cannot avoid reading it. A watcher is
/// worse than useless if the person relying on it believes it covers hours it
/// does not.
///
/// So the gap is arithmetic, not a disclaimer: the usable window is computed
/// from this channel's own `challenge_blocks` and printed in minutes.
pub fn response_watch_startup_notice(
    kit: &HvmRegistryExitKitV1,
    coverage: &HvmRegistryResponseWatchCoverageV1,
    node_url: &str,
    fee_payer: &Account,
) -> String {
    let usable = plain_duration(coverage.usable_window_seconds);
    let whole = plain_duration(
        coverage
            .answer_window_blocks
            .saturating_mul(HACASH_BLOCK_TARGET_SECONDS),
    );
    let human = if coverage.window_is_human_answerable {
        format!(
            "  This channel's window is {} blocks ({whole}). That is long enough that a\n  \
             person who is awake and near a computer could answer it themselves.",
            coverage.answer_window_blocks
        )
    } else {
        format!(
            "  This channel's window is only {} blocks ({whole}), of which {} blocks\n  \
             ({usable}) are usable after the response margin. A person cannot be relied\n  \
             on to answer that. It is below the {HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS}-block figure this project\n  \
             writes down as human-answerable.\n\n  \
             OWNER DECISION, STILL OPEN: whether to enforce a minimum window on new\n  \
             channels, and what it should be. Nothing enforces one today. A wider window\n  \
             is safer for a sleeping user and also a longer wait, and a longer lock on\n  \
             your own money, during an honest exit.",
            coverage.answer_window_blocks, coverage.usable_window_blocks
        )
    };
    format!(
        "\n\
         ===========================================================================\n\
             HPAY REGISTRY RESPONSE WATCH\n\
             Answers an arbitration challenge for somebody who is not awake.\n\
         ===========================================================================\n\
         \n\
         WHO THIS IS FOR\n\
         \n  \
           Channel  : {channel}\n  \
           Beneficiary (the ONLY address money from this channel can reach):\n  \
           {left}\n  \
           Provider (Hub) : {hub}\n  \
           Kit bill serial: {serial}, leaving {left_zhu} zhu to the beneficiary\n  \
           Fullnode : {node_url}\n  \
           Fees paid by   : {fee_payer}\n\
         \n\
         WHAT THIS PROTECTS\n\
         \n  \
           If a challenge appears naming a bill OLDER than the one in the kit, this\n  \
           answers it with the kit's bill before the window closes. If a close is\n  \
           already settled correctly, it finalises it and sends the money home.\n\
         \n\
         WHAT THIS DOES NOT PROTECT\n\
         \n  \
           Nothing at all while this process is not running. There is no queue and\n  \
           no catch-up: a challenge that opens and expires while this is stopped is\n  \
           simply lost. The whole exposure is {usable} from the moment a challenge\n  \
           is mined.\n\
         \n\
{human}\n\
         \n  \
           It also does not renew this channel's storage lease. That is a separate\n  \
           clock, and it is the one that destroys money outright rather than\n  \
           misallocating it.\n\
         \n\
         WHAT IT CANNOT DO, BY CONSTRUCTION\n\
         \n  \
           It never starts a close. There is no challenge step in this program, so\n  \
           no flag and no configuration can make it open a window against you.\n  \
           It cannot pay itself or anyone else. The contract pins the payout to the\n  \
           beneficiary above and to the exact settled amount.\n  \
           It holds no key of yours. The kit it reads is not a private key and\n  \
           cannot be turned into one. Whoever holds a kit can finish this channel\n  \
           in your favour, can read your channel balance, and can do nothing else.\n\
         \n\
         WHY A SLEEPING USER IS CURRENTLY SAFE ANYWAY, AND WHAT THAT RESTS ON\n\
         \n  \
           On this rail every bill you sign pays you less than the one before it, so\n  \
           a stale challenge from the provider hands money BACK to you. That is not\n  \
           a property of this program. It is a property of exactly two refusals:\n\n    \
             crates/l2-fast-pay-hub/src/hvm_registry.rs\n      \
             right_hub_deposit_zhu != 0 is refused, so the provider never has\n      \
             principal of its own inside the channel.\n    \
             crates/l2-fast-pay-hub/src/hvm_registry_ledger.rs\n      \
             checked_sub on the left balance, so no bill can ever move value\n      \
             back towards you.\n\n  \
           If either ever changes, an unanswered window starts costing real money\n  \
           and this program stops being optional.\n\
         \n  \
           A STALE KIT IS THE ONE MISTAKE THAT COSTS YOU. Refresh it after every\n  \
           payment. Answering with a bill older than your real head installs an\n  \
           older split, and an older split is one the provider prefers.\n\
         \n\
         ===========================================================================\n",
        channel = kit.binding.channel_id,
        left = kit.beneficiary(),
        hub = kit.binding.right_hub_address,
        serial = kit.latest_bill.serial,
        left_zhu = kit.latest_bill.left_balance_zhu,
        node_url = node_url,
        fee_payer = fee_payer.readable(),
        usable = usable,
        human = human,
    )
}

/// The poll loop: the only part of this module that touches a network.
///
/// It is kept small on purpose. Everything that decides anything lives above
/// and is pure; this reads the chain, hands the answer to the pure core, and
/// submits whatever comes back. A watcher whose judgement lives in its I/O
/// layer is a watcher nobody can test.
pub mod poll {
    use super::{
        HvmRegistryExitKitV1, HvmRegistryResponseWatchActionV1, HvmRegistryResponseWatchStepV1,
        build_response_watch_transaction, decide_response_watch_action,
    };
    use crate::error::{HubError, HubResult};
    use crate::hvm_registry_watchtower::{
        HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS, require_fresh_registry_evidence,
    };
    use crate::node::NodeClient;
    use sys::Account;

    /// What one look at the chain concluded. Every arm is printed by the
    /// binary; there is no silent state.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PollOutcomeV1 {
        /// Nothing needed doing. The overwhelmingly common case, and it is
        /// still reported, because a watcher that prints nothing while
        /// healthy is indistinguishable from a watcher that has died.
        Idle {
            status: u8,
            chain_serial: u64,
            observed_height: u64,
            lease_live_blocks: u64,
        },
        /// A step was needed and this run had already taken it against the
        /// same chain state. Not re-signed and not re-paid for.
        AlreadySubmitted {
            step: HvmRegistryResponseWatchStepV1,
        },
        Submitted {
            step: HvmRegistryResponseWatchStepV1,
            transaction_hash: String,
        },
        /// Would have acted. `--dry-run` is the mode an operator runs first,
        /// and it must reach exactly the same decision as the live mode.
        WouldSubmit {
            step: HvmRegistryResponseWatchStepV1,
            transaction_hash: String,
        },
        /// The window closed below the response margin. Nothing signed.
        WindowTooShort { blocks_left: u64 },
        /// The chain is ahead of the kit. The loop stops.
        RecoveryRequired,
    }

    /// One watched channel.
    ///
    /// Holds no key of the user's. `signer` is the responder's own key and it
    /// pays fees; the kit is public evidence.
    pub struct ResponseWatchV1 {
        kit: HvmRegistryExitKitV1,
        network_fee_zhu: u64,
        gas_max: u8,
        dry_run: bool,
        /// The exact chain position a step was last submitted against.
        ///
        /// A submitted transaction takes blocks to be mined, and the poll
        /// interval is shorter than a block. Without this the loop would
        /// re-sign and re-pay for the same `respond` every tick until it
        /// landed. Keyed on the chain facts the decision was made from, so a
        /// genuine change of situation is never suppressed.
        last_submitted: Option<(HvmRegistryResponseWatchStepV1, u8, u64, bool)>,
    }

    impl ResponseWatchV1 {
        pub fn new(
            kit: HvmRegistryExitKitV1,
            network_fee_zhu: u64,
            gas_max: u8,
            dry_run: bool,
        ) -> HubResult<Self> {
            kit.validate_crypto()?;
            if network_fee_zhu == 0 || gas_max == 0 {
                return Err(HubError::State(
                    "registry response watch fee and gas limit must be positive".into(),
                ));
            }
            Ok(Self {
                kit,
                network_fee_zhu,
                gas_max,
                dry_run,
                last_submitted: None,
            })
        }

        pub fn kit(&self) -> &HvmRegistryExitKitV1 {
            &self.kit
        }

        /// One look at the chain.
        ///
        /// The lease is read but never used as a gate. A channel whose
        /// storage lease is running out still deserves an answer to a
        /// challenge; refusing to look because the lease is short would turn
        /// one problem into two. It is reported so the operator can act on
        /// it, in the one place that is guaranteed to be watching.
        pub async fn poll_once(
            &mut self,
            node: &NodeClient,
            signer: &Account,
            now_unix: u64,
        ) -> HubResult<PollOutcomeV1> {
            let binding = &self.kit.binding;
            // The node's own tip is read before its registry view, so that
            // `observed_height` can be cross-checked rather than trusted.
            // Every deadline decision below rests on that height.
            let capabilities = node.capabilities().await?;
            let snapshot = node.hvm_registry_runtime_snapshot(binding, 1, 1).await?;
            require_fresh_registry_evidence(
                &snapshot,
                capabilities.height,
                capabilities.tip_age_seconds,
            )?;

            let position = (
                snapshot.channel.status.value,
                snapshot.channel.serial.value,
                snapshot.channel.left_claimed.value,
            );
            let step = match decide_response_watch_action(&snapshot, &self.kit)? {
                HvmRegistryResponseWatchActionV1::Nothing => {
                    return Ok(PollOutcomeV1::Idle {
                        status: snapshot.channel.status.value,
                        chain_serial: snapshot.channel.serial.value,
                        observed_height: snapshot.observed_height,
                        lease_live_blocks: snapshot.minimum_live_blocks,
                    });
                }
                HvmRegistryResponseWatchActionV1::RecoveryRequired => {
                    return Ok(PollOutcomeV1::RecoveryRequired);
                }
                HvmRegistryResponseWatchActionV1::RefuseWindowTooShort { blocks_left } => {
                    return Ok(PollOutcomeV1::WindowTooShort { blocks_left });
                }
                HvmRegistryResponseWatchActionV1::Act(step) => step,
            };
            if self.last_submitted == Some((step, position.0, position.1, position.2)) {
                return Ok(PollOutcomeV1::AlreadySubmitted { step });
            }

            let signed = build_response_watch_transaction(
                signer,
                &self.kit,
                step,
                &snapshot,
                self.network_fee_zhu,
                now_unix,
                self.gas_max,
            )?;
            if self.dry_run {
                return Ok(PollOutcomeV1::WouldSubmit {
                    step,
                    transaction_hash: signed.transaction_hash,
                });
            }
            let transaction_hash = node
                .submit_hvm_registry_transaction_bound(
                    &signed.signed_transaction_hex,
                    &signed.transaction_hash,
                    binding,
                )
                .await?;
            self.last_submitted = Some((step, position.0, position.1, position.2));
            Ok(PollOutcomeV1::Submitted {
                step,
                transaction_hash,
            })
        }
    }

    /// The shortest poll interval worth allowing.
    ///
    /// Mirrors `HvmLeaseSchedulerConfig`'s floor. Anything shorter is polling
    /// a node harder than the chain can change, which buys no coverage and
    /// looks like abuse from the node's side.
    pub const MIN_POLL_INTERVAL_SECONDS: u64 = 60;

    /// The longest interval that still leaves room to answer.
    ///
    /// Derived, not chosen: the usable window is
    /// `challenge_blocks - HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS` blocks, and an
    /// interval longer than that can step straight over a whole challenge
    /// without ever seeing it. This is the arithmetic that decides whether a
    /// configuration protects anybody, so it is a refusal rather than a
    /// warning.
    pub fn max_poll_interval_seconds(challenge_blocks: u64) -> u64 {
        challenge_blocks
            .saturating_sub(HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS)
            .saturating_mul(super::HACASH_BLOCK_TARGET_SECONDS)
    }

    pub fn require_usable_poll_interval(
        challenge_blocks: u64,
        poll_interval_seconds: u64,
    ) -> HubResult<()> {
        if poll_interval_seconds < MIN_POLL_INTERVAL_SECONDS {
            return Err(HubError::State(format!(
                "registry response watch poll interval must be at least {MIN_POLL_INTERVAL_SECONDS}s"
            )));
        }
        let ceiling = max_poll_interval_seconds(challenge_blocks);
        if poll_interval_seconds > ceiling {
            return Err(HubError::State(format!(
                "a {poll_interval_seconds}s poll interval cannot answer a {challenge_blocks}-block challenge window: the usable window is {ceiling}s, so a challenge could open and expire between two looks"
            )));
        }
        Ok(())
    }
}
