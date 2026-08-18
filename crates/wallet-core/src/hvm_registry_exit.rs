//! The user's own side of an HVM registry V2 unilateral exit.
//!
//! # What was missing
//!
//! The `hpay_channel_registry_v2` contract is permissionless where a
//! unilateral exit needs it to be. `challenge`, `respond`, `finalize` and
//! `renew_channel` all take the channel's left address as a *parameter* and
//! carry no signature check of their own — the two signatures on the bill are
//! the authority. The Action 14 payout that walks the settled principal out of
//! the contract needs no signature from the contract either, because a
//! contract address is not a privakey and `TransactionType3::intrinsic_req_sign`
//! only demands signatures from addresses that are. The chain would accept a
//! user walking out alone.
//!
//! What did not exist was any code that *built* those transactions for anyone
//! but the Hub. Both builders in
//! [`l2_fast_pay_hub::hvm_registry_watchtower`] opened with
//! `signer.readable() != binding.right_hub_address`, and nothing under
//! `wallet-core`, `agent-wallet-core`, `apps/desktop` or `apps/mobile`
//! constructed a challenge, respond, finalize or claim by any other route. The
//! door was unlocked and nobody had made the user a key.
//!
//! # What this module is
//!
//! The key. It is pure: it decides and it builds, and it performs no I/O. The
//! caller supplies the live snapshot it already fetched from its own pinned
//! fullnode and submits the bytes this returns.
//!
//! Everything load-bearing is **reused, not reimplemented**. The fitsh call
//! strings, the Action 44 and Action 14 encoders, the freshness rule, the
//! response-window margin and the decision table all come from the Hub's own
//! watchtower module unchanged. A second encoder of the same call would be a
//! second place to be wrong, and worse, it would make a durable record built
//! by one encoder unverifiable by the other later.
//!
//! # What makes it safe to widen who may build these bytes
//!
//! Not this module. Two checks that already existed and are untouched:
//!
//! * [`registry_claim_payout_source`] refuses any payee that is not
//!   `binding.left_address`. The user cannot aim the payout anywhere else, and
//!   neither could anyone else who got hold of an exit kit.
//! * The contract's `PermitHAC` hook pins the amount to `c_left_balance_`, so
//!   the payout is the channel's own settled left balance or it throws.
//!
//! `tx.main` — the signer these builders check — only pays the network fee. It
//! has no authority over where the coin goes. That is why making the builders
//! role-aware widens who may *spend a fee* and not who may *be paid*.

use l2_fast_pay_hub::hvm_registry::{
    HvmRegistryBillV2, HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2,
};
// The exit kit is defined once, in the Hub crate, and shared by the wallet's
// driver and the standalone response watcher. Two structurally identical types
// carrying the same schema string would be exactly the drift this whole module
// exists to avoid: a kit exported by one and refused by the other.
pub use l2_fast_pay_hub::hvm_registry_response_watch::{
    HVM_REGISTRY_EXIT_KIT_SCHEMA, HvmRegistryExitKitV1,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS, HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
    HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS, HvmRegistryCallerRole, HvmRegistryWatchtowerDecisionV2,
    SignedHvmRegistryCallTransactionV2, build_signed_hvm_registry_call_transaction,
    build_signed_hvm_registry_claim_transaction, decide_user_exit_action,
    read_exact_registry_claim_transaction, registry_challenge_call_source,
    registry_claim_payout_source, registry_finalize_call_source,
    registry_left_payout_shortfall_zhu, registry_renew_channel_call_source,
    registry_renew_registry_call_source, registry_respond_call_source,
    registry_response_window_blocks, registry_response_window_is_safe,
    require_fresh_registry_evidence,
};
use serde::{Deserialize, Serialize};
use sys::Account;

use crate::error::{WalletError, WalletResult};

/// Extra lease head-room, on top of the whole challenge window and the
/// response margin, that the channel's storage keys must still have before an
/// exit is allowed to *start*.
///
/// An expiring lease is the only path in this system that destroys money
/// outright: when a channel's storage keys lapse, `c_status_` reads Nil, every
/// contract entry point aborts comparing Nil against a number, and the deposit
/// stays inside the contract with nobody — not the user, not the Hub, not a
/// stranger — able to reach it. There is no re-creation path.
///
/// An exit that runs out of lease halfway is therefore strictly worse than an
/// exit that never started: the fees are spent and the money is gone for good.
/// So the floor covers the full sequence rather than the next step —
/// `challenge_blocks` for the objection window, the response margin the
/// watchtower already reserves, and this slack for the finalize and the Action
/// 14 claim that follow the deadline. 24 blocks is roughly two hours at the
/// 300s Hacash block target.
pub const HVM_REGISTRY_EXIT_LEASE_SLACK_BLOCKS: u64 = 24;

/// Assemble an exit kit from a binding and the wallet's own head bill, and
/// refuse to hand out one that does not verify.
///
/// A kit is a bearer proof of *entitlement*, so it is checked on the way out
/// as well as on the way in: an unverifiable kit exported to a watchtower or a
/// backup is a user who believes they have a route out and does not.
pub fn build_exit_kit(
    binding: HvmRegistryBindingV2,
    latest_bill: HvmRegistryBillV2,
) -> WalletResult<HvmRegistryExitKitV1> {
    let kit = HvmRegistryExitKitV1 {
        schema: HVM_REGISTRY_EXIT_KIT_SCHEMA.into(),
        binding,
        latest_bill,
    };
    kit.validate_crypto().map_err(hub_error)?;
    Ok(kit)
}

/// One step of the exit sequence, named so a durable record and a UI can both
/// say which one they mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryExitStep {
    /// Put the latest fully-signed bill on chain and start the objection
    /// window. Status 2 (OPEN) -> 3 (CHALLENGING).
    Challenge,
    /// Supersede a challenge that carries an older serial than ours.
    Respond,
    /// Lock the result once the deadline has passed. Permissionless: anybody
    /// may press it, and it cannot change who gets paid.
    Finalize,
    /// The Action 14 payout. The only door HAC leaves the contract by.
    Claim,
    /// Buy this channel's 12 storage keys more life.
    RenewChannelLease,
    /// Buy the deployment's 6 shared globals more life. Any channel's user may
    /// do this, and if the globals lapse every channel in the deployment is
    /// affected, not just one.
    RenewRegistryLease,
}

impl HvmRegistryExitStep {
    /// Stable lowercase name, used as half of a durable record's key.
    ///
    /// Written out rather than derived from the `Debug` or serde
    /// representation because it is a *storage* key: a rename of the variant
    /// must not silently orphan every record already on disk under the old
    /// name.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Respond => "respond",
            Self::Finalize => "finalize",
            Self::Claim => "claim",
            Self::RenewChannelLease => "renew_channel_lease",
            Self::RenewRegistryLease => "renew_registry_lease",
        }
    }

    /// True for the two lease renewals, which are the only steps a single exit
    /// can legitimately need more than once: a long objection window can
    /// outlive the lease bought at its start.
    pub fn is_lease_renewal(self) -> bool {
        matches!(self, Self::RenewChannelLease | Self::RenewRegistryLease)
    }
}

/// The exact next thing to do, with the exact call source that does it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvmRegistryExitPlanV1 {
    /// Nothing to sign right now. Carries why, so a screen can say something
    /// truthful instead of spinning.
    Wait { reason: String },
    /// An Action 44 contract call.
    Call {
        step: HvmRegistryExitStep,
        call_source: String,
    },
    /// The Action 14 payout, which is not a fitsh call and whose `call_source`
    /// is the canonical descriptor rather than compiled code.
    Claim {
        payee: String,
        amount_zhu: u64,
        call_source: String,
    },
}

/// How much lease this channel must still have before an exit may start.
pub fn exit_lease_floor_blocks(binding: &HvmRegistryBindingV2) -> u64 {
    binding
        .challenge_blocks
        .saturating_add(HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS)
        .saturating_add(HVM_REGISTRY_EXIT_LEASE_SLACK_BLOCKS)
}

/// Live blocks left on the six **shared** registry globals.
///
/// Separate from the channel's own twelve because the two halves are renewed
/// by two different calls, and `snapshot.minimum_live_blocks` — the minimum
/// over all eighteen — cannot tell a caller which call to make. Renewing the
/// wrong half is not a wasted fee that fixes itself on the next pass; it is a
/// loop that never terminates.
pub fn registry_lease_blocks(snapshot: &HvmRegistryLiveSnapshotV2) -> u64 {
    let registry = &snapshot.registry;
    [
        registry.g_network.live_blocks,
        registry.g_hub.live_blocks,
        registry.g_locked.live_blocks,
        registry.g_left_claimable.live_blocks,
        registry.g_hub_claimable.live_blocks,
        registry.g_open_count.live_blocks,
    ]
    .into_iter()
    .min()
    .unwrap_or_default()
}

/// Live blocks left on this channel's own twelve keys.
pub fn channel_lease_blocks(snapshot: &HvmRegistryLiveSnapshotV2) -> u64 {
    let channel = &snapshot.channel;
    [
        channel.status.live_blocks,
        channel.channel_id.live_blocks,
        channel.reuse.live_blocks,
        channel.deposit.live_blocks,
        channel.paid.live_blocks,
        channel.total.live_blocks,
        channel.serial.live_blocks,
        channel.left_balance.live_blocks,
        channel.hub_balance.live_blocks,
        channel.challenge_blocks.live_blocks,
        channel.deadline.live_blocks,
        channel.left_claimed.live_blocks,
    ]
    .into_iter()
    .min()
    .unwrap_or_default()
}

/// Decide the next exit step from the user's own evidence and a live snapshot.
///
/// The snapshot is whatever the caller's pinned fullnode returned; this
/// function never asks the Hub anything, and would behave identically with the
/// Hub's process deleted. Its inputs are the binding, the user's own stored
/// head bill and the chain.
///
/// Order matters here:
///
/// 1. the kit's signatures, because everything below is meaningless without
///    them;
/// 2. the snapshot's freshness against the node's own tip, because a stale
///    `observed_height` makes every deadline comparison a fiction
///    ([`require_fresh_registry_evidence`]);
/// 3. the lease, because starting an exit that outlives its own storage keys
///    destroys the deposit;
/// 4. only then, what the chain state actually calls for.
pub fn plan_user_exit_step(
    kit: &HvmRegistryExitKitV1,
    snapshot: &HvmRegistryLiveSnapshotV2,
    node_tip_height: u64,
    node_tip_age_seconds: u64,
) -> WalletResult<HvmRegistryExitPlanV1> {
    kit.validate_crypto().map_err(hub_error)?;
    require_fresh_registry_evidence(snapshot, node_tip_height, node_tip_age_seconds)
        .map_err(hub_error)?;
    let binding = &kit.binding;

    // Renew before anything else — but renew *the half that is actually
    // short*.
    //
    // This used to emit `renew_channel` for any short lease and then re-read
    // `snapshot.minimum_live_blocks`, which is the minimum over all eighteen
    // keys: the twelve that belong to this channel and the six the whole
    // deployment shares. `renew_channel` touches only the twelve. Measured on
    // chain, the shared globals are the binding constraint on a funded channel
    // — funding tops the channel's own keys up and leaves the globals where
    // deployment left them — so the old rule signed a renewal, paid for it,
    // watched the minimum tick *down* by one block, and planned the identical
    // renewal again. A driver looping on a fee while the clock it is trying to
    // beat runs out is worse than one that does nothing.
    //
    // The globals go first when both are short. They are shared: if they
    // lapse, every channel in the deployment becomes unreachable, not just
    // this one.
    let floor = exit_lease_floor_blocks(binding);
    if registry_lease_blocks(snapshot) < floor {
        return Ok(HvmRegistryExitPlanV1::Call {
            step: HvmRegistryExitStep::RenewRegistryLease,
            call_source: registry_renew_registry_call_source(
                binding,
                HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
            )
            .map_err(hub_error)?,
        });
    }
    if channel_lease_blocks(snapshot) < floor {
        return Ok(HvmRegistryExitPlanV1::Call {
            step: HvmRegistryExitStep::RenewChannelLease,
            call_source: registry_renew_channel_call_source(
                binding,
                HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS,
            )
            .map_err(hub_error)?,
        });
    }

    match decide_user_exit_action(snapshot, binding, &kit.latest_bill).map_err(hub_error)? {
        HvmRegistryWatchtowerDecisionV2::OpenChallengeWithLatestBill => {
            // An exit that recovers nothing is three fees spent to arrive
            // where we already are. On a one-directional rail a user who has
            // spent their whole balance holds a head bill with
            // `left_balance == 0`, which is an ordinary end state and not an
            // error — `challenge` and `finalize` both execute happily, and
            // then `settle()` marks the zero balance claimed and the Action 14
            // payout refuses `amount 0` after the money is already gone.
            // Measured: 3,603,000 zhu of fees, 3.6x the deposit, to recover
            // nothing.
            //
            // Refuse at the start, where it is still free, rather than at the
            // claim, where it is not. The channel is not stuck: closing an
            // empty channel buys nothing back, so the honest advice is to stop
            // paying rent on it rather than to pay to shut it.
            if kit.latest_bill.left_balance_zhu == 0 {
                return Ok(HvmRegistryExitPlanV1::Wait {
                    reason: "this channel holds nothing for this wallet, so closing it would \
                             spend network fees to recover zero"
                        .into(),
                });
            }
            Ok(HvmRegistryExitPlanV1::Call {
                step: HvmRegistryExitStep::Challenge,
                call_source: registry_challenge_call_source(binding, &kit.latest_bill)
                    .map_err(hub_error)?,
            })
        }
        HvmRegistryWatchtowerDecisionV2::RespondWithLatestBill => {
            // Not enough window left to build, sign, submit and still be mined
            // before `respond` closes. Spending the fee anyway buys nothing and
            // leaves the stale split standing. Refuse loudly instead — the
            // wallet's peer of the Hub's `escalate_registry_response_window`.
            if !registry_response_window_is_safe(snapshot) {
                return Err(WalletError::Policy(format!(
                    "registry challenge window is too short to answer safely: {} blocks left, {HVM_REGISTRY_RESPONSE_MARGIN_BLOCKS} required",
                    registry_response_window_blocks(snapshot)
                )));
            }
            Ok(HvmRegistryExitPlanV1::Call {
                step: HvmRegistryExitStep::Respond,
                call_source: registry_respond_call_source(binding, &kit.latest_bill)
                    .map_err(hub_error)?,
            })
        }
        HvmRegistryWatchtowerDecisionV2::Finalize => Ok(HvmRegistryExitPlanV1::Call {
            step: HvmRegistryExitStep::Finalize,
            call_source: registry_finalize_call_source(binding).map_err(hub_error)?,
        }),
        HvmRegistryWatchtowerDecisionV2::ClaimLeftPayout => {
            // The amount is read straight off live contract storage, never
            // inferred from the bill: `PermitHAC` rejects anything that is not
            // exactly `c_left_balance_`.
            let payee = binding.left_address.clone();
            let amount_zhu = snapshot.channel.left_balance.value;
            Ok(HvmRegistryExitPlanV1::Claim {
                call_source: registry_claim_payout_source(binding, &payee, amount_zhu)
                    .map_err(hub_error)?,
                payee,
                amount_zhu,
            })
        }
        HvmRegistryWatchtowerDecisionV2::NoAction => Ok(HvmRegistryExitPlanV1::Wait {
            reason: registry_wait_reason(snapshot, &kit.latest_bill),
        }),
        // Only a status this contract has no exit from reaches here now; see
        // the user-chair rules in
        // [`l2_fast_pay_hub::hvm_registry_watchtower::decide_user_exit_action`].
        // The sentence used to say the chain was newer than the wallet, and
        // said it in the one situation where the chain was *older* — the exact
        // case a hostile Hub creates on purpose by challenging with a stale
        // bill. Report the two serials instead of asserting a direction.
        HvmRegistryWatchtowerDecisionV2::RecoveryRequired => Err(WalletError::Policy(format!(
            "RecoveryRequired: this channel is in registry status {} on chain, which has no exit \
             path; the contract holds serial {} and this wallet holds serial {}",
            snapshot.channel.status.value, snapshot.channel.serial.value, kit.latest_bill.serial
        ))),
    }
}

/// How much less than its own head bill the chain would pay this wallet.
///
/// Re-exported from the Hub crate's
/// [`registry_left_payout_shortfall_zhu`] so a wallet surface can warn about a
/// smaller payout without importing the Hub's watchtower directly. `None` is
/// the ordinary answer; see that function for when it is not.
pub fn exit_payout_shortfall_zhu(
    kit: &HvmRegistryExitKitV1,
    snapshot: &HvmRegistryLiveSnapshotV2,
) -> Option<u64> {
    registry_left_payout_shortfall_zhu(snapshot, &kit.latest_bill)
}

/// Build and sign the planned step with the user's own key.
///
/// The plan's `call_source` is **re-derived here and compared**, never trusted
/// as text. A plan can be carried across a crash in a durable record, and a
/// durable record that is trusted for its own contents is not evidence of
/// anything. This is the wallet's peer of the Hub re-deriving every stored
/// call source before it signs.
pub fn build_user_exit_transaction(
    signer: &Account,
    kit: &HvmRegistryExitKitV1,
    plan: &HvmRegistryExitPlanV1,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> WalletResult<SignedHvmRegistryCallTransactionV2> {
    kit.validate_crypto().map_err(hub_error)?;
    let binding = &kit.binding;
    match plan {
        HvmRegistryExitPlanV1::Wait { reason } => Err(WalletError::Policy(format!(
            "there is no registry exit step to sign right now: {reason}"
        ))),
        HvmRegistryExitPlanV1::Call { step, call_source } => {
            let expected = match step {
                HvmRegistryExitStep::Challenge => {
                    registry_challenge_call_source(binding, &kit.latest_bill)
                }
                HvmRegistryExitStep::Respond => {
                    registry_respond_call_source(binding, &kit.latest_bill)
                }
                HvmRegistryExitStep::Finalize => registry_finalize_call_source(binding),
                HvmRegistryExitStep::RenewChannelLease => registry_renew_channel_call_source(
                    binding,
                    HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS,
                ),
                HvmRegistryExitStep::RenewRegistryLease => registry_renew_registry_call_source(
                    binding,
                    HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
                ),
                HvmRegistryExitStep::Claim => {
                    return Err(WalletError::Policy(
                        "the registry claim is an Action 14 payout, not a contract call".into(),
                    ));
                }
            }
            .map_err(hub_error)?;
            if &expected != call_source {
                return Err(WalletError::Policy(
                    "registry exit call source is not the canonical call for this step".into(),
                ));
            }
            build_signed_hvm_registry_call_transaction(
                signer,
                binding,
                // The user signing as the channel's left party. Its rule is
                // `signer == binding.left_address`, checked inside the builder;
                // the Hub's rule is untouched and still its own.
                HvmRegistryCallerRole::ChannelLeft,
                expected,
                network_fee_zhu,
                timestamp,
                gas_max,
            )
            .map_err(hub_error)
        }
        HvmRegistryExitPlanV1::Claim {
            payee,
            amount_zhu,
            call_source,
        } => {
            let expected =
                registry_claim_payout_source(binding, payee, *amount_zhu).map_err(hub_error)?;
            if &expected != call_source {
                return Err(WalletError::Policy(
                    "registry claim descriptor is not canonical for this binding".into(),
                ));
            }
            let signed = build_signed_hvm_registry_claim_transaction(
                signer,
                binding,
                HvmRegistryCallerRole::ChannelLeft,
                payee,
                *amount_zhu,
                network_fee_zhu,
                timestamp,
                gas_max,
            )
            .map_err(hub_error)?;
            // Read our own bytes back through the same reader the recovery
            // path uses, before they are handed to a node. A builder whose
            // output cannot be read exactly is not exact.
            read_exact_registry_claim_transaction(
                &signed.signed_transaction_hex,
                binding,
                payee,
                *amount_zhu,
            )
            .map_err(hub_error)?;
            Ok(signed)
        }
    }
}

fn registry_wait_reason(
    snapshot: &HvmRegistryLiveSnapshotV2,
    latest: &HvmRegistryBillV2,
) -> String {
    match snapshot.channel.status.value {
        2 => "this channel is open and nothing on chain is disputing it".into(),
        // The old single sentence claimed the standing challenge carried this
        // wallet's own bill. That is the common case and not the only one: a
        // provider can put an *older* bill on chain, which on this rail pays
        // this wallet more, and there is nothing to argue with. Saying "your
        // bill is already the one on chain" there would be a lie on the one
        // screen a person reads when they suspect they are being cheated.
        3 if snapshot.channel.serial.value == latest.serial => format!(
            "the objection window is open and this wallet's bill is already the one on chain; finalize becomes available at block {}",
            snapshot.channel.deadline.value
        ),
        3 => format!(
            "the objection window is open on a receipt this wallet did not put there; it pays this wallet {} zhu against its own receipt of {} zhu, and finalize becomes available at block {}",
            snapshot.channel.left_balance.value,
            latest.left_balance_zhu,
            snapshot.channel.deadline.value
        ),
        // Distinguish the two settled endings. `settle()` marks a zero left
        // balance claimed without paying anything, so the old single sentence
        // told a user with an empty channel that their "payout has already
        // been made" when no payout ever existed.
        4 if snapshot.channel.left_balance.value == 0 => {
            "this channel is settled with nothing owed to this wallet, so there is no payout to make"
                .into()
        }
        4 => "this channel is settled and its payout has already been made".into(),
        other => format!("registry channel status {other} needs no action from this wallet"),
    }
}

fn hub_error(error: l2_fast_pay_hub::error::HubError) -> WalletError {
    WalletError::L2(error.to_string())
}
