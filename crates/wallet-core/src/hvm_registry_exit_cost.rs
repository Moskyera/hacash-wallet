//! What each step of a unilateral exit can take out of the owner's main
//! balance, priced per step from measured bytes.
//!
//! # Why a per-step model and not one number
//!
//! The chain does not charge gas per transaction. `GasCounter::calc_burn_amount`
//! (`hacash-fullnodedev/protocol/src/context/gas.rs:124`) computes
//! `ceil(budget * purity_fee / billing_size)`, and `ContextInst::gas_initialize`
//! (same file, line 279) takes that whole amount out of the sender's main
//! balance with `hac_sub` *before* the call runs, refunding the unused part in
//! `gas_refund`. Because `billing_size` is the denominator, a **smaller**
//! transaction reserves **more**: the number an owner must be able to hold is
//! largest for the shortest transaction the exit sends.
//!
//! The first version of this quote had exactly one size bound - the smallest
//! transaction observed anywhere in a whole run - and applied it to every step.
//! That is right in direction and wrong in size: it over-stated the requirement
//! by about 17% on the smallest step and about 2.6x on the largest, and an
//! over-quote shows a red affordability precondition to an owner who could in
//! fact complete the exit.
//!
//! So each step now carries its own floor, and each floor is a *measurement*:
//! `crates/wallet-core/tests/exit_fee_quote_per_step.rs` builds every one of
//! the six exit transactions with the shipped builder, decodes the signed bytes
//! with the fullnode's own codec and reads `billing_size()` off the decoded
//! transaction, across the full range of the only inputs that can shorten one.
//! That test is the authority for every number below and it fails if a floor is
//! ever set above what the builders actually produce.
//!
//! # Which direction the remaining slack runs in
//!
//! Down, always. Every floor is the measured minimum rounded **down** to the
//! next multiple of [`EXIT_BILLING_FLOOR_ROUNDING_BYTES`], because a floor
//! below the truth over-states the reserve and a floor above it under-states
//! the reserve. Only the second kind walks somebody into a two-step
//! irreversible press whose first transaction cannot execute.

use crate::hvm_registry_exit::HvmRegistryExitStep;

/// The gas budget the chain actually grants one exit transaction.
///
/// `decode_gas_budget(gas_max_byte.min(TX_GAS_BUDGET_CAP_BYTE))` in
/// `hacash-fullnodedev/protocol/src/transaction/type3.rs`, with
/// `TX_GAS_BUDGET_CAP_BYTE = 99` and `decode_gas_budget(99) == 111911`
/// (`protocol/src/context/gas.rs:47`). Asking for a higher `gas_max` does not
/// raise it: the chain clamps, and every exit step is built with
/// `gas_max = u8::MAX`.
pub const HVM_REGISTRY_EXIT_GAS_BUDGET: u64 = 111_911;

/// The chain's own floor on fee purity, in unit-238 per billing byte.
/// `VM_LOWEST_FEE_PURITY` in `hacash-fullnodedev/protocol/src/params.rs`.
pub const HVM_REGISTRY_EXIT_LOWEST_FEE_PURITY_UNIT238: u64 = 50_000;

/// Unit-238 amounts per zhu. `protocol/src/params.rs` records the conversion
/// in its own words: "50000:238 == 100:244 == 0.000005 HAC per byte", and one
/// zhu is 1e-8 HAC, so one zhu is a hundred unit-238.
const UNIT238_PER_ZHU: u64 = 100;

/// How far below its measured minimum each step's billing floor is rounded.
///
/// Small on purpose. The point of the floors is to stop guessing, and a large
/// rounding is a guess wearing a measurement's clothes; the point of rounding
/// *down* rather than to nearest is that the error then has only one sign, and
/// it is the sign that over-quotes.
pub const EXIT_BILLING_FLOOR_ROUNDING_BYTES: u64 = 8;

/// The smallest this step's signed transaction is known to encode to, in
/// canonical billing bytes.
///
/// Measured, not assumed. Every value here is the minimum
/// `protocol::TransactionRead::billing_size` observed over the whole range of
/// inputs that can shorten the step - bill serial, both balances, the payout
/// amount, the channel and its parties - rounded down by
/// [`EXIT_BILLING_FLOOR_ROUNDING_BYTES`]. The measurements, at the shipped
/// network fee of `MAX_CHANNEL_NETWORK_FEE_ZHU`, were:
///
/// | step                  | measured min | measured max | floor |
/// |-----------------------|--------------|--------------|-------|
/// | challenge             | 414          | 443          | 408   |
/// | respond               | 414          | 443          | 408   |
/// | finalize              | 210          | 210          | 208   |
/// | claim                 | 209          | 216          | 208   |
/// | renew_channel_lease   | 214          | 214          | 208   |
/// | renew_registry_lease  | 187          | 187          | 184   |
///
/// The renewals and `finalize` do not vary at all: their compiled call carries
/// no bill numbers, and the addresses inside it are 21-byte literals rather
/// than text. `challenge` and `respond` carry the serial and both balances as
/// decimal literals, and `claim` carries an on-wire `Amount`, which is why
/// those three have a range at all.
///
/// The single flat 160 this quote used before was taken from one run's
/// smallest transaction (187, a registry renewal) and rounded down hard. It
/// was never wrong about any *one* step; it was wrong to be the only number.
pub const fn exit_step_billing_floor_bytes(step: HvmRegistryExitStep) -> u64 {
    match step {
        HvmRegistryExitStep::Challenge => 408,
        HvmRegistryExitStep::Respond => 408,
        HvmRegistryExitStep::Finalize => 208,
        HvmRegistryExitStep::Claim => 208,
        HvmRegistryExitStep::RenewChannelLease => 208,
        HvmRegistryExitStep::RenewRegistryLease => 184,
    }
}

/// What the chain takes out of the owner's main balance before a transaction
/// of this size runs, over and above the network fee.
///
/// Mirrors `GasCounter::calc_burn_amount` exactly: `ceil(budget * purity_fee /
/// purity_size)` with `purity_fee = max(raw_fee, floor * size)` and the result
/// converted up to whole zhu, because a balance that cannot cover the reserve
/// fails the transaction outright.
///
/// A zero size is not a cheap transaction, it is a size nobody measured, so it
/// answers with the largest number rather than the smallest.
pub const fn exit_gas_reserve_zhu(billing_size_bytes: u64, network_fee_zhu: u64) -> u64 {
    if billing_size_bytes == 0 {
        return u64::MAX;
    }
    let raw_fee_238 = network_fee_zhu.saturating_mul(UNIT238_PER_ZHU);
    let floor_fee_238 =
        HVM_REGISTRY_EXIT_LOWEST_FEE_PURITY_UNIT238.saturating_mul(billing_size_bytes);
    let purity_fee_238 = if raw_fee_238 > floor_fee_238 {
        raw_fee_238
    } else {
        floor_fee_238
    };
    let reserve_238 = HVM_REGISTRY_EXIT_GAS_BUDGET
        .saturating_mul(purity_fee_238)
        .div_ceil(billing_size_bytes);
    reserve_238.div_ceil(UNIT238_PER_ZHU)
}

/// The smallest network fee the chain will accept for a transaction of this
/// billing size, in zhu.
///
/// # Why a fee floor exists at all, separately from the gas reserve
///
/// `GasPrice::from_tx` (`hacash-fullnodedev/protocol/src/context/gas.rs:62-67`)
/// prices gas at `max(raw_fee, vm_lowest_fee_purity(height) * billing_size)`.
/// A transaction that pays less than the floor is not cheaper to run: the chain
/// prices it *as if* it had paid the floor, and it still has to get into a
/// block. `mint/src/api/submit_transaction.rs:44` and `node/src/core/protocol.
/// rs:372` both drop a transaction whose `fee_purity()` is under the node's
/// configured `lowest_fee_purity` before it is ever relayed.
///
/// This is a floor and not an estimate. It is what the chain will not go below;
/// it says nothing about what a congested mempool would actually clear. See
/// `MAX_CHANNEL_NETWORK_FEE_ZHU` for the margin between the two and for what
/// is still missing.
pub const fn minimum_network_fee_zhu(billing_size_bytes: u64) -> u64 {
    HVM_REGISTRY_EXIT_LOWEST_FEE_PURITY_UNIT238
        .saturating_mul(billing_size_bytes)
        .div_ceil(UNIT238_PER_ZHU)
}

/// The gas this one step can reserve, at its own measured floor.
pub const fn exit_step_gas_reserve_zhu(step: HvmRegistryExitStep, network_fee_zhu: u64) -> u64 {
    exit_gas_reserve_zhu(exit_step_billing_floor_bytes(step), network_fee_zhu)
}

/// Everything this one step can take from the owner's main balance: its
/// network fee, plus the gas the chain reserves before it runs.
pub const fn exit_step_ceiling_zhu(step: HvmRegistryExitStep, network_fee_zhu: u64) -> u64 {
    network_fee_zhu.saturating_add(exit_step_gas_reserve_zhu(step, network_fee_zhu))
}

/// The steps an ordinary exit sends, in order.
///
/// `Respond` is not here and neither renewal is: a response only happens if
/// the provider objects, and a renewal only if the channel's storage lease is
/// short. Both are conditional, both are named separately on the screen, and
/// both are priced by [`exit_largest_step_ceiling_zhu`], which is what "one
/// more transaction at the same ceiling" means there.
pub const EXIT_RUN_STEPS: [HvmRegistryExitStep; 3] = [
    HvmRegistryExitStep::Challenge,
    HvmRegistryExitStep::Finalize,
    HvmRegistryExitStep::Claim,
];

/// What the three ordinary steps cost together, and nothing else.
///
/// This is *not* the number to gate an irreversible press on — see
/// [`exit_worst_press_ceiling_zhu`] for that. It is published so a screen can
/// tell an owner what the ordinary path costs, which is the number the per-step
/// measurement made honest and which used to be over-stated by 56%.
///
/// A sum rather than a maximum, and deliberately so. The fees are spent for
/// good, and while each step's gas reserve is taken and refunded one step at a
/// time, an owner who can cover all three at once can certainly cover them in
/// sequence. That is conservative in the direction this number has to be
/// conservative in.
pub const fn exit_run_ceiling_zhu(network_fee_zhu: u64) -> u64 {
    let mut total = 0_u64;
    let mut index = 0;
    while index < EXIT_RUN_STEPS.len() {
        total = total.saturating_add(exit_step_ceiling_zhu(
            EXIT_RUN_STEPS[index],
            network_fee_zhu,
        ));
        index += 1;
    }
    total
}

/// Every step an exit can send, ordinary or conditional.
pub const EXIT_ALL_STEPS: [HvmRegistryExitStep; 6] = [
    HvmRegistryExitStep::Challenge,
    HvmRegistryExitStep::Respond,
    HvmRegistryExitStep::Finalize,
    HvmRegistryExitStep::Claim,
    HvmRegistryExitStep::RenewChannelLease,
    HvmRegistryExitStep::RenewRegistryLease,
];

/// The most any single exit transaction can take from the main balance.
///
/// This is the number behind "each one can take up to", and it is taken over
/// *all* steps rather than only the three an ordinary run sends. The largest
/// is a registry lease renewal, which is the shortest transaction the exit can
/// send and therefore the one that reserves the most gas. Quoting the run's
/// own maximum instead would understate exactly the step the screen tells an
/// owner to expect as an extra.
pub const fn exit_largest_step_ceiling_zhu(network_fee_zhu: u64) -> u64 {
    let mut largest = 0_u64;
    let mut index = 0;
    while index < EXIT_ALL_STEPS.len() {
        let ceiling = exit_step_ceiling_zhu(EXIT_ALL_STEPS[index], network_fee_zhu);
        if ceiling > largest {
            largest = ceiling;
        }
        index += 1;
    }
    largest
}

/// What an owner must be able to hold before pressing: every step one press can
/// send, each at its own measured size.
///
/// # The hole this closes
///
/// The affordability precondition used to be [`exit_run_ceiling_zhu`], the
/// three ordinary steps. A press is not always three steps.
/// `HvmRegistryExitDriver`'s planner
/// (`crates/wallet-core/src/hvm_registry_exit.rs`) renews the *registry* lease
/// first when it is short, then re-plans and renews the *channel* lease when
/// that one is short, and only then challenges; it can also plan `Respond`.
/// Each of those is a real transaction inside the same press, out of the same
/// balance.
///
/// So an owner holding exactly the three-step quote, whose lease happened to be
/// short, would pass the precondition, clear the renewal and the challenge, and
/// then be unable to pay for `finalize` - stranded mid-press with the objection
/// window already running. That is the exact failure the quote exists to
/// prevent, moved from the first transaction to the third.
///
/// # Why the whole sum, and not a maximum
///
/// The gas reserve is taken and refunded per transaction, so a run *usually*
/// needs only the largest single ceiling. But the burn is only refunded to the
/// extent it is unused, and nothing here measures how much of the budget each
/// call actually burns. Bounded by what the chain can take, the balance needed
/// before step `k` is `sum(ceilings before k) + ceiling(k)`, whose maximum over
/// the sequence is the sum of every ceiling. Guessing at a smaller burn is the
/// mistake this module was written to undo, so the bound is used as the bound.
///
/// # What is deliberately conservative here
///
/// `Challenge` and `Respond` are both counted, though one press very likely
/// sends only one of them: the user challenges from status OPEN and responds
/// only to a challenge someone else opened. That is a reading of the contract's
/// state machine, not a measurement, and it is worth 275,291,667 zhu at the
/// shipped fee. Over-stating by one step shows a red precondition to somebody
/// who could have finished; under-stating strands somebody mid-press. Only the
/// second is unrecoverable, so the unproven case is counted in.
pub const fn exit_worst_press_ceiling_zhu(network_fee_zhu: u64) -> u64 {
    let mut total = 0_u64;
    let mut index = 0;
    while index < EXIT_ALL_STEPS.len() {
        total = total.saturating_add(exit_step_ceiling_zhu(
            EXIT_ALL_STEPS[index],
            network_fee_zhu,
        ));
        index += 1;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The formula is the chain's, so it is checked against the chain's own
    /// arithmetic rather than against itself: at 111,911 budget, a 1,000,000
    /// zhu fee and a 408-byte transaction, `calc_burn_amount` computes
    /// `ceil(111911 * 100000000 / 408) = 27,429,166,667` unit-238, which is
    /// 274,291,667 zhu once rounded up to whole zhu.
    #[test]
    fn the_reserve_is_the_chains_own_ceiling_division() {
        assert_eq!(exit_gas_reserve_zhu(408, 1_000_000), 274_291_667);
        assert_eq!(exit_gas_reserve_zhu(208, 1_000_000), 538_033_654);
        assert_eq!(exit_gas_reserve_zhu(184, 1_000_000), 608_211_957);
        // The old flat assumption, kept as arithmetic so the size the quote
        // used to apply to every step is still legible next to the ones it
        // applies now.
        assert_eq!(exit_gas_reserve_zhu(160, 1_000_000), 699_443_750);
    }

    /// A shorter transaction must never quote a smaller reserve. This is the
    /// property the whole module exists to preserve, and it is the one a
    /// future edit to the floors could break silently.
    #[test]
    fn a_shorter_transaction_never_reserves_less() {
        let mut previous = 0;
        for size in (160..=460).rev() {
            let reserve = exit_gas_reserve_zhu(size, 1_000_000);
            assert!(
                reserve >= previous,
                "reserve fell as the transaction got shorter at {size} bytes"
            );
            previous = reserve;
        }
        assert_eq!(exit_gas_reserve_zhu(0, 1_000_000), u64::MAX);
    }

    /// The run quote is the three ordinary steps and nothing else, and the
    /// per-transaction ceiling is the largest of all six.
    #[test]
    fn the_run_quote_is_the_sum_of_its_own_measured_steps() {
        let fee = 1_000_000;
        let expected = exit_step_ceiling_zhu(HvmRegistryExitStep::Challenge, fee)
            + exit_step_ceiling_zhu(HvmRegistryExitStep::Finalize, fee)
            + exit_step_ceiling_zhu(HvmRegistryExitStep::Claim, fee);
        assert_eq!(exit_run_ceiling_zhu(fee), expected);
        assert_eq!(exit_run_ceiling_zhu(fee), 1_353_358_975);
        assert_eq!(
            exit_largest_step_ceiling_zhu(fee),
            exit_step_ceiling_zhu(HvmRegistryExitStep::RenewRegistryLease, fee),
            "the shortest transaction the exit can send reserves the most gas"
        );
        assert_eq!(exit_largest_step_ceiling_zhu(fee), 609_211_957);
    }

    /// The press quote has to survive being walked, one transaction at a time,
    /// down every sequence the planner can actually produce.
    ///
    /// This is the regression test for a real hole: the affordability
    /// precondition was the three-step [`exit_run_ceiling_zhu`], and an owner
    /// holding exactly that, whose registry lease was short, cleared the
    /// renewal and the challenge and then could not pay for `finalize`. The
    /// walk below is the chain's own rule - before each transaction the balance
    /// must cover that transaction's fee plus the whole reserve, and what the
    /// previous transactions took is gone - so it fails the way the chain
    /// fails, at the step where the money runs out.
    #[test]
    fn the_press_quote_survives_every_sequence_the_planner_can_send() {
        let fee = 1_000_000;
        let quote = exit_worst_press_ceiling_zhu(fee);

        // The orderings `plan_user_exit_step` can walk. The registry lease is
        // renewed before the channel lease and both before the challenge; a
        // press either opens a challenge or answers one; finalize and claim
        // always follow.
        let sequences: [&[HvmRegistryExitStep]; 6] = [
            &EXIT_RUN_STEPS,
            &[
                HvmRegistryExitStep::Respond,
                HvmRegistryExitStep::Finalize,
                HvmRegistryExitStep::Claim,
            ],
            &[
                HvmRegistryExitStep::RenewRegistryLease,
                HvmRegistryExitStep::Challenge,
                HvmRegistryExitStep::Finalize,
                HvmRegistryExitStep::Claim,
            ],
            &[
                HvmRegistryExitStep::RenewChannelLease,
                HvmRegistryExitStep::Challenge,
                HvmRegistryExitStep::Finalize,
                HvmRegistryExitStep::Claim,
            ],
            &[
                HvmRegistryExitStep::RenewRegistryLease,
                HvmRegistryExitStep::RenewChannelLease,
                HvmRegistryExitStep::Challenge,
                HvmRegistryExitStep::Finalize,
                HvmRegistryExitStep::Claim,
            ],
            &EXIT_ALL_STEPS,
        ];

        for sequence in sequences {
            // What the balance has to be, before the first transaction, for
            // every transaction in this sequence to execute at full burn.
            let mut spent = 0_u64;
            let mut needed = 0_u64;
            for step in sequence {
                needed = needed.max(spent + exit_step_ceiling_zhu(*step, fee));
                spent += exit_step_ceiling_zhu(*step, fee);
            }
            assert!(
                quote >= needed,
                "a press that sends {sequence:?} needs {needed} zhu held up front and the quote \
                 is {quote}: an owner would pass the affordability precondition and stall \
                 part-way through an irreversible press"
            );
        }

        // And the hole this closes was real, not hypothetical: the three-step
        // quote does not survive the shortest renewal sequence.
        let renewal_then_run = exit_step_ceiling_zhu(HvmRegistryExitStep::RenewRegistryLease, fee)
            + exit_run_ceiling_zhu(fee);
        assert!(
            exit_run_ceiling_zhu(fee) < renewal_then_run,
            "the three-step quote is being asserted to cover a sequence it never covered"
        );
        assert!(quote >= renewal_then_run);
        assert_eq!(quote, 2_776_896_253);
    }

    /// Tightening a quote that guards an irreversible press is only allowed to
    /// move in one direction from the measurement. Every floor must sit at or
    /// below the size that was actually measured, and within the documented
    /// rounding of it - so it can be conservative, but not silently
    /// arbitrarily so.
    ///
    /// The measured minima themselves live in
    /// `tests/exit_fee_quote_per_step.rs`, which builds the transactions; this
    /// is the same pair of bounds stated where the constants are, so a floor
    /// edited here without re-running the measurement fails immediately.
    #[test]
    fn every_floor_sits_just_under_a_measured_size() {
        for (step, measured) in [
            (HvmRegistryExitStep::Challenge, 414),
            (HvmRegistryExitStep::Respond, 414),
            (HvmRegistryExitStep::Finalize, 210),
            (HvmRegistryExitStep::Claim, 209),
            (HvmRegistryExitStep::RenewChannelLease, 214),
            (HvmRegistryExitStep::RenewRegistryLease, 187),
        ] {
            let floor = exit_step_billing_floor_bytes(step);
            assert!(
                floor <= measured,
                "{}: floor {floor} is above the measured {measured}, so the quote under-states \
                 the gas reserve",
                step.slug()
            );
            assert!(
                measured - floor <= EXIT_BILLING_FLOOR_ROUNDING_BYTES,
                "{}: floor {floor} is {} bytes under the measured {measured}, which is more \
                 slack than this model documents",
                step.slug(),
                measured - floor
            );
        }
    }
}
