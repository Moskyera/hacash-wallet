//! MEASURE WHAT EACH EXIT STEP ACTUALLY COSTS, RATHER THAN ASSUMING THE
//! SMALLEST STEP FOR ALL OF THEM.
//!
//! The chain reserves gas as `budget * purity_fee / billing_size`
//! (`GasCounter::calc_burn_amount`, `hacash-fullnodedev/protocol/src/context/
//! gas.rs:124`), so a **smaller** transaction reserves **more**. The affordability
//! quote therefore needs a lower bound on the size of each transaction the exit
//! sends. It had exactly one such bound, taken from the smallest transaction of
//! a whole run, and applied it to every step - which over-stated the requirement
//! by about 17% on the smallest step and about 2.6x on the largest.
//!
//! This file is the measurement the per-step model is built from. It builds
//! every one of the six exit transactions with the shipped builder
//! (`build_user_exit_transaction`), decodes the signed bytes with the
//! fullnode's own codec and reads `billing_size()` - the exact quantity the
//! chain divides by - off the decoded transaction. Nothing here is estimated.

use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitPlanV1, HvmRegistryExitStep, build_exit_kit, build_user_exit_transaction,
};
use hacash_wallet_core::hvm_registry_exit_cost::{
    EXIT_BILLING_FLOOR_ROUNDING_BYTES, exit_gas_reserve_zhu, exit_run_ceiling_zhu,
    exit_step_billing_floor_bytes, exit_step_ceiling_zhu,
};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HvmRegistryBillV2, HvmRegistryBindingV2,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS, HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
    registry_challenge_call_source, registry_claim_payout_source, registry_finalize_call_source,
    registry_renew_channel_call_source, registry_renew_registry_call_source,
    registry_respond_call_source,
};
use sys::Account;
use vm::ContractAddress;

/// The fee every exit step is signed with: `MAX_CHANNEL_NETWORK_FEE_ZHU`, the
/// same constant the driver spends and the screen quotes.
const NETWORK_FEE_ZHU: u64 = l2_fast_pay_hub::l1_channel::MAX_CHANNEL_NETWORK_FEE_ZHU;

fn binding_for(
    left: &Account,
    hub: &Account,
    contract: [u8; 20],
    deposit_zhu: u64,
) -> HvmRegistryBindingV2 {
    HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: "11".repeat(32),
        contract_address: ContractAddress::from_unchecked(Address::create_contract(contract))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: "33".repeat(16),
        reuse_version: 0,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*hub.address()).to_readable(),
        left_deposit_zhu: deposit_zhu,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    }
}

fn sign_bill(
    binding: &HvmRegistryBindingV2,
    left: &Account,
    hub: &Account,
    serial: u64,
    left_balance_zhu: u64,
    hub_balance_zhu: u64,
) -> HvmRegistryBillV2 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial,
        left_balance_zhu,
        hub_balance_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    bill
}

/// The exact number the chain divides the gas budget by, read off this
/// wallet's own signed bytes with the fullnode's own decoder.
fn measured_billing_size(signed_transaction_hex: &str) -> u64 {
    let raw = hex::decode(signed_transaction_hex).expect("the builder returns hex");
    let (tx, consumed) =
        protocol::transaction::transaction_create(&raw).expect("the chain can read our own bytes");
    assert_eq!(consumed, raw.len(), "trailing bytes");
    tx.billing_size().expect("billing size") as u64
}

/// Build one step for one channel and return the billing size of the signed
/// bytes.
#[allow(clippy::too_many_arguments)]
fn step_billing_size(
    step: HvmRegistryExitStep,
    left: &Account,
    hub: &Account,
    contract: [u8; 20],
    serial: u64,
    left_balance_zhu: u64,
    hub_balance_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
) -> Option<u64> {
    let binding = binding_for(left, hub, contract, left_balance_zhu + hub_balance_zhu);
    let bill = sign_bill(
        &binding,
        left,
        hub,
        serial,
        left_balance_zhu,
        hub_balance_zhu,
    );
    let kit = build_exit_kit(binding.clone(), bill.clone()).expect("the kit verifies");
    let plan = match step {
        HvmRegistryExitStep::Challenge => HvmRegistryExitPlanV1::Call {
            step,
            call_source: registry_challenge_call_source(&binding, &bill).unwrap(),
        },
        HvmRegistryExitStep::Respond => HvmRegistryExitPlanV1::Call {
            step,
            call_source: registry_respond_call_source(&binding, &bill).unwrap(),
        },
        HvmRegistryExitStep::Finalize => HvmRegistryExitPlanV1::Call {
            step,
            call_source: registry_finalize_call_source(&binding).unwrap(),
        },
        HvmRegistryExitStep::RenewChannelLease => HvmRegistryExitPlanV1::Call {
            step,
            call_source: registry_renew_channel_call_source(
                &binding,
                HVM_REGISTRY_RENEW_CHANNEL_MAX_PERIODS,
            )
            .unwrap(),
        },
        HvmRegistryExitStep::RenewRegistryLease => HvmRegistryExitPlanV1::Call {
            step,
            call_source: registry_renew_registry_call_source(
                &binding,
                HVM_REGISTRY_RENEW_REGISTRY_MAX_PERIODS,
            )
            .unwrap(),
        },
        HvmRegistryExitStep::Claim => HvmRegistryExitPlanV1::Claim {
            payee: binding.left_address.clone(),
            amount_zhu: left_balance_zhu,
            call_source: registry_claim_payout_source(
                &binding,
                &binding.left_address,
                left_balance_zhu,
            )
            .ok()?,
        },
    };
    let signed =
        build_user_exit_transaction(left, &kit, &plan, network_fee_zhu, timestamp, u8::MAX).ok()?;
    Some(measured_billing_size(&signed.signed_transaction_hex))
}

/// The measured minimum and maximum billing size of every exit step, over
/// every input that can change it.
fn measure(step: HvmRegistryExitStep) -> (u64, u64) {
    // The only inputs that can shorten one of these transactions. The compiled
    // call carries addresses as 21-byte literals, so the parties cannot change
    // a size; the bill serial, the two balances and the payout amount are
    // numeric literals and an on-wire `Amount`, and they can.
    let bills: [(u64, u64, u64); 5] = [
        (1, 1, 0),
        (1, 1, u64::MAX - 1),
        (3, 900_000, 100_000),
        (u64::MAX, 9_000_000_000_000_000_000, 1_000_000_000_000_000),
        (u64::MAX, u64::MAX - 1, 1),
    ];
    let mut smallest = u64::MAX;
    let mut largest = 0;
    for index in 0..24u8 {
        let left = Account::create_by(&format!("exit-size-left-{index}")).unwrap();
        let hub = Account::create_by(&format!("exit-size-hub-{index}")).unwrap();
        // Two timestamps a decade apart, because the timestamp is part of the
        // signed bytes.
        for timestamp in [1_600_000_000_u64, 1_900_000_000] {
            for (serial, left_balance, hub_balance) in bills {
                let Some(size) = step_billing_size(
                    step,
                    &left,
                    &hub,
                    [index; 20],
                    serial,
                    left_balance,
                    hub_balance,
                    NETWORK_FEE_ZHU,
                    timestamp,
                ) else {
                    // The claim refuses an amount an on-wire `Amount` cannot
                    // carry exactly. A step that cannot be built cannot be
                    // charged for either, so it is not a size.
                    continue;
                };
                smallest = smallest.min(size);
                largest = largest.max(size);
            }
        }
    }
    assert!(
        smallest < u64::MAX,
        "no size was measured for {}",
        step.slug()
    );
    (smallest, largest)
}

/// THE MEASUREMENT. Every floor the affordability quote is built from must sit
/// at or below a size the shipped builders actually produce, and within the
/// rounding the model documents.
///
/// Both bounds matter and they guard opposite mistakes. A floor **above** the
/// measured size under-states the gas the chain reserves, which is what sends
/// an owner into a two-step irreversible press whose first transaction cannot
/// execute. A floor far **below** it over-states what the owner must hold,
/// which is what shows a red precondition to somebody who could in fact
/// finish: the exact defect this per-step model was written to remove, and one
/// that would come straight back if a later edit quietly dropped a floor.
#[test]
fn every_exit_step_is_priced_from_its_own_measured_bytes() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    // The minima recorded in `hvm_registry_exit_cost.rs`. Equality, not a
    // bound: if a builder change moves a size, the quote has to be re-measured
    // rather than silently carried forward.
    let recorded: [(HvmRegistryExitStep, u64, u64); 6] = [
        (HvmRegistryExitStep::Challenge, 414, 443),
        (HvmRegistryExitStep::Respond, 414, 443),
        (HvmRegistryExitStep::Finalize, 210, 210),
        (HvmRegistryExitStep::Claim, 209, 216),
        (HvmRegistryExitStep::RenewChannelLease, 214, 214),
        (HvmRegistryExitStep::RenewRegistryLease, 187, 187),
    ];
    for (step, expected_min, expected_max) in recorded {
        let (smallest, largest) = measure(step);
        println!(
            "{:>22}  measured min {smallest}  max {largest}  floor {}  ceiling {} zhu",
            step.slug(),
            exit_step_billing_floor_bytes(step),
            exit_step_ceiling_zhu(step, NETWORK_FEE_ZHU)
        );
        assert_eq!(
            (smallest, largest),
            (expected_min, expected_max),
            "{} no longer encodes to the sizes the fee quote was measured from",
            step.slug()
        );
        let floor = exit_step_billing_floor_bytes(step);
        assert!(
            floor <= smallest,
            "{}: the quote assumes {floor} billing bytes but the builder produced {smallest}; a \
             floor above the real size under-states the gas the chain reserves",
            step.slug()
        );
        assert!(
            smallest - floor <= EXIT_BILLING_FLOOR_ROUNDING_BYTES,
            "{}: the quote assumes {floor} billing bytes against a measured {smallest}, which \
             over-states what the owner must hold by more than this model documents",
            step.slug()
        );
    }
}

/// What the whole quote comes to, stated against what it replaced.
///
/// The old model applied one flat 160-byte assumption to all three
/// transactions of an ordinary run. Every step's real size is larger than
/// that, so every per-step number is smaller - but the run quote must still
/// cover, step by step, what the chain can actually take at each step's
/// measured size. Both halves are asserted here, because dropping either one
/// is how a quote becomes a story.
#[test]
fn the_run_quote_covers_every_step_and_is_tighter_than_the_flat_assumption() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let old_flat_run = 3 * (NETWORK_FEE_ZHU + exit_gas_reserve_zhu(160, NETWORK_FEE_ZHU));
    let run = exit_run_ceiling_zhu(NETWORK_FEE_ZHU);
    println!("  run quote {run} zhu, against the flat-assumption {old_flat_run} zhu");
    assert!(
        run < old_flat_run,
        "the per-step quote {run} is not tighter than the flat one {old_flat_run}"
    );
    // Every step of the ordinary run, priced at the size that step actually
    // encoded to in the measurement, is covered.
    let mut true_cost = 0;
    for step in [
        HvmRegistryExitStep::Challenge,
        HvmRegistryExitStep::Finalize,
        HvmRegistryExitStep::Claim,
    ] {
        let (smallest, _) = measure(step);
        true_cost += NETWORK_FEE_ZHU + exit_gas_reserve_zhu(smallest, NETWORK_FEE_ZHU);
    }
    assert!(
        run >= true_cost,
        "the quote {run} does not cover what the chain can take at the measured sizes: {true_cost}"
    );
    println!("  the chain can take at most {true_cost} zhu at the measured sizes");
}
