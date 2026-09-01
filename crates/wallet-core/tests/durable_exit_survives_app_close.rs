//! The exit has to survive the app closing.
//!
//! The arbitration window is `binding.challenge_blocks` plus the response
//! margin plus the lease slack, measured in blocks at a 300s target: hours. A
//! laptop lid closing between `challenge` and the Action 14 claim is the
//! ordinary case on this rail, not the edge case.
//!
//! Before this test's subject existed there was no durable per-step record
//! anywhere — `PersistedHvmRegistryExit`, `exit_operation` and `ExitStep`
//! matched nothing under `crates/agent-wallet-core` or
//! `crates/wallet-core/src/l2_safety.rs` — while
//! `apps/desktop/src/agent/AgentAdminPages.tsx:591` already told the owner the
//! exit "continues from where it left off if this wallet is closed".
//!
//! Every close below is a real one: the `ClientL2Safety` is dropped, which
//! releases its exclusive lock and its whole in-memory state, and the store is
//! reopened from disk exactly as a restarted process would open it.
//!
//! Nothing here weakens or edits production code. It asks the shipped
//! functions what they do.

use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep, build_exit_kit,
    build_user_exit_transaction, plan_user_exit_step,
};
use hacash_wallet_core::hvm_registry_exit_record::{
    HvmRegistryExitIntentV1, HvmRegistryExitPhase, HvmRegistryExitResumeV1,
    validate_persisted_exit_step,
};
use hacash_wallet_core::l2_safety::ClientL2Safety;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use vm::ContractAddress;

const DEPOSIT_ZHU: u64 = 1_000_000;
const FEE_ZHU: u64 = 10_000;
const GAS_MAX: u8 = 250;

struct Fixture {
    wallet: WalletAccount,
    hub: Account,
    binding: HvmRegistryBindingV2,
    root: tempfile::TempDir,
}

impl Fixture {
    /// Open the wallet's own L2 store exactly the way a process start opens
    /// it: same root, same scope, same network, same channel key.
    fn open_store(&self) -> ClientL2Safety {
        ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.wallet,
            self.root.path(),
            "personal:durable-exit-test",
            "testnet",
            &self.binding.right_hub_address,
            &self.binding.commitment().unwrap(),
        )
        .expect("the wallet's own L2 store opens")
    }

    fn signer(&self) -> &Account {
        self.wallet.inner()
    }
}

fn fixture() -> Fixture {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let wallet = WalletAccount::create("durable-exit-left").unwrap();
    let hub = Account::create_by("durable-exit-hub").unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: "11".repeat(32),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([9; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: "33".repeat(16),
        reuse_version: 0,
        left_address: wallet.address(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    Fixture {
        wallet,
        hub,
        binding,
        root: tempfile::tempdir().expect("tempdir"),
    }
}

fn kit_at(f: &Fixture, serial: u64, left_zhu: u64, hub_zhu: u64) -> HvmRegistryExitKitV1 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: f.binding.commitment().unwrap(),
        serial,
        left_balance_zhu: left_zhu,
        hub_balance_zhu: hub_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&f.binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(f.signer(), &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(&f.hub, &hash).serialize());
    build_exit_kit(f.binding.clone(), bill).expect("kit must verify")
}

fn entry<T>(value: T, live_blocks: u64) -> HvmStorageEntry<T> {
    HvmStorageEntry {
        value,
        live_blocks,
        recover_blocks: 100,
        active: true,
        recoverable: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    binding: &HvmRegistryBindingV2,
    status: u8,
    serial: u64,
    left_balance_zhu: u64,
    hub_balance_zhu: u64,
    observed_height: u64,
    deadline: u64,
    minimum_live_blocks: u64,
) -> HvmRegistryLiveSnapshotV2 {
    HvmRegistryLiveSnapshotV2 {
        ret: 0,
        schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        chain_id: binding.chain_id,
        network_instance_id: binding.network_instance_id.clone(),
        observed_height,
        evaluation_height: observed_height + 1,
        contract_address: binding.contract_address.clone(),
        deployment_tx_hash: binding.deployment_tx_hash.clone(),
        deployment_height: binding.deployment_height,
        deployment_action_verified: true,
        bytecode_sha3: binding.bytecode_sha3.clone(),
        hub_address: binding.right_hub_address.clone(),
        left_address: binding.left_address.clone(),
        registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
        channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
        all_keys_active: true,
        minimum_live_blocks,
        minimum_recover_blocks: 100,
        registry: HvmRegistryGlobalStorageV2 {
            g_network: entry(binding.network_instance_id.clone(), minimum_live_blocks),
            g_hub: entry(binding.right_hub_address.clone(), minimum_live_blocks),
            g_locked: entry(binding.left_deposit_zhu, minimum_live_blocks),
            g_left_claimable: entry(0, minimum_live_blocks),
            g_hub_claimable: entry(0, minimum_live_blocks),
            g_open_count: entry(1, minimum_live_blocks),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(status, minimum_live_blocks),
            channel_id: entry(binding.channel_id.clone(), minimum_live_blocks),
            reuse: entry(binding.reuse_version, minimum_live_blocks),
            deposit: entry(binding.left_deposit_zhu, minimum_live_blocks),
            paid: entry(binding.left_deposit_zhu, minimum_live_blocks),
            total: entry(binding.left_deposit_zhu, minimum_live_blocks),
            serial: entry(serial, minimum_live_blocks),
            left_balance: entry(left_balance_zhu, minimum_live_blocks),
            hub_balance: entry(hub_balance_zhu, minimum_live_blocks),
            challenge_blocks: entry(binding.challenge_blocks, minimum_live_blocks),
            deadline: entry(deadline, minimum_live_blocks),
            left_claimed: entry(false, minimum_live_blocks),
        },
    }
}

fn hash64(byte: u8) -> String {
    hex::encode([byte; 32])
}

// ===========================================================================
// 1. The whole point: a challenge signed, then the app closes, then the app
//    reopens and does NOT sign a second transaction for the same step.
// ===========================================================================
#[test]
fn a_challenge_signed_before_the_app_closed_is_never_signed_again() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);
    let plan = plan_user_exit_step(&kit, &snap, 500, 10).unwrap();
    assert!(matches!(
        plan,
        HvmRegistryExitPlanV1::Call {
            step: HvmRegistryExitStep::Challenge,
            ..
        }
    ));

    // --- session one -----------------------------------------------------
    let first_timestamp = 1_700_000_000;
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &snap, FEE_ZHU, first_timestamp, GAS_MAX)
            .expect("the plan and its snapshot become a durable intent");
    let mut store = f.open_store();
    let opened = store
        .begin_or_resume_exit_step(&kit, &intent)
        .expect("a fresh step is recorded");
    assert!(matches!(opened, HvmRegistryExitResumeV1::SignFresh { .. }));

    // The possibility of a signature is durable BEFORE the key is used.
    store
        .mark_exit_step_signature_may_exist(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Challenge,
        )
        .expect("the signer is announced first");
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, first_timestamp, GAS_MAX)
            .expect("the user's own key signs the challenge");
    store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Challenge,
            &signed.signed_transaction_hex,
            &signed.transaction_hash,
        )
        .expect("the exact bytes are durable");
    store
        .mark_exit_step_submitted(&kit, &binding_commitment, HvmRegistryExitStep::Challenge)
        .expect("submission is durable");
    println!(
        "session one: challenge submitted as {}",
        signed.transaction_hash
    );

    // --- the app closes --------------------------------------------------
    drop(store);
    println!("the wallet process exits: lock released, all memory gone");

    // --- session two -----------------------------------------------------
    let mut store = f.open_store();
    let resumed = store
        .resume_exit_step(&kit, &binding_commitment, HvmRegistryExitStep::Challenge)
        .expect("the record re-derives")
        .expect("the record survived the close");
    let HvmRegistryExitResumeV1::AwaitChain {
        record,
        transaction_hash,
        signed_transaction_hex,
    } = resumed
    else {
        panic!("a submitted step must resume as AwaitChain, never as something signable");
    };
    assert_eq!(transaction_hash, signed.transaction_hash);
    assert_eq!(signed_transaction_hex, signed.signed_transaction_hex);
    assert_eq!(record.phase, HvmRegistryExitPhase::Submitted);
    assert_eq!(record.pre_observed_height, 500);
    assert_eq!(record.pre_status, 2);
    assert_eq!(record.bill_serial, Some(3));
    println!(
        "session two: the reopened wallet finds {} already on the wire and must look it up, \
         not sign",
        transaction_hash
    );

    // A driver reopening an hour later holds a different clock. Signing on it
    // would put a SECOND challenge on the wire for a step that may already be
    // mined: `adversarial_user_side_exit.rs` ATTACK 4 measures exactly that
    // divergence at the builder level.
    let later = build_user_exit_transaction(
        f.signer(),
        &kit,
        &plan,
        FEE_ZHU,
        first_timestamp + 3_600,
        GAS_MAX,
    )
    .unwrap();
    assert_ne!(later.transaction_hash, signed.transaction_hash);
    let naive = HvmRegistryExitIntentV1::from_plan(
        &kit,
        &plan,
        &snap,
        FEE_ZHU,
        first_timestamp + 3_600,
        GAS_MAX,
    )
    .unwrap();
    let refusal = store
        .begin_or_resume_exit_step(&kit, &naive)
        .expect_err("the store must refuse a second set of terms for a step in flight");
    println!("session two refusal: {refusal}");
    assert!(
        refusal
            .to_string()
            .contains("already recorded on different terms")
    );

    // The only legal way forward is the stored bytes.
    assert_eq!(
        store
            .exit_step_record(&binding_commitment, HvmRegistryExitStep::Challenge)
            .and_then(|record| record.signed_transaction_hex),
        Some(signed.signed_transaction_hex.clone()),
    );

    // And a confirmation has to be OUR transaction.
    let wrong = store
        .mark_exit_step_confirmed(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Challenge,
            &later.transaction_hash,
            520,
            &hash64(0xab),
        )
        .expect_err("a confirmation for another transaction is not evidence about this step");
    println!("session two refusal: {wrong}");
    let confirmed = store
        .mark_exit_step_confirmed(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Challenge,
            &signed.transaction_hash,
            520,
            &hash64(0xab),
        )
        .expect("our own transaction confirms");
    assert_eq!(confirmed.phase, HvmRegistryExitPhase::Confirmed);
    assert_eq!(confirmed.confirmed_block_height, Some(520));
}

// ===========================================================================
// 2. The nastier close: the process dies INSIDE the signer, after the
//    signature was announced and before its bytes were durable.
// ===========================================================================
#[test]
fn a_close_inside_the_signer_resumes_to_the_same_transaction_not_a_second_one() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let snap = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);
    let plan = plan_user_exit_step(&kit, &snap, 500, 10).unwrap();
    let timestamp = 1_700_000_000;
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &snap, FEE_ZHU, timestamp, GAS_MAX)
            .unwrap();

    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    store
        .mark_exit_step_signature_may_exist(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Challenge,
        )
        .unwrap();
    // ... and the process dies here, with the key possibly already used.
    drop(store);
    println!("the wallet process exits mid-signature");

    let store = f.open_store();
    let resumed = store
        .resume_exit_step(&kit, &binding_commitment, HvmRegistryExitStep::Challenge)
        .unwrap()
        .unwrap();
    let HvmRegistryExitResumeV1::ResignExact { record } = resumed else {
        panic!("a half-signed step must resume as ResignExact");
    };
    println!(
        "resume says: re-sign with the stored timestamp {}, fee {} zhu, gas {}",
        record.transaction_timestamp, record.network_fee_zhu, record.gas_max
    );

    // The record carries every non-deterministic input the builder takes, and
    // `libsecp256k1::sign` is RFC 6979 deterministic, so re-signing from the
    // record cannot produce a second transaction.
    let first =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, timestamp, GAS_MAX).unwrap();
    let again = build_user_exit_transaction(
        f.signer(),
        &kit,
        &plan,
        record.network_fee_zhu,
        record.transaction_timestamp,
        record.gas_max,
    )
    .unwrap();
    assert_eq!(first.transaction_hash, again.transaction_hash);
    assert_eq!(first.signed_transaction_hex, again.signed_transaction_hex);
    println!(
        "re-signed from the record -> {} (identical, not a second transaction)",
        again.transaction_hash
    );
}

// ===========================================================================
// 3. The money-moving step. A confirmed Action 14 claim can never be signed
//    again, across any number of closes.
// ===========================================================================
#[test]
fn a_confirmed_claim_can_never_be_signed_a_second_time() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let HvmRegistryExitPlanV1::Claim {
        payee, amount_zhu, ..
    } = &plan
    else {
        panic!("a settled channel plans the Action 14 claim");
    };
    assert_eq!(payee, &f.binding.left_address);
    assert_eq!(*amount_zhu, 900_000);

    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, 1_700_000_000, GAS_MAX)
            .unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, 1_700_000_000, GAS_MAX)
            .unwrap();
    store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &signed.signed_transaction_hex,
            &signed.transaction_hash,
        )
        .unwrap();
    store
        .mark_exit_step_submitted(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    store
        .mark_exit_step_confirmed(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &signed.transaction_hash,
            705,
            &hash64(0xcd),
        )
        .unwrap();
    println!(
        "the payout is mined at height 705 as {}",
        signed.transaction_hash
    );
    drop(store);

    // The app is closed and reopened. The chain read that follows a restart is
    // not instantaneous, so a driver could easily re-plan the claim it already
    // made.
    let mut store = f.open_store();
    let replan =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, 1_700_009_999, GAS_MAX)
            .unwrap();
    let resumed = store.begin_or_resume_exit_step(&kit, &replan).unwrap();
    assert!(
        !resumed.may_sign(),
        "a confirmed payout must never come back as signable"
    );
    let HvmRegistryExitResumeV1::Done { record } = resumed else {
        panic!("a confirmed claim resumes Done");
    };
    assert_eq!(record.phase, HvmRegistryExitPhase::Confirmed);
    assert_eq!(record.claim_amount_zhu, Some(900_000));
    println!("after the close, the claim resumes Done at height 705 and signs nothing");

    // Even asked directly, the store refuses to overwrite the bytes.
    let refusal = store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            "00ff",
            &hash64(0x11),
        )
        .expect_err("a confirmed step cannot take a new signature");
    println!("direct refusal: {refusal}");
}

// ===========================================================================
// 4. A store with no exit in it is byte-identical to what the previous
//    version wrote.
//
//    `state_commitment` hashes the whole state minus three keys, and
//    `initialize_state` refuses to open a store whose commitment does not
//    match its journal. If the new map were serialised empty, every store
//    already on disk would fail to open — the wallets of exactly the people
//    who have channels open.
// ===========================================================================
#[test]
fn a_store_with_no_exit_does_not_serialise_the_new_key_at_all() {
    let f = fixture();
    let store = f.open_store();
    drop(store);
    let mut found = Vec::new();
    for entry in walk(f.root.path()) {
        if entry
            .file_name()
            .is_some_and(|name| name == "operations.json")
        {
            let text = std::fs::read_to_string(&entry).unwrap();
            assert!(
                !text.contains("exit_operations"),
                "an exit-free store must not mention the new key: {text}"
            );
            found.push(entry);
        }
    }
    assert_eq!(found.len(), 1, "exactly one state file was written");
    println!("an exit-free store is byte-identical to the previous version's");

    // And it reopens, which is the property that would actually break.
    let store = f.open_store();
    assert!(
        store
            .exit_step_records(&f.binding.commitment().unwrap())
            .is_empty()
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

// ===========================================================================
// 5. A record is not evidence of itself.
// ===========================================================================
#[test]
fn a_record_whose_call_source_does_not_re_derive_is_refused() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, 1_700_000_000, GAS_MAX)
            .unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    let record = store
        .exit_step_record(&binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    validate_persisted_exit_step(&record, &kit).expect("the honest record re-derives");

    // Re-aim the payout at somebody else and re-commit to it, so the record is
    // internally perfectly consistent. The re-derivation is what catches it.
    let thief = Account::create_by("durable-exit-thief").unwrap();
    let mut stolen = record.clone();
    stolen.claim_payee = Some(thief.readable().to_owned());
    stolen.call_source = stolen
        .call_source
        .replace(&f.binding.left_address, thief.readable());
    stolen.call_source_commitment = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        stolen.call_source.as_bytes(),
    ));
    let refusal = validate_persisted_exit_step(&stolen, &kit)
        .expect_err("a re-aimed payout must not validate");
    println!("re-aimed payout refused: {refusal}");

    // A record that keeps the honest payee but inflates the amount.
    let mut inflated = record.clone();
    inflated.claim_amount_zhu = Some(DEPOSIT_ZHU);
    let refusal = validate_persisted_exit_step(&inflated, &kit)
        .expect_err("an inflated payout must not validate");
    println!("inflated payout refused: {refusal}");

    // A record that claims to be signed while holding nothing.
    let mut lying = record.clone();
    lying.phase = HvmRegistryExitPhase::Submitted;
    let refusal = validate_persisted_exit_step(&lying, &kit)
        .expect_err("a phase without its bytes must not validate");
    println!("empty signed phase refused: {refusal}");

    // A record built from a bill this wallet no longer holds.
    let challenge_snapshot = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 4_000);
    let challenge_plan = plan_user_exit_step(&kit, &challenge_snapshot, 500, 10).unwrap();
    let challenge_intent = HvmRegistryExitIntentV1::from_plan(
        &kit,
        &challenge_plan,
        &challenge_snapshot,
        FEE_ZHU,
        1_700_000_000,
        GAS_MAX,
    )
    .unwrap();
    store
        .begin_or_resume_exit_step(&kit, &challenge_intent)
        .unwrap();
    let challenge_record = store
        .exit_step_record(&binding_commitment, HvmRegistryExitStep::Challenge)
        .unwrap();
    let newer_kit = kit_at(&f, 4, 800_000, 200_000);
    let refusal = validate_persisted_exit_step(&challenge_record, &newer_kit)
        .expect_err("a record built from another bill must not validate");
    println!("stale-bill record refused: {refusal}");
}
