//! CORRUPT THE RECORD.
//!
//! `crates/wallet-core/src/hvm_registry_exit_record.rs` and the
//! `exit_operations` map in `crates/wallet-core/src/l2_safety.rs` are a new
//! durable store that the wallet **trusts on resume** to decide whether its own
//! signing key may be used again. That makes it a new place to lose money: a
//! store that can be rewound, blanked or lied to is a store that will happily
//! say "nothing was ever signed for this step" about a transaction that is
//! already in a block.
//!
//! Nothing here edits production code. Every attack below drives the shipped
//! functions and the shipped on-disk format, and every "close" is a real
//! `drop(ClientL2Safety)` followed by a fresh open from disk.
//!
//! Default assumption throughout: the user is trapped. A scenario only counts
//! as survived when the store REFUSES rather than proceeding on a false
//! premise.

use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep, build_exit_kit,
    build_user_exit_transaction, plan_user_exit_step,
};
use hacash_wallet_core::hvm_registry_exit_record::{
    HvmRegistryExitIntentV1, HvmRegistryExitPhase, HvmRegistryExitResumeV1,
    deterministic_exit_transaction_timestamp, validate_persisted_exit_step,
};
use hacash_wallet_core::l2_safety::ClientL2Safety;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use std::path::{Path, PathBuf};
use sys::Account;
use vm::ContractAddress;

const DEPOSIT_ZHU: u64 = 1_000_000;
const FEE_ZHU: u64 = 10_000;
const GAS_MAX: u8 = 250;
const T0: u64 = 1_700_000_000;

struct Fixture {
    wallet: WalletAccount,
    hub: Account,
    binding: HvmRegistryBindingV2,
    root: tempfile::TempDir,
}

impl Fixture {
    fn open_store(&self) -> ClientL2Safety {
        self.try_open_store()
            .expect("the wallet's own L2 store opens")
    }

    fn try_open_store(&self) -> Result<ClientL2Safety, hacash_wallet_core::error::WalletError> {
        ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.wallet,
            self.root.path(),
            "personal:corrupt-exit-test",
            "testnet",
            &self.binding.right_hub_address,
            &self.binding.commitment().unwrap(),
        )
    }

    fn signer(&self) -> &Account {
        self.wallet.inner()
    }

    /// The one directory the store keeps everything in: `operations.json`, the
    /// authenticated journal and its checkpoint.
    fn store_dir(&self) -> PathBuf {
        let state = walk(self.root.path())
            .into_iter()
            .find(|p| p.file_name().is_some_and(|n| n == "operations.json"))
            .expect("the store wrote its state file");
        state
            .parent()
            .expect("state file has a parent")
            .to_path_buf()
    }
}

fn fixture() -> Fixture {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let wallet = WalletAccount::create("corrupt-exit-left").unwrap();
    let hub = Account::create_by("corrupt-exit-hub").unwrap();
    Fixture {
        binding: binding_for(&wallet, &hub, 0),
        wallet,
        hub,
        root: tempfile::tempdir().expect("tempdir"),
    }
}

fn binding_for(wallet: &WalletAccount, hub: &Account, reuse_version: u32) -> HvmRegistryBindingV2 {
    HvmRegistryBindingV2 {
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
        reuse_version,
        left_address: wallet.address(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    }
}

fn kit_for(
    f: &Fixture,
    binding: &HvmRegistryBindingV2,
    serial: u64,
    left_zhu: u64,
    hub_zhu: u64,
) -> HvmRegistryExitKitV1 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial,
        left_balance_zhu: left_zhu,
        hub_balance_zhu: hub_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(f.signer(), &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(&f.hub, &hash).serialize());
    build_exit_kit(binding.clone(), bill).expect("kit must verify")
}

fn kit_at(f: &Fixture, serial: u64, left_zhu: u64, hub_zhu: u64) -> HvmRegistryExitKitV1 {
    kit_for(f, &f.binding, serial, left_zhu, hub_zhu)
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

fn walk(root: &Path) -> Vec<PathBuf> {
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

/// Byte-for-byte copy of every file in the store directory. This is what a VM
/// snapshot, a Time Machine backup, a restore point or a folder-sync client
/// takes, and it is the only kind of tampering that does not have to forge the
/// authenticated journal.
fn snapshot_dir(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("store dir readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            // The lock file is an artifact of a live process, not state.
            if name == "operations.lock" {
                continue;
            }
            out.push((name, std::fs::read(&path).expect("read")));
        }
    }
    out.sort();
    out
}

fn restore_dir(dir: &Path, files: &[(String, Vec<u8>)]) {
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).expect("restore write");
    }
}

/// Drive one channel to a settled state and take the Action 14 claim all the
/// way to Confirmed, returning the exact bytes that were signed.
struct ClaimRun {
    kit: HvmRegistryExitKitV1,
    plan: HvmRegistryExitPlanV1,
    snapshot: HvmRegistryLiveSnapshotV2,
    binding_commitment: String,
    signed_hash: String,
    confirmed_block_hash: String,
}

fn run_claim_to_confirmed(f: &Fixture) -> ClaimRun {
    let kit = kit_at(f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
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
    drop(store);
    ClaimRun {
        kit,
        plan,
        snapshot: settled,
        binding_commitment,
        signed_hash: signed.transaction_hash,
        confirmed_block_hash: hash64(0xcd),
    }
}

// ===========================================================================
// ATTACK 1. Rewind the whole store directory to an earlier consistent
//           snapshot, while the chain moved on.
//
//   This is the attack the authentication cannot see. Field-by-field tampering
//   is caught because `state_commitment` hashes the whole state and is carried
//   in a journal MACed under a key derived from the wallet's own secret key
//   (l2_safety.rs:2409, :2280). But a WHOLE-DIRECTORY restore is internally
//   consistent: the state, the journal and the checkpoint were all genuinely
//   written by this wallet, just earlier.
// ===========================================================================
#[test]
fn attack_1_a_whole_directory_rollback_rewinds_the_record_and_the_store_accepts_it() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();

    // t=0: the intent is durable, nothing signed. The backup runs here.
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    drop(store);
    let dir = f.store_dir();
    let backup = snapshot_dir(&dir);
    println!(
        "backup taken with the claim at IntentPersisted ({} files)",
        backup.len()
    );

    // t=1: the wallet signs, submits and sees the payout mined.
    let mut store = f.open_store();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
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
    drop(store);
    println!(
        "the Action 14 payout {} is mined at 705",
        signed.transaction_hash
    );

    // t=2: the backup is restored. Nothing was forged; these are this wallet's
    // own bytes from twenty minutes ago.
    restore_dir(&dir, &backup);

    let opened = f.try_open_store();
    match opened {
        Err(error) => {
            println!("SURVIVES: the rolled-back store refuses to open: {error}");
        }
        Ok(mut store) => {
            let resumed = store
                .resume_exit_step(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
                .expect("record re-derives")
                .expect("record present");
            println!(
                "the rolled-back store opened and says: may_sign={}, phase={:?}",
                resumed.may_sign(),
                resumed.record().phase
            );
            assert!(
                resumed.may_sign(),
                "MEASURED: a rollback is expected to rewind the record to a signable phase"
            );
            assert_eq!(
                resumed.record().phase,
                HvmRegistryExitPhase::IntentPersisted
            );

            // The rollback is real and it cannot be prevented from inside this
            // directory: the state, the journal and the checkpoint were all
            // genuinely written by this wallet. What can be prevented is the
            // part that costs money — a *second, different* transaction for a
            // payout that has already mined.
            //
            // Two things stop it now, and each is enough on its own.
            //
            // 1. The terms are sticky. A re-plan on a clock an hour later comes
            //    back at the record's original timestamp, so re-signing
            //    reproduces the transaction that is already on chain.
            let replan = HvmRegistryExitIntentV1::from_plan(
                &kit,
                &plan,
                &settled,
                FEE_ZHU,
                T0 + 3_600,
                GAS_MAX,
            )
            .unwrap();
            let again = store.begin_or_resume_exit_step(&kit, &replan).unwrap();
            assert!(again.may_sign());
            assert_eq!(
                again.record().transaction_timestamp,
                T0,
                "SURVIVES: a rewound record keeps its own terms"
            );
            let resigned = build_user_exit_transaction(
                f.signer(),
                &kit,
                &plan,
                again.record().network_fee_zhu,
                again.record().transaction_timestamp,
                again.record().gas_max,
            )
            .unwrap();
            assert_eq!(
                resigned.transaction_hash, signed.transaction_hash,
                "SURVIVES: the rewound wallet re-signs the transaction already mined, not a new one"
            );

            // 2. And a caller that ignores the record anyway cannot file the
            //    result: the bytes are re-hashed and their timestamp is
            //    compared against the record before anything is written.
            let later =
                build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0 + 3_600, GAS_MAX)
                    .unwrap();
            assert_ne!(later.transaction_hash, signed.transaction_hash);
            store
                .mark_exit_step_signature_may_exist(
                    &kit,
                    &binding_commitment,
                    HvmRegistryExitStep::Claim,
                )
                .unwrap();
            let refusal = store
                .persist_exit_step_signature(
                    &kit,
                    &binding_commitment,
                    HvmRegistryExitStep::Claim,
                    &later.signed_transaction_hex,
                    &later.transaction_hash,
                )
                .expect_err("a second, different transaction must not become durable");
            println!("SURVIVES: the rewound store refuses off-record bytes: {refusal}");
            // Filing real bytes under a different name is refused too.
            let liar = store
                .persist_exit_step_signature(
                    &kit,
                    &binding_commitment,
                    HvmRegistryExitStep::Claim,
                    &later.signed_transaction_hex,
                    &signed.transaction_hash,
                )
                .expect_err("bytes must hash to the name they are filed under");
            println!("SURVIVES: bytes filed under somebody else's hash -> {liar}");
        }
    }
}

// ===========================================================================
// ATTACK 2. Rewind only PART of the store. The half-restores must not open.
// ===========================================================================
#[test]
fn attack_2_a_partial_rollback_is_refused() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    drop(store);
    let dir = f.store_dir();
    let backup = snapshot_dir(&dir);

    let mut store = f.open_store();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
    store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &signed.signed_transaction_hex,
            &signed.transaction_hash,
        )
        .unwrap();
    drop(store);
    let current = snapshot_dir(&dir);

    // A partial rollback must either be refused outright, or leave the record
    // at its newest phase. What must never happen is a store that opens with a
    // rewound record.
    for (name, old_bytes) in &backup {
        restore_dir(&dir, &current);
        std::fs::write(dir.join(name), old_bytes).unwrap();
        match f.try_open_store() {
            Err(error) => println!("SURVIVES: rolling back only `{name}` is refused: {error}"),
            Ok(store) => {
                let phase = store
                    .exit_step_record(&binding_commitment, HvmRegistryExitStep::Claim)
                    .map(|r| r.phase);
                assert_eq!(
                    phase,
                    Some(HvmRegistryExitPhase::Signed),
                    "HOLE: rolling back only `{name}` opened with a rewound record"
                );
                println!(
                    "SURVIVES: rolling back only `{name}` opens but the record is NOT rewound \
                     (still {phase:?})"
                );
            }
        }
    }

    // The one thing standing between this store and a silent rewind is the
    // checkpoint's `sequence > last.entry_sequence` test
    // (l2_safety.rs:2374). Roll the state and the journal back but leave the
    // checkpoint where it is, and that test has to fire.
    restore_dir(&dir, &current);
    for (name, old_bytes) in &backup {
        if name != "operations.journal.checkpoint.json" {
            std::fs::write(dir.join(name), old_bytes).unwrap();
        }
    }
    match f.try_open_store() {
        Err(error) => println!(
            "SURVIVES: state+journal rewound with the checkpoint left current -> refused: {error}"
        ),
        Ok(store) => {
            let phase = store
                .exit_step_record(&binding_commitment, HvmRegistryExitStep::Claim)
                .map(|r| r.phase);
            panic!("HOLE: a rewound state+journal opened anyway, phase={phase:?}");
        }
    }
    println!(
        "  -> so the checkpoint IS the whole anti-rollback defence, and attack 1 defeats it by \
         restoring the checkpoint along with everything else"
    );

    restore_dir(&dir, &current);
    assert!(
        f.try_open_store().is_ok(),
        "the untouched store still opens"
    );
}

// ===========================================================================
// ATTACK 3. Hand-edit one field of the durable record.
//
//   Every one of these is a record that would still pass
//   `validate_persisted_exit_step` on its own terms; the question is whether
//   the store lets the bytes through the door at all.
// ===========================================================================
#[test]
fn attack_3_a_hand_edited_record_never_reaches_the_resume_path() {
    let f = fixture();
    let run = run_claim_to_confirmed(&f);
    let dir = f.store_dir();
    let state_path = dir.join("operations.json");
    let original = std::fs::read_to_string(&state_path).unwrap();
    assert!(
        original.contains("exit_operations"),
        "the record really is in the state file"
    );

    let edits: Vec<(&str, String)> = vec![
        (
            "phase rolled back from confirmed to unsigned, so the wallet would sign again",
            original
                .replace("\"confirmed\"", "\"intent_persisted\"")
                .replace(
                    &format!("\"transaction_hash\":\"{}\"", run.signed_hash),
                    "\"transaction_hash\":null",
                ),
        ),
        (
            "the payout amount inflated to the whole deposit",
            original.replace(
                "\"claim_amount_zhu\":900000",
                "\"claim_amount_zhu\":1000000",
            ),
        ),
        (
            "the mined block height moved",
            original.replace(
                "\"confirmed_block_height\":705",
                "\"confirmed_block_height\":1",
            ),
        ),
        ("the exit_operations map removed entirely", {
            let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
            value.as_object_mut().unwrap().remove("exit_operations");
            serde_json::to_string(&value).unwrap()
        }),
        ("the exit_operations map emptied", {
            let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("exit_operations".into(), serde_json::json!({}));
            serde_json::to_string(&value).unwrap()
        }),
    ];

    for (label, edited) in edits {
        assert_ne!(
            edited, original,
            "the edit `{label}` actually changed bytes"
        );
        std::fs::write(&state_path, edited.as_bytes()).unwrap();
        match f.try_open_store() {
            Err(error) => println!("SURVIVES: {label} -> refused: {error}"),
            Ok(store) => {
                let phase = store
                    .exit_step_record(&run.binding_commitment, HvmRegistryExitStep::Claim)
                    .map(|r| r.phase);
                panic!("HOLE: `{label}` opened anyway, phase={phase:?}");
            }
        }
    }
    std::fs::write(&state_path, original.as_bytes()).unwrap();
    assert!(
        f.try_open_store().is_ok(),
        "the untouched store still opens"
    );
}

// ===========================================================================
// ATTACK 4. An empty, truncated, blanked or deleted store.
// ===========================================================================
#[test]
fn attack_4_an_empty_or_truncated_store_is_refused() {
    let f = fixture();
    let run = run_claim_to_confirmed(&f);
    let dir = f.store_dir();
    let state_path = dir.join("operations.json");
    let original = std::fs::read(&state_path).unwrap();

    let mut cases: Vec<(String, Option<Vec<u8>>)> = vec![
        ("zero bytes".into(), Some(Vec::new())),
        ("an empty JSON object".into(), Some(b"{}".to_vec())),
        ("JSON null".into(), Some(b"null".to_vec())),
        ("a JSON array".into(), Some(b"[]".to_vec())),
        ("the file deleted while the journal survives".into(), None),
    ];
    for cut in [4_usize, 32, original.len() / 2, original.len() - 1] {
        cases.push((
            format!("truncated to {cut} of {} bytes", original.len()),
            Some(original[..cut].to_vec()),
        ));
    }

    for (label, bytes) in cases {
        match bytes {
            Some(bytes) => std::fs::write(&state_path, &bytes).unwrap(),
            None => std::fs::remove_file(&state_path).unwrap(),
        }
        match f.try_open_store() {
            Err(error) => println!("SURVIVES: {label} -> refused: {error}"),
            Ok(store) => {
                let phase = store
                    .exit_step_record(&run.binding_commitment, HvmRegistryExitStep::Claim)
                    .map(|r| r.phase);
                panic!("HOLE: `{label}` opened anyway, phase={phase:?}");
            }
        }
    }

    // The journal itself.
    std::fs::write(&state_path, &original).unwrap();
    let journal_path = dir.join("operations.journal.jsonl");
    let journal = std::fs::read(&journal_path).unwrap();
    for (label, bytes) in [
        ("journal emptied", Vec::new()),
        (
            "journal truncated mid-entry",
            journal[..journal.len() / 2].to_vec(),
        ),
        ("journal last entry dropped", {
            let text = String::from_utf8_lossy(&journal).into_owned();
            let mut lines: Vec<&str> = text.lines().collect();
            lines.pop();
            (lines.join("\n") + "\n").into_bytes()
        }),
    ] {
        std::fs::write(&journal_path, &bytes).unwrap();
        match f.try_open_store() {
            Err(error) => println!("SURVIVES: {label} -> refused: {error}"),
            Ok(_) => panic!("HOLE: `{label}` opened anyway"),
        }
    }

    // And the total loss case, stated rather than dressed up: if the whole
    // directory goes, nothing durable survives its own deletion.
    std::fs::write(&journal_path, &journal).unwrap();
    assert!(
        f.try_open_store().is_ok(),
        "the untouched store still opens"
    );
    for path in walk(&dir) {
        let _ = std::fs::remove_file(&path);
    }
    let store = f.open_store();
    assert!(
        store.exit_step_records(&run.binding_commitment).is_empty(),
        "a deleted directory is amnesia, not a refusal"
    );
    println!(
        "MEASURED: deleting the whole store directory yields a fresh, empty store with no memory \
         of the confirmed payout {} - the wallet would re-plan and re-sign",
        run.signed_hash
    );
}

// ===========================================================================
// ATTACK 5. A record from a different channel.
// ===========================================================================
#[test]
fn attack_5_a_record_from_a_different_channel_is_refused() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    let record = store
        .exit_step_record(&binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();

    // A genuinely different incarnation of the same channel.
    let other_binding = binding_for(&f.wallet, &f.hub, 1);
    let other_kit = kit_for(&f, &other_binding, 3, 900_000, 100_000);
    assert_ne!(
        other_binding.commitment().unwrap(),
        binding_commitment,
        "the two incarnations are different bindings"
    );
    let refusal = validate_persisted_exit_step(&record, &other_kit)
        .expect_err("a record from another incarnation must not validate");
    println!("SURVIVES: another incarnation's kit -> {refusal}");

    // And the store, asked through its own API with the other commitment.
    let resumed = store
        .resume_exit_step(
            &other_kit,
            &other_binding.commitment().unwrap(),
            HvmRegistryExitStep::Claim,
        )
        .expect("no record under the other key");
    assert!(
        resumed.is_none(),
        "no record exists for the other incarnation"
    );

    // The nastier version: the record is relabelled with the other binding's
    // commitment, so key and content agree, but its call source still names the
    // old channel.
    let mut relabelled = record.clone();
    relabelled.binding_commitment = other_binding.commitment().unwrap();
    let refusal = validate_persisted_exit_step(&relabelled, &other_kit)
        .expect_err("a relabelled record must not validate");
    println!("SURVIVES: relabelled to the other incarnation -> {refusal}");

    // A whole different wallet's channel entirely.
    let stranger = WalletAccount::create("corrupt-exit-stranger").unwrap();
    let stranger_binding = binding_for(&stranger, &f.hub, 0);
    let mut stranger_bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: stranger_binding.commitment().unwrap(),
        serial: 3,
        left_balance_zhu: 900_000,
        hub_balance_zhu: 100_000,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = stranger_bill.signing_hash(&stranger_binding).unwrap();
    stranger_bill.left_signature_hex =
        hex::encode(Sign::create_by(stranger.inner(), &hash).serialize());
    stranger_bill.hub_signature_hex = hex::encode(Sign::create_by(&f.hub, &hash).serialize());
    let stranger_kit = build_exit_kit(stranger_binding, stranger_bill).unwrap();
    let refusal = validate_persisted_exit_step(&record, &stranger_kit)
        .expect_err("a record from another wallet's channel must not validate");
    println!("SURVIVES: a stranger's channel -> {refusal}");
}

// ===========================================================================
// ATTACK 6. The transaction is mined but the phase says otherwise, reached
//           WITHOUT touching the disk: a driver that signs before it announces.
// ===========================================================================
#[test]
fn attack_6_bytes_signed_before_they_were_announced_can_never_be_recorded() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();

    // A driver that forgets `mark_exit_step_signature_may_exist` signs anyway
    // and broadcasts. Now it tries to write the bytes down.
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
    let refusal = store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &signed.signed_transaction_hex,
            &signed.transaction_hash,
        )
        .expect_err("the store refuses bytes it was not warned about");
    println!("the store refuses to record unannounced bytes: {refusal}");

    // The refusal is correct as a rule and catastrophic as an outcome: the
    // transaction is on the wire and the store's only durable statement about
    // it is that nothing was ever signed.
    drop(store);
    let mut store = f.open_store();
    let resumed = store
        .resume_exit_step(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap()
        .unwrap();
    assert!(
        resumed.may_sign(),
        "MEASURED: the orphaned bytes leave the record signable"
    );
    assert_eq!(
        resumed.record().phase,
        HvmRegistryExitPhase::IntentPersisted
    );
    println!(
        "MEASURED: {} is on the wire and the durable record still says IntentPersisted",
        signed.transaction_hash
    );

    // This used to be the second half of the finding: because nothing was
    // signed as far as the record knew, a re-plan on a new clock silently
    // REPLACED the intent, and the orphaned bytes became a second transaction
    // waiting to happen. The terms are now sticky from the moment the step is
    // opened, so a re-plan on any clock at all comes back with the *original*
    // timestamp and re-signs into the very bytes that are already on the wire.
    let replan =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0 + 3_600, GAS_MAX)
            .unwrap();
    let again = store.begin_or_resume_exit_step(&kit, &replan).unwrap();
    assert!(again.may_sign());
    assert_eq!(
        again.record().transaction_timestamp,
        T0,
        "SURVIVES: a re-plan on a later clock must not move a step's terms"
    );
    let resigned = build_user_exit_transaction(
        f.signer(),
        &kit,
        &plan,
        again.record().network_fee_zhu,
        again.record().transaction_timestamp,
        again.record().gas_max,
    )
    .unwrap();
    assert_eq!(
        resigned.transaction_hash, signed.transaction_hash,
        "SURVIVES: the orphaned bytes are reproduced exactly, not duplicated"
    );
    println!(
        "SURVIVES: the re-plan came back at timestamp {} and re-signed into {}, which is the \
         transaction already on the wire rather than a second one",
        again.record().transaction_timestamp,
        resigned.transaction_hash
    );

    // And the derived timestamp closes the remaining half: a wallet that lost
    // the record entirely still lands on one transaction per step, because the
    // clock is not an input.
    assert_eq!(
        deterministic_exit_transaction_timestamp(
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            1
        ),
        deterministic_exit_transaction_timestamp(
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            1
        ),
        "the derived timestamp must not depend on when it is asked for"
    );
    assert_ne!(
        deterministic_exit_transaction_timestamp(
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            1
        ),
        deterministic_exit_transaction_timestamp(
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            2
        ),
        "a deliberate second attempt must be a different transaction"
    );
}

// ===========================================================================
// ATTACK 7. Retire a step whose bytes are still live, then take a second run
//           at it. Reachable through the public API with no tampering at all.
// ===========================================================================
#[test]
fn attack_7_a_live_submitted_step_can_be_retired_and_re_signed() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    // A short registry lease is what plans a renewal, and a renewal is the one
    // step the store lets a caller attempt twice.
    let short = snapshot(&f.binding, 2, 0, DEPOSIT_ZHU, 0, 500, 0, 10);
    let plan = plan_user_exit_step(&kit, &short, 500, 10).unwrap();
    let HvmRegistryExitPlanV1::Call { step, .. } = &plan else {
        panic!("a short lease plans a renewal");
    };
    assert!(step.is_lease_renewal(), "planned {step:?}");
    let step = *step;
    println!("planned step: {}", step.slug());

    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &short, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, step)
        .unwrap();
    let signed =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
    store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            step,
            &signed.signed_transaction_hex,
            &signed.transaction_hash,
        )
        .unwrap();
    store
        .mark_exit_step_submitted(&kit, &binding_commitment, step)
        .unwrap();
    println!(
        "renewal {} is submitted and live on the wire",
        signed.transaction_hash
    );

    // The driver sees the lease look longer (somebody else renewed, or its own
    // transaction landed and it misreads the cause) and retires the step.
    let retired = store.mark_exit_step_settled_elsewhere(&kit, &binding_commitment, step, 505);
    match retired {
        Err(error) => {
            println!("SURVIVES: a live submitted step cannot be retired: {error}");

            // Closing that door must not wedge the one clock in this system
            // that destroys a deposit. The narrow replacement door is the
            // answer, and it asks for evidence the wide one never did.
            let bump = HvmRegistryExitIntentV1::from_plan(
                &kit,
                &plan,
                &short,
                FEE_ZHU * 2,
                T0 + 600,
                GAS_MAX,
            )
            .unwrap();
            let same_fee =
                HvmRegistryExitIntentV1::from_plan(&kit, &plan, &short, FEE_ZHU, T0 + 600, GAS_MAX)
                    .unwrap();
            let too_cheap = store
                .supersede_stuck_lease_renewal(&kit, &same_fee, false)
                .expect_err("a replacement that pays no more is a duplicate, not a replacement");
            println!("SURVIVES: a replacement at the same fee -> {too_cheap}");
            let on_chain = store
                .supersede_stuck_lease_renewal(&kit, &bump, true)
                .expect_err("a renewal the chain has must be confirmed, not replaced");
            println!("SURVIVES: a replacement for bytes the chain holds -> {on_chain}");

            let claim_intent = HvmRegistryExitIntentV1::from_plan(
                &kit,
                &plan_user_exit_step(
                    &kit,
                    &snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000),
                    700,
                    10,
                )
                .unwrap(),
                &snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000),
                FEE_ZHU * 2,
                T0 + 600,
                GAS_MAX,
            )
            .unwrap();
            let not_a_renewal = store
                .supersede_stuck_lease_renewal(&kit, &claim_intent, false)
                .expect_err("only a lease renewal may be replaced while live");
            println!("SURVIVES: the same door tried on the Action 14 payout -> {not_a_renewal}");

            let replaced = store
                .supersede_stuck_lease_renewal(&kit, &bump, false)
                .expect("a stuck renewal the chain does not have may be replaced at a higher fee");
            assert!(replaced.may_sign());
            assert_eq!(replaced.record().attempt, 2);
            assert_eq!(
                replaced.record().previous_transaction_hashes,
                vec![signed.transaction_hash.clone()],
                "the superseded hash must be carried forward, never dropped"
            );
            println!(
                "SURVIVES: the stuck renewal is replaced as attempt 2 at {} zhu, and {} is \
                 remembered rather than forgotten",
                replaced.record().network_fee_zhu,
                signed.transaction_hash
            );
        }
        Ok(record) => {
            println!(
                "MEASURED: a Submitted step was retired to {:?} while its bytes {} are still live",
                record.phase,
                record.transaction_hash.as_deref().unwrap_or("?")
            );
            assert!(record.phase.is_terminal());
            drop(store);

            // Reopened, the step is terminal, so a renewal supersedes it and
            // signs a SECOND transaction while the first may still be mined.
            let mut store = f.open_store();
            let resumed = store
                .resume_exit_step(&kit, &binding_commitment, step)
                .unwrap()
                .unwrap();
            assert!(matches!(resumed, HvmRegistryExitResumeV1::Done { .. }));
            let replan =
                HvmRegistryExitIntentV1::from_plan(&kit, &plan, &short, FEE_ZHU, T0 + 600, GAS_MAX)
                    .unwrap();
            let second = store.begin_or_resume_exit_step(&kit, &replan).unwrap();
            assert!(
                second.may_sign(),
                "MEASURED: the retired step comes back signable"
            );
            let record = second.record();
            println!(
                "MEASURED: attempt {} is signable at timestamp {}; the first hash is carried as {:?}",
                record.attempt, record.transaction_timestamp, record.previous_transaction_hashes
            );
            assert_eq!(record.attempt, 2);
            assert_eq!(
                record.previous_transaction_hashes,
                vec![signed.transaction_hash.clone()],
                "at least the superseded hash is remembered"
            );
            let later =
                build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0 + 600, GAS_MAX)
                    .unwrap();
            assert_ne!(later.transaction_hash, signed.transaction_hash);
            println!(
                "MONEY: two lease renewals for one lease - {} and {} - both payable",
                signed.transaction_hash, later.transaction_hash
            );
        }
    }
}

// ===========================================================================
// ATTACK 8. Is `validate_persisted_exit_step` actually evidence, or does it
//           re-derive from the record's own inputs?
//
//   `canonical_call_source` takes `record.claim_amount_zhu` as an argument and
//   `registry_claim_payout_source` bounds it only by "positive and exactly
//   representable" (hvm_registry_watchtower.rs:600). Nothing ties the amount to
//   the bill, the deposit, or the snapshot the record itself carries.
// ===========================================================================
#[test]
fn attack_8_a_consistently_rewritten_payout_amount_re_derives_cleanly() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);
    let binding_commitment = f.binding.commitment().unwrap();
    let settled = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &settled, 700, 10).unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &settled, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    let record = store
        .exit_step_record(&binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    assert_eq!(record.claim_amount_zhu, Some(900_000));

    // Inflate the amount AND the call source AND its commitment together, so
    // the record is internally consistent - which is what an attacker who could
    // write the file would obviously do.
    let inflated_zhu = u64::MAX / 2;
    let mut inflated = record.clone();
    inflated.claim_amount_zhu = Some(inflated_zhu);
    inflated.call_source = record
        .call_source
        .replace("zhu=900000", &format!("zhu={inflated_zhu}"));
    assert_ne!(inflated.call_source, record.call_source);
    inflated.call_source_commitment = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        inflated.call_source.as_bytes(),
    ));

    match validate_persisted_exit_step(&inflated, &kit) {
        Err(error) => println!("SURVIVES: the inflated payout is refused: {error}"),
        Ok(()) => {
            println!(
                "MEASURED: a payout of {inflated_zhu} zhu against a {DEPOSIT_ZHU} zhu deposit and \
                 a {} zhu bill re-derives cleanly",
                kit.latest_bill.left_balance_zhu
            );
            println!(
                "  the record's own pre-state says left_balance={} at height {}",
                inflated.pre_left_balance_zhu, inflated.pre_observed_height
            );
            println!(
                "  re-derivation is circular here: canonical_call_source() is fed \
                 record.claim_amount_zhu and compared against a call source built from the same \
                 number"
            );
        }
    }

    // The reachability question, answered separately: can such a record be
    // WRITTEN? Only through the store, and only for a step whose intent is
    // honest, so the file would have to be edited - which attack 3 shows the
    // journal catches.
    let dir = f.store_dir();
    drop(store);
    let state_path = dir.join("operations.json");
    let text = std::fs::read_to_string(&state_path).unwrap();
    let edited = text
        .replace(
            "\"claim_amount_zhu\":900000",
            &format!("\"claim_amount_zhu\":{inflated_zhu}"),
        )
        .replace("zhu=900000", &format!("zhu={inflated_zhu}"));
    assert_ne!(edited, text);
    std::fs::write(&state_path, edited.as_bytes()).unwrap();
    match f.try_open_store() {
        Err(error) => println!("SURVIVES: writing it to disk is caught at open: {error}"),
        Ok(_) => panic!("HOLE: an inflated payout survived a reopen"),
    }
}

// ===========================================================================
// ATTACK 10. How much does the rollback of attack 1 actually cost?
//
//   `plan_user_exit_step` re-reads the live chain, so once the payout is mined
//   the chain itself says "already claimed" and the rewound record does no
//   damage. The dangerous window is the one where the transaction is on the
//   wire and NOT yet in a block, which is exactly the window a durable record
//   exists to cover.
// ===========================================================================
#[test]
fn attack_10_the_rollback_bites_precisely_where_the_record_was_the_only_guard() {
    let f = fixture();
    let kit = kit_at(&f, 3, 900_000, 100_000);

    // Once the chain shows the payout taken, the chain is the backstop.
    let mut claimed = snapshot(&f.binding, 4, 3, 900_000, 100_000, 710, 600, 4_000);
    claimed.channel.left_claimed.value = true;
    let after = plan_user_exit_step(&kit, &claimed, 710, 10).unwrap();
    assert!(
        matches!(after, HvmRegistryExitPlanV1::Wait { .. }),
        "a mined payout must plan no further action, got {after:?}"
    );
    println!("once the payout is mined the chain itself refuses to plan it again: {after:?}");

    // But before it is mined the chain looks exactly as it did, so the record
    // is the ONLY thing that knows a transaction is already on the wire. Roll
    // the record back and that knowledge is gone.
    let pending = snapshot(&f.binding, 4, 3, 900_000, 100_000, 700, 600, 4_000);
    let plan = plan_user_exit_step(&kit, &pending, 700, 10).unwrap();
    let binding_commitment = f.binding.commitment().unwrap();
    let intent =
        HvmRegistryExitIntentV1::from_plan(&kit, &plan, &pending, FEE_ZHU, T0, GAS_MAX).unwrap();
    let mut store = f.open_store();
    store.begin_or_resume_exit_step(&kit, &intent).unwrap();
    drop(store);
    let dir = f.store_dir();
    let backup = snapshot_dir(&dir);

    let mut store = f.open_store();
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let first = build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0, GAS_MAX).unwrap();
    store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &first.signed_transaction_hex,
            &first.transaction_hash,
        )
        .unwrap();
    store
        .mark_exit_step_submitted(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    drop(store);
    restore_dir(&dir, &backup);

    // Same chain read as before: nothing has been mined yet.
    let replan_plan = plan_user_exit_step(&kit, &pending, 700, 10).unwrap();
    assert_eq!(replan_plan, plan, "the chain still plans the same step");
    let replan = HvmRegistryExitIntentV1::from_plan(
        &kit,
        &replan_plan,
        &pending,
        FEE_ZHU,
        T0 + 900,
        GAS_MAX,
    )
    .unwrap();
    let mut store = f.open_store();
    let resumed = store.begin_or_resume_exit_step(&kit, &replan).unwrap();
    assert!(
        resumed.may_sign(),
        "with the record rewound and the chain not yet caught up, the step is signable again"
    );
    // Signable, yes — but signable into *what*. The rewound record hands back
    // its own terms rather than the caller's new clock, so the only transaction
    // this wallet can produce here is the one already on the wire.
    assert_eq!(
        resumed.record().transaction_timestamp,
        T0,
        "SURVIVES: the rewound step is signable only at its own terms"
    );
    let resigned = build_user_exit_transaction(
        f.signer(),
        &kit,
        &plan,
        resumed.record().network_fee_zhu,
        resumed.record().transaction_timestamp,
        resumed.record().gas_max,
    )
    .unwrap();
    assert_eq!(
        resigned.transaction_hash, first.transaction_hash,
        "SURVIVES: in the one window the chain cannot cover, the wallet re-signs the same bytes"
    );
    // And a caller that signs on its own clock anyway cannot make it durable.
    let second =
        build_user_exit_transaction(f.signer(), &kit, &plan, FEE_ZHU, T0 + 900, GAS_MAX).unwrap();
    assert_ne!(second.transaction_hash, first.transaction_hash);
    store
        .mark_exit_step_signature_may_exist(&kit, &binding_commitment, HvmRegistryExitStep::Claim)
        .unwrap();
    let refusal = store
        .persist_exit_step_signature(
            &kit,
            &binding_commitment,
            HvmRegistryExitStep::Claim,
            &second.signed_transaction_hex,
            &second.transaction_hash,
        )
        .expect_err("off-record bytes must not become durable");
    println!(
        "SURVIVES: {} is on the wire, the rewound wallet re-signs into the same {}, and the \
         off-record alternative {} is refused: {refusal}",
        first.transaction_hash, resigned.transaction_hash, second.transaction_hash
    );
}

// ===========================================================================
// ATTACK 9. A chain reorg under a confirmed step.
// ===========================================================================
#[test]
fn attack_9_a_reorg_under_a_confirmed_step_wedges_it() {
    let f = fixture();
    let run = run_claim_to_confirmed(&f);
    let mut store = f.open_store();

    // The same transaction, now reported in a different block: an ordinary
    // reorg, not an attack.
    let refusal = store
        .mark_exit_step_confirmed(
            &run.kit,
            &run.binding_commitment,
            HvmRegistryExitStep::Claim,
            &run.signed_hash,
            706,
            &hash64(0xee),
        )
        .expect_err("a different block for the same transaction is refused");
    println!("SURVIVES: reorg to a different block -> {refusal}");

    // The harder case: the transaction is gone from the chain entirely. There
    // is no way to say so.
    let settled_elsewhere = store.mark_exit_step_settled_elsewhere(
        &run.kit,
        &run.binding_commitment,
        HvmRegistryExitStep::Claim,
        706,
    );
    println!(
        "un-confirming a reorged-out step: {}",
        match &settled_elsewhere {
            Err(error) => format!("refused - {error}"),
            Ok(record) => format!("accepted, phase now {:?}", record.phase),
        }
    );
    let replan = HvmRegistryExitIntentV1::from_plan(
        &run.kit,
        &run.plan,
        &run.snapshot,
        FEE_ZHU,
        T0 + 3_600,
        GAS_MAX,
    )
    .unwrap();
    let resumed = store.begin_or_resume_exit_step(&run.kit, &replan).unwrap();
    println!(
        "after a reorg the step still resumes may_sign={} in phase {:?}",
        resumed.may_sign(),
        resumed.record().phase
    );
    assert!(
        !resumed.may_sign(),
        "a confirmed record stays terminal, so a reorged-out payout can never be RE-SIGNED"
    );

    // The way out is not a new signature and must never be one. The record
    // disowns the block that vanished, keeps its exact bytes, and goes back to
    // saying what is true: handed to a node, fate unknown.
    let reorged = store
        .mark_exit_step_reorged_out(
            &run.kit,
            &run.binding_commitment,
            HvmRegistryExitStep::Claim,
            705,
            &run.confirmed_block_hash,
        )
        .expect("a confirmed step whose block vanished can be put back on the wire");
    assert_eq!(reorged.phase, HvmRegistryExitPhase::Submitted);
    assert_eq!(reorged.transaction_hash.as_deref(), Some(&*run.signed_hash));
    assert_eq!(reorged.confirmed_block_height, None);
    let resumed = store
        .resume_exit_step(
            &run.kit,
            &run.binding_commitment,
            HvmRegistryExitStep::Claim,
        )
        .unwrap()
        .unwrap();
    assert!(
        !resumed.may_sign(),
        "un-confirming must never hand the key back"
    );
    match &resumed {
        HvmRegistryExitResumeV1::AwaitChain {
            transaction_hash, ..
        } => assert_eq!(transaction_hash, &run.signed_hash),
        other => panic!("expected the same bytes to be re-submittable, got {other:?}"),
    }
    println!(
        "SURVIVES: the reorged-out payout is re-submittable as the SAME transaction {}, and the \
         key is not touched to do it",
        run.signed_hash
    );
    // A reorg that names a block this step was never in proves nothing.
    let bogus = store
        .mark_exit_step_reorged_out(
            &run.kit,
            &run.binding_commitment,
            HvmRegistryExitStep::Claim,
            705,
            &hash64(0xee),
        )
        .expect_err("only a confirmed step can be disowned, and only from its own block");
    println!("SURVIVES: a reorg naming the wrong block -> {bogus}");
}
