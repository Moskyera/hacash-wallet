//! WHAT AN AGENT WALLET BACKUP WOULD ACTUALLY BE, ESTABLISHED BY EXECUTION.
//!
//! NO BACKUP OR RESTORE PATH IS BUILT. This file is the evidence for why not.
//!
//! Nothing here is read off the source. Every claim is driven against a real
//! wallet on a real directory, copied the way an owner's backup would copy it,
//! and reopened. The findings, in order:
//!
//!   A. An Agent Wallet is ten files, and only two of them are secrets.
//!   B. The wallet directory alone is not a wallet: `AgentWalletNotFound`.
//!   C. The whole storage root, copied, does restore and unlock.
//!   D. The vault alone does not restore. This is a state backup, not a key
//!      backup: `PersistenceFailed`.
//!   E. Without `journal.json` the state will not load: `RecoveryRequired`.
//!   F. Without `wallet_state.enc.json` there is nothing to load.
//!   G. A restored wallet meeting its own phone is refused for the right
//!      reason: the phone answers `RollbackDetected` and will never sign again.
//!   H. `store_id` lives in `registry.json` and is inside the AAD of every
//!      encrypted state file. A registry rebuilt on the new machine cannot
//!      decrypt anything: `JournalAuthenticationFailed`.
//!   I. The rollback is not self-limiting. `LostPhoneRecovery` re-baselines a
//!      fresh phone onto the restored position with no old-phone authorization,
//!      and the wallet then spends again on a spend window that has silently
//!      returned to what it was when the backup was taken.
//!   J. A backup file is a second live Agent Wallet. Two roots, one key, both
//!      unlocked at once, both signing.
//!
//! G is fail-closed and correct. I and J are why a restore cannot simply be
//! offered the way the Personal Wallet offers one.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use hpay_companion_protocol::{DeviceRole, MobileWitnessState, SoftwareDeviceIdentity};

use super::desktop_witness_flow::{
    desktop_approved_operation, pair_desktop_agent, payment_request, settle_with_witness,
};
use super::fixtures::*;
use super::pilot_node::*;
use super::*;
use crate::service::companion::session::composite_registry;
use crate::service::companion::tests::witness::pair_unregistered_rotation_candidate;

fn walk(root: &Path, prefix: &Path, out: &mut Vec<(String, u64)>) {
    let mut entries: Vec<_> = fs::read_dir(root).unwrap().filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(prefix)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            out.push((format!("{relative}/"), 0));
            walk(&path, prefix, out);
        } else {
            out.push((relative, fs::metadata(&path).unwrap().len()));
        }
    }
}

fn tree(root: &Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
    fs::set_permissions(to, fs::metadata(from).unwrap().permissions()).unwrap();
}

/// Everything under the storage root except the process lock, which is
/// runtime-only and is recreated by `AgentStorage::open`.
fn copy_backup(from: &Path, to: &Path) {
    copy_tree(from, to);
    let _ = fs::remove_file(to.join(".agent-wallet.lock"));
}

fn state_of(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> crate::service::AgentWalletState {
    let (state_master, journal_key) = keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
}

/// A wallet that has really paid once, witnessed by a real phone, so its
/// journal, its witness chain and its operation history are all non-trivial.
async fn wallet_with_one_settled_payment(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    MockPilotNode,
    u64,
) {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(now).await;
    let after =
        settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, now + 40).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    (root, manager, wallet_id, mobile, node, after)
}

/// PROBE A. What an Agent Wallet is, on disk, after a real payment.
#[tokio::test]
async fn probe_a_what_is_durable() {
    let (root, manager, wallet_id, _mobile, _node, _after) =
        wallet_with_one_settled_payment(70_000).await;
    let listing = tree(root.path());
    println!("--- PROBE A: storage root tree ---");
    for (name, size) in &listing {
        println!("{name}\t{size}");
    }
    let state = state_of(&manager, &wallet_id);
    println!(
        "journal_sequence={} head={} operations={} anchor_seq={}",
        state.journal_sequence,
        state.journal_head_hash,
        state.operations.len(),
        state
            .rollback_witness
            .as_ref()
            .map_or(0, |witness| witness.last_anchor_sequence)
    );

    // The exact durable set. Anything added here is something a backup would
    // have to carry, so this list is deliberately brittle.
    let names: Vec<&str> = listing.iter().map(|(name, _)| name.as_str()).collect();
    let wallet_dir = format!("wallets/{}", wallet_id.as_str());
    for required in [
        ".storage-version",
        "registry.json",
        "wallets/",
        &format!("{wallet_dir}/"),
        &format!("{wallet_dir}/journal.json"),
        &format!("{wallet_dir}/vault.json"),
        &format!("{wallet_dir}/wallet_state.enc.json"),
        &format!("{wallet_dir}/wallet_state_pending.enc.json"),
    ] {
        assert!(
            names.contains(&required),
            "{required} is durable state and must be accounted for; got {names:?}"
        );
    }
    // `sessions/` and `l2/` are created and never written to. `journal.json` is
    // authenticated but not encrypted: it is a plaintext record of what this
    // wallet did and when, so it can never leave the machine unwrapped.
    let journal_raw =
        fs::read_to_string(root.path().join(&wallet_dir).join("journal.json")).unwrap();
    for readable in [
        "\"wallet_scope\":\"agent_wallet:",
        "\"event_kind\":\"approval_granted\"",
        "\"event_kind\":\"transaction_signed\"",
        "\"event_kind\":\"rollback_witness_accepted\"",
        "\"occurred_at_unix_ms\"",
    ] {
        assert!(
            journal_raw.contains(readable),
            "the journal is readable plaintext and {readable} should be legible in it"
        );
    }
}

/// PROBE B. The wallet directory alone, without the registry, on a new machine.
#[tokio::test]
async fn probe_b_wallet_directory_without_registry() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(71_000).await;
    drop(manager);
    let fresh = tempfile::tempdir().unwrap();
    copy_tree(&root.path().join("wallets"), &fresh.path().join("wallets"));
    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    println!(
        "--- PROBE B: list_wallets = {:?}",
        restored.list_wallets().unwrap().len()
    );
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE B: unlock = {outcome:?}");
    assert!(outcome.is_err());
}

/// PROBE C. The whole storage root, copied, on a new machine.
#[tokio::test]
async fn probe_c_whole_root_copied() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(72_000).await;
    let before = state_of(&manager, &wallet_id);
    let (before_seq, before_head) = (before.journal_sequence, before.journal_head_hash.clone());
    let before_anchor = before.rollback_witness.as_ref().map(|witness| {
        (
            witness.last_anchor_sequence,
            witness.last_anchor_hash.clone(),
        )
    });
    drop(manager);

    let fresh = tempfile::tempdir().unwrap();
    copy_backup(root.path(), fresh.path());
    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE C: unlock = {outcome:?}");
    let unlocked = outcome.unwrap();
    let after_state = state_of(&restored, &wallet_id);
    println!(
        "--- PROBE C: address {} seq {} -> {} anchor {:?} -> {:?}",
        unlocked.address,
        before_seq,
        after_state.journal_sequence,
        before_anchor,
        after_state.rollback_witness.as_ref().map(|witness| (
            witness.last_anchor_sequence,
            witness.last_anchor_hash.clone()
        ))
    );
    assert_eq!(after_state.address, before.address);
    // The unlock itself journals, so the restored journal advances past the copy.
    assert!(after_state.journal_sequence > before_seq);
    assert_ne!(after_state.journal_head_hash, before_head);
}

/// PROBE D. A key-only backup: the vault and the registry, nothing else.
#[tokio::test]
async fn probe_d_vault_only() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(73_000).await;
    drop(manager);

    let fresh = tempfile::tempdir().unwrap();
    fs::create_dir_all(fresh.path()).unwrap();
    fs::copy(
        root.path().join("registry.json"),
        fresh.path().join("registry.json"),
    )
    .unwrap();
    fs::copy(
        root.path().join(".storage-version"),
        fresh.path().join(".storage-version"),
    )
    .unwrap();
    let wallet_dir = fresh.path().join("wallets").join(wallet_id.as_str());
    fs::create_dir_all(&wallet_dir).unwrap();
    fs::copy(
        root.path()
            .join("wallets")
            .join(wallet_id.as_str())
            .join("vault.json"),
        wallet_dir.join("vault.json"),
    )
    .unwrap();

    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE D: vault-only unlock = {outcome:?}");
    assert!(outcome.is_err());
}

/// PROBE E. Everything except the journal.
#[tokio::test]
async fn probe_e_no_journal() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(74_000).await;
    drop(manager);

    let fresh = tempfile::tempdir().unwrap();
    copy_backup(root.path(), fresh.path());
    fs::remove_file(
        fresh
            .path()
            .join("wallets")
            .join(wallet_id.as_str())
            .join("journal.json"),
    )
    .unwrap();
    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE E: journal-less unlock = {outcome:?}");
    assert!(outcome.is_err());
}

/// PROBE F. Everything except the encrypted state, journal kept.
#[tokio::test]
async fn probe_f_no_state() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(75_000).await;
    drop(manager);

    let fresh = tempfile::tempdir().unwrap();
    copy_backup(root.path(), fresh.path());
    fs::remove_file(
        fresh
            .path()
            .join("wallets")
            .join(wallet_id.as_str())
            .join("wallet_state.enc.json"),
    )
    .unwrap();
    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE F: state-less unlock = {outcome:?}");
    assert!(outcome.is_err());
}

/// PROBE G. A backup restored to an earlier point, meeting the phone that
/// already moved past it.
#[tokio::test]
async fn probe_g_restored_wallet_meets_the_same_phone() {
    let now = 76_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 3);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 4,
    );

    // The phone's own durable anti-rollback state, the real type the handset keeps.
    let registry = {
        let state = state_of(&manager, &wallet_id);
        let signer = manager
            .session(&wallet_id)
            .unwrap()
            .desktop_companion_signer
            .clone();
        composite_registry(&state, &signer, now + 5).unwrap()
    };
    let desktop_device_id = {
        let state = state_of(&manager, &wallet_id);
        hpay_companion_protocol::DeviceId::parse(state.primary_signing_device_id.clone()).unwrap()
    };
    let mut phone = MobileWitnessState::new(
        wallet_id.to_string(),
        desktop_device_id,
        mobile.device_id().clone(),
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND.to_owned(),
        TESTNET_ANCHOR.to_owned(),
        1,
        1,
        1,
    )
    .unwrap();

    // ---- One complete payment, witnessed by that phone at every phase. ----
    let mut clock = now + 10;
    let operation_id = manager
        .create_payment_intent(
            &authorization,
            payment_request("probe-g-one", clock + 600),
            clock,
        )
        .await
        .unwrap()
        .operation_id;
    clock += 2;
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, clock)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(&wallet_id, approval, clock)
        .await
        .unwrap();
    clock += 2;
    for _ in 0..8 {
        let view = manager
            .list_operations_admin(&wallet_id, clock)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_id)
            .unwrap();
        if view.status == OperationStatus::Committed {
            break;
        }
        if view.status == OperationStatus::ReconciliationRequired {
            let hash = view.tx_hash.clone().unwrap();
            manager
                .confirm_broadcast(&wallet_id, &operation_id, &hash, clock)
                .unwrap();
            clock += 2;
            continue;
        }
        let anchor = manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), clock)
            .await
            .unwrap();
        phone.accept_anchor(&anchor, &registry, clock + 1).unwrap();
        let receipt = signed_receipt(&anchor, &mobile, clock + 1).await;
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, clock + 2)
            .await
            .unwrap();
        clock += 4;
    }
    let backup_state = state_of(&manager, &wallet_id);
    let backup_anchor = backup_state
        .rollback_witness
        .as_ref()
        .map(|witness| witness.last_anchor_sequence)
        .unwrap();
    println!(
        "--- PROBE G: backup taken at journal seq {} anchor seq {} (phone at {})",
        backup_state.journal_sequence, backup_anchor, phone.last_anchor_sequence
    );

    // ---- THE BACKUP IS TAKEN HERE ----
    let backup_dir: PathBuf = tempfile::tempdir().unwrap().keep();
    copy_backup(root.path(), &backup_dir);

    // ---- The owner keeps using the wallet: a second full payment. ----
    let operation_two = manager
        .create_payment_intent(
            &authorization,
            payment_request("probe-g-two", clock + 600),
            clock,
        )
        .await
        .unwrap()
        .operation_id;
    clock += 2;
    let approval_two = manager
        .pending_approval(&wallet_id, &operation_two, clock)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(&wallet_id, approval_two, clock)
        .await
        .unwrap();
    clock += 2;
    for _ in 0..8 {
        let view = manager
            .list_operations_admin(&wallet_id, clock)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation_two)
            .unwrap();
        if view.status == OperationStatus::Committed {
            break;
        }
        if view.status == OperationStatus::ReconciliationRequired {
            let hash = view.tx_hash.clone().unwrap();
            manager
                .confirm_broadcast(&wallet_id, &operation_two, &hash, clock)
                .unwrap();
            clock += 2;
            continue;
        }
        let anchor = manager
            .pending_rollback_anchor(&wallet_id, &operation_two, mobile.device_id(), clock)
            .await
            .unwrap();
        phone.accept_anchor(&anchor, &registry, clock + 1).unwrap();
        let receipt = signed_receipt(&anchor, &mobile, clock + 1).await;
        manager
            .apply_mobile_witness_and_broadcast(&wallet_id, receipt, clock + 2)
            .await
            .unwrap();
        clock += 4;
    }
    let live = state_of(&manager, &wallet_id);
    println!(
        "--- PROBE G: live wallet now at journal seq {} anchor seq {} (phone at {})",
        live.journal_sequence,
        live.rollback_witness
            .as_ref()
            .map(|witness| witness.last_anchor_sequence)
            .unwrap(),
        phone.last_anchor_sequence
    );
    println!(
        "--- PROBE G: spent today at backup {} vs live {}",
        backup_state.operations.len(),
        live.operations.len()
    );
    drop(manager);

    // ---- The machine dies. The owner restores the backup. ----
    let mut restored = AgentWalletManager::open(&backup_dir).unwrap();
    restored.unlock(&wallet_id, PASSPHRASE, clock + 10).unwrap();
    let restored_state = state_of(&restored, &wallet_id);
    println!(
        "--- PROBE G: restored wallet is at anchor seq {} with {} operations",
        restored_state
            .rollback_witness
            .as_ref()
            .map(|witness| witness.last_anchor_sequence)
            .unwrap(),
        restored_state.operations.len()
    );

    // The restored wallet tries to pay again, and asks the same phone to witness.
    let operation_three = restored
        .create_payment_intent(
            &authorization,
            payment_request("probe-g-three", clock + 700),
            clock + 12,
        )
        .await
        .unwrap()
        .operation_id;
    let approval_three = restored
        .pending_approval(&wallet_id, &operation_three, clock + 13)
        .unwrap();
    restored
        .approve_desktop_and_broadcast(&wallet_id, approval_three, clock + 14)
        .await
        .unwrap();
    let anchor = restored
        .pending_rollback_anchor(&wallet_id, &operation_three, mobile.device_id(), clock + 16)
        .await
        .unwrap();
    println!(
        "--- PROBE G: restored desktop offers anchor seq {} prev {}",
        anchor.anchor.anchor_sequence, anchor.anchor.previous_anchor_hash
    );
    let verdict = phone.accept_anchor(&anchor, &registry, clock + 17);
    println!("--- PROBE G: the phone answers {verdict:?}");
    assert!(verdict.is_err());
    let _ = fs::remove_dir_all(&backup_dir);
}

/// PROBE H. A registry rebuilt on the new machine instead of restored.
///
/// `registry.json` carries `store_id`, and `store_id` is inside the AAD and the
/// HKDF info of every encrypted state file. This asks whether an owner could
/// carry only the wallet directory and let the target machine make its own.
#[tokio::test]
async fn probe_h_rebuilt_registry() {
    let (root, manager, wallet_id, _mobile, _node, after) =
        wallet_with_one_settled_payment(77_000).await;
    let address = state_of(&manager, &wallet_id).address.clone();
    drop(manager);

    let fresh = tempfile::tempdir().unwrap();
    copy_backup(root.path(), fresh.path());
    // A registry generated here: same wallet entry, this machine's own store id,
    // which is exactly what `AgentStorage::open` writes on a clean root.
    let rebuilt = serde_json::json!({
        "schema_version": 1,
        "store_id": uuid::Uuid::new_v4().to_string(),
        "wallets": {
            wallet_id.as_str(): {
                "wallet_id": wallet_id.as_str(),
                "address": address,
                "created_at_unix": 77_000,
            }
        }
    });
    hacash_wallet_core::paths::secure_write(
        &fresh.path().join("registry.json"),
        &serde_json::to_vec(&rebuilt).unwrap(),
    )
    .unwrap();

    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    println!(
        "--- PROBE H: the rebuilt registry lists {} wallet(s)",
        restored.list_wallets().unwrap().len()
    );
    let outcome = restored.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE H: unlock with a rebuilt store id = {outcome:?}");
    assert!(outcome.is_err());
}

async fn one_payment(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    authorization: &crate::service::AgentAuthorization,
    mobile: &SoftwareDeviceIdentity,
    key: &str,
    mut clock: u64,
) -> u64 {
    let operation_id = manager
        .create_payment_intent(authorization, payment_request(key, clock + 600), clock)
        .await
        .unwrap()
        .operation_id;
    clock += 2;
    let approval = manager
        .pending_approval(wallet_id, &operation_id, clock)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(wallet_id, approval, clock)
        .await
        .unwrap();
    clock += 2;
    settle_with_witness(manager, wallet_id, &operation_id, mobile, clock).await
}

/// PROBE I. Does a restored wallet have an exit, and what does taking it cost?
///
/// The paired phone fail-closes on the rollback (PROBE G). This asks whether the
/// documented lost-phone recovery re-baselines a fresh phone onto the restored
/// position, and what the wallet then believes about what it already spent.
#[tokio::test]
async fn probe_i_restored_wallet_rebaselines_onto_a_fresh_phone() {
    use hpay_companion_protocol::{
        SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationMode,
        WitnessRotationPhase, WitnessRotationReason,
    };

    let now = 78_000;
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 3);
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        now + 4,
    );

    let mut clock = one_payment(
        &mut manager,
        &wallet_id,
        &authorization,
        &mobile,
        "probe-i-one",
        now + 10,
    )
    .await
        + 4;
    let backup_state = state_of(&manager, &wallet_id);
    let backup_spent = manager
        .overview(&wallet_id, clock)
        .await
        .unwrap()
        .spent_today_units;
    println!(
        "--- PROBE I: backup taken with {} operation(s), spent today {backup_spent:?}, anchor seq {}",
        backup_state.operations.len(),
        backup_state
            .rollback_witness
            .as_ref()
            .unwrap()
            .last_anchor_sequence
    );
    let backup_dir: PathBuf = tempfile::tempdir().unwrap().keep();
    copy_backup(root.path(), &backup_dir);

    clock = one_payment(
        &mut manager,
        &wallet_id,
        &authorization,
        &mobile,
        "probe-i-two",
        clock,
    )
    .await
        + 4;
    clock = one_payment(
        &mut manager,
        &wallet_id,
        &authorization,
        &mobile,
        "probe-i-three",
        clock,
    )
    .await
        + 4;
    let live_spent = manager
        .overview(&wallet_id, clock)
        .await
        .unwrap()
        .spent_today_units;
    let live_state = state_of(&manager, &wallet_id);
    println!(
        "--- PROBE I: live wallet has {} operation(s), spent today {live_spent:?}, anchor seq {}, submissions {}",
        live_state.operations.len(),
        live_state
            .rollback_witness
            .as_ref()
            .unwrap()
            .last_anchor_sequence,
        node.submit_count.load(Ordering::SeqCst)
    );
    drop(manager);

    // ---- The machine dies. The owner restores. ----
    let mut restored = AgentWalletManager::open(&backup_dir).unwrap();
    restored.unlock(&wallet_id, PASSPHRASE, clock + 10).unwrap();
    let restored_spent = restored
        .overview(&wallet_id, clock + 11)
        .await
        .unwrap()
        .spent_today_units;
    println!("--- PROBE I: the restored wallet believes it spent {restored_spent:?} today");
    // THE COST, WITH A NUMBER ON IT. Two payments that really reached the node
    // are gone from the wallet's own record, and the agent's daily window with
    // them. Nothing in the wallet notices.
    assert_eq!(restored_spent, backup_spent);
    assert!(
        restored_spent < live_spent,
        "restoring rolled the spend window back from {live_spent:?} to {restored_spent:?}"
    );
    assert_eq!(
        state_of(&restored, &wallet_id).operations.len(),
        1,
        "the restored wallet has lost the record of the payments it made after the backup"
    );

    // ---- The exit: a fresh phone, re-baselined onto the restored position. ----
    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = restored
        .prepare_witness_rotation(
            &wallet_id,
            "probe-i-recovery".to_owned(),
            replacement.device_id(),
            WitnessRotationMode::LostPhoneRecovery,
            WitnessRotationReason::LostPhone,
            clock + 12,
        )
        .await
        .unwrap();
    println!(
        "--- PROBE I: recovery rotation baselines the new phone at anchor seq {} epoch {} -> {}",
        record.last_accepted_anchor_sequence, record.old_witness_epoch, record.new_witness_epoch
    );
    pair_unregistered_rotation_candidate(
        &mut restored,
        &wallet_id,
        &record.rotation_id,
        &replacement,
        clock + 13,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        clock + 14,
    )
    .unwrap();
    restored
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(baseline, &replacement)
                .await
                .unwrap(),
            clock + 14,
        )
        .unwrap();
    let completion = restored
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, clock + 15)
        .await
        .unwrap();
    restored
        .complete_witness_rotation(
            &wallet_id,
            signed_receipt(&completion, &replacement, clock + 16).await,
            clock + 16,
        )
        .unwrap();
    assert_eq!(
        restored
            .overview(&wallet_id, clock + 17)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );

    // ---- And now it pays again, on the rolled-back budget. ----
    let done = one_payment(
        &mut restored,
        &wallet_id,
        &authorization,
        &replacement,
        "probe-i-after-restore",
        clock + 20,
    )
    .await;
    let final_spent = restored
        .overview(&wallet_id, done + 1)
        .await
        .unwrap()
        .spent_today_units;
    println!(
        "--- PROBE I: after restore the wallet paid again; it believes it spent {final_spent:?} today, node saw {} submissions",
        node.submit_count.load(Ordering::SeqCst)
    );
    // Four payments really reached the node. The wallet thinks it made two.
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 4);
    assert!(
        final_spent < live_spent,
        "after restoring and paying again the wallet still believes it spent {final_spent:?}, \
         less than the {live_spent:?} it had already spent before the backup was restored"
    );
    let _ = fs::remove_dir_all(&backup_dir);
}

/// PROBE J. A backup restored while the original is still alive.
///
/// The Agent Wallet store lock is one exclusive lock per storage root. A backup
/// is a second root. This asks what stops two copies of the same Agent Wallet,
/// holding the same blockchain key, from both running.
#[tokio::test]
async fn probe_j_two_live_copies_of_one_wallet() {
    let (root, mut manager, wallet_id, mobile, node, after) =
        wallet_with_one_settled_payment(79_000).await;

    let fork: PathBuf = tempfile::tempdir().unwrap().keep();
    copy_backup(root.path(), &fork);

    // Both roots open at once, in one process, each taking its own lock.
    let mut second = AgentWalletManager::open(&fork).unwrap();
    let opened = second.unlock(&wallet_id, PASSPHRASE, after + 10);
    println!("--- PROBE J: the copy unlocks alongside the original = {opened:?}");
    let original_address = state_of(&manager, &wallet_id).address.clone();
    let copy_address = state_of(&second, &wallet_id).address.clone();
    println!("--- PROBE J: original address {original_address}, copy address {copy_address}");
    assert_eq!(original_address, copy_address, "same key, two roots");

    // The original keeps working; the phone is still its phone.
    let authorization = pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        after + 12,
    );
    let done = one_payment(
        &mut manager,
        &wallet_id,
        &authorization,
        &mobile,
        "probe-j-original",
        after + 14,
    )
    .await;
    println!(
        "--- PROBE J: the original paid again; node saw {} submissions",
        node.submit_count.load(Ordering::SeqCst)
    );

    // And the copy signs a transaction of its own with the same key.
    let copy_authorization = pair_desktop_agent(
        &mut second,
        &wallet_id,
        ApprovalMode::DesktopManual,
        done + 4,
    );
    let operation = second
        .create_payment_intent(
            &copy_authorization,
            payment_request("probe-j-copy", done + 600),
            done + 6,
        )
        .await
        .unwrap()
        .operation_id;
    let approval = second
        .pending_approval(&wallet_id, &operation, done + 7)
        .unwrap();
    let signed = second
        .approve_desktop_and_broadcast(&wallet_id, approval, done + 8)
        .await
        .unwrap();
    println!(
        "--- PROBE J: the copy signed its own transaction: {:?} tx {:?}",
        signed.status, signed.tx_hash
    );
    assert_eq!(signed.status, OperationStatus::SignedAwaitingWitness);
    assert!(signed.tx_hash.is_some());
    let _ = fs::remove_dir_all(&fork);
}
