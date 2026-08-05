//! THE AGENT WALLET RESTORE IS ONE TRANSACTION, EXECUTED AT EVERY WINDOW.
//!
//! `restore_agent_wallet_backup` performs five durable writes in a row - the
//! write-ahead record, the layout, the vault, the journal, the state, the pending
//! removal - and publishes the registry entry last. Every one of those is a
//! durable write with another step after it, so every one of them is crashed at
//! here, by name, and the store is then inspected from a FRESH manager, which is
//! what a real crash produces.
//!
//! The claim under test is not "it usually works". It is: for every window, after
//! the next open, the store holds either a completely restored wallet or no trace
//! of that wallet at all - and in the second case the owner's retry of the same
//! backup succeeds.
//!
//! Before the write-ahead record existed this was false at five of the eight
//! windows: the keys landed, the registry never did, and the restore's own
//! pre-check then answered `AgentWalletAlreadyExists` for ever, to the retry and
//! to a retry after a reboot alike. `the_pre_check_no_longer_mistakes_its_own_
//! debris_for_a_live_wallet` is that exact executed case.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::desktop_witness_flow::settle_with_witness;
use super::fixtures::{PASSPHRASE, TESTNET_ANCHOR};
use super::*;
use crate::service::{AgentWalletBackupAcknowledgement, RestoreCrashPoint};

fn ack() -> AgentWalletBackupAcknowledgement {
    AgentWalletBackupAcknowledgement::complete()
}

/// Every path under a root, relative to it, so two moments of a store can be
/// compared as sets rather than by hand.
fn tree(root: &Path) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            found.insert(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
    found
}

/// A wallet with real history, and a backup of it.
async fn backup_of_a_used_wallet(at: u64) -> String {
    let (source_root, mut source, wallet_id, mobile, operation_id, _node, _authorization) =
        super::desktop_witness_flow::desktop_approved_operation(at).await;
    let settled_at =
        settle_with_witness(&mut source, &wallet_id, &operation_id, &mobile, at + 20).await;
    let backup = source
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, ack(), settled_at)
        .unwrap();
    drop(source);
    drop(source_root);
    backup
}

fn wallet_id_of(backup: &str) -> AgentWalletId {
    let root = tempfile::tempdir().unwrap();
    let manager = AgentWalletManager::open(root.path()).unwrap();
    let preview = manager.preview_agent_wallet_backup(backup).unwrap();
    AgentWalletId::parse(preview.wallet_id).unwrap()
}

/// EXECUTION: EVERY DURABLE-WRITE WINDOW IN THE RESTORE, CRASHED AT.
///
/// One fresh store per window, one crash, then a fresh `AgentWalletManager::open`
/// over the same directory - the reboot. The assertion is all-or-nothing, and it
/// is made against the disk, not against the return value.
#[tokio::test]
async fn every_window_in_the_restore_lands_all_four_or_none() {
    let backup = backup_of_a_used_wallet(120_000).await;
    let wallet_id = wallet_id_of(&backup);
    let at = 120_500;

    for point in RestoreCrashPoint::ALL {
        let target_root = tempfile::tempdir().unwrap();
        let mut target = AgentWalletManager::open(target_root.path()).unwrap();
        let untouched = tree(target_root.path());

        target.crash_restore_at = Some(point);
        let interrupted = target.restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), at);
        assert!(
            interrupted.is_err(),
            "{point:?}: the armed restore must not have completed"
        );
        // Nothing may be discoverable while the transaction is open, whichever
        // window it stopped at.
        assert!(
            !target
                .list_wallets()
                .unwrap()
                .iter()
                .any(|entry| entry.wallet_id == wallet_id)
                || point == RestoreCrashPoint::AfterRegistry,
            "{point:?}: an uncommitted restore must not be listed"
        );
        drop(target);

        // THE REBOOT. This is the only place the recovery gets to run.
        let mut rebooted = AgentWalletManager::open(target_root.path()).unwrap();
        let registered = rebooted
            .list_wallets()
            .unwrap()
            .iter()
            .any(|entry| entry.wallet_id == wallet_id);
        let wallet_root = target_root.path().join("wallets").join(wallet_id.as_str());
        let after = tree(target_root.path());

        if registered {
            // The commit point was reached, so EVERYTHING must be here and the
            // wallet must actually work.
            assert_eq!(
                point,
                RestoreCrashPoint::AfterRegistry,
                "only a crash after the registry entry may leave a restored wallet"
            );
            for document in [
                "vault.json",
                "journal.json",
                "wallet_state.enc.json",
                ".storage-version",
            ] {
                assert!(
                    wallet_root.join(document).exists(),
                    "{point:?}: a committed restore is missing {document}"
                );
            }
            let status = rebooted.unlock(&wallet_id, PASSPHRASE, at + 5).unwrap();
            assert_eq!(status.wallet_id, wallet_id);
            // And the write-ahead record is retired rather than left to be
            // re-run against a live wallet for ever.
            assert!(
                !target_root
                    .path()
                    .join(".agent-restore-journal")
                    .exists(),
                "{point:?}: a committed restore must retire its own record"
            );
            let again =
                rebooted.restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), at + 6);
            assert_eq!(
                again.unwrap_err(),
                AgentWalletError::AgentWalletAlreadyExists,
                "{point:?}: a live wallet is never overwritten by a second restore"
            );
        } else {
            // Nothing committed, so there must be NO TRACE - not an empty
            // directory, not a marker, not the record itself.
            assert!(
                !wallet_root.exists(),
                "{point:?}: an uncommitted restore left {} behind",
                wallet_root.display()
            );
            assert_eq!(
                after, untouched,
                "{point:?}: an uncommitted restore left the store changed"
            );

            // AND THE OWNER'S RETRY OF THE SAME BACKUP WORKS. This is the part
            // that used to be impossible.
            let outcome = rebooted
                .restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), at + 7)
                .unwrap_or_else(|error| {
                    panic!("{point:?}: the owner's retry was refused: {error:?}")
                });
            assert_eq!(outcome.wallet_id, wallet_id);
            rebooted.unlock(&wallet_id, PASSPHRASE, at + 8).unwrap();
        }
        drop(rebooted);
        drop(target_root);
    }
}

/// EXECUTION: THE SAME CRASH, WITHOUT A REBOOT. A retry inside the same process
/// must be answered the same way, because an owner who presses the button again
/// is far more likely than one who restarts the app.
#[tokio::test]
async fn the_pre_check_no_longer_mistakes_its_own_debris_for_a_live_wallet() {
    let backup = backup_of_a_used_wallet(121_000).await;
    let wallet_id = wallet_id_of(&backup);
    let at = 121_500;
    let target_root = tempfile::tempdir().unwrap();
    let mut target = AgentWalletManager::open(target_root.path()).unwrap();

    // The window the enumeration executed: the vault has landed, the journal
    // never will.
    target.crash_restore_at = Some(RestoreCrashPoint::AfterVault);
    let interrupted = target.restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), at);
    assert_eq!(interrupted.unwrap_err(), AgentWalletError::PersistenceFailed);
    let wallet_root = target_root.path().join("wallets").join(wallet_id.as_str());
    assert!(
        wallet_root.join("vault.json").exists(),
        "the crash must be real: the vault landed"
    );
    assert!(
        !wallet_root.join("wallet_state.enc.json").exists(),
        "and the state did not"
    );
    assert!(
        target_root.path().join(".agent-restore-journal").exists(),
        "the write-ahead record is what a crash leaves behind"
    );
    assert!(target.list_wallets().unwrap().is_empty());

    // THE OWNER PRESSES RESTORE AGAIN, in the same process, with no reboot.
    target.crash_restore_at = None;
    let outcome = target
        .restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), at + 1)
        .unwrap();
    assert_eq!(outcome.wallet_id, wallet_id);
    assert!(!target_root.path().join(".agent-restore-journal").exists());
    let status = target.unlock(&wallet_id, PASSPHRASE, at + 2).unwrap();
    assert_eq!(status.wallet_id, wallet_id);
    drop(target);
    drop(target_root);
}

/// THE ROLLBACK REMOVES EVERYTHING A REAL, FULLY USED WALLET DIRECTORY HOLDS.
///
/// The allow-list the rollback deletes through is a fixed set of names, and a
/// name it does not know is left behind by design. That is only safe while the
/// list actually covers what the wallet writes, so this drives a wallet through
/// creation, an unlock, a pairing, a payment, a witness settlement and an
/// emergency stop - which is what produces the sessions and l2 directories, the
/// pending state slot and the emergency marker - and then makes the rollback
/// remove that exact directory.
#[tokio::test]
async fn the_rollback_covers_every_file_a_used_wallet_writes() {
    let at = 122_000;
    let (root, mut manager, wallet_id, mobile, operation_id, _node, _authorization) =
        super::desktop_witness_flow::desktop_approved_operation(at).await;
    settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, at + 20).await;
    // The emergency marker is a durable file inside the same directory.
    manager
        .emergency_controller(&wallet_id)
        .unwrap()
        .request_stop()
        .unwrap();
    let wallet_root = manager
        .storage
        .paths(&wallet_id)
        .unwrap()
        .wallet_root()
        .to_path_buf();
    let before: BTreeSet<PathBuf> = tree(&wallet_root);
    assert!(
        before.contains(Path::new("vault.json"))
            && before.contains(Path::new("journal.json"))
            && before.contains(Path::new("wallet_state.enc.json"))
            && before.contains(Path::new("wallet_state_pending.enc.json"))
            && before.contains(Path::new(".emergency-stop-v1"))
            && before.contains(Path::new("sessions"))
            && before.contains(Path::new("l2")),
        "the fixture must produce a fully populated wallet directory: {before:?}"
    );

    // Put the store into exactly the shape a crashed restore leaves: the wallet
    // is not in the registry, and a write-ahead record names it.
    let mut registry = manager.storage.load_registry().unwrap();
    registry.wallets.remove(wallet_id.as_str());
    manager.storage.save_registry(&registry).unwrap();
    manager.storage.begin_wallet_restore(&wallet_id).unwrap();

    manager
        .storage
        .recover_interrupted_wallet_restore()
        .unwrap();
    assert!(
        !wallet_root.exists(),
        "the rollback left part of a used wallet directory behind: {:?}",
        tree(&wallet_root)
    );
    assert!(!root.path().join(".agent-restore-journal").exists());
    drop(manager);
    drop(root);
}

/// A RECOVERY NEVER DELETES SOMETHING IT DID NOT WRITE, AND NEVER DELETES A
/// WALLET THE REGISTRY KNOWS ABOUT.
#[test]
fn the_rollback_refuses_a_registered_wallet_and_spares_a_foreign_file() {
    let (root, manager, wallet_id) = super::fixtures::create_manager(123_000);
    let wallet_root = manager
        .storage
        .paths(&wallet_id)
        .unwrap()
        .wallet_root()
        .to_path_buf();

    // 1. THE WALLET IS REGISTERED. A record naming it authorises nothing.
    manager.storage.begin_wallet_restore(&wallet_id).unwrap();
    manager
        .storage
        .recover_interrupted_wallet_restore()
        .unwrap();
    assert!(
        wallet_root.join("vault.json").exists(),
        "a registered wallet is never removed by a recovery"
    );
    assert!(!root.path().join(".agent-restore-journal").exists());

    // 2. AN UNREGISTERED WALLET DIRECTORY WITH A FOREIGN FILE IN IT. The four
    //    documents go, because a retry has to be able to run; the owner's file
    //    stays, and so does the directory holding it.
    let foreign = wallet_root.join("owner-notes.txt");
    fs::write(&foreign, b"do not delete me").unwrap();
    let mut registry = manager.storage.load_registry().unwrap();
    registry.wallets.remove(wallet_id.as_str());
    manager.storage.save_registry(&registry).unwrap();
    manager.storage.begin_wallet_restore(&wallet_id).unwrap();
    manager
        .storage
        .recover_interrupted_wallet_restore()
        .unwrap();
    assert!(foreign.exists(), "a foreign file must never be deleted");
    assert!(wallet_root.exists(), "and its directory must survive with it");
    for document in [
        "vault.json",
        "journal.json",
        "wallet_state.enc.json",
        "wallet_state_pending.enc.json",
    ] {
        assert!(
            !wallet_root.join(document).exists(),
            "{document} must go, or the retry cannot run"
        );
    }
    drop(manager);
    drop(root);
}

/// A RECORD THAT CANNOT BE READ, OR THAT BELONGS TO A DIFFERENT STORE,
/// AUTHORISES NOTHING - AND DOES NOT WEDGE THE STORE EITHER.
#[test]
fn an_unreadable_or_foreign_write_ahead_record_deletes_nothing() {
    let (root, manager, wallet_id) = super::fixtures::create_manager(124_000);
    let wallet_root = manager
        .storage
        .paths(&wallet_id)
        .unwrap()
        .wallet_root()
        .to_path_buf();
    let record_path = root.path().join(".agent-restore-journal");
    let mut registry = manager.storage.load_registry().unwrap();
    registry.wallets.remove(wallet_id.as_str());
    manager.storage.save_registry(&registry).unwrap();

    for bytes in [
        b"{}".to_vec(),
        b"not json at all".to_vec(),
        // Well-formed, but naming another store: the only act it could
        // authorise is a deletion here, so it authorises nothing.
        serde_json::to_vec(&serde_json::json!({
            "magic": "hpay_agent_wallet_restore_journal",
            "version": 1,
            "store_id": "00000000-0000-4000-8000-000000000000",
            "wallet_id": wallet_id.as_str(),
        }))
        .unwrap(),
    ] {
        hacash_wallet_core::paths::secure_write(&record_path, &bytes).unwrap();
        manager
            .storage
            .recover_interrupted_wallet_restore()
            .unwrap();
        assert!(
            wallet_root.join("vault.json").exists(),
            "an unauthorised record deleted a vault"
        );
        assert!(
            !record_path.exists(),
            "and it must be retired rather than retried for ever"
        );
    }

    // The wallet is still openable, which is the other half of "does not wedge".
    drop(manager);
    let reopened = AgentWalletManager::open(root.path()).unwrap();
    assert!(reopened.list_wallets().unwrap().is_empty());
    drop(reopened);
    drop(root);
}

/// AN OWNER WHO NEVER RESTORES ANYTHING SEES NOTHING OF ANY OF THIS.
#[test]
fn a_store_that_never_restores_never_grows_a_write_ahead_record() {
    let (root, mut manager, wallet_id) = super::fixtures::create_manager(125_000);
    manager
        .create_wallet(
            CreateAgentWallet {
                network_mode: "testnet".into(),
                node_url: "http://127.0.0.1:18081".into(),
                passphrase: PASSPHRASE.into(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
            },
            125_100,
        )
        .unwrap();
    manager.lock(&wallet_id, 125_200).unwrap();
    drop(manager);
    let reopened = AgentWalletManager::open(root.path()).unwrap();
    assert_eq!(reopened.list_wallets().unwrap().len(), 2);
    assert!(!root.path().join(".agent-restore-journal").exists());
    drop(reopened);
    drop(root);
}
