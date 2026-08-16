//! ENUMERATION PHASE PROBE. Executes a crash at the durable-write windows the
//! enumeration found OUTSIDE `persist_event`, so that "open" and "benign" are
//! observed outcomes rather than readings.
//!
//! Nothing here fixes anything. Each test asserts what the code does TODAY.
//!
//! The crash is executed without adding an injection hook: making the SECOND
//! durable write fail is indistinguishable, from the caller's side, from dying
//! between the first and the second - the first write is on disk, the rest of
//! the function never ran, and the process is gone. A directory in the place of
//! `journal.json` makes `secure_write`'s final `rename` fail after `vault.save`
//! has already landed.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use super::desktop_witness_flow::settle_with_witness;
use super::fixtures::{PASSPHRASE, TESTNET_ANCHOR};
use super::*;
use crate::service::AgentWalletBackupAcknowledgement;

fn ack() -> AgentWalletBackupAcknowledgement {
    AgentWalletBackupAcknowledgement::complete()
}

/// WINDOW R1-R4: `restore_agent_wallet_backup` writes vault, journal, state and
/// only then the registry. A crash after the FIRST of those four used to leave a
/// wallet directory with a vault in it and no registry entry - invisible, and
/// refused for ever by the restore's own pre-check.
///
/// KEPT, AND ITS EXPECTATION INVERTED. The probe still arms the second durable
/// write to fail by occupying `journal.json` with a directory, which is a real
/// filesystem failure rather than an injected one, so it is worth keeping
/// alongside the named crash points in `restore_atomicity`. What has changed is
/// the answer: the write-ahead record makes the retry and the rebooted retry
/// both succeed where both used to return `AgentWalletAlreadyExists`.
#[tokio::test]
async fn crash_between_the_first_and_second_restore_write() {
    let at = 90_000;
    let (source_root, mut source, wallet_id, mobile, operation_id, _node, _authorization) =
        super::desktop_witness_flow::desktop_approved_operation(at).await;
    let settled_at =
        settle_with_witness(&mut source, &wallet_id, &operation_id, &mobile, at + 20).await;
    let backup = source
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, ack(), settled_at)
        .unwrap();
    drop(source);
    drop(source_root);

    // A fresh, empty store: this is where a restore goes.
    let target_root = tempfile::tempdir().unwrap();
    let mut target = AgentWalletManager::open(target_root.path()).unwrap();

    // Arm the second durable write to fail.
    let wallet_root = target_root.path().join("wallets").join(wallet_id.as_str());
    fs::create_dir_all(wallet_root.join(crate::service::JOURNAL_FILE)).unwrap();

    let interrupted = target.restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), settled_at);
    assert!(
        interrupted.is_err(),
        "the armed restore must not have completed: {interrupted:?}"
    );

    let vault_landed = wallet_root.join("vault.json").exists();
    let state_landed = wallet_root.join("wallet_state.enc.json").exists();
    let registered = target
        .list_wallets()
        .unwrap()
        .iter()
        .any(|entry| entry.wallet_id == wallet_id);
    eprintln!(
        "PROBE R: after interrupted restore: vault={vault_landed} state={state_landed} \
         registered={registered} error={interrupted:?}"
    );

    // Remove the instrument. What is left is exactly what a crash leaves.
    fs::remove_dir_all(wallet_root.join(crate::service::JOURNAL_FILE)).unwrap();

    // THE OWNER RETRIES THE SAME BACKUP - the only control they have, and it now
    // works, because the retry rolls the interrupted attempt back first.
    let retry = target.restore_agent_wallet_backup(&backup, PASSPHRASE, ack(), settled_at + 10);
    eprintln!("PROBE R: same-process retry: {retry:?}");
    assert_eq!(retry.unwrap().wallet_id, wallet_id);

    // And a fresh process over the same directory, which is what a real crash
    // produces: the wallet is there, registered, and unlockable.
    drop(target);
    let mut rebooted = AgentWalletManager::open(target_root.path()).unwrap();
    assert!(
        rebooted
            .list_wallets()
            .unwrap()
            .iter()
            .any(|entry| entry.wallet_id == wallet_id),
        "the retried restore must survive a reboot"
    );
    rebooted
        .unlock(&wallet_id, PASSPHRASE, settled_at + 20)
        .unwrap();

    assert!(
        vault_landed && !state_landed,
        "the crash must have been real: the vault landed and the state did not"
    );
    assert!(
        !registered,
        "and nothing was discoverable while the transaction was open"
    );
}

/// WINDOW C1: `create_wallet` writes the vault (durable), journals the creation
/// (durable) and only then publishes the registry entry (durable). Executed by
/// making the LAST write fail, which is the same disk state as a crash just
/// before it.
#[test]
fn crash_between_the_creation_journal_and_the_registry_entry() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();

    // Arm `save_registry` to fail: a directory cannot be replaced by rename.
    let registry_path = root.path().join("registry.json");
    let saved = fs::read(&registry_path).unwrap();
    fs::remove_file(&registry_path).unwrap();
    fs::create_dir_all(&registry_path).unwrap();

    let interrupted = manager.create_wallet(
        CreateAgentWallet {
            network_mode: "testnet".into(),
            node_url: "http://127.0.0.1:18081".into(),
            passphrase: PASSPHRASE.into(),
            block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
            mainnet_pilot_acknowledgement: None,
        },
        70_000,
    );
    eprintln!("PROBE C: interrupted create: {interrupted:?}");
    let orphans: Vec<String> = fs::read_dir(root.path().join("wallets"))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    eprintln!("PROBE C: orphaned wallet directories: {orphans:?}");

    // Remove the instrument and let the owner try again.
    fs::remove_dir_all(&registry_path).unwrap();
    hacash_wallet_core::paths::secure_write(&registry_path, &saved).unwrap();
    let retry = manager.create_wallet(
        CreateAgentWallet {
            network_mode: "testnet".into(),
            node_url: "http://127.0.0.1:18081".into(),
            passphrase: PASSPHRASE.into(),
            block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
            mainnet_pilot_acknowledgement: None,
        },
        70_100,
    );
    eprintln!(
        "PROBE C: retry create: {:?}, registry now lists {}",
        retry.as_ref().map(|created| created.wallet_id.to_string()),
        manager.list_wallets().unwrap().len()
    );
    assert!(interrupted.is_err());
}

/// WINDOW E1/E2: the emergency marker is one durable write, and the
/// authenticated `payments_suspended` transition is a second one. Executed in
/// both orders.
#[test]
fn crash_between_the_emergency_marker_and_the_authenticated_state() {
    let (root, manager, wallet_id) = super::fixtures::create_manager(60_000);
    let controller = manager.emergency_controller(&wallet_id).unwrap();

    // Marker first, authenticated state never. This is the STOP order.
    controller.request_stop().unwrap();
    assert!(controller.marker_path().exists());
    drop(manager);
    let rebooted = AgentWalletManager::open(root.path());
    eprintln!(
        "PROBE E: marker-without-state reopen: {:?}",
        rebooted.as_ref().map(|_| "opened")
    );
    let mut rebooted = rebooted.unwrap();
    let unlocked = rebooted.unlock(&wallet_id, PASSPHRASE, 60_100);
    eprintln!("PROBE E: unlock after marker-only stop: {unlocked:?}");
    let status = rebooted
        .emergency_controller(&wallet_id)
        .unwrap()
        .status(false);
    eprintln!("PROBE E: status after marker-only stop: {status:?}");
    drop(root);
}

/// WINDOW E3: `enable_agent_payments_locally` journals `payments_suspended =
/// false` (durable) and only then removes the emergency marker (durable). A
/// crash between the two leaves an enabled state under a present marker.
///
/// The post-crash disk state is reproduced exactly: run the enable to
/// completion, then put the marker back, which is what the disk looks like when
/// the process died before the removal.
#[test]
fn crash_between_the_enable_journal_and_the_marker_removal() {
    let (root, mut manager, wallet_id) = super::fixtures::create_manager(60_000);
    let controller = manager.emergency_controller(&wallet_id).unwrap();
    controller.request_stop().unwrap();
    manager
        .disable_all_agent_payments(&wallet_id, 60_100)
        .unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, 60_200)
        .unwrap();
    assert!(!controller.marker_path().exists());

    // The crash: the authenticated enable is durable, the marker never went.
    let marker = controller.marker_path().to_path_buf();
    let (state_master, journal_key) = super::fixtures::keys(&manager, &wallet_id);
    let enabled_state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(!enabled_state.payments_suspended);
    drop(enabled_state);
    // Put the marker back through the code that writes it, so the bytes are the
    // real ones and this is the disk a crash leaves, not a hand-made file.
    controller.request_stop().unwrap();
    assert!(marker.exists());
    drop(controller);
    drop(manager);

    let mut rebooted = AgentWalletManager::open(root.path()).unwrap();
    let unlocked = rebooted.unlock(&wallet_id, PASSPHRASE, 60_300);
    eprintln!("PROBE E3: unlock after enable-without-marker-removal: {unlocked:?}");
    let retry = rebooted.enable_agent_payments_locally(&wallet_id, 60_400);
    eprintln!("PROBE E3: owner presses Enable again: {retry:?}");
    eprintln!(
        "PROBE E3: marker still present after retry: {}",
        marker.exists()
    );
    drop(root);
}
