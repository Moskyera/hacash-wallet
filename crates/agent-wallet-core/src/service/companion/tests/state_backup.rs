//! THE AGENT WALLET BACKUP, AND THE COST OF RESTORING IT, EXECUTED.
//!
//! The owner chose "restore everything, exactly as the Personal Wallet does, and
//! warn". This file builds the evidence for both halves of that sentence:
//!
//!   * everything really is restored - the four files, the agents, the policies,
//!     the witness pin, the journal position - and the restored wallet really
//!     runs; and
//!   * each of the four facts in `AGENT_WALLET_BACKUP_WARNING` is a thing this
//!     suite makes happen, not a thing it asserts about a comment. The spend
//!     window really goes backwards. A revoked agent really comes back live.
//!     The old phone really answers `RollbackDetected` for ever. The backup file
//!     plus its passphrase really is a second wallet that can spend, live, at
//!     the same time as the first.
//!
//! Nothing here writes a state document by hand. Every wallet is driven through
//! the real public entry points against the mock Local Pilot node.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::atomic::Ordering;

use hpay_companion_protocol::{CompanionError, MobileWitnessState, SoftwareDeviceIdentity};

use super::super::session::composite_registry;
use super::desktop_witness_flow::{
    desktop_approved_operation, payment_request, settle_with_witness,
};
use super::fixtures::*;
use super::pilot_node::*;
use super::*;
use crate::service::backup::{
    BackupDocument, backup_documents_for_test, replace_backup_document_for_test,
    reseal_backup_metadata_for_test,
};
use crate::service::{
    AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING, AgentWalletBackupAcknowledgement,
    AgentWalletBackupWarning,
};

fn acknowledged() -> AgentWalletBackupAcknowledgement {
    AgentWalletBackupAcknowledgement::complete()
}

/// Opens a brand-new, empty Agent Wallet store, which is where a restore goes.
fn empty_store() -> (tempfile::TempDir, AgentWalletManager) {
    let root = tempfile::tempdir().unwrap();
    let manager = AgentWalletManager::open(root.path()).unwrap();
    (root, manager)
}

fn agent_ids(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId, now: u64) -> Vec<String> {
    let mut ids: Vec<String> = manager
        .list_agents_admin(wallet_id, now)
        .unwrap()
        .into_iter()
        .map(|agent| agent.agent_id.to_string())
        .collect();
    ids.sort();
    ids
}

/// The real durable anti-rollback state a handset persists, built for this
/// wallet's actual desktop device and phone.
fn real_phone(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> (MobileWitnessState, hpay_companion_protocol::DeviceRegistry) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let signer = manager
        .session(wallet_id)
        .unwrap()
        .desktop_companion_signer
        .clone();
    let registry = composite_registry(&state, &signer, now).unwrap();
    let desktop_device_id =
        hpay_companion_protocol::DeviceId::parse(state.primary_signing_device_id.clone()).unwrap();
    drop(state);
    let phone = MobileWitnessState::new(
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
    (phone, registry)
}

/// Settles one payment with a REAL handset: every anchor is accepted by the
/// phone's own durable state before the receipt is signed, so the phone's
/// high-water mark is the honest consequence of the run.
async fn settle_with_real_phone(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
    mobile: &SoftwareDeviceIdentity,
    phone: &mut MobileWitnessState,
    registry: &hpay_companion_protocol::DeviceRegistry,
    mut now: u64,
) -> u64 {
    for _ in 0..8 {
        let view = manager
            .list_operations_admin(wallet_id, now)
            .unwrap()
            .into_iter()
            .find(|view| &view.operation_id == operation_id)
            .unwrap();
        if view.status == OperationStatus::ReconciliationRequired {
            let hash = view.tx_hash.clone().unwrap();
            manager
                .confirm_broadcast(wallet_id, operation_id, &hash, now)
                .unwrap();
            now += 2;
            continue;
        }
        if !view.status.awaits_mobile_witness() {
            return now;
        }
        let proposal = manager
            .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now)
            .await
            .unwrap();
        phone.accept_anchor(&proposal, registry, now).unwrap();
        let receipt = signed_receipt(&proposal, mobile, now + 1).await;
        manager
            .apply_mobile_witness_and_broadcast(wallet_id, receipt, now + 2)
            .await
            .unwrap();
        now += 5;
    }
    panic!("the operation never left the witness lifecycle");
}

/// Drives a wallet through one complete, committed payment so that the four
/// files hold real history: a journal with a real chain, a state with a real
/// spend, a real witness pin and a real agent.
async fn wallet_with_one_settled_payment(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    MockPilotNode,
    crate::service::AgentAuthorization,
    u64,
) {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(now).await;
    let settled_at =
        settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, now + 20).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    (
        root,
        manager,
        wallet_id,
        mobile,
        node,
        authorization,
        settled_at,
    )
}

/// EXECUTION 1: EVERYTHING IS RESTORED, AND THE RESTORED WALLET RUNS.
#[tokio::test]
async fn a_backup_restores_all_four_files_and_the_wallet_still_works() {
    let (root, mut manager, wallet_id, mobile, node, authorization, at) =
        wallet_with_one_settled_payment(80_000).await;
    let before_agents = agent_ids(&mut manager, &wallet_id, at);
    let before_policy = manager
        .agent_policy_admin(
            &wallet_id,
            &AgentId::parse(before_agents[0].clone()).unwrap(),
            at,
        )
        .unwrap();
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let before_state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let before_sequence = before_state.journal_sequence;
    let before_witness = before_state
        .rollback_witness
        .as_ref()
        .map(|witness| (witness.mobile_device_id.clone(), witness.witness_epoch));
    let address = before_state.address.clone();
    drop(before_state);

    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    // ---- THE RESTORE, INTO A COMPLETELY SEPARATE, EMPTY STORE.
    let (restored_root, mut restored) = empty_store();
    let preview = restored.preview_agent_wallet_backup(&backup).unwrap();
    assert_eq!(preview.wallet_id, wallet_id.to_string());
    assert_eq!(preview.address, address);
    assert_eq!(preview.journal_sequence, before_sequence);
    assert!(!preview.already_present);
    assert_eq!(preview.warning, AGENT_WALLET_RESTORE_WARNING);

    let outcome = restored
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 2)
        .unwrap();
    assert_eq!(outcome.wallet_id, wallet_id);
    assert_eq!(outcome.address, address);
    assert_eq!(outcome.network_mode, "testnet");
    assert_eq!(outcome.journal_sequence, before_sequence);
    assert!(
        outcome.witness_phone_must_be_replaced,
        "the restored wallet names a witness phone, so that handset has to be \
         replaced before it can pay - and the outcome says so"
    );
    assert_eq!(outcome.restored_active_agents, 1);

    // ---- ALL FOUR FILES ARE ON DISK IN THE NEW STORE.
    let paths = restored
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    assert!(restored.storage_root().join("registry.json").is_file());
    assert!(paths.join("vault.json").is_file());
    assert!(paths.join("journal.json").is_file());
    assert!(paths.join("wallet_state.enc.json").is_file());
    assert!(
        !paths.join("wallet_state_pending.enc.json").exists(),
        "a restore leaves no pending slot for the next unlock to misread"
    );

    // ---- AND THE RESTORED WALLET OPENS, WITH EVERYTHING IN IT.
    restored.unlock(&wallet_id, PASSPHRASE, at + 3).unwrap();
    let (restored_master, restored_journal) = keys(&restored, &wallet_id);
    let restored_state = restored
        .load_verified_state(&wallet_id, &restored_master, &restored_journal)
        .unwrap();
    assert_eq!(
        restored_state.journal_sequence,
        before_sequence + 1,
        "the restore put the wallet at exactly the position the backup froze - \
         `outcome.journal_sequence` above - and the one record on top of it is \
         this unlock's own `WalletUnlocked`, which every unlock of every wallet \
         writes"
    );
    assert_eq!(
        restored_state
            .rollback_witness
            .as_ref()
            .map(|witness| (witness.mobile_device_id.clone(), witness.witness_epoch)),
        before_witness,
        "the witness pin survives, which is why the old handset will refuse"
    );
    assert_eq!(restored_state.address, address);
    drop(restored_state);
    assert_eq!(agent_ids(&mut restored, &wallet_id, at + 4), before_agents);
    assert_eq!(
        restored
            .agent_policy_admin(
                &wallet_id,
                &AgentId::parse(before_agents[0].clone()).unwrap(),
                at + 5,
            )
            .unwrap(),
        before_policy,
        "the restored agent has exactly the policy it had - which is the point, \
         and also the danger"
    );

    // The restored wallet is a working wallet: it takes a new agent payment.
    assert_eq!(
        restored
            .create_payment_intent(
                &authorization,
                payment_request("after-restore", at + 400),
                at + 6,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    let _ = mobile;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(restored);
    drop(restored_root);
    drop(root);
}

/// EXECUTION 2: THE FIRST WARNING, MADE TO HAPPEN. RESTORING REWINDS THE RECORD
/// OF WHAT HAS BEEN SPENT, AND THE WALLET WILL PAY AGAIN.
///
/// The agent's daily allowance is set so that exactly two of these payments fit
/// in a day. One payment is made, the backup is taken, the second payment is
/// made, and the third is correctly refused - the allowance is spent. Then the
/// backup is restored, and the SAME agent, with the SAME allowance, inside the
/// SAME day, is allowed to pay twice more.
#[tokio::test]
async fn restoring_rewinds_the_spend_record_and_the_wallet_pays_again() {
    let (root, mut manager, wallet_id, mobile, node, mut authorization, mut at) =
        wallet_with_one_settled_payment(81_000).await;
    let agent_id = AgentId::parse(agent_ids(&mut manager, &wallet_id, at)[0].clone()).unwrap();
    let mut policy = manager
        .agent_policy_admin(&wallet_id, &agent_id, at)
        .unwrap();
    // Two payments of 11,000 units fit in a day. Three do not.
    policy.max_daily_units = HacUnits::new(23_000);
    manager
        .update_agent_policy_admin(&wallet_id, &agent_id, policy, at + 1)
        .unwrap();
    // Lowering a limit advances the agent's authorization epoch, so the agent
    // re-authenticates. This is the connector's ordinary behaviour, not
    // anything to do with backups.
    authorization.authorization_epoch += 1;
    at += 2;

    // The wallet has already spent 11,000 on the settled payment above.
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at)
        .unwrap();

    // SPEND THE REST OF THE ALLOWANCE, FOR REAL, THROUGH THE WHOLE LIFECYCLE.
    let second = manager
        .create_payment_intent(&authorization, payment_request("second", at + 400), at + 1)
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &second.operation_id, at + 2)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(&wallet_id, approval, at + 3)
        .await
        .unwrap();
    let after_second = settle_with_witness(
        &mut manager,
        &wallet_id,
        &second.operation_id,
        &mobile,
        at + 4,
    )
    .await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 2);
    // The unlock session is time-bounded, so the owner is at their desk again.
    manager
        .unlock(&wallet_id, PASSPHRASE, after_second + 1)
        .unwrap();

    // THE ALLOWANCE IS SPENT, AND THE WALLET SAYS SO.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("third", after_second + 400),
                after_second + 2,
            )
            .await
            .unwrap_err(),
        AgentWalletError::DailyLimitExceeded,
        "22,000 of a 23,000 daily allowance is spent, so the next payment is refused"
    );

    // ---- THE RESTORE. Same day, same agent, same allowance.
    let (restored_root, mut restored) = empty_store();
    restored
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), after_second + 3)
        .unwrap();
    restored
        .unlock(&wallet_id, PASSPHRASE, after_second + 4)
        .unwrap();

    // AND THE ALLOWANCE IS BACK. This is the first line of the warning, executed:
    // the record of what has been spent has gone backwards, and the wallet will
    // now spend money it has already spent.
    let again = restored
        .create_payment_intent(
            &authorization,
            payment_request("second", after_second + 400),
            after_second + 5,
        )
        .await
        .unwrap();
    assert_eq!(
        again.status,
        OperationStatus::ApprovalRequested,
        "the payment the live wallet refused as over-budget is admitted by the \
         restored one, inside the same day"
    );
    assert_ne!(
        again.operation_id, second.operation_id,
        "and it is a NEW payment: the same idempotency key no longer resolves to \
         the payment that was already made, because the record of it is gone"
    );
    assert_eq!(
        node.submit_count.load(Ordering::SeqCst),
        2,
        "this test stops short of paying twice; what it proves is that nothing \
         is left to stop it"
    );
    drop(restored);
    drop(restored_root);
    drop(root);
}

/// EXECUTION 3: THE SECOND AND THIRD WARNINGS, BOTH MADE TO HAPPEN.
///
/// A REVOKED AGENT COMES BACK LIVE, and THE OLD PHONE REFUSES FOR EVER - the
/// second one against a real `MobileWitnessState`, the exact type the handset
/// persists, which accepted every anchor of the run that happened after the
/// backup and therefore holds a high-water mark the restored wallet is behind.
#[tokio::test]
async fn a_revoked_agent_comes_back_and_the_old_phone_refuses_after_a_restore() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(82_000).await;
    let (mut phone, registry) = real_phone(&mut manager, &wallet_id, &mobile, 82_010);
    let mut at = settle_with_real_phone(
        &mut manager,
        &wallet_id,
        &operation_id,
        &mobile,
        &mut phone,
        &registry,
        82_020,
    )
    .await;
    let agent_id = AgentId::parse(agent_ids(&mut manager, &wallet_id, at)[0].clone()).unwrap();

    // ---- THE BACKUP, taken here.
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();
    let backup_position = phone.last_anchor_sequence;

    // ---- AND THEN LIFE CARRIES ON. A second payment is really made, and the
    // REAL handset really advances past the backup's position.
    manager.unlock(&wallet_id, PASSPHRASE, at + 2).unwrap();
    let second = manager
        .create_payment_intent(&authorization, payment_request("second", at + 400), at + 3)
        .await
        .unwrap();
    let approval = manager
        .pending_approval(&wallet_id, &second.operation_id, at + 4)
        .unwrap();
    manager
        .approve_desktop_and_broadcast(&wallet_id, approval, at + 5)
        .await
        .unwrap();
    at = settle_with_real_phone(
        &mut manager,
        &wallet_id,
        &second.operation_id,
        &mobile,
        &mut phone,
        &registry,
        at + 6,
    )
    .await;
    assert!(
        phone.last_anchor_sequence > backup_position,
        "the handset is now genuinely ahead of the backup: {} against {}",
        phone.last_anchor_sequence,
        backup_position
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 2);

    // THE OWNER REVOKES THE AGENT, FOR REAL, AND IT IS REALLY DEAD.
    manager.unlock(&wallet_id, PASSPHRASE, at + 1).unwrap();
    manager.revoke_agent(&wallet_id, &agent_id, at + 2).unwrap();
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-revoke", at + 400),
                at + 3,
            )
            .await
            .unwrap_err(),
        AgentWalletError::AgentRevoked
    );

    // ---- THE RESTORE.
    let (restored_root, mut restored) = empty_store();
    let outcome = restored
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 4)
        .unwrap();
    assert_eq!(
        outcome.restored_active_agents, 1,
        "the outcome names how many agents came back live, because \"a revoked \
         agent can return\" is only useful if the owner knows to go and look"
    );
    assert!(outcome.witness_phone_must_be_replaced);
    restored.unlock(&wallet_id, PASSPHRASE, at + 5).unwrap();

    // WARNING TWO, EXECUTED: the agent the owner revoked is live again, with its
    // allowance reset, and it can spend.
    assert_eq!(
        restored
            .list_agents_admin(&wallet_id, at + 6)
            .unwrap()
            .into_iter()
            .find(|agent| agent.agent_id == agent_id)
            .unwrap()
            .status,
        AgentStatus::Active,
        "the agent the owner revoked is live again"
    );
    let revived = restored
        .create_payment_intent(
            &authorization,
            payment_request("revived-agent-pays", at + 500),
            at + 7,
        )
        .await
        .unwrap();
    assert_eq!(
        revived.status,
        OperationStatus::ApprovalRequested,
        "and it can spend again, with its allowance reset"
    );

    // WARNING THREE, EXECUTED: the restored wallet's witness pin still names this
    // handset, so it asks THAT handset for an anchor - at a chain position the
    // handset has already signed past. The handset answers `RollbackDetected`,
    // and nothing on the desktop can talk it out of that.
    let approval = restored
        .pending_approval(&wallet_id, &revived.operation_id, at + 8)
        .unwrap();
    restored
        .approve_desktop_and_broadcast(&wallet_id, approval, at + 9)
        .await
        .unwrap();
    let anchor = restored
        .pending_rollback_anchor(
            &wallet_id,
            &revived.operation_id,
            mobile.device_id(),
            at + 10,
        )
        .await
        .unwrap();
    assert!(
        anchor.anchor.anchor_sequence <= phone.last_anchor_sequence,
        "sequence {} against a handset at {}",
        anchor.anchor.anchor_sequence,
        phone.last_anchor_sequence
    );
    let restored_registry = {
        let (state_master, journal_key) = keys(&restored, &wallet_id);
        let state = restored
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        let signer = restored
            .session(&wallet_id)
            .unwrap()
            .desktop_companion_signer
            .clone();
        composite_registry(&state, &signer, at + 11).unwrap()
    };
    assert_eq!(
        phone
            .accept_anchor(&anchor, &restored_registry, at + 11)
            .unwrap_err(),
        CompanionError::RollbackDetected,
        "the owner's own phone refuses the restored wallet, which is why the \
         warning says the handset has to be replaced"
    );
    // And it refuses for ever: a year later, and for a freshly issued anchor.
    let much_later = at + 365 * 24 * 60 * 60;
    restored.unlock(&wallet_id, PASSPHRASE, much_later).unwrap();
    let later_anchor = restored
        .pending_rollback_anchor(
            &wallet_id,
            &revived.operation_id,
            mobile.device_id(),
            much_later + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        phone
            .accept_anchor(&later_anchor, &restored_registry, much_later + 2)
            .unwrap_err(),
        CompanionError::RollbackDetected,
        "time does not heal a rollback, and nothing here pretends it does"
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 2);
    drop(restored);
    drop(restored_root);
    drop(root);
}

/// EXECUTION 4: THE FOURTH WARNING. THE BACKUP FILE IS A SECOND LIVE WALLET.
///
/// Whoever holds the file and the passphrase holds a signing wallet, at the same
/// time as the owner. Two stores, one wallet id, one address, one key - both
/// unlocked, both able to start a payment.
#[tokio::test]
async fn the_backup_file_and_its_passphrase_are_a_second_live_wallet() {
    let (root, mut manager, wallet_id, _mobile, node, authorization, at) =
        wallet_with_one_settled_payment(83_000).await;
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    let (copy_root, mut copy) = empty_store();
    copy.restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 2)
        .unwrap();
    copy.unlock(&wallet_id, PASSPHRASE, at + 3).unwrap();

    // The original is still open and still working. Nothing about the restore
    // told it anything.
    let original_address = manager.list_wallets().unwrap()[0].address.clone();
    let copy_address = copy.list_wallets().unwrap()[0].address.clone();
    assert_eq!(
        original_address, copy_address,
        "one address, two wallets, at the same time"
    );

    // And the copy can start spending from that address on its own.
    assert_eq!(
        copy.create_payment_intent(
            &authorization,
            payment_request("from-the-copy", at + 500),
            at + 4,
        )
        .await
        .unwrap()
        .status,
        OperationStatus::ApprovalRequested
    );
    // As can the original, in ignorance of the copy.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("from-the-original", at + 500),
                at + 5,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    drop(copy);
    drop(copy_root);
    drop(root);
}

/// AN EXPORT REFUSES A WALLET WHOSE FOUR FILES DISAGREE RIGHT NOW.
///
/// A backup is only worth anything if it was mutually consistent at the moment
/// it was taken, so the consistency a restore will demand is proved first against
/// the live files. Both directions of disagreement are made to happen, using this
/// wallet's own real documents from an earlier moment of its own life - which is
/// exactly the shape an interrupted write, or a file copied back by hand, leaves
/// behind: a document that is internally perfect and out of step with the other
/// three.
#[tokio::test]
async fn a_backup_of_a_wallet_whose_four_files_disagree_is_refused() {
    // The wallet mid-life, with its journal and its state as they stand at this
    // moment.
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(90_000).await;
    let dir = manager
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    let journal_path = dir.join("journal.json");
    let state_path = dir.join("wallet_state.enc.json");
    let earlier_journal = std::fs::read(&journal_path).unwrap();
    let earlier_state = std::fs::read(&state_path).unwrap();

    // The wallet runs on. The payment settles, so both documents move past the
    // moment above, together.
    let at = settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, 90_020).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    let settled_journal = std::fs::read(&journal_path).unwrap();
    let settled_state = std::fs::read(&state_path).unwrap();
    assert_ne!(earlier_journal, settled_journal);
    assert_ne!(earlier_state, settled_state);

    // Consistent, so a backup is possible at all. This is the control: every
    // refusal below has to be the disagreement and not the fixture.
    manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    // CASE 1: the journal behind the state.
    let before = walk(manager.storage_root());
    std::fs::write(&journal_path, &earlier_journal).unwrap();
    assert_eq!(
        manager
            .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 2)
            .unwrap_err(),
        AgentWalletError::BackupInconsistent,
        "a wallet whose four files disagree is a wallet to recover, not one to \
         photograph: a backup taken here would restore a lie later"
    );
    assert_eq!(
        walk(manager.storage_root()),
        before,
        "and the refused export wrote nothing"
    );

    // CASE 2: the state behind the journal - the same defect from the other side.
    std::fs::write(&journal_path, &settled_journal).unwrap();
    std::fs::write(&state_path, &earlier_state).unwrap();
    assert_eq!(
        manager
            .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 3)
            .unwrap_err(),
        AgentWalletError::BackupInconsistent
    );

    // And with both documents back where the wallet itself left them, the export
    // works again, so what was refused was the disagreement.
    std::fs::write(&state_path, &settled_state).unwrap();
    manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 4)
        .unwrap();
    drop(manager);
    drop(root);
}

/// A RESTORE REFUSES AN ARTIFACT WHOSE DECLARED WALLET, OR WHOSE DECLARED
/// VERSION, IS NOT WHAT IS ACTUALLY INSIDE IT.
///
/// These are re-sealed under the real passphrase, because the metadata is the
/// AEAD's own additional authenticated data: without the passphrase none of these
/// files opens at all, and that case is already executed as the tampered-metadata
/// assertion. The adversary here is therefore the only one who exists - whoever
/// holds the file and its passphrase - and a restore still has to refuse.
#[tokio::test]
async fn a_restore_refuses_an_artifact_whose_declared_wallet_or_version_is_wrong() {
    let (root, manager, wallet_id, _mobile, _node, _auth, at) =
        wallet_with_one_settled_payment(91_000).await;
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();
    // The control: this artifact does restore, so every refusal below is the
    // edited field and not the fixture.
    let (control_root, mut control) = empty_store();
    control
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 2)
        .unwrap();
    drop(control);
    drop(control_root);

    // A DIFFERENT WALLET ID THAN THE ONE IN THE FOUR DOCUMENTS. The file claims
    // to be some other wallet; the vault, the registry entry and the state inside
    // it are this one. Restoring it would register a wallet under an id whose
    // own documents say something else.
    let other_id = AgentWalletId::new().to_string();
    assert_ne!(other_id, wallet_id.to_string());
    let mislabelled = reseal_backup_metadata_for_test(&backup, PASSPHRASE, |metadata| {
        metadata.wallet_id = other_id.clone();
    })
    .unwrap();
    let (restore_root, mut restored) = empty_store();
    assert_eq!(
        restored
            .restore_agent_wallet_backup(&mislabelled, PASSPHRASE, acknowledged(), at + 3)
            .unwrap_err(),
        AgentWalletError::BackupInconsistent
    );
    assert!(restored.list_wallets().unwrap().is_empty());
    for id in [other_id.as_str(), wallet_id.as_str()] {
        assert!(
            !restored
                .storage_root()
                .join("wallets")
                .join(id)
                .join("vault.json")
                .exists(),
            "a refused restore leaves no vault behind, under either id"
        );
    }

    // AN INCOMPATIBLE VERSION, IN EACH OF THE THREE FIELDS THAT DECLARE ONE. The
    // owner is told it is a version problem, by name: an owner handed the same
    // opaque error a wrong passphrase produces retypes a passphrase that was
    // never wrong.
    for (label, mutate) in [
        (
            "a newer backup format",
            (|metadata: &mut crate::service::AgentWalletBackupMetadata| {
                metadata.backup_version += 1
            }) as fn(&mut crate::service::AgentWalletBackupMetadata),
        ),
        ("a foreign document kind", |metadata| {
            metadata.kind = "hpay_something_else".to_owned();
        }),
        ("a newer state schema", |metadata| {
            metadata.state_schema_version += 1;
        }),
    ] {
        let foreign = reseal_backup_metadata_for_test(&backup, PASSPHRASE, mutate).unwrap();
        let error = restored
            .restore_agent_wallet_backup(&foreign, PASSPHRASE, acknowledged(), at + 4)
            .unwrap_err();
        assert_eq!(
            error,
            AgentWalletError::BackupUnsupportedVersion,
            "{label} must be refused as a version, not as a vault error"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("different version"),
            "and the owner is told what is actually wrong: {rendered}"
        );
        assert!(!rendered.contains(PASSPHRASE));
        // The preview refuses it too, so the owner learns this before they type
        // a passphrase at all.
        assert_eq!(
            restored.preview_agent_wallet_backup(&foreign).unwrap_err(),
            AgentWalletError::BackupUnsupportedVersion
        );
        assert!(restored.list_wallets().unwrap().is_empty());
    }
    drop(restored);
    drop(restore_root);
    drop(root);
}

/// A RESTORE REFUSES AN ARTIFACT SPLICED FROM TWO MOMENTS OF THE SAME WALLET,
/// AND REFUSES IT BEFORE IT HAS WRITTEN ANYTHING.
///
/// This is the case the cross-check exists for, and the only one where it is
/// load-bearing. Documents borrowed from a DIFFERENT wallet carry different keys,
/// so the AEAD and the journal MAC catch those on their own. These two documents
/// are this wallet's own: the journal authenticates perfectly under this wallet's
/// own journal key, the state decrypts perfectly under this wallet's own state
/// master, the bundle commitment is recomputed and the envelope re-sealed - and
/// they are from two different moments of its life, which nothing but the
/// sequence-and-commitment comparison can see.
///
/// If that comparison ran any later than it does, this restore would have written
/// the vault, the journal and the state before noticing, and left exactly the
/// half-restored wallet the whole design is there to prevent.
#[tokio::test]
async fn a_restore_refuses_a_backup_spliced_from_two_moments_of_the_same_wallet() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, _authorization) =
        desktop_approved_operation(93_000).await;
    let dir = manager
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    let earlier_journal = std::fs::read_to_string(dir.join("journal.json")).unwrap();

    let at = settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, 93_020).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    let spliced = replace_backup_document_for_test(
        &backup,
        PASSPHRASE,
        BackupDocument::Journal,
        earlier_journal,
    )
    .unwrap();
    let (restore_root, mut restored) = empty_store();
    let error = restored
        .restore_agent_wallet_backup(&spliced, PASSPHRASE, acknowledged(), at + 2)
        .unwrap_err();
    // NOTHING WAS WRITTEN - not the registry entry, and not one of the three
    // private documents either. Asserted BEFORE the error identity, because this
    // is the load-bearing claim: a restore that notices this one document later
    // than it does still returns an error, and leaves a wallet directory with
    // three of the four documents in it.
    assert!(restored.list_wallets().unwrap().is_empty());
    let restored_dir = restored
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    for name in ["vault.json", "journal.json", "wallet_state.enc.json"] {
        assert!(
            !restored_dir.join(name).exists(),
            "a refused restore must not have written {name}, and it wrote it: \
             the refusal came too late and this is a half-restored wallet"
        );
    }
    assert_eq!(
        error,
        AgentWalletError::BackupInconsistent,
        "the journal and the state inside this file describe two different \
         moments, and no key, hash or MAC in it is wrong"
    );
    // And the untouched artifact restores, so what was refused was the splice.
    restored
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 3)
        .unwrap();
    drop(restored);
    drop(restore_root);
    drop(manager);
    drop(root);
}

/// AN OWNER WHO NEVER MAKES A BACKUP SEES NO BEHAVIOUR CHANGE.
///
/// The backup is reachable only by asking for it. Nothing on the ordinary path
/// calls into it, it writes no file and it journals no record, so the four
/// documents of a wallet that is merely used are byte-for-byte what they were -
/// and asking for a backup, previewing one, or having a restore refused does not
/// change that either.
#[tokio::test]
async fn an_owner_who_never_makes_a_backup_sees_no_behaviour_change() {
    let (root, mut manager, wallet_id, mobile, operation_id, node, authorization) =
        desktop_approved_operation(92_000).await;
    let dir = manager
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    let four_files = |dir: &std::path::Path, root: &std::path::Path| {
        (
            std::fs::read(root.join("registry.json")).unwrap(),
            std::fs::read(dir.join("vault.json")).unwrap(),
            std::fs::read(dir.join("journal.json")).unwrap(),
            std::fs::read(dir.join("wallet_state.enc.json")).unwrap(),
        )
    };
    let store_root = manager.storage_root().to_path_buf();

    // Mid-life, before the feature is touched at all.
    let before_files = four_files(&dir, &store_root);
    let before_tree = walk(&store_root);

    // Everything the feature offers, exercised: the warnings, a backup, a
    // preview of it, and a restore that is refused because this wallet is live.
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), 92_010)
        .unwrap();
    manager.preview_agent_wallet_backup(&backup).unwrap();
    assert_eq!(
        manager
            .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), 92_011)
            .unwrap_err(),
        AgentWalletError::AgentWalletAlreadyExists
    );
    assert_eq!(
        four_files(&dir, &store_root),
        before_files,
        "none of the four documents moved by a single byte"
    );
    assert_eq!(
        walk(&store_root),
        before_tree,
        "and no file was created or removed anywhere in the store"
    );

    // The ordinary path then continues exactly as it would have: the payment
    // settles, with one submission, and the journal grows only by the records
    // the settlement itself writes.
    let at = settle_with_witness(&mut manager, &wallet_id, &operation_id, &mobile, 92_020).await;
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    drop(state);

    // And nothing the backup did is in the record. The journal of a wallet that
    // was backed up carries no trace of it: a backup is a read, and the file the
    // owner walks away with is the only thing that was produced.
    let journal = std::fs::read_to_string(dir.join("journal.json")).unwrap();
    for forbidden in ["ackup", "estore", "Acknowledg"] {
        assert!(
            !journal.contains(forbidden),
            "the journal must carry no backup record, and it contains {forbidden:?}"
        );
    }

    // The wallet still takes work afterwards.
    assert_eq!(
        manager
            .create_payment_intent(&authorization, payment_request("after", at + 400), at + 5)
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );
    drop(manager);
    drop(root);
}

/// A RESTORE REFUSES A BACKUP WHOSE FOUR FILES DISAGREE, RATHER THAN
/// HALF-RESTORING.
///
/// Each document in turn is replaced with a valid document from a DIFFERENT
/// wallet, the bundle commitment is recomputed and the envelope is re-sealed, so
/// what is under test is the four-file consistency check itself and not the AEAD
/// or the hash. Nothing may be written in any of these cases.
#[tokio::test]
async fn a_restore_refuses_a_backup_whose_four_files_disagree() {
    let (root_a, manager_a, wallet_a, _mobile_a, _node_a, _auth_a, at_a) =
        wallet_with_one_settled_payment(84_000).await;
    let backup_a = manager_a
        .create_agent_wallet_backup(&wallet_a, PASSPHRASE, acknowledged(), at_a + 1)
        .unwrap();
    let (root_b, manager_b, wallet_b, _mobile_b, _node_b, _auth_b, at_b) =
        wallet_with_one_settled_payment(85_000).await;
    let backup_b = manager_b
        .create_agent_wallet_backup(&wallet_b, PASSPHRASE, acknowledged(), at_b + 1)
        .unwrap();
    let foreign = backup_documents_for_test(&backup_b, PASSPHRASE).unwrap();

    for (document, replacement) in [
        (BackupDocument::RegistryEntry, foreign[0].clone()),
        (BackupDocument::Vault, foreign[1].clone()),
        (BackupDocument::Journal, foreign[2].clone()),
        (BackupDocument::StateEnvelope, foreign[3].clone()),
    ] {
        let spliced =
            replace_backup_document_for_test(&backup_a, PASSPHRASE, document, replacement).unwrap();
        let (restore_root, mut restored) = empty_store();
        let error = restored
            .restore_agent_wallet_backup(&spliced, PASSPHRASE, acknowledged(), at_a + 2)
            .unwrap_err();
        assert!(
            matches!(
                error,
                AgentWalletError::BackupInconsistent
                    | AgentWalletError::Vault
                    | AgentWalletError::JournalAuthenticationFailed
                    | AgentWalletError::RecoveryRequired
            ),
            "a spliced {document:?} must be refused, got {error:?}"
        );
        // NOTHING WAS WRITTEN. No registry entry, and no wallet directory with
        // a vault or a state in it.
        assert!(
            restored.list_wallets().unwrap().is_empty(),
            "a refused restore never registers a wallet ({document:?})"
        );
        for wallet in [&wallet_a, &wallet_b] {
            let dir = restored
                .storage_root()
                .join("wallets")
                .join(wallet.as_str());
            assert!(
                !dir.join("wallet_state.enc.json").exists(),
                "a refused restore never leaves a state document ({document:?})"
            );
        }
        drop(restored);
        drop(restore_root);
    }

    // And a byte flipped anywhere in the sealed envelope, or in its
    // authenticated metadata, fails before any of that.
    let tampered_metadata = backup_a.replace(
        "\"backed_up_at_unix\":",
        "\"backed_up_at_unix\": 1, \"ignored\":",
    );
    let (restore_root, mut restored) = empty_store();
    assert!(
        restored
            .restore_agent_wallet_backup(&tampered_metadata, PASSPHRASE, acknowledged(), at_a + 3)
            .is_err()
    );
    assert!(restored.list_wallets().unwrap().is_empty());
    drop(restored);
    drop(restore_root);
    drop(root_a);
    drop(root_b);
}

/// THE WARNING IS PART OF THE FEATURE. NEITHER ENTRY POINT RUNS WITHOUT ALL FOUR
/// FACTS ACKNOWLEDGED, ONE AT A TIME.
#[tokio::test]
async fn neither_backup_nor_restore_runs_without_all_four_facts_acknowledged() {
    let (root, manager, wallet_id, _mobile, _node, _auth, at) =
        wallet_with_one_settled_payment(86_000).await;

    // Every single-fact omission is refused, for the backup.
    for mutate in [
        (|ack: &mut AgentWalletBackupAcknowledgement| ack.restore_rewinds_spending = false)
            as fn(&mut AgentWalletBackupAcknowledgement),
        |ack| ack.revoked_agents_return = false,
        |ack| ack.old_phone_must_be_replaced = false,
        |ack| ack.the_file_is_a_working_wallet = false,
    ] {
        let mut ack = acknowledged();
        mutate(&mut ack);
        assert!(!ack.is_complete());
        assert_eq!(
            manager
                .create_agent_wallet_backup(&wallet_id, PASSPHRASE, ack, at + 1)
                .unwrap_err(),
            AgentWalletError::BackupWarningNotAcknowledged
        );
    }
    assert_eq!(
        manager
            .create_agent_wallet_backup(
                &wallet_id,
                PASSPHRASE,
                AgentWalletBackupAcknowledgement::default(),
                at + 1,
            )
            .unwrap_err(),
        AgentWalletError::BackupWarningNotAcknowledged,
        "and the default is refused, so a caller that forgets the struct \
         entirely gets nothing"
    );

    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 2)
        .unwrap();

    // And every single-fact omission is refused again, for the restore.
    for mutate in [
        (|ack: &mut AgentWalletBackupAcknowledgement| ack.restore_rewinds_spending = false)
            as fn(&mut AgentWalletBackupAcknowledgement),
        |ack| ack.revoked_agents_return = false,
        |ack| ack.old_phone_must_be_replaced = false,
        |ack| ack.the_file_is_a_working_wallet = false,
    ] {
        let mut ack = acknowledged();
        mutate(&mut ack);
        let (restore_root, mut restored) = empty_store();
        assert_eq!(
            restored
                .restore_agent_wallet_backup(&backup, PASSPHRASE, ack, at + 3)
                .unwrap_err(),
            AgentWalletError::BackupWarningNotAcknowledged
        );
        assert!(restored.list_wallets().unwrap().is_empty());
        drop(restored);
        drop(restore_root);
    }

    // THE SAME THING AGAIN, DERIVED FROM THE WARNING RATHER THAN LISTED HERE.
    //
    // The loops above name the four fields, which means a FIFTH consequence
    // added to the warning and not gated would pass them. This loop walks
    // `FACT_KEYS` instead - the list the warning itself publishes - so a fact
    // that exists on screen and not in the gate fails here, and a fact that
    // exists in the gate and not on screen fails the round trip below. That is
    // the difference between pinning the text and pinning the enforcement.
    for key in AgentWalletBackupWarning::FACT_KEYS {
        for warning in [AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING] {
            let sentence = warning
                .fact(key)
                .unwrap_or_else(|| panic!("the warning has no sentence for {key}"));
            assert!(
                sentence.len() > 40,
                "the sentence for {key} must actually say something"
            );
        }
        let withheld = acknowledged()
            .with_fact(key, false)
            .unwrap_or_else(|| panic!("{key} is not a field of the acknowledgement"));
        assert_eq!(withheld.fact(key), Some(false));
        assert_eq!(withheld.missing_facts(), vec![key]);
        assert!(!withheld.is_complete());

        // WITHHELD, SO NEITHER ENTRY POINT MAY RUN AND NEITHER MAY WRITE.
        assert_eq!(
            manager
                .create_agent_wallet_backup(&wallet_id, PASSPHRASE, withheld, at + 1)
                .unwrap_err(),
            AgentWalletError::BackupWarningNotAcknowledged,
            "a backup ran with {key} unread"
        );
        let (bypass_root, mut bypassed) = empty_store();
        let before = walk(bypass_root.path());
        assert_eq!(
            bypassed
                .restore_agent_wallet_backup(&backup, PASSPHRASE, withheld, at + 3)
                .unwrap_err(),
            AgentWalletError::BackupWarningNotAcknowledged,
            "a restore ran with {key} unread"
        );
        assert!(bypassed.list_wallets().unwrap().is_empty());
        assert_eq!(
            walk(bypass_root.path()),
            before,
            "a refused restore wrote to disk with {key} unread"
        );
        drop(bypassed);
        drop(bypass_root);

        // And ticking it back is the only thing that lets either run.
        assert!(
            withheld
                .with_fact(key, true)
                .unwrap()
                .missing_facts()
                .is_empty()
        );
    }
    assert!(
        AgentWalletBackupAcknowledgement::default()
            .missing_facts()
            .len()
            == AgentWalletBackupWarning::FACT_KEYS.len(),
        "every fact must be outstanding on a fresh acknowledgement"
    );
    assert_eq!(
        AgentWalletBackupWarning::FACT_KEYS.len(),
        4,
        "the owner chose four consequences; a fifth needs a gate of its own"
    );

    // THE WARNING PUBLISHES EXACTLY THOSE FOUR FACTS AND A HEADLINE, AND NOTHING
    // ELSE. This is what stops a fifth consequence from being added to the struct
    // and shipped to the screen with no acknowledgement field behind it: the
    // serialized shape is what the desktop receives, and it is checked against
    // `FACT_KEYS` rather than against a hand-written list.
    let published = serde_json::to_value(AGENT_WALLET_RESTORE_WARNING).unwrap();
    let mut keys: Vec<String> = published
        .as_object()
        .unwrap()
        .keys()
        .filter(|key| key.as_str() != "headline")
        .cloned()
        .collect();
    keys.sort();
    let mut expected: Vec<String> = AgentWalletBackupWarning::FACT_KEYS
        .into_iter()
        .map(str::to_owned)
        .collect();
    expected.sort();
    assert_eq!(
        keys, expected,
        "the warning sent to the screen has a fact that nothing gates"
    );

    // The two warnings are different texts for the two moments, and both name
    // all four facts.
    for warning in [AGENT_WALLET_BACKUP_WARNING, AGENT_WALLET_RESTORE_WARNING] {
        for line in [
            warning.headline,
            warning.restore_rewinds_spending,
            warning.revoked_agents_return,
            warning.old_phone_must_be_replaced,
            warning.the_file_is_a_working_wallet,
        ] {
            assert!(
                line.len() > 40,
                "a warning line must actually say something"
            );
        }
        assert!(warning.restore_rewinds_spending.contains("already paid"));
        assert!(warning.revoked_agents_return.contains("revoke"));
        assert!(warning.old_phone_must_be_replaced.contains("refuse"));
        assert!(
            warning
                .the_file_is_a_working_wallet
                .contains("working wallet")
        );
    }
    drop(root);
}

/// NOTHING SECRET IS EVER IN THE BACKUP FILE, IN AN ERROR, OR ON DISK IN CLEAR.
#[tokio::test]
async fn the_backup_never_contains_key_material_a_passphrase_or_a_state_plaintext() {
    let (root, manager, wallet_id, _mobile, _node, _auth, at) =
        wallet_with_one_settled_payment(87_000).await;

    // The exact secrets this wallet holds, read out of the vault the only way
    // anybody can: with the passphrase.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state_master_hex = hex::encode(state_master);
    let journal_key_hex = hex::encode(journal_key);
    let paths = manager
        .storage_root()
        .join("wallets")
        .join(wallet_id.as_str());
    let vault_json = std::fs::read_to_string(paths.join("vault.json")).unwrap();

    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    assert!(
        !backup.contains(PASSPHRASE),
        "the passphrase is never written to the backup"
    );
    assert!(
        !backup.contains(&state_master_hex),
        "the state master key is never written to the backup"
    );
    assert!(
        !backup.contains(&journal_key_hex),
        "and neither is the key the journal is authenticated with - a derived key \
         is still key material"
    );
    // The vault travels as its own ciphertext, so its ciphertext appears and its
    // plaintext cannot: the backup is the vault FILE, not the vault CONTENTS.
    let vault_ciphertext: String = serde_json::from_str::<serde_json::Value>(&vault_json).unwrap()
        ["ciphertext_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !backup.contains(&vault_ciphertext),
        "and not even the vault's own ciphertext is in the clear in the backup: \
         the whole bundle is encrypted again"
    );
    // The state plaintext is not there either. The recipient address is in the
    // state and in nothing else visible here.
    assert!(
        !backup.contains(RECIPIENT),
        "no part of the state plaintext reaches the backup document"
    );
    // What IS there is only authenticated, non-secret metadata.
    let parsed: serde_json::Value = serde_json::from_str(&backup).unwrap();
    assert_eq!(parsed["metadata"]["wallet_id"], wallet_id.to_string());
    assert_eq!(parsed["metadata"]["network_mode"], "testnet");

    // A WRONG PASSPHRASE SAYS NOTHING AND WRITES NOTHING.
    let (restore_root, mut restored) = empty_store();
    let wrong = "this-is-not-the-passphrase-at-all";
    let error = restored
        .restore_agent_wallet_backup(&backup, wrong, acknowledged(), at + 2)
        .unwrap_err();
    assert_eq!(error, AgentWalletError::Vault);
    let rendered = error.to_string();
    assert!(!rendered.contains(wrong));
    assert!(!rendered.contains(PASSPHRASE));
    assert!(!rendered.contains(&state_master_hex));
    assert!(!rendered.contains(&journal_key_hex));
    assert!(
        restored.list_wallets().unwrap().is_empty(),
        "and a wrong passphrase restores nothing"
    );
    assert!(
        !restored
            .storage_root()
            .join("wallets")
            .join(wallet_id.as_str())
            .join("vault.json")
            .exists()
    );
    drop(restored);
    drop(restore_root);
    drop(root);
}

/// A RESTORE NEVER OVERWRITES A LIVE WALLET, AND A BACKUP OF A WALLET THAT IS
/// NOT HERE IS NOT A THING.
#[tokio::test]
async fn a_restore_never_overwrites_a_live_wallet() {
    let (root, mut manager, wallet_id, _mobile, _node, authorization, at) =
        wallet_with_one_settled_payment(88_000).await;
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();

    // Into the store it came from, where the wallet is alive.
    assert_eq!(
        manager
            .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 2)
            .unwrap_err(),
        AgentWalletError::AgentWalletAlreadyExists
    );
    let preview = manager.preview_agent_wallet_backup(&backup).unwrap();
    assert!(
        preview.already_present,
        "and the preview says so before the owner presses anything"
    );

    // The live wallet is untouched: same session, same state, still paying.
    assert_eq!(
        manager
            .create_payment_intent(
                &authorization,
                payment_request("after-refused-restore", at + 500),
                at + 3,
            )
            .await
            .unwrap()
            .status,
        OperationStatus::ApprovalRequested
    );

    // And a wallet id that is not in this store cannot be backed up.
    let (other_root, other) = empty_store();
    assert_eq!(
        other
            .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 4)
            .unwrap_err(),
        AgentWalletError::AgentWalletNotFound
    );
    drop(other);
    drop(other_root);
    drop(root);
}

/// THE PERSONAL WALLET IS NOT TOUCHED, AND NEITHER IS ANY PATH OUTSIDE THE AGENT
/// ROOT.
///
/// `create_agent_wallet_backup` writes no file at all - it returns the document
/// and lets the caller decide where a working copy of the owner's wallet goes -
/// and a restore writes only inside the store root it was given.
#[tokio::test]
async fn backup_and_restore_write_only_inside_the_agent_store_root() {
    let (root, manager, wallet_id, _mobile, _node, _auth, at) =
        wallet_with_one_settled_payment(89_000).await;
    let before: Vec<_> = walk(manager.storage_root());
    let backup = manager
        .create_agent_wallet_backup(&wallet_id, PASSPHRASE, acknowledged(), at + 1)
        .unwrap();
    assert_eq!(
        walk(manager.storage_root()),
        before,
        "creating a backup writes nothing, anywhere"
    );

    let (restore_root, mut restored) = empty_store();
    let restored_before = walk(restored.storage_root());
    restored
        .restore_agent_wallet_backup(&backup, PASSPHRASE, acknowledged(), at + 2)
        .unwrap();
    let restored_after = walk(restored.storage_root());
    assert!(
        restored_after.len() > restored_before.len(),
        "the restore really did write files"
    );
    for path in &restored_after {
        assert!(
            path.starts_with(restored.storage_root()),
            "every file a restore writes is inside the store root it was given, \
             and this one is not: {}",
            path.display()
        );
    }
    // And the store the backup came from is untouched by the restore: two Agent
    // Wallet stores are two separate domains, and so are they and the Personal
    // Wallet, whose paths this crate cannot even name.
    assert_eq!(
        walk(manager.storage_root()),
        before,
        "restoring into one store writes nothing into another"
    );
    drop(restored);
    drop(restore_root);
    drop(root);
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
