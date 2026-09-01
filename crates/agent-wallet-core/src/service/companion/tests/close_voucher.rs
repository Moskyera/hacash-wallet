//! The owner's exit, proved end to end: held, gating, restorable, and
//! broadcastable with no Hub in the picture at all.

use std::sync::atomic::Ordering;

use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::channel::{
    CHANNEL_STATUS_OPENING, ChannelInfo, ChannelPartyBalance, derive_channel_id,
};
use hpay_companion_protocol::AgentFastPayNetworkBinding;

use super::pilot_node;
use super::*;
use crate::service::AgentWalletBackupAcknowledgement;
use crate::service::l2::{
    AgentChannelCloseVoucherPhase, AgentL2Binding, test_held_close_voucher,
    test_local_pilot_network_binding,
};

struct VoucherFixture {
    _root: tempfile::TempDir,
    node: pilot_node::MockPilotNode,
    manager: AgentWalletManager,
    wallet_id: AgentWalletId,
    hub: WalletAccount,
    binding: AgentL2Binding,
    now: u64,
}

/// A wallet with a confirmed chain-7 channel and, separately, the countersigned
/// delta-zero close for it. The two are installed separately on purpose so a
/// test can look at the wallet in the state it is in during the real hostage
/// window: deposit committed, no exit yet.
async fn voucher_fixture(with_voucher: bool) -> VoucherFixture {
    let now = 1_800_000_000_u64;
    let node = pilot_node::spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = pilot_node::create_manager_for_node(&node.url, now);
    let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let hub = WalletAccount::create_random().unwrap();
    let channel_id = derive_channel_id(&state.address, &hub.address(), 1);
    let channel = ChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 5,
        close_height: 0,
        reuse_version: 1,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: state.address.clone(),
            hacash: "1".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    node.set_channel(channel_id, serde_json::to_value(&channel).unwrap())
        .await;
    let verified =
        crate::node_binding::verified_agent_node(&node.url, "testnet", fixtures::TESTNET_ANCHOR)
            .await
            .unwrap();
    let snapshot = verified.snapshot();
    let binding = AgentL2Binding::from_verified_channel(
        wallet_id.clone(),
        "testnet",
        AgentFastPayNetworkBinding {
            network_mode: "testnet".to_owned(),
            chain_id: snapshot.chain_id,
            genesis_identifier: snapshot.block_one_fingerprint.clone(),
            node_profile_id: snapshot.node_profile_commitment.clone(),
            network_instance_id: snapshot.network_instance_id.clone(),
            transaction_format_version: snapshot.transaction_format_version,
        },
        &state.address,
        "https://hub.example",
        &hub.address(),
        &channel,
        snapshot.current_height,
        now,
    )
    .unwrap();

    if with_voucher {
        let permit = manager
            .emergency_controller(&wallet_id)
            .unwrap()
            .issue_safety_permit(false)
            .unwrap();
        let owner_address = state.address.clone();
        let voucher = test_held_close_voucher(
            &manager.session(&wallet_id).unwrap().signer,
            &permit,
            &wallet_id,
            &owner_address,
            &binding,
            hub.inner(),
            test_local_pilot_network_binding(fixtures::TESTNET_ANCHOR),
            &node.url,
            now,
        );
        state.l2_channel_close_voucher = Some(voucher);
    }
    state.l2_binding = Some(binding.clone());
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::L2BindingVerified,
            None,
            None,
            now,
        )
        .unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, now + 1)
        .unwrap();
    VoucherFixture {
        _root: root,
        node,
        manager,
        wallet_id,
        hub,
        binding,
        now,
    }
}

#[tokio::test]
async fn the_wallet_reports_the_exit_it_holds_and_what_it_pays() {
    let mut fixture = voucher_fixture(true).await;
    let view = fixture
        .manager
        .l2_channel_close_voucher(&fixture.wallet_id, fixture.now + 2)
        .unwrap()
        .expect("a confirmed channel holds its one close voucher");
    assert_eq!(view.phase, AgentChannelCloseVoucherPhase::Held);
    // What it pays the owner is the whole deposit recorded at open, because a
    // delta-zero close refunds the balances stored when the channel opened.
    assert_eq!(view.refund_units, fixture.binding.deposit_units());
    assert_eq!(view.deposit_units, fixture.binding.deposit_units());
    assert_eq!(view.channel_id, fixture.binding.channel_id());
    assert_eq!(view.hub_address, fixture.hub.address());
    assert!(view.signed_transaction_hex.is_some());
    assert!(view.transaction_hash.is_some());
    assert!(view.broadcast.is_none());
}

#[tokio::test]
async fn a_bound_channel_without_an_exit_reports_none() {
    // The real hostage window, held still: the deposit is on chain, the
    // channel is bound and payable in every other respect, and no
    // countersigned close exists yet. The wallet says so rather than implying
    // an exit it does not have. `fast_pay_is_refused_until_the_exit_is_held`
    // in `service::l2::tests` proves this state also refuses payments.
    let mut without = voucher_fixture(false).await;
    assert!(
        without
            .manager
            .l2_channel_close_voucher(&without.wallet_id, without.now + 2)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_tampered_voucher_is_not_an_exit() {
    let fixture = voucher_fixture(true).await;
    let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
    let mut state = fixture
        .manager
        .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
        .unwrap();
    // Flip one byte of the Hub's countersignature. Nothing about the stored
    // record's shape changes; only the bytes stop proving what they claim.
    let voucher = state.l2_channel_close_voucher.as_mut().unwrap();
    let hex = voucher.view.signed_transaction_hex.clone().unwrap();
    let mut bytes = hex.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
    voucher.view.signed_transaction_hex = Some(String::from_utf8(bytes).unwrap());
    let tampered = state.l2_channel_close_voucher.clone().unwrap();
    let address = state.address.clone();
    assert_eq!(
        tampered.validate(&fixture.wallet_id, &address).unwrap_err(),
        AgentWalletError::RecoveryRequired,
        "a voucher is only as good as the bytes, never as good as the stored phase"
    );
    assert_eq!(
        tampered.verified_bytes().unwrap_err(),
        AgentWalletError::RecoveryRequired
    );
}

#[tokio::test]
async fn the_owner_broadcasts_the_exit_without_the_hub() {
    let mut fixture = voucher_fixture(true).await;
    let held = fixture
        .manager
        .l2_channel_close_voucher(&fixture.wallet_id, fixture.now + 2)
        .unwrap()
        .unwrap();
    let expected_hash = held.transaction_hash.clone().unwrap();
    let expected_bytes = held.signed_transaction_hex.clone().unwrap();

    // No Hub is running. `https://hub.example` does not resolve to anything in
    // this test, which is the point: the escape hatch must not need it.
    let view = fixture
        .manager
        .broadcast_l2_channel_close_voucher(&fixture.wallet_id, fixture.now + 2)
        .await
        .expect("the owner's own node accepts the exit with no Hub involved");
    assert_eq!(view.phase, AgentChannelCloseVoucherPhase::Broadcast);
    let broadcast = view.broadcast.expect("a broadcast record is written");
    assert_eq!(broadcast.transaction_hash, expected_hash);
    assert_eq!(broadcast.node_url, fixture.node.url);

    assert_eq!(fixture.node.bound_submit_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.node.bound_submitted_bodies.read().await.as_slice(),
        &[expected_bytes],
        "the exact countersigned bytes reached the chain, unmodified"
    );
    // The Hub-owned cooperative-close route was not touched.
    assert_eq!(fixture.node.submit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_exit_survives_the_encrypted_backup_and_a_restore() {
    let mut fixture = voucher_fixture(true).await;
    let before = fixture
        .manager
        .l2_channel_close_voucher(&fixture.wallet_id, fixture.now + 2)
        .unwrap()
        .unwrap();

    let backup = fixture
        .manager
        .create_agent_wallet_backup(
            &fixture.wallet_id,
            fixtures::PASSPHRASE,
            AgentWalletBackupAcknowledgement::complete(),
            fixture.now + 3,
        )
        .unwrap();
    // A completely separate, empty store, which is where a restore goes.
    let fresh = tempfile::tempdir().unwrap();
    let mut restored = AgentWalletManager::open(fresh.path()).unwrap();
    restored
        .restore_agent_wallet_backup(
            &backup,
            fixtures::PASSPHRASE,
            AgentWalletBackupAcknowledgement::complete(),
            fixture.now + 4,
        )
        .unwrap();
    restored
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, fixture.now + 5)
        .unwrap();
    let after = restored
        .l2_channel_close_voucher(&fixture.wallet_id, fixture.now + 6)
        .unwrap()
        .expect("a voucher that does not survive a restore is not an exit");
    assert_eq!(before, after);
    assert_eq!(after.phase, AgentChannelCloseVoucherPhase::Held);
    // Still the same transaction, re-derived from the bytes rather than read
    // off the record.
    assert_eq!(
        hacash_wallet_core::l1_channel_close_safety::transaction_hash_of_hex(
            after.signed_transaction_hex.as_deref().unwrap()
        )
        .unwrap(),
        after.transaction_hash.unwrap()
    );
}
