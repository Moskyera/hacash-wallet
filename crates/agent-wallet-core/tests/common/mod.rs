//! An honest fullnode, for tests of the registry channel open.
//!
//! # Why every one of these tests now needs one
//!
//! The wallet no longer believes a binding. Before it will left-sign the
//! serial-1 refund, and again before it will produce funding permission, it
//! reads its own pinned node and refuses unless the contract at the named
//! address really is the reviewed registry, really on this wallet's chain, and
//! really carrying the exact unfunded channel the binding describes. A
//! reviewer took a deposit through the gap where that check was missing, on
//! chain, using an entirely honest Hub.
//!
//! So a test that wants an open to succeed has to supply a node that
//! corroborates it, and - this is the whole point of the type below - a node
//! that corroborates **one** channel and tells the truth about everything
//! else. [`HonestNode`] is constructed for a single binding. Ask it about any
//! other contract address, channel id, reuse version, deposit or objection
//! window and it answers the way a real node answers about an address that is
//! not carrying that channel: with nothing the gate can use.
//!
//! It holds no key and decides nothing. It cannot make the gate pass; it can
//! only tell the truth, and the truth is what the gate is judging.

#![allow(dead_code)]

use std::cell::RefCell;

use hacash_wallet_core::WalletError;
use hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitSightingV1;
use hacash_wallet_core::hvm_registry_open::HvmRegistryOpenChainV1;
use l2_fast_pay_hub::hvm_pilot::HvmLocalPilotNetwork;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use l2_fast_pay_hub::node::HvmStorageEntry;

/// The block-1 fingerprint every wallet in these tests is pinned to.
///
/// It is the local pilot chain's, because that is the chain [`HonestNode`]
/// speaks for, and the open path refuses a node whose block 1 is not the one
/// the wallet recorded when it was created.
pub const NODE_BLOCK_ONE: &str = l2_fast_pay_hub::hvm_pilot::HPAY_LOCAL_PILOT_BLOCK_ONE_HASH;

pub fn pilot_network() -> HvmLocalPilotNetwork {
    HvmLocalPilotNetwork::canonical()
}

fn entry<T>(value: T) -> HvmStorageEntry<T> {
    HvmStorageEntry {
        value,
        live_blocks: 300_000,
        recover_blocks: 0,
        active: true,
        recoverable: false,
    }
}

/// The exact unfunded channel this binding describes, as a node would report
/// it after `init` has confirmed and before any coin has been paid in.
pub fn unfunded_snapshot(binding: &HvmRegistryBindingV2) -> HvmRegistryLiveSnapshotV2 {
    HvmRegistryLiveSnapshotV2 {
        ret: 0,
        schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        chain_id: binding.chain_id,
        network_instance_id: binding.network_instance_id.clone(),
        observed_height: binding.deployment_height + 4,
        evaluation_height: binding.deployment_height + 5,
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
        minimum_live_blocks: 300_000,
        minimum_recover_blocks: 0,
        registry: HvmRegistryGlobalStorageV2 {
            g_network: entry(binding.network_instance_id.clone()),
            g_hub: entry(binding.right_hub_address.clone()),
            g_locked: entry(0),
            g_left_claimable: entry(0),
            g_hub_claimable: entry(0),
            g_open_count: entry(0),
        },
        channel: HvmRegistryChannelStorageV2 {
            status: entry(1),
            channel_id: entry(binding.channel_id.clone()),
            reuse: entry(binding.reuse_version),
            deposit: entry(binding.left_deposit_zhu),
            paid: entry(0),
            total: entry(binding.left_deposit_zhu),
            serial: entry(0),
            left_balance: entry(binding.left_deposit_zhu),
            hub_balance: entry(0),
            challenge_blocks: entry(binding.challenge_blocks),
            deadline: entry(0),
            left_claimed: entry(false),
        },
    }
}

/// A node that corroborates exactly one channel and tells the truth about
/// every other question it is asked.
pub struct HonestNode {
    real: HvmRegistryBindingV2,
    /// Set to make the node itself unreachable, which is a different failure
    /// from a node that answers and disagrees.
    pub offline: RefCell<bool>,
    pub submitted: RefCell<Vec<String>>,
    /// Hashes this node will report as mined.
    pub mined: RefCell<Vec<String>>,
    /// When true, a submitted transaction is mined immediately.
    pub auto_mine: RefCell<bool>,
}

impl HonestNode {
    pub fn for_channel(real: &HvmRegistryBindingV2) -> Self {
        Self {
            real: real.clone(),
            offline: RefCell::new(false),
            submitted: RefCell::new(Vec::new()),
            mined: RefCell::new(Vec::new()),
            auto_mine: RefCell::new(true),
        }
    }
}

impl HvmRegistryOpenChainV1 for HonestNode {
    async fn network_binding(&self) -> Result<L1ChannelNetworkBinding, WalletError> {
        if *self.offline.borrow() {
            return Err(WalletError::Node("node unreachable".into()));
        }
        let network = pilot_network();
        L1ChannelNetworkBinding::from_node_identity(
            &network.network_kind,
            false,
            network.chain_id,
            &network.block_1_hash,
            &network.node_profile_id,
            Some(&network.network_instance_id),
            2,
        )
        .map_err(|error| WalletError::Node(error.to_string()))
    }

    async fn registry_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
    ) -> Result<HvmRegistryLiveSnapshotV2, WalletError> {
        if *self.offline.borrow() {
            return Err(WalletError::Node("node unreachable".into()));
        }
        // Everything a real reader would have to find on chain in order to
        // answer at all: the contract, the deployment it was asked about, and
        // the channel record itself. A binding that differs in any of these is
        // asking about something that is not there.
        if binding.contract_address != self.real.contract_address
            || binding.deployment_tx_hash != self.real.deployment_tx_hash
            || binding.deployment_height != self.real.deployment_height
            || binding.bytecode_sha3 != self.real.bytecode_sha3
            || binding.left_address != self.real.left_address
            || binding.right_hub_address != self.real.right_hub_address
            || binding.channel_id != self.real.channel_id
            || binding.reuse_version != self.real.reuse_version
            || binding.left_deposit_zhu != self.real.left_deposit_zhu
            || binding.challenge_blocks != self.real.challenge_blocks
        {
            return Err(WalletError::Node(
                "this node holds no such registry channel".into(),
            ));
        }
        Ok(unfunded_snapshot(&self.real))
    }

    async fn submit_funding_transaction(
        &self,
        _binding: &HvmRegistryBindingV2,
        _signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), WalletError> {
        if *self.offline.borrow() {
            return Err(WalletError::Node("node unreachable".into()));
        }
        self.submitted
            .borrow_mut()
            .push(transaction_hash.to_owned());
        if *self.auto_mine.borrow() {
            self.mined.borrow_mut().push(transaction_hash.to_owned());
        }
        Ok(())
    }

    async fn funding_sighting(
        &self,
        transaction_hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, WalletError> {
        if *self.offline.borrow() {
            return Err(WalletError::Node("node unreachable".into()));
        }
        if self
            .mined
            .borrow()
            .iter()
            .any(|hash| hash == transaction_hash)
        {
            return Ok(HvmRegistryExitSightingV1::Mined {
                block_height: 4_242,
                block_hash: "ab".repeat(32),
            });
        }
        if self
            .submitted
            .borrow()
            .iter()
            .any(|hash| hash == transaction_hash)
        {
            return Ok(HvmRegistryExitSightingV1::Pending);
        }
        Ok(HvmRegistryExitSightingV1::Unknown)
    }
}
