//! The wallet's own view of a chain, for opening and funding an HVM registry
//! channel.
//!
//! # What was missing, and what it cost
//!
//! Until this module existed, nothing on the path from an owner's press to
//! `hacash_wallet_core::hvm_registry_open::authorize_registry_funding` read a
//! chain at all. Every field of the channel description was a claim, and the
//! wallet believed all of them: `binding.validate()` checks that the *claimed*
//! bytecode digest equals the reviewed constant, and has no way to check the
//! code actually deployed at `contract_address`; `deployment_tx_hash` and
//! `deployment_height` were carried and never used; `chain_id` and
//! `network_instance_id` were never compared with the node the wallet is
//! pinned to.
//!
//! A reviewer drove the consequence to a real theft in real blocks. A provider
//! deployed its own contract at the address the funding builder demands,
//! published the reviewed bytecode hash beside it, and countersigned the full
//! refund with complete sincerity. Every signature was genuine. The refund
//! referred to something that was not the registry, the deposit landed in the
//! provider's own contract, the owner's `challenge` call errored because there
//! was no such function, and the provider withdrew the money its own signature
//! promised to return.
//!
//! Every check that would have caught it did exist - inside
//! `verify_and_bind_hvm_registry`, which runs after the spend. This module is
//! how they are read *before* it.
//!
//! # What this module may not do
//!
//! It holds no key, makes no decisions and keeps no state. It cannot choose a
//! contract, an amount, a fee or a destination: those are derived from the
//! countersigned bundle, and every judgement about what it reports belongs to
//! `hacash_wallet_core::hvm_registry_open`. A chain view that could influence
//! any of them would be a fullnode with a vote on where the money goes.

use hacash_wallet_core::WalletError;
use hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitSightingV1;
use hacash_wallet_core::hvm_registry_open::HvmRegistryOpenChainV1;
use l2_fast_pay_hub::hvm_registry::{HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use l2_fast_pay_hub::node::NodeClient;

/// The fullnode, as opening and funding a channel need to see it.
pub struct FullnodeRegistryOpenChain {
    client: NodeClient,
    network_mode: String,
}

impl FullnodeRegistryOpenChain {
    pub fn new(node_url: &str, network_mode: &str) -> Result<Self, String> {
        let client = NodeClient::new(node_url).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            network_mode: network_mode.to_owned(),
        })
    }
}

fn node_error(error: l2_fast_pay_hub::error::HubError) -> WalletError {
    WalletError::Node(error.to_string())
}

impl HvmRegistryOpenChainV1 for FullnodeRegistryOpenChain {
    /// Who this node says it is, from its own capabilities document.
    ///
    /// The caller does not take this on trust either: `AgentWalletManager`
    /// compares the block-1 fingerprint and network mode here against the ones
    /// the wallet recorded when it was created, so a node pointed at some
    /// other chain cannot supply evidence about some other chain.
    async fn network_binding(&self) -> Result<L1ChannelNetworkBinding, WalletError> {
        let capabilities = self.client.capabilities().await.map_err(node_error)?;
        L1ChannelNetworkBinding::from_node_identity(
            &capabilities.network_kind,
            self.network_mode == "mainnet",
            capabilities.chain_id,
            &capabilities.block_1_hash,
            &capabilities.node_profile_id,
            capabilities.network_instance_id.as_deref(),
            capabilities.transaction_format_version,
        )
        .map_err(|error| WalletError::Node(error.to_string()))
    }

    /// This channel's live contract storage, read raw.
    ///
    /// Raw on purpose. The node's own reader applies whichever validator it
    /// was asked for, and the pre-funding judgement belongs in exactly one
    /// place - `authorize_registry_funding` - rather than being split between
    /// a fetcher and a gate. What arrives here is what the chain says; what it
    /// means is decided there.
    async fn registry_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
    ) -> Result<HvmRegistryLiveSnapshotV2, WalletError> {
        self.client
            .hvm_registry_raw_snapshot(binding)
            .await
            .map_err(node_error)
    }

    /// Hand exact signed funding bytes to the node.
    ///
    /// A duplicate is success: the bytes are idempotent by hash and the caller
    /// made them durable before calling. That is checked rather than assumed -
    /// the refusal is only swallowed when the node can then be seen holding
    /// the hash.
    async fn submit_funding_transaction(
        &self,
        binding: &HvmRegistryBindingV2,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), WalletError> {
        let submitted = self
            .client
            .submit_hvm_registry_transaction_bound(
                signed_transaction_hex,
                transaction_hash,
                binding,
            )
            .await;
        let error = match submitted {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        match self.funding_sighting(transaction_hash).await {
            Ok(HvmRegistryExitSightingV1::Pending | HvmRegistryExitSightingV1::Mined { .. }) => {
                Ok(())
            }
            _ => Err(node_error(error)),
        }
    }

    /// What this node knows about the funding transaction hash.
    ///
    /// A hash the node has never heard of answers `Unknown`, and `Unknown` is
    /// the answer that makes the caller hand the stored bytes over again. So a
    /// node that is merely unreachable must never reach that arm: it returns
    /// an error instead.
    async fn funding_sighting(
        &self,
        transaction_hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, WalletError> {
        let observation = match self
            .client
            .query_hvm_registry_funding_transaction(transaction_hash)
            .await
        {
            Ok(Some(observation)) => observation,
            Ok(None) => return Ok(HvmRegistryExitSightingV1::Unknown),
            Err(error) => return Err(node_error(error)),
        };
        if observation.pending {
            return Ok(HvmRegistryExitSightingV1::Pending);
        }
        match (observation.block_height, observation.block_hash) {
            (Some(block_height), Some(block_hash)) if block_height != 0 => {
                Ok(HvmRegistryExitSightingV1::Mined {
                    block_height,
                    block_hash,
                })
            }
            // A confirmation that cannot name its block is not a confirmation.
            // Reporting it as `Unknown` would re-submit bytes that are already
            // mined; reporting it as `Mined` would write an unanchored block
            // into the durable record. Neither is safe.
            _ => Err(WalletError::Node(format!(
                "the fullnode reports transaction {transaction_hash} as confirmed without naming \
                 its block"
            ))),
        }
    }
}
