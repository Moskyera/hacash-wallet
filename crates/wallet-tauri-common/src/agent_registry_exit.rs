//! The wallet's own view of a chain, for walking out of an HVM registry
//! channel when the provider has stopped answering.
//!
//! # What was missing
//!
//! `hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit` has
//! existed and been proven on a real chain for some time, and until this
//! module its only caller in the entire tree was a test. The driver asks for
//! four things and deliberately not one of them is a Hub call:
//!
//! 1. this channel's live contract storage,
//! 2. the node's own tip and how old it is,
//! 3. what the node knows about one transaction hash,
//! 4. somewhere to hand exact signed bytes.
//!
//! All four are answered here by `l2_fast_pay_hub::node::NodeClient` against
//! the fullnode this wallet is already pinned to. Nothing in this file talks
//! to a provider, and every method would answer identically with the
//! provider's process deleted, which is the entire point: the exit exists for
//! the moment the provider is gone.
//!
//! # What this module may not do
//!
//! It holds no key, makes no decisions and keeps no state. It cannot choose a
//! step, a fee, a timestamp or a payee. Those come from the driver, from the
//! wallet's own durable record, and from constants in `agent-wallet-core`; a
//! chain view that could influence any of them would be a fullnode with a vote
//! on where the money goes.

use hacash_wallet_core::WalletError;
use hacash_wallet_core::hvm_registry_exit_driver::{
    HvmRegistryExitChainV1, HvmRegistryExitSightingV1,
};
use l2_fast_pay_hub::hvm_registry::{HvmRegistryBindingV2, HvmRegistryLiveSnapshotV2};
use l2_fast_pay_hub::node::NodeClient;

/// The fullnode, as the exit driver needs to see it.
pub struct FullnodeRegistryExitChain {
    client: NodeClient,
    binding: HvmRegistryBindingV2,
    minimum_live_blocks: u64,
    minimum_recover_blocks: u64,
}

impl FullnodeRegistryExitChain {
    pub fn new(
        node_url: &str,
        binding: HvmRegistryBindingV2,
        minimum_live_blocks: u64,
        minimum_recover_blocks: u64,
    ) -> Result<Self, String> {
        let client = NodeClient::new(node_url).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            binding,
            minimum_live_blocks,
            minimum_recover_blocks,
        })
    }
}

fn node_error(error: l2_fast_pay_hub::error::HubError) -> WalletError {
    WalletError::Node(error.to_string())
}

impl HvmRegistryExitChainV1 for FullnodeRegistryExitChain {
    /// This channel's live contract storage, read from the wallet's own
    /// pinned fullnode.
    ///
    /// # Why the lease floor is read twice
    ///
    /// `hvm_registry_runtime_snapshot` checks the binding's identity — the
    /// contract, the deployment, the bytecode hash, the channel, the balances,
    /// that every storage key is active — and *also* refuses a snapshot whose
    /// leases have fallen below the floor recorded when the channel was
    /// adopted.
    ///
    /// Applying that floor here would break the exit at exactly the moment it
    /// matters. A short lease is not a reason to stop reading the chain; it is
    /// the reason the driver's first planned step is a lease renewal. Refusing
    /// the read would leave the driver unable to see the problem it exists to
    /// fix, and an expiring lease is the only path in this system that
    /// destroys a deposit outright.
    ///
    /// So the adoption floor is applied first, and only if that read is
    /// refused is the same snapshot read again with the floor set aside. Every
    /// other check is identical on both reads: nothing is skipped, and the
    /// lease decision moves to
    /// `hacash_wallet_core::hvm_registry_exit::exit_lease_floor_blocks`, which
    /// covers the whole exit sequence rather than one step of it. If the
    /// second read is refused too, the first refusal is the one reported,
    /// because it is the stricter statement of what is wrong.
    async fn registry_snapshot(&self) -> Result<HvmRegistryLiveSnapshotV2, WalletError> {
        let strict = self
            .client
            .hvm_registry_runtime_snapshot(
                &self.binding,
                self.minimum_live_blocks,
                self.minimum_recover_blocks,
            )
            .await;
        let strict_error = match strict {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => error,
        };
        self.client
            .hvm_registry_runtime_snapshot(&self.binding, 0, 0)
            .await
            .map_err(|_| node_error(strict_error))
    }

    async fn chain_tip(&self) -> Result<(u64, u64), WalletError> {
        let capabilities = self.client.capabilities().await.map_err(node_error)?;
        Ok((capabilities.height, capabilities.tip_age_seconds))
    }

    /// What this node knows about one exit transaction.
    ///
    /// The exit puts two shapes on chain and they prove themselves
    /// differently: `challenge`, `respond`, `finalize` and the two lease
    /// renewals are Action 44 contract calls, while the payout is an Action 14
    /// `HacFromToTrs` that carries no Action 44 at all. Asking for the wrong
    /// proof is not a missing transaction, it is a node answering a question
    /// nobody asked, so the second shape is tried only when the first one
    /// found a transaction that could not be read as a contract call.
    ///
    /// A hash the node has never heard of answers `Unknown` from either
    /// query, and `Unknown` is the answer that makes the driver hand the
    /// stored bytes over again. That is why a node that is merely unreachable
    /// must never reach that arm: it returns an error instead.
    async fn transaction_sighting(
        &self,
        hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, WalletError> {
        let observation = match self.client.query_hvm_registry_call_transaction(hash).await {
            Ok(Some(observation)) => observation,
            Ok(None) => return Ok(HvmRegistryExitSightingV1::Unknown),
            Err(call_error) => match self.client.query_hvm_registry_claim_transaction(hash).await {
                Ok(Some(observation)) => observation,
                Ok(None) => return Ok(HvmRegistryExitSightingV1::Unknown),
                Err(_) => return Err(node_error(call_error)),
            },
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
            // A confirmation that cannot name the block it lives in is not a
            // confirmation. Reporting it as `Unknown` would re-submit bytes
            // that are already mined; reporting it as `Mined` would write an
            // unanchored block into the durable record. Neither is safe, so
            // this pass fails and the next one asks again.
            _ => Err(WalletError::Node(format!(
                "the fullnode reports transaction {hash} as confirmed without naming its block"
            ))),
        }
    }

    /// Hand exact signed bytes to the node, bound to this exact chain.
    ///
    /// A duplicate is success. The bytes are idempotent by hash and the caller
    /// has already made them durable, so a node that refuses because it
    /// already holds them has done the thing that was asked. That is checked
    /// rather than assumed: the refusal is only swallowed when the node can
    /// then be seen holding the hash.
    async fn submit_exit_transaction(
        &self,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), WalletError> {
        let submitted = self
            .client
            .submit_hvm_registry_transaction_bound(
                signed_transaction_hex,
                transaction_hash,
                &self.binding,
            )
            .await;
        let error = match submitted {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        match self.transaction_sighting(transaction_hash).await {
            Ok(HvmRegistryExitSightingV1::Pending | HvmRegistryExitSightingV1::Mined { .. }) => {
                Ok(())
            }
            _ => Err(node_error(error)),
        }
    }
}
