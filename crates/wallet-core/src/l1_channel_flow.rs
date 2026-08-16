//! Shared, fail-closed network proof for Personal and Agent L1 channel flows.
//!
//! This module deliberately contains no wallet session or signing authority.
//! Callers must still revalidate this exact binding immediately before any
//! irreversible signature or broadcast boundary.

use crate::error::{WalletError, WalletResult};
use crate::node::NodeClient;
pub fn verify_partial_channel_signature(
    signed_transaction_hex: &str,
    user_address: &str,
    action_kind: u16,
    chain_id: u32,
) -> WalletResult<()> {
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let (transaction, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if consumed != raw.len()
        || transaction.ty() != 2
        || transaction.actions().len() != 2
        || transaction.actions()[0].kind() != 0x0411
        || transaction.actions()[1].kind() != action_kind
        || transaction.signs().len() != 1
    {
        return Err(WalletError::Policy(format!(
            "partial channel transaction has an invalid signed Type 2 topology for Action {action_kind}"
        )));
    }
    let guard = protocol::action::ChainAllow::downcast(&transaction.actions()[0])
        .ok_or_else(|| WalletError::Policy("partial channel ChainAllow codec mismatch".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != chain_id {
        return Err(WalletError::Policy(
            "partial channel transaction is bound to a different chain".into(),
        ));
    }
    let user = field::Address::from_readable(user_address)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let signer = field::Address::from(sys::Account::get_address_by_public_key(
        *transaction.signs()[0].publickey,
    ));
    let verified = protocol::transaction::verify_target_signature(&user, transaction.as_read())
        .map_err(|error| WalletError::Policy(error.to_string()))?;
    if signer != user || !verified {
        return Err(WalletError::Policy(
            "partial channel transaction user signature was not verified".into(),
        ));
    }
    Ok(())
}

pub async fn exact_l1_channel_network_binding(
    node: &NodeClient,
    expected_mode: &str,
) -> WalletResult<l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding> {
    let capabilities = node.capabilities().await?;
    let expected_mainnet = match expected_mode {
        "mainnet" => true,
        "testnet" => false,
        _ => {
            return Err(WalletError::Policy(
                "unsupported wallet network mode for Fast Pay channel".into(),
            ));
        }
    };
    if capabilities.chain.mainnet != expected_mainnet
        || !capabilities.supports_transaction(2)
        || !capabilities.supports_action(2)
        || !capabilities.supports_action(3)
        || !capabilities.supports_action(14)
        || !capabilities.supports_action(0x0411)
        || !capabilities.api.transaction_submit_bound
        || !capabilities.network.transaction_ready
    {
        return Err(WalletError::Policy(
            "node cannot prove the exact Fast Pay channel transaction contract".into(),
        ));
    }
    if expected_mainnet
        && (capabilities.network.kind != crate::node_capabilities::HPAY_MAINNET_NETWORK_KIND
            || capabilities.network.node_profile_id
                != crate::node_capabilities::HPAY_MAINNET_PROFILE_ID
            || capabilities.network.block_1_hash.as_deref()
                != Some(crate::node_discovery::MAINNET_BLOCK_ONE_HASH))
    {
        return Err(WalletError::Policy(
            "node is not the pinned Hacash mainnet identity".into(),
        ));
    }
    let block_1_hash = capabilities
        .network
        .block_1_hash
        .clone()
        .ok_or_else(|| WalletError::Policy("node did not prove block 1".into()))?;
    l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding::from_node_identity(
        &capabilities.network.kind,
        capabilities.chain.mainnet,
        capabilities.chain.id,
        &block_1_hash,
        &capabilities.network.node_profile_id,
        capabilities.network.instance_id.as_deref(),
        capabilities.network.transaction_format_version,
    )
    .map_err(|error| WalletError::Policy(error.to_string()))
}
