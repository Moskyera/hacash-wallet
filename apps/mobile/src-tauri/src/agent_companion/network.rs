use hacash_wallet_core::node_capabilities::{
    HPAY_MAINNET_NETWORK_KIND, HPAY_MAINNET_PROFILE_ID, network_instance_id,
};
use hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH;
use hpay_companion_protocol::AgentFastPayNetworkBinding;

const FAST_PAY_TRANSACTION_FORMAT_VERSION: u64 = 2;

/// The phone approves only an exact network identity already authenticated by
/// the desktop. Testnet remains available in pilot builds. Mainnet additionally
/// requires the explicit bounded-mainnet build and the canonical Hacash anchor.
pub(super) fn agent_fast_pay_network_allowed(binding: &AgentFastPayNetworkBinding) -> bool {
    if binding.transaction_format_version != FAST_PAY_TRANSACTION_FORMAT_VERSION {
        return false;
    }
    match binding.network_mode.as_str() {
        "testnet" => binding.chain_id > 0,
        "mainnet" if cfg!(feature = "agent-wallet-bounded-mainnet-pilot") => {
            let expected_instance = network_instance_id(
                HPAY_MAINNET_NETWORK_KIND,
                0,
                true,
                MAINNET_BLOCK_ONE_HASH,
                HPAY_MAINNET_PROFILE_ID,
                FAST_PAY_TRANSACTION_FORMAT_VERSION,
            );
            binding.chain_id == 0
                && binding.genesis_identifier == MAINNET_BLOCK_ONE_HASH
                && binding.network_instance_id == expected_instance
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(network_mode: &str, chain_id: u32) -> AgentFastPayNetworkBinding {
        AgentFastPayNetworkBinding {
            network_mode: network_mode.to_owned(),
            chain_id,
            genesis_identifier: if network_mode == "mainnet" {
                MAINNET_BLOCK_ONE_HASH.to_owned()
            } else {
                "11".repeat(32)
            },
            node_profile_id: "22".repeat(32),
            network_instance_id: if network_mode == "mainnet" {
                network_instance_id(
                    HPAY_MAINNET_NETWORK_KIND,
                    0,
                    true,
                    MAINNET_BLOCK_ONE_HASH,
                    HPAY_MAINNET_PROFILE_ID,
                    FAST_PAY_TRANSACTION_FORMAT_VERSION,
                )
            } else {
                "testnet:mobile".to_owned()
            },
            transaction_format_version: FAST_PAY_TRANSACTION_FORMAT_VERSION,
        }
    }

    #[test]
    fn testnet_and_only_canonical_feature_gated_mainnet_are_allowed() {
        assert!(agent_fast_pay_network_allowed(&binding("testnet", 1)));
        let mainnet = binding("mainnet", 0);
        assert_eq!(
            agent_fast_pay_network_allowed(&mainnet),
            cfg!(feature = "agent-wallet-bounded-mainnet-pilot")
        );
        let mut wrong_anchor = mainnet.clone();
        wrong_anchor.genesis_identifier = "33".repeat(32);
        assert!(!agent_fast_pay_network_allowed(&wrong_anchor));
        let mut wrong_instance = mainnet;
        wrong_instance.network_instance_id = "44".repeat(32);
        assert!(!agent_fast_pay_network_allowed(&wrong_instance));
    }
}
