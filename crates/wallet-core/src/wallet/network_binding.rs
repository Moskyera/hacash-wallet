//! Fail-closed binding between wallet network settings and the selected node.

use std::time::{Duration, Instant};

use crate::error::{WalletError, WalletResult};
use crate::node_capabilities::{CapabilitySource, NodeChain};
use crate::node_discovery::probe_node;
use crate::settings::is_official_node_url;
use crate::tx_binding::CanonicalTransaction;

use super::WalletService;

const NETWORK_BINDING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(super) struct CachedNetworkBinding {
    node_url: String,
    network_mode: String,
    verified_at: Instant,
    chain_id: Option<u32>,
    enabled_transactions: Vec<u8>,
}

impl CachedNetworkBinding {
    fn is_fresh_for(&self, node_url: &str, network_mode: &str) -> bool {
        self.node_url == node_url
            && self.network_mode == network_mode
            && self.verified_at.elapsed() <= NETWORK_BINDING_TTL
    }

    fn require_transaction(&self, tx_type: u8) -> WalletResult<Option<u32>> {
        if self.enabled_transactions.binary_search(&tx_type).is_err() {
            return Err(WalletError::Policy(format!(
                "node_network_transaction_unsupported: selected node does not enable Type {tx_type}"
            )));
        }
        Ok(self.chain_id)
    }
}

fn validate_reported_network(network_mode: &str, chain: &NodeChain) -> WalletResult<()> {
    let matched = match network_mode {
        "mainnet" => chain.mainnet && chain.id == 0,
        "testnet" => !chain.mainnet && chain.id != 0,
        _ => false,
    };
    if !matched {
        return Err(WalletError::Policy(format!(
            "node_network_mismatch: wallet is configured for {network_mode}, node reports chain id {} ({})",
            chain.id,
            if chain.mainnet { "mainnet" } else { "testnet" }
        )));
    }
    Ok(())
}

impl WalletService {
    pub(crate) fn invalidate_network_binding(&mut self) {
        self.network_binding = None;
    }

    async fn refresh_network_binding(&self) -> WalletResult<CachedNetworkBinding> {
        let node_url = self.node.base_url().to_owned();
        let network_mode = self.network_mode.clone();
        if !matches!(network_mode.as_str(), "mainnet" | "testnet") {
            return Err(WalletError::Policy(
                "node_network_mode_invalid: wallet network mode is not mainnet or testnet".into(),
            ));
        }

        let capabilities = self.node.capabilities().await?;
        let (chain_id, enabled_transactions) = match capabilities.source {
            CapabilitySource::Reported => {
                validate_reported_network(&network_mode, &capabilities.chain)?;
                (
                    Some(capabilities.chain.id),
                    capabilities.transactions.enabled.clone(),
                )
            }
            CapabilitySource::LegacyType2 => (None, vec![2]),
        };

        // Custom nodes, and legacy nodes without a real capability chain id,
        // must also match the canonical block-one anchor used by discovery.
        if !is_official_node_url(&node_url) || capabilities.source == CapabilitySource::LegacyType2
        {
            let status = probe_node(&node_url, &network_mode).await;
            if !status.online {
                return Err(WalletError::Node(format!(
                    "node network binding failed: {}",
                    status.error.unwrap_or_else(|| "node is offline".into())
                )));
            }
            if !status.network_match {
                return Err(WalletError::Policy(format!(
                    "node_network_mismatch: {}",
                    status
                        .error
                        .unwrap_or_else(|| "node does not match the configured network".into())
                )));
            }
        }

        Ok(CachedNetworkBinding {
            node_url,
            network_mode,
            verified_at: Instant::now(),
            chain_id,
            enabled_transactions,
        })
    }

    async fn ensure_node_network_for_type(&mut self, tx_type: u8) -> WalletResult<Option<u32>> {
        if !matches!(tx_type, 2..=4) {
            return Err(WalletError::Policy(format!(
                "node_network_transaction_unsupported: wallet will not sign Type {tx_type}"
            )));
        }
        let node_url = self.node.base_url();
        if let Some(binding) = self.network_binding.as_ref()
            && binding.is_fresh_for(node_url, &self.network_mode)
        {
            return binding.require_transaction(tx_type);
        }
        let binding = self.refresh_network_binding().await?;
        let chain_id = binding.require_transaction(tx_type)?;
        self.network_binding = Some(binding);
        Ok(chain_id)
    }

    pub(crate) async fn ensure_transaction_network_binding(
        &mut self,
        body_hex: &str,
    ) -> WalletResult<CanonicalTransaction> {
        let canonical = crate::tx_binding::decode_transaction(body_hex)?;
        let chain_id = self.ensure_node_network_for_type(canonical.tx_type).await?;
        if canonical.tx_type == 3 {
            let chain_id = chain_id.ok_or_else(|| {
                WalletError::Policy(
                    "node_network_type3_unbound: Type 3 requires a reported node chain id".into(),
                )
            })?;
            crate::tx_binding::inspect_transaction(body_hex, Some(chain_id))?;
        }
        Ok(canonical)
    }

    pub(crate) async fn sign_tx_for_network(&mut self, body_hex: &str) -> WalletResult<String> {
        self.ensure_transaction_network_binding(body_hex).await?;
        self.sign_tx_hex(body_hex)
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, routing::get};

    use super::*;
    use crate::node_capabilities::{CapabilitySource, NodeCapabilities};
    use crate::test_support::IsolatedWalletData;

    fn reported_capabilities(mainnet: bool) -> NodeCapabilities {
        let mut capabilities = NodeCapabilities::legacy_type2("mock");
        capabilities.source = CapabilitySource::Reported;
        capabilities.chain.id = if mainnet { 0 } else { 1 };
        capabilities.chain.mainnet = mainnet;
        capabilities
    }

    async fn spawn_capability_node(
        capabilities: NodeCapabilities,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/query/capabilities",
            get(move || {
                let capabilities = capabilities.clone();
                async move { Json(capabilities) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    #[tokio::test]
    async fn custom_node_network_mismatch_fails_closed_in_both_directions() {
        let _wallet_data = IsolatedWalletData::new();

        let (testnet_node, testnet_server) =
            spawn_capability_node(reported_capabilities(false)).await;
        let mut mainnet_wallet = WalletService::new(Some(testnet_node), None).unwrap();
        mainnet_wallet.network_mode = "mainnet".into();
        let error = mainnet_wallet
            .ensure_node_network_for_type(2)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("node_network_mismatch"));
        testnet_server.abort();

        let (mainnet_node, mainnet_server) =
            spawn_capability_node(reported_capabilities(true)).await;
        let mut testnet_wallet = WalletService::new(Some(mainnet_node), None).unwrap();
        testnet_wallet.network_mode = "testnet".into();
        let error = testnet_wallet
            .ensure_node_network_for_type(2)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("node_network_mismatch"));
        mainnet_server.abort();
    }

    #[test]
    fn reported_chain_contract_is_exact_for_mainnet_and_testnet() {
        let mainnet = reported_capabilities(true);
        let testnet = reported_capabilities(false);
        assert!(validate_reported_network("mainnet", &mainnet.chain).is_ok());
        assert!(validate_reported_network("testnet", &testnet.chain).is_ok());
        assert!(validate_reported_network("mainnet", &testnet.chain).is_err());
        assert!(validate_reported_network("testnet", &mainnet.chain).is_err());
    }
}
