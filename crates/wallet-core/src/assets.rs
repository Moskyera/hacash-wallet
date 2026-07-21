use std::time::{Duration, Instant};

use crate::error::{WalletError, WalletResult};
use crate::node::{DiamondInfo, NativeAssetBalance, NodeClient};
use crate::settings::{DEFAULT_NODE_URL, is_official_node_url};

const BALANCE_CACHE_TTL: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, serde::Serialize)]
pub struct AssetSummary {
    pub hac_mei: f64,
    pub hacd_count: usize,
    pub hacd_names: Vec<String>,
    /// Bridged BTC held by the L1 Hacash wallet, in satoshi.
    pub btc_wallet_satoshi: u64,
    /// Bridged BTC locked in the active Fast Pay channel, in satoshi.
    pub btc_channel_satoshi: u64,
    /// Istanbul native-asset primitive balances. Read-only in wallet v1.0.0.
    #[serde(default)]
    pub native_assets: Vec<NativeAssetBalance>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AssetSnapshot {
    pub hac_mei: f64,
    pub hacd_names: Vec<String>,
    pub btc_wallet_satoshi: u64,
    pub native_assets: Vec<NativeAssetBalance>,
}

/// Asset-domain state kept behind the existing `WalletService` facade.
///
/// It borrows the active node per call, so settings changes cannot leave a
/// duplicated node client stale.
#[derive(Default)]
pub(crate) struct AssetService {
    balance_cache: Option<(String, f64, Instant)>,
}

/// Cloneable, read-only HACD metadata client.
///
/// Wallet shells snapshot this reader while holding the session mutex and then
/// perform HTTP after releasing it, so gallery requests cannot block signing,
/// locking, or status checks.
#[derive(Debug, Clone)]
pub struct DiamondMetadataReader {
    configured_node: NodeClient,
    fallback_url: Option<String>,
}

impl DiamondMetadataReader {
    pub(crate) fn new(configured_node: NodeClient) -> Self {
        let fallback_url = should_try_mainnet_metadata(configured_node.base_url())
            .then(|| DEFAULT_NODE_URL.to_owned());
        Self {
            configured_node,
            fallback_url,
        }
    }

    #[cfg(test)]
    fn with_fallback_url(configured_node: NodeClient, fallback_url: Option<String>) -> Self {
        Self {
            configured_node,
            fallback_url,
        }
    }

    pub async fn query(&self, name: &str) -> WalletResult<DiamondInfo> {
        let normalized = normalize_diamond_name(name)?;
        match self
            .configured_node
            .query_diamond_by_name(&normalized)
            .await
        {
            Ok(info) => Ok(info),
            Err(configured_error) => {
                let Some(fallback_url) = &self.fallback_url else {
                    return Err(configured_error);
                };
                let fallback = NodeClient::new(fallback_url.clone())?;
                match fallback.query_diamond_by_name(&normalized).await {
                    Ok(mut info) => {
                        info.metadata_source = "mainnet".into();
                        Ok(info)
                    }
                    Err(_) => Err(configured_error),
                }
            }
        }
    }
}

impl AssetService {
    pub(crate) fn clear_cache(&mut self) {
        self.balance_cache = None;
    }

    pub(crate) async fn balance_mei(
        &mut self,
        node: &NodeClient,
        address: &str,
    ) -> WalletResult<f64> {
        if let Some((cached_address, balance, fetched_at)) = &self.balance_cache
            && cached_address == address
            && fetched_at.elapsed() < BALANCE_CACHE_TTL
        {
            return Ok(*balance);
        }
        let balance = node.balance_mei(address).await?;
        self.remember_balance(address, balance);
        Ok(balance)
    }

    pub(crate) async fn snapshot(
        &mut self,
        node: &NodeClient,
        address: &str,
    ) -> WalletResult<AssetSnapshot> {
        let balance_entry = node.query_balance_entry(address, true).await?;
        let hac_mei = balance_entry.hacash_mei()?;
        self.remember_balance(address, hac_mei);
        let hacd_names = balance_entry
            .diamonds
            .as_deref()
            .map(crate::hacd_send::parse_owned_diamonds)
            .unwrap_or_default();
        Ok(AssetSnapshot {
            hac_mei,
            hacd_names,
            btc_wallet_satoshi: balance_entry.btc_satoshi(),
            native_assets: balance_entry.native_assets()?,
        })
    }

    pub(crate) async fn list_owned_diamonds(
        &self,
        node: &NodeClient,
        address: &str,
    ) -> WalletResult<Vec<String>> {
        crate::hacd_send::list_owned_diamonds(node, address).await
    }

    fn remember_balance(&mut self, address: &str, balance: f64) {
        self.balance_cache = Some((address.to_string(), balance, Instant::now()));
    }
}

fn normalize_diamond_name(name: &str) -> WalletResult<String> {
    let normalized = name.trim().to_uppercase();
    if !crate::hacd_send::is_valid_diamond_name(&normalized) {
        return Err(WalletError::Other(
            "HACD name must use 4 to 6 letters from WTYUIAHXVMEKBSZN".into(),
        ));
    }
    Ok(normalized)
}

fn should_try_mainnet_metadata(configured_url: &str) -> bool {
    !is_official_node_url(configured_url)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::Query;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::task::JoinHandle;

    use super::*;

    async fn spawn_balance_node() -> (NodeClient, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let route_calls = Arc::clone(&calls);
        let app = Router::new().route(
            "/query/balance",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let calls = Arc::clone(&route_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let address = params
                        .get("address")
                        .cloned()
                        .unwrap_or_else(|| "1Example".into());
                    Json(json!({
                        "ret": 0,
                        "list": [{
                            "address": address,
                            "hacash": "12.5",
                            "diamond": 2,
                            "satoshi": 42,
                            "diamonds": "ZAKXMIWTYUIA",
                            "assets": [{"serial": 7, "amount": 9000}]
                        }]
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock node");
        let address = listener.local_addr().expect("mock node address");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock node");
        });
        (
            NodeClient::new(format!("http://{address}")).expect("mock node client"),
            calls,
            handle,
        )
    }

    async fn spawn_diamond_node(
        response: serde_json::Value,
        delay: Duration,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let route_active = Arc::clone(&active);
        let route_max = Arc::clone(&max_active);
        let app = Router::new().route(
            "/query/diamond",
            get(move || {
                let response = response.clone();
                let active = Arc::clone(&route_active);
                let max_active = Arc::clone(&route_max);
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Json(response)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind diamond node");
        let address = listener.local_addr().expect("diamond node address");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve diamond node");
        });
        (format!("http://{address}"), max_active, handle)
    }

    #[test]
    fn official_aliases_do_not_trigger_a_second_mainnet_request() {
        for url in [
            DEFAULT_NODE_URL,
            "https://nodeapi.hacash.org",
            "nodeapi.hacash.org",
            "nodeapi.org",
        ] {
            assert!(!should_try_mainnet_metadata(url), "{url}");
        }
        assert!(should_try_mainnet_metadata("https://wallet-node.example"));
    }

    #[test]
    fn clear_cache_removes_the_entire_address_bound_entry() {
        let mut service = AssetService::default();
        service.remember_balance("1Example", 12.5);
        assert!(service.balance_cache.is_some());
        service.clear_cache();
        assert!(service.balance_cache.is_none());
    }

    #[tokio::test]
    async fn invalid_diamond_is_rejected_before_network_access() {
        let reader = DiamondMetadataReader::new(
            NodeClient::new(DEFAULT_NODE_URL).expect("default node client"),
        );
        let error = reader
            .query("BAD<script>")
            .await
            .expect_err("invalid HACD name");
        assert!(error.to_string().contains("HACD name"));
    }

    #[tokio::test]
    async fn metadata_reader_uses_the_configured_fallback_without_hiding_source() {
        let (configured_url, _, configured_server) =
            spawn_diamond_node(json!({ "ret": 1, "err": "not found" }), Duration::ZERO).await;
        let (fallback_url, _, fallback_server) = spawn_diamond_node(
            json!({ "ret": 0, "name": "WTYU", "number": 7 }),
            Duration::ZERO,
        )
        .await;
        let reader = DiamondMetadataReader::with_fallback_url(
            NodeClient::new(configured_url).expect("configured node"),
            Some(fallback_url),
        );

        let info = reader.query("wtyu").await.expect("fallback metadata");
        assert_eq!(info.name, "WTYU");
        assert_eq!(info.number, Some(7));
        assert_eq!(info.metadata_source, "mainnet");
        configured_server.abort();
        fallback_server.abort();
    }

    #[tokio::test]
    async fn metadata_reader_preserves_configured_error_when_fallback_also_fails() {
        let (configured_url, _, configured_server) = spawn_diamond_node(
            json!({ "ret": 1, "err": "configured metadata missing" }),
            Duration::ZERO,
        )
        .await;
        let (fallback_url, _, fallback_server) = spawn_diamond_node(
            json!({ "ret": 1, "err": "fallback unavailable" }),
            Duration::ZERO,
        )
        .await;
        let reader = DiamondMetadataReader::with_fallback_url(
            NodeClient::new(configured_url).expect("configured node"),
            Some(fallback_url),
        );

        let error = reader.query("WTYU").await.expect_err("both nodes fail");
        assert!(error.to_string().contains("configured metadata missing"));
        assert!(!error.to_string().contains("fallback unavailable"));
        configured_server.abort();
        fallback_server.abort();
    }

    #[tokio::test]
    async fn cloned_metadata_reader_allows_concurrent_queries() {
        let (node_url, max_active, server) = spawn_diamond_node(
            json!({ "ret": 0, "name": "WTYU", "number": 7 }),
            Duration::from_millis(50),
        )
        .await;
        let reader = DiamondMetadataReader::with_fallback_url(
            NodeClient::new(node_url).expect("metadata node"),
            None,
        );

        let (first, second) = tokio::join!(reader.query("WTYU"), reader.query("YUIA"));
        first.expect("first metadata");
        second.expect("second metadata");
        assert!(max_active.load(Ordering::SeqCst) >= 2);
        server.abort();
    }

    #[tokio::test]
    async fn balance_cache_is_address_bound_and_clearable() {
        let (node, calls, server) = spawn_balance_node().await;
        let mut service = AssetService::default();

        assert_eq!(service.balance_mei(&node, "1Example").await.unwrap(), 12.5);
        assert_eq!(service.balance_mei(&node, "1Example").await.unwrap(), 12.5);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert_eq!(service.balance_mei(&node, "1Other").await.unwrap(), 12.5);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        service.clear_cache();
        assert_eq!(service.balance_mei(&node, "1Other").await.unwrap(), 12.5);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        server.abort();
    }

    #[tokio::test]
    async fn snapshot_preserves_hac_btc_and_full_owned_list_contract() {
        let (node, calls, server) = spawn_balance_node().await;
        let mut service = AssetService::default();
        let snapshot = service.snapshot(&node, "1Example").await.unwrap();

        assert_eq!(snapshot.hac_mei, 12.5);
        assert_eq!(snapshot.btc_wallet_satoshi, 42);
        assert_eq!(snapshot.hacd_names, ["ZAKXMI", "WTYUIA"]);
        assert_eq!(
            snapshot.native_assets,
            [NativeAssetBalance {
                serial: 7,
                amount: 9000
            }]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }
}
