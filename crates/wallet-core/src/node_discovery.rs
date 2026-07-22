//! Safe RPC failover across user-approved Hacash nodes.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::node::NodeClient;
use crate::settings::{DEFAULT_NODE_URL, WalletSettings};

pub const MAINNET_BLOCK_ONE_HASH: &str =
    "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_CONCURRENT_NODE_PROBES: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCandidateStatus {
    pub url: String,
    pub online: bool,
    pub network_match: bool,
    pub height: Option<u64>,
    pub diamond: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDiscoveryReport {
    pub active_node: String,
    pub switched: bool,
    pub network_mode: String,
    pub candidates: Vec<NodeCandidateStatus>,
}

/// Immutable node configuration captured while the wallet state lock is held.
///
/// Discovery performs network I/O from this snapshot after releasing the lock.
/// The wallet accepts a discovered fallback only if this configuration is still
/// current when the probe finishes.
#[derive(Debug, Clone)]
pub struct NodeDiscoverySnapshot {
    pub(crate) settings: WalletSettings,
    pub(crate) active_node: String,
    pub(crate) network_mode: String,
}

impl NodeDiscoverySnapshot {
    pub(crate) fn new(settings: WalletSettings, active_node: String, network_mode: String) -> Self {
        Self {
            settings,
            active_node,
            network_mode,
        }
    }
}

pub fn candidate_urls(settings: &WalletSettings) -> Vec<String> {
    let mut urls = vec![settings.node_url.clone()];
    for url in &settings.node_fallback_urls {
        if !urls.contains(url) {
            urls.push(url.clone());
        }
    }
    if settings.network_mode == "mainnet" && !urls.iter().any(|url| url == DEFAULT_NODE_URL) {
        urls.push(DEFAULT_NODE_URL.into());
    }
    urls
}

pub async fn discover_node_snapshot(snapshot: &NodeDiscoverySnapshot) -> NodeDiscoveryReport {
    discover_node_candidates(&snapshot.settings).await
}

pub async fn discover_node_candidates(settings: &WalletSettings) -> NodeDiscoveryReport {
    let urls = candidate_urls(settings);
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_NODE_PROBES));
    let mut probes = JoinSet::new();
    for (index, url) in urls.iter().cloned().enumerate() {
        let limiter = Arc::clone(&limiter);
        let network_mode = settings.network_mode.clone();
        let _ = probes.spawn(async move {
            let Ok(_permit) = limiter.acquire_owned().await else {
                return (
                    index,
                    failed(&url, "node probe concurrency limiter closed".into()),
                );
            };
            let status = probe_node(&url, &network_mode).await;
            (index, status)
        });
    }

    let mut ordered = vec![None; urls.len()];
    while let Some(result) = probes.join_next().await {
        if let Ok((index, status)) = result {
            ordered[index] = Some(status);
        }
    }
    let candidates = ordered
        .into_iter()
        .enumerate()
        .map(|(index, status)| {
            status
                .unwrap_or_else(|| failed(&urls[index], "node probe task did not complete".into()))
        })
        .collect();

    NodeDiscoveryReport {
        active_node: settings.node_url.clone(),
        switched: false,
        network_mode: settings.network_mode.clone(),
        candidates,
    }
}

pub async fn probe_node(url: &str, network_mode: &str) -> NodeCandidateStatus {
    let node = match NodeClient::new(url.to_string()) {
        Ok(node) => node,
        Err(error) => return failed(url, error.to_string()),
    };
    let latest = match tokio::time::timeout(PROBE_TIMEOUT, node.ping()).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return failed(url, error.to_string()),
        Err(_) => return failed(url, "health check timed out".into()),
    };
    let latest = latest.get("latest").cloned().unwrap_or_default();
    let ret = latest.get("ret").and_then(|value| value.as_i64());
    let height = latest.get("height").and_then(|value| value.as_u64());
    let diamond = latest.get("diamond").and_then(|value| value.as_u64());
    if ret != Some(0) || height.unwrap_or(0) == 0 {
        return failed(url, "node returned an invalid latest-block response".into());
    }

    let anchor = match tokio::time::timeout(PROBE_TIMEOUT, node.block_intro(1)).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return failed(url, format!("network anchor check failed: {error}")),
        Err(_) => return failed(url, "network anchor check timed out".into()),
    };
    let network_match = network_anchor_matches(network_mode, anchor.height, &anchor.hash);
    if !network_match {
        let expected = if network_mode == "mainnet" {
            "does not match the Hacash mainnet anchor"
        } else {
            "is a mainnet node and cannot be used in testnet mode"
        };
        return NodeCandidateStatus {
            url: url.to_string(),
            online: true,
            network_match: false,
            height,
            diamond,
            error: Some(format!("node is online but {expected}")),
        };
    }

    NodeCandidateStatus {
        url: url.to_string(),
        online: true,
        network_match: true,
        height,
        diamond,
        error: None,
    }
}

fn failed(url: &str, error: String) -> NodeCandidateStatus {
    NodeCandidateStatus {
        url: url.to_string(),
        online: false,
        network_match: false,
        height: None,
        diamond: None,
        error: Some(error),
    }
}

fn network_anchor_matches(network_mode: &str, height: u64, hash: &str) -> bool {
    height == 1
        && if network_mode == "mainnet" {
            hash.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH)
        } else {
            !hash.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH)
        }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use axum::{Json, Router, extract::State, routing::get};
    use serde_json::json;

    #[test]
    fn mainnet_candidates_always_keep_official_fallback() {
        let settings = WalletSettings {
            node_url: "https://node.example".into(),
            node_fallback_urls: vec!["https://backup.example".into()],
            ..WalletSettings::default()
        };
        assert_eq!(
            candidate_urls(&settings),
            vec![
                "https://node.example",
                "https://backup.example",
                DEFAULT_NODE_URL
            ]
        );
    }

    #[test]
    fn testnet_never_falls_back_to_mainnet() {
        let settings = WalletSettings {
            node_url: "http://127.0.0.1:8080".into(),
            network_mode: "testnet".into(),
            ..WalletSettings::default()
        };
        assert_eq!(candidate_urls(&settings), vec!["http://127.0.0.1:8080"]);
    }

    #[test]
    fn testnet_rejects_the_mainnet_anchor() {
        assert!(!network_anchor_matches(
            "testnet",
            1,
            MAINNET_BLOCK_ONE_HASH
        ));
        assert!(network_anchor_matches(
            "testnet",
            1,
            "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
        ));
    }

    async fn spawn_probe_node(
        block_one_hash: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/query/latest",
                get(|| async { Json(json!({ "ret": 0, "height": 100, "diamond": 5 })) }),
            )
            .route(
                "/query/block/intro",
                get(move || async move {
                    Json(json!({ "ret": 0, "height": 1, "hash": block_one_hash }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn probe_prevents_cross_network_failover() {
        let (mainnet_url, mainnet_task) = spawn_probe_node(MAINNET_BLOCK_ONE_HASH).await;
        let (testnet_url, testnet_task) =
            spawn_probe_node("000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff")
                .await;

        assert!(probe_node(&mainnet_url, "mainnet").await.network_match);
        assert!(!probe_node(&mainnet_url, "testnet").await.network_match);
        assert!(probe_node(&testnet_url, "testnet").await.network_match);
        assert!(!probe_node(&testnet_url, "mainnet").await.network_match);

        mainnet_task.abort();
        testnet_task.abort();
    }

    #[derive(Clone, Default)]
    struct ProbeLoad {
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    async fn spawn_slow_probe_node(load: ProbeLoad) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/query/latest",
                get(|State(load): State<ProbeLoad>| async move {
                    let active = load.active.fetch_add(1, Ordering::SeqCst) + 1;
                    load.peak.fetch_max(active, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(75)).await;
                    load.active.fetch_sub(1, Ordering::SeqCst);
                    Json(json!({ "ret": 0, "height": 100, "diamond": 5 }))
                }),
            )
            .route(
                "/query/block/intro",
                get(|| async {
                    Json(json!({
                        "ret": 0,
                        "height": 1,
                        "hash": "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
                    }))
                }),
            )
            .with_state(load);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn discovery_is_bounded_concurrent_and_preserves_candidate_order() {
        let load = ProbeLoad::default();
        let mut urls = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let (url, task) = spawn_slow_probe_node(load.clone()).await;
            urls.push(url);
            tasks.push(task);
        }
        let settings = WalletSettings {
            node_url: urls[0].clone(),
            node_fallback_urls: urls[1..].to_vec(),
            network_mode: "testnet".into(),
            ..WalletSettings::default()
        };

        let report = discover_node_candidates(&settings).await;

        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| candidate.url.clone())
                .collect::<Vec<_>>(),
            urls
        );
        assert!(report.candidates.iter().all(|candidate| candidate.online));
        let peak = load.peak.load(Ordering::SeqCst);
        assert!(peak > 1, "node probes ran sequentially");
        assert!(peak <= MAX_CONCURRENT_NODE_PROBES, "probe limit exceeded");

        for task in tasks {
            task.abort();
        }
    }
}
