use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderValue;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{HubError, HubResult};

pub const CHANNEL_STATUS_OPENING: u8 = 0;
pub const FULLNODE_CAPABILITIES_API_V1: u64 = 1;
pub const HACASH_MAINNET_CHAIN_ID: u32 = 0;
pub const HACASH_MAINNET_BLOCK_ONE_HASH: &str =
    "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
pub const HACASH_MAINNET_MIN_SAFE_HEIGHT: u64 = 765_432;
pub const FULLNODE_MAX_TIP_AGE_SECONDS: u64 = 3_600;
pub const FULLNODE_MAX_FUTURE_SKEW_SECONDS: u64 = 120;
pub const ACTION_COOPERATIVE_ORIGINAL_CLOSE: u16 = 3;
const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const NODE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NODE_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullnodeCapabilitiesV1 {
    pub observed_unix: u64,
    pub api_version: u64,
    pub chain_id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
    pub tip_timestamp_unix: u64,
    pub tip_age_seconds: u64,
    pub registered_actions: Vec<u16>,
    pub enabled_actions: Vec<u16>,
}

impl FullnodeCapabilitiesV1 {
    pub fn action_enabled(&self, kind: u16) -> bool {
        self.enabled_actions.binary_search(&kind).is_ok()
    }

    fn parse(value: &Value) -> HubResult<Self> {
        if value.get("ret").and_then(Value::as_u64) != Some(0) {
            return Err(HubError::Node(
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("fullnode capabilities query failed")
                    .to_string(),
            ));
        }
        let api_version = required_u64(value, "api_version")?;
        if api_version != FULLNODE_CAPABILITIES_API_V1 {
            return Err(HubError::Node(format!(
                "unsupported fullnode capabilities api_version {api_version}"
            )));
        }
        let chain = value
            .get("chain")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing chain object".into()))?;
        let chain_id = u32::try_from(required_object_u64(chain, "id")?)
            .map_err(|_| HubError::Node("fullnode chain id exceeds u32".into()))?;
        let height = required_object_u64(chain, "height")?;
        let next_height = required_object_u64(chain, "next_height")?;
        if height.checked_add(1) != Some(next_height) {
            return Err(HubError::Node(
                "fullnode capabilities next_height is inconsistent".into(),
            ));
        }
        let mainnet = chain
            .get("mainnet")
            .and_then(Value::as_bool)
            .ok_or_else(|| HubError::Node("fullnode chain.mainnet must be boolean".into()))?;
        if mainnet != (chain_id == HACASH_MAINNET_CHAIN_ID) {
            return Err(HubError::Node(
                "fullnode capabilities chain identity is inconsistent".into(),
            ));
        }
        if mainnet {
            let network = value
                .get("network")
                .and_then(Value::as_object)
                .ok_or_else(|| HubError::Node("fullnode capabilities missing network".into()))?;
            let kind = network
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let block_one = network
                .get("block_1_hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let instance = network
                .get("instance_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if kind != "mainnet" || block_one != HACASH_MAINNET_BLOCK_ONE_HASH {
                return Err(HubError::Node(
                    "fullnode mainnet genesis identity is not the pinned Hacash network".into(),
                ));
            }
            if instance.len() != 64 || !instance.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(HubError::Node(
                    "fullnode mainnet instance_id is invalid".into(),
                ));
            }
        }
        let sync = value
            .get("sync")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing sync object".into()))?;
        let tip_timestamp_unix = required_object_u64(sync, "tip_timestamp_unix")?;
        let max_tip_age = required_object_u64(sync, "max_tip_age_seconds")?;
        let fresh = sync
            .get("fresh")
            .and_then(Value::as_bool)
            .ok_or_else(|| HubError::Node("fullnode sync.fresh must be boolean".into()))?;
        if max_tip_age != FULLNODE_MAX_TIP_AGE_SECONDS {
            return Err(HubError::Node(
                "fullnode sync freshness policy is incompatible".into(),
            ));
        }
        let observed_unix = now_unix();
        if tip_timestamp_unix > observed_unix.saturating_add(FULLNODE_MAX_FUTURE_SKEW_SECONDS) {
            return Err(HubError::Node(
                "fullnode chain tip timestamp is too far in the future".into(),
            ));
        }
        let tip_age_seconds = observed_unix.saturating_sub(tip_timestamp_unix);
        if !fresh || tip_age_seconds > FULLNODE_MAX_TIP_AGE_SECONDS {
            return Err(HubError::Node(format!(
                "fullnode chain tip is stale ({tip_age_seconds}s)"
            )));
        }
        let actions = value
            .get("actions")
            .and_then(Value::as_object)
            .ok_or_else(|| HubError::Node("fullnode capabilities missing actions".into()))?;
        let registered_actions = parse_action_list(actions.get("registered"), "registered")?;
        let enabled_actions = parse_action_list(actions.get("enabled"), "enabled")?;
        if enabled_actions
            .iter()
            .any(|kind| !registered_actions.contains(kind))
        {
            return Err(HubError::Node(
                "fullnode enabled action is not registered".into(),
            ));
        }
        Ok(Self {
            observed_unix,
            api_version,
            chain_id,
            height,
            next_height,
            mainnet,
            tip_timestamp_unix,
            tip_age_seconds,
            registered_actions,
            enabled_actions,
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ChannelPartyBalance {
    pub address: String,
    pub hacash: String,
    pub satoshi: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct ChannelChallenging {
    #[serde(default)]
    pub assert_bill_auto_number: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ChannelInfo {
    #[serde(default)]
    pub ret: i32,
    pub id: String,
    pub status: u8,
    #[serde(default)]
    pub reuse_version: u64,
    pub left: ChannelPartyBalance,
    pub right: ChannelPartyBalance,
    #[serde(default)]
    pub challenging: Option<ChannelChallenging>,
}

impl ChannelInfo {
    /// On-chain floor for the next bill serial (from an active challenge assert).
    pub fn l1_bill_auto_floor(&self) -> u64 {
        self.challenging
            .as_ref()
            .map(|c| c.assert_bill_auto_number)
            .unwrap_or(0)
    }

    pub fn is_open(&self) -> bool {
        self.status == CHANNEL_STATUS_OPENING
    }

    pub fn party_side(&self, address: &str) -> Option<ChannelSide> {
        if self.left.address == address {
            Some(ChannelSide::Left)
        } else if self.right.address == address {
            Some(ChannelSide::Right)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSide {
    Left,
    Right,
}

pub(crate) fn validate_mainnet_node_url(node_url: &str) -> HubResult<()> {
    let parsed = reqwest::Url::parse(node_url)
        .map_err(|_| HubError::Node("mainnet fullnode URL is invalid".into()))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(HubError::Node(
            "mainnet fullnode URL must be a clean origin without credentials, path, query, or fragment"
                .into(),
        ));
    }
    let loopback = parsed.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(HubError::Node(
            "mainnet fullnode URL must use HTTPS or loopback HTTP".into(),
        ));
    }
    Ok(())
}
pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
    api_token: Option<HeaderValue>,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> HubResult<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(NODE_CONNECT_TIMEOUT)
            .timeout(NODE_REQUEST_TIMEOUT)
            .user_agent(concat!("HPAYFastPayHub/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                HubError::Node(format!("cannot create fullnode HTTP client: {error}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            api_token: None,
        })
    }

    pub fn with_api_token(mut self, api_token: Option<&str>) -> HubResult<Self> {
        if let Some(token) = api_token.filter(|token| !token.is_empty()) {
            if token.len() > 512 || token.trim() != token {
                return Err(HubError::Node(
                    "fullnode API token is oversized or has surrounding whitespace".into(),
                ));
            }
            let mut value = HeaderValue::from_str(token).map_err(|_| {
                HubError::Node("fullnode API token contains invalid header bytes".into())
            })?;
            value.set_sensitive(true);
            self.api_token = Some(value);
        }
        Ok(self)
    }

    fn get(&self, url: String) -> reqwest::RequestBuilder {
        let request = self.http.get(url);
        match &self.api_token {
            Some(token) => request.header("x-api-token", token.clone()),
            None => request,
        }
    }

    pub async fn capabilities(&self) -> HubResult<FullnodeCapabilitiesV1> {
        let url = format!("{}/query/capabilities", self.base_url);
        let response = self
            .get(url)
            .send()
            .await
            .map_err(|error| HubError::Node(error.to_string()))?;
        if !response.status().is_success() {
            return Err(HubError::Node(format!(
                "capabilities HTTP {}",
                response.status()
            )));
        }
        let value: Value = read_bounded_json(response, "capabilities").await?;
        FullnodeCapabilitiesV1::parse(&value)
    }

    pub async fn query_channel(&self, channel_id_hex: &str) -> HubResult<ChannelInfo> {
        let url = format!(
            "{}/query/channel?unit=mei&id={channel_id_hex}",
            self.base_url
        );
        let resp = self
            .get(url)
            .send()
            .await
            .map_err(|e| HubError::Node(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(HubError::Node(format!("channel HTTP {}", resp.status())));
        }
        let info: ChannelInfo = read_bounded_json(resp, "channel").await?;
        if info.ret != 0 {
            return Err(HubError::Channel("channel not found on node".into()));
        }
        Ok(info)
    }
}
async fn read_bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    context: &str,
) -> HubResult<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NODE_RESPONSE_BYTES as u64)
    {
        return Err(HubError::Node(format!(
            "fullnode {context} response exceeds {MAX_NODE_RESPONSE_BYTES} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| HubError::Node(format!("fullnode {context} body failed: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_NODE_RESPONSE_BYTES {
            return Err(HubError::Node(format!(
                "fullnode {context} response exceeds {MAX_NODE_RESPONSE_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| HubError::Node(format!("invalid fullnode {context} response: {error}")))
}
fn parse_action_list(value: Option<&Value>, field: &str) -> HubResult<Vec<u16>> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| HubError::Node(format!("actions.{field} must be an array")))?;
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .as_u64()
            .ok_or_else(|| HubError::Node(format!("actions.{field} must contain integers")))?;
        let kind = u16::try_from(raw)
            .map_err(|_| HubError::Node(format!("actions.{field} exceeds u16")))?;
        if !seen.insert(kind) {
            return Err(HubError::Node(format!(
                "actions.{field} contains duplicates"
            )));
        }
        output.push(kind);
    }
    output.sort_unstable();
    Ok(output)
}

fn required_u64(value: &Value, field: &str) -> HubResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| HubError::Node(format!("{field} must be an integer")))
}

fn required_object_u64(value: &serde_json::Map<String, Value>, field: &str) -> HubResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| HubError::Node(format!("{field} must be an integer")))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(actions: Vec<u16>) -> Value {
        let now = now_unix();
        serde_json::json!({
            "ret": 0,
            "api_version": 1,
            "chain": {
                "id": 0,
                "height": HACASH_MAINNET_MIN_SAFE_HEIGHT,
                "next_height": HACASH_MAINNET_MIN_SAFE_HEIGHT + 1,
                "mainnet": true
            },
            "network": {
                "kind": "mainnet",
                "block_1_hash": HACASH_MAINNET_BLOCK_ONE_HASH,
                "instance_id": "11".repeat(32)
            },
            "sync": {
                "tip_timestamp_unix": now,
                "max_tip_age_seconds": FULLNODE_MAX_TIP_AGE_SECONDS,
                "fresh": true
            },
            "actions": {
                "registered": actions,
                "enabled": actions
            }
        })
    }

    #[test]
    fn mainnet_node_url_never_leaks_credentials_over_remote_http() {
        for allowed in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "https://node.example.com",
        ] {
            validate_mainnet_node_url(allowed).unwrap();
        }
        for rejected in [
            "http://192.168.1.10:8080",
            "http://node.example.com:8080",
            "ftp://127.0.0.1:8080",
            "https://user:secret@node.example.com",
            "https://node.example.com/api",
            "https://node.example.com?token=secret",
        ] {
            assert!(validate_mainnet_node_url(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn capabilities_bind_mainnet_identity_sync_and_actions() {
        let parsed = FullnodeCapabilitiesV1::parse(&capabilities(vec![1, 2, 3])).unwrap();
        assert!(parsed.mainnet);
        assert!(parsed.action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE));

        let mut wrong_genesis = capabilities(vec![3]);
        wrong_genesis["network"]["block_1_hash"] = serde_json::json!("00".repeat(32));
        assert!(FullnodeCapabilitiesV1::parse(&wrong_genesis).is_err());

        let duplicate = capabilities(vec![3, 3]);
        assert!(FullnodeCapabilitiesV1::parse(&duplicate).is_err());

        let mut unregistered = capabilities(vec![3]);
        unregistered["actions"]["enabled"] = serde_json::json!([3, 23]);
        assert!(FullnodeCapabilitiesV1::parse(&unregistered).is_err());
    }
    #[tokio::test]
    async fn configured_api_token_is_sent_and_invalid_tokens_fail_closed() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/query/capabilities",
            get(|headers: HeaderMap| async move {
                let authorized = headers
                    .get("x-api-token")
                    .and_then(|value| value.to_str().ok())
                    == Some("node-token");
                let status = if authorized {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                };
                (status, Json(capabilities(vec![1, 2, 3])))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = NodeClient::new(format!("http://{address}"))
            .unwrap()
            .with_api_token(Some("node-token"))
            .unwrap();
        assert!(
            client
                .capabilities()
                .await
                .unwrap()
                .action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE)
        );
        for invalid in ["bad\nheader", " leading", "trailing ", &"x".repeat(513)] {
            assert!(
                NodeClient::new("http://127.0.0.1:1")
                    .unwrap()
                    .with_api_token(Some(invalid))
                    .is_err()
            );
        }

        server.abort();
    }

    #[tokio::test]
    async fn redirects_are_not_followed_and_oversized_responses_fail_closed() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::Router;
        use axum::http::StatusCode;
        use axum::response::Redirect;
        use axum::routing::get;

        let redirected_calls = Arc::new(AtomicUsize::new(0));
        let target_app = Router::new().route(
            "/query/capabilities",
            get({
                let redirected_calls = redirected_calls.clone();
                move || {
                    let redirected_calls = redirected_calls.clone();
                    async move {
                        redirected_calls.fetch_add(1, Ordering::SeqCst);
                        axum::Json(capabilities(vec![1, 2, 3]))
                    }
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target_server = tokio::spawn(async move {
            axum::serve(target_listener, target_app).await.unwrap();
        });

        let redirect_location = format!("http://{target_address}/query/capabilities");
        let redirect_app = Router::new().route(
            "/query/capabilities",
            get(move || {
                let redirect_location = redirect_location.clone();
                async move { Redirect::temporary(&redirect_location) }
            }),
        );
        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let redirect_server = tokio::spawn(async move {
            axum::serve(redirect_listener, redirect_app).await.unwrap();
        });

        let redirect_client = NodeClient::new(format!("http://{redirect_address}"))
            .unwrap()
            .with_api_token(Some("must-not-leak"))
            .unwrap();
        assert!(redirect_client.capabilities().await.is_err());
        assert_eq!(redirected_calls.load(Ordering::SeqCst), 0);

        let oversized_app = Router::new().route(
            "/query/capabilities",
            get(|| async move {
                (
                    StatusCode::OK,
                    "x".repeat(MAX_NODE_RESPONSE_BYTES.saturating_add(1)),
                )
            }),
        );
        let oversized_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oversized_address = oversized_listener.local_addr().unwrap();
        let oversized_server = tokio::spawn(async move {
            axum::serve(oversized_listener, oversized_app)
                .await
                .unwrap();
        });
        let oversized_client = NodeClient::new(format!("http://{oversized_address}")).unwrap();
        assert!(oversized_client.capabilities().await.is_err());

        oversized_server.abort();
        redirect_server.abort();
        target_server.abort();
    }
}
