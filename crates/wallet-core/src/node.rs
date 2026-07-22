use field::Address;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
#[cfg(target_os = "android")]
use std::io::Read;

use crate::error::{WalletError, WalletResult};
#[cfg(target_os = "android")]
use crate::http_client::blocking_http_client;
use crate::http_client::shared_http_client;
use crate::node_capabilities::{NodeApiError, NodeCapabilities};
use crate::settings::sanitize_node_url;

const MAX_NODE_JSON_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum BalanceError {
    UnsupportedAddress { message: String },
    Node { ret: i32, message: String },
}

impl From<BalanceError> for WalletError {
    fn from(error: BalanceError) -> Self {
        match error {
            BalanceError::UnsupportedAddress { message } => {
                WalletError::UnsupportedAddress(message)
            }
            BalanceError::Node { ret, message } => {
                WalletError::Node(format!("{message} (ret={ret})"))
            }
        }
    }
}

fn classify_balance_error(ret: i32, address: &str, message: String) -> BalanceError {
    let type4_address = Address::from_readable(address)
        .map(|parsed| matches!(parsed.version(), Address::PQCKEY | Address::HYBRID))
        .unwrap_or(false);

    if ret == 1 && type4_address {
        BalanceError::UnsupportedAddress { message }
    } else {
        BalanceError::Node { ret, message }
    }
}

fn select_balance_entry(
    entries: &[BalanceEntry],
    requested_address: &str,
) -> WalletResult<BalanceEntry> {
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.address.as_deref() == Some(requested_address))
    {
        return Ok(entry.clone());
    }

    // Older nodes may omit the address when a single address was requested.
    // Never accept an explicitly different address or an ambiguous row set.
    if let [entry] = entries
        && entry.address.is_none()
    {
        return Ok(entry.clone());
    }

    Err(WalletError::Node(
        "balance response did not contain the requested address".into(),
    ))
}

fn node_reachability_hint(url: &str) -> String {
    let mut hints: Vec<&str> = Vec::new();
    if url.starts_with("https://nodeapi.hacash.org") || url.starts_with("https://nodeapi.org") {
        hints.push("Official Hacash node is HTTP only. use http://nodeapi.hacash.org.");
    }
    if url.contains("127.0.0.1")
        || url.contains("localhost")
        || url.contains("10.0.2.2")
        || url.contains("192.168.")
        || url.contains("10.")
    {
        hints.push("That URL points to a local/private network host. it will not work on a phone unless it is your LAN IP.");
    }
    #[cfg(target_os = "android")]
    {
        hints.push(
            "On phone: More → Settings → Node URL must be http://nodeapi.hacash.org, tap Save, then Test node. Turn VPN off and try Wi‑Fi and mobile data.",
        );
    }
    #[cfg(not(target_os = "android"))]
    if hints.is_empty() {
        hints.push("Check network connection and node URL in Settings.");
    }
    if hints.is_empty() {
        String::new()
    } else {
        format!(" {}", hints.join(" "))
    }
}

fn node_transport_err(url: &str, err: impl std::fmt::Display) -> WalletError {
    let hint = node_reachability_hint(url);
    WalletError::Node(format!("cannot reach {url}. {err}.{hint}"))
}

fn decode_http_json<T>(url: &str, status: reqwest::StatusCode, body: &[u8]) -> WalletResult<T>
where
    T: DeserializeOwned,
{
    if body.len() > MAX_NODE_JSON_BYTES {
        return Err(WalletError::Node(format!(
            "{url}: node response exceeds {} bytes",
            MAX_NODE_JSON_BYTES
        )));
    }
    if !status.is_success() {
        let fallback = format!("HTTP {}", status.as_u16());
        let error = serde_json::from_slice::<Value>(body)
            .map(|value| NodeApiError::from_value(&value, fallback.clone()))
            .unwrap_or_else(|_| NodeApiError::from_value(&Value::Null, fallback));
        return Err(WalletError::NodeHttpStatus {
            status: status.as_u16(),
            message: error.to_string(),
        });
    }
    serde_json::from_slice(body)
        .map_err(|error| WalletError::Node(format!("{url}: invalid JSON response: {error}")))
}

fn oversized_node_response(url: &str) -> WalletError {
    WalletError::Node(format!(
        "{url}: node response exceeds {} bytes",
        MAX_NODE_JSON_BYTES
    ))
}

#[cfg(target_os = "android")]
fn read_blocking_node_body(
    response: reqwest::blocking::Response,
    url: &str,
) -> WalletResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NODE_JSON_BYTES as u64)
    {
        return Err(oversized_node_response(url));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_NODE_JSON_BYTES as u64) as usize,
    );
    response
        .take(MAX_NODE_JSON_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| WalletError::Node(format!("{url}: cannot read response: {error}")))?;
    if body.len() > MAX_NODE_JSON_BYTES {
        return Err(oversized_node_response(url));
    }
    Ok(body)
}

#[cfg(not(target_os = "android"))]
async fn read_async_node_body(mut response: reqwest::Response, url: &str) -> WalletResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NODE_JSON_BYTES as u64)
    {
        return Err(oversized_node_response(url));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_NODE_JSON_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| WalletError::Node(format!("{url}: cannot read response: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_NODE_JSON_BYTES {
            return Err(oversized_node_response(url));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn http_get_json<T>(url: String) -> WalletResult<T>
where
    T: DeserializeOwned + Send + 'static,
{
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(move || {
            let response = blocking_http_client()
                .map_err(WalletError::Node)?
                .get(&url)
                .send()
                .map_err(|e| node_transport_err(&url, e))?;
            let status = response.status();
            let body = read_blocking_node_body(response, &url)?;
            decode_http_json(&url, status, &body)
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let response = shared_http_client()
            .map_err(WalletError::Node)?
            .get(&url)
            .send()
            .await
            .map_err(|e| node_transport_err(&url, e))?;
        let status = response.status();
        let body = read_async_node_body(response, &url).await?;
        decode_http_json(&url, status, &body)
    }
}

async fn http_post_json<T, R>(url: String, payload: T) -> WalletResult<R>
where
    T: serde::Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(move || {
            let response = blocking_http_client()
                .map_err(WalletError::Node)?
                .post(&url)
                .json(&payload)
                .send()
                .map_err(|e| node_transport_err(&url, e))?;
            let status = response.status();
            let body = read_blocking_node_body(response, &url)?;
            decode_http_json(&url, status, &body)
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let response = shared_http_client()
            .map_err(WalletError::Node)?
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| node_transport_err(&url, e))?;
        let status = response.status();
        let body = read_async_node_body(response, &url).await?;
        decode_http_json(&url, status, &body)
    }
}

async fn http_post_text_json<R>(url: String, body: String) -> WalletResult<R>
where
    R: DeserializeOwned + Send + 'static,
{
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(move || {
            let response = blocking_http_client()
                .map_err(WalletError::Node)?
                .post(&url)
                .header("content-type", "text/plain")
                .body(body)
                .send()
                .map_err(|e| node_transport_err(&url, e))?;
            let status = response.status();
            let body = read_blocking_node_body(response, &url)?;
            decode_http_json(&url, status, &body)
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let response = shared_http_client()
            .map_err(WalletError::Node)?
            .post(&url)
            .header("content-type", "text/plain")
            .body(body)
            .send()
            .await
            .map_err(|e| node_transport_err(&url, e))?;
        let status = response.status();
        let body = read_async_node_body(response, &url).await?;
        decode_http_json(&url, status, &body)
    }
}

#[derive(Debug, Clone)]
pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> WalletResult<Self> {
        Ok(Self {
            base_url: sanitize_node_url(&base_url.into()),
            http: shared_http_client().map_err(WalletError::Node)?.clone(),
        })
    }

    pub async fn ping(&self) -> WalletResult<serde_json::Value> {
        // Public nodeapi has no /query/metrics (404). /query/latest is always JSON with ret=0.
        let url = format!("{}/query/latest", self.base_url);
        let latest: serde_json::Value = http_get_json(url).await?;
        Ok(serde_json::json!({
            "reachable": true,
            "node": self.base_url,
            "latest": latest
        }))
    }

    pub async fn capabilities(&self) -> WalletResult<NodeCapabilities> {
        let url = format!("{}/query/capabilities", self.base_url);
        let value: Value = match http_get_json(url).await {
            Ok(value) => value,
            Err(WalletError::NodeHttpStatus { status: 404, .. }) => {
                return Ok(NodeCapabilities::legacy_type2(self.base_url.clone()));
            }
            Err(error) => return Err(error),
        };
        let ret = value.get("ret").and_then(Value::as_i64).ok_or_else(|| {
            WalletError::Node("capability response is missing numeric ret".into())
        })?;
        if ret != 0 {
            return Err(WalletError::Node(
                NodeApiError::from_value(&value, "capability query failed").to_string(),
            ));
        }
        let capabilities: NodeCapabilities = serde_json::from_value(value).map_err(|error| {
            WalletError::Node(format!("capability response shape invalid: {error}"))
        })?;
        capabilities.validate()
    }

    pub async fn block_intro(&self, height: u64) -> WalletResult<BlockIntroResponse> {
        let url = format!("{}/query/block/intro?height={height}", self.base_url);
        let body: BlockIntroResponse = http_get_json(url).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(body.err.clone().unwrap_or_else(|| {
                format!("block intro failed (ret={})", body.ret)
            })));
        }
        Ok(body)
    }

    /// Estimate minimum Type 4 fee: `fee_purity × wire_bytes` (see `/query/fee/average`).
    pub async fn query_fee_average(
        &self,
        consumption_bytes: usize,
        tx_type: u8,
    ) -> WalletResult<FeeAverageResponse> {
        let url = format!(
            "{}/query/fee/average?consumption={}&tx_type={}&unit=mei",
            self.base_url, consumption_bytes, tx_type
        );
        let body: FeeAverageResponse = http_get_json(url).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(body.err.unwrap_or_else(|| {
                format!("fee/average failed (ret={})", body.ret)
            })));
        }
        Ok(body)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub async fn post_create_transaction(
        &self,
        payload: serde_json::Value,
    ) -> WalletResult<BuildTxResponse> {
        let url = format!("{}/create/transaction", self.base_url);
        let body: BuildTxResponse = http_post_json(url, payload).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(body.api_error().to_string()));
        }
        Ok(body)
    }

    pub async fn balance_mei(&self, address: &str) -> WalletResult<f64> {
        self.query_balance_entry(address, false).await?.hacash_mei()
    }

    pub async fn query_balance_entry(
        &self,
        address: &str,
        include_asset_details: bool,
    ) -> WalletResult<BalanceEntry> {
        let mut url = format!(
            "{}/query/balance?unit=mei&address={}",
            self.base_url, address
        );
        if include_asset_details {
            url.push_str("&diamonds=true&assets=true");
        }
        let body: BalanceResponse = http_get_json(url).await?;
        if body.ret != 0 {
            let node_message = body
                .err
                .unwrap_or_else(|| format!("balance query failed (ret={})", body.ret));
            return Err(classify_balance_error(body.ret, address, node_message).into());
        }
        select_balance_entry(&body.list, address)
    }

    pub async fn build_send_diamond_tx(
        &self,
        from: &str,
        to: &str,
        diamond_names: &[String],
        fee: &str,
    ) -> WalletResult<BuildTxResponse> {
        let action = if diamond_names.len() == 1 {
            json!({
                "kind": 5,
                "to": to,
                "diamond": diamond_names[0]
            })
        } else {
            json!({
                "kind": 7,
                "to": to,
                "diamonds": diamond_names.join("")
            })
        };
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": [action]
        });
        self.post_create_transaction(payload).await
    }

    /// Build an HACD transfer with a mandatory HAC treasury action in the same
    /// transaction, so either both legs settle or neither does.
    pub async fn build_send_diamond_tx_with_service_fee(
        &self,
        from: &str,
        to: &str,
        diamond_names: &[String],
        service_fee: &str,
        fee: &str,
    ) -> WalletResult<BuildTxResponse> {
        let diamond_action = if diamond_names.len() == 1 {
            json!({ "kind": 5, "to": to, "diamond": diamond_names[0] })
        } else {
            json!({ "kind": 7, "to": to, "diamonds": diamond_names.join("") })
        };
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": [
                diamond_action,
                { "kind": 1, "to": crate::send_options::WALLET_TREASURY_ADDRESS, "hacash": service_fee }
            ]
        });
        self.post_create_transaction(payload).await
    }

    pub async fn build_send_hac_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        fee: &str,
    ) -> WalletResult<BuildTxResponse> {
        self.build_send_hac_tx_actions(from, fee, &[(to, amount)])
            .await
    }

    /// Build an L1 HAC send with one or more `kind: 1` transfer actions (e.g. recipient + treasury).
    pub async fn build_send_hac_tx_actions(
        &self,
        from: &str,
        fee: &str,
        transfers: &[(&str, &str)],
    ) -> WalletResult<BuildTxResponse> {
        let actions: Vec<_> = transfers
            .iter()
            .map(|(to, amount)| {
                json!({
                    "kind": 1,
                    "to": to,
                    "hacash": amount
                })
            })
            .collect();
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": actions
        });
        self.post_create_transaction(payload).await
    }

    pub async fn build_send_btc_tx(
        &self,
        from: &str,
        to: &str,
        satoshi: u64,
        fee: &str,
    ) -> WalletResult<BuildTxResponse> {
        self.build_send_btc_tx_actions(from, fee, &[(to, satoshi)])
            .await
    }

    pub async fn build_send_btc_tx_actions(
        &self,
        from: &str,
        fee: &str,
        transfers: &[(&str, u64)],
    ) -> WalletResult<BuildTxResponse> {
        let actions: Vec<_> = transfers
            .iter()
            .map(|(to, satoshi)| {
                json!({
                    "kind": 10,
                    "to": to,
                    "satoshi": satoshi
                })
            })
            .collect();
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": actions
        });
        self.post_create_transaction(payload).await
    }

    pub async fn submit_tx_hex(&self, tx_hex: &str) -> WalletResult<SubmitTxResponse> {
        self.submit_tx_hex_body(tx_hex).await
    }

    pub async fn submit_tx_hex_body(&self, tx_hex: &str) -> WalletResult<SubmitTxResponse> {
        let url = format!("{}/submit/transaction?hexbody=true", self.base_url);
        let body: SubmitTxResponse = http_post_text_json(url, tx_hex.to_owned()).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(body.api_error().to_string()));
        }
        Ok(body)
    }

    pub async fn query_metrics(&self) -> WalletResult<serde_json::Value> {
        self.ping().await
    }

    pub async fn query_diamond_by_name(&self, name: &str) -> WalletResult<DiamondInfo> {
        let normalized = name.trim().to_ascii_uppercase();
        if !is_valid_node_diamond_name(&normalized) {
            return Err(WalletError::Other(
                "HACD name must use 4 to 6 letters from WTYUIAHXVMEKBSZN".into(),
            ));
        }
        let url = format!("{}/query/diamond?name={}", self.base_url, normalized);
        let body: DiamondQueryResponse = http_get_json(url).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(body.err.unwrap_or_else(|| {
                format!("diamond '{}' not found (ret={})", normalized, body.ret)
            })));
        }
        Ok(body.into_info(&normalized))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockIntroResponse {
    pub ret: i32,
    #[serde(default)]
    pub err: Option<String>,
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeeAverageResponse {
    pub ret: i32,
    #[serde(default)]
    pub err: Option<String>,
    pub feasible: String,
    pub purity: u64,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct DiamondBornInfo {
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiamondInfo {
    pub name: String,
    /// `configured` for the selected node, or `mainnet` for the read-only
    /// official-node metadata fallback used when a testnet has no diamonds.
    pub metadata_source: String,
    pub number: Option<u64>,
    pub visual_gene: Option<String>,
    pub life_gene: Option<String>,
    pub belong: Option<String>,
    pub miner: Option<String>,
    pub bid_fee: Option<String>,
    pub average_bid_burn: Option<u64>,
    pub born: Option<DiamondBornInfo>,
    pub prev_hash: Option<String>,
    pub inscriptions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DiamondQueryResponse {
    ret: i32,
    #[serde(default)]
    err: Option<String>,
    #[allow(dead_code)]
    name: Option<String>,
    number: Option<u64>,
    visual_gene: Option<String>,
    life_gene: Option<String>,
    belong: Option<String>,
    miner: Option<String>,
    bid_fee: Option<String>,
    average_bid_burn: Option<u64>,
    born: Option<DiamondBornInfo>,
    prev_hash: Option<String>,
    #[serde(default)]
    inscriptions: Vec<String>,
    #[serde(default)]
    inscription_items: Vec<DiamondInscriptionItem>,
}

#[derive(Debug, Deserialize)]
struct DiamondInscriptionItem {
    content: Option<String>,
}

impl DiamondQueryResponse {
    fn into_info(self, requested_name: &str) -> DiamondInfo {
        DiamondInfo {
            // The HTTP node is untrusted. Keep the exact validated name requested by the wallet.
            name: requested_name.to_ascii_uppercase(),
            metadata_source: "configured".into(),
            number: self.number,
            visual_gene: clean_visual_gene(self.visual_gene),
            life_gene: exact_hex(self.life_gene, 64),
            belong: clean_node_address(self.belong),
            miner: clean_node_address(self.miner),
            bid_fee: self.bid_fee.and_then(clean_bid_fee),
            average_bid_burn: self.average_bid_burn,
            born: self.born.and_then(|born| {
                exact_hex(Some(born.hash), 64).map(|hash| DiamondBornInfo {
                    height: born.height,
                    hash,
                })
            }),
            prev_hash: exact_hex(self.prev_hash, 64),
            inscriptions: self
                .inscriptions
                .into_iter()
                .chain(
                    self.inscription_items
                        .into_iter()
                        .filter_map(|item| item.content),
                )
                .filter_map(clean_inscription)
                .fold(Vec::new(), |mut values, value| {
                    if !values.contains(&value) {
                        values.push(value);
                    }
                    values
                })
                .into_iter()
                .take(16)
                .collect(),
        }
    }
}

fn exact_hex(value: Option<String>, expected_len: usize) -> Option<String> {
    let value = value?;
    (value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// Official nodes/explorers use 18–20 hex visual genes (HIP-5).
fn clean_visual_gene(value: Option<String>) -> Option<String> {
    let value = value?;
    let lower = value.to_ascii_lowercase();
    let len = lower.len();
    ((18..=20).contains(&len) && lower.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(lower)
}

fn clean_node_address(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        Address::from_readable(value.trim())
            .ok()
            .map(|address| address.to_readable())
    })
}

fn clean_bid_fee(value: String) -> Option<String> {
    let value = value.trim();
    let mut parts = value.split(':');
    let amount = parts.next()?;
    let unit = parts.next();
    let valid_amount = !amount.is_empty() && amount.bytes().all(|byte| byte.is_ascii_digit());
    let valid_unit = unit.is_none_or(|part| {
        !part.is_empty() && part.len() <= 3 && part.bytes().all(|byte| byte.is_ascii_digit())
    });
    (value.len() <= 32 && valid_amount && valid_unit && parts.next().is_none())
        .then(|| value.to_owned())
}

fn is_valid_node_diamond_name(name: &str) -> bool {
    const ALPHABET: &str = "WTYUIAHXVMEKBSZN";
    (4..=6).contains(&name.len()) && name.chars().all(|character| ALPHABET.contains(character))
}

fn clean_inscription(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.chars().count() <= 128 && value.chars().all(|ch| !ch.is_control()))
        .then(|| value.to_owned())
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    ret: i32,
    #[serde(default)]
    err: Option<String>,
    #[serde(default)]
    list: Vec<BalanceEntry>,
}

mod u64_decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireValue {
        Number(u64),
        Decimal(String),
    }

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        match WireValue::deserialize(deserializer)? {
            WireValue::Number(value) => Ok(value),
            WireValue::Decimal(value) => value.parse::<u64>().map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAssetBalance {
    /// Serialized as a decimal string so JavaScript cannot lose u64 precision.
    #[serde(with = "u64_decimal")]
    pub serial: u64,
    /// Serialized as a decimal string so JavaScript cannot lose u64 precision.
    #[serde(with = "u64_decimal")]
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceEntry {
    address: Option<String>,
    hacash: String,

    #[serde(default)]
    pub satoshi: u64,
    #[serde(default)]
    pub diamonds: Option<String>,
    #[serde(default)]
    pub assets: Vec<NativeAssetBalance>,
}

impl BalanceEntry {
    pub fn hacash_mei(&self) -> WalletResult<f64> {
        self.hacash
            .parse::<f64>()
            .map_err(|e| WalletError::Node(e.to_string()))
    }

    pub fn btc_satoshi(&self) -> u64 {
        self.satoshi
    }

    pub fn native_assets(&self) -> WalletResult<Vec<NativeAssetBalance>> {
        let max_assets = field::BALANCE_ASSET_MAX;
        if self.assets.len() > max_assets {
            return Err(WalletError::Node(format!(
                "native asset list exceeds {max_assets} entries"
            )));
        }
        let mut assets = self.assets.clone();
        if assets
            .iter()
            .any(|asset| asset.serial == 0 || asset.amount == 0)
        {
            return Err(WalletError::Node(
                "native asset balance contains a zero serial or amount".into(),
            ));
        }
        assets.sort_by_key(|asset| asset.serial);
        if assets
            .windows(2)
            .any(|pair| pair[0].serial == pair[1].serial)
        {
            return Err(WalletError::Node(
                "native asset balance contains duplicate serials".into(),
            ));
        }
        Ok(assets)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildTxResponse {
    pub ret: i32,
    #[serde(default)]
    pub err: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default, flatten)]
    pub details: Map<String, Value>,
}

impl BuildTxResponse {
    pub fn api_error(&self) -> NodeApiError {
        NodeApiError {
            ret: Some(self.ret),
            code: self.code.clone(),
            stage: self.stage.clone(),
            message: self
                .message
                .clone()
                .or_else(|| self.error.clone())
                .or_else(|| self.err.clone())
                .unwrap_or_else(|| "create transaction failed".into()),
            details: self.details.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub ret: i32,
    #[serde(default)]
    pub err: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default, flatten)]
    pub details: Map<String, Value>,
}

impl SubmitTxResponse {
    pub fn api_error(&self) -> NodeApiError {
        NodeApiError {
            ret: Some(self.ret),
            code: self.code.clone(),
            stage: self.stage.clone(),
            message: self
                .message
                .clone()
                .or_else(|| self.error.clone())
                .or_else(|| self.err.clone())
                .unwrap_or_else(|| "submit failed".into()),
            details: self.details.clone(),
        }
    }
}

#[cfg(test)]
mod diamond_metadata_tests {
    use super::*;

    #[test]
    fn parses_and_bounds_official_diamond_metadata() {
        let raw = r#"{
            "ret": 0,
            "name": "VWMMMM",
            "number": 101028,
            "visual_gene": "2580999930cc13fbfde0",
            "life_gene": "ede9413718d6927708542f05c8c86526634cf4e1c3d01c7c91138f7b3f2d9e25",
            "belong": "15fv6cNEapTNqYhigMPr38pC1XRKn3Wh5q",
            "miner": "1Hf721QbjYCaD6YUFvBa9dF9RJkM4DgBXP",
            "bid_fee": "225214:244",
            "average_bid_burn": 14,
            "born": {
                "height": 599640,
                "hash": "00000000000d36e38debbb4f38423a66d4620884b6ae1e4e447372210043f471"
            },
            "prev_hash": "000000000012930b81cafac920c2a9ce2af116e2cf6725c6183dc206754430e5",
            "inscriptions": ["hacds"]
        }"#;
        let response: DiamondQueryResponse = serde_json::from_str(raw).unwrap();
        let info = response.into_info("vwmmmm");

        assert_eq!(info.name, "VWMMMM");
        assert_eq!(info.number, Some(101028));
        assert_eq!(info.average_bid_burn, Some(14));
        assert_eq!(info.born.as_ref().map(|born| born.height), Some(599640));
        assert_eq!(info.inscriptions, vec!["hacds"]);
    }

    #[test]
    fn rejects_untrusted_metadata_fields() {
        let response = DiamondQueryResponse {
            ret: 0,
            err: None,
            name: Some("<script>".into()),
            number: None,
            visual_gene: Some("<svg onload=alert(1)>".into()),
            life_gene: Some("g".repeat(64)),
            belong: Some("javascript:alert(1)".into()),
            miner: None,
            bid_fee: Some("1:244<script>".into()),
            average_bid_burn: None,
            born: None,
            prev_hash: Some("0".repeat(63)),
            inscriptions: vec!["ok".into(), "bad\ncontrol".into()],
            inscription_items: vec![],
        };
        let info = response.into_info("WTYU");
        assert_eq!(info.name, "WTYU");
        assert!(info.visual_gene.is_none());
        assert!(info.life_gene.is_none());
        assert!(info.belong.is_none());
        assert!(info.bid_fee.is_none());
        assert!(info.prev_hash.is_none());
        assert_eq!(info.inscriptions, vec!["ok"]);
        assert!(clean_bid_fee("::".into()).is_none());
        assert!(clean_bid_fee("1:244:1".into()).is_none());
        assert_eq!(
            clean_bid_fee("225214:244".into()).as_deref(),
            Some("225214:244")
        );
        assert!(is_valid_node_diamond_name("VWMMMM"));
        assert!(!is_valid_node_diamond_name("ABCDEF"));
    }

    #[test]
    fn parses_official_balance_error_envelope_without_decode_failure() {
        let raw = r#"{"err":"address 3RAj55Bnux2JBJ1W91hHy7Mv3hbHBFxBRj format invalid","ret":1}"#;
        let response: BalanceResponse = serde_json::from_str(raw).unwrap();

        assert_eq!(response.ret, 1);
        assert_eq!(
            response.err.as_deref(),
            Some("address 3RAj55Bnux2JBJ1W91hHy7Mv3hbHBFxBRj format invalid")
        );
        assert!(response.list.is_empty());
    }

    #[test]
    fn reads_inscriptions_from_current_official_metadata_shape() {
        let raw = r#"{
            "ret": 0,
            "name": "VWMMMM",
            "inscription_items": [{"content":"hacds","engraved_type":0}]
        }"#;
        let response: DiamondQueryResponse = serde_json::from_str(raw).unwrap();
        let info = response.into_info("VWMMMM");

        assert_eq!(info.inscriptions, vec!["hacds"]);
    }

    #[test]
    fn classifies_type4_balance_rejection_without_matching_node_text() {
        let error = classify_balance_error(
            1,
            "3RAj55Bnux2JBJ1W91hHy7Mv3hbHBFxBRj",
            "address rejected".into(),
        );

        assert!(matches!(error, BalanceError::UnsupportedAddress { .. }));
    }

    #[test]
    fn preserves_non_format_type4_node_errors() {
        let error = classify_balance_error(
            2,
            "3RAj55Bnux2JBJ1W91hHy7Mv3hbHBFxBRj",
            "node unavailable".into(),
        );

        assert!(matches!(error, BalanceError::Node { ret: 2, .. }));
    }

    #[test]
    fn preserves_regular_node_balance_errors() {
        let error = classify_balance_error(
            1,
            "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9",
            "temporary failure".into(),
        );

        assert!(matches!(error, BalanceError::Node { ret: 1, .. }));
    }

    fn parse_balance_entries(value: serde_json::Value) -> Vec<BalanceEntry> {
        serde_json::from_value::<BalanceResponse>(json!({
            "ret": 0,
            "list": value,
        }))
        .expect("balance response")
        .list
    }

    #[test]
    fn balance_selector_uses_the_exact_requested_address() {
        let entries = parse_balance_entries(json!([
            { "address": "1Other", "hacash": "99" },
            { "address": "1Requested", "hacash": "7" }
        ]));

        let selected = select_balance_entry(&entries, "1Requested").expect("exact match");
        assert_eq!(selected.hacash_mei().unwrap(), 7.0);
    }

    #[test]
    fn balance_selector_accepts_only_a_sole_addressless_legacy_row() {
        let entries = parse_balance_entries(json!([{ "hacash": "7" }]));
        assert_eq!(
            select_balance_entry(&entries, "1Requested")
                .expect("sole legacy row")
                .hacash_mei()
                .unwrap(),
            7.0
        );

        let ambiguous = parse_balance_entries(json!([
            { "hacash": "7" },
            { "hacash": "8" }
        ]));
        assert!(select_balance_entry(&ambiguous, "1Requested").is_err());
    }

    #[test]
    fn balance_selector_rejects_a_sole_mismatched_address() {
        let entries = parse_balance_entries(json!([{
            "address": "1Other",
            "hacash": "99"
        }]));

        let error = select_balance_entry(&entries, "1Requested").expect_err("mismatch");
        assert!(error.to_string().contains("requested address"));
    }

    #[test]
    fn native_asset_balances_are_sorted_and_consensus_bounded() {
        let entries = parse_balance_entries(json!([{
            "address": "1Requested",
            "hacash": "1",
            "assets": [
                { "serial": 9, "amount": 2 },
                { "serial": 3, "amount": 4 }
            ]
        }]));
        assert_eq!(
            entries[0].native_assets().unwrap(),
            [
                NativeAssetBalance {
                    serial: 3,
                    amount: 4
                },
                NativeAssetBalance {
                    serial: 9,
                    amount: 2
                }
            ]
        );

        let too_many = (1..=field::BALANCE_ASSET_MAX + 1)
            .map(|serial| json!({ "serial": serial, "amount": 1 }))
            .collect::<Vec<_>>();
        let entries = parse_balance_entries(json!([{
            "address": "1Requested", "hacash": "1", "assets": too_many
        }]));
        assert!(entries[0].native_assets().is_err());
    }

    #[test]
    fn native_asset_balances_reject_zero_and_duplicate_entries() {
        for assets in [
            json!([{ "serial": 0, "amount": 1 }]),
            json!([{ "serial": 1, "amount": 0 }]),
            json!([
                { "serial": 7, "amount": 1 },
                { "serial": 7, "amount": 2 }
            ]),
        ] {
            let entries = parse_balance_entries(json!([{
                "address": "1Requested", "hacash": "1", "assets": assets
            }]));
            assert!(entries[0].native_assets().is_err());
        }
    }

    #[test]
    fn native_asset_json_preserves_full_u64_precision() {
        let asset = NativeAssetBalance {
            serial: u64::MAX,
            amount: u64::MAX - 1,
        };
        assert_eq!(
            serde_json::to_value(&asset).unwrap(),
            json!({
                "serial": u64::MAX.to_string(),
                "amount": (u64::MAX - 1).to_string()
            })
        );

        for wire in [
            json!({ "serial": 7, "amount": 9 }),
            json!({ "serial": "7", "amount": "9" }),
        ] {
            let decoded: NativeAssetBalance = serde_json::from_value(wire).unwrap();
            assert_eq!(
                decoded,
                NativeAssetBalance {
                    serial: 7,
                    amount: 9
                }
            );
        }
    }
}
