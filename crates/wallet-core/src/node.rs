use std::sync::OnceLock;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;

use crate::error::{WalletError, WalletResult};
use crate::settings::{sanitize_node_url, DEFAULT_NODE_URL};

const DEFAULT_NODE: &str = DEFAULT_NODE_URL;
const USER_AGENT: &str = "HacashWalletMobile/0.1.6";

fn shared_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(45))
            .user_agent(USER_AGENT)
            .no_proxy()
            .build()
            .expect("http client")
    })
}

fn blocking_http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(45))
        .user_agent(USER_AGENT)
        .no_proxy()
        .build()
        .expect("blocking http client")
}

async fn http_get_json<T>(url: String) -> WalletResult<T>
where
    T: DeserializeOwned + Send + 'static,
{
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(move || {
            blocking_http_client()
                .get(&url)
                .send()
                .map_err(|e| WalletError::Node(e.to_string()))?
                .json::<T>()
                .map_err(|e| WalletError::Node(e.to_string()))
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        shared_http_client()
            .get(url)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?
            .json::<T>()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))
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
            blocking_http_client()
                .post(&url)
                .json(&payload)
                .send()
                .map_err(|e| WalletError::Node(e.to_string()))?
                .json::<R>()
                .map_err(|e| WalletError::Node(e.to_string()))
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        shared_http_client()
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?
            .json::<R>()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))
    }
}

async fn http_post_text_json<R>(url: String, body: String) -> WalletResult<R>
where
    R: DeserializeOwned + Send + 'static,
{
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(move || {
            blocking_http_client()
                .post(&url)
                .header("content-type", "text/plain")
                .body(body)
                .send()
                .map_err(|e| WalletError::Node(e.to_string()))?
                .json::<R>()
                .map_err(|e| WalletError::Node(e.to_string()))
        })
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    }
    #[cfg(not(target_os = "android"))]
    {
        shared_http_client()
            .post(url)
            .header("content-type", "text/plain")
            .body(body)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?
            .json::<R>()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
}

impl Default for NodeClient {
    fn default() -> Self {
        Self::new(DEFAULT_NODE)
    }
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: sanitize_node_url(&base_url.into()),
            http: shared_http_client().clone(),
        }
    }

    pub async fn ping(&self) -> WalletResult<serde_json::Value> {
        let url = format!("{}/query/metrics", self.base_url);
        http_get_json(url).await
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
            return Err(WalletError::Node(
                body.err
                    .or(body.message)
                    .unwrap_or_else(|| "create transaction failed".into()),
            ));
        }
        Ok(body)
    }

    pub async fn balance_mei(&self, address: &str) -> WalletResult<f64> {
        self.query_balance_entry(address, false).await?.hacash_mei()
    }

    pub async fn query_balance_entry(
        &self,
        address: &str,
        include_diamonds: bool,
    ) -> WalletResult<BalanceEntry> {
        let mut url = format!(
            "{}/query/balance?unit=mei&address={}",
            self.base_url, address
        );
        if include_diamonds {
            url.push_str("&diamonds=true");
        }
        let body: BalanceResponse = http_get_json(url).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(format!("balance query failed ret={}", body.ret)));
        }
        body.list
            .iter()
            .find(|x| x.address.as_deref() == Some(address))
            .or_else(|| body.list.first())
            .cloned()
            .ok_or_else(|| WalletError::Node("address not in balance response".into()))
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

    pub async fn build_send_hac_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        fee: &str,
    ) -> WalletResult<BuildTxResponse> {
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": [
                {
                    "kind": 1,
                    "to": to,
                    "hacash": amount
                }
            ]
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
        let payload = json!({
            "main_address": from,
            "fee": fee,
            "actions": [
                {
                    "kind": 8,
                    "to": to,
                    "satoshi": satoshi
                }
            ]
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
            return Err(WalletError::Node(
                body.err
                    .or(body.message)
                    .unwrap_or_else(|| "submit failed".into()),
            ));
        }
        Ok(body)
    }

    pub async fn query_metrics(&self) -> WalletResult<serde_json::Value> {
        self.ping().await
    }

    pub async fn query_diamond_by_name(&self, name: &str) -> WalletResult<DiamondInfo> {
        let url = format!("{}/query/diamond?name={}", self.base_url, name);
        let body: DiamondQueryResponse = http_get_json(url).await?;
        if body.ret != 0 {
            return Err(WalletError::Node(format!(
                "diamond '{}' not found (ret={})",
                name, body.ret
            )));
        }
        Ok(DiamondInfo {
            name: body.name.unwrap_or_else(|| name.to_uppercase()),
            number: body.number,
            visual_gene: body.visual_gene,
            life_gene: body.life_gene,
            belong: body.belong,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiamondInfo {
    pub name: String,
    pub number: Option<u64>,
    pub visual_gene: Option<String>,
    pub life_gene: Option<String>,
    pub belong: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiamondQueryResponse {
    ret: i32,
    name: Option<String>,
    number: Option<u64>,
    visual_gene: Option<String>,
    life_gene: Option<String>,
    belong: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    ret: i32,
    list: Vec<BalanceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceEntry {
    address: Option<String>,
    hacash: String,
    diamond: Option<u32>,
    #[serde(default)]
    pub satoshi: u64,
    #[serde(default)]
    pub diamonds: Option<String>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct BuildTxResponse {
    pub ret: i32,
    pub err: Option<String>,
    pub message: Option<String>,
    pub body: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitTxResponse {
    pub ret: i32,
    pub err: Option<String>,
    pub message: Option<String>,
    pub hash: Option<String>,
}