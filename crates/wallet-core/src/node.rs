use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::error::{WalletError, WalletResult};

const DEFAULT_NODE: &str = "http://nodeapi.hacash.org";

fn shared_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("http client")
    })
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
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: shared_http_client().clone(),
        }
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
        let resp = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
        let body: BuildTxResponse = resp
            .json()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
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
        let url = format!(
            "{}/query/balance?unit=mei&address={}",
            self.base_url, address
        );
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
        let body: BalanceResponse = resp
            .json()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
        if body.ret != 0 {
            return Err(WalletError::Node(format!("balance query failed ret={}", body.ret)));
        }
        let entry = body
            .list
            .iter()
            .find(|x| x.address.as_deref() == Some(address))
            .or_else(|| body.list.first())
            .ok_or_else(|| WalletError::Node("address not in balance response".into()))?
            .clone();
        entry
            .hacash
            .parse::<f64>()
            .map_err(|e| WalletError::Node(e.to_string()))
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

    pub async fn submit_tx_hex(&self, tx_hex: &str) -> WalletResult<SubmitTxResponse> {
        self.submit_tx_hex_body(tx_hex).await
    }

    pub async fn submit_tx_hex_body(&self, tx_hex: &str) -> WalletResult<SubmitTxResponse> {
        let url = format!("{}/submit/transaction?hexbody=true", self.base_url);
        let resp = self
            .http
            .post(url)
            .body(tx_hex.to_owned())
            .header("content-type", "text/plain")
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
        let body: SubmitTxResponse = resp
            .json()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
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
        let url = format!("{}/query/metrics", self.base_url);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))?;
        resp.json()
            .await
            .map_err(|e| WalletError::Node(e.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    ret: i32,
    list: Vec<BalanceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct BalanceEntry {
    address: Option<String>,
    hacash: String,
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