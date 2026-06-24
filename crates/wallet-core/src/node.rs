use serde::Deserialize;
use serde_json::json;

use crate::error::{WalletError, WalletResult};

const DEFAULT_NODE: &str = "https://nodeapi.hacash.org";

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
            http: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
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
            .into_iter()
            .find(|x| x.address == address)
            .ok_or_else(|| WalletError::Node("address not in balance response".into()))?;
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

    pub async fn submit_tx_hex(&self, tx_hex: &str) -> WalletResult<SubmitTxResponse> {
        let url = format!("{}/submit/transaction", self.base_url);
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
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    ret: i32,
    list: Vec<BalanceEntry>,
}

#[derive(Debug, Deserialize)]
struct BalanceEntry {
    address: String,
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