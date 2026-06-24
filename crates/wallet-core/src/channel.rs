use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};
use crate::node::{BuildTxResponse, NodeClient};

pub const CHANNEL_STATUS_OPENING: u8 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPartyBalance {
    pub address: String,
    pub hacash: String,
    pub satoshi: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    #[serde(default)]
    pub ret: i32,
    pub id: String,
    pub status: u8,
    pub open_height: u64,
    pub close_height: u64,
    pub reuse_version: u64,
    pub arbitration_lock: u64,
    pub left: ChannelPartyBalance,
    pub right: ChannelPartyBalance,
}

impl ChannelInfo {
    pub fn is_open(&self) -> bool {
        self.status == CHANNEL_STATUS_OPENING
    }

    pub fn user_is_left(&self, user_address: &str) -> bool {
        self.left.address == user_address
    }

    pub fn user_is_right(&self, user_address: &str) -> bool {
        self.right.address == user_address
    }
}

pub fn derive_channel_id(left: &str, right: &str, reuse_version: u64) -> String {
    let seed = format!("{left}|{right}|{reuse_version}");
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(&hash[..16])
}

pub async fn query_channel(node: &NodeClient, channel_id_hex: &str) -> WalletResult<ChannelInfo> {
    let url = format!(
        "{}/query/channel?unit=mei&id={}",
        node.base_url(),
        channel_id_hex
    );
    let resp = node
        .http()
        .get(url)
        .send()
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    let info: ChannelInfo = resp
        .json()
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    if info.ret != 0 {
        return Err(WalletError::Node("channel not found".into()));
    }
    Ok(info)
}

pub async fn build_channel_open_tx(
    node: &NodeClient,
    fee_payer: &str,
    channel_id_hex: &str,
    left_address: &str,
    left_amount: &str,
    right_address: &str,
    right_amount: &str,
    fee: &str,
) -> WalletResult<BuildTxResponse> {
    let payload = json!({
        "main_address": fee_payer,
        "fee": fee,
        "actions": [{
            "kind": 2,
            "channel_id": channel_id_hex,
            "left_bill": { "address": left_address, "amount": left_amount },
            "right_bill": { "address": right_address, "amount": right_amount }
        }]
    });
    node.post_create_transaction(payload).await
}

pub async fn build_channel_close_tx(
    node: &NodeClient,
    fee_payer: &str,
    channel_id_hex: &str,
    fee: &str,
) -> WalletResult<BuildTxResponse> {
    let payload = json!({
        "main_address": fee_payer,
        "fee": fee,
        "actions": [{ "kind": 3, "channel_id": channel_id_hex }]
    });
    node.post_create_transaction(payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_is_deterministic_32_hex() {
        let id = derive_channel_id("1Left", "1Right", 1);
        assert_eq!(id.len(), 32);
        assert_eq!(id, derive_channel_id("1Left", "1Right", 1));
    }
}