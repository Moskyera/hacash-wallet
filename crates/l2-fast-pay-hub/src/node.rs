use serde::Deserialize;

use crate::error::{HubError, HubResult};

pub const CHANNEL_STATUS_OPENING: u8 = 0;

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

pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn query_channel(&self, channel_id_hex: &str) -> HubResult<ChannelInfo> {
        let url = format!(
            "{}/query/channel?unit=mei&id={channel_id_hex}",
            self.base_url
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| HubError::Node(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(HubError::Node(format!("channel HTTP {}", resp.status())));
        }
        let info: ChannelInfo = resp
            .json()
            .await
            .map_err(|e| HubError::Node(e.to_string()))?;
        if info.ret != 0 {
            return Err(HubError::Channel("channel not found on node".into()));
        }
        Ok(info)
    }
}