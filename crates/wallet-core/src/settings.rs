use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

/// Non-secret wallet preferences (node URL, L2 hub, channel cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSettings {
    pub node_url: String,
    pub l2_hub_url: Option<String>,
    pub hub_right_address: Option<String>,
    pub channel_id_hex: Option<String>,
    pub webauthn_enabled: bool,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            node_url: "https://nodeapi.hacash.org".into(),
            l2_hub_url: None,
            hub_right_address: None,
            channel_id_hex: None,
            webauthn_enabled: false,
        }
    }
}

impl WalletSettings {
    pub fn load() -> WalletResult<Self> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::Other(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn save(&self) -> WalletResult<()> {
        let path = settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::Other(e.to_string()))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        fs::write(path, json).map_err(|e| WalletError::Other(e.to_string()))
    }
}

pub fn settings_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("HacashWallet")
        .join("settings.json")
}