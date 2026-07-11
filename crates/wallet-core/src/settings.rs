use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;
use crate::dust_whisper::DustWhisperSettings;
use crate::privacy::PrivacySettings;
use crate::send_options::SendPreferences;

fn default_security_profile() -> String {
    "balanced".into()
}

fn default_hardware_mode() -> String {
    "software".into()
}

/// Display-safe quantum account metadata (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantumMeta {
    pub address: String,
    pub kind: String,
    pub address_version: u8,
}

/// Non-secret wallet preferences (node URL, L2 hub, channel cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSettings {
    pub node_url: String,
    pub l2_hub_url: Option<String>,
    pub hub_right_address: Option<String>,
    pub channel_id_hex: Option<String>,
    pub webauthn_enabled: bool,
    #[serde(default = "default_security_profile")]
    pub security_profile: String,
    #[serde(default = "default_hardware_mode")]
    pub hardware_signing_mode: String,
    #[serde(default)]
    pub watch_only_address: Option<String>,
    #[serde(default)]
    pub privacy: PrivacySettings,
    #[serde(default)]
    pub dust_whisper: DustWhisperSettings,
    #[serde(default)]
    pub send: SendPreferences,
    #[serde(default)]
    pub quantum_mode: bool,
    #[serde(default)]
    pub quantum_meta: Option<QuantumMeta>,
    /// Legacy plaintext storage — migrated to `quantum.keystore.enc` on unlock.
    #[serde(default)]
    pub quantum_keystore_json: Option<String>,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            node_url: "http://nodeapi.hacash.org".into(),
            l2_hub_url: None,
            hub_right_address: None,
            channel_id_hex: None,
            webauthn_enabled: false,
            security_profile: default_security_profile(),
            hardware_signing_mode: default_hardware_mode(),
            watch_only_address: None,
            privacy: PrivacySettings::default(),
            dust_whisper: DustWhisperSettings::default(),
            send: SendPreferences::default(),
            quantum_mode: false,
            quantum_meta: None,
            quantum_keystore_json: None,
        }
    }
}

impl WalletSettings {
    pub fn hardware_mode(&self) -> crate::hardware::HardwareSigningMode {
        crate::hardware::HardwareSigningMode::from_name(&self.hardware_signing_mode)
    }

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
        let json = serde_json::to_string(self).map_err(|e| WalletError::Other(e.to_string()))?;
        secure_write(&path, json.as_bytes()).map_err(|e| WalletError::Other(e.to_string()))
    }
}

pub fn settings_path() -> PathBuf {
    crate::paths::settings_path()
}