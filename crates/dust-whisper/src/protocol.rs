use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const INFO_PATH: &str = "/whisper/v1/info";
pub const SUBMIT_PATH: &str = "/whisper/v1/submit";
pub const HKDF_INFO: &[u8] = b"dust-whisper-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhisperSettings {
    pub enabled: bool,
    pub relay_urls: Vec<String>,
    pub fallback_direct: bool,
}

impl Default for WhisperSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_urls: Vec::new(),
            fallback_direct: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhisperInfo {
    pub v: u8,
    /// Base64-encoded X25519 relay public key (32 bytes).
    pub pubkey: String,
    /// Default fullnode URL the relay forwards to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperSubmitRequest {
    pub v: u8,
    pub ephemeral_pubkey: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperInnerPayload {
    pub tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperSubmitResponse {
    pub ret: i32,
    pub err: Option<String>,
    pub message: Option<String>,
    pub hash: Option<String>,
}