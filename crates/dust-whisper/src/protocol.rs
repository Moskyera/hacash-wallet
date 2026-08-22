use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const INFO_PATH: &str = "/whisper/v1/info";
pub const SUBMIT_PATH: &str = "/whisper/v1/submit";
pub const MESSENGER_SEND_PATH: &str = "/whisper/v1/messenger/send";
pub const MESSENGER_INBOX_PATH: &str = "/whisper/v1/messenger/inbox";
pub const MESSENGER_CHALLENGE_PATH: &str = "/whisper/v1/messenger/challenge";
pub const MESSENGER_ACK_PATH: &str = "/whisper/v1/messenger/ack";
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

/// Opaque encrypted chat envelope routed by recipient address (relay does not decrypt).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessengerEnvelope {
    #[serde(default = "default_messenger_v")]
    pub v: u8,
    pub id: String,
    pub to: String,
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_pubkey: Option<String>,
    /// Compact secp256k1 signature, hex, over `messenger_auth::envelope_auth_digest`.
    ///
    /// Without it `from` is a string anybody can write. A relay accepted such an
    /// envelope, the receiving wallet filed it as an incoming message from that
    /// address, and the screen showed it as a message from a trusted contact.
    /// The relay refuses an envelope that does not carry a signature by the key
    /// that `from` derives from, and the receiving wallet refuses it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_sig: Option<String>,
    pub nonce: String,
    pub ciphertext: String,
    pub sent_at: String,
}

fn default_messenger_v() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerSendRequest {
    pub envelope: MessengerEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerSendResponse {
    pub ok: bool,
    pub err: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerInboxResponse {
    pub messages: Vec<MessengerEnvelope>,
    /// Whether the relay accepted the inbox claim.
    ///
    /// A refused claim used to answer with an empty message list, which is
    /// byte-for-byte what an empty inbox looks like, so the wallet reported
    /// "nothing new" to somebody who had in fact been locked out. This says
    /// which of the two happened. It leaks nothing: a caller without the
    /// address's key gets `false` whether or not that inbox exists.
    ///
    /// It defaults to `false` on a response that omits it, so an answer that
    /// cannot vouch for itself is never read as a healthy empty inbox.
    #[serde(default)]
    pub auth_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerChallengeResponse {
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerInboxRequest {
    pub to: String,
    pub claimant_pubkey: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerAckRequest {
    pub to: String,
    pub claimant_pubkey: String,
    pub nonce: String,
    pub signature: String,
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerAckResponse {
    pub ok: bool,
    pub removed: u32,
    pub err: Option<String>,
}
