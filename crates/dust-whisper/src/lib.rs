//! DUST Whisper — encrypted relay transport for Hacash transaction submission.
//!
//! Wallets encrypt signed tx hex and POST to a relay; the relay decrypts and forwards
//! to a fullnode without the wallet exposing its IP to the node API.

pub mod crypto;
pub mod error;
pub mod http_util;
pub mod protocol;

pub mod client;
pub mod relay;

pub use client::{
    check_relay_health, check_relays_health, listen_addr_from_relay_url, submit_tx,
    RelayHealthStatus,
};
pub use error::{WhisperError, WhisperResult};
pub use protocol::{WhisperInfo, WhisperSettings, PROTOCOL_VERSION};