//! DUST Whisper settings and transaction submission routing.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::node::{NodeClient, SubmitTxResponse};
use dust_whisper::protocol::WhisperSettings as CoreWhisperSettings;

fn default_true() -> bool {
    true
}

/// Encrypted relay transport for private tx submission (wallet → relay → fullnode).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DustWhisperSettings {
    #[serde(default)]
    pub enabled: bool,
    /// Whisper relay base URLs (tried in order).
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Fall back to direct node submit if all relays fail.
    #[serde(default = "default_true")]
    pub fallback_direct: bool,
    /// Start local `dust-whisper-relay` when the wallet app launches (if whisper enabled).
    #[serde(default = "default_true")]
    pub auto_start_relay: bool,
}

impl Default for DustWhisperSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_urls: Vec::new(),
            fallback_direct: true,
            auto_start_relay: true,
        }
    }
}

pub use dust_whisper::RelayHealthStatus;

pub fn listen_addr_from_relay_url(relay_url: &str) -> Option<String> {
    dust_whisper::listen_addr_from_relay_url(relay_url)
}

pub fn is_local_relay_url(relay_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(relay_url.trim()) else {
        return false;
    };
    matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
    )
}

pub async fn relay_health(
    node: &NodeClient,
    settings: &DustWhisperSettings,
) -> Vec<RelayHealthStatus> {
    dust_whisper::check_relays_health(node.http(), &settings.relay_urls).await
}

impl DustWhisperSettings {
    /// Non-empty relay URLs trimmed and deduplicated in order.
    pub fn trimmed_relay_urls(&self) -> Vec<String> {
        let mut out = Vec::new();
        for u in &self.relay_urls {
            let t = u.trim().to_string();
            if !t.is_empty() && !out.contains(&t) {
                out.push(t);
            }
        }
        out
    }

    fn to_core(&self) -> CoreWhisperSettings {
        CoreWhisperSettings {
            enabled: self.enabled,
            relay_urls: self.relay_urls.clone(),
            fallback_direct: self.fallback_direct,
        }
    }
}

/// User-visible notice when whisper failed and direct fallback was used.
pub fn whisper_fallback_notice(message: &Option<String>) -> Option<&str> {
    message
        .as_deref()
        .filter(|m| m.contains("DUST Whisper failed"))
}

pub async fn submit_tx_hex(
    node: &NodeClient,
    settings: &DustWhisperSettings,
    tx_hex: &str,
) -> WalletResult<SubmitTxResponse> {
    let core = settings.to_core();
    if core.enabled && !core.relay_urls.iter().any(|u| !u.trim().is_empty()) {
        return Err(WalletError::Node(
            "DUST Whisper enabled but no relay URL configured".into(),
        ));
    }

    if core.enabled {
        match dust_whisper::submit_tx(
            node.http(),
            &core,
            node.base_url(),
            tx_hex,
        )
        .await
        {
            Ok(result) => {
                return Ok(SubmitTxResponse {
                    ret: result.ret,
                    err: None,
                    message: None,
                    hash: result.hash,
                });
            }
            Err(e) if settings.fallback_direct => {
                tracing::warn!(error = %e, "DUST Whisper failed, falling back to direct submit");
                let submitted = node.submit_tx_hex(tx_hex).await?;
                return Ok(SubmitTxResponse {
                    ret: submitted.ret,
                    err: submitted.err,
                    message: Some(format!(
                        "DUST Whisper failed ({e}); submitted directly to node."
                    )),
                    hash: submitted.hash,
                });
            }
            Err(e) => {
                return Err(WalletError::Node(format!("DUST Whisper: {e}")));
            }
        }
    }

    node.submit_tx_hex(tx_hex).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_disabled() {
        let s = DustWhisperSettings::default();
        assert!(!s.enabled);
        assert!(s.fallback_direct);
    }

    #[test]
    fn detects_fallback_notice() {
        let msg = Some("DUST Whisper failed (x); submitted directly to node.".into());
        assert!(whisper_fallback_notice(&msg).is_some());
        assert!(whisper_fallback_notice(&Some("ok".into())).is_none());
    }
}