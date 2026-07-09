use reqwest::Client;
use url::Url;

use crate::crypto::encrypt_payload;
use crate::error::{WhisperError, WhisperResult};
use crate::http_util::ensure_success;
use crate::protocol::{
    WhisperInfo, WhisperInnerPayload, WhisperSettings, WhisperSubmitResponse, INFO_PATH,
    SUBMIT_PATH,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayHealthStatus {
    pub url: String,
    pub online: bool,
    pub error: Option<String>,
    pub node_url: Option<String>,
    pub protocol_version: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct SubmitTxResult {
    pub ret: i32,
    pub hash: Option<String>,
    pub relay_url: String,
}

pub async fn check_relay_health(http: &Client, relay_url: &str) -> RelayHealthStatus {
    let url = relay_url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return RelayHealthStatus {
            url,
            online: false,
            error: Some("empty relay URL".into()),
            node_url: None,
            protocol_version: None,
        };
    }
    match fetch_relay_info(http, &url).await {
        Ok(info) => RelayHealthStatus {
            url,
            online: true,
            error: None,
            node_url: info.node_url,
            protocol_version: Some(info.v),
        },
        Err(e) => RelayHealthStatus {
            url,
            online: false,
            error: Some(e.to_string()),
            node_url: None,
            protocol_version: None,
        },
    }
}

pub async fn check_relays_health(
    http: &Client,
    relay_urls: &[String],
) -> Vec<RelayHealthStatus> {
    let mut out = Vec::new();
    for raw in relay_urls {
        let url = raw.trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            continue;
        }
        if out.iter().any(|e: &RelayHealthStatus| e.url == url) {
            continue;
        }
        out.push(check_relay_health(http, &url).await);
    }
    out
}

pub async fn submit_tx(
    http: &Client,
    settings: &WhisperSettings,
    default_node_url: &str,
    tx_hex: &str,
) -> WhisperResult<SubmitTxResult> {
    if !settings.enabled {
        return Err(WhisperError::Protocol("whisper disabled".into()));
    }
    let relays: Vec<_> = settings
        .relay_urls
        .iter()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .collect();
    if relays.is_empty() {
        return Err(WhisperError::NoRelay);
    }

    let mut last_err = WhisperError::NoRelay;
    for relay_url in relays {
        match submit_to_relay(http, &relay_url, default_node_url, tx_hex).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                tracing::warn!(relay = %relay_url, error = %e, "DUST Whisper relay failed");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

async fn submit_to_relay(
    http: &Client,
    relay_url: &str,
    _wallet_node_url: &str,
    tx_hex: &str,
) -> WhisperResult<SubmitTxResult> {
    validate_relay_url(relay_url)?;

    let info = fetch_relay_info(http, relay_url).await?;
    let pubkey = decode_relay_pubkey(&info.pubkey)?;

    let inner = WhisperInnerPayload {
        tx_hex: tx_hex.to_owned(),
    };
    let envelope = encrypt_payload(&pubkey, &inner)?;

    let url = format!("{relay_url}{SUBMIT_PATH}");
    let resp = http
        .post(url)
        .json(&envelope)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("submit request: {e}")))?;

    let resp = ensure_success(resp, "relay submit").await?;
    let body: WhisperSubmitResponse = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("submit response JSON: {e}")))?;

    if body.ret != 0 {
        return Err(WhisperError::Relay(
            body.err
                .or(body.message)
                .unwrap_or_else(|| format!("relay submit failed ret={}", body.ret)),
        ));
    }

    Ok(SubmitTxResult {
        ret: body.ret,
        hash: body.hash,
        relay_url: relay_url.to_owned(),
    })
}

async fn fetch_relay_info(http: &Client, relay_url: &str) -> WhisperResult<WhisperInfo> {
    let url = format!("{relay_url}{INFO_PATH}");
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("info request: {e}")))?;

    let resp = ensure_success(resp, "relay info").await?;
    let info: WhisperInfo = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("info response JSON: {e}")))?;
    Ok(info)
}

fn validate_relay_url(relay_url: &str) -> WhisperResult<()> {
    let parsed = Url::parse(relay_url)
        .map_err(|e| WhisperError::Relay(format!("invalid relay URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(WhisperError::Relay(format!(
            "relay URL scheme must be http or https, got {scheme}"
        )));
    }
    let host = parsed.host_str().unwrap_or("");
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
    if !loopback && scheme != "https" {
        return Err(WhisperError::Relay(
            "relay URL must use HTTPS for non-local hosts".into(),
        ));
    }
    Ok(())
}

fn decode_relay_pubkey(b64: &str) -> WhisperResult<[u8; 32]> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| WhisperError::Crypto(format!("relay pubkey: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WhisperError::Crypto("relay pubkey must be 32 bytes".into()))
}

/// Parse `http://host:port` into `host:port` for relay `--listen`.
pub fn listen_addr_from_relay_url(relay_url: &str) -> Option<String> {
    let parsed = Url::parse(relay_url.trim()).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_require_relay_when_enabled() {
        let settings = WhisperSettings {
            enabled: true,
            relay_urls: vec![],
            fallback_direct: true,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = Client::new();
        let err = rt
            .block_on(submit_tx(
                &client,
                &settings,
                "https://node.example.com",
                "aa",
            ))
            .unwrap_err();
        assert!(matches!(err, WhisperError::NoRelay));
    }

    #[test]
    fn remote_relay_requires_https() {
        let err = validate_relay_url("http://relay.example.com").unwrap_err();
        assert!(matches!(err, WhisperError::Relay(_)));
        assert!(validate_relay_url("https://relay.example.com").is_ok());
        assert!(validate_relay_url("http://127.0.0.1:8787").is_ok());
    }

    #[test]
    fn parses_listen_addr() {
        assert_eq!(
            listen_addr_from_relay_url("http://127.0.0.1:8787").as_deref(),
            Some("127.0.0.1:8787")
        );
    }
}