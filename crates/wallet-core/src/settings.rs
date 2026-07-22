use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dust_whisper::DustWhisperSettings;
use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;
use crate::privacy::PrivacySettings;
use crate::send_options::SendPreferences;

fn default_security_profile() -> String {
    "balanced".into()
}

fn default_hardware_mode() -> String {
    "software".into()
}

fn default_biometric_send_enabled() -> bool {
    true
}

fn default_biometric_unlock_enabled() -> bool {
    false
}

fn default_auto_node_failover() -> bool {
    true
}

fn default_network_mode() -> String {
    "mainnet".into()
}

/// Public Hacash L1 node (HTTP only. no valid TLS cert).
pub const DEFAULT_NODE_URL: &str = "http://nodeapi.hacash.org";

/// Whether a node draft resolves to the exact official endpoint.
/// Persisted settings are canonicalized by [`validate_node_url`], while this
/// helper also covers accepted aliases before a draft is saved.
pub fn is_official_node_url(raw: &str) -> bool {
    if raw.trim().is_empty() {
        return false;
    }
    validate_node_url(raw).is_ok_and(|url| url == DEFAULT_NODE_URL)
}

/// Validate and canonicalize a Hacash node endpoint.
///
/// The official node is a temporary exact HTTP exception. Custom remote nodes must use HTTPS;
/// loopback HTTP remains available for local development.
pub fn validate_node_url(raw: &str) -> WalletResult<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(DEFAULT_NODE_URL.into());
    }

    let candidate = if raw.contains("://") {
        raw.to_string()
    } else if raw.eq_ignore_ascii_case("nodeapi.hacash.org")
        || raw.eq_ignore_ascii_case("nodeapi.org")
    {
        DEFAULT_NODE_URL.into()
    } else {
        format!("https://{raw}")
    };
    let url = url::Url::parse(&candidate)
        .map_err(|e| WalletError::Policy(format!("invalid node URL: {e}")))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WalletError::Policy(
            "node URL must not contain credentials, query parameters, or fragments".into(),
        ));
    }
    if url.path() != "/" {
        return Err(WalletError::Policy(
            "node URL must point to the server root".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| WalletError::Policy("node URL is missing a host".into()))?
        .to_ascii_lowercase();
    if host == "nodeapi.hacash.org" || host == "nodeapi.org" {
        if !matches!(url.scheme(), "http" | "https") || url.port().is_some() {
            return Err(WalletError::Policy(
                "official node URL must not use a custom port".into(),
            ));
        }
        return Ok(DEFAULT_NODE_URL.into());
    }

    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&host) => {}
        "http" => {
            return Err(WalletError::Policy(
                "custom remote nodes must use HTTPS; only the official node is allowed over HTTP"
                    .into(),
            ));
        }
        _ => {
            return Err(WalletError::Policy(
                "node URL scheme must be HTTPS (or local HTTP)".into(),
            ));
        }
    }

    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// Safe normalization for internal constructors and migration of old settings.
pub fn sanitize_node_url(raw: &str) -> String {
    validate_node_url(raw).unwrap_or_else(|_| DEFAULT_NODE_URL.into())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Validate a remote service endpoint such as a Fast Pay hub.
pub fn validate_service_url(raw: &str, label: &str) -> WalletResult<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(WalletError::Policy(format!("{label} URL is empty")));
    }
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = url::Url::parse(&candidate)
        .map_err(|e| WalletError::Policy(format!("invalid {label} URL: {e}")))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WalletError::Policy(format!(
            "{label} URL must not contain credentials, query parameters, or fragments"
        )));
    }
    if url.path() != "/" {
        return Err(WalletError::Policy(format!(
            "{label} URL must point to the server root"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| WalletError::Policy(format!("{label} URL is missing a host")))?
        .to_ascii_lowercase();
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&host) => {}
        "http" => {
            return Err(WalletError::Policy(format!(
                "remote {label} endpoints must use HTTPS"
            )));
        }
        _ => {
            return Err(WalletError::Policy(format!(
                "{label} URL scheme must be HTTPS (or local HTTP)"
            )));
        }
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
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
    /// User-approved fallback RPC endpoints. Random internet nodes are never auto-added.
    #[serde(default)]
    pub node_fallback_urls: Vec<String>,
    /// Automatically select the first verified fallback when the active node is unreachable.
    #[serde(default = "default_auto_node_failover")]
    pub auto_node_failover: bool,
    /// Mainnet verifies the Hacash block-1 anchor. Testnet only accepts configured nodes.
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    pub l2_hub_url: Option<String>,
    pub hub_right_address: Option<String>,
    pub channel_id_hex: Option<String>,
    pub webauthn_enabled: bool,
    #[serde(default = "default_biometric_send_enabled")]
    pub biometric_send_enabled: bool,
    #[serde(default = "default_biometric_unlock_enabled")]
    pub biometric_unlock_enabled: bool,
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
    /// Legacy plaintext storage. migrated to `quantum.keystore.enc` on unlock.
    #[serde(default)]
    pub quantum_keystore_json: Option<String>,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            node_url: DEFAULT_NODE_URL.into(),
            node_fallback_urls: Vec::new(),
            auto_node_failover: true,
            network_mode: default_network_mode(),
            l2_hub_url: None,
            hub_right_address: None,
            channel_id_hex: None,
            webauthn_enabled: false,
            biometric_send_enabled: true,
            biometric_unlock_enabled: false,
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

    pub fn normalize(&mut self) {
        self.node_url = sanitize_node_url(&self.node_url);
        if !matches!(self.network_mode.as_str(), "mainnet" | "testnet") {
            self.network_mode = default_network_mode();
        }
        self.node_fallback_urls =
            canonicalize_node_fallbacks(&self.node_url, &self.node_fallback_urls)
                .unwrap_or_default();
        self.l2_hub_url = self
            .l2_hub_url
            .as_deref()
            .and_then(|url| validate_service_url(url, "Fast Pay hub").ok());
        if self.send.validate().is_err() {
            self.send = SendPreferences::default();
        }
        self.send.enforce_mandatory_service_fee();
        if !matches!(self.security_profile.as_str(), "balanced" | "paranoid") {
            self.security_profile = default_security_profile();
        }
        if !matches!(
            self.hardware_signing_mode.as_str(),
            "software" | "webauthn_gate" | "watch_only"
        ) {
            self.hardware_signing_mode = default_hardware_mode();
        }
    }

    pub fn validate_and_normalize(&mut self) -> WalletResult<()> {
        self.node_url = validate_node_url(&self.node_url)?;
        if !matches!(self.network_mode.as_str(), "mainnet" | "testnet") {
            return Err(WalletError::Policy(
                "network mode must be mainnet or testnet".into(),
            ));
        }
        self.node_fallback_urls =
            canonicalize_node_fallbacks(&self.node_url, &self.node_fallback_urls)?;
        if let Some(hub) = self.l2_hub_url.as_deref() {
            self.l2_hub_url = Some(validate_service_url(hub, "Fast Pay hub")?);
        }
        self.send.validate()?;
        self.send.enforce_mandatory_service_fee();
        if !matches!(self.security_profile.as_str(), "balanced" | "paranoid") {
            return Err(WalletError::Policy("unknown security profile".into()));
        }
        if !matches!(
            self.hardware_signing_mode.as_str(),
            "software" | "webauthn_gate" | "watch_only"
        ) {
            return Err(WalletError::Policy("unknown hardware signing mode".into()));
        }
        Ok(())
    }

    pub fn load() -> WalletResult<Self> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::Other(e.to_string()))?;
        let mut settings: Self =
            serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))?;
        let before = settings.node_url.clone();
        settings.normalize();
        if settings.node_url != before {
            let _ = settings.save();
        }
        Ok(settings)
    }

    pub fn save(&self) -> WalletResult<()> {
        let path = settings_path();
        let mut canonical = self.clone();
        canonical.send.enforce_mandatory_service_fee();
        let json =
            serde_json::to_string(&canonical).map_err(|e| WalletError::Other(e.to_string()))?;
        secure_write(&path, json.as_bytes()).map_err(|e| WalletError::Other(e.to_string()))
    }
}

fn canonicalize_node_fallbacks(active: &str, raw: &[String]) -> WalletResult<Vec<String>> {
    if raw.len() > 8 {
        return Err(WalletError::Policy(
            "at most 8 fallback node URLs are allowed".into(),
        ));
    }
    let mut out = Vec::new();
    for candidate in raw {
        let url = validate_node_url(candidate)?;
        if url != active && !out.contains(&url) {
            out.push(url);
        }
    }
    Ok(out)
}

pub fn settings_path() -> PathBuf {
    crate::paths::settings_path()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_url_allows_only_the_exact_http_exception() {
        assert_eq!(
            validate_node_url("https://nodeapi.hacash.org").unwrap(),
            DEFAULT_NODE_URL
        );
        assert!(validate_node_url("http://nodeapi.hacash.org.evil.example").is_err());
        assert!(validate_node_url("http://nodeapi.hacash.org@evil.example").is_err());
        assert!(validate_node_url("http://remote.example").is_err());
        assert_eq!(
            validate_node_url("node.example").unwrap(),
            "https://node.example"
        );
        assert_eq!(
            validate_node_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn official_node_detection_never_accepts_an_empty_or_lookalike_draft() {
        for official in [
            DEFAULT_NODE_URL,
            " https://nodeapi.hacash.org/ ",
            "nodeapi.hacash.org",
            "nodeapi.org",
        ] {
            assert!(is_official_node_url(official), "{official}");
        }
        for other in [
            "",
            "   ",
            "http://nodeapi.hacash.org:8080",
            "http://nodeapi.hacash.org.evil.example",
            "http://nodeapi.hacash.org@evil.example",
            "https://wallet-node.example",
        ] {
            assert!(!is_official_node_url(other), "{other}");
        }
    }

    #[test]
    fn remote_fast_pay_hubs_require_https() {
        assert!(validate_service_url("http://hub.example", "Fast Pay hub").is_err());
        assert!(validate_service_url("https://hub.example", "Fast Pay hub").is_ok());
        assert!(validate_service_url("http://localhost:8790", "Fast Pay hub").is_ok());
    }

    #[test]
    fn fallback_nodes_are_validated_and_deduplicated() {
        let mut settings = WalletSettings {
            node_fallback_urls: vec![
                "https://node.example".into(),
                "https://node.example/".into(),
                DEFAULT_NODE_URL.into(),
            ],
            ..WalletSettings::default()
        };
        settings.validate_and_normalize().unwrap();
        assert_eq!(
            settings.node_fallback_urls,
            vec!["https://node.example".to_string()]
        );
    }

    #[test]
    fn invalid_network_mode_is_rejected() {
        let mut settings = WalletSettings {
            network_mode: "unknown".into(),
            ..WalletSettings::default()
        };
        assert!(settings.validate_and_normalize().is_err());
    }
}
