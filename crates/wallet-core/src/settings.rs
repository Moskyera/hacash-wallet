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

/// Validate a node endpoint that will be trusted immediately before signing.
///
/// The legacy official API remains readable over HTTP for compatibility, but
/// it must never become a mainnet signing authority. Mainnet signing accepts
/// only authenticated remote transport or an endpoint on the same machine.
pub fn validate_signing_node_url(raw: &str, network_mode: &str) -> WalletResult<String> {
    let normalized = validate_node_url(raw)?;
    if network_mode != "mainnet" {
        return Ok(normalized);
    }
    let url = url::Url::parse(&normalized)
        .map_err(|e| WalletError::Policy(format!("invalid signing node URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| WalletError::Policy("signing node URL is missing a host".into()))?;
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(host)) {
        return Ok(normalized);
    }
    Err(WalletError::Policy(
        "mainnet signing requires HTTPS, except for a node on this same device".into(),
    ))
}

/// What it costs to sign an ordinary payment through the official node.
///
/// Said in the words a person would use, because it is the only thing they can
/// act on. The official endpoint answers plain HTTP and serves no TLS at all
/// (`https://nodeapi.hacash.org`, `:443`, `nodeapi.org`, `api.hacash.org` and
/// `node.hacash.org` all refuse the connection), so there is no HTTPS address
/// to point at and "wait for TLS" is not a shipping option.
///
/// What somebody on the network path can do, and what they cannot:
/// they can read the request and the reply, which ties an address and a
/// payment to an IP; and they can quote a wrong network fee. They cannot forge
/// a signature, they cannot change who is paid or how much (the transaction the
/// node builds is compared against the request before anything is signed), and
/// they cannot pass off a different chain while the block 1 anchor is checked,
/// which it now is on this path as on every other.
pub const OFFICIAL_NODE_PLAINTEXT_DISCLOSURE: &str = "This wallet is talking to the official Hacash node over plain HTTP, because that node offers nothing else. Whoever carries your traffic (your wifi, your ISP, a VPN) can read which address you are asking about and see the payment go out, so it links your address to your connection. They can also quote a wrong network fee, which is why the fee below is worth reading. They cannot change who gets paid or how much, they cannot sign anything for you, and they cannot swap in a different chain. Running Hacash on your own computer and pointing this wallet at http://127.0.0.1:8080 removes all of it.";

/// The same fact, short enough to sit in a fingerprint prompt.
///
/// The full disclosure belongs on a screen a person can read at their own
/// pace. A native biometric prompt is not that screen, and a paragraph pushed
/// into one is a paragraph nobody reads, so this is the one sentence that has
/// to survive: the connection is readable, and the fee beside it is the node's
/// own number rather than the wallet's.
pub const OFFICIAL_NODE_PLAINTEXT_SHORT: &str = "Plain HTTP to the official node. Readable on the way, and the fee above is the node's own number. Nobody on the way can change who is paid or how much.";

/// Validate a node endpoint for an ordinary on-chain payment.
///
/// This is [`validate_signing_node_url`] plus exactly one named exception: the
/// official endpoint, the wallet's own shipped default, at exactly
/// `http://nodeapi.hacash.org`. Nothing else changes and nothing else is
/// widened. A custom remote plaintext node is refused by `validate_node_url`
/// before this function sees it, with the same message it has always had.
///
/// It is deliberately a separate function rather than a loosening of
/// [`validate_signing_node_url`]. That rule still governs Fast Pay channels,
/// the HPAY rail preflight, the Agent Wallet and unattended node failover, and
/// none of those move. The exception applies only where a person is sending
/// their own money on chain, having been told what it costs.
pub fn validate_l1_payment_node_url(raw: &str, network_mode: &str) -> WalletResult<String> {
    let normalized = validate_node_url(raw)?;
    match validate_signing_node_url(&normalized, network_mode) {
        Ok(url) => Ok(url),
        Err(strict) => {
            if network_mode == "mainnet" && normalized == DEFAULT_NODE_URL {
                Ok(normalized)
            } else {
                Err(strict)
            }
        }
    }
}

/// True when the named exception, and nothing else, is what permits signing.
///
/// A screen uses this to decide whether to print
/// [`OFFICIAL_NODE_PLAINTEXT_DISCLOSURE`]. It is false for loopback, false for
/// HTTPS, and false off mainnet, so the disclosure appears only where the cost
/// is actually being paid.
pub fn l1_payment_uses_official_plaintext(raw: &str, network_mode: &str) -> bool {
    if network_mode != "mainnet" {
        return false;
    }
    let Ok(normalized) = validate_node_url(raw) else {
        return false;
    };
    normalized == DEFAULT_NODE_URL && validate_signing_node_url(&normalized, network_mode).is_err()
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
    /// Explicit consent to the capped Hub-dependent mainnet pilot.
    ///
    /// False is the fail-closed default. This never weakens L1 sends and is
    /// consulted only when constructing an L2 Hub client on mainnet.
    ///
    /// Turning it on needs `WalletService::set_trusted_mainnet_fast_pay_pilot`,
    /// which asks for the wallet passphrase; `update_settings` refuses. Turning
    /// it off is a tightening and needs nothing. It is still a plain field in a
    /// plain file, so a party who can write this file can set it - but the same
    /// party can already point `l2_hub_url` at a Hub of their choosing, so what
    /// bounds that exposure is the Hub caps and the prepared-review ceremony,
    /// not this flag. What the authenticated command buys is that no
    /// unauthenticated caller on the IPC surface can turn it on.
    #[serde(default)]
    pub trusted_mainnet_fast_pay_pilot: bool,
    pub hub_right_address: Option<String>,
    pub channel_id_hex: Option<String>,
    pub webauthn_enabled: bool,
    #[serde(default = "default_biometric_send_enabled")]
    pub biometric_send_enabled: bool,
    #[serde(default = "default_biometric_unlock_enabled")]
    pub biometric_unlock_enabled: bool,
    #[serde(default = "default_security_profile")]
    pub security_profile: String,
    /// User-chosen amount, in HAC, at or above which a signature needs a second factor.
    ///
    /// This can only ever *lower* the value the authenticated security profile sets.
    /// See `WalletService::second_factor_threshold_mei`, which takes the minimum of the
    /// two. That is what makes it safe to keep here, in a file that is not
    /// cryptographically bound to the vault: editing or replacing this file can make
    /// the policy stricter, never weaker.
    #[serde(default)]
    pub require_second_factor_above_mei: Option<u64>,
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
            trusted_mainnet_fast_pay_pilot: false,
            hub_right_address: None,
            channel_id_hex: None,
            webauthn_enabled: false,
            biometric_send_enabled: true,
            biometric_unlock_enabled: false,
            security_profile: default_security_profile(),
            require_second_factor_above_mei: None,
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
        // Transaction confirmation is a policy control, not a renderer preference.
        self.biometric_send_enabled = true;
        // Zero would be meaningless, since every positive amount rounds up to at least
        // one. A value above the profile ceiling is harmless because the effective
        // threshold takes the minimum, but storing it would mislead the interface.
        if self.require_second_factor_above_mei == Some(0) {
            self.require_second_factor_above_mei = None;
        }
        if !matches!(self.security_profile.as_str(), "balanced" | "paranoid") {
            self.security_profile = default_security_profile();
        }
        if !matches!(
            self.hardware_signing_mode.as_str(),
            "software" | "webauthn_gate" | "airgap_only" | "watch_only"
        ) {
            self.hardware_signing_mode = default_hardware_mode();
        }
        self.enforce_hardware_mode_invariants();
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
        if self.require_second_factor_above_mei == Some(0) {
            return Err(WalletError::Policy(
                "the second-factor amount must be at least 1 HAC; every smaller amount already rounds up to it"
                    .into(),
            ));
        }
        if !matches!(self.security_profile.as_str(), "balanced" | "paranoid") {
            return Err(WalletError::Policy("unknown security profile".into()));
        }
        if !matches!(
            self.hardware_signing_mode.as_str(),
            "software" | "webauthn_gate" | "airgap_only" | "watch_only"
        ) {
            return Err(WalletError::Policy("unknown hardware signing mode".into()));
        }
        self.enforce_hardware_mode_invariants();
        Ok(())
    }

    fn enforce_hardware_mode_invariants(&mut self) {
        if self.hardware_signing_mode == "airgap_only" {
            self.security_profile = "paranoid".into();
            self.biometric_unlock_enabled = false;
        }
    }

    pub fn load() -> WalletResult<Self> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::Other(e.to_string()))?;
        let mut settings: Self =
            serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))?;
        let before = (
            settings.node_url.clone(),
            settings.security_profile.clone(),
            settings.hardware_signing_mode.clone(),
            settings.biometric_send_enabled,
            settings.biometric_unlock_enabled,
        );
        settings.normalize();
        let after = (
            settings.node_url.clone(),
            settings.security_profile.clone(),
            settings.hardware_signing_mode.clone(),
            settings.biometric_send_enabled,
            settings.biometric_unlock_enabled,
        );
        if after != before {
            let _ = settings.save();
        }
        Ok(settings)
    }

    pub fn save(&self) -> WalletResult<()> {
        let path = settings_path();
        let mut canonical = self.clone();
        canonical.validate_and_normalize()?;
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
    fn mainnet_signing_rejects_the_legacy_http_node_but_allows_https_or_loopback() {
        assert!(validate_signing_node_url(DEFAULT_NODE_URL, "mainnet").is_err());
        assert_eq!(
            validate_signing_node_url("https://node.example", "mainnet").unwrap(),
            "https://node.example"
        );
        assert_eq!(
            validate_signing_node_url("http://127.0.0.1:8080", "mainnet").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(validate_signing_node_url(DEFAULT_NODE_URL, "testnet").is_ok());
    }

    /// The exception is one URL wide, and the proof is the refusals beside it.
    ///
    /// A wallet that shipped pointed at a node its own signing gate refused is
    /// a wallet that cannot send out of the box, which is what this exception
    /// exists to fix. What it must not do is become a general permission for
    /// plaintext, so every neighbour of the exception is listed here: the
    /// lookalike host, the userinfo trick, an unrelated plaintext host, and a
    /// port variant of the official name.
    #[test]
    fn the_l1_payment_exception_is_exactly_one_url_wide() {
        assert_eq!(
            validate_l1_payment_node_url(DEFAULT_NODE_URL, "mainnet").unwrap(),
            DEFAULT_NODE_URL
        );
        for alias in ["nodeapi.hacash.org", "nodeapi.org", " nodeapi.hacash.org "] {
            assert_eq!(
                validate_l1_payment_node_url(alias, "mainnet").unwrap(),
                DEFAULT_NODE_URL,
                "{alias}"
            );
        }

        // Loopback stays allowed, and stays the configuration that needs no
        // disclosure at all.
        assert_eq!(
            validate_l1_payment_node_url("http://127.0.0.1:8080", "mainnet").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_l1_payment_node_url("https://node.example", "mainnet").unwrap(),
            "https://node.example"
        );

        // A custom remote plaintext node is refused, and the refusal is the
        // one it has always had. This assertion is on the exact words because
        // a message that drifts is a message somebody has to re-learn.
        for hostile in [
            "http://attacker.example",
            "http://nodeapi.hacash.org.evil.example",
        ] {
            let error = validate_l1_payment_node_url(hostile, "mainnet")
                .expect_err("a custom remote plaintext node must stay refused");
            assert_eq!(
                error.to_string(),
                WalletError::Policy(
                    "custom remote nodes must use HTTPS; only the official node is allowed over HTTP"
                        .into(),
                )
                .to_string(),
                "{hostile}"
            );
        }
        let ported = validate_l1_payment_node_url("http://nodeapi.hacash.org:8080", "mainnet")
            .expect_err("a port variant is not the official endpoint");
        assert!(
            ported.to_string().contains("must not use a custom port"),
            "{ported}"
        );
    }

    /// The disclosure appears exactly where the cost is being paid.
    #[test]
    fn the_plaintext_disclosure_is_claimed_only_by_the_official_node_on_mainnet() {
        assert!(l1_payment_uses_official_plaintext(
            DEFAULT_NODE_URL,
            "mainnet"
        ));
        assert!(!l1_payment_uses_official_plaintext(
            "http://127.0.0.1:8080",
            "mainnet"
        ));
        assert!(!l1_payment_uses_official_plaintext(
            "https://node.example",
            "mainnet"
        ));
        assert!(!l1_payment_uses_official_plaintext(
            DEFAULT_NODE_URL,
            "testnet"
        ));
        assert!(!l1_payment_uses_official_plaintext(
            "http://attacker.example",
            "mainnet"
        ));

        // The words a person acts on, checked rather than assumed present.
        for needed in [
            "plain HTTP",
            "read which address",
            "wrong network fee",
            "cannot change who gets paid",
            "http://127.0.0.1:8080",
        ] {
            assert!(
                OFFICIAL_NODE_PLAINTEXT_DISCLOSURE.contains(needed),
                "the disclosure has to say {needed:?}: {OFFICIAL_NODE_PLAINTEXT_DISCLOSURE}"
            );
        }
        assert!(OFFICIAL_NODE_PLAINTEXT_SHORT.len() < 200);
    }

    /// The strict rule did not move, and everything that depends on it is
    /// named here so a future edit has to read this list before widening it.
    #[test]
    fn the_strict_signing_rule_still_refuses_the_official_node() {
        assert!(validate_signing_node_url(DEFAULT_NODE_URL, "mainnet").is_err());
        assert!(!crate::node_discovery::failover_may_adopt(
            DEFAULT_NODE_URL,
            "mainnet"
        ));
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
    fn airgap_only_forces_paranoid_and_disables_biometric_unlock() {
        let mut settings = WalletSettings {
            hardware_signing_mode: "airgap_only".into(),
            security_profile: "balanced".into(),
            biometric_unlock_enabled: true,
            ..WalletSettings::default()
        };
        settings.validate_and_normalize().unwrap();
        assert_eq!(settings.security_profile, "paranoid");
        assert!(!settings.biometric_unlock_enabled);
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
