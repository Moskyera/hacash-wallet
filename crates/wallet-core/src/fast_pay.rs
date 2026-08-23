//! Fast Pay (L2) presets and user-facing status. hides channel/hub complexity from normal sends.

use serde::{Deserialize, Serialize};

use crate::channel::{CHANNEL_STATUS_OPENING, query_channel};
use crate::error::WalletResult;
use crate::l2_hub::L2HubClient;
use crate::node::NodeClient;
use crate::settings::WalletSettings;

/// Default one-time channel deposit when the user taps “Enable Fast Pay”.
pub const DEFAULT_CHANNEL_DEPOSIT_MEI: f64 = 10.0;

/// Known CSP / hub endpoints. The wallet tries these in order when none is configured.
#[derive(Debug, Clone)]
pub struct CspPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub hub_url: &'static str,
    /// On-chain address of the hub. Empty means it must come from hub `/v1/health`.
    pub hub_address: &'static str,
}

pub const CSP_PRESETS: &[CspPreset] = &[CspPreset {
    id: "local",
    name: "Local dev hub",
    hub_url: "http://127.0.0.1:8790",
    hub_address: "",
}];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPayState {
    /// Hub healthy and channel open. instant sends available.
    Ready,
    /// Hub found but channel not opened yet.
    NeedsChannel,
    /// User configured a hub URL but it is unreachable.
    HubUnreachable,
    /// A provider is configured and its capabilities are being checked.
    Checking,
    /// Provider is online but cannot create safe fee-free routed settlements.
    ProviderIncompatible,
    /// No hub configured and no preset responded.
    NoProvider,
}

impl FastPayState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsChannel => "needs_channel",
            Self::HubUnreachable => "hub_unreachable",
            Self::Checking => "checking",
            Self::ProviderIncompatible => "provider_incompatible",
            Self::NoProvider => "no_provider",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayStatus {
    pub state: FastPayState,
    pub message: String,
    pub provider_name: Option<String>,
    pub hub_url: Option<String>,
    pub can_enable: bool,
    pub default_deposit_mei: f64,
}

impl FastPayStatus {
    pub fn ready(provider: impl Into<String>) -> Self {
        Self {
            state: FastPayState::Ready,
            message: "Sends settle in seconds with no Fast Pay fee.".into(),
            provider_name: Some(provider.into()),
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn needs_channel(provider: impl Into<String>, deposit: f64) -> Self {
        Self {
            state: FastPayState::NeedsChannel,
            message: format!("Deposit {deposit} HAC once to turn on. Blockchain pays still work."),
            provider_name: Some(provider.into()),
            hub_url: None,
            can_enable: true,
            default_deposit_mei: deposit,
        }
    }

    pub fn no_provider() -> Self {
        Self {
            state: FastPayState::NoProvider,
            message: "Not set up yet. Sends use the blockchain.".into(),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn hub_unreachable() -> Self {
        Self {
            state: FastPayState::HubUnreachable,
            message: "Payment network offline. Sends use the blockchain for now.".into(),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn checking() -> Self {
        Self {
            state: FastPayState::Checking,
            message: "Checking provider settlement and routing capabilities.".into(),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn provider_incompatible() -> Self {
        Self {
            state: FastPayState::ProviderIncompatible,
            message:
                "Provider is online but does not support safe, fee-free routed settlement yet."
                    .into(),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    /// The provider is capable, and a mainnet gate refused. Say which.
    ///
    /// [`Self::provider_incompatible`] states a cause: the provider "does not
    /// support safe, fee-free routed settlement yet". That is true of a Hub
    /// whose `/v1/health` is missing a capability, and it was also shown when a
    /// mainnet readiness gate refused, where it is simply false - the same Hub
    /// was publishing `settlement_ready: true`, `cross_channel_ready: true` and
    /// a zero fee at the moment the wallet told the user it could not do
    /// fee-free routed settlement. What it lacked was the mainnet guarantees,
    /// and the wallet was holding the Hub's own reason and dropped it. Telling
    /// a user a wrong cause is worse than telling them a vague one: they go and
    /// change the provider, which fixes nothing.
    pub fn provider_incompatible_because(error: &crate::error::WalletError) -> Self {
        Self {
            state: FastPayState::ProviderIncompatible,
            message: format!(
                "Fast Pay is not available on this provider: {}",
                user_facing_reason(error)
            ),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }
}

/// User-facing text for a wallet error, without the `l2:` routing prefix that
/// only makes sense inside the codebase.
pub fn user_facing_reason(error: &crate::error::WalletError) -> String {
    let text = error.to_string();
    text.strip_prefix("l2: ").unwrap_or(&text).to_owned()
}

#[derive(Debug, Clone)]
pub struct DiscoveredHub {
    pub preset_id: String,
    pub name: String,
    pub hub_url: String,
    pub hub_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubDiscoveryEntry {
    pub id: String,
    pub name: String,
    pub hub_url: String,
    pub online: bool,
    pub hub_address: Option<String>,
    pub hub_fee_mei: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubDiscoveryReport {
    pub hubs: Vec<HubDiscoveryEntry>,
    pub online_count: usize,
}

pub async fn discover_all_hubs(extra_urls: &[String]) -> HubDiscoveryReport {
    let mut candidates: Vec<(String, String, String)> = CSP_PRESETS
        .iter()
        .map(|preset| {
            (
                preset.id.to_string(),
                preset.name.to_string(),
                preset.hub_url.to_string(),
            )
        })
        .collect();

    for raw in extra_urls {
        let url = raw.trim().trim_end_matches('/').to_string();
        if url.is_empty() || candidates.iter().any(|(_, _, u)| u == &url) {
            continue;
        }
        candidates.push(("custom".into(), "Configured hub".into(), url));
    }

    let mut hubs = Vec::with_capacity(candidates.len());
    for (id, name, hub_url) in candidates {
        hubs.push(probe_hub_entry(id, name, hub_url).await);
    }

    let online_count = hubs.iter().filter(|h| h.online).count();
    HubDiscoveryReport { hubs, online_count }
}

async fn probe_hub_entry(id: String, fallback_name: String, hub_url: String) -> HubDiscoveryEntry {
    let preset = CSP_PRESETS.iter().find(|p| p.id == id);
    let client = L2HubClient::for_health_discovery(&hub_url);
    match client.health().await {
        Ok(health)
            if health.ok
                && health.version >= 3
                && health.settlement_ready
                && health.cross_channel_ready
                && crate::l2_hub::hub_fee_is_zero(&health) =>
        {
            HubDiscoveryEntry {
                id,
                name: health
                    .name
                    .clone()
                    .filter(|n| !n.is_empty())
                    .unwrap_or(fallback_name),
                hub_url,
                online: true,
                hub_address: health
                    .hub_address
                    .clone()
                    .filter(|a| !a.is_empty())
                    .or_else(|| {
                        preset.and_then(|p| {
                            (!p.hub_address.is_empty()).then(|| p.hub_address.to_string())
                        })
                    }),
                hub_fee_mei: crate::l2_hub::hub_fee_label(&health),
                error: None,
            }
        }
        Ok(health) => HubDiscoveryEntry {
            id,
            name: fallback_name,
            hub_url,
            online: false,
            hub_address: None,
            hub_fee_mei: None,
            error: Some(if health.ok {
                "Provider is not compatible with routing-ready, fee-free Fast Pay v3".into()
            } else {
                "Hub returned ok=false".into()
            }),
        },
        Err(e) => HubDiscoveryEntry {
            id,
            name: fallback_name,
            hub_url,
            online: false,
            hub_address: None,
            hub_fee_mei: None,
            error: Some(e.to_string()),
        },
    }
}

/// What one Hub says about itself, in the Hub's own words, before any money.
///
/// Every field here is transcribed from that Hub's `/v1/health` and
/// `/v1/readiness/mainnet`. Nothing in it is this build's opinion, and nothing
/// in it grants anything: the readiness document is re-fetched and re-gated at
/// the signing boundary, so a green declaration here is a preview and not an
/// authority. It exists because a person choosing a Hub was previously shown
/// only this build's compile-time ceilings (1/10/100 HAC) while the Hub they
/// were about to fund might declare a tenth of that and refuse the first
/// channel - and because when a Hub refuses, its own named blockers are the
/// only actionable thing anyone has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubDeclaration {
    pub hub_url: String,
    pub reachable: bool,
    /// Why the Hub could not be read, verbatim. `None` when it answered.
    pub error: Option<String>,
    pub name: Option<String>,
    pub hub_address: Option<String>,
    pub version: Option<u64>,
    pub settlement_ready: bool,
    pub cross_channel_ready: bool,
    pub hub_fee_mei: Option<String>,
    /// The Hub's own transport/deployment label from `/v1/health`.
    pub deployment_profile: Option<String>,
    /// True when this wallet is on mainnet, so the reader knows whether the
    /// readiness half below was even asked for.
    pub mainnet_checked: bool,
    /// The readiness profile the Hub published, e.g. `mainnet-bounded-pilot`.
    pub readiness_profile: Option<String>,
    pub payments_enabled: Option<bool>,
    /// The Hub's three declared caps, in HAC. `None` per cap it did not send.
    pub declared_caps: crate::l2_hub::DeclaredHubCaps,
    /// What the Hub says is stopping it. Verbatim, not summarised.
    pub blockers: Vec<String>,
    /// What the Hub says is outstanding and has decided not to gate on.
    pub disclosed_blockers: Vec<String>,
    pub limitations: Vec<String>,
    /// Why the readiness document could not be read, when health succeeded.
    pub readiness_error: Option<String>,
}

impl HubDeclaration {
    fn unreachable(hub_url: String, mainnet_checked: bool, error: String) -> Self {
        Self {
            hub_url,
            reachable: false,
            error: Some(error),
            name: None,
            hub_address: None,
            version: None,
            settlement_ready: false,
            cross_channel_ready: false,
            hub_fee_mei: None,
            deployment_profile: None,
            mainnet_checked,
            readiness_profile: None,
            payments_enabled: None,
            declared_caps: Default::default(),
            blockers: Vec::new(),
            disclosed_blockers: Vec::new(),
            limitations: Vec::new(),
            readiness_error: None,
        }
    }
}

/// Read one Hub's own declaration from a URL the person typed.
///
/// Deliberately takes the URL as an argument rather than reading saved
/// settings: the whole point is to let somebody see what a Hub says *before*
/// they commit to it. Saves nothing and changes nothing.
///
/// The URL goes through [`crate::settings::validate_service_url`] first, which
/// applies exactly the rule the rest of the wallet applies to service
/// endpoints - HTTPS, or HTTP on this same machine - so a bad URL is refused
/// with a reason instead of producing a confusing connection failure.
pub async fn hub_declaration(raw_url: &str, network_mode: &str) -> HubDeclaration {
    let is_mainnet = network_mode == "mainnet";
    let hub_url = match crate::settings::validate_service_url(raw_url, "Fast Pay hub") {
        Ok(url) => url,
        Err(error) => {
            return HubDeclaration::unreachable(
                raw_url.trim().to_string(),
                is_mainnet,
                user_facing_reason(&error),
            );
        }
    };

    let client = L2HubClient::new_for_network(&hub_url, network_mode);
    let health = match client.health().await {
        Ok(health) => health,
        Err(error) => {
            return HubDeclaration::unreachable(hub_url, is_mainnet, user_facing_reason(&error));
        }
    };

    let mut declaration = HubDeclaration {
        hub_url,
        reachable: true,
        error: (!health.ok).then(|| "the Hub reports itself as not ok".to_string()),
        name: health.name.clone().filter(|name| !name.is_empty()),
        hub_address: health.hub_address.clone().filter(|a| !a.is_empty()),
        version: Some(u64::from(health.version)),
        settlement_ready: health.settlement_ready,
        cross_channel_ready: health.cross_channel_ready,
        hub_fee_mei: crate::l2_hub::hub_fee_label(&health),
        deployment_profile: health.deployment_profile.clone(),
        mainnet_checked: is_mainnet,
        readiness_profile: None,
        payments_enabled: None,
        declared_caps: Default::default(),
        blockers: Vec::new(),
        disclosed_blockers: Vec::new(),
        limitations: Vec::new(),
        readiness_error: None,
    };

    if !is_mainnet {
        return declaration;
    }

    match client.mainnet_readiness().await {
        Ok(readiness) => {
            declaration.readiness_profile = Some(readiness.profile.clone());
            declaration.payments_enabled = Some(readiness.payments_enabled);
            declaration.declared_caps = readiness.declared_caps_hac();
            declaration.blockers = readiness.blockers.clone();
            declaration.disclosed_blockers = readiness.disclosed_blockers.clone();
            declaration.limitations = readiness.limitations.clone();
        }
        Err(error) => {
            declaration.readiness_error = Some(user_facing_reason(&error));
        }
    }
    declaration
}

pub async fn discover_healthy_hub() -> Option<DiscoveredHub> {
    let report = discover_all_hubs(&[]).await;
    report
        .hubs
        .into_iter()
        .find(|h| h.online)
        .map(|h| DiscoveredHub {
            preset_id: h.id,
            name: h.name,
            hub_url: h.hub_url,
            hub_address: h.hub_address,
        })
}

pub async fn evaluate_fast_pay(
    node: &NodeClient,
    settings: &WalletSettings,
    user_address: Option<&str>,
) -> WalletResult<FastPayStatus> {
    let hub_url = settings.l2_hub_url.clone();
    let channel_id = settings.channel_id_hex.clone();

    if let (Some(url), Some(ch_id), Some(user)) = (&hub_url, &channel_id, user_address) {
        let hub = L2HubClient::new_for_wallet_policy(
            url.clone(),
            &settings.network_mode,
            settings.trusted_mainnet_fast_pay_pilot,
        );
        match hub.health().await {
            Ok(h)
                if h.ok
                    && h.version >= 3
                    && h.settlement_ready
                    && h.cross_channel_ready
                    && crate::l2_hub::hub_fee_is_zero(&h) =>
            {
                if settings.network_mode == "mainnet"
                    && let Err(error) = hub.require_mainnet_payment_ready(None).await
                {
                    return Ok(FastPayStatus::provider_incompatible_because(&error));
                }
                if let Ok(ch) = query_channel(node, ch_id).await
                    && channel_ready(&ch, user)
                {
                    let name = settings
                        .hub_right_address
                        .as_deref()
                        .map(|_| "your provider".to_string())
                        .or_else(|| Some("Fast Pay".into()));
                    return Ok(FastPayStatus::ready(
                        name.unwrap_or_else(|| "Fast Pay".into()),
                    ));
                }
                return Ok(FastPayStatus::needs_channel(
                    "your provider",
                    DEFAULT_CHANNEL_DEPOSIT_MEI,
                ));
            }
            Ok(_) => return Ok(FastPayStatus::provider_incompatible()),
            Err(_) => return Ok(FastPayStatus::hub_unreachable()),
        }
    }

    if let Some(url) = hub_url.as_deref()
        && channel_id.is_none()
    {
        let client = L2HubClient::new_for_wallet_policy(
            url,
            &settings.network_mode,
            settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = match client.health().await {
            Ok(health) => health,
            Err(_) => return Ok(FastPayStatus::hub_unreachable()),
        };
        if !health.ok
            || health.version < 3
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            return Ok(FastPayStatus::provider_incompatible());
        }
        let deposit = if settings.network_mode == "mainnet" {
            let readiness = match client.require_mainnet_payment_ready(None).await {
                Ok(readiness) => readiness,
                Err(error) => return Ok(FastPayStatus::provider_incompatible_because(&error)),
            };
            (readiness.max_channel_funding_millimeis() as f64 / 1_000.0)
                .min(DEFAULT_CHANNEL_DEPOSIT_MEI)
        } else {
            DEFAULT_CHANNEL_DEPOSIT_MEI
        };
        return Ok(FastPayStatus::needs_channel(
            health.name.unwrap_or_else(|| "your provider".into()),
            deposit,
        ));
    }
    if let Some(discovered) = discover_healthy_hub().await {
        return Ok(FastPayStatus::needs_channel(
            discovered.name,
            DEFAULT_CHANNEL_DEPOSIT_MEI,
        ));
    }

    Ok(FastPayStatus::no_provider())
}

pub fn apply_discovered_hub(settings: &mut WalletSettings, discovered: &DiscoveredHub) {
    if settings.l2_hub_url.is_none() {
        settings.l2_hub_url = Some(discovered.hub_url.clone());
    }
    if settings.hub_right_address.is_none()
        && let Some(addr) = &discovered.hub_address
    {
        settings.hub_right_address = Some(addr.clone());
    }
}

fn channel_ready(channel: &crate::channel::ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}

pub fn rail_label(rail: crate::payment::PaymentRail) -> &'static str {
    match rail {
        crate::payment::PaymentRail::L2Fast => "Instant Fast Pay",
        crate::payment::PaymentRail::L1OnChain => "Blockchain",
        crate::payment::PaymentRail::QuantumType4 => "Quantum",
    }
}

pub fn rail_detail(rail: crate::payment::PaymentRail) -> &'static str {
    match rail {
        crate::payment::PaymentRail::L2Fast => "Settles in seconds with no Fast Pay fee.",
        crate::payment::PaymentRail::L1OnChain => {
            "Broadcast to the configured Hacash network. Confirmation time depends on mining."
        }
        crate::payment::PaymentRail::QuantumType4 => {
            "Type 4 transaction using the selected PQC or hybrid signing mode."
        }
    }
}

#[cfg(test)]
mod hub_declaration_tests {
    use axum::{Json, Router, routing::get};

    use super::*;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A bounded-pilot Hub whose aggregate cap is a tenth of its channel cap:
    /// the exact configuration the shipped binary default produces, and the one
    /// a person could not previously see.
    fn readiness_json() -> serde_json::Value {
        let now = unix_now();
        serde_json::json!({
            "schema": "hpay-fast-pay-mainnet-readiness/1",
            "evaluated_unix": now,
            "valid_until_unix": now + 60,
            "profile": "mainnet-bounded-pilot",
            "payments_enabled": false,
            "close_enabled": true,
            "mainnet_detected": true,
            "fullnode_capabilities": null,
            "max_payment_hac_zhu": 100_000_000_u64,
            "max_channel_funding_hac_zhu": 1_000_000_000_u64,
            "max_aggregate_tvl_hac_zhu": 100_000_000_u64,
            "aggregate_tvl_within_limit": true,
            "max_payment_satoshi": 0,
            "wallet_fee_hac": "0",
            "trustless_finality": false,
            "unilateral_l1_enforceable": false,
            "trusted_bounded_pilot": true,
            "settlement_model": "hub-coordinated ordered signatures with durable recovery",
            "blockers": ["fullnode_capability_probe_failed: connection refused"],
            "close_blockers": [],
            "disclosed_blockers": ["unilateral_l1_dispute_path_is_not_ready"],
            "limitations": [
                "new channels require an allowlisted user and aggregate Hub TVL at or below 100000000 zhu"
            ]
        })
    }

    fn health_json() -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "version": 7,
            "name": "Pilot Hub",
            "hub_address": "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9",
            "hub_fee_mei": "0",
            "settlement_ready": true,
            "cross_channel_ready": true,
            "deployment_profile": "mainnet-bounded-pilot"
        })
    }

    async fn spawn_hub() -> String {
        let app = Router::new()
            .route("/v1/health", get(|| async { Json(health_json()) }))
            .route(
                "/v1/readiness/mainnet",
                get(|| async { Json(readiness_json()) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// The point of the whole surface: a person sees the Hub's own numbers, not
    /// this build's ceilings. A Hub declaring 1/10/1 must not be described by
    /// the 1/10/100 the build refuses to cross.
    #[tokio::test]
    async fn a_hub_declares_all_three_caps_and_its_own_blockers() {
        let url = spawn_hub().await;
        let declaration = hub_declaration(&url, "mainnet").await;

        assert!(declaration.reachable, "{:?}", declaration.error);
        assert_eq!(declaration.name.as_deref(), Some("Pilot Hub"));
        assert_eq!(
            declaration.readiness_profile.as_deref(),
            Some("mainnet-bounded-pilot")
        );
        assert_eq!(declaration.payments_enabled, Some(false));

        let caps = &declaration.declared_caps;
        assert_eq!(caps.max_payment_hac.as_deref(), Some("1"));
        assert_eq!(caps.max_channel_funding_hac.as_deref(), Some("10"));
        // The field the wallet used to drop entirely. Without it a person with
        // 7 HAC reads a 10 HAC channel cap off a Hub that will refuse anything
        // over 1 HAC at admission.
        assert_eq!(caps.max_aggregate_tvl_hac.as_deref(), Some("1"));
        assert_eq!(caps.aggregate_tvl_within_limit, Some(true));

        // Verbatim, not summarised into "provider incompatible".
        assert_eq!(
            declaration.blockers,
            vec!["fullnode_capability_probe_failed: connection refused".to_string()]
        );
        assert_eq!(
            declaration.disclosed_blockers,
            vec!["unilateral_l1_dispute_path_is_not_ready".to_string()]
        );
        assert!(
            declaration.limitations[0].contains("100000000 zhu"),
            "the Hub's own limitation text must survive the hop"
        );
        assert!(declaration.readiness_error.is_none());
    }

    /// A URL that could never be saved is refused with a reason, before any
    /// network call, rather than producing a confusing connection failure.
    #[tokio::test]
    async fn a_remote_plaintext_hub_url_is_refused_with_the_settings_layer_reason() {
        let declaration = hub_declaration("http://hub.example.com", "mainnet").await;
        assert!(!declaration.reachable);
        let error = declaration.error.expect("a reason");
        assert!(
            error.contains("must use HTTPS"),
            "expected the service-URL rule, got: {error}"
        );
    }

    /// A node on this same machine is the safest configuration and must not be
    /// the one turned away. Same reasoning as `validate_signing_node_url`.
    #[tokio::test]
    async fn a_loopback_http_hub_is_accepted() {
        let url = spawn_hub().await;
        assert!(url.starts_with("http://127.0.0.1:"));
        let declaration = hub_declaration(&url, "mainnet").await;
        assert!(declaration.reachable, "{:?}", declaration.error);
    }

    /// Off mainnet the readiness half is not asked for, and the reader is told
    /// that rather than shown an empty declaration that looks like a refusal.
    #[tokio::test]
    async fn testnet_does_not_claim_a_mainnet_readiness_answer() {
        let url = spawn_hub().await;
        let declaration = hub_declaration(&url, "testnet").await;
        assert!(declaration.reachable);
        assert!(!declaration.mainnet_checked);
        assert!(declaration.readiness_profile.is_none());
        assert!(declaration.blockers.is_empty());
    }

    /// Health answers and readiness does not: that is a different situation
    /// from an unreachable Hub and must not be reported as one.
    #[tokio::test]
    async fn a_hub_without_a_readiness_route_is_reachable_and_says_why() {
        let app = Router::new().route("/v1/health", get(|| async { Json(health_json()) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let declaration = hub_declaration(&format!("http://{addr}"), "mainnet").await;
        assert!(declaration.reachable);
        assert!(declaration.readiness_error.is_some());
        assert!(declaration.payments_enabled.is_none());
    }
}
