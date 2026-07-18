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
    pub hub_fee_mei: Option<f64>,
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
    let client = L2HubClient::new(&hub_url);
    match client.health().await {
        Ok(health)
            if health.ok
                && health.version >= 3
                && health.settlement_ready
                && health.cross_channel_ready
                && health.hub_fee_mei.unwrap_or(0.0).abs() <= f64::EPSILON =>
        {
            HubDiscoveryEntry {
                id,
                name: health
                    .name
                    .filter(|n| !n.is_empty())
                    .unwrap_or(fallback_name),
                hub_url,
                online: true,
                hub_address: health.hub_address.filter(|a| !a.is_empty()).or_else(|| {
                    preset.and_then(|p| {
                        (!p.hub_address.is_empty()).then(|| p.hub_address.to_string())
                    })
                }),
                hub_fee_mei: health.hub_fee_mei,
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
        let hub = L2HubClient::new(url.clone());
        match hub.health().await {
            Ok(h)
                if h.ok
                    && h.version >= 3
                    && h.settlement_ready
                    && h.cross_channel_ready
                    && h.hub_fee_mei.unwrap_or(0.0).abs() <= f64::EPSILON =>
            {
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

    if hub_url.is_some() && channel_id.is_none() {
        return Ok(FastPayStatus::needs_channel(
            "your provider",
            DEFAULT_CHANNEL_DEPOSIT_MEI,
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
