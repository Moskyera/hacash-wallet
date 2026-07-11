//! Fast Pay (L2) presets and user-facing status — hides channel/hub complexity from normal sends.

use serde::{Deserialize, Serialize};

use crate::channel::{query_channel, CHANNEL_STATUS_OPENING};
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
    /// On-chain address of the hub (right party). Empty = must come from hub `/v1/health`.
    pub hub_address: &'static str,
}

pub const CSP_PRESETS: &[CspPreset] = &[
    CspPreset {
        id: "local",
        name: "Local dev hub",
        hub_url: "http://127.0.0.1:8790",
        hub_address: "",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPayState {
    /// Hub healthy and channel open — instant sends available.
    Ready,
    /// Hub found but channel not opened yet.
    NeedsChannel,
    /// User configured a hub URL but it is unreachable.
    HubUnreachable,
    /// No hub configured and no preset responded.
    NoProvider,
}

impl FastPayState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsChannel => "needs_channel",
            Self::HubUnreachable => "hub_unreachable",
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
            message: "Fast Pay is ready — sends use instant low-fee routing.".into(),
            provider_name: Some(provider.into()),
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn needs_channel(provider: impl Into<String>, deposit: f64) -> Self {
        Self {
            state: FastPayState::NeedsChannel,
            message: format!(
                "One-time setup ({deposit} HAC deposit) unlocks instant Fast Pay. On-chain still works until then."
            ),
            provider_name: Some(provider.into()),
            hub_url: None,
            can_enable: true,
            default_deposit_mei: deposit,
        }
    }

    pub fn no_provider() -> Self {
        Self {
            state: FastPayState::NoProvider,
            message: "No Fast Pay provider online — your send will use the standard on-chain route."
                .into(),
            provider_name: None,
            hub_url: None,
            can_enable: false,
            default_deposit_mei: DEFAULT_CHANNEL_DEPOSIT_MEI,
        }
    }

    pub fn hub_unreachable() -> Self {
        Self {
            state: FastPayState::HubUnreachable,
            message: "Fast Pay provider is offline — using on-chain route for this send.".into(),
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

pub async fn discover_healthy_hub() -> Option<DiscoveredHub> {
    for preset in CSP_PRESETS {
        let client = L2HubClient::new(preset.hub_url);
        let health = client.health().await.ok()?;
        if !health.ok {
            continue;
        }
        let hub_address = health
            .hub_address
            .clone()
            .filter(|a| !a.is_empty())
            .or_else(|| {
                (!preset.hub_address.is_empty()).then(|| preset.hub_address.to_string())
            });
        return Some(DiscoveredHub {
            preset_id: preset.id.to_string(),
            name: health.name.unwrap_or_else(|| preset.name.to_string()),
            hub_url: preset.hub_url.to_string(),
            hub_address,
        });
    }
    None
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
        if hub.health().await.map(|h| h.ok).unwrap_or(false) {
            if let Ok(ch) = query_channel(node, ch_id).await {
                if channel_ready(&ch, user) {
                    let name = settings
                        .hub_right_address
                        .as_deref()
                        .map(|_| "your provider".to_string())
                        .or_else(|| Some("Fast Pay".into()));
                    return Ok(FastPayStatus::ready(name.unwrap_or_else(|| "Fast Pay".into())));
                }
            }
            return Ok(FastPayStatus::needs_channel(
                "your provider",
                DEFAULT_CHANNEL_DEPOSIT_MEI,
            ));
        }
        return Ok(FastPayStatus::hub_unreachable());
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
    if settings.hub_right_address.is_none() {
        if let Some(addr) = &discovered.hub_address {
            settings.hub_right_address = Some(addr.clone());
        }
    }
}

fn channel_ready(channel: &crate::channel::ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}

pub fn rail_label(rail: crate::payment::PaymentRail) -> &'static str {
    match rail {
        crate::payment::PaymentRail::L2Fast => "Instant (Fast Pay)",
        crate::payment::PaymentRail::L1OnChain => "Standard (on-chain)",
        crate::payment::PaymentRail::QuantumType4 => "Quantum",
    }
}

pub fn rail_detail(rail: crate::payment::PaymentRail) -> &'static str {
    match rail {
        crate::payment::PaymentRail::L2Fast => {
            "Settles in seconds with a very low fee via the payment network."
        }
        crate::payment::PaymentRail::L1OnChain => {
            "Broadcast to the Hacash mainnet — typically confirmed in a few minutes."
        }
        crate::payment::PaymentRail::QuantumType4 => "Post-quantum Type-4 transaction.",
    }
}