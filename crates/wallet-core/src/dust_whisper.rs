//! DUST Whisper settings and transaction submission routing.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::node::{NodeClient, SubmitTxResponse};
use crate::paths::wallet_data_root;
use dust_whisper::protocol::WhisperSettings as CoreWhisperSettings;

fn default_true() -> bool {
    true
}

/// Which addresses the wallet's own relay accepts connections on.
///
/// The wallet has always run a relay: `auto_start_relay` is on by default and
/// `desktop_relay::sync_managed_relay` binds and serves it. What it has never
/// had is a way to be reached, because the socket went to loopback and there
/// was no other option. This is that option, and it is a stored choice rather
/// than something inferred from a URL, so that widening the bind is always
/// something a person did.
///
/// `Loopback` binds `127.0.0.1`. No machine other than this one can open a
/// connection to it, including the machine of the person you are trying to
/// message.
///
/// `AllInterfaces` binds `0.0.0.0`: every network this computer is on. Whoever
/// can route to this computer can reach the relay, which is what makes hosting
/// for a friend possible and is also the whole of section 6 of
/// `docs/RUNNING-A-RELAY.md` becoming yours to keep.
///
/// There is deliberately no "LAN only" variant. The kernel binds an address,
/// not a trust boundary, and the only honest two answers it offers are this
/// machine and every interface. Who can actually reach an interface is a fact
/// about the network and the router, not about the bind, and the screen says
/// so rather than encoding a promise here that a socket cannot keep.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayBind {
    /// This machine only.
    #[default]
    Loopback,
    /// Every interface. Reachable by whoever can route here.
    AllInterfaces,
}

impl RelayBind {
    /// The host the managed relay binds for this choice.
    pub fn bind_host(self) -> &'static str {
        match self {
            RelayBind::Loopback => "127.0.0.1",
            RelayBind::AllInterfaces => "0.0.0.0",
        }
    }

    /// True when nothing outside this machine can open a connection.
    pub fn is_loopback_only(self) -> bool {
        matches!(self, RelayBind::Loopback)
    }
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
    /// Where that relay listens. Absent in every settings file written before
    /// this field existed, and absent from every payload a shell that does not
    /// offer the choice sends, so the default has to be the narrow one: an
    /// upgrade must never widen a socket on somebody's behalf.
    #[serde(default)]
    pub relay_bind: RelayBind,
    /// The OTHER people this wallet's own relay carries mail for.
    ///
    /// Other, because the wallet's own address is added to the list the relay
    /// actually enforces, in `desktop_relay::sync_managed_relay`, and is never
    /// stored here. So this field holds exactly the deliberate additions a
    /// person made, and an empty one - which is what `#[serde(default)]` gives
    /// every settings file written before this field existed - is a relay that
    /// serves its own owner and no other address at all.
    ///
    /// That is default deny, and it is the whole of the defence. Every other
    /// bound in the relay bounds volume, and free keypairs walk around all of
    /// them; a list of addresses is the one rule they cannot buy past. See
    /// `InboxAllowlist` in `crates/dust-whisper/src/messenger_relay.rs`.
    ///
    /// It changes nothing on the loopback bind, where nothing off this machine
    /// can open a connection in the first place, and everything on the wide
    /// bind, where the list is the only reason a neighbour gets nothing.
    #[serde(default)]
    pub relay_allowlist: Vec<String>,
}

impl Default for DustWhisperSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_urls: Vec::new(),
            fallback_direct: true,
            auto_start_relay: true,
            relay_bind: RelayBind::Loopback,
            relay_allowlist: Vec::new(),
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

/// The loopback relay URL this wallet is configured with, if any.
///
/// This is the URL the wallet uses to reach its own relay, and it is also the
/// only thing that makes the wallet host one at all
/// (`should_manage_relay`). A remote URL in the list is somebody else's relay
/// and never starts a listener here.
pub fn own_relay_url(settings: &DustWhisperSettings) -> Option<String> {
    settings
        .relay_urls
        .iter()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .find(|u| !u.is_empty() && is_local_relay_url(u))
}

/// The socket address the wallet's own relay binds, or `None` when this wallet
/// is not configured to host one.
///
/// The port is the one in the wallet's own loopback relay URL. The host comes
/// from `relay_bind` and from nowhere else. In particular a relay URL naming a
/// LAN or public host cannot widen the bind: it is not a local URL, so it does
/// not start a relay in the first place, and if a loopback URL sits beside it
/// the port is taken from that one and the host still comes from the setting.
pub fn managed_relay_listen_addr(settings: &DustWhisperSettings) -> Option<String> {
    let own = own_relay_url(settings)?;
    let port = managed_relay_port(&own)?;
    Some(format!("{}:{port}", settings.relay_bind.bind_host()))
}

/// The port of a relay URL, which is what the wallet binds.
pub fn managed_relay_port(relay_url: &str) -> Option<u16> {
    let listen = listen_addr_from_relay_url(relay_url)?;
    listen.rsplit(':').next()?.parse::<u16>().ok()
}

pub async fn relay_health(
    node: &NodeClient,
    settings: &DustWhisperSettings,
) -> Vec<RelayHealthStatus> {
    let mut rows = dust_whisper::check_relays_health(node.http(), &settings.relay_urls).await;
    for row in &mut rows {
        if !row.online {
            continue;
        }
        match row.node_url.as_deref() {
            Some(relay_node) if dust_whisper::node_urls_match(relay_node, node.base_url()) => {}
            Some(relay_node) => {
                row.online = false;
                row.error = Some(format!(
                    "Relay targets {relay_node}, but this wallet uses {}. Broadcast blocked.",
                    node.base_url()
                ));
            }
            None => {
                row.online = false;
                row.error =
                    Some("Relay did not declare its target node. Broadcast blocked.".into());
            }
        }
    }
    rows
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

    /// The allowlist as the relay reads it: trimmed, empty entries dropped,
    /// order and duplicates immaterial.
    ///
    /// Empty is open. Nothing here validates an entry: an address that is not
    /// claimable simply never matches, so a typo costs the person who typed it
    /// and can never silently open the relay to everybody.
    pub fn trimmed_relay_allowlist(&self) -> Vec<String> {
        let mut out = Vec::new();
        for a in &self.relay_allowlist {
            let t = a.trim().to_string();
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

/// The credential this machine's own relay asks for at its transaction door.
///
/// The relay key lives under the wallet data directory and is written by
/// whichever process started the relay; this reads it and derives the token
/// (`dust_whisper::relay::submit_token_from_secret`). `None` when there is no
/// key file, which is a machine with no relay of its own - a phone, or a
/// desktop that has never started one - and such a wallet has no local relay to
/// submit through anyway.
///
/// It is deliberately read on each submit rather than cached: a relay whose key
/// was replaced would otherwise be presented a token that stopped being right,
/// and the failure would look like a broken relay rather than a stale read.
fn local_submit_token() -> Option<String> {
    dust_whisper::relay::local_submit_token(&wallet_data_root().join("relay.key"))
}

pub async fn submit_tx_hex(
    node: &NodeClient,
    settings: &DustWhisperSettings,
    tx_hex: &str,
) -> WalletResult<SubmitTxResponse> {
    let core = settings.to_core();
    if core.enabled && !core.relay_urls.iter().any(|u| !u.trim().is_empty()) {
        return Err(WalletError::Node(
            // The field is empty by default because there is no public relay to
            // ship an address for. Saying only "configure one" leaves a person
            // who has never seen a relay with nowhere to go, so name where one
            // comes from: `dust-whisper-relay` in this repo, and the guide for
            // running it.
            "DUST Whisper enabled but no relay URL configured. Somebody has to run a relay, and it can be you: docs/RUNNING-A-RELAY.md".into(),
        ));
    }

    if core.enabled {
        match dust_whisper::submit_tx(
            node.http(),
            &core,
            node.base_url(),
            tx_hex,
            local_submit_token().as_deref(),
        )
        .await
        {
            Ok(result) => {
                return Ok(SubmitTxResponse {
                    ret: result.ret,
                    err: None,
                    message: None,
                    hash: result.hash,
                    ..SubmitTxResponse::default()
                });
            }
            Err(e) if settings.fallback_direct => {
                tracing::warn!(error = %e, "DUST Whisper failed, falling back to direct submit");
                let mut submitted = node.submit_tx_hex(tx_hex).await?;
                submitted.message = Some(format!(
                    "DUST Whisper failed ({e}); submitted directly to node."
                ));
                return Ok(submitted);
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

    fn hosting(relay_urls: &[&str], bind: RelayBind) -> DustWhisperSettings {
        DustWhisperSettings {
            enabled: true,
            relay_urls: relay_urls.iter().map(|u| (*u).to_string()).collect(),
            fallback_direct: false,
            auto_start_relay: true,
            relay_bind: bind,
            relay_allowlist: Vec::new(),
        }
    }

    #[test]
    fn a_wallet_that_never_chose_binds_loopback() {
        assert_eq!(
            DustWhisperSettings::default().relay_bind,
            RelayBind::Loopback
        );
        assert_eq!(
            managed_relay_listen_addr(&hosting(&["http://127.0.0.1:8787"], RelayBind::Loopback))
                .as_deref(),
            Some("127.0.0.1:8787")
        );
    }

    /// Every settings file written before `relay_bind` existed, and every save
    /// from a shell that does not offer the choice, arrives without the field.
    /// An upgrade must not widen a socket, so the missing field is loopback.
    #[test]
    fn settings_without_the_field_bind_loopback() {
        let older: DustWhisperSettings = serde_json::from_str(
            r#"{"enabled":true,"relay_urls":["http://127.0.0.1:8787"],
                "fallback_direct":false,"auto_start_relay":true}"#,
        )
        .expect("settings written before relay_bind existed still load");
        assert_eq!(older.relay_bind, RelayBind::Loopback);
        assert!(older.relay_bind.is_loopback_only());
        assert_eq!(
            managed_relay_listen_addr(&older).as_deref(),
            Some("127.0.0.1:8787")
        );
    }

    #[test]
    fn the_bind_widens_only_when_the_setting_says_so() {
        assert_eq!(
            managed_relay_listen_addr(&hosting(
                &["http://127.0.0.1:8787"],
                RelayBind::AllInterfaces
            ))
            .as_deref(),
            Some("0.0.0.0:8787")
        );
    }

    /// A relay URL is not a bind instruction. Naming a LAN or public host in
    /// the list points this wallet at somebody else's relay; it does not open
    /// a socket here, and it does not widen the one that is open.
    #[test]
    fn a_remote_url_never_widens_the_bind() {
        let remote_only = hosting(&["https://relay.example.org"], RelayBind::Loopback);
        assert_eq!(managed_relay_listen_addr(&remote_only), None);
        assert_eq!(own_relay_url(&remote_only), None);

        let both = hosting(
            &["https://relay.example.org", "http://127.0.0.1:8790"],
            RelayBind::Loopback,
        );
        assert_eq!(
            managed_relay_listen_addr(&both).as_deref(),
            Some("127.0.0.1:8790")
        );
    }

    /// The list is a restriction, so the absent field has to mean "no
    /// restriction", the same way the absent bind field has to mean loopback.
    /// An upgrade that silently narrowed somebody's running relay would stop
    /// their correspondent's mail with no screen having said anything.
    #[test]
    fn settings_without_the_allowlist_field_name_nobody() {
        let older: DustWhisperSettings = serde_json::from_str(
            r#"{"enabled":true,"relay_urls":["http://127.0.0.1:8787"],
                "fallback_direct":false,"auto_start_relay":true,"relay_bind":"all_interfaces"}"#,
        )
        .expect("settings written before relay_allowlist existed still load");
        assert!(older.relay_allowlist.is_empty());
        assert!(older.trimmed_relay_allowlist().is_empty());
        assert_eq!(older.relay_bind, RelayBind::AllInterfaces);
    }

    #[test]
    fn the_allowlist_is_trimmed_and_deduplicated_and_never_invented() {
        let mut s = hosting(&["http://127.0.0.1:8787"], RelayBind::AllInterfaces);
        s.relay_allowlist = vec![
            "  1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8 ".into(),
            String::new(),
            "   ".into(),
            "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8".into(),
            "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9".into(),
        ];
        assert_eq!(
            s.trimmed_relay_allowlist(),
            vec![
                "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8".to_string(),
                "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9".to_string(),
            ]
        );
        // Naming somebody does not move the socket, and it is not a substitute
        // for the bind choice either.
        assert_eq!(
            managed_relay_listen_addr(&s).as_deref(),
            Some("0.0.0.0:8787")
        );
    }

    #[test]
    fn reads_the_port_out_of_the_forms_the_field_accepts() {
        assert_eq!(managed_relay_port("http://127.0.0.1:8787"), Some(8787));
        assert_eq!(managed_relay_port("http://localhost:9001/"), Some(9001));
        assert_eq!(managed_relay_port("http://[::1]:8787"), Some(8787));
        // No port in the URL means the scheme's default, which is what the
        // wallet would then try to bind.
        assert_eq!(managed_relay_port("http://localhost"), Some(80));
    }
}
