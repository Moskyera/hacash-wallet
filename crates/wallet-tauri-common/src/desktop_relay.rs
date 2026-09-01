//! Desktop-only managed DUST Whisper relay process.
//!
//! The wallet has hosted a relay since `auto_start_relay` was added, and it
//! defaults to on. What this module now also answers is the question a person
//! has to be able to answer before that is any use to them: what address is my
//! wallet serving on, and can anybody else reach it. See `relay_endpoint`.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

use hacash_wallet_core::dust_whisper::{
    DustWhisperSettings, RelayBind, is_local_relay_url, managed_relay_listen_addr,
    managed_relay_port, own_relay_url,
};
use hacash_wallet_core::paths::wallet_data_root;
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};

use crate::state::AppState;

pub struct RelayProcess {
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    managed: Mutex<bool>,
    /// What the socket is actually bound to, read back from the listener
    /// rather than from the settings that asked for it. The screen quotes
    /// this, so it has to be the kernel's answer and not our intention.
    bound: Mutex<Option<SocketAddr>>,
    /// THE RUNNING RELAY'S OWN STORE AND ITS OWN LIST.
    ///
    /// Held here for two reasons, both of which were bugs.
    ///
    /// The list the screen showed used to be recomputed from settings beside
    /// the relay, while the list the socket enforced was frozen at the last
    /// restart. `wallet_create` and `wallet_reset` change the owner address and
    /// restarted nothing, so after a reset the screen said "this relay will
    /// carry mail for nobody" while the socket was still carrying mail for the
    /// deleted wallet's address. The screen must quote what is being enforced,
    /// so it reads the list off this.
    ///
    /// And the store used to be rebuilt on every sync, which threw away every
    /// undelivered envelope on the relay - on a save that changed nothing, and
    /// on an automatic node failover that was not a press at all. Keeping the
    /// inbox means a list change swaps the rule and touches nothing else, and
    /// even a rebind carries the mail across.
    inbox: Mutex<Option<std::sync::Arc<dust_whisper::messenger_relay::MessengerInbox>>>,
    /// What the running relay forwards transactions to. A change here is the
    /// one thing that genuinely needs the relay rebuilt.
    node_url: Mutex<Option<String>>,
}

impl RelayProcess {
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
            managed: Mutex::new(false),
            bound: Mutex::new(None),
            inbox: Mutex::new(None),
            node_url: Mutex::new(None),
        }
    }
}

impl Default for RelayProcess {
    fn default() -> Self {
        Self::new()
    }
}

pub fn stop_managed_relay(state: &AppState) -> Result<(), String> {
    let managed = *state.relay.managed.lock().map_err(|e| e.to_string())?;
    if !managed {
        // Nothing of ours is listening either way, so the address the screen
        // shows must not survive a stop that found nothing to stop, and neither
        // must the list it was enforcing.
        *state.relay.bound.lock().map_err(|e| e.to_string())? = None;
        *state.relay.inbox.lock().map_err(|e| e.to_string())? = None;
        *state.relay.node_url.lock().map_err(|e| e.to_string())? = None;
        return Ok(());
    }
    if let Some(task) = state.relay.task.lock().map_err(|e| e.to_string())?.take() {
        task.abort();
    }
    *state.relay.managed.lock().map_err(|e| e.to_string())? = false;
    *state.relay.bound.lock().map_err(|e| e.to_string())? = None;
    *state.relay.inbox.lock().map_err(|e| e.to_string())? = None;
    *state.relay.node_url.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}

/// Stop the relay, but keep its store so a rebind does not lose anybody's mail.
fn stop_but_keep_the_mail(
    state: &AppState,
) -> Result<Option<std::sync::Arc<dust_whisper::messenger_relay::MessengerInbox>>, String> {
    let held = state.relay.inbox.lock().map_err(|e| e.to_string())?.clone();
    stop_managed_relay(state)?;
    Ok(held)
}

/// Generic over the runtime so the relay start is reachable outside a real
/// window server. See `wallet_update_dust_whisper_settings_desktop`.
pub async fn sync_managed_relay<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let state = app.state::<AppState>();

    let (settings, node_url, own_address) = {
        let mut svc = state.inner.lock().await;
        let status = svc.status();
        (svc.dust_whisper_settings(), status.node_url, status.address)
    };

    if !should_manage_relay(&settings) {
        stop_managed_relay(&state)?;
        return Ok(());
    }

    let local_url = own_relay_url(&settings)
        .ok_or_else(|| "No local relay URL configured for auto-start".to_string())?;

    // Who the relay is for, and nobody else. Composed here and only here:
    // this wallet's own address, so a host is never locked out of the relay
    // running on their own computer, plus the addresses the person deliberately
    // typed. Nothing infers an entry from anything - not from the relay URL
    // list, not from who has messaged before, not from the network - so every
    // address this relay will answer for is one somebody chose.
    //
    // A settings file with an empty list is therefore a relay that serves one
    // person, the owner. That is what an upgrade lands on, and it exposes
    // nobody.
    let served = served_addresses(own_address.as_deref(), &settings);
    let allowlist = dust_whisper::messenger_relay::InboxAllowlist::from_addresses(&served);

    // The port is the one in the wallet's own relay URL; the host is the
    // stored bind choice and nothing else. `managed_relay_listen_addr` is the
    // only place either is decided, and it is unit tested against a URL that
    // names a public host.
    let listen = managed_relay_listen_addr(&settings)
        .ok_or_else(|| format!("Invalid relay listen address in {local_url}"))?;

    // THE CHEAP PATH, WHICH IS ALSO THE ONE THAT KEEPS THE MAIL.
    //
    // If a relay of ours is already listening where this one would listen and
    // forwarding to the same node, nothing needs rebuilding: swap the address
    // list on the running relay and return. That makes a save which changes
    // nothing change nothing, instead of dropping every undelivered envelope
    // on the relay, and it makes a list change take effect on the very next
    // request rather than after a rebind.
    {
        let already_bound = *state.relay.bound.lock().map_err(|e| e.to_string())?;
        let same_node = state
            .relay
            .node_url
            .lock()
            .map_err(|e| e.to_string())?
            .as_deref()
            == Some(node_url.as_str());
        let running = state.relay.inbox.lock().map_err(|e| e.to_string())?.clone();
        if let (Some(bound), true, Some(inbox)) = (already_bound, same_node, running)
            && bound.to_string() == listen
        {
            inbox.set_allowlist(allowlist);
            tracing::info!(%bound, serves = served.len(), "updated the embedded DUST Whisper relay's address list in place");
            return Ok(());
        }
    }

    let carried = stop_but_keep_the_mail(&state)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let key_file = wallet_data_root().join("relay.key");
    let secret = dust_whisper::relay::load_or_create_secret_key(&key_file)?;
    let socket: SocketAddr = listen
        .parse()
        .map_err(|error| format!("Invalid relay listen address {listen}: {error}"))?;
    let listener = tokio::net::TcpListener::bind(socket)
        .await
        .map_err(|error| {
            format!(
                "Cannot start the local DUST relay at {listen}. The port is already in use: {error}"
            )
        })?;
    // Read back from the listener, not from `listen`. This is the address the
    // relay is on, and the screen quotes it.
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let relay_state = dust_whisper::relay::relay_state_from_secret(secret, node_url.clone());
    // The store the last relay was using, if there was one, so a rebind carries
    // undelivered mail across instead of discarding it.
    let inbox = carried.unwrap_or_else(|| {
        std::sync::Arc::new(dust_whisper::messenger_relay::MessengerInbox::default())
    });
    inbox.set_allowlist(allowlist);
    // Both doors, stated together. The transaction path is not widened by the
    // address list and is not widened by the bind: it stays on this machine,
    // and a caller on this machine still has to hold the relay's own submit
    // token. See `dust_whisper::relay::SubmitAccess`.
    let submit = dust_whisper::relay::SubmitAccess::ThisMachineOnly;
    tracing::info!(
        %bound,
        %node_url,
        serves = served.len(),
        "starting embedded DUST Whisper relay"
    );
    if !bound.ip().is_loopback() {
        tracing::info!(
            %bound,
            serves = served.len(),
            "the embedded DUST Whisper relay is bound to a non loopback address and carries mail only for the addresses its operator listed. It forwards transactions only from this machine"
        );
    }
    let app = dust_whisper::relay::build_router_with_inbox(relay_state, inbox.clone(), submit);
    let task = tauri::async_runtime::spawn(async move {
        if let Err(error) = dust_whisper::relay::serve_router(listener, app).await {
            tracing::error!(%error, "embedded DUST Whisper relay stopped");
        }
    });

    *state.relay.task.lock().map_err(|e| e.to_string())? = Some(task);
    *state.relay.managed.lock().map_err(|e| e.to_string())? = true;
    *state.relay.bound.lock().map_err(|e| e.to_string())? = Some(bound);
    *state.relay.inbox.lock().map_err(|e| e.to_string())? = Some(inbox);
    *state.relay.node_url.lock().map_err(|e| e.to_string())? = Some(node_url.clone());

    tokio::time::sleep(Duration::from_millis(600)).await;
    Ok(())
}

/// What this wallet is serving, and who could possibly reach it.
///
/// Every field is a fact the wallet holds. `listen_addr` is what the kernel
/// said the socket is bound to. `lan_url` is a candidate address to hand
/// somebody, offered only once the bind is wide enough for it to mean
/// anything, and it is a candidate rather than a promise: see
/// `route_local_address`. Nothing here says a friend will be able to connect,
/// because nothing here knows that. The router does.
#[derive(Debug, Clone, Serialize)]
pub struct RelayEndpointReport {
    /// The wallet is configured to host a relay: whisper on, auto-start on,
    /// and a loopback URL of its own in the list.
    pub hosting: bool,
    /// A socket is bound and being served right now.
    pub serving: bool,
    /// The bound address, from the listener. `None` when nothing is serving.
    pub listen_addr: Option<String>,
    /// The stored bind choice, `loopback` or `all_interfaces`.
    pub bind: RelayBind,
    /// Nothing off this machine can open a connection to it.
    pub loopback_only: bool,
    /// The port the wallet's own relay URL names.
    pub port: Option<u16>,
    /// The wallet's own relay URL: how this wallet reaches its own relay.
    pub own_url: Option<String>,
    /// This computer's address on its network, when it has one and the bind
    /// is wide enough for the address to be worth giving out.
    pub lan_addr: Option<String>,
    /// That address as a relay URL, which is the string a friend pastes.
    pub lan_url: Option<String>,
    /// Why nothing is being hosted, when nothing is.
    pub idle_reason: Option<String>,
    /// The addresses the person deliberately added, exactly as stored. This
    /// does NOT include the wallet's own address: see `served_addresses`.
    pub allowlist: Vec<String>,
    /// This wallet's own address, which its own relay always carries mail for.
    /// `None` when no wallet is loaded, in which case the relay serves only
    /// whatever was typed, and if nothing was typed, nobody.
    pub own_address: Option<String>,
    /// Every address this relay will answer for, which is the owner plus the
    /// additions. Anybody not on this list gets nothing on every route: they
    /// cannot post, cannot be posted to, cannot obtain a mailbox challenge,
    /// cannot collect, cannot acknowledge and are not in the key directory.
    ///
    /// This is the list the screen must quote, because it is the one the relay
    /// enforces.
    pub served_addresses: Vec<String>,
    /// True when this relay would carry mail for no address at all, which is
    /// what a wallet with no account loaded and nothing typed amounts to.
    pub serves_nobody: bool,
    /// Who may push a transaction through this relay to this wallet's node.
    /// Always this machine only, and stated because a person who opened a
    /// message relay must not be left guessing whether they also opened this.
    pub transaction_reach: String,
    /// Every relay URL this wallet is configured with, in the order a send
    /// walks them.
    ///
    /// The screen needs the ORDER, not just the set: `messenger_send` stops at
    /// the first relay that accepts, while polling tries every one. A list with
    /// this wallet's own relay above somebody else's therefore delivers every
    /// outgoing message into this machine's own mailbox, where the other person
    /// cannot collect it, while their replies still arrive through the second
    /// relay - so the thread looks alive and only one direction of it is.
    pub relay_urls: Vec<String>,
}

/// Build the report from the settings and the live listener.
pub async fn relay_endpoint<R: Runtime>(app: &AppHandle<R>) -> Result<RelayEndpointReport, String> {
    let state = app.state::<AppState>();
    let (settings, own_address) = {
        let mut svc = state.inner.lock().await;
        let address = svc.status().address;
        (svc.dust_whisper_settings(), address)
    };
    let bound = *state.relay.bound.lock().map_err(|e| e.to_string())?;
    let serving = *state.relay.managed.lock().map_err(|e| e.to_string())? && bound.is_some();
    let hosting = should_manage_relay(&settings);
    let own_url = own_relay_url(&settings);
    let port = own_url.as_deref().and_then(managed_relay_port);

    // Only offered when the socket is actually wide. On loopback there is no
    // address to give anybody, and printing one would be the exact lie this
    // screen exists to stop.
    let (lan_addr, lan_url) = match (serving, settings.relay_bind, port) {
        (true, RelayBind::AllInterfaces, Some(port)) => match route_local_address() {
            Some(ip) => (Some(ip.to_string()), Some(format!("http://{ip}:{port}"))),
            None => (None, None),
        },
        _ => (None, None),
    };

    let idle_reason = if hosting {
        None
    } else if !settings.enabled {
        Some("DUST Whisper is off, so this wallet is not hosting a relay.".to_string())
    } else if !settings.auto_start_relay {
        Some(
            "Auto-start is off, so this wallet is not hosting a relay even though a relay address of its own is configured."
                .to_string(),
        )
    } else if own_url.is_none() {
        Some(
            "No relay address on this computer is configured, so this wallet is not hosting one."
                .to_string(),
        )
    } else {
        Some("This wallet is not hosting a relay.".to_string())
    };

    let served = served_addresses(own_address.as_deref(), &settings);
    Ok(RelayEndpointReport {
        allowlist: settings.trimmed_relay_allowlist(),
        serves_nobody: served.is_empty(),
        served_addresses: served,
        own_address,
        transaction_reach: TRANSACTION_REACH.to_string(),
        relay_urls: settings.trimmed_relay_urls(),
        hosting,
        serving,
        listen_addr: bound.map(|addr| addr.to_string()),
        bind: settings.relay_bind,
        loopback_only: bound
            .map(|addr| addr.ip().is_loopback())
            .unwrap_or_else(|| settings.relay_bind.is_loopback_only()),
        port,
        own_url,
        lan_addr,
        lan_url,
        idle_reason,
    })
}

/// The address this computer uses to reach other machines on its network, or
/// `None` when it has none to offer.
///
/// A relay bound to `0.0.0.0` is bound to every interface, and `0.0.0.0` is
/// not an address anybody can connect to. So the wallet asks the operating
/// system which local address a datagram leaving this machine would carry.
/// `UdpSocket::connect` sets a default peer and picks a route; it sends no
/// packet and contacts nothing, and the address it is pointed at is the
/// documentation range reserved by RFC 5737, which is routed nowhere.
///
/// It is a candidate and the screen calls it one. It is the address of the
/// default route's interface, so a machine on several networks has others;
/// DHCP can hand this machine a different one tomorrow; and none of it says
/// whether anything between here and your friend will let a connection
/// through.
fn route_local_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("203.0.113.1:9").ok()?;
    let addr = socket.local_addr().ok()?.ip();
    if addr.is_loopback() || addr.is_unspecified() {
        return None;
    }
    Some(addr)
}

/// The transaction path, in the words the screen uses.
///
/// Held as a constant beside the code that sets `SubmitAccess::LoopbackOnly`,
/// so the sentence and the rule move together.
pub const TRANSACTION_REACH: &str = "Transactions are not relayed for anybody else. This relay forwards a transaction to your fullnode only when it was submitted from this computer by something that can read this relay's own key file, whatever the bind is set to and whoever is on the address list. Another machine that tries is refused before its payload is even read, and that stays true behind a reverse proxy, where every caller in the world would otherwise look like this computer.";

/// Every address the embedded relay will carry mail for.
///
/// The owner first, then the deliberate additions, trimmed and deduplicated,
/// order preserved so the screen can show it back in the shape it was typed.
/// An empty result is a relay that serves nobody, and that is a real state: a
/// wallet with no account loaded and nothing typed.
pub fn served_addresses(own_address: Option<&str>, settings: &DustWhisperSettings) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |candidate: &str| {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    };
    if let Some(own) = own_address {
        push(own);
    }
    for listed in settings.trimmed_relay_allowlist() {
        push(&listed);
    }
    out
}

fn should_manage_relay(settings: &DustWhisperSettings) -> bool {
    cfg!(not(any(target_os = "android", target_os = "ios")))
        && settings.enabled
        && settings.auto_start_relay
        && settings.relay_urls.iter().any(|u| is_local_relay_url(u))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(listed: &[&str]) -> DustWhisperSettings {
        DustWhisperSettings {
            relay_allowlist: listed.iter().map(|a| a.to_string()).collect(),
            ..DustWhisperSettings::default()
        }
    }

    /// THE DEFAULT, WHICH IS THE STATE NOBODY CHOSE.
    ///
    /// A settings file written before `relay_allowlist` existed has an empty
    /// one, and so does a wallet whose owner has never opened the box. That
    /// state has to serve the owner and nobody else, because it is the state a
    /// person is in when they have made no decision, and the only safe thing to
    /// do with a decision nobody made is nothing.
    #[test]
    fn nothing_typed_serves_the_owner_and_nobody_else() {
        assert_eq!(
            served_addresses(Some("1Owner"), &settings(&[])),
            vec!["1Owner".to_string()]
        );
    }

    /// And with no wallet loaded there is nobody at all, which is a relay that
    /// refuses everybody including itself. That is a relay that does not work,
    /// and it is the right way for this to fail: the alternative to "serves
    /// nobody" is "serves everybody".
    #[test]
    fn no_wallet_and_nothing_typed_serves_nobody() {
        assert!(served_addresses(None, &settings(&[])).is_empty());
        assert!(
            dust_whisper::messenger_relay::InboxAllowlist::from_addresses(served_addresses(
                None,
                &settings(&[])
            ))
            .serves_nobody()
        );
    }

    /// The owner is added, not required. Somebody who types their own address
    /// does not get it twice, and somebody who does not type it is not locked
    /// out of the relay running on their own computer.
    #[test]
    fn the_owner_is_first_and_never_duplicated() {
        assert_eq!(
            served_addresses(Some("1Owner"), &settings(&["1Friend"])),
            vec!["1Owner".to_string(), "1Friend".to_string()]
        );
        assert_eq!(
            served_addresses(
                Some("1Owner"),
                &settings(&["1Owner", "1Friend", " 1Friend "])
            ),
            vec!["1Owner".to_string(), "1Friend".to_string()]
        );
        assert_eq!(
            served_addresses(Some(" 1Owner "), &settings(&["  ", ""])),
            vec!["1Owner".to_string()]
        );
    }

    /// Nothing invents an entry. The list is what a person typed plus the
    /// owner, and there is no path from a relay URL, a past correspondent or a
    /// network to a name on it.
    #[test]
    fn nothing_but_the_owner_and_what_was_typed_reaches_the_list() {
        let mut with_urls = settings(&["1Friend"]);
        with_urls.relay_urls = vec![
            "http://127.0.0.1:8787".to_string(),
            "http://192.168.1.24:8787".to_string(),
        ];
        assert_eq!(
            served_addresses(Some("1Owner"), &with_urls),
            vec!["1Owner".to_string(), "1Friend".to_string()]
        );
    }

    /// The sentence the screen shows about transactions has to be the one the
    /// code enforces, so it lives beside the code that sets the rule.
    #[test]
    fn the_transaction_sentence_says_what_the_rule_says() {
        assert!(TRANSACTION_REACH.contains("only when it was submitted from this computer"));
        assert!(
            TRANSACTION_REACH.contains("key file"),
            "the sentence does not mention the credential the rule actually wants"
        );
        assert!(TRANSACTION_REACH.contains("refused"));
        assert_eq!(
            dust_whisper::relay::SubmitAccess::default(),
            dust_whisper::relay::SubmitAccess::ThisMachineOnly,
            "the default stopped being loopback only, and the screen still says it is"
        );
    }
}
