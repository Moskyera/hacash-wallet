//! ONE OF YOU HOSTS: WHAT THE WALLET'S OWN RELAY IS ACTUALLY BOUND TO.
//!
//! # What was missing
//!
//! The desktop wallet has hosted a relay all along. `auto_start_relay` defaults
//! to on (`crates/wallet-core/src/dust_whisper.rs`) and
//! `desktop_relay::sync_managed_relay` binds the socket and serves it, which
//! `messenger_two_wallets_one_relay.rs` already runs two wallets through. So
//! the messenger never needed a third party: one of two people can host and the
//! other can point at them.
//!
//! Two things stopped that being a path a person could take, and both were
//! ours. No screen told anybody what address their own wallet was serving on.
//! And the socket went to loopback with no way to move it, so the address would
//! have been no use to a second machine anyway.
//!
//! This file is about the second one, and about the rule that comes with it:
//! **the bind is never wider than the person asked for.** A wider socket means
//! the relay accepts strangers and holds their metadata, which is the whole of
//! section 6 of `docs/RUNNING-A-RELAY.md` becoming the host's to keep. That is
//! a decision, so it is a stored setting, and this run is what proves nothing
//! else moves it.
//!
//! # What is real here
//!
//! * **The bind is moved by the press that moves it.** Every act enters
//!   `wallet_update_dust_whisper_settings_desktop` through Tauri IPC with the
//!   `{ dustWhisper }` payload `apps/desktop/src/api.ts` sends, and reads the
//!   result back through `wallet_relay_endpoint`, the command the Privacy and
//!   Messages screens call. Nothing here calls `sync_managed_relay` directly.
//!
//! * **The address is the kernel's answer, not ours.** `sync_managed_relay`
//!   records `TcpListener::local_addr()` after binding, and that is the field
//!   the report carries and the screen quotes.
//!
//! * **Reachability is tested by connecting**, from this machine's own network
//!   address rather than from loopback, which is the only way the difference
//!   between the two binds shows up at all.
//!
//! # What this run does open, briefly
//!
//! Act 3 asks for `0.0.0.0` and therefore binds every interface on this
//! machine, on one ephemeral port, for the length of that act. That is the
//! thing being tested: a person asked for it here, in the payload, exactly as a
//! person asks for it on the screen. Act 4 puts it back on loopback and proves
//! the socket moved back.
//!
//! No chain is contacted. Every shell's node URL points at a port nothing
//! listens on.

#![cfg(feature = "desktop")]

use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hacash_wallet_core::WalletService;
use serde_json::{Value, json};
use tauri::test::MockRuntime;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};
use wallet_tauri_common::AppState;

// ---------------------------------------------------------------------------
// One wallet's whole world. Same harness as
// `messenger_two_wallets_one_relay.rs`, and for the same reason: a press has to
// enter where a press enters.
// ---------------------------------------------------------------------------

struct Shell {
    who: &'static str,
    root: PathBuf,
    _app: tauri::App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
}

/// `wallet_data_root` reads the process environment on every call, so the root
/// is set before each entrance rather than held on the service.
fn enter(root: &Path) {
    // SAFETY: single-threaded test flow, one shell.
    unsafe { std::env::set_var("HACASH_WALLET_DATA", root) };
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn open_shell(who: &'static str, root: &Path, node_url: &str) -> Shell {
    enter(root);
    let mut service =
        WalletService::new(Some(node_url.to_string()), None).expect("wallet service on this root");
    service.warm_vault_cache().expect("warm vault cache");
    let app = tauri::test::mock_builder()
        .invoke_handler(tauri::generate_handler![
            wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop,
            wallet_tauri_common::desktop_commands::wallet_relay_endpoint,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("build the wallet application");
    app.manage(AppState::new(service));
    let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("webview");
    Shell {
        who,
        root: root.to_path_buf(),
        _app: app,
        webview,
    }
}

fn try_invoke(shell: &Shell, cmd: &str, args: Value) -> Result<Value, Value> {
    enter(&shell.root);
    tauri::test::get_ipc_response(
        &shell.webview,
        tauri::webview::InvokeRequest {
            cmd: cmd.into(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            url: if cfg!(any(windows, target_os = "android")) {
                "http://tauri.localhost"
            } else {
                "tauri://localhost"
            }
            .parse()
            .expect("ipc url"),
            body: tauri::ipc::InvokeBody::Json(args),
            headers: Default::default(),
            invoke_key: tauri::test::INVOKE_KEY.to_string(),
        },
    )
    .map(|body| body.deserialize::<Value>().expect("ipc response json"))
}

fn invoke(shell: &Shell, cmd: &str, args: Value) -> Value {
    match try_invoke(shell, cmd, args) {
        Ok(value) => value,
        Err(error) => panic!("{} invoked {cmd} and it failed: {error}", shell.who),
    }
}

/// The save press. `dust_whisper` is passed through as given so each act can
/// send exactly the payload it means to, including the one that predates the
/// bind setting and therefore does not carry it.
fn save(shell: &Shell, dust_whisper: Value) -> Value {
    invoke(
        shell,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": dust_whisper }),
    );
    invoke(shell, "wallet_relay_endpoint", json!({}))
}

fn field<'a>(report: &'a Value, key: &str) -> &'a Value {
    report
        .get(key)
        .unwrap_or_else(|| panic!("report has {key}"))
}

fn text(report: &Value, key: &str) -> String {
    field(report, key).as_str().unwrap_or("null").to_string()
}

/// This machine's address on its own network, asked of the routing table.
///
/// Same question `desktop_relay::route_local_address` asks, and asked the same
/// way: a UDP socket connected to the RFC 5737 documentation range, which puts
/// no packet on the wire and contacts nothing. Here it is used to get an
/// address that is NOT loopback to attempt connections against, because the
/// difference between the two binds is invisible from `127.0.0.1`.
fn route_local_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("203.0.113.1:9").ok()?;
    let addr = socket.local_addr().ok()?.ip();
    if addr.is_loopback() || addr.is_unspecified() {
        return None;
    }
    Some(addr)
}

/// Did a TCP connection to this address get accepted, within a second.
fn connects(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

#[test]
fn the_relay_binds_where_the_person_asked_and_nowhere_wider() {
    // A port with nothing on it. An accidental chain call fails loudly rather
    // than reaching a real node.
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let dir = tempfile::tempdir().expect("host dir");
    let root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&root).expect("wallet root");

    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    let host = open_shell("the person hosting", &root, &node_url);

    let route = route_local_address();
    println!("\n== THE MACHINE ==");
    match route {
        Some(ip) => println!("this machine on its network   {ip}"),
        None => println!("this machine on its network   none found, the network acts are skipped"),
    }

    // -- 1. The payload that predates the setting. --------------------------
    //
    // Every settings file written before `relay_bind` existed, and every save
    // from a shell that does not offer the choice, looks exactly like this. An
    // upgrade must not widen anybody's socket, so this has to land on loopback.
    println!("\n== 1. A SAVE THAT NEVER MENTIONS THE BIND ==");
    let report = save(
        &host,
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
        }),
    );
    println!("payload                       no relay_bind field at all");
    println!(
        "serving                       {}",
        field(&report, "serving")
    );
    println!(
        "listen_addr                   {}",
        text(&report, "listen_addr")
    );
    println!("bind                          {}", text(&report, "bind"));
    println!(
        "loopback_only                 {}",
        field(&report, "loopback_only")
    );
    println!("own_url                       {}", text(&report, "own_url"));
    println!("lan_url                       {}", text(&report, "lan_url"));
    assert_eq!(field(&report, "serving"), &json!(true));
    assert_eq!(text(&report, "listen_addr"), format!("127.0.0.1:{port}"));
    assert_eq!(text(&report, "bind"), "loopback");
    assert_eq!(field(&report, "loopback_only"), &json!(true));
    // Nothing to hand a friend, so nothing is offered. A relay on loopback has
    // no shareable address and printing one would be the lie the screen exists
    // to stop.
    assert_eq!(field(&report, "lan_url"), &json!(null));
    assert!(
        connects(format!("127.0.0.1:{port}").parse().expect("addr")),
        "the relay is serving on this machine"
    );

    // -- 2. "Only this machine" is a claim, so it gets tested. --------------
    if let Some(ip) = route {
        println!("\n== 2. WHO CAN REACH A LOOPBACK RELAY ==");
        let from_network = SocketAddr::new(ip, port);
        let reached = connects(from_network);
        println!(
            "connect to {from_network:<24} {}",
            if reached { "accepted" } else { "refused" }
        );
        assert!(
            !reached,
            "a loopback relay must not accept a connection to this machine's network address"
        );
    }

    // -- 3. The person asks for it, in the payload, and the socket moves. ----
    println!("\n== 3. THE SAME WALLET, ASKED TO ACCEPT OTHER MACHINES ==");
    let report = save(
        &host,
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "all_interfaces",
        }),
    );
    println!("payload                       relay_bind: all_interfaces");
    println!(
        "listen_addr                   {}",
        text(&report, "listen_addr")
    );
    println!("bind                          {}", text(&report, "bind"));
    println!(
        "loopback_only                 {}",
        field(&report, "loopback_only")
    );
    println!(
        "lan_addr                      {}",
        text(&report, "lan_addr")
    );
    println!("lan_url                       {}", text(&report, "lan_url"));
    assert_eq!(text(&report, "listen_addr"), format!("0.0.0.0:{port}"));
    assert_eq!(text(&report, "bind"), "all_interfaces");
    assert_eq!(field(&report, "loopback_only"), &json!(false));
    if let Some(ip) = route {
        assert_eq!(text(&report, "lan_addr"), ip.to_string());
        assert_eq!(text(&report, "lan_url"), format!("http://{ip}:{port}"));
        let from_network = SocketAddr::new(ip, port);
        let reached = connects(from_network);
        println!(
            "connect to {from_network:<24} {}",
            if reached { "accepted" } else { "refused" }
        );
        assert!(
            reached,
            "a relay bound to every interface accepts a connection to this machine's network address"
        );
    }

    // -- 4. And it goes back. -----------------------------------------------
    println!("\n== 4. PUT BACK ==");
    let report = save(
        &host,
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
        }),
    );
    println!(
        "listen_addr                   {}",
        text(&report, "listen_addr")
    );
    println!(
        "loopback_only                 {}",
        field(&report, "loopback_only")
    );
    assert_eq!(text(&report, "listen_addr"), format!("127.0.0.1:{port}"));
    assert_eq!(field(&report, "loopback_only"), &json!(true));
    if let Some(ip) = route {
        let from_network = SocketAddr::new(ip, port);
        let reached = connects(from_network);
        println!(
            "connect to {from_network:<24} {}",
            if reached { "accepted" } else { "refused" }
        );
        assert!(!reached, "the socket moved back");
    }

    // -- 5. A URL is not a bind instruction. --------------------------------
    //
    // The obvious way to get this wrong is to widen the socket because a URL
    // in the list names a public host. That URL is somebody else's relay: it
    // is what this wallet talks to, not what this wallet serves.
    println!("\n== 5. A PUBLIC URL IN THE LIST ==");
    let report = save(
        &host,
        json!({
            "enabled": true,
            "relay_urls": ["https://relay.example.org", own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
        }),
    );
    println!("relay_urls                    https://relay.example.org, {own_url}");
    println!(
        "listen_addr                   {}",
        text(&report, "listen_addr")
    );
    println!("own_url                       {}", text(&report, "own_url"));
    assert_eq!(text(&report, "listen_addr"), format!("127.0.0.1:{port}"));
    assert_eq!(text(&report, "own_url"), own_url);

    // -- 6. Not hosting says so, and says why. ------------------------------
    println!("\n== 6. AUTO-START OFF ==");
    let report = save(
        &host,
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": false,
            "relay_bind": "loopback",
        }),
    );
    println!(
        "hosting                       {}",
        field(&report, "hosting")
    );
    println!(
        "serving                       {}",
        field(&report, "serving")
    );
    println!(
        "listen_addr                   {}",
        text(&report, "listen_addr")
    );
    println!(
        "idle_reason                   {}",
        text(&report, "idle_reason")
    );
    assert_eq!(field(&report, "hosting"), &json!(false));
    assert_eq!(field(&report, "serving"), &json!(false));
    // The address does not outlive the listener. A stale address on the screen
    // is an address somebody hands out for a relay that is not running.
    assert_eq!(field(&report, "listen_addr"), &json!(null));
    assert!(text(&report, "idle_reason").contains("Auto-start is off"));
    assert!(
        !connects(format!("127.0.0.1:{port}").parse().expect("addr")),
        "nothing is listening once the wallet stops hosting"
    );
}

/// The screens call these two commands by these two names, and the desktop
/// shell registers them. If any of the three drifts, the address a person is
/// shown stops being the address the wallet is serving on.
#[test]
fn the_endpoint_the_screens_read_is_the_endpoint_the_shell_registers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |relative: &str| {
        std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"))
    };

    let api = read("apps/desktop/src/api.ts");
    assert!(
        api.contains("wallet_relay_endpoint"),
        "the desktop api invokes wallet_relay_endpoint"
    );

    let shell = read("apps/desktop/src-tauri/src/lib.rs");
    assert!(
        shell.contains("desktop_commands::wallet_relay_endpoint"),
        "the desktop shell registers wallet_relay_endpoint"
    );

    // The allowlist is checked in full by `acl_inventory.rs`; this is the one
    // entry this file's command depends on.
    let acl = read("apps/desktop/src-tauri/permissions/wallet.toml");
    assert!(
        acl.contains("\"wallet_relay_endpoint\""),
        "wallet_relay_endpoint is in the desktop allowlist"
    );
}
