//! A RELAY THAT STOPPED, AND A SCREEN THAT WENT ON QUOTING ITS ADDRESS.
//!
//! # What was wrong
//!
//! `sync_managed_relay` binds the socket, spawns a task to serve it, and writes
//! down what it started: `managed` true, `bound` the address the kernel gave
//! back. Those two were what `relay_endpoint` answered `serving` with.
//!
//! They are a note about the past. The task can end on its own: `serve_router`
//! returning an error logs one line and exits, and a panic inside it ends just
//! as quietly. Neither touches the note. So after the relay stopped, the report
//! still said `serving: true` and still carried the `listen_addr` the Privacy
//! and Messages screens turn into "your wallet is serving a relay on ...",
//! beside an invitation to give that address to somebody. `idle_reason` stayed
//! null, because it was only ever filled in when the wallet was not configured
//! to host at all.
//!
//! The screens were already right about this shape: `relayReach` in
//! apps/desktop/src/relayReach.ts says "set to host a relay, but nothing is
//! listening" the moment `serving` goes false. It never went false.
//!
//! # What this run proves
//!
//! The relay is started through the press that starts it, and every answer is
//! read back through `wallet_relay_endpoint`, the command the screens call.
//!
//! 1. A relay that is serving reports its address, and the socket accepts a
//!    connection at that address.
//! 2. The serve task ends without telling anybody, and the report stops
//!    claiming an address. The socket is asked too, so this is a real dead
//!    relay rather than a bookkeeping change.
//! 3. It says why, in words, because a person who was shown that address needs
//!    to know it stopped meaning anything.
//! 4. Saving the settings again brings it back. That half matters: the save
//!    path has a cheap branch that swaps the address list on a relay it
//!    believes is already listening, and taking that branch on a dead relay
//!    would report success and leave the port shut.
//!
//! No chain is contacted: the node URL is a port nothing listens on. The relay
//! stays on loopback throughout.

#![cfg(feature = "desktop")]

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hacash_wallet_core::WalletService;
use serde_json::{Value, json};
use tauri::test::MockRuntime;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};
use wallet_tauri_common::AppState;

// ---------------------------------------------------------------------------
// One wallet's whole world. Same harness as
// `relay_bind_is_the_persons_choice.rs`, and for the same reason: a press has
// to enter where a press enters.
// ---------------------------------------------------------------------------

struct Shell {
    who: &'static str,
    root: PathBuf,
    app: tauri::App<MockRuntime>,
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
        app,
        webview,
    }
}

fn invoke(shell: &Shell, cmd: &str, args: Value) -> Value {
    enter(&shell.root);
    let outcome = tauri::test::get_ipc_response(
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
    .map(|body| body.deserialize::<Value>().expect("ipc response json"));
    match outcome {
        Ok(value) => value,
        Err(error) => panic!("{} invoked {cmd} and it failed: {error}", shell.who),
    }
}

/// The save press, followed by the read the screens do after it.
fn save(shell: &Shell, dust_whisper: Value) -> Value {
    invoke(
        shell,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": dust_whisper }),
    );
    report(shell)
}

/// What the screens are given.
fn report(shell: &Shell) -> Value {
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

/// Did a TCP connection to this address get accepted, within a second.
fn connects(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
}

/// The report, once the wallet stops claiming to be serving, or the last one it
/// gave before the deadline ran out.
///
/// Cancelling a task is not instant: the runtime has to take it. So this waits
/// rather than reading once, and a wallet that never stops claiming an address
/// arrives at the assertions below still claiming one.
fn report_once_not_serving(shell: &Shell) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let latest = report(shell);
        if field(&latest, "serving") == &json!(false) || Instant::now() >= deadline {
            return latest;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

#[test]
fn a_relay_that_stopped_is_not_reported_as_serving() {
    // A port with nothing on it. An accidental chain call fails loudly rather
    // than reaching a real node.
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let dir = tempfile::tempdir().expect("host dir");
    let root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&root).expect("wallet root");

    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let host = open_shell("the person hosting", &root, &node_url);
    let settings = json!({
        "enabled": true,
        "relay_urls": [own_url],
        "fallback_direct": false,
        "auto_start_relay": true,
        "relay_bind": "loopback",
    });

    // -- 1. Serving, and the address is real. -------------------------------
    println!("\n== 1. THE RELAY IS UP ==");
    let up = save(&host, settings.clone());
    println!("hosting                       {}", field(&up, "hosting"));
    println!("serving                       {}", field(&up, "serving"));
    println!("listen_addr                   {}", text(&up, "listen_addr"));
    println!("idle_reason                   {}", text(&up, "idle_reason"));
    assert_eq!(field(&up, "serving"), &json!(true));
    assert_eq!(text(&up, "listen_addr"), listen.to_string());
    assert_eq!(field(&up, "idle_reason"), &json!(null));
    assert!(
        connects(listen),
        "the relay is serving on the address it reported"
    );

    // -- 2. It stops, and nothing is told. ----------------------------------
    //
    // This is the state a returning `serve_router` leaves behind: the task
    // gone, the wallet's note of what it started untouched. It is staged
    // rather than provoked because a listening socket cannot be made to fail
    // on demand from outside the process.
    println!("\n== 2. THE SERVE TASK ENDS, AND NOBODY IS TOLD ==");
    assert!(
        host.app
            .state::<AppState>()
            .relay
            .stop_serving_and_tell_nobody(),
        "there was a serve task to end"
    );

    let down = report_once_not_serving(&host);
    println!("hosting                       {}", field(&down, "hosting"));
    println!("serving                       {}", field(&down, "serving"));
    println!(
        "listen_addr                   {}",
        text(&down, "listen_addr")
    );
    println!("lan_url                       {}", text(&down, "lan_url"));
    println!(
        "idle_reason                   {}",
        text(&down, "idle_reason")
    );

    // The socket is asked as well as the report, because a report that agrees
    // with a socket nobody tested is only a report that agrees with itself.
    let reachable = connects(listen);
    println!(
        "connect to {listen:<24} {}",
        if reachable { "accepted" } else { "refused" }
    );
    assert!(
        !reachable,
        "the relay really is gone: nothing accepts a connection on {listen}"
    );

    assert_eq!(
        field(&down, "serving"),
        &json!(false),
        "the wallet reported a relay as serving after its serve task had ended"
    );
    // The address does not outlive the thing serving it. This is the field a
    // screen invites somebody to hand to a friend.
    assert_eq!(field(&down, "listen_addr"), &json!(null));
    assert_eq!(field(&down, "lan_url"), &json!(null));
    assert_eq!(field(&down, "lan_addr"), &json!(null));

    // -- 3. And it says why. ------------------------------------------------
    //
    // The settings still say host, so `hosting` stays true, and the person is
    // owed the difference between "you turned this off" and "this stopped".
    assert_eq!(field(&down, "hosting"), &json!(true));
    let reason = text(&down, "idle_reason");
    assert_eq!(
        reason,
        wallet_tauri_common::desktop_relay::NOT_SERVING,
        "a wallet that is set to host and is serving nothing has to say so"
    );
    assert!(reason.contains("nothing is serving one"));

    // -- 4. Saving again brings it back. ------------------------------------
    //
    // `sync_managed_relay` has a branch that swaps the address list on a relay
    // it believes is already listening at this address and returns. Taking it
    // here would report a success that left the port shut, so the socket is
    // asked again afterwards.
    println!("\n== 4. SAVED AGAIN ==");
    let again = save(&host, settings);
    println!("serving                       {}", field(&again, "serving"));
    println!(
        "listen_addr                   {}",
        text(&again, "listen_addr")
    );
    assert_eq!(field(&again, "serving"), &json!(true));
    assert_eq!(text(&again, "listen_addr"), listen.to_string());
    assert_eq!(field(&again, "idle_reason"), &json!(null));
    assert!(
        connects(listen),
        "the save restarted the relay instead of patching the record of a dead one"
    );
}

/// The staged stop is a door into the wallet's own state, so it is held to
/// being a door only tests use. If the wallet itself ever ends a relay this
/// way, a relay stops for a person and nothing tells them.
#[test]
fn nothing_in_the_wallet_ends_the_relay_this_way() {
    const DOOR: &str = "stop_serving_and_tell_nobody";
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let shipped = [
        "crates/wallet-tauri-common/src",
        "apps/desktop/src-tauri/src",
        "apps/mobile/src-tauri/src",
    ];

    let mut callers: Vec<String> = Vec::new();
    for dir in shipped {
        let root = repo.join(dir);
        assert!(root.is_dir(), "{dir} is not where this test thinks it is");
        let mut pending = vec![root];
        while let Some(next) = pending.pop() {
            for entry in std::fs::read_dir(&next).expect("read a source directory") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read a source file");
                // The definition lives in one file and names itself in its own
                // doc comment. Every other mention is a caller.
                if source.contains(DOOR)
                    && path.file_name().and_then(|n| n.to_str()) != Some("desktop_relay.rs")
                {
                    callers.push(path.display().to_string());
                }
            }
        }
    }

    assert!(
        callers.is_empty(),
        "{DOOR} ends a relay and tells nobody. It is for tests. Called from: {callers:?}"
    );
}
