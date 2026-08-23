//! ADVERSARIAL PROBE, KEPT AS THE REGRESSION TEST: THE LIST ON THE SCREEN AND
//! THE LIST IN THE SOCKET.
//!
//! Written by a reviewer against the behaviour that shipped, and left here with
//! its assertions flipped to the behaviour that replaced it. Three things were
//! found and all three are asserted closed below.
//!
//! 1. `RelayEndpointReport::served_addresses` is documented as "the list the
//!    screen must quote, because it is the one the relay enforces". It was
//!    recomputed on every call to `wallet_relay_endpoint` from
//!    `status().address` plus the settings box, while the list the SOCKET
//!    enforced was frozen at the last `sync_managed_relay` - which ran on app
//!    start, a whisper save and a node switch, and not when the wallet's own
//!    address changed. `wallet_create` and `wallet_reset` change that address.
//!    After a reset the screen therefore said "this relay carries mail for
//!    nobody" while the socket went on carrying mail for the deleted wallet.
//!    Two things fixed it: the report reads the enforced list off the running
//!    relay, and those commands resync it.
//!
//! 2. Removing an address and pressing Save is promised to take effect at once.
//!    It did, by rebinding the socket, which also hung up on anybody already
//!    connected. The list is swapped in place now, so a held connection stays
//!    open and is refused on its next request.
//!
//! 3. Every Save rebuilt the message store, so any undelivered envelope on the
//!    relay was silently discarded - by a save that changed nothing, and by an
//!    automatic node failover that is not a press at all. The store is kept
//!    across a list change now, and carried across a rebind.
//!
//! The probe is a signed envelope, because the relay no longer answers an
//! unauthenticated question about who it serves: that WAS the leak, and
//! `crates/dust-whisper/tests/messenger_relay_stranger_probe.rs` is where it is
//! held closed. An envelope needs both ends on the list, so posting one from a
//! known-listed account to a candidate address answers "is this candidate
//! served" and nothing else.
//!
//! No chain is contacted: the node URL is a port nothing listens on. The relay
//! is bound to loopback throughout.

#![cfg(feature = "desktop")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hacash_wallet_core::WalletService;
use serde_json::{Value, json};
use tauri::test::MockRuntime;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};
use wallet_tauri_common::AppState;

struct Shell {
    who: &'static str,
    root: PathBuf,
    _app: tauri::App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
}

fn enter(root: &Path) {
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
            wallet_tauri_common::commands::wallet_create,
            wallet_tauri_common::commands::wallet_status,
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

/// Does the RUNNING relay carry mail for this address? Asked of the socket,
/// not of the report.
///
/// This used to be one unauthenticated GET, because the challenge route
/// answered a served address with a nonce and an unserved one with an empty
/// string. That difference was the leak. It is gone, so the question is asked
/// the only way that is left: `sender` is an account this relay is known to
/// carry mail for, and the relay accepts an envelope only when BOTH ends are on
/// the list, so acceptance means the candidate is served too.
fn socket_serves(port: u16, sender: &sys::Account, address: &str, id: &str) -> bool {
    let body = http_post(
        port,
        "/whisper/v1/messenger/send",
        &signed_envelope(address, sender, id),
    );
    body.contains("\"ok\":true")
}

/// A connection held open across a settings save, so the question "when does
/// Save take effect" can be asked of a caller who was already there.
struct HeldConnection {
    stream: TcpStream,
}

impl HeldConnection {
    fn open(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the relay");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        Self { stream }
    }

    /// One keep-alive POST on the connection already open, which is how this
    /// file asks the relay a question it will only answer to a listed address.
    fn post(&mut self, path: &str, body: &Value) -> Option<String> {
        let payload = serde_json::to_string(body).expect("json body");
        write!(
            self.stream,
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{payload}",
            payload.len()
        )
        .ok()?;
        self.stream.flush().ok()?;
        self.read_answer()
    }

    fn read_answer(&mut self) -> Option<String> {
        // Read headers, then exactly Content-Length bytes, so the connection is
        // left usable for the next request.
        let mut raw: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.stream.read(&mut byte) {
                Ok(0) => return None,
                Ok(_) => raw.push(byte[0]),
                Err(_) => return None,
            }
            if raw.len() >= 4 && &raw[raw.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }
        let head = String::from_utf8_lossy(&raw).to_string();
        let len: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        let mut got = 0;
        while got < len {
            match self.stream.read(&mut body[got..]) {
                Ok(0) => return None,
                Ok(n) => got += n,
                Err(_) => return None,
            }
        }
        Some(String::from_utf8_lossy(&body).to_string())
    }
}

fn field<'a>(report: &'a Value, key: &str) -> &'a Value {
    report
        .get(key)
        .unwrap_or_else(|| panic!("report has {key}"))
}

fn served(report: &Value) -> Vec<String> {
    field(report, "served_addresses")
        .as_array()
        .expect("served_addresses is an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn the_screens_list_and_the_sockets_list_stay_in_step() {
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let dir = tempfile::tempdir().expect("host dir");
    let root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&root).expect("wallet root");

    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    let host = open_shell("the host", &root, &node_url);

    // A friend the host deliberately typed into the box. Never changes.
    let friend = sys::Account::create_by("misclick-friend").unwrap();
    let friend_addr = friend.readable().to_string();

    let whisper = |allow: &[String]| {
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
            "relay_allowlist": allow,
        })
    };

    // -- 1. No wallet yet. Save the settings, which starts the relay. -------
    println!("\n== 1. THE RELAY STARTS BEFORE THERE IS A WALLET ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper(std::slice::from_ref(&friend_addr)) }),
    );
    let report = invoke(&host, "wallet_relay_endpoint", json!({}));
    println!("serving              {}", field(&report, "serving"));
    println!("listen_addr          {}", field(&report, "listen_addr"));
    println!("screen served list   {:?}", served(&report));
    assert_eq!(field(&report, "serving"), &json!(true));
    assert_eq!(served(&report), vec![friend_addr.clone()]);
    assert!(
        socket_serves(port, &friend, &friend_addr, "step-1"),
        "the friend is served"
    );

    // -- 2. Now a wallet is created. Nothing resyncs the relay. -------------
    println!("\n== 2. THE PERSON CREATES THEIR WALLET ==");
    let created = invoke(
        &host,
        "wallet_create",
        json!({ "passphrase": "correct horse battery staple" }),
    );
    let owner_addr = created
        .as_str()
        .expect("wallet_create returns an address")
        .to_string();
    println!("new wallet address   {owner_addr}");

    let report = invoke(&host, "wallet_relay_endpoint", json!({}));
    let screen_list = served(&report);
    let socket_has_owner = socket_serves(port, &friend, &owner_addr, "step-2");
    println!("screen served list   {screen_list:?}");
    println!("screen serves_nobody {}", field(&report, "serves_nobody"));
    println!("socket serves owner? {socket_has_owner}");
    println!(
        "socket serves friend? {}",
        socket_serves(port, &friend, &friend_addr, "step-3")
    );
    assert!(
        screen_list.contains(&owner_addr),
        "the screen lists the new owner address"
    );
    // DIRECTION ONE, CLOSED. The screen used to name an address the running
    // relay refused, so everything the owner sent or collected through their
    // own relay was refused while the screen said the relay was theirs.
    // `wallet_create` resyncs now, so the socket has the owner before the
    // screen can be asked about them.
    assert!(
        socket_has_owner,
        "the screen lists an address the running relay refuses"
    );
    println!("  -> the screen and the socket name the same addresses");

    // -- 3. A whisper save resyncs, and the two agree again. ----------------
    println!("\n== 3. ANY WHISPER SAVE PUTS THEM BACK IN STEP ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper(std::slice::from_ref(&friend_addr)) }),
    );
    let report = invoke(&host, "wallet_relay_endpoint", json!({}));
    println!("screen served list   {:?}", served(&report));
    let still = socket_serves(port, &friend, &owner_addr, "step-4");
    println!("socket serves owner? {still}");
    assert!(still);

    // -- 4. The wallet is reset. Nothing resyncs the relay. -----------------
    println!("\n== 4. THE PERSON RESETS THE WALLET ==");
    // `wallet_reset` itself takes a concrete `AppHandle<Wry>` and so cannot be
    // entered under the mock runtime. Its last two lines, after the two
    // authorization checks, are exactly these two calls. Neither authorization
    // check touches the relay; the resync is what was missing and is what is
    // being exercised.
    {
        enter(&host.root);
        let state = host._app.state::<AppState>();
        {
            let mut svc = state.inner.blocking_lock();
            svc.reset_wallet().expect("reset the wallet");
        }
    }
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper(std::slice::from_ref(&friend_addr)) }),
    );
    let report = invoke(&host, "wallet_relay_endpoint", json!({}));
    let screen_list = served(&report);
    let socket_has_owner = socket_serves(port, &friend, &owner_addr, "step-5");
    println!("screen served list   {screen_list:?}");
    println!("screen serves_nobody {}", field(&report, "serves_nobody"));
    println!("socket serves the deleted wallet's address? {socket_has_owner}");
    assert!(
        !screen_list.contains(&owner_addr),
        "the screen has dropped the deleted address"
    );
    // DIRECTION TWO, CLOSED, and this is the one that mattered: the socket used
    // to go on carrying mail for an address the screen no longer listed, which
    // is the door open wider than the list the person is being shown.
    assert!(
        !socket_has_owner,
        "the running relay serves an address the screen does not list"
    );
    println!("  -> the deleted address is refused by the socket as well");

    // AND THE REPORT IS READ OFF THE RELAY, not recomputed beside it. With the
    // relay running, whatever the report names is what the socket enforces.
    for named in &screen_list {
        assert!(
            named == &friend_addr,
            "the report named something other than the enforced list: {named}"
        );
    }
}

/// "Removing an address takes effect as soon as you press Save."
///
/// That is what `widenConsequences` tells the person, and it is what
/// `ALLOWLIST_EXPLANATION` tells them again above the box. Save used to make it
/// true by stopping and rebinding the socket, which also hung up on anybody
/// already connected and threw away the store. It swaps the list on the running
/// relay now, so this asks the harder version of the question: the connection
/// that was already open is still open, and it has to be refused anyway.
#[test]
fn a_connection_opened_before_save_is_asked_what_save_did_to_it() {
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let dir = tempfile::tempdir().expect("host dir");
    let root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&root).expect("wallet root");

    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    let host = open_shell("the host", &root, &node_url);

    let friend = sys::Account::create_by("in-flight-friend").unwrap();
    let friend_addr = friend.readable().to_string();

    let whisper = |allow: Vec<String>| {
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
            "relay_allowlist": allow,
        })
    };

    println!("\n== 1. THE FRIEND IS LISTED AND CONNECTED ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper(vec![friend_addr.clone()]) }),
    );
    let mut held = HeldConnection::open(port);
    let before = held
        .post(
            "/whisper/v1/messenger/send",
            &signed_envelope(&friend_addr, &friend, "in-flight-1"),
        )
        .expect("the relay answered on the held connection");
    println!("held connection, before Save : {before}");
    assert!(before.contains("\"ok\":true"));

    println!("\n== 2. THE HOST REMOVES THEM AND PRESSES SAVE ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper(Vec::new()) }),
    );
    let report = invoke(&host, "wallet_relay_endpoint", json!({}));
    println!("screen served list           {:?}", served(&report));
    assert!(!served(&report).contains(&friend_addr));

    println!("\n== 3. A NEW CONNECTION, AND THE ONE THAT WAS ALREADY THERE ==");
    let fresh_refused = !socket_serves(port, &friend, &friend_addr, "in-flight-2");
    println!("a NEW connection asks        : refused = {fresh_refused}");
    let after = held.post(
        "/whisper/v1/messenger/send",
        &signed_envelope(&friend_addr, &friend, "in-flight-3"),
    );
    match &after {
        Some(body) => println!("the HELD connection asks     : {body}"),
        None => println!("the HELD connection asks     : the relay hung up"),
    }
    assert!(
        fresh_refused,
        "a new connection must see the new list immediately"
    );
    let held_still_served = after
        .as_ref()
        .map(|b| b.contains("\"ok\":true"))
        .unwrap_or(false);
    println!("held connection still served : {held_still_served}");
    assert!(
        !held_still_served,
        "Save did not reach a caller who was already connected"
    );
    // And the connection is still THERE, which is what changed: the removal is
    // enforced by the list rather than by hanging up on everybody.
    assert!(
        after.is_some(),
        "the relay hung up rather than refusing, which also loses the store"
    );
    println!("  -> Save reached the caller who was already connected, without a rebind");
}

/// One signed envelope, the way the relay demands them.
fn signed_envelope(to: &str, sender: &sys::Account, id: &str) -> serde_json::Value {
    let mut env = dust_whisper::protocol::MessengerEnvelope {
        v: 1,
        id: id.to_string(),
        to: to.to_string(),
        from: sender.readable().to_string(),
        from_pubkey: Some(hex::encode(sender.public_key().serialize_compressed())),
        from_sig: None,
        nonce: "00112233445566778899aabb".to_string(),
        ciphertext: "deadbeef".to_string(),
        sent_at: chrono::Utc::now().to_rfc3339(),
    };
    env.from_sig = Some(hex::encode(
        sender.do_sign(&dust_whisper::messenger_auth::envelope_auth_digest(&env)),
    ));
    json!({ "envelope": serde_json::to_value(env).expect("envelope json") })
}

fn http_post(port: u16, path: &str, body: &Value) -> String {
    let payload = serde_json::to_string(body).expect("json body");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the relay");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .expect("write request");
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

/// WHAT SAVE DOES TO MAIL THAT HAS NOT BEEN COLLECTED.
///
/// The screen says the relay "runs while this wallet is open, and stops when
/// you close it. Mail nobody has collected yet is held in memory and is gone
/// when it stops." A person reads that as a statement about closing the wallet.
///
/// It was not one. `sync_managed_relay` built a fresh `MessengerInbox` on every
/// run, and it runs on every DUST Whisper save, on every general settings save
/// (`wallet_update_settings`), and on an automatic node switch after a failed
/// balance or asset call - which is not a press at all. So an undelivered
/// message could be thrown away by a save that changed nothing and by an event
/// nobody caused. The store is now kept across a list change and carried across
/// a rebind, so the sentence on the screen is true as written.
#[test]
fn a_save_that_changes_nothing_keeps_the_mail() {
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let dir = tempfile::tempdir().expect("host dir");
    let root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&root).expect("wallet root");

    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    let host = open_shell("the host", &root, &node_url);

    let alice = sys::Account::create_by("mail-loss-alice").unwrap();
    let bob = sys::Account::create_by("mail-loss-bob").unwrap();
    let listed = vec![alice.readable().to_string(), bob.readable().to_string()];

    let whisper = json!({
        "enabled": true,
        "relay_urls": [own_url],
        "fallback_direct": false,
        "auto_start_relay": true,
        "relay_bind": "loopback",
        "relay_allowlist": listed,
    });

    println!("\n== 1. TWO LISTED FRIENDS, ONE MESSAGE WAITING ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper.clone() }),
    );
    let accepted = http_post(
        port,
        "/whisper/v1/messenger/send",
        &signed_envelope(bob.readable(), &alice, "mail-loss-1"),
    );
    println!("relay answered  {}", accepted.lines().last().unwrap_or(""));
    assert!(accepted.contains("\"ok\":true"));

    // A duplicate id is refused while the original is still held, which is how
    // this test asks "is it still there" without holding Bob's key.
    let duplicate = http_post(
        port,
        "/whisper/v1/messenger/send",
        &signed_envelope(bob.readable(), &alice, "mail-loss-1"),
    );
    println!("same id again   {}", duplicate.lines().last().unwrap_or(""));
    assert!(
        duplicate.contains("already holds an envelope with that id"),
        "the message is in the store"
    );

    println!("\n== 2. THE HOST SAVES THE IDENTICAL SETTINGS AGAIN ==");
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": whisper }),
    );
    let after = http_post(
        port,
        "/whisper/v1/messenger/send",
        &signed_envelope(bob.readable(), &alice, "mail-loss-1"),
    );
    println!("same id again   {}", after.lines().last().unwrap_or(""));
    if after.contains("\"ok\":true") {
        println!("  -> the store is empty: the waiting message was discarded by Save");
    } else {
        println!("  -> the store survived Save");
    }
    assert!(
        after.contains("already holds an envelope with that id"),
        "a save that changed nothing discarded a message that had not been collected"
    );

    println!("\n== 3. AND A SAVE THAT REMOVES SOMEBODY ELSE ==");
    let carol = sys::Account::create_by("mail-loss-carol").unwrap();
    let narrowed = json!({
        "enabled": true,
        "relay_urls": [own_url],
        "fallback_direct": false,
        "auto_start_relay": true,
        "relay_bind": "loopback",
        "relay_allowlist": [alice.readable(), bob.readable(), carol.readable()],
    });
    invoke(
        &host,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": narrowed }),
    );
    let widened = http_post(
        port,
        "/whisper/v1/messenger/send",
        &signed_envelope(bob.readable(), &alice, "mail-loss-1"),
    );
    println!("same id again   {}", widened.lines().last().unwrap_or(""));
    assert!(
        widened.contains("already holds an envelope with that id"),
        "adding a third address discarded the mail waiting for the first two"
    );
}
