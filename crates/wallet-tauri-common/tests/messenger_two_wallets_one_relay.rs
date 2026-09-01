//! TWO WALLETS, ONE RELAY, A MESSAGE THAT ARRIVES AND IS READ.
//!
//! # What was missing
//!
//! Every piece of the messenger had been proven on its own. The relay was
//! driven with `curl`. The inbox claim was proven with a scratch signer. The
//! ECDH sealing was proven in unit tests of the crypto module. Nobody had ever
//! stood up a relay, opened two wallets against it, sent a message from one and
//! watched the other read it. "The messenger works" was an inference from
//! parts, and `docs/RUNNING-A-RELAY.md` said so itself.
//!
//! This is that run, and it is a test so it is that run every time.
//!
//! # What is real here
//!
//! * **The relay is started by the press that starts it.** Not by this file:
//!   by `wallet_update_dust_whisper_settings_desktop`, the command the desktop
//!   Settings screen invokes (`apps/desktop/src/api.ts`,
//!   `updateDustWhisperSettings`), which saves the settings and then calls
//!   `desktop_relay::sync_managed_relay`, which binds the socket and serves
//!   `dust_whisper::relay::serve_listener`. A third shell plays the relay
//!   operator, because a relay is somebody's machine and not either
//!   correspondent's.
//!
//! * **Both wallets are entered through Tauri IPC.** `tauri::test::
//!   get_ipc_response` delivers the same `InvokeRequest` the webview builds
//!   from `invoke("messenger_send", { peer, body })`. The command name and the
//!   argument names are the ones in `apps/desktop/src/api.ts`, and
//!   `the_commands_this_test_drives_are_the_ones_the_shipped_screens_invoke`
//!   at the bottom of this file re-reads those two files and the shared
//!   handler list to keep it that way. Nothing here calls
//!   `hacash_wallet_core::messenger` directly. The chain entered is:
//!
//!       screen -> invoke(cmd) -> Tauri IPC -> whisper_commands::messenger_*
//!         -> WalletService::messenger_* -> messenger::messenger_*
//!         -> dust_whisper::messenger_client -> HTTP -> the relay
//!
//! * **Two wallets, separately.** Separate data roots, so separate vaults,
//!   separate settings, separate encrypted message stores. Each is a real
//!   `WalletService` behind a real `AppState` in its own Tauri application,
//!   created and unlocked through `wallet_create` and `wallet_unlock`.
//!
//! * **A relay operator who can read what a relay operator can read.** The
//!   recorder in this file sits on the wire between the wallets and the relay
//!   and keeps every envelope, exactly as posted. It forwards every byte
//!   onward untouched, which the run proves by the messages arriving. It is
//!   how this file can show the difference between a sealed message and a
//!   message that only looks sealed: the operator holds both addresses in
//!   clear, and `messenger_crypto::decrypt_body` on the v1 path needs nothing
//!   else. It opens the first message. It cannot open the sealed ones.
//!
//! # What this file does not claim
//!
//! The transport is loopback. TLS belongs to the reverse proxy in front of a
//! public relay and is not exercised here. Nothing is broadcast, no chain is
//! contacted, and the node URL every shell is configured with points at a port
//! nothing listens on, so any accidental node call fails loudly instead of
//! reaching anybody.
//!
//! # The first message
//!
//! The first message of a conversation used to travel v1 always: no shipped
//! screen passes `peer_pubkey` to `messenger_send`, so a wallet had nothing to
//! seal to until the peer had written to it once, and v1's key is a hash of the
//! two addresses printed in clear on the envelope. The recorder in this file
//! read Alice's opening message word for word, and that is still what section 6
//! shows, because at that moment nothing anywhere held a key for Bob.
//!
//! Sections 8 to 11 are the case that changed. A relay has seen `from_pubkey`
//! on every envelope ever posted through it, so it can serve the last public
//! key it saw for an address, and a sender can check that answer before using
//! it: a Hacash address is `base58check(0 || RIPEMD160(SHA256(pubkey)))`, so a
//! key that derives to an address IS that address's key, and a relay cannot
//! substitute another without a second preimage on that hash. Carol opens a
//! conversation with Bob having never heard from him, seals it, and the
//! recorder cannot read it. The two paths where no key survives checking are
//! run beside it and both land exactly where every sender was before: v1, and a
//! record that says the message is not sealed.

#![cfg(feature = "desktop")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dust_whisper::protocol::{
    MESSENGER_PUBKEY_PATH, MESSENGER_SEND_PATH, MessengerEnvelope, MessengerPubkeyResponse,
    MessengerSendRequest,
};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::messenger_crypto::{
    EnvelopeBinding, MESSENGER_CRYPTO_V1, MESSENGER_CRYPTO_V2, decrypt_body, parse_pubkey_hex,
    pubkey_hex, verify_pubkey_address,
};
use serde_json::{Value, json};
use tauri::test::MockRuntime;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};
use wallet_tauri_common::AppState;

const PASSPHRASE_A: &str = "two wallets one relay alpha 4417";
const PASSPHRASE_B: &str = "two wallets one relay bravo 9268";
const PASSPHRASE_C: &str = "two wallets one relay charlie 3390";
const PASSPHRASE_D: &str = "two wallets one relay delta 7715";

const FIRST: &str = "A to B: first contact, and this one is not sealed yet.";
const REPLY: &str = "B to A: got it. This reply is sealed to your key.";
const SECOND: &str = "A to B: now I hold your key, so this one is sealed too.";
/// Carol's opening message to Bob. Carol has never heard from Bob and holds no
/// key of his, but the relay has seen Bob send, so this one can be sealed.
const CAROL_FIRST: &str = "C to B: opening message, and the operator must not read this one.";
/// Carol's opening message to Dave, who has never sent through this relay. The
/// relay has no key for him, so this is the honest v1 fallback, unchanged.
const CAROL_TO_DAVE: &str = "C to D: nobody has a key for Dave, so this one is readable.";
/// Dave's opening message to Bob while the operator forges directory answers.
const DAVE_UNDER_FORGERY: &str = "D to B: the relay lied about Bob's key, so this is readable.";

// ---------------------------------------------------------------------------
// One wallet's whole world.
// ---------------------------------------------------------------------------

/// A running wallet application: its own data root, its own `WalletService`,
/// its own `AppState`, its own webview to invoke through.
struct Shell {
    who: &'static str,
    root: PathBuf,
    _app: tauri::App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
}

/// Point the wallet data root at this shell's directory.
///
/// # Why this exists, and why it is a finding and not a convenience
///
/// `hacash_wallet_core::paths::wallet_data_root` reads the process
/// environment on every call, and every messenger read and write goes through
/// it - `messenger_path()` is resolved inside `MessengerStore::load`, not held
/// on the service. So two wallets cannot exist in one process at the same
/// time: they would share one vault and one message store. A person runs each
/// wallet on their own machine, so this is not a bug they can hit, but it is
/// the reason this file switches the root before each shell acts instead of
/// simply holding two services. Only one shell acts at a time, and every
/// entrance goes through `invoke`, which sets the root first.
/// One run at a time in this process.
///
/// `enter` moves a process-wide environment variable, so two runs that each
/// open wallets would take each other's data root out from under them. There
/// is more than one run in this file now, and `cargo test` runs them on
/// separate threads by default. A person runs one wallet per machine; this is
/// the test harness paying for putting several in one process.
static ONE_RUN_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold the lock for a whole run, whatever happened on the run before.
fn one_run_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_RUN_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn enter(root: &Path) {
    // SAFETY: single-threaded test flow. Only one shell acts at a time, and
    // the relay and the recorder never read the wallet data root.
    unsafe { std::env::set_var("HACASH_WALLET_DATA", root) };
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Start a wallet application on `root`, exactly as `apps/desktop/src-tauri`
/// does at launch: build the service on the data root, warm the vault cache,
/// manage it as `AppState`, and register the messenger commands from the
/// shared handler list.
///
/// The handler list here is a subset of `wallet_invoke_handler!` rather than
/// the macro itself, because the macro cannot be instantiated for any runtime
/// but Wry - see the note on that in the source-text check at the bottom of
/// this file, which is what keeps this subset honest.
fn open_shell(who: &'static str, root: &Path, node_url: &str) -> Shell {
    enter(root);
    let mut service =
        WalletService::new(Some(node_url.to_string()), None).expect("wallet service on this root");
    service.warm_vault_cache().expect("warm vault cache");
    let app = tauri::test::mock_builder()
        .invoke_handler(tauri::generate_handler![
            wallet_tauri_common::commands::wallet_status,
            wallet_tauri_common::commands::wallet_create,
            wallet_tauri_common::commands::wallet_unlock,
            wallet_tauri_common::whisper_commands::wallet_whisper_relay_health,
            wallet_tauri_common::whisper_commands::messenger_threads,
            wallet_tauri_common::whisper_commands::messenger_messages,
            wallet_tauri_common::whisper_commands::messenger_mark_read,
            wallet_tauri_common::whisper_commands::messenger_peer_security,
            wallet_tauri_common::whisper_commands::messenger_send,
            wallet_tauri_common::whisper_commands::messenger_poll_inbox,
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

/// The press. One `InvokeRequest`, built the way the webview builds it.
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

/// The relay settings press, `{ dustWhisper }`, exactly as
/// `apps/desktop/src/api.ts` sends it.
fn set_relay(shell: &Shell, relay_url: &str, auto_start: bool) {
    invoke(
        shell,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": {
            "enabled": true,
            "relay_urls": [relay_url],
            "fallback_direct": false,
            "auto_start_relay": auto_start,
        }}),
    );
}

/// The same press with the whole payload spelled out, for the acts that move
/// the bind, name the addresses the relay is for, or put two relays in the list
/// in a particular order.
fn set_whisper(shell: &Shell, dust_whisper: Value) {
    invoke(
        shell,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": dust_whisper }),
    );
}

/// The relay operator naming who their relay is for.
///
/// The relay denies by default: an address the operator has not named gets
/// nothing on any route. So a third party who is running a relay for other
/// people has to say who those people are, and this is that press - the same
/// command the Privacy screen invokes, with `relay_allowlist` filled in.
///
/// This did not exist while an empty list meant "open", and the run below
/// worked without it because the operator's relay carried mail for whoever
/// asked. That is the exposure this change is about: the operator was also
/// relaying for every other machine that could reach the socket, and had
/// pressed nothing that said so.
fn set_relay_for(shell: &Shell, relay_url: &str, serving: &[&str]) {
    invoke(
        shell,
        "wallet_update_dust_whisper_settings_desktop",
        json!({ "dustWhisper": {
            "enabled": true,
            "relay_urls": [relay_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_allowlist": serving,
        }}),
    );
}

/// What this wallet reports it is serving, read through the same read-only
/// command the Privacy and Chat screens invoke.
fn relay_endpoint(shell: &Shell) -> Value {
    invoke(shell, "wallet_relay_endpoint", json!({}))
}

/// One HTTP request over a bare TCP socket, and the body that came back.
///
/// Deliberately not a client this workspace ships: the point of the acts that
/// use it is that a machine which is not either wallet can open a connection to
/// the address the wallet printed, so it must not borrow anything from either
/// wallet to do it. `None` when the connection could not be made at all, which
/// is what a relay bound to loopback gives a caller on the network address.
fn http_request(addr: &str, request: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().ok()?,
        std::time::Duration::from_secs(3),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// `host:port` out of a relay URL, for the raw socket above.
fn host_port(url: &str) -> String {
    url.trim()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

// ---------------------------------------------------------------------------
// The relay operator's view of the wire.
// ---------------------------------------------------------------------------

/// Every envelope posted towards the relay, kept as posted, plus the one lever
/// a hostile operator has over the key directory.
///
/// This is not more than a relay operator has. The relay is handed these
/// bytes; it stores them; it hands them to whoever can sign for the recipient
/// address. What an operator can do with them is the question this file
/// answers below.
///
/// `forged_pubkey` is the hostile case for the directory added in act 8. The
/// relay serves the last public key it saw for an address; an operator can
/// serve anything at all instead, and this is how the run makes it do so.
#[derive(Clone, Default)]
struct OperatorView {
    envelopes: Arc<Mutex<Vec<MessengerEnvelope>>>,
    forged_pubkey: Arc<Mutex<Option<String>>>,
}

impl OperatorView {
    fn recorded(&self) -> Vec<MessengerEnvelope> {
        self.envelopes.lock().expect("operator view").clone()
    }

    /// Answer every directory lookup with this key instead of the truth.
    fn forge_directory(&self, pubkey_hex: Option<String>) {
        *self.forged_pubkey.lock().expect("operator view") = pubkey_hex;
    }
}

#[derive(Clone)]
struct TapState {
    view: OperatorView,
    upstream: String,
    http: reqwest::Client,
}

/// Record, then forward untouched. Every path, every method.
async fn tap(
    axum::extract::State(state): axum::extract::State<TapState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
        .await
        .unwrap_or_default();
    if parts.uri.path() == MESSENGER_SEND_PATH
        && let Ok(sent) = serde_json::from_slice::<MessengerSendRequest>(&bytes)
    {
        state
            .view
            .envelopes
            .lock()
            .expect("operator view")
            .push(sent.envelope);
    }
    // A hostile operator answering the key directory with a key of its own
    // choosing. The request never reaches the relay behind it.
    if parts.uri.path() == MESSENGER_PUBKEY_PATH {
        let forged = state
            .view
            .forged_pubkey
            .lock()
            .expect("operator view")
            .clone();
        if let Some(pubkey) = forged {
            return axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&MessengerPubkeyResponse {
                        pubkey: Some(pubkey),
                    })
                    .expect("forged directory answer"),
                ))
                .expect("forged directory response");
        }
    }
    let target = format!(
        "{}{}",
        state.upstream,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).expect("method");
    let mut outbound = state.http.request(method, target);
    if let Some(content_type) = parts.headers.get(axum::http::header::CONTENT_TYPE) {
        outbound = outbound.header("content-type", content_type.clone().to_str().unwrap_or(""));
    }
    match outbound.body(bytes.to_vec()).send().await {
        Ok(response) => {
            let status = axum::http::StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let payload = response.bytes().await.unwrap_or_default();
            axum::response::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(payload))
                .expect("tap response")
        }
        Err(error) => axum::response::Response::builder()
            .status(axum::http::StatusCode::BAD_GATEWAY)
            .body(axum::body::Body::from(format!("tap upstream: {error}")))
            .expect("tap error response"),
    }
}

/// Start the recorder on its own thread and return the port it listens on.
fn start_tap(upstream: String, view: OperatorView) -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tap runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("tap listener");
            tx.send(listener.local_addr().expect("tap addr").port())
                .expect("tap port");
            let router = axum::Router::new().fallback(tap).with_state(TapState {
                view,
                upstream,
                http: reqwest::Client::new(),
            });
            axum::serve(listener, router).await.expect("tap serve");
        });
    });
    rx.recv().expect("tap started")
}

// ---------------------------------------------------------------------------
// Reading the wire the way the operator would.
// ---------------------------------------------------------------------------

/// Any account at all. The v1 branch of `decrypt_body` derives its key from
/// the two address strings and never touches the account, which is the whole
/// problem with v1 and the reason this argument is a throwaway.
fn any_account() -> WalletAccount {
    WalletAccount::from_secret_hex(
        "0000000000000000000000000000000000000000000000000000000000000007",
    )
    .expect("throwaway account")
}

/// What the operator gets by trying the only key it can derive: the one made
/// from the two addresses written in clear on the envelope it is holding.
fn operator_attempt(envelope: &MessengerEnvelope) -> Option<String> {
    decrypt_body(
        any_account().inner(),
        &envelope.from,
        &envelope.to,
        None,
        &envelope.nonce,
        &envelope.ciphertext,
        // Everything the binding needs is written in clear on the envelope the
        // operator is holding, so this costs the attempt nothing.
        &EnvelopeBinding {
            id: &envelope.id,
            from: &envelope.from,
            to: &envelope.to,
            v: MESSENGER_CRYPTO_V1,
        },
    )
    .ok()
    .map(|plain| plain.body)
}

fn body_of(messages: &Value, index: usize) -> String {
    messages[index]["body"]
        .as_str()
        .expect("message body")
        .to_string()
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

#[test]
fn two_wallets_exchange_a_message_through_one_relay_and_still_have_it_after_a_cold_start() {
    let _one_at_a_time = one_run_at_a_time();
    // A port with nothing on it. Every shell is configured with this as its
    // node, so an accidental chain call fails loudly rather than reaching a
    // real node. No chain is contacted by anything in this file.
    let node_url = format!("http://127.0.0.1:{}", free_port());

    let operator_dir = tempfile::tempdir().expect("operator dir");
    let alice_dir = tempfile::tempdir().expect("alice dir");
    let bob_dir = tempfile::tempdir().expect("bob dir");
    // Two more strangers, for the first-contact acts in sections 8 to 11.
    let carol_dir = tempfile::tempdir().expect("carol dir");
    let dave_dir = tempfile::tempdir().expect("dave dir");
    let operator_root = operator_dir.path().join("wallet-data");
    let alice_root = alice_dir.path().join("wallet-data");
    let bob_root = bob_dir.path().join("wallet-data");
    let carol_root = carol_dir.path().join("wallet-data");
    let dave_root = dave_dir.path().join("wallet-data");
    for root in [
        &operator_root,
        &alice_root,
        &bob_root,
        &carol_root,
        &dave_root,
    ] {
        std::fs::create_dir_all(root).expect("wallet root");
    }

    // -- 1. A relay, started by the press that starts one. ------------------
    let relay_port = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");
    let operator = open_shell("the relay operator", &operator_root, &node_url);
    set_relay(&operator, &relay_url, true);
    println!("\n== 1. THE RELAY ==");
    println!("started by wallet_update_dust_whisper_settings_desktop -> sync_managed_relay");
    println!("listening on          {relay_url}");
    println!("operator data root    {}", operator_root.display());

    let view = OperatorView::default();
    let tap_port = start_tap(relay_url.clone(), view.clone());
    let tap_url = format!("http://127.0.0.1:{tap_port}");
    println!("recorder on the wire  {tap_url} -> {relay_url}");

    // -- 2. Two wallets, separate vaults, separate stores. ------------------
    let alice = open_shell("Alice", &alice_root, &node_url);
    let bob = open_shell("Bob", &bob_root, &node_url);
    let alice_address = invoke(
        &alice,
        "wallet_create",
        json!({ "passphrase": PASSPHRASE_A }),
    )
    .as_str()
    .expect("alice address")
    .to_string();
    let bob_address = invoke(&bob, "wallet_create", json!({ "passphrase": PASSPHRASE_B }))
        .as_str()
        .expect("bob address")
        .to_string();
    assert_ne!(alice_address, bob_address, "two wallets, two addresses");
    assert_ne!(alice_root, bob_root, "two wallets, two data roots");
    set_relay(&alice, &tap_url, false);
    set_relay(&bob, &tap_url, false);

    // Carol and Dave, the two strangers section 8 needs, opened here rather
    // than there for one reason: the operator has to name everybody this relay
    // will carry mail for, and naming somebody is a settings press. A press
    // used to rebuild the relay, which erased the directory of "which key did I
    // last see this address send with" and with it every undelivered envelope -
    // exactly what section 8 is about. A press swaps the list on the running
    // relay now and leaves both alone, so the ordering here is no longer
    // load-bearing; it is kept because one press before any mail moves is still
    // the clearest way to read the run.
    let carol = open_shell("Carol", &carol_root, &node_url);
    let dave = open_shell("Dave", &dave_root, &node_url);
    let carol_address = invoke(
        &carol,
        "wallet_create",
        json!({ "passphrase": PASSPHRASE_C }),
    )
    .as_str()
    .expect("carol address")
    .to_string();
    let dave_address = invoke(
        &dave,
        "wallet_create",
        json!({ "passphrase": PASSPHRASE_D }),
    )
    .as_str()
    .expect("dave address")
    .to_string();
    set_relay(&carol, &tap_url, false);
    set_relay(&dave, &tap_url, false);

    // The operator says who this relay is for. Without this press the relay
    // carries mail for nobody but the operator, which is what a relay whose
    // owner has named nobody should do, and every send below is refused. There
    // is no press anywhere that says "and whoever else turns up".
    set_relay_for(
        &operator,
        &relay_url,
        &[&alice_address, &bob_address, &carol_address, &dave_address],
    );

    println!("\n== 2. TWO WALLETS ==");
    println!("Alice {alice_address}");
    println!("      vault  {}", alice_root.join("vault.json").display());
    println!(
        "      store  {}",
        alice_root.join("messenger.json").display()
    );
    println!("Bob   {bob_address}");
    println!("      vault  {}", bob_root.join("vault.json").display());
    println!("      store  {}", bob_root.join("messenger.json").display());

    // Both wallets see the one relay, through the wallet's own health check.
    for (shell, name) in [(&alice, "Alice"), (&bob, "Bob")] {
        let health = invoke(shell, "wallet_whisper_relay_health", json!({}));
        assert_eq!(
            health[0]["online"],
            json!(true),
            "{name} cannot see the relay: {health}"
        );
        println!("{name} relay health   {}", health[0]);
    }

    // -- 3. Alice writes to Bob, by address, through the command. -----------
    let sent = invoke(
        &alice,
        "messenger_send",
        json!({ "peer": bob_address, "body": FIRST }),
    );
    assert_eq!(
        sent["delivered"],
        json!(true),
        "no relay accepted the envelope: {sent}"
    );
    println!("\n== 3. ALICE SENDS ==");
    println!("to        {bob_address}");
    println!("body      {FIRST}");
    println!("delivered {}  sealed {}", sent["delivered"], sent["sealed"]);
    println!(
        "not sealed, and that is the honest state of THIS first message. Alice's wallet holds no\n\
         key of Bob's, and it did ask the relay for one, but this relay has never seen Bob send:\n\
         it has nothing to serve. Section 8 is the same opening move against a relay that has."
    );
    assert_eq!(
        sent["sealed"],
        json!(false),
        "nothing has taught Alice a key for Bob, and the relay has never seen Bob send either, \
         so there is nothing to seal to and the record has to say so"
    );

    // -- 4. Bob polls, receives, and reads it. ------------------------------
    let outcome = invoke(&bob, "messenger_poll_inbox", json!({}));
    assert_eq!(outcome["added"], json!(1), "Bob's poll: {outcome}");
    assert_eq!(outcome["relays_answered"], json!(1), "{outcome}");
    assert_eq!(outcome["relays_refused"], json!(0), "{outcome}");
    assert_eq!(outcome["rejected_envelopes"], json!(0), "{outcome}");

    let threads = invoke(&bob, "messenger_threads", json!({}));
    assert_eq!(threads[0]["peer"], json!(alice_address), "{threads}");
    assert_eq!(threads[0]["unread"], json!(1), "{threads}");
    let bob_sees = invoke(&bob, "messenger_messages", json!({ "peer": alice_address }));
    assert_eq!(body_of(&bob_sees, 0), FIRST, "Bob read something else");
    invoke(
        &bob,
        "messenger_mark_read",
        json!({ "peer": alice_address }),
    );

    println!("\n== 4. BOB POLLS AND READS ==");
    println!("poll      {outcome}");
    println!("thread    {}", threads[0]);
    println!("plaintext {}", body_of(&bob_sees, 0));

    // -- 5. Bob replies, and this one is sealed. ---------------------------
    let security = invoke(
        &bob,
        "messenger_peer_security",
        json!({ "peer": alice_address }),
    );
    assert_eq!(
        security["sends_sealed"],
        json!(true),
        "Bob's poll should have taught him Alice's verified key: {security}"
    );
    let reply = invoke(
        &bob,
        "messenger_send",
        json!({ "peer": alice_address, "body": REPLY }),
    );
    assert_eq!(reply["delivered"], json!(true), "{reply}");
    assert_eq!(
        reply["sealed"],
        json!(true),
        "Bob holds Alice's key and should have sealed to it: {reply}"
    );

    let alice_poll = invoke(&alice, "messenger_poll_inbox", json!({}));
    assert_eq!(alice_poll["added"], json!(1), "{alice_poll}");
    let alice_sees = invoke(&alice, "messenger_messages", json!({ "peer": bob_address }));
    assert_eq!(body_of(&alice_sees, 1), REPLY, "Alice read something else");
    assert_eq!(
        alice_sees[1]["sealed"],
        json!(true),
        "Alice's copy of the reply should record that it was sealed: {alice_sees}"
    );

    println!("\n== 5. BOB REPLIES, ALICE READS ==");
    println!("Bob peer security {security}");
    println!("reply sealed      {}", reply["sealed"]);
    println!("Alice poll        {alice_poll}");
    println!("Alice reads       {}", body_of(&alice_sees, 1));

    // Now Alice holds Bob's key too, so the sealed path runs in both
    // directions. A one-way proof would not have shown that.
    let second = invoke(
        &alice,
        "messenger_send",
        json!({ "peer": bob_address, "body": SECOND }),
    );
    assert_eq!(
        second["sealed"],
        json!(true),
        "Alice learned Bob's key from his reply: {second}"
    );
    let bob_poll_two = invoke(&bob, "messenger_poll_inbox", json!({}));
    assert_eq!(bob_poll_two["added"], json!(1), "{bob_poll_two}");
    let bob_sees = invoke(&bob, "messenger_messages", json!({ "peer": alice_address }));
    assert_eq!(body_of(&bob_sees, 2), SECOND, "Bob read something else");
    println!("Alice sends again, sealed this time. Bob reads: {SECOND}");

    // -- 6. Sealed, read off the wire and not off a flag. -------------------
    let wire = view.recorded();
    assert_eq!(
        wire.len(),
        3,
        "three envelopes crossed the wire, not {}",
        wire.len()
    );
    println!("\n== 6. WHAT THE RELAY OPERATOR HOLDS ==");
    for envelope in &wire {
        let claimed = envelope
            .from_pubkey
            .as_deref()
            .and_then(|hex| parse_pubkey_hex(hex).ok())
            .expect("every envelope carries its sender's key");
        assert!(
            verify_pubkey_address(&claimed, &envelope.from),
            "an envelope named a sender its key does not derive to"
        );
        let opened = operator_attempt(envelope);
        println!(
            "v{} {} -> {}  address-derived key opens it: {}",
            envelope.v,
            &envelope.from[..8],
            &envelope.to[..8],
            match &opened {
                Some(text) => format!("YES, and it reads {text:?}"),
                None => "NO".to_string(),
            }
        );
        match envelope.v {
            MESSENGER_CRYPTO_V1 => assert_eq!(
                opened.as_deref(),
                Some(FIRST),
                "v1 is the key made from the two addresses. If the operator could not read it, \
                 this test is not reading the wire it thinks it is"
            ),
            MESSENGER_CRYPTO_V2 => assert!(
                opened.is_none(),
                "a v2 envelope opened with the key derived from the two public addresses. That is \
                 not ECDH, and it is not private from the relay"
            ),
            other => panic!("unknown messenger crypto version v{other} on the wire"),
        }
    }
    let sealed_on_the_wire = wire.iter().filter(|e| e.v == MESSENGER_CRYPTO_V2).count();
    assert_eq!(
        sealed_on_the_wire, 2,
        "the reply and the second message travelled the ECDH path"
    );
    println!(
        "Alice's opening is the only one of these three the operator can read: nothing had ever\n\
         taught her a key for Bob, and at that moment the relay had never seen Bob send either."
    );

    // -- 8. A first message that IS sealed, without trusting the relay. -----
    //
    // The relay has now seen Bob send (his reply above), so it holds Bob's
    // public key: every envelope carries `from_pubkey` and this one was signed
    // by the key `from` derives from. Carol has never heard from Bob and holds
    // nothing of his. She asks, checks the answer against Bob's address
    // herself, and seals to it. The recorder below is the proof.
    println!("\n== 8. A FIRST MESSAGE THAT IS SEALED ==");
    println!("Carol {carol_address}");
    println!("Dave  {dave_address}  (has never sent through this relay)");

    // Before she writes: her wallet holds nothing of Bob's, and says so.
    let carol_before = invoke(
        &carol,
        "messenger_peer_security",
        json!({ "peer": bob_address }),
    );
    assert_eq!(
        carol_before["sends_sealed"],
        json!(false),
        "Carol has never heard from Bob, so her wallet holds no key of his: {carol_before}"
    );

    let carol_opening = invoke(
        &carol,
        "messenger_send",
        json!({ "peer": bob_address, "body": CAROL_FIRST }),
    );
    assert_eq!(carol_opening["delivered"], json!(true), "{carol_opening}");
    assert_eq!(
        carol_opening["sealed"],
        json!(true),
        "the relay had seen Bob send, and Carol checked the key it served against Bob's own \
         address before using it, so her opening message must be sealed: {carol_opening}"
    );

    // And Bob really reads it, which is what proves the key she sealed to was
    // his and not a shape that merely passed a check.
    let bob_poll_three = invoke(&bob, "messenger_poll_inbox", json!({}));
    assert_eq!(bob_poll_three["added"], json!(1), "{bob_poll_three}");
    let bob_from_carol = invoke(&bob, "messenger_messages", json!({ "peer": carol_address }));
    assert_eq!(
        body_of(&bob_from_carol, 0),
        CAROL_FIRST,
        "Bob could not read the first message Carol sealed to him"
    );
    assert_eq!(bob_from_carol[0]["sealed"], json!(true), "{bob_from_carol}");
    println!("Carol's opening to Bob: sealed {}", carol_opening["sealed"]);
    println!("Bob reads it: {}", body_of(&bob_from_carol, 0));

    // -- 9. The control: nobody has a key for Dave, so nothing changes. -----
    //
    // This is the path that had to survive untouched. Dave has never sent
    // through this relay, so the directory has nothing for him, and Carol is
    // exactly where every sender was before any of this: v1, and the record
    // says the message is not sealed.
    let carol_to_dave = invoke(
        &carol,
        "messenger_send",
        json!({ "peer": dave_address, "body": CAROL_TO_DAVE }),
    );
    assert_eq!(carol_to_dave["delivered"], json!(true), "{carol_to_dave}");
    assert_eq!(
        carol_to_dave["sealed"],
        json!(false),
        "no relay has ever seen Dave send, so there is nothing to seal to and the record must \
         say so rather than claiming otherwise: {carol_to_dave}"
    );

    // -- 10. The hostile relay: an answer that fails the check is no answer. -
    //
    // The operator now serves a key of its own for every directory lookup.
    // Dave holds nothing of Bob's and asks. The key that comes back does not
    // derive to Bob's address, so Dave's wallet discards it and falls straight
    // through to v1. The one thing that must never happen is that it seals to
    // a key it has not itself verified.
    let operator_key = pubkey_hex(any_account().inner());
    view.forge_directory(Some(operator_key.clone()));
    let dave_to_bob = invoke(
        &dave,
        "messenger_send",
        json!({ "peer": bob_address, "body": DAVE_UNDER_FORGERY }),
    );
    view.forge_directory(None);
    assert_eq!(dave_to_bob["delivered"], json!(true), "{dave_to_bob}");
    assert_eq!(
        dave_to_bob["sealed"],
        json!(false),
        "the relay answered with a key that is not Bob's, and the only acceptable outcome is the \
         fallback that already existed: {dave_to_bob}"
    );
    let dave_after = invoke(
        &dave,
        "messenger_peer_security",
        json!({ "peer": bob_address }),
    );
    assert_eq!(
        dave_after["sends_sealed"],
        json!(false),
        "a key that failed the address check was written into Dave's store: {dave_after}"
    );

    // -- 11. All three read off the wire, not off a flag. -------------------
    let wire = view.recorded();
    let since = &wire[3..];
    assert_eq!(
        since.len(),
        3,
        "three more envelopes crossed the wire, not {}",
        since.len()
    );
    println!("\n== 11. WHAT THE OPERATOR HOLDS, SECOND PASS ==");
    let mut readable = Vec::new();
    for envelope in since {
        let opened = operator_attempt(envelope);
        println!(
            "v{} {} -> {}  address-derived key opens it: {}",
            envelope.v,
            &envelope.from[..8],
            &envelope.to[..8],
            match &opened {
                Some(text) => format!("YES, and it reads {text:?}"),
                None => "NO".to_string(),
            }
        );
        if let Some(text) = opened {
            readable.push(text);
        }
    }
    assert_eq!(
        since[0].v, MESSENGER_CRYPTO_V2,
        "Carol's opening message to Bob had to travel the ECDH path"
    );
    assert!(
        !readable.contains(&CAROL_FIRST.to_string()),
        "the operator read the FIRST message of Carol's conversation with Bob: {readable:?}"
    );
    assert_eq!(
        readable,
        vec![CAROL_TO_DAVE.to_string(), DAVE_UNDER_FORGERY.to_string()],
        "exactly the two messages with no verified key behind them are readable, and in order"
    );
    println!(
        "Carol's opening to Bob is closed to the operator. The two the operator can still read are\n\
         the two where no key survived checking: nobody had ever seen Dave send, and the forged\n\
         answer for Bob did not derive to Bob's address. Both land on v1, which is where every\n\
         sender was before, and both say so on screen."
    );

    // -- 12. Cold start. Close both wallets, open them from disk. ----------
    drop(alice);
    drop(bob);
    let alice = open_shell("Alice", &alice_root, &node_url);
    let bob = open_shell("Bob", &bob_root, &node_url);
    let reopened_alice = invoke(
        &alice,
        "wallet_unlock",
        json!({ "passphrase": PASSPHRASE_A }),
    );
    let reopened_bob = invoke(&bob, "wallet_unlock", json!({ "passphrase": PASSPHRASE_B }));
    assert_eq!(reopened_alice, json!(alice_address), "same wallet");
    assert_eq!(reopened_bob, json!(bob_address), "same wallet");

    let alice_after = invoke(&alice, "messenger_messages", json!({ "peer": bob_address }));
    let bob_after = invoke(&bob, "messenger_messages", json!({ "peer": alice_address }));
    for (who, seen) in [("Alice", &alice_after), ("Bob", &bob_after)] {
        assert_eq!(
            seen.as_array().expect("messages").len(),
            3,
            "{who} lost messages across the restart: {seen}"
        );
        assert_eq!(body_of(seen, 0), FIRST, "{who} first message");
        assert_eq!(body_of(seen, 1), REPLY, "{who} reply");
        assert_eq!(body_of(seen, 2), SECOND, "{who} second message");
        assert_eq!(seen[0]["sealed"], json!(false), "{who} first, v1");
        assert_eq!(seen[1]["sealed"], json!(true), "{who} reply, sealed");
        assert_eq!(seen[2]["sealed"], json!(true), "{who} second, sealed");
    }

    // The peer keys survived too, so the next message is still sealed rather
    // than falling back to v1 after a restart.
    let alice_security = invoke(
        &alice,
        "messenger_peer_security",
        json!({ "peer": bob_address }),
    );
    assert_eq!(
        alice_security["sends_sealed"],
        json!(true),
        "Alice forgot Bob's key when the app closed: {alice_security}"
    );
    assert_eq!(
        alice_security["unsealed_messages"],
        json!(1),
        "exactly the first message was not sealed: {alice_security}"
    );

    println!("\n== 12. COLD START ==");
    println!("both wallets dropped and reopened from disk, unlocked with their passphrases");
    println!(
        "Alice sees {} messages",
        alice_after.as_array().unwrap().len()
    );
    println!(
        "Bob   sees {} messages",
        bob_after.as_array().unwrap().len()
    );
    println!("Alice peer security after restart {alice_security}");
    println!("conversation intact and still readable\n");
}

// ---------------------------------------------------------------------------
// The hop above the IPC.
// ---------------------------------------------------------------------------

/// The one hop this test cannot execute: the TypeScript `invoke` call.
///
/// The run above enters at Tauri IPC with a command name and argument names
/// typed into this file. If a screen invoked a different name, or sent
/// `{ address }` where the command reads `peer`, this test would still pass
/// and the shipped app would still be broken. So the names are read back out
/// of the shipped sources.
///
/// It also pins the handler registration, because the run cannot use
/// `wallet_invoke_handler!` itself: that macro contains commands taking a bare
/// `AppHandle`, which is `AppHandle<Wry>`, and Wry cannot be built without a
/// window server. The macro is therefore uninstantiable for the mock runtime,
/// and a test can only ever drive a hand-written subset of it. This check is
/// what keeps that subset from drifting away from what the shells register.
#[test]
fn the_commands_this_test_drives_are_the_ones_the_shipped_screens_invoke() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf();
    let read = |relative: &str| {
        std::fs::read_to_string(repo.join(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"))
    };

    let desktop_api = read("apps/desktop/src/api.ts");
    for call in [
        r#"invoke<ChatThread[]>("messenger_threads")"#,
        r#"invoke<ChatMessage[]>("messenger_messages", { peer })"#,
        r#"invoke<void>("messenger_mark_read", { peer })"#,
        r#"invoke<MessengerPeerSecurity>("messenger_peer_security", { peer })"#,
        r#"invoke<ChatMessage>("messenger_send", { peer, body })"#,
        r#"invoke<MessengerPollOutcome>("messenger_poll_inbox")"#,
        r#"invoke<void>("wallet_update_dust_whisper_settings_desktop", { dustWhisper })"#,
        // The read-only command the second run reads the shareable address out
        // of. Without it the guest in that run is handed an address this file
        // made up rather than one a person would be shown.
        r#"invoke<RelayEndpoint>("wallet_relay_endpoint")"#,
    ] {
        assert!(
            desktop_api.contains(call),
            "apps/desktop/src/api.ts no longer contains `{call}`. The run in this file invokes \
             that command with those argument names, so if the screen changed, the run is \
             proving something the screen does not do"
        );
    }

    let handlers = read("crates/wallet-tauri-common/src/handlers.rs");
    for command in [
        "wallet_tauri_common::commands::wallet_create",
        "wallet_tauri_common::commands::wallet_unlock",
        "wallet_tauri_common::whisper_commands::wallet_whisper_relay_health",
        "wallet_tauri_common::whisper_commands::messenger_threads",
        "wallet_tauri_common::whisper_commands::messenger_messages",
        "wallet_tauri_common::whisper_commands::messenger_mark_read",
        "wallet_tauri_common::whisper_commands::messenger_peer_security",
        "wallet_tauri_common::whisper_commands::messenger_send",
        "wallet_tauri_common::whisper_commands::messenger_poll_inbox",
    ] {
        assert!(
            handlers.contains(command),
            "{command} is no longer in the shared invoke handler list, so no screen can reach it"
        );
    }

    let desktop_entry = read("apps/desktop/src-tauri/src/lib.rs");
    assert!(
        desktop_entry.contains(
            "wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop"
        ),
        "the desktop shell no longer registers the command that starts the managed relay"
    );
    assert!(
        desktop_entry.contains("wallet_tauri_common::desktop_relay::sync_managed_relay"),
        "the desktop shell no longer starts the managed relay at launch"
    );
    assert!(
        desktop_entry.contains("wallet_tauri_common::desktop_commands::wallet_relay_endpoint"),
        "the desktop shell no longer registers the command the screens read the relay address          from, so the second run in this file drives something no screen can reach"
    );

    // The order of the relay list is what the second run's trap turns on, and
    // the screens can only warn about it if they are given the list in order.
    let relay_reach = read("apps/desktop/src/relayReach.ts");
    assert!(
        relay_reach.contains("export function firstAcceptWarning"),
        "the sentence for a wallet whose own relay sits above somebody else's is gone"
    );
    assert!(
        relay_reach.contains("export function acceptedByNote"),
        "the sentence naming which relay took a message is gone, and `delivered` alone is what          the second run in this file proves is not enough"
    );
}

// ---------------------------------------------------------------------------
// Two people. One of them hosting. Nothing else deployed.
// ---------------------------------------------------------------------------

const HOST_FIRST: &str = "Host to guest: first contact, over a relay I am running myself.";
const GUEST_REPLY: &str = "Guest to host: got it, and this reply is sealed to your key.";
const HOST_SEALED: &str = "Host to guest: now I hold your key, so this one is sealed too.";
const TRAPPED: &str = "Guest to host: this one is the trap, and it never left my computer.";

/// THE WHOLE POINT, WITH NOBODY ELSE INVOLVED.
///
/// The run above has a third shell playing a relay operator, because that is
/// what publishing a relay looks like. This one has nobody but the two people
/// messaging: one wallet hosts on its own machine, the other points at the
/// address that wallet printed, and a sealed message goes each way. No third
/// party, no server, no domain, no certificate.
///
/// # What each act is really doing
///
/// 1. The host's Privacy screen press: DUST Whisper on, auto-start on, its own
///    loopback URL in the box, the bind moved to every interface, and both
///    addresses named as the people this relay is for. One
///    `wallet_update_dust_whisper_settings_desktop`, the payload `api.ts` sends.
/// 2. The address the guest is given comes from `wallet_relay_endpoint`, the
///    read-only command the screens invoke. This file does not construct it.
/// 3. A bare TCP socket, borrowing nothing from either wallet, fetches
///    `/whisper/v1/info` from that address. That is the check section 0 step 5
///    tells a person to run from the other machine.
/// 4. A stranger with a real keypair, posting a properly signed envelope over
///    that same bare socket, is refused, because the host named who this relay
///    is for. That is the defence a free keypair does not walk around.
/// 5. Three messages, and both directions end up sealed.
/// 6. The trap: the guest turns on their own relay and leaves it ABOVE the
///    host's in the list. The send is accepted, by the guest's own machine, and
///    the host never sees it. `delivered_via` is what makes that visible, and
///    the endpoint report carries the list in order so the screens can warn.
///
/// # What it does not claim
///
/// It does not claim the two machines are on different networks: they are the
/// same machine, and the socket is what differs. It does not claim TLS. It
/// contacts no node and broadcasts nothing: every shell's node URL points at a
/// port nothing listens on.
#[test]
fn two_people_one_of_them_hosting_and_no_third_party_at_all() {
    let _one_at_a_time = one_run_at_a_time();
    let node_url = format!("http://127.0.0.1:{}", free_port());

    let host_dir = tempfile::tempdir().expect("host dir");
    let guest_dir = tempfile::tempdir().expect("guest dir");
    let host_root = host_dir.path().join("wallet-data");
    let guest_root = guest_dir.path().join("wallet-data");
    for root in [&host_root, &guest_root] {
        std::fs::create_dir_all(root).expect("wallet root");
    }

    let host = open_shell("the host", &host_root, &node_url);
    let guest = open_shell("the guest", &guest_root, &node_url);
    let host_address = invoke(
        &host,
        "wallet_create",
        json!({ "passphrase": PASSPHRASE_A }),
    )
    .as_str()
    .expect("host address")
    .to_string();
    let guest_address = invoke(
        &guest,
        "wallet_create",
        json!({ "passphrase": PASSPHRASE_B }),
    )
    .as_str()
    .expect("guest address")
    .to_string();
    assert_ne!(host_address, guest_address);
    assert_ne!(
        host_root, guest_root,
        "two people, two machines' worth of data"
    );

    println!("\n== TWO PEOPLE, NOBODY ELSE ==");
    println!("host  {host_address}");
    println!("guest {guest_address}");
    println!("nothing else is deployed: no operator shell, no server, no domain");

    // -- 1. The host presses Save on their own Privacy screen. --------------
    let port = free_port();
    let own_url = format!("http://127.0.0.1:{port}");
    set_whisper(
        &host,
        json!({
            "enabled": true,
            "relay_urls": [own_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            // The bind is a stored choice and never inferred. This is the
            // person choosing it, knowingly, on the screen that lists what it
            // costs.
            "relay_bind": "all_interfaces",
            // And naming who the relay is for, which is what stops a passer-by
            // on the same network filling it and stopping the guest's mail.
            "relay_allowlist": [host_address, guest_address],
        }),
    );

    let report = relay_endpoint(&host);
    println!("\n== 1. THE HOST'S OWN WALLET IS THE RELAY ==");
    println!("hosting        {}", report["hosting"]);
    println!("serving        {}", report["serving"]);
    println!("listen_addr    {}", report["listen_addr"]);
    println!("bind           {}", report["bind"]);
    println!("loopback_only  {}", report["loopback_only"]);
    println!("allowlist      {}", report["allowlist"]);
    println!("lan_url        {}", report["lan_url"]);
    assert_eq!(report["hosting"], json!(true));
    assert_eq!(report["serving"], json!(true));
    assert_eq!(report["bind"], json!("all_interfaces"));
    assert_eq!(report["loopback_only"], json!(false));
    assert_eq!(
        report["listen_addr"],
        json!(format!("0.0.0.0:{port}")),
        "the socket is not where the person asked for it: {report}"
    );
    assert_eq!(
        report["allowlist"],
        json!([host_address, guest_address]),
        "the relay does not report who its operator said it is for: {report}"
    );

    // -- 2. The address the guest is given, from the wallet and not from us. -
    // On a machine with no route off itself the wallet offers no address, and
    // says so rather than inventing one. The round trip below is the same
    // either way; only the reachability act depends on there being one.
    let shared_url = match report["lan_url"].as_str() {
        Some(url) => url.to_string(),
        None => {
            println!(
                "this machine offered no network address of its own, so the guest is pointed at\n\
                 the same socket over loopback. The relay is still the host's wallet and still\n\
                 nobody else's."
            );
            own_url.clone()
        }
    };
    println!("\n== 2. THE ADDRESS THE HOST HANDS OVER ==");
    println!("from wallet_relay_endpoint   {shared_url}");

    // -- 3. Somebody who is not either wallet opens a connection to it. -----
    let target = host_port(&shared_url);
    let info = http_request(
        &target,
        &format!("GET /whisper/v1/info HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
    );
    println!("\n== 3. A BARE SOCKET, BORROWING NOTHING FROM EITHER WALLET ==");
    match &info {
        Some(body) => println!(
            "GET /whisper/v1/info      {}",
            body.lines().next().unwrap_or("")
        ),
        None => println!("GET /whisper/v1/info      no connection"),
    }
    let info = info.expect("the address the wallet printed refused a connection");
    assert!(
        info.contains("\"v\":") && info.contains("pubkey"),
        "the address the wallet printed is not answering as a relay: {info}"
    );

    // -- 4. A stranger who can reach the port, and holds a real key. --------
    let stranger =
        WalletAccount::create("a stranger on the same network 5521").expect("stranger account");
    let stranger_address = stranger.address();
    let mut envelope = MessengerEnvelope {
        v: MESSENGER_CRYPTO_V1,
        id: "stranger-flood-1".to_string(),
        to: stranger_address.clone(),
        from: stranger_address.clone(),
        from_pubkey: Some(pubkey_hex(stranger.inner())),
        from_sig: None,
        nonce: "00112233445566778899aabb".to_string(),
        ciphertext: "deadbeef".to_string(),
        sent_at: chrono::Utc::now().to_rfc3339(),
    };
    let digest = dust_whisper::messenger_auth::envelope_auth_digest(&envelope);
    envelope.from_sig = Some(hex::encode(stranger.inner().do_sign(&digest)));
    let body = serde_json::to_string(&MessengerSendRequest {
        envelope: envelope.clone(),
    })
    .expect("send request json");
    let refusal = http_request(
        &target,
        &format!(
            "POST {MESSENGER_SEND_PATH} HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .expect("the relay answered the stranger");
    println!("\n== 4. A STRANGER ON THAT NETWORK, WITH A REAL KEY ==");
    println!("stranger address          {stranger_address}");
    println!(
        "posts a signed envelope   {}",
        refusal.lines().last().unwrap_or("")
    );
    assert!(
        refusal.contains("\"ok\":false"),
        "a relay named for two people accepted a stranger's envelope: {refusal}"
    );
    assert!(
        refusal.contains("only for the addresses its operator listed"),
        "the relay refused the stranger for the wrong reason: {refusal}"
    );

    // -- 5. The guest points at the host, and messages go both ways. --------
    set_relay(&guest, &shared_url, false);
    let guest_report = relay_endpoint(&guest);
    println!("\n== 5. THE GUEST POINTS AT THE HOST ==");
    println!("guest relay_urls   {}", guest_report["relay_urls"]);
    println!("guest hosting      {}", guest_report["hosting"]);
    assert_eq!(
        guest_report["hosting"],
        json!(false),
        "the guest must not be hosting anything: {guest_report}"
    );
    let health = invoke(&guest, "wallet_whisper_relay_health", json!({}));
    assert_eq!(
        health[0]["online"],
        json!(true),
        "the guest cannot see the host's relay: {health}"
    );

    // Opening message. Nothing anywhere holds a key for the guest yet, and this
    // relay has never seen the guest send, so it is v1 and says so.
    let opening = invoke(
        &host,
        "messenger_send",
        json!({ "peer": guest_address, "body": HOST_FIRST }),
    );
    assert_eq!(opening["delivered"], json!(true), "{opening}");
    assert_eq!(
        opening["delivered_via"],
        json!(own_url),
        "the host's own send went somewhere other than the host's own relay: {opening}"
    );
    assert_eq!(opening["sealed"], json!(false), "{opening}");

    let guest_poll = invoke(&guest, "messenger_poll_inbox", json!({}));
    assert_eq!(guest_poll["added"], json!(1), "{guest_poll}");
    let guest_sees = invoke(
        &guest,
        "messenger_messages",
        json!({ "peer": host_address }),
    );
    assert_eq!(body_of(&guest_sees, 0), HOST_FIRST);

    // The reply. The guest's wallet learned the host's key off that envelope,
    // so this one is sealed with ECDH to a key only the host's secret opens.
    let reply = invoke(
        &guest,
        "messenger_send",
        json!({ "peer": host_address, "body": GUEST_REPLY }),
    );
    assert_eq!(reply["delivered"], json!(true), "{reply}");
    assert_eq!(
        reply["sealed"],
        json!(true),
        "the reply is not sealed: {reply}"
    );
    assert_eq!(
        reply["delivered_via"],
        json!(shared_url),
        "the guest's message did not go to the host's relay: {reply}"
    );

    let host_poll = invoke(&host, "messenger_poll_inbox", json!({}));
    assert_eq!(host_poll["added"], json!(1), "{host_poll}");
    let host_sees = invoke(
        &host,
        "messenger_messages",
        json!({ "peer": guest_address }),
    );
    assert_eq!(body_of(&host_sees, 1), GUEST_REPLY);

    // And back the other way, sealed now that the host holds the guest's key.
    let sealed_back = invoke(
        &host,
        "messenger_send",
        json!({ "peer": guest_address, "body": HOST_SEALED }),
    );
    assert_eq!(sealed_back["delivered"], json!(true), "{sealed_back}");
    assert_eq!(
        sealed_back["sealed"],
        json!(true),
        "the host's second message is not sealed: {sealed_back}"
    );
    let guest_poll2 = invoke(&guest, "messenger_poll_inbox", json!({}));
    assert_eq!(guest_poll2["added"], json!(1), "{guest_poll2}");
    let guest_sees2 = invoke(
        &guest,
        "messenger_messages",
        json!({ "peer": host_address }),
    );
    assert_eq!(body_of(&guest_sees2, 2), HOST_SEALED);

    println!("\n== 6. A SEALED MESSAGE EACH WAY, THROUGH A RELAY NEITHER RENTED ==");
    println!(
        "host  -> guest  {}  sealed {}",
        HOST_FIRST, opening["sealed"]
    );
    println!(
        "guest -> host   {}  sealed {}",
        GUEST_REPLY, reply["sealed"]
    );
    println!(
        "host  -> guest  {}  sealed {}",
        HOST_SEALED, sealed_back["sealed"]
    );
    println!("accepted by     host: {}", opening["delivered_via"]);
    println!("accepted by     guest: {}", reply["delivered_via"]);

    // -- 7. The trap, what closed most of it, and what is left. -------------
    // The guest turns on their own relay and leaves it above the host's, which
    // is exactly what happens to somebody who adds a friend's address underneath
    // the line their Privacy screen came with. A send stops at the first relay
    // that accepts, and the relay on your own machine always used to accept.
    //
    // It does not any more, and that is worth stating precisely rather than
    // celebrating. The guest's own relay now carries mail only for the
    // addresses the guest named, and the guest named nobody, so it serves the
    // guest's own address and nothing else. A message ADDRESSED TO THE HOST is
    // refused by it and the send falls through to the host's relay, which is
    // where it was supposed to go. Default deny closed the common shape of this
    // trap as a side effect of being default deny.
    let guest_port = free_port();
    let guest_own = format!("http://127.0.0.1:{guest_port}");
    set_whisper(
        &guest,
        json!({
            "enabled": true,
            "relay_urls": [guest_own, shared_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
        }),
    );
    let fell_through = invoke(
        &guest,
        "messenger_send",
        json!({ "peer": host_address, "body": TRAPPED }),
    );
    let host_poll2 = invoke(&host, "messenger_poll_inbox", json!({}));
    let trap_report = relay_endpoint(&guest);

    println!("\n== 7a. THE OWN RELAY ON TOP, AND IT NO LONGER SWALLOWS ==");
    println!("guest relay list   {}", trap_report["relay_urls"]);
    println!("guest own_url      {}", trap_report["own_url"]);
    println!("guest serves       {}", trap_report["served_addresses"]);
    println!("delivered          {}", fell_through["delivered"]);
    println!("delivered_via      {}", fell_through["delivered_via"]);
    println!("host poll after it {host_poll2}");

    assert_eq!(
        trap_report["served_addresses"],
        json!([guest_address]),
        "the guest's own relay carries mail for somebody the guest never named: {trap_report}"
    );
    assert_eq!(fell_through["delivered"], json!(true));
    assert_eq!(
        fell_through["delivered_via"],
        json!(shared_url),
        "the guest's own relay accepted mail for an address it does not carry: {fell_through}"
    );
    assert_eq!(
        host_poll2["added"],
        json!(1),
        "the message did not reach the host after falling through: {host_poll2}"
    );

    // What is LEFT of the trap, and it is why `firstAcceptWarning` stays.
    // Default deny closed the trap for a peer your own relay does not carry.
    // Two friends who host for each other both name each other, and then each
    // one's own relay DOES accept mail for the other - so the order of the list
    // is load bearing again, and the message stops on the sender's own machine
    // where the recipient cannot collect it.
    set_whisper(
        &guest,
        json!({
            "enabled": true,
            "relay_urls": [guest_own, shared_url],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
            "relay_allowlist": [host_address.clone()],
        }),
    );
    let trapped = invoke(
        &guest,
        "messenger_send",
        json!({ "peer": host_address, "body": TRAPPED }),
    );
    let host_poll3 = invoke(&host, "messenger_poll_inbox", json!({}));
    let trap_report = relay_endpoint(&guest);

    println!("\n== 7b. THE TRAP THAT IS LEFT: BOTH OF THEM NAMED EACH OTHER ==");
    println!("guest serves       {}", trap_report["served_addresses"]);
    println!("delivered          {}", trapped["delivered"]);
    println!("delivery_error     {}", trapped["delivery_error"]);
    println!("delivered_via      {}", trapped["delivered_via"]);
    println!("host poll after it {host_poll3}");

    assert_eq!(
        trap_report["served_addresses"],
        json!([guest_address, host_address]),
        "the report does not show who the guest's own relay is now for: {trap_report}"
    );
    assert_eq!(
        trapped["delivered"],
        json!(true),
        "the relay on the guest's own machine did accept it, which is the trap"
    );
    assert_eq!(
        trapped["delivered_via"],
        json!(guest_own),
        "the field that makes the trap visible is wrong: {trapped}"
    );
    assert_eq!(
        host_poll3["added"],
        json!(0),
        "the host received a message that stopped at the guest's own relay: {host_poll3}"
    );
    // The report the screens read carries the list IN ORDER and the wallet's own
    // relay URL, which is everything `firstAcceptWarning` in
    // apps/desktop/src/relayReach.ts needs to raise the warning.
    assert_eq!(
        trap_report["relay_urls"],
        json!([guest_own, shared_url]),
        "the endpoint report lost the order of the relay list: {trap_report}"
    );
    assert_eq!(trap_report["own_url"], json!(guest_own), "{trap_report}");
    assert_eq!(trap_report["serving"], json!(true), "{trap_report}");

    // Put it back the way section 0 step 4 says, and the same message goes.
    set_whisper(
        &guest,
        json!({
            "enabled": true,
            "relay_urls": [shared_url, guest_own],
            "fallback_direct": false,
            "auto_start_relay": true,
            "relay_bind": "loopback",
            // Still naming the host, so this is the order changing and nothing
            // else: the same wallet that swallowed the last message.
            "relay_allowlist": [host_address.clone()],
        }),
    );
    let untrapped = invoke(
        &guest,
        "messenger_send",
        json!({ "peer": host_address, "body": TRAPPED }),
    );
    let host_poll3 = invoke(&host, "messenger_poll_inbox", json!({}));
    println!("\n== 8. THE SAME TWO URLS, THE OTHER WAY ROUND ==");
    println!("guest relay list   {}", json!([shared_url, guest_own]));
    println!("delivered_via      {}", untrapped["delivered_via"]);
    println!("host poll          {host_poll3}");
    assert_eq!(untrapped["delivered_via"], json!(shared_url), "{untrapped}");
    assert_eq!(
        host_poll3["added"],
        json!(1),
        "order was the whole difference and the message still did not arrive: {host_poll3}"
    );
    assert!(
        first_accept_warning_is_reachable(),
        "the screens' warning for this configuration is gone from the shipped source"
    );
}

/// The sentence the screens raise for the configuration act 7 produces.
///
/// This run stops at Tauri IPC and cannot execute the TypeScript above it, so
/// the report it just asserted on is only useful if a screen still reads it.
/// `apps/desktop/src/relayReach.test.ts` holds what the sentence says; this
/// holds that it exists and that both screens render it.
fn first_accept_warning_is_reachable() -> bool {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf();
    let read = |relative: &str| {
        std::fs::read_to_string(repo.join(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"))
    };
    read("apps/desktop/src/relayReach.ts").contains("export function firstAcceptWarning")
        && read("apps/desktop/src/screens/PrivacyScreen.tsx").contains("firstAcceptWarning")
        && read("apps/desktop/src/screens/MessagesScreen.tsx").contains("firstAcceptWarning")
}
