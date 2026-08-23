//! THE MAILBOX THAT COULD NOT BE EMPTIED, THROUGH THE COMMANDS THAT EMPTY IT.
//!
//! # What used to happen
//!
//! Two hundred correctly signed envelopes, which is ten free keypairs at the
//! relay's per-sender share, each carrying a body no key on earth could open.
//! The relay accepted every one, because every one really was signed by the key
//! its `from` address derives from, which is all the relay is asked to check.
//!
//! The wallet's poll then hit its decrypt-failure arm, which was a bare
//! `continue`: no ack, no count. So the junk was never removed, was re-fetched
//! on every poll for the relay's whole seven-day TTL, and held the inbox at the
//! relay's per-recipient cap. Every correspondent whose mail the owner had
//! already collected was refused with "inbox full", because collecting your mail
//! releases your slots and a sender holding none in a full inbox is refused by
//! design. The owner's own screen reported a healthy poll of an empty mailbox,
//! and none of the six messenger commands could delete, block or ack anything.
//!
//! # What this file drives
//!
//! A real relay started by the settings command the desktop Settings screen
//! invokes, two real wallets entered through Tauri IPC at the command names in
//! `apps/desktop/src/api.ts`, and an attacker who is nothing more than an HTTP
//! client posting straight at the relay's public send endpoint. Nothing here
//! calls `hacash_wallet_core::messenger` to make a wallet act.
//!
//! Everything is loopback and no chain is contacted: every shell's node URL
//! points at a port nothing listens on.

#![cfg(feature = "desktop")]

use std::path::{Path, PathBuf};

use dust_whisper::protocol::{MESSENGER_SEND_PATH, MessengerEnvelope, MessengerSendRequest};
use hacash_wallet_core::WalletService;
use serde_json::{Value, json};
use sys::Account;
use tauri::test::MockRuntime;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};
use wallet_tauri_common::AppState;

const PASSPHRASE_A: &str = "wedged inbox alpha 5512";
const PASSPHRASE_B: &str = "wedged inbox bravo 7734";

/// The relay's own ceilings (`MAX_PER_RECIPIENT` and `MAX_PER_SENDER`,
/// `crates/dust-whisper/src/messenger_relay.rs`). Not public, so restated here.
const MAX_PER_RECIPIENT: usize = 200;
const MAX_PER_SENDER: usize = 20;

struct Shell {
    who: &'static str,
    root: PathBuf,
    _app: tauri::App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
}

/// See the same note in `messenger_two_wallets_one_relay.rs`: the wallet data
/// root is process-global, so two wallets in one process take turns. Single
/// threaded flow, one shell acting at a time.
fn enter(root: &Path) {
    // SAFETY: single-threaded test flow, and only one shell acts at a time.
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
            wallet_tauri_common::whisper_commands::messenger_messages,
            wallet_tauri_common::whisper_commands::messenger_send,
            wallet_tauri_common::whisper_commands::messenger_poll_inbox,
            wallet_tauri_common::desktop_commands::wallet_update_dust_whisper_settings_desktop,
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

fn invoke(shell: &Shell, cmd: &str, args: Value) -> Value {
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
    .unwrap_or_else(|error| panic!("{} invoked {cmd} and it failed: {error}", shell.who))
}

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

/// Junk that every check the relay makes will pass: a real key, a real
/// signature over the real envelope, a fresh timestamp, and a body that is
/// simply not a message to anybody.
fn signed_junk(sender: &Account, to: &str, seed: u32) -> MessengerEnvelope {
    let mut env = MessengerEnvelope {
        v: 1,
        id: format!("junk-{seed:04}"),
        to: to.to_string(),
        from: sender.readable().to_string(),
        from_pubkey: Some(hex::encode(sender.public_key().serialize_compressed())),
        from_sig: None,
        nonce: "000102030405060708090a0b".to_string(),
        ciphertext: hex::encode(vec![(seed % 251) as u8; 96]),
        sent_at: chrono::Utc::now().to_rfc3339(),
    };
    let digest = dust_whisper::messenger_auth::envelope_auth_digest(&env);
    env.from_sig = Some(hex::encode(sender.do_sign(&digest)));
    env
}

/// Post straight at the relay's public send endpoint, which is all an attacker
/// needs and all they have.
fn post_envelope(relay_url: &str, envelope: &MessengerEnvelope) -> Value {
    let body = serde_json::to_vec(&MessengerSendRequest {
        envelope: envelope.clone(),
    })
    .expect("send request");
    let url = format!("{relay_url}{MESSENGER_SEND_PATH}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let text = reqwest::Client::new()
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("relay reachable")
            .text()
            .await
            .expect("relay body");
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    })
}

#[test]
fn a_flood_of_unreadable_mail_does_not_shut_an_inbox_and_the_owner_is_told() {
    let node_url = format!("http://127.0.0.1:{}", free_port());
    let operator_dir = tempfile::tempdir().expect("operator dir");
    let alice_dir = tempfile::tempdir().expect("alice dir");
    let bob_dir = tempfile::tempdir().expect("bob dir");
    let operator_root = operator_dir.path().join("wallet-data");
    let alice_root = alice_dir.path().join("wallet-data");
    let bob_root = bob_dir.path().join("wallet-data");
    for root in [&operator_root, &alice_root, &bob_root] {
        std::fs::create_dir_all(root).expect("wallet root");
    }

    // -- 1. A relay on somebody else's machine. -----------------------------
    let relay_port = free_port();
    let relay_url = format!("http://127.0.0.1:{relay_port}");
    let operator = open_shell("the relay operator", &operator_root, &node_url);
    set_relay(&operator, &relay_url, true);
    println!("\n== 1. THE RELAY ==");
    println!("started by wallet_update_dust_whisper_settings_desktop -> sync_managed_relay");
    println!("listening on  {relay_url}");

    // -- 2. Two wallets that already talk to each other. --------------------
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
    set_relay(&alice, &relay_url, false);
    set_relay(&bob, &relay_url, false);
    println!("\n== 2. TWO WALLETS ==");
    println!("Alice {alice_address}");
    println!("Bob   {bob_address}");

    let sent = invoke(
        &alice,
        "messenger_send",
        json!({ "peer": bob_address, "body": "morning" }),
    );
    assert_eq!(sent["delivered"], json!(true), "first message: {sent}");
    let collected = invoke(&bob, "messenger_poll_inbox", json!({}));
    assert_eq!(
        collected["added"],
        json!(1),
        "Bob's first poll: {collected}"
    );
    println!("Alice writes, Bob collects: {collected}");
    println!("Bob has now released Alice's slot, which is what the attack needs.");

    // -- 3. The flood. Ten free keypairs, an HTTP client, nothing else. -----
    let flooders: Vec<Account> = (0..(MAX_PER_RECIPIENT / MAX_PER_SENDER))
        .map(|i| Account::create_by(&format!("wedge-flooder-{i}")).expect("key"))
        .collect();
    let mut accepted = 0usize;
    let mut seed = 0u32;
    for flooder in &flooders {
        for _ in 0..MAX_PER_SENDER {
            let answer = post_envelope(&relay_url, &signed_junk(flooder, &bob_address, seed));
            if answer["ok"] == json!(true) {
                accepted += 1;
            }
            seed += 1;
        }
    }
    println!("\n== 3. THE FLOOD ==");
    println!(
        "{} keypairs x {MAX_PER_SENDER} correctly signed envelopes of noise, {accepted} accepted",
        flooders.len()
    );
    assert_eq!(
        accepted, MAX_PER_RECIPIENT,
        "the relay was supposed to take these; every one is properly signed"
    );

    // -- 4. Alice is locked out, and is told why. ---------------------------
    let blocked = invoke(
        &alice,
        "messenger_send",
        json!({ "peer": bob_address, "body": "are you there" }),
    );
    println!("\n== 4. ALICE WRITES INTO A FULL MAILBOX ==");
    println!(
        "delivered {}  delivery_error {}",
        blocked["delivered"], blocked["delivery_error"]
    );
    assert_eq!(
        blocked["delivered"],
        json!(false),
        "the inbox is full of junk, so this cannot have gone: {blocked}"
    );
    assert_eq!(
        blocked["delivery_error"],
        json!("inbox full"),
        "the relay said why and the person has to be told: {blocked}"
    );

    // -- 5. Bob polls. The junk is counted, and cleared. --------------------
    let poll = invoke(&bob, "messenger_poll_inbox", json!({}));
    println!("\n== 5. BOB CHECKS HIS MAIL ==");
    println!("poll {poll}");
    assert_eq!(
        poll["added"],
        json!(0),
        "there was nothing readable: {poll}"
    );
    assert_eq!(
        poll["undecryptable"],
        json!(MAX_PER_RECIPIENT),
        "the junk has to be counted, or the screen says 'nothing new': {poll}"
    );

    let second = invoke(&bob, "messenger_poll_inbox", json!({}));
    println!("poll again {second}");
    assert_eq!(
        second["undecryptable"],
        json!(0),
        "the junk was left on the relay, which is exactly the wedge: {second}"
    );

    // -- 6. And the mailbox works again. ------------------------------------
    let after = invoke(
        &alice,
        "messenger_send",
        json!({ "peer": bob_address, "body": "are you there" }),
    );
    println!("\n== 6. AFTER ==");
    println!("Alice sends again: delivered {}", after["delivered"]);
    assert_eq!(
        after["delivered"],
        json!(true),
        "Bob is still deaf to the person he was talking to: {after}"
    );
    let final_poll = invoke(&bob, "messenger_poll_inbox", json!({}));
    assert_eq!(final_poll["added"], json!(1), "Bob's poll: {final_poll}");
    let messages = invoke(&bob, "messenger_messages", json!({ "peer": alice_address }));
    let bodies: Vec<&str> = messages
        .as_array()
        .expect("messages")
        .iter()
        .map(|m| m["body"].as_str().expect("body"))
        .collect();
    println!("Bob reads {bodies:?}");
    assert_eq!(bodies, vec!["morning", "are you there"]);
    println!(
        "\nThe flood cost the attacker 200 posts and bought a delay until one poll,\n\
         which is spam. It used to buy seven days of silence, renewable forever."
    );
}
