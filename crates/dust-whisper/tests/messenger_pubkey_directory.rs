//! What the key directory serves, driven through the shipped router.
//!
//! The relay has always been handed `from_pubkey` on every envelope, checked it
//! against `from`, stored it, and thrown it away when the envelope was
//! collected. The directory keeps the last one it saw per address so a wallet
//! with nothing to seal to can ask for a key instead of sending the first
//! message of a conversation under v1, whose key is a hash of the two addresses
//! printed in clear on the same envelope.
//!
//! The relay is not trusted about any of this. The sending wallet re-derives
//! the address from whatever comes back
//! (`wallet-core/src/messenger_crypto.rs::verified_peer_pubkey`) and discards
//! it unless it matches. These tests are about the other half: that an honest
//! relay serves something true, that it serves nothing for an address it has
//! never seen, and that it cannot be made to hold an entry whose key does not
//! derive to its own address.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::routing::any;
use dust_whisper::error::WhisperError;
use dust_whisper::messenger_auth::envelope_auth_digest;
use dust_whisper::messenger_client::{fetch_peer_pubkey, send_envelope};
use dust_whisper::protocol::{MESSENGER_PUBKEY_PATH, MessengerEnvelope};
use dust_whisper::relay::{build_router, relay_state_from_secret};
use reqwest::Client;
use sys::Account;
use tokio::task::JoinHandle;

/// The budget a real send gives one relay (`PEER_KEY_RELAY_TIMEOUT`,
/// `crates/wallet-core/src/messenger.rs`). Used here so these tests wait no
/// longer for an answer than a person pressing Send does.
const ASK: Duration = Duration::from_secs(3);

async fn ask(
    http: &Client,
    url: &str,
    address: &str,
) -> dust_whisper::error::WhisperResult<Option<String>> {
    fetch_peer_pubkey(http, url, address, ASK).await
}

async fn spawn_relay() -> (String, JoinHandle<()>) {
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn signed_envelope(to: &str, sender: &Account, id: &str) -> MessengerEnvelope {
    let mut env = MessengerEnvelope {
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
    env.from_sig = Some(hex::encode(sender.do_sign(&envelope_auth_digest(&env))));
    env
}

/// True when this public key really is the key that address was derived from.
///
/// The same check the sending wallet makes, restated here so this file proves
/// what it serves rather than only that it serves a string.
fn derives_to(pubkey_hex: &str, address: &str) -> bool {
    let bytes = hex::decode(pubkey_hex).expect("hex");
    let pk: [u8; 33] = bytes.try_into().expect("33 bytes");
    dust_whisper::messenger_auth::pubkey_matches_address(&pk, address)
}

#[tokio::test]
async fn the_relay_serves_the_key_it_saw_and_nothing_for_an_address_it_has_not() {
    let (url, relay) = spawn_relay().await;
    let http = Client::new();

    let bob = Account::create_by("directory-bob").unwrap();
    let carol = Account::create_by("directory-carol").unwrap();
    let bob_addr = bob.readable().to_string();
    let carol_addr = carol.readable().to_string();

    // Nobody has sent anything yet, so there is nothing to serve about either.
    for who in [&bob_addr, &carol_addr] {
        assert_eq!(
            ask(&http, &url, who).await.unwrap(),
            None,
            "the relay answered with a key for an address it has never seen send"
        );
    }

    // Bob sends one message to Carol. That is the only thing that teaches this
    // relay anything, and it is a thing it was already being handed.
    send_envelope(&http, &url, signed_envelope(&carol_addr, &bob, "bob-1"))
        .await
        .expect("the relay accepts a well-formed envelope");

    let served = ask(&http, &url, &bob_addr)
        .await
        .unwrap()
        .expect("the relay saw Bob send, so it has a key for him");
    assert!(
        derives_to(&served, &bob_addr),
        "the relay served a key that does not derive to the address it was asked about"
    );
    assert_eq!(
        served,
        hex::encode(bob.public_key().serialize_compressed()),
        "the relay served something other than the key it was handed"
    );

    // Carol has still only RECEIVED. Receiving teaches the relay nothing about
    // her key, and the directory must not invent one.
    assert_eq!(
        ask(&http, &url, &carol_addr).await.unwrap(),
        None,
        "the relay answered with a key for somebody who has only ever received"
    );

    relay.abort();
}

/// An envelope the relay refused must not leave a directory entry behind, and
/// nothing that is not a claimable Hacash address may ever be answered for.
#[tokio::test]
async fn a_refused_envelope_and_an_unclaimable_address_leave_the_directory_empty() {
    let (url, relay) = spawn_relay().await;
    let http = Client::new();

    let mallory = Account::create_by("directory-mallory").unwrap();
    let victim = Account::create_by("directory-victim").unwrap();
    let mallory_addr = mallory.readable().to_string();

    // Signed by the wrong key: `from` says Mallory, the signature is the
    // victim's. The send endpoint refuses this, and the directory must learn
    // nothing from an envelope the relay would not store.
    let mut forged = signed_envelope(victim.readable(), &mallory, "forged-1");
    forged.from_sig = Some(hex::encode(victim.do_sign(&envelope_auth_digest(&forged))));
    assert!(
        send_envelope(&http, &url, forged).await.is_err(),
        "the relay accepted an envelope that was not signed by the key its sender derives from"
    );
    assert_eq!(
        ask(&http, &url, &mallory_addr).await.unwrap(),
        None,
        "a refused envelope taught the directory a key anyway"
    );

    // An address no key could ever sign for is refused before the table is
    // touched, so the directory cannot be probed with invented names.
    let contract = field::Address::create_contract([9u8; 20]).to_readable();
    for junk in [contract.as_str(), "not-an-address", "   "] {
        assert_eq!(
            ask(&http, &url, junk).await.unwrap(),
            None,
            "the relay answered a directory lookup for {junk:?}"
        );
    }

    relay.abort();
}

/// The last key seen, not the first. An address that rotates its key (a new
/// wallet from the same seed is not this, but a person moving is) must not be
/// pinned to a stale one by this relay.
///
/// There is only one key per address, because the address IS the hash of the
/// key, so "rotating" means a different address. What this actually pins is
/// that the entry is overwritten rather than kept, which is what makes the
/// table bounded per address instead of growing.
#[tokio::test]
async fn a_second_send_from_the_same_address_replaces_rather_than_adds() {
    let (url, relay) = spawn_relay().await;
    let http = Client::new();

    let bob = Account::create_by("directory-repeat-bob").unwrap();
    let carol = Account::create_by("directory-repeat-carol").unwrap();
    let bob_addr = bob.readable().to_string();
    let carol_addr = carol.readable().to_string();

    for id in ["bob-a", "bob-b", "bob-c"] {
        send_envelope(&http, &url, signed_envelope(&carol_addr, &bob, id))
            .await
            .expect("accepted");
    }
    let served = ask(&http, &url, &bob_addr)
        .await
        .unwrap()
        .expect("a key for Bob");
    assert_eq!(
        served,
        hex::encode(bob.public_key().serialize_compressed()),
        "three sends from one address produced something other than that address's key"
    );
    assert!(derives_to(&served, &bob_addr));

    relay.abort();
}

/// What a hostile or careless relay is handed, and what it can spend.
///
/// The three tests below are not about the answer at all - a wrong answer is
/// already discarded by the wallet, which is the point of the whole design.
/// They are about the three things a relay gets for free by being asked: the
/// address in a place that gets logged, the wallet's memory, and the wallet's
/// time.
struct Probe {
    seen: Arc<Mutex<Vec<(String, String, String)>>>,
}

/// A stand-in relay that answers the lookup however the test tells it to, and
/// records the method, the full URI and the body it was asked with.
async fn spawn_probe(
    reply: &'static str,
    stall: Option<Duration>,
) -> (String, Probe, JoinHandle<()>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let app = Router::new().fallback(any(
        move |method: axum::http::Method, uri: axum::http::Uri, body: String| {
            let recorder = recorder.clone();
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push((method.to_string(), uri.to_string(), body));
                if let Some(d) = stall {
                    tokio::time::sleep(d).await;
                }
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    reply,
                )
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), Probe { seen }, handle)
}

/// The address asked about must not travel anywhere that gets written down by
/// default.
///
/// A query string lands in the access log of every relay asked and of every
/// proxy in front of them, and the relays asked are not only the one that ends
/// up carrying the message. The send path already posts its address in a body.
/// This one does too.
#[tokio::test]
async fn the_address_asked_about_is_never_put_in_the_url() {
    let (url, probe, relay) = spawn_probe(r#"{"pubkey":null}"#, None).await;
    let http = Client::new();

    let bob = Account::create_by("directory-url-bob").unwrap();
    let bob_addr = bob.readable().to_string();
    assert_eq!(ask(&http, &url, &bob_addr).await.unwrap(), None);

    let seen = probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "the lookup made more than one request");
    let (method, uri, body) = &seen[0];
    assert_eq!(method, "POST", "the lookup was not a POST");
    assert_eq!(
        uri, MESSENGER_PUBKEY_PATH,
        "the lookup carried a query string"
    );
    assert!(
        !uri.contains(&bob_addr),
        "the address asked about appeared in the request line: {uri}"
    );
    assert!(
        body.contains(&bob_addr),
        "the address was not in the request body either, so nothing was asked"
    );

    relay.abort();
}

/// A relay cannot spend this wallet's memory by answering with something
/// enormous.
///
/// A real answer is 66 characters of hex inside a small object. Before the cap
/// the answer was parsed with `resp.json()`, which reads whatever arrives.
#[tokio::test]
async fn an_answer_larger_than_the_cap_is_refused_rather_than_read() {
    // Well-formed JSON, valid hex, and far past anything a key could be.
    let huge: &'static str =
        Box::leak(format!(r#"{{"pubkey":"{}"}}"#, "ab".repeat(64 * 1024)).into_boxed_str());
    let (url, _probe, relay) = spawn_probe(huge, None).await;
    let http = Client::new();

    let bob = Account::create_by("directory-huge-bob").unwrap();
    let err = ask(&http, &url, bob.readable())
        .await
        .expect_err("a 128 KiB answer was read instead of refused");
    match err {
        WhisperError::Relay(msg) => assert!(
            msg.contains("more than this wallet will read")
                || msg.contains("longer than this wallet will read"),
            "refused for the wrong reason: {msg}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }

    relay.abort();
}

/// A relay that accepts the connection and never answers costs the lookup's own
/// short budget, not the shared client's twenty seconds.
///
/// This is the finding that mattered most in review: three relays behaving this
/// way put a full minute in front of a person pressing Send, on the first
/// message of every conversation, repeated on every message until the peer
/// wrote back.
#[tokio::test]
async fn a_relay_that_never_answers_costs_only_the_lookups_own_budget() {
    let (url, _probe, relay) =
        spawn_probe(r#"{"pubkey":null}"#, Some(Duration::from_secs(120))).await;
    let http = Client::new();

    let bob = Account::create_by("directory-stall-bob").unwrap();
    let started = Instant::now();
    let outcome = ask(&http, &url, bob.readable()).await;
    let took = started.elapsed();

    assert!(
        outcome.is_err(),
        "a relay that never answered was treated as an answer"
    );
    assert!(
        took < ASK * 2,
        "the lookup waited {took:?} on a relay that never answered, with a {ASK:?} budget"
    );

    relay.abort();
}
