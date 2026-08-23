//! What a stranger with an HTTP client can do to a relay, and to the people on it.
//!
//! Everything here is driven through the shipped router
//! (`dust_whisper::relay::build_router`) over a real socket, which is the same
//! door `docs/RUNNING-A-RELAY.md` tells an operator to open. None of it needs a
//! wallet, a relay operator's cooperation, or a single stolen key: the whole
//! point is that these were free.
//!
//! Each test names the thing that used to work.

use std::net::SocketAddr;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::messenger_auth::{envelope_auth_digest, inbox_auth_digest};
use dust_whisper::messenger_client::{fetch_challenge, fetch_inbox, send_envelope};
use dust_whisper::protocol::{MessengerEnvelope, MessengerInboxRequest};
use dust_whisper::relay::{build_router, relay_state_from_secret};
use reqwest::Client;
use sys::Account;
use tokio::task::JoinHandle;

/// One sender's share of one inbox (`MAX_PER_SENDER`, messenger_relay.rs).
const MAX_PER_SENDER: usize = 20;

async fn spawn_relay() -> (String, JoinHandle<()>) {
    let (sk, _pk) = generate_relay_keypair();
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn sign(mut env: MessengerEnvelope, sender: &Account) -> MessengerEnvelope {
    env.from_sig = Some(hex::encode(sender.do_sign(&envelope_auth_digest(&env))));
    env
}

fn envelope_for(to: &str, sender: &Account, id: &str) -> MessengerEnvelope {
    sign(
        MessengerEnvelope {
            v: 1,
            id: id.to_string(),
            to: to.to_string(),
            from: sender.readable().to_string(),
            from_pubkey: Some(hex::encode(sender.public_key().serialize_compressed())),
            from_sig: None,
            nonce: "00112233445566778899aabb".to_string(),
            ciphertext: "deadbeef".to_string(),
            sent_at: Utc::now().to_rfc3339(),
        },
        sender,
    )
}

async fn read_inbox(http: &Client, relay_url: &str, owner: &Account) -> Vec<MessengerEnvelope> {
    let addr = owner.readable().to_string();
    let challenge = fetch_challenge(http, relay_url, &addr).await.unwrap();
    let digest = inbox_auth_digest(&addr, &challenge.nonce);
    let resp = fetch_inbox(
        http,
        relay_url,
        &MessengerInboxRequest {
            to: addr,
            claimant_pubkey: hex::encode(owner.public_key().serialize_compressed()),
            nonce: challenge.nonce,
            signature: hex::encode(owner.do_sign(&digest)),
        },
    )
    .await
    .unwrap();
    assert!(resp.auth_ok, "the owner's own claim must authenticate");
    resp.messages
}

/// Deleting somebody's mail with bytes copied off the wire.
///
/// The attacker holds no key and forges nothing. They copied ONE genuine
/// envelope from an unencrypted hop and posted it again. Because a replay
/// carries the real sender's real signature, the per-sender cap charged every
/// copy to the real sender, and twenty replays of one captured envelope evicted
/// twenty of that sender's genuine, undelivered messages. The cap built to stop
/// flooding was the mechanism doing the deleting.
#[tokio::test]
async fn a_replayed_envelope_cannot_delete_the_senders_mail() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("replay-victim").unwrap();
    let friend = Account::create_by("replay-friend").unwrap();
    let victim_addr = victim.readable().to_string();

    let mut first: Option<MessengerEnvelope> = None;
    for i in 0..MAX_PER_SENDER {
        let env = envelope_for(&victim_addr, &friend, &format!("real-{i:02}"));
        if first.is_none() {
            first = Some(env.clone());
        }
        send_envelope(&http, &relay_url, env).await.unwrap();
    }
    let captured = first.expect("one envelope off the wire");

    // Everything a passive eavesdropper on an unencrypted hop has: the exact
    // bytes. Not one of these may be accepted.
    let mut refused = 0usize;
    for _ in 0..MAX_PER_SENDER {
        if send_envelope(&http, &relay_url, captured.clone())
            .await
            .is_err()
        {
            refused += 1;
        }
    }
    assert_eq!(
        refused, MAX_PER_SENDER,
        "the relay accepted a replay of an envelope it was already holding"
    );

    let inbox = read_inbox(&http, &relay_url, &victim).await;
    assert_eq!(
        inbox.len(),
        MAX_PER_SENDER,
        "the replays cost the genuine sender {} of their messages",
        MAX_PER_SENDER - inbox.len()
    );
    let mut ids: Vec<&str> = inbox.iter().map(|e| e.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        MAX_PER_SENDER,
        "the inbox holds duplicates: {ids:?}"
    );

    relay.abort();
}

/// A captured envelope has a shelf life.
///
/// Dedup alone only covers a replay while the original is still in the inbox.
/// `sent_at` is inside `envelope_auth_digest`, so nobody but the sender can
/// choose it, which makes the relay's freshness window a real bound on how long
/// copied bytes stay useful.
#[tokio::test]
async fn an_envelope_older_than_the_window_is_refused() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("stale-victim").unwrap();
    let friend = Account::create_by("stale-friend").unwrap();
    let victim_addr = victim.readable().to_string();

    let stale = sign(
        MessengerEnvelope {
            v: 1,
            id: "stale-1".into(),
            to: victim_addr.clone(),
            from: friend.readable().to_string(),
            from_pubkey: Some(hex::encode(friend.public_key().serialize_compressed())),
            from_sig: None,
            nonce: "00112233445566778899aabb".into(),
            ciphertext: "deadbeef".into(),
            sent_at: (Utc::now() - ChronoDuration::hours(3)).to_rfc3339(),
        },
        &friend,
    );
    let err = send_envelope(&http, &relay_url, stale)
        .await
        .expect_err("a three hour old envelope must not be accepted");
    assert!(
        err.to_string().contains("older"),
        "the refusal has to say why: {err}"
    );

    let ahead = sign(
        MessengerEnvelope {
            v: 1,
            id: "ahead-1".into(),
            to: victim_addr.clone(),
            from: friend.readable().to_string(),
            from_pubkey: Some(hex::encode(friend.public_key().serialize_compressed())),
            from_sig: None,
            nonce: "00112233445566778899aabb".into(),
            ciphertext: "deadbeef".into(),
            sent_at: (Utc::now() + ChronoDuration::hours(3)).to_rfc3339(),
        },
        &friend,
    );
    assert!(
        send_envelope(&http, &relay_url, ahead).await.is_err(),
        "an envelope dated three hours ahead must not be accepted either"
    );

    // A message sent now, which is every honest message, still goes through.
    send_envelope(
        &http,
        &relay_url,
        envelope_for(&victim_addr, &friend, "fresh-1"),
    )
    .await
    .expect("an envelope sent now is accepted");
    assert_eq!(read_inbox(&http, &relay_url, &victim).await.len(), 1);

    relay.abort();
}

/// Parking a stranger's machine full of mail nobody can ever collect.
///
/// `to` was any non-empty string, and the per-sender share is per RECIPIENT, so
/// inventing recipients multiplied the cap instead of being bound by it: one
/// keypair, a loop, and 195 MiB resident on somebody else's computer. Nothing
/// ever pruned an inbox no key could claim, because pruning only happened on a
/// successful owner ack.
#[tokio::test]
async fn mail_can_only_be_left_for_an_address_a_key_could_collect() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();
    let sender = Account::create_by("invented-inbox-sender").unwrap();

    for invented in [
        "1NotAnAddressAtAllJustSo",
        "..........",
        "hello world",
        &"A".repeat(4000),
    ] {
        let env = envelope_for(invented, &sender, &format!("junk-{}", invented.len()));
        let err = send_envelope(&http, &relay_url, env)
            .await
            .expect_err("an invented recipient must be refused");
        assert!(
            err.to_string().contains("Hacash account address"),
            "the refusal has to say why: {err}"
        );
    }

    // A contract address decodes but has no signing key behind it, so nothing
    // addressed to one could ever be collected either.
    let contract = field::Address::create_contract([7u8; 20]).to_readable();
    assert!(
        send_envelope(
            &http,
            &relay_url,
            envelope_for(&contract, &sender, "to-a-contract"),
        )
        .await
        .is_err(),
        "a contract address has no inbox anybody can claim"
    );

    let real = Account::create_by("invented-inbox-real").unwrap();
    send_envelope(
        &http,
        &relay_url,
        envelope_for(real.readable(), &sender, "real-1"),
    )
    .await
    .expect("a real account address is still accepted");
    assert_eq!(read_inbox(&http, &relay_url, &real).await.len(), 1);

    relay.abort();
}

/// One envelope may not be a file transfer.
///
/// The only ceiling was the router's 512 KiB body limit, so a single sender
/// could park half a megabyte per envelope. A chat message is small.
#[tokio::test]
async fn an_oversized_body_is_refused() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();
    let victim = Account::create_by("oversize-victim").unwrap();
    let sender = Account::create_by("oversize-sender").unwrap();
    let victim_addr = victim.readable().to_string();

    let mut big = envelope_for(&victim_addr, &sender, "big-1");
    // 100 KiB of ciphertext, which the 512 KiB body limit was happy with.
    big.ciphertext = "ab".repeat(50 * 1024);
    let big = sign(big, &sender);
    assert!(
        send_envelope(&http, &relay_url, big).await.is_err(),
        "the relay accepted a 100 KiB ciphertext"
    );

    let mut ordinary = envelope_for(&victim_addr, &sender, "ordinary-1");
    ordinary.ciphertext = "ab".repeat(600);
    let ordinary = sign(ordinary, &sender);
    send_envelope(&http, &relay_url, ordinary)
        .await
        .expect("an ordinary message is still accepted");
    assert_eq!(read_inbox(&http, &relay_url, &victim).await.len(), 1);

    relay.abort();
}

/// Locking every inbox on the relay with unauthenticated GETs.
///
/// The challenge table was one global ceiling, and reaching it made
/// `issue_challenge` hand an EMPTY nonce to everybody. An empty nonce never
/// verifies, so 8320 requests that need no signature, no key and no proof of
/// anything refused every honest owner on the relay at once, and holding it
/// there cost about 68 requests a second.
///
/// The table is smaller in this test than the relay's own ceiling only in the
/// sense that this test does not need to fill it: the fix is that filling it
/// evicts the oldest outstanding challenge rather than refusing the newest
/// caller, and that one address can never hold more than its own share.
#[tokio::test]
async fn a_challenge_flood_cannot_lock_an_owner_out_of_their_own_inbox() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let owner = Account::create_by("challenge-flood-owner").unwrap();
    let friend = Account::create_by("challenge-flood-friend").unwrap();
    let owner_addr = owner.readable().to_string();
    send_envelope(
        &http,
        &relay_url,
        envelope_for(&owner_addr, &friend, "waiting-1"),
    )
    .await
    .unwrap();

    // The cheapest version of the attack: one address, asked for over and over.
    // This used to be free and unbounded; it now costs the attacker its own
    // share of the table and nothing else.
    for _ in 0..200 {
        let _ = fetch_challenge(&http, &relay_url, &owner_addr).await;
    }
    // And the wide version: thousands of distinct claimed addresses. 9000 is
    // past MAX_PENDING_CHALLENGES (8192), which is exactly where the old code
    // started handing out empty nonces.
    let started = Instant::now();
    for i in 0..9000u32 {
        let invented = Account::create_by(&format!("challenge-flood-{i}"))
            .unwrap()
            .readable()
            .to_string();
        let _ = fetch_challenge(&http, &relay_url, &invented).await;
    }
    let flooded_in = started.elapsed();

    let challenge = fetch_challenge(&http, &relay_url, &owner_addr)
        .await
        .expect("the owner can still ask for a challenge");
    assert!(
        !challenge.nonce.is_empty(),
        "the relay handed the owner an empty nonce after a flood of {flooded_in:?}, \
         which is a refusal wearing a challenge's clothes"
    );
    let inbox = read_inbox(&http, &relay_url, &owner).await;
    assert_eq!(
        inbox.len(),
        1,
        "the owner's own correctly signed claim was refused after a challenge flood"
    );

    relay.abort();
}
