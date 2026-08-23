//! What the per-sender cap does and does not protect, driven through the shipped
//! router rather than through the inbox struct.
//!
//! `docs/RUNNING-A-RELAY.md` sections 2 and 8 tell a relay operator what a flood
//! costs them and costs the people they serve. The answer is not one sentence,
//! and the shorter version that used to be in both that document and the comment
//! on `MAX_PER_SENDER` was wrong in the direction that matters. These two tests
//! are the two halves of the real answer, so the document can be checked instead
//! of believed.

use std::net::SocketAddr;

use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::messenger_auth::{envelope_auth_digest, inbox_auth_digest};
use dust_whisper::messenger_client::{fetch_challenge, fetch_inbox, send_envelope};
use dust_whisper::protocol::{MessengerEnvelope, MessengerInboxRequest};
use dust_whisper::relay::{build_router, relay_state_from_secret};
use reqwest::Client;
use sys::Account;
use tokio::task::JoinHandle;

/// The relay's own cap on undelivered envelopes in one inbox
/// (`MAX_PER_RECIPIENT`, `crates/dust-whisper/src/messenger_relay.rs`). Not
/// public, so it is restated here; the assertions below fail loudly if it moves.
const MAX_PER_RECIPIENT: usize = 200;
/// One sender's share of that inbox (`MAX_PER_SENDER`, same file).
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

fn envelope_for(to: &str, sender: &Account, id: &str) -> MessengerEnvelope {
    let mut env = MessengerEnvelope {
        v: 1,
        id: id.to_string(),
        to: to.to_string(),
        from: sender.readable().to_string(),
        from_pubkey: Some(hex::encode(sender.public_key().serialize_compressed())),
        from_sig: None,
        nonce: "00112233445566778899aabb".to_string(),
        ciphertext: "deadbeef".to_string(),
        // The relay refuses an envelope whose signed timestamp is outside its
        // freshness window (`MAX_AGE_PAST_SECS`), which is what stops a captured
        // envelope being replayed at leisure. A fixture with a hardcoded date
        // would be testing the clock rather than the cap.
        sent_at: chrono::Utc::now().to_rfc3339(),
    };
    env.from_sig = Some(hex::encode(sender.do_sign(&envelope_auth_digest(&env))));
    env
}

/// Reads the inbox the way a wallet does: challenge, sign it with the address's
/// own key, claim.
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

fn count_from(messages: &[MessengerEnvelope], who: &Account) -> usize {
    let addr = who.readable().to_string();
    messages.iter().filter(|m| m.from == addr).count()
}

/// The half of the story that holds: one identity cannot push anybody else out.
///
/// A sender already holding its whole share evicts its own oldest entry, so mail
/// that was already waiting from somebody else is untouched no matter how long
/// the flood runs.
#[tokio::test]
async fn a_flood_from_one_key_evicts_only_its_own_messages() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("flood-one-victim").unwrap();
    let friend = Account::create_by("flood-one-friend").unwrap();
    let flooder = Account::create_by("flood-one-flooder").unwrap();
    let victim_addr = victim.readable().to_string();

    let genuine = 11usize;
    for i in 0..genuine {
        send_envelope(
            &http,
            &relay_url,
            envelope_for(&victim_addr, &friend, &format!("friend-{i}")),
        )
        .await
        .unwrap();
    }

    // Far past both caps, from a single identity.
    for i in 0..300 {
        send_envelope(
            &http,
            &relay_url,
            envelope_for(&victim_addr, &flooder, &format!("flood-{i}")),
        )
        .await
        .unwrap();
    }

    let inbox = read_inbox(&http, &relay_url, &victim).await;
    assert_eq!(
        count_from(&inbox, &friend),
        genuine,
        "a single-identity flood must not cost the friend a single message"
    );
    assert_eq!(
        count_from(&inbox, &flooder),
        MAX_PER_SENDER,
        "the flooder is held to its own share"
    );

    relay.abort();
}

/// The half that does not hold, and the reason section 8 no longer says a flood
/// costs the flooder rather than the person being written to.
///
/// Keys are free, so this used to work: eviction took from whichever sender held
/// the most slots, and after a wide flood of one-message identities that sender
/// is the person the owner actually talks to. The flood deleted the
/// correspondent and kept itself, and this test recorded that loss.
///
/// It cannot now. A sender holding nothing in a full inbox is refused rather
/// than allowed to displace stored mail, so a deletion no longer costs the
/// price of a keypair. Nothing here is forged: every envelope is signed by the
/// key its `from` address derives from, which is all the relay asks for, and
/// that is exactly why authentication alone never fixed this.
#[tokio::test]
async fn a_flood_from_many_keys_cannot_evict_the_genuine_correspondent() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("flood-many-victim").unwrap();
    let friend = Account::create_by("flood-many-friend").unwrap();
    let victim_addr = victim.readable().to_string();

    let genuine = 11usize;
    for i in 0..genuine {
        send_envelope(
            &http,
            &relay_url,
            envelope_for(&victim_addr, &friend, &format!("friend-{i}")),
        )
        .await
        .unwrap();
    }
    let before = read_inbox(&http, &relay_url, &victim).await;
    assert_eq!(count_from(&before, &friend), genuine);

    // One throwaway identity per message, which costs an attacker a keypair.
    // These are no longer unwrapped: once the inbox is full every further
    // brand new sender is refused, and that refusal is the defence. Counting
    // them rather than panicking on them is what lets this test assert both
    // halves - the flood is turned away AND nothing stored is lost.
    let throwaways = MAX_PER_RECIPIENT + 60;
    let mut refused = 0usize;
    for i in 0..throwaways {
        let one_shot = Account::create_by(&format!("flood-many-throwaway-{i}")).unwrap();
        if send_envelope(
            &http,
            &relay_url,
            envelope_for(&victim_addr, &one_shot, &format!("junk-{i}")),
        )
        .await
        .is_err()
        {
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "a flood this wide must run the inbox out of room and start being refused;          none of {throwaways} were, so the cap is not doing anything"
    );

    let after = read_inbox(&http, &relay_url, &victim).await;
    assert!(
        after.len() <= MAX_PER_RECIPIENT,
        "the inbox is still capped: {} stored",
        after.len()
    );
    let survived = count_from(&after, &friend);
    assert_eq!(
        survived, genuine,
        "every one of the {genuine} genuine messages must survive a flood of \
         throwaway keys, {survived} did. If this drops, a brand new sender can \
         displace stored mail again and docs/RUNNING-A-RELAY.md sections 2 and 8 \
         need rereading."
    );

    relay.abort();
}
