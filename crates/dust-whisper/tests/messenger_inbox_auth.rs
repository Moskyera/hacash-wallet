//! The relay inbox door: only the address owner may read or delete an inbox.
//!
//! These drive the same `build_router()` that `desktop_relay.rs` serves and the same
//! `messenger_client` calls `wallet-core`'s `messenger_poll_inbox` makes, so a pass
//! here is a statement about the shipped endpoints, not about a helper function.

use std::net::SocketAddr;

use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::messenger_auth::{envelope_auth_digest, inbox_auth_digest};
use dust_whisper::messenger_client::{ack_messages, fetch_challenge, fetch_inbox, send_envelope};
use dust_whisper::messenger_relay::InboxAllowlist;
use dust_whisper::protocol::{MessengerAckRequest, MessengerEnvelope, MessengerInboxRequest};
use dust_whisper::relay::{build_router_for, relay_state_from_secret, serve_router};
use reqwest::Client;
use sys::Account;
use tokio::task::JoinHandle;

async fn spawn_relay() -> (String, JoinHandle<()>) {
    let (sk, _pk) = generate_relay_keypair();
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    // A DELIBERATELY PUBLIC RELAY, because that is what this file is about.
    //
    // The relay denies by default now: an address its operator did not name gets
    // nothing on any route, which is `messenger_relay_allowlist.rs`. The rules
    // exercised below are the ones that apply ON TOP of that, to callers the relay
    // has already agreed to serve, and they are the rules a public relay operator
    // is left holding. So this harness asks for the open relay by name, which is
    // the only way to get one.
    let app = build_router_for(state, InboxAllowlist::serving_everybody());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        serve_router(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

/// An envelope the way a real wallet builds one: signed by the key its `from`
/// address derives from.
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

/// Signs the relay's challenge for `claimed_address` with `signer`'s key. When the
/// signer is not the owner of that address this is exactly the forged claim an
/// attacker can build from public data alone.
fn signed_claim(signer: &Account, claimed_address: &str, nonce: &str) -> (String, String) {
    let digest = inbox_auth_digest(claimed_address, nonce);
    (
        hex::encode(signer.public_key().serialize_compressed()),
        hex::encode(signer.do_sign(&digest)),
    )
}

#[tokio::test]
async fn relay_refuses_an_inbox_fetch_signed_by_a_key_that_is_not_the_address() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("inbox-auth-victim").unwrap();
    let sender = Account::create_by("inbox-auth-sender").unwrap();
    let attacker = Account::create_by("inbox-auth-attacker").unwrap();
    let victim_addr = victim.readable().to_string();
    assert_ne!(victim.readable(), attacker.readable());

    send_envelope(
        &http,
        &relay_url,
        envelope_for(&victim_addr, &sender, "msg-1"),
    )
    .await
    .expect("relay accepts an envelope for the victim");

    // The attacker knows only the victim's address, which travels in clear on every
    // envelope. It asks the relay for a challenge on that address and signs it.
    let challenge = fetch_challenge(&http, &relay_url, &victim_addr)
        .await
        .expect("relay issues a challenge to anyone");
    let (attacker_pubkey, attacker_sig) = signed_claim(&attacker, &victim_addr, &challenge.nonce);

    let stolen = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: victim_addr.clone(),
            claimant_pubkey: attacker_pubkey,
            nonce: challenge.nonce,
            signature: attacker_sig,
        },
    )
    .await
    .expect("the endpoint answers");

    assert!(
        stolen.messages.is_empty(),
        "a key unrelated to {victim_addr} read {} message(s) out of that inbox",
        stolen.messages.len()
    );
    assert!(
        !stolen.auth_ok,
        "a refused claim must say so, or the caller cannot tell it from an empty inbox"
    );

    relay.abort();
}

#[tokio::test]
async fn relay_refuses_an_ack_signed_by_a_key_that_is_not_the_address() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("ack-auth-victim").unwrap();
    let sender = Account::create_by("ack-auth-sender").unwrap();
    let attacker = Account::create_by("ack-auth-attacker").unwrap();
    let victim_addr = victim.readable().to_string();

    send_envelope(
        &http,
        &relay_url,
        envelope_for(&victim_addr, &sender, "msg-1"),
    )
    .await
    .expect("relay accepts an envelope for the victim");

    let challenge = fetch_challenge(&http, &relay_url, &victim_addr)
        .await
        .unwrap();
    let (attacker_pubkey, attacker_sig) = signed_claim(&attacker, &victim_addr, &challenge.nonce);

    let deletion = ack_messages(
        &http,
        &relay_url,
        &MessengerAckRequest {
            to: victim_addr.clone(),
            claimant_pubkey: attacker_pubkey,
            nonce: challenge.nonce,
            signature: attacker_sig,
            ids: vec!["msg-1".to_string()],
        },
    )
    .await;

    assert!(
        deletion.is_err(),
        "a key unrelated to {victim_addr} deleted {:?} message(s) from that inbox",
        deletion.ok()
    );

    // And the message is still there for its actual owner.
    let challenge = fetch_challenge(&http, &relay_url, &victim_addr)
        .await
        .unwrap();
    let (victim_pubkey, victim_sig) = signed_claim(&victim, &victim_addr, &challenge.nonce);
    let mine = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: victim_addr.clone(),
            claimant_pubkey: victim_pubkey,
            nonce: challenge.nonce,
            signature: victim_sig,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        mine.messages.len(),
        1,
        "the attacker's ack destroyed the message"
    );

    relay.abort();
}

/// The owner must still get through. This is the path `messenger_poll_inbox` walks.
#[tokio::test]
async fn relay_still_serves_and_clears_the_inbox_for_its_actual_owner() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let owner = Account::create_by("owner-auth-owner").unwrap();
    let sender = Account::create_by("owner-auth-sender").unwrap();
    let owner_addr = owner.readable().to_string();

    send_envelope(
        &http,
        &relay_url,
        envelope_for(&owner_addr, &sender, "msg-1"),
    )
    .await
    .unwrap();

    let challenge = fetch_challenge(&http, &relay_url, &owner_addr)
        .await
        .unwrap();
    let (pubkey, sig) = signed_claim(&owner, &owner_addr, &challenge.nonce);
    let fetched = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: owner_addr.clone(),
            claimant_pubkey: pubkey,
            nonce: challenge.nonce,
            signature: sig,
        },
    )
    .await
    .unwrap();
    assert!(fetched.auth_ok, "the owner's own claim was accepted");
    assert_eq!(fetched.messages.len(), 1);
    assert_eq!(fetched.messages[0].id, "msg-1");

    let challenge = fetch_challenge(&http, &relay_url, &owner_addr)
        .await
        .unwrap();
    let (pubkey, sig) = signed_claim(&owner, &owner_addr, &challenge.nonce);
    let removed = ack_messages(
        &http,
        &relay_url,
        &MessengerAckRequest {
            to: owner_addr.clone(),
            claimant_pubkey: pubkey,
            nonce: challenge.nonce,
            signature: sig,
            ids: vec!["msg-1".to_string()],
        },
    )
    .await
    .expect("the owner may clear their own inbox");
    assert_eq!(removed, 1);

    relay.abort();
}

/// The door messages come IN through.
///
/// The send endpoint had no authentication of any kind, so `from` was a string
/// anybody could write. A stranger who knew two public addresses could post a
/// message that the recipient's wallet filed as an incoming message from a
/// trusted contact, and the screen showed it as one.
#[tokio::test]
async fn relay_refuses_an_envelope_that_claims_to_come_from_someone_else() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let victim = Account::create_by("forge-victim").unwrap();
    let alice = Account::create_by("forge-alice").unwrap();
    let mallory = Account::create_by("forge-mallory").unwrap();
    let victim_addr = victim.readable().to_string();
    let alice_addr = alice.readable().to_string();

    // Everything Mallory has: two public addresses. She writes Alice's address
    // into `from` and signs with her own key, then tries it unsigned, then with
    // Alice's real public key but no signature to go with it.
    let mut forged = envelope_for(&victim_addr, &mallory, "forged-1");
    forged.from = alice_addr.clone();
    assert!(
        send_envelope(&http, &relay_url, forged.clone())
            .await
            .is_err(),
        "the relay took an envelope signed by a key that is not its sender address"
    );

    forged.from_sig = None;
    assert!(
        send_envelope(&http, &relay_url, forged.clone())
            .await
            .is_err(),
        "the relay took an unsigned envelope"
    );

    forged.from_pubkey = Some(hex::encode(alice.public_key().serialize_compressed()));
    forged.from_sig = Some(hex::encode(mallory.do_sign(&envelope_auth_digest(&forged))));
    assert!(
        send_envelope(&http, &relay_url, forged).await.is_err(),
        "the relay took an envelope whose signature does not match the key on it"
    );

    // Nothing reached the victim's inbox.
    let challenge = fetch_challenge(&http, &relay_url, &victim_addr)
        .await
        .unwrap();
    let (pubkey, sig) = signed_claim(&victim, &victim_addr, &challenge.nonce);
    let inbox = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: victim_addr.clone(),
            claimant_pubkey: pubkey,
            nonce: challenge.nonce,
            signature: sig,
        },
    )
    .await
    .unwrap();
    assert!(inbox.auth_ok);
    assert!(
        inbox.messages.is_empty(),
        "a forged envelope reached the inbox: {:?}",
        inbox.messages
    );

    // And Alice herself, signing her own envelope, still gets through.
    send_envelope(
        &http,
        &relay_url,
        envelope_for(&victim_addr, &alice, "real-1"),
    )
    .await
    .expect("a properly signed envelope is still accepted");

    relay.abort();
}

/// A stranger asking for challenges must not lock the owner out of their inbox.
///
/// The relay kept one challenge slot per address and let anybody overwrite it,
/// and it spent the nonce before checking the signature. Either way the owner's
/// own correctly signed fetch came back empty, which is indistinguishable from
/// an empty inbox at every layer above it.
#[tokio::test]
async fn a_stranger_requesting_challenges_cannot_empty_the_owners_inbox() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let owner = Account::create_by("nonce-owner").unwrap();
    let sender = Account::create_by("nonce-sender").unwrap();
    let attacker = Account::create_by("nonce-attacker").unwrap();
    let owner_addr = owner.readable().to_string();

    send_envelope(
        &http,
        &relay_url,
        envelope_for(&owner_addr, &sender, "waiting-1"),
    )
    .await
    .unwrap();

    // The owner takes a challenge, and the attacker then does everything it can
    // to invalidate it: more challenge requests on the same address, and a
    // failed claim against the owner's own nonce.
    let mine = fetch_challenge(&http, &relay_url, &owner_addr)
        .await
        .unwrap();
    for _ in 0..8 {
        let _ = fetch_challenge(&http, &relay_url, &owner_addr)
            .await
            .unwrap();
    }
    let (bad_pubkey, bad_sig) = signed_claim(&attacker, &owner_addr, &mine.nonce);
    let stolen = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: owner_addr.clone(),
            claimant_pubkey: bad_pubkey,
            nonce: mine.nonce.clone(),
            signature: bad_sig,
        },
    )
    .await
    .unwrap();
    assert!(!stolen.auth_ok, "the attacker's claim was accepted");

    // The owner's own nonce is still good, and the message is still there.
    let (pubkey, sig) = signed_claim(&owner, &owner_addr, &mine.nonce);
    let fetched = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: owner_addr.clone(),
            claimant_pubkey: pubkey,
            nonce: mine.nonce,
            signature: sig,
        },
    )
    .await
    .unwrap();
    assert!(
        fetched.auth_ok,
        "a stranger's traffic invalidated the owner's own challenge"
    );
    assert_eq!(
        fetched.messages.len(),
        1,
        "the owner was answered with an empty inbox while a message was waiting"
    );

    relay.abort();
}

/// A flood must cost the flooder, not the person being written to.
///
/// Eviction was "drop the oldest entry", so 200 junk envelopes deleted the
/// genuine mail that had been waiting longest, before it was ever collected.
#[tokio::test]
async fn a_flood_from_one_sender_does_not_destroy_another_senders_mail() {
    let (relay_url, relay) = spawn_relay().await;
    let http = Client::new();

    let owner = Account::create_by("flood-owner").unwrap();
    let alice = Account::create_by("flood-alice").unwrap();
    let mallory = Account::create_by("flood-mallory").unwrap();
    let owner_addr = owner.readable().to_string();

    // Alice writes first, so hers is the oldest entry in the inbox.
    send_envelope(
        &http,
        &relay_url,
        envelope_for(&owner_addr, &alice, "alice-1"),
    )
    .await
    .unwrap();

    for n in 0..300 {
        send_envelope(
            &http,
            &relay_url,
            envelope_for(&owner_addr, &mallory, &format!("flood-{n}")),
        )
        .await
        .unwrap();
    }

    let challenge = fetch_challenge(&http, &relay_url, &owner_addr)
        .await
        .unwrap();
    let (pubkey, sig) = signed_claim(&owner, &owner_addr, &challenge.nonce);
    let inbox = fetch_inbox(
        &http,
        &relay_url,
        &MessengerInboxRequest {
            to: owner_addr.clone(),
            claimant_pubkey: pubkey,
            nonce: challenge.nonce,
            signature: sig,
        },
    )
    .await
    .unwrap();

    assert!(
        inbox.messages.iter().any(|m| m.id == "alice-1"),
        "300 envelopes from one stranger destroyed the genuine message"
    );
    let from_mallory = inbox
        .messages
        .iter()
        .filter(|m| m.from == mallory.readable())
        .count();
    assert!(
        from_mallory <= 20,
        "one sender held {from_mallory} slots in somebody else's inbox"
    );

    relay.abort();
}
