//! DEFAULT DENY: WHAT A RELAY SERVES SOMEBODY ITS HOST NEVER NAMED.
//!
//! # What this is answering
//!
//! The wallet offers to bind its own relay to every interface so that one
//! friend can host for another. Reaching a friend means binding somewhere
//! reachable, and a socket a friend can reach is a socket every other machine
//! on that network can reach too. So the question is not how much a stranger
//! may do. It is whether a stranger may be there at all.
//!
//! The answer this file holds the code to is no, on every route, unless the
//! host named that exact address. Not "allow everyone unless blocked", not
//! "allow the LAN": an address the host did not list gets no inbox, no send, no
//! challenge, no acknowledgement, and no directory answer. A neighbour on the
//! same network learns nothing and stores nothing with the host, and the host
//! is left holding no stranger's metadata to lose.
//!
//! It matters that this is the rule rather than a ceiling. Every ceiling in
//! this relay bounds how much one identity may hold, and keys are free, so
//! every one of them is walked around by spreading across identities. A list of
//! addresses is the one rule a free keypair cannot buy its way past.
//!
//! # What is real here
//!
//! The shipped router (`dust_whisper::relay::build_router_with`), over a real
//! socket, served the way the wallet serves it (`serve_router`), driven with
//! the shipped client. The same router the wallet's own embedded relay serves
//! (`serve_listener_with`, `crates/wallet-tauri-common/src/desktop_relay.rs`).
//! Every envelope is signed by a real `sys::Account`, because the relay refuses
//! anything else and this file is not about that door.
//!
//! # The limit that is not engineered away here
//!
//! A host sees the metadata of the friend they relay for: both addresses,
//! timing, sizes. That is inherent to relaying and no list changes it. It is
//! also nearly nothing, because the only fact it reveals is that these two
//! people talk to each other, which both of them already know. What this file
//! is about is everybody else.

use std::net::SocketAddr;

use dust_whisper::messenger_auth::{envelope_auth_digest, inbox_auth_digest};
use dust_whisper::messenger_client::{
    PubkeyAsker, ack_messages, fetch_challenge, fetch_inbox, fetch_peer_pubkey, send_envelope,
};
use dust_whisper::messenger_relay::InboxAllowlist;
use dust_whisper::protocol::{
    INFO_PATH, MessengerAckRequest, MessengerEnvelope, MessengerInboxRequest, SUBMIT_PATH,
    WhisperInfo, WhisperInnerPayload, WhisperSubmitRequest, WhisperSubmitResponse,
};
use dust_whisper::relay::{
    RelayAccess, SUBMIT_TOKEN_HEADER, build_router_with, relay_state_from_secret, serve_router,
    submit_token_from_secret,
};
use reqwest::Client;
use std::time::Duration;
use sys::Account;
use tokio::task::JoinHandle;

const ASK: Duration = Duration::from_secs(3);

async fn spawn_relay(allowlist: InboxAllowlist) -> (String, JoinHandle<()>) {
    spawn_relay_with(RelayAccess::for_addresses(allowlist)).await
}

async fn spawn_relay_with(access: RelayAccess) -> (String, JoinHandle<()>) {
    let (url, handle, _secret) = spawn_relay_with_secret(access).await;
    (url, handle)
}

/// The same, handing back the relay's secret so a test can derive the submit
/// token the way a local process would from the key file.
async fn spawn_relay_with_secret(access: RelayAccess) -> (String, JoinHandle<()>, [u8; 32]) {
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    let app = build_router_with(state, access);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        serve_router(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle, sk)
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

/// A correctly signed claim on one's own mailbox, which is the strongest thing
/// an address holder can present.
fn inbox_request(owner: &Account, nonce: &str) -> MessengerInboxRequest {
    let address = owner.readable().to_string();
    let digest = inbox_auth_digest(&address, nonce);
    MessengerInboxRequest {
        to: address,
        claimant_pubkey: hex::encode(owner.public_key().serialize_compressed()),
        nonce: nonce.to_string(),
        signature: hex::encode(owner.do_sign(&digest)),
    }
}

fn ack_request(owner: &Account, nonce: &str) -> MessengerAckRequest {
    let request = inbox_request(owner, nonce);
    MessengerAckRequest {
        to: request.to,
        claimant_pubkey: request.claimant_pubkey,
        nonce: request.nonce,
        signature: request.signature,
        ids: Vec::new(),
    }
}

/// A real encrypted submission, sealed to the relay key the relay published.
///
/// Built the way `dust_whisper::client::submit_tx` builds one, so what the
/// route refuses is a payload it could otherwise have opened.
fn sealed_transaction(relay_pubkey_b64: &str) -> WhisperSubmitRequest {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, relay_pubkey_b64)
        .expect("the relay published a base64 key");
    let key: [u8; 32] = raw.try_into().expect("32 byte relay key");
    dust_whisper::crypto::encrypt_payload(
        &key,
        &WhisperInnerPayload {
            tx_hex: "00".to_string(),
        },
    )
    .expect("sealing a transaction to the relay key")
}

/// The refusal, in the relay's own words, or `None` when it accepted.
async fn refusal(http: &Client, url: &str, env: MessengerEnvelope) -> Option<String> {
    match send_envelope(http, url, env).await {
        Ok(()) => None,
        Err(e) => Some(e.to_string()),
    }
}

/// Who is asking the key directory, which it now requires.
struct Asker {
    address: String,
    pubkey: String,
    nonce: String,
    signature: String,
}

impl Asker {
    fn borrow(&self) -> PubkeyAsker<'_> {
        PubkeyAsker {
            address: &self.address,
            pubkey_hex: &self.pubkey,
            nonce: &self.nonce,
            signature: &self.signature,
        }
    }
}

/// A credential built from a real challenge issued by the relay being asked.
///
/// It is built the same way for a listed and an unlisted account, deliberately:
/// an unlisted account receives a decoy nonce, signs it perfectly, and is
/// refused for being unlisted rather than for holding a bad key. That is the
/// case these tests are about.
async fn credential(http: &Client, url: &str, who: &Account) -> Asker {
    let address = who.readable().to_string();
    let nonce = fetch_challenge(http, url, &address).await.unwrap().nonce;
    let digest = inbox_auth_digest(&address, &nonce);
    Asker {
        signature: hex::encode(who.do_sign(&digest)),
        pubkey: hex::encode(who.public_key().serialize_compressed()),
        nonce,
        address,
    }
}

/// No credential at all, which is what a passer-by has.
fn no_credential() -> Asker {
    Asker {
        address: String::new(),
        pubkey: String::new(),
        nonce: String::new(),
        signature: String::new(),
    }
}

async fn ask_directory(http: &Client, url: &str, address: &str, asker: &Asker) -> Option<String> {
    fetch_peer_pubkey(http, url, address, &asker.borrow(), ASK)
        .await
        .unwrap()
}

/// Two friends who named each other, and one stranger who can reach the port.
///
/// This is the shape of section 0: one wallet hosting, one wallet pointed at
/// it, and a network that has other people on it.
#[tokio::test]
async fn a_named_relay_carries_the_two_friends_and_refuses_everybody_else() {
    let alice = Account::create_by("allowlist-alice").unwrap();
    let bob = Account::create_by("allowlist-bob").unwrap();
    let mallory = Account::create_by("allowlist-mallory").unwrap();
    let (alice_addr, bob_addr, mallory_addr) = (
        alice.readable().to_string(),
        bob.readable().to_string(),
        mallory.readable().to_string(),
    );

    let (url, relay) = spawn_relay(InboxAllowlist::from_addresses([
        // As a person would paste them, whitespace and all.
        format!("  {alice_addr} "),
        bob_addr.clone(),
    ]))
    .await;
    let http = Client::new();

    // The arrangement the relay exists for works, in both directions.
    assert_eq!(
        refusal(&http, &url, signed_envelope(&bob_addr, &alice, "a-1")).await,
        None,
        "the relay refused mail between the two addresses its operator named"
    );
    assert_eq!(
        refusal(&http, &url, signed_envelope(&alice_addr, &bob, "b-1")).await,
        None
    );

    // A stranger on the same network cannot post at all: not to a friend, and
    // not to a mailbox of their own, which is the one that matters because that
    // is what a flood is made of.
    let to_friend = refusal(&http, &url, signed_envelope(&bob_addr, &mallory, "m-1"))
        .await
        .expect("a stranger must not be able to post to a named address");
    assert!(
        to_friend.contains("only for the addresses its operator listed"),
        "the relay refused without saying why: {to_friend}"
    );
    let to_self = refusal(&http, &url, signed_envelope(&mallory_addr, &mallory, "m-2"))
        .await
        .expect("a stranger must not be able to park mail in a mailbox of their own");
    assert_eq!(
        to_self, to_friend,
        "the refusal differed depending on who the envelope was addressed to, which is an oracle"
    );

    // And a named address cannot be used as a drop box addressed to a stranger,
    // which is the other end of the same rule.
    let to_stranger = refusal(&http, &url, signed_envelope(&mallory_addr, &alice, "a-2"))
        .await
        .expect("a listed sender must not be able to post to an unlisted recipient");
    assert_eq!(to_stranger, to_friend);

    // The mailbox door is shut too, so a stranger cannot even start the claim -
    // and the shutting must not be visible. A stranger is handed a nonce that
    // LOOKS exactly like a real one and is written down nowhere, so this route
    // cannot be used to test an address against the host's list. What proves it
    // is a decoy is that it cannot be spent, which is the assertion below.
    let stranger_challenge = fetch_challenge(&http, &url, &mallory_addr)
        .await
        .expect("the relay answers the challenge request");
    let friend_challenge = fetch_challenge(&http, &url, &bob_addr)
        .await
        .expect("the relay answers the challenge request");
    assert_eq!(
        stranger_challenge.nonce.len(),
        friend_challenge.nonce.len(),
        "the challenge route told a listed address apart from an unlisted one"
    );
    assert!(
        !friend_challenge.nonce.is_empty(),
        "a listed address must still be able to claim its own mailbox"
    );
    let stranger_fetch = fetch_inbox(
        &http,
        &url,
        &inbox_request(&mallory, &stranger_challenge.nonce),
    )
    .await
    .expect("the relay answers the inbox request");
    assert!(
        !stranger_fetch.auth_ok,
        "the nonce handed to an unlisted address actually worked"
    );

    // The directory. It answers a caller this relay carries mail for, and
    // nobody else: Alice really did send through this relay, so an open one
    // would say so to anyone who asked.
    let bobs_credential = credential(&http, &url, &bob).await;
    assert_eq!(
        ask_directory(&http, &url, &alice_addr, &bobs_credential).await,
        Some(hex::encode(alice.public_key().serialize_compressed())),
        "a listed address must still be answerable, or first contact cannot be sealed"
    );
    assert_eq!(
        ask_directory(&http, &url, &alice_addr, &no_credential()).await,
        None,
        "the directory answered a caller that presented nothing"
    );
    assert_eq!(
        ask_directory(
            &http,
            &url,
            &alice_addr,
            &credential(&http, &url, &mallory).await
        )
        .await,
        None,
        "the directory answered a caller this relay does not carry mail for"
    );
    assert_eq!(
        ask_directory(&http, &url, &mallory_addr, &bobs_credential).await,
        None,
        "the directory answered about an address this relay does not carry mail for"
    );

    relay.abort();
}

/// THE ORACLE THAT WAS OPEN, AND IS THE REASON THIS FILE CHANGED.
///
/// A neighbour with no key, no envelope and no relationship with the host used
/// to be able to put candidate addresses to `challenge` and read the host's
/// list straight back out: a listed address answered with a 32 character nonce,
/// an unlisted one answered with an empty string. The refusal was symmetric and
/// that is what the old tests checked; the ACCEPTANCE was not, and the fact it
/// handed over is the single fact this whole design says only the host holds -
/// that these two people talk to each other.
///
/// Three routes carried it. All three are checked here against a passer-by who
/// knows both a listed address and an unlisted one and is trying to tell them
/// apart.
#[tokio::test]
async fn a_stranger_cannot_tell_a_listed_address_from_an_unlisted_one() {
    let listed = Account::create_by("oracle-listed").unwrap();
    let unlisted = Account::create_by("oracle-unlisted").unwrap();
    let other = Account::create_by("oracle-other").unwrap();
    let listed_addr = listed.readable().to_string();
    let unlisted_addr = unlisted.readable().to_string();
    let (url, relay) = spawn_relay(InboxAllowlist::from_addresses([
        listed_addr.clone(),
        other.readable().to_string(),
    ]))
    .await;
    let http = Client::new();

    // The listed address really has used this relay, so there is something to
    // give away.
    assert_eq!(
        refusal(
            &http,
            &url,
            signed_envelope(other.readable(), &listed, "oracle-1")
        )
        .await,
        None
    );

    // 1. CHALLENGE, which was the readable one.
    let a = fetch_challenge(&http, &url, &listed_addr).await.unwrap();
    let b = fetch_challenge(&http, &url, &unlisted_addr).await.unwrap();
    assert_eq!(
        a.nonce.len(),
        b.nonce.len(),
        "challenge answered a listed address and an unlisted one in different lengths"
    );
    assert_eq!(a.nonce.len(), 32, "the nonce stopped being 16 bytes of hex");
    assert_ne!(
        a.nonce, b.nonce,
        "two challenges came back identical, so they are not random"
    );

    // 2. DIRECTORY, with no credential, which is what a passer-by holds.
    assert_eq!(
        ask_directory(&http, &url, &listed_addr, &no_credential()).await,
        ask_directory(&http, &url, &unlisted_addr, &no_credential()).await,
        "the key directory told a listed address apart from an unlisted one"
    );
    assert_eq!(
        ask_directory(&http, &url, &listed_addr, &no_credential()).await,
        None
    );

    // 3. ACK, which chose its wording by list membership. Identical rubbish
    // credentials, varying only the address named.
    let rubbish = |who: &str| MessengerAckRequest {
        to: who.to_string(),
        claimant_pubkey: "00".repeat(33),
        nonce: "0".repeat(32),
        signature: "00".repeat(64),
        ids: Vec::new(),
    };
    let listed_ack = ack_messages(&http, &url, &rubbish(&listed_addr))
        .await
        .expect_err("rubbish credentials were accepted");
    let unlisted_ack = ack_messages(&http, &url, &rubbish(&unlisted_addr))
        .await
        .expect_err("rubbish credentials were accepted");
    assert_eq!(
        listed_ack.to_string(),
        unlisted_ack.to_string(),
        "ack answered a listed address and an unlisted one in different words"
    );

    // And with a PERFECT signature over a decoy nonce, which is the strongest
    // thing an address holder who is not on the list can present.
    let signed_for = |who: &Account, nonce: &str| ack_request(who, nonce);
    let listed_nonce = fetch_challenge(&http, &url, &listed_addr)
        .await
        .unwrap()
        .nonce;
    let unlisted_nonce = fetch_challenge(&http, &url, &unlisted_addr)
        .await
        .unwrap()
        .nonce;
    // The listed address spends its own nonce first, so the second attempt is
    // a stale-but-real nonce; the unlisted address's nonce was never written
    // down. Both have to come back in the same words.
    let _ = ack_messages(&http, &url, &signed_for(&listed, &listed_nonce)).await;
    let listed_again = ack_messages(&http, &url, &signed_for(&listed, &listed_nonce))
        .await
        .expect_err("a spent nonce was accepted twice");
    let unlisted_signed = ack_messages(&http, &url, &signed_for(&unlisted, &unlisted_nonce))
        .await
        .expect_err("an unlisted address was allowed to delete mail");
    assert_eq!(
        listed_again.to_string(),
        unlisted_signed.to_string(),
        "a properly signed unlisted caller was told something a listed one was not"
    );

    println!("listed   challenge {} chars", a.nonce.len());
    println!("unlisted challenge {} chars", b.nonce.len());
    println!("listed   ack {listed_again}");
    println!("unlisted ack {unlisted_signed}");

    relay.abort();
}

/// EVERY ROUTE, against the strongest thing a stranger can present.
///
/// Mallory holds her own key, so she can sign anything about her own address
/// perfectly. That is the point: she is not being caught out by a bad
/// signature. She is being refused because the host never named her, and the
/// refusal has to be the same on every door the relay has.
#[tokio::test]
async fn an_unlisted_address_gets_nothing_on_any_route() {
    let alice = Account::create_by("route-alice").unwrap();
    let mallory = Account::create_by("route-mallory").unwrap();
    let (alice_addr, mallory_addr) = (alice.readable().to_string(), mallory.readable().to_string());
    let (url, relay) = spawn_relay(InboxAllowlist::from_addresses([alice_addr.clone()])).await;
    let http = Client::new();

    // SEND, in either direction.
    assert!(
        refusal(&http, &url, signed_envelope(&mallory_addr, &mallory, "r-1"))
            .await
            .is_some()
    );

    // CHALLENGE: a nonce that looks exactly like a real one and is worth
    // nothing. It is not empty, because an empty one is a membership test
    // anybody can run; it is a decoy that no table has ever seen, so spending
    // it fails exactly as spending an expired one fails.
    let issued = fetch_challenge(&http, &url, &mallory_addr).await.unwrap();
    assert_eq!(
        issued.nonce.len(),
        32,
        "an unlisted address was answered in a shape a listed one is not"
    );
    let with_decoy = fetch_inbox(&http, &url, &inbox_request(&mallory, &issued.nonce))
        .await
        .expect("the relay answers the inbox request");
    assert!(
        !with_decoy.auth_ok && with_decoy.messages.is_empty(),
        "the decoy nonce opened an inbox"
    );

    // FETCH. Alice is listed, so she can get a real nonce; Mallory then signs
    // her OWN address against it with her own key, which is the best forgery
    // available to somebody who holds a key and is not on the list. The relay
    // must refuse, and must refuse identically to a caller with a bad key.
    let alice_nonce = fetch_challenge(&http, &url, &alice_addr)
        .await
        .unwrap()
        .nonce;
    assert!(!alice_nonce.is_empty());
    let stranger_fetch = fetch_inbox(&http, &url, &inbox_request(&mallory, &alice_nonce))
        .await
        .expect("the relay answers the inbox request");
    assert!(
        !stranger_fetch.auth_ok,
        "an unlisted address was allowed to collect an inbox"
    );
    assert!(stranger_fetch.messages.is_empty());

    // ACK: same, and the refusal is the one any strangler without a challenge
    // gets, so it tells the caller nothing about who is on the list.
    let stranger_ack = ack_messages(&http, &url, &ack_request(&mallory, &alice_nonce))
        .await
        .expect_err("an unlisted address was allowed to delete mail");
    assert!(
        stranger_ack
            .to_string()
            .contains("invalid or expired challenge"),
        "the ack refusal named the list: {stranger_ack}"
    );

    // DIRECTORY, asked by Mallory herself with the best credential she can
    // build: her own address, the nonce this relay handed her, and her own
    // signature over both. It is refused because she is not on the list.
    assert_eq!(
        ask_directory(
            &http,
            &url,
            &alice_addr,
            &credential(&http, &url, &mallory).await
        )
        .await,
        None,
        "an unlisted caller was answered by the key directory"
    );
    assert_eq!(
        ask_directory(&http, &url, &mallory_addr, &no_credential()).await,
        None
    );

    // And Alice, who IS listed, can still do all of it: the doors are shut to
    // strangers, not welded shut.
    assert_eq!(
        refusal(&http, &url, signed_envelope(&alice_addr, &alice, "r-2")).await,
        None
    );
    let alice_nonce = fetch_challenge(&http, &url, &alice_addr)
        .await
        .unwrap()
        .nonce;
    let alice_fetch = fetch_inbox(&http, &url, &inbox_request(&alice, &alice_nonce))
        .await
        .unwrap();
    assert!(alice_fetch.auth_ok);
    assert_eq!(alice_fetch.messages.len(), 1);
    let alice_nonce = fetch_challenge(&http, &url, &alice_addr)
        .await
        .unwrap()
        .nonce;
    assert_eq!(
        ack_messages(&http, &url, &ack_request(&alice, &alice_nonce))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ask_directory(
            &http,
            &url,
            &alice_addr,
            &credential(&http, &url, &alice).await
        )
        .await,
        Some(hex::encode(alice.public_key().serialize_compressed())),
        "a listed address cannot use the directory it is listed on"
    );

    relay.abort();
}

/// THE REFUSAL LEAKS NOTHING EITHER.
///
/// An unlisted address and an address this relay has simply never heard of have
/// to be indistinguishable from outside, or the relay becomes a way to ask a
/// host who they are relaying for. Mallory is on nobody's list; Carol is on
/// nobody's list either and has never touched this relay. Every route has to
/// answer them the same.
#[tokio::test]
async fn an_unlisted_address_and_an_unknown_one_look_the_same() {
    let alice = Account::create_by("leak-alice").unwrap();
    let mallory = Account::create_by("leak-mallory").unwrap();
    let carol = Account::create_by("leak-carol").unwrap();
    let alice_addr = alice.readable().to_string();
    let (url, relay) = spawn_relay(InboxAllowlist::from_addresses([alice_addr.clone()])).await;
    let http = Client::new();

    // Mallory makes herself known to this relay in every way a stranger can:
    // she tries to send, tries to be sent to, and asks for a challenge. None of
    // it may leave a trace another route can report.
    let _ = refusal(
        &http,
        &url,
        signed_envelope(mallory.readable(), &mallory, "leak-1"),
    )
    .await;
    let _ = refusal(
        &http,
        &url,
        signed_envelope(&alice_addr, &mallory, "leak-2"),
    )
    .await;
    let _ = fetch_challenge(&http, &url, mallory.readable()).await;

    let one = mallory.readable().to_string();
    let two = carol.readable().to_string();

    let send_one = refusal(&http, &url, signed_envelope(&one, &mallory, "cmp-1")).await;
    let send_two = refusal(&http, &url, signed_envelope(&two, &mallory, "cmp-2")).await;
    assert_eq!(
        send_one, send_two,
        "send told the address that tried apart from the address that never appeared"
    );
    assert!(send_one.is_some());

    let ch_one = fetch_challenge(&http, &url, &one).await.unwrap();
    let ch_two = fetch_challenge(&http, &url, &two).await.unwrap();
    assert_eq!(
        ch_one.nonce.len(),
        ch_two.nonce.len(),
        "challenge told them apart"
    );
    // And neither of them is worth anything, which is what makes the shape a
    // decoy rather than an answer.
    for (who, nonce) in [(&mallory, &ch_one.nonce), (&carol, &ch_two.nonce)] {
        let attempt = fetch_inbox(&http, &url, &inbox_request(who, nonce))
            .await
            .expect("the relay answers the inbox request");
        assert!(!attempt.auth_ok, "a decoy nonce opened an inbox");
    }

    assert_eq!(
        ask_directory(&http, &url, &one, &no_credential()).await,
        ask_directory(&http, &url, &two, &no_credential()).await,
        "the directory told them apart"
    );

    relay.abort();
}

/// AN EMPTY LIST SERVES NOBODY.
///
/// This is the default and it is the state an upgraded settings file lands in,
/// so it is the state of a person who never made a choice. It used to mean
/// open. Meaning open was the whole exposure: a host who turned on a relay to
/// message one friend was running a relay for the entire network their computer
/// was on, and had made no decision that said so.
#[tokio::test]
async fn an_empty_list_carries_mail_for_nobody() {
    let sender = Account::create_by("closed-sender").unwrap();
    let recipient = Account::create_by("closed-recipient").unwrap();
    let recipient_addr = recipient.readable().to_string();

    for list in [
        InboxAllowlist::closed(),
        InboxAllowlist::default(),
        // Whitespace only is not a list, and it is not a way to open one either.
        InboxAllowlist::from_addresses(["", "   "]),
    ] {
        assert!(list.serves_nobody());
        let (url, relay) = spawn_relay(list).await;
        let http = Client::new();
        assert!(
            refusal(
                &http,
                &url,
                signed_envelope(&recipient_addr, &sender, "closed-1")
            )
            .await
            .is_some(),
            "a relay that names nobody accepted a message"
        );
        // A nonce comes back, and it is worth nothing: the shape must not
        // depend on the list, only the outcome of spending it.
        let issued = fetch_challenge(&http, &url, &recipient_addr)
            .await
            .unwrap()
            .nonce;
        assert_eq!(issued.len(), 32);
        assert!(
            !fetch_inbox(&http, &url, &inbox_request(&recipient, &issued))
                .await
                .unwrap()
                .auth_ok,
            "a relay that names nobody let somebody open an inbox"
        );
        assert_eq!(
            ask_directory(
                &http,
                &url,
                &recipient_addr,
                &credential(&http, &url, &recipient).await
            )
            .await,
            None
        );
        relay.abort();
    }
}

/// THE TRANSACTION PATH IS A DIFFERENT DOOR AND IT IS SHUT SEPARATELY.
///
/// `/whisper/v1/submit` decrypts a payload and posts the transaction inside to
/// the operator's fullnode. It has no sender address to match against any list,
/// and the key it decrypts with is handed to anybody who asks `/whisper/v1/info`
/// - so a host who widened the bind for messages would have been running an open
/// transaction submitter as well, without a screen anywhere having said so.
///
/// It is denied by default and denied by a credential, not by the list. The
/// credential used to be the peer's IP address, and that was not a credential:
/// section 4 of docs/RUNNING-A-RELAY.md tells operators to put a reverse proxy
/// in front of the relay, and behind one of those every submitter on earth
/// arrives as 127.0.0.1. So it is a secret derived from the relay's own key
/// file now, and loopback is kept as a second condition rather than the only
/// one. This test drives the ALLOWED case (this machine, holding the token),
/// the same case without the token, a caller with no connection information at
/// all, and the proxy case that used to get through.
#[tokio::test]
async fn a_transaction_is_forwarded_only_for_this_machine() {
    let (url, relay, relay_secret) = spawn_relay_with_secret(RelayAccess::closed()).await;
    let token = submit_token_from_secret(&relay_secret);
    let http = Client::new();

    // Loopback is allowed through the door, and then fails on the far side
    // because this fixture's node URL points at nothing. That is the proof it
    // got past the access check: the error is about the node, not about who is
    // asking.
    let info: WhisperInfo = http
        .get(format!("{url}{INFO_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let payload = sealed_transaction(&info.pubkey);
    let accepted: WhisperSubmitResponse = http
        .post(format!("{url}{SUBMIT_PATH}"))
        .header(SUBMIT_TOKEN_HEADER, &token)
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let accepted_err = accepted.err.unwrap_or_default();
    println!(
        "submit from THIS machine, with the token: ret={} err={accepted_err:?}",
        accepted.ret
    );
    assert!(
        !accepted_err.contains("does not accept transactions from other machines"),
        "a submission from this machine was refused as remote: {accepted_err}"
    );

    // The same machine, the same payload, without the token. Loopback on its
    // own is not the credential any more, so this is refused.
    let no_token: WhisperSubmitResponse = http
        .post(format!("{url}{SUBMIT_PATH}"))
        .json(&sealed_transaction(&info.pubkey))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!(
        "submit from THIS machine, no token: ret={} err={:?}",
        no_token.ret, no_token.err
    );
    assert_eq!(no_token.ret, 1);
    assert!(
        no_token
            .err
            .unwrap_or_default()
            .contains("does not accept transactions from other machines"),
        "loopback alone opened the transaction door"
    );

    // A wrong token from this machine, which is what a guesser has.
    let wrong: WhisperSubmitResponse = http
        .post(format!("{url}{SUBMIT_PATH}"))
        .header(SUBMIT_TOKEN_HEADER, "0".repeat(64))
        .json(&sealed_transaction(&info.pubkey))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(wrong.ret, 1);

    // The same relay, served without connection information, which is the
    // shape any caller the kernel cannot vouch for arrives in. Fail closed.
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    let blind = build_router_with(state, RelayAccess::closed());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blind_addr: SocketAddr = listener.local_addr().unwrap();
    let blind_relay = tokio::spawn(async move {
        axum::serve(listener, blind).await.unwrap();
    });
    let blind_url = format!("http://{blind_addr}");
    let blind_info: WhisperInfo = http
        .get(format!("{blind_url}{INFO_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // `/whisper/v1/info` answers everybody, deliberately: see `info_handler`.
    // What it hands out is the operator's own configuration, and what this test
    // is about is the route that would act on it.
    assert!(blind_info.node_url.is_some());
    let payload = sealed_transaction(&blind_info.pubkey);
    let refused: WhisperSubmitResponse = http
        .post(format!("{blind_url}{SUBMIT_PATH}"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!(
        "submit from a caller the kernel cannot place as local: ret={} err={:?}",
        refused.ret, refused.err
    );
    assert_eq!(refused.ret, 1);
    assert!(
        refused
            .err
            .unwrap_or_default()
            .contains("does not accept transactions from other machines"),
        "a transaction from an unplaceable caller was not refused"
    );

    blind_relay.abort();
    relay.abort();
}

/// A REVERSE PROXY DOES NOT MAKE A STRANGER LOCAL.
///
/// This is the case that was open and that this whole credential exists for.
/// Section 4 of docs/RUNNING-A-RELAY.md says "keep it on loopback and let a
/// reverse proxy be the only thing exposed" and ships two configurations that
/// both `proxy_pass http://127.0.0.1:8787`. Behind either of them the relay's
/// `ConnectInfo` peer is 127.0.0.1 for every caller in the world, so an IP
/// check said yes to the internet while the screen said the door was shut.
///
/// The forwarder below is exactly that shape and nothing more: it accepts a
/// connection from a non-loopback address, opens its own connection to the
/// relay on loopback, and copies bytes. No headers are added, because a
/// forwarder that adds none is the hardest case and sniffing for
/// `X-Forwarded-For` would not have closed anything.
#[tokio::test]
async fn a_reverse_proxy_does_not_make_a_stranger_local() {
    let (url, relay, _secret) = spawn_relay_with_secret(RelayAccess::closed()).await;
    let http = Client::new();
    let info: WhisperInfo = http
        .get(format!("{url}{INFO_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let relay_addr: SocketAddr = url.trim_start_matches("http://").parse().unwrap();

    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let forwarder = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, from)) = proxy.accept().await else {
                return;
            };
            println!("proxy accepted a connection from {from}");
            let Ok(mut outbound) = tokio::net::TcpStream::connect(relay_addr).await else {
                return;
            };
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });

    let through_proxy: WhisperSubmitResponse = http
        .post(format!("http://{proxy_addr}{SUBMIT_PATH}"))
        .json(&sealed_transaction(&info.pubkey))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let err = through_proxy.err.unwrap_or_default();
    println!(
        "submit through a forwarder: ret={} err={err:?}",
        through_proxy.ret
    );
    assert_eq!(through_proxy.ret, 1);
    assert!(
        err.contains("does not accept transactions from other machines"),
        "a caller one TCP hop away was treated as local: {err}"
    );

    // And the mail door is unchanged by the proxy either way, because it keys
    // on an address and not on a connection.
    let stranger = Account::create_by("proxy-stranger").unwrap();
    let proxied = format!("http://{proxy_addr}");
    assert!(
        refusal(
            &http,
            &proxied,
            signed_envelope(stranger.readable(), &stranger, "proxy-1")
        )
        .await
        .is_some(),
        "the proxy let an unlisted address post"
    );

    forwarder.abort();
    relay.abort();
}

/// A list does not weaken any door that was already shut.
///
/// Being named is permission to use the relay, and nothing else. It is not
/// permission to read somebody's mailbox and it is not permission to claim
/// somebody else's name on an envelope.
#[tokio::test]
async fn being_on_the_list_is_not_permission_to_be_somebody_else() {
    let alice = Account::create_by("allowlist-strict-alice").unwrap();
    let bob = Account::create_by("allowlist-strict-bob").unwrap();
    let (alice_addr, bob_addr) = (alice.readable().to_string(), bob.readable().to_string());
    let (url, relay) = spawn_relay(InboxAllowlist::from_addresses([
        alice_addr.clone(),
        bob_addr.clone(),
    ]))
    .await;
    let http = Client::new();

    // Alice is on the list. She signs an envelope that claims to come from Bob,
    // who is also on the list. The signature check is what answers, not the list.
    let mut forged = signed_envelope(&bob_addr, &alice, "forged-1");
    forged.from = bob_addr.clone();
    forged.from_pubkey = Some(hex::encode(bob.public_key().serialize_compressed()));
    let err = refusal(&http, &url, forged)
        .await
        .expect("a forged sender must be refused whoever is on the list");
    assert!(
        err.contains("not signed by the key its sender address derives from"),
        "the wrong check answered: {err}"
    );

    // And Bob, who is on the list, still cannot read Alice's mailbox: he has
    // his own key and Alice's address, which is everything an allowlisted peer
    // holds, and it is not enough.
    assert_eq!(
        refusal(&http, &url, signed_envelope(&alice_addr, &bob, "for-alice")).await,
        None
    );
    let alice_nonce = fetch_challenge(&http, &url, &alice_addr)
        .await
        .unwrap()
        .nonce;
    let digest = inbox_auth_digest(&alice_addr, &alice_nonce);
    let stolen = MessengerInboxRequest {
        to: alice_addr.clone(),
        claimant_pubkey: hex::encode(bob.public_key().serialize_compressed()),
        nonce: alice_nonce,
        signature: hex::encode(bob.do_sign(&digest)),
    };
    let answer = fetch_inbox(&http, &url, &stolen).await.unwrap();
    assert!(
        !answer.auth_ok && answer.messages.is_empty(),
        "an allowlisted peer read another listed address's mailbox"
    );

    relay.abort();
}

/// THE DEFAULT CONSTRUCTOR, WHICH IS WHAT A FORGETFUL CALLER GETS.
///
/// `build_router(state)` is the entry point that names nobody. Until this
/// change it built a relay open to whoever could reach the socket, so every
/// caller that did not think about the question shipped an open relay, and the
/// wallet's own embedded relay was one of them whenever its owner had typed
/// nothing. It now builds a relay that carries mail for nobody.
///
/// The two halves are run side by side against the same stranger with the same
/// envelope, and the run prints both answers, so the change is one command's
/// output rather than a claim. `serving_everybody` is the old behaviour exactly:
/// it is what `build_router` used to construct.
#[tokio::test]
async fn the_default_relay_denies_and_the_old_default_did_not() {
    let stranger = Account::create_by("default-stranger").unwrap();
    let stranger_addr = stranger.readable().to_string();
    let http = Client::new();

    // BEFORE: what `build_router` used to construct.
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    let old = build_router_with(
        relay_state_from_secret(sk, "http://127.0.0.1:1".to_string()),
        RelayAccess::for_addresses(InboxAllowlist::serving_everybody()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old_url = format!("http://{}", listener.local_addr().unwrap());
    let old_relay = tokio::spawn(async move { serve_router(listener, old).await.unwrap() });
    let before = refusal(
        &http,
        &old_url,
        signed_envelope(&stranger_addr, &stranger, "before-1"),
    )
    .await;

    // AFTER: what `build_router` constructs now, through the shipped function
    // and not through a hand built access value.
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    let now = dust_whisper::relay::build_router(relay_state_from_secret(
        sk,
        "http://127.0.0.1:1".to_string(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new_url = format!("http://{}", listener.local_addr().unwrap());
    let new_relay = tokio::spawn(async move { serve_router(listener, now).await.unwrap() });
    let after = refusal(
        &http,
        &new_url,
        signed_envelope(&stranger_addr, &stranger, "after-1"),
    )
    .await;

    println!("stranger address {stranger_addr}");
    println!("BEFORE, a relay built naming nobody: {before:?}");
    println!("AFTER,  a relay built naming nobody: {after:?}");
    // The challenge route answers both in the same shape, deliberately: what
    // changed is whether the nonce is worth anything, not what it looks like.
    // See `a_stranger_cannot_tell_a_listed_address_from_an_unlisted_one`.
    let before_inbox = fetch_inbox(
        &http,
        &old_url,
        &inbox_request(
            &stranger,
            &fetch_challenge(&http, &old_url, &stranger_addr)
                .await
                .unwrap()
                .nonce,
        ),
    )
    .await
    .unwrap();
    let after_inbox = fetch_inbox(
        &http,
        &new_url,
        &inbox_request(
            &stranger,
            &fetch_challenge(&http, &new_url, &stranger_addr)
                .await
                .unwrap()
                .nonce,
        ),
    )
    .await
    .unwrap();
    println!(
        "BEFORE, that address could open its inbox: {}",
        before_inbox.auth_ok
    );
    println!(
        "AFTER,  that address could open its inbox: {}",
        after_inbox.auth_ok
    );
    assert!(before_inbox.auth_ok);
    assert!(!after_inbox.auth_ok);

    assert_eq!(before, None, "the old default was an open relay");
    assert!(
        after.is_some(),
        "the default relay accepted a message for an address nobody named"
    );

    old_relay.abort();
    new_relay.abort();
}
