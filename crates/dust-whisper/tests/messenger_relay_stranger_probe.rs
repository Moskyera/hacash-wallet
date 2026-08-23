//! ADVERSARIAL PROBE, originally written by a reviewer to demonstrate four
//! leaks in the shipped relay. Every probe below is the one that found them,
//! unchanged in what it sends and what it prints. The assertions are the ones
//! that were flipped when the leaks were closed, so this file is now the
//! regression test for exactly the attacks that worked.
//!
//! What was found, and what each probe now holds:
//!
//! 1. `GET /whisper/v1/messenger/challenge?to=X` answered a listed address with
//!    a 32 character nonce and an unlisted one with an empty string, with no
//!    credential of any kind. A neighbour could put candidate addresses to it
//!    and read the host's correspondent list straight back out. It hands every
//!    caller a nonce of the same shape now, and writes down only the ones it
//!    means; a decoy cannot be spent.
//! 2. `POST /whisper/v1/messenger/pubkey` confirmed it a second way, answering
//!    a stranger with the key of any listed address that had sent. It answers
//!    only a caller the relay carries mail for now.
//! 3. `POST /whisper/v1/messenger/ack` chose its refusal WORDING by list
//!    membership. It checks the signature first now, so the wording depends on
//!    what the caller sent and not on who the host listed.
//! 4. `SubmitAccess` was a check on the last hop's IP address, and section 4 of
//!    docs/RUNNING-A-RELAY.md tells operators to put a reverse proxy in front
//!    of the relay, behind which every caller in the world is 127.0.0.1. The
//!    door now wants a secret derived from the relay's key file as well.
//!
//! Nothing here contacts a real node, a real network or mainnet: every relay
//! points at a dead port.

use std::net::{IpAddr, SocketAddr, UdpSocket};

use dust_whisper::messenger_auth::{envelope_auth_digest, inbox_auth_digest};
use dust_whisper::messenger_client::{
    PubkeyAsker, fetch_challenge, fetch_inbox, fetch_peer_pubkey, send_envelope,
};
use dust_whisper::messenger_relay::InboxAllowlist;
use dust_whisper::protocol::{
    INFO_PATH, MessengerEnvelope, MessengerInboxRequest, SUBMIT_PATH, WhisperInfo,
    WhisperInnerPayload, WhisperSubmitRequest, WhisperSubmitResponse,
};
use dust_whisper::relay::{RelayAccess, build_router_with, relay_state_from_secret, serve_router};
use reqwest::Client;
use std::time::Duration;
use sys::Account;
use tokio::task::JoinHandle;

const ASK: Duration = Duration::from_secs(3);

async fn spawn_relay_on(bind: &str, access: RelayAccess) -> (SocketAddr, JoinHandle<()>) {
    let (sk, _pk) = dust_whisper::crypto::generate_relay_keypair();
    // A node URL that points at nothing. Nothing in this file contacts a real
    // node, a real network or mainnet.
    let state = relay_state_from_secret(sk, "http://127.0.0.1:1".to_string());
    let app = build_router_with(state, access);
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = serve_router(listener, app).await;
    });
    (addr, handle)
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

/// What a passer-by presents at the key directory, which is nothing.
fn no_credential() -> PubkeyAsker<'static> {
    PubkeyAsker {
        address: "",
        pubkey_hex: "",
        nonce: "",
        signature: "",
    }
}

/// This machine's address on its own network, the way `desktop_relay` finds it.
fn route_local_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("203.0.113.1:9").ok()?;
    let addr = socket.local_addr().ok()?.ip();
    if addr.is_loopback() || addr.is_unspecified() {
        return None;
    }
    Some(addr)
}

/// FINDING 1, CLOSED: THE ACCEPTANCE IS SYMMETRIC TOO NOW.
///
/// The old suite compared two REFUSED addresses and found the answers
/// identical, which they were. It never compared a refused address with a
/// LISTED one, and that is the comparison an attacker makes.
///
/// `GET /whisper/v1/messenger/challenge?to=X` is still unauthenticated, because
/// the wallet that needs it is asking before it has anything to present. What
/// changed is that it hands back a nonce of the same shape whatever X is, and
/// only writes down the ones it means. The nonce an unlisted address receives
/// is sixteen fresh random bytes that no table has ever seen, so it cannot be
/// spent - which this test also checks, because "same length" without "worth
/// nothing" would be a cosmetic fix.
#[tokio::test]
async fn a_stranger_cannot_test_any_address_against_the_hosts_list() {
    let owner = Account::create_by("probe-owner").unwrap();
    let friend = Account::create_by("probe-friend").unwrap();
    let outsider = Account::create_by("probe-outsider").unwrap();
    let (addr, relay) = spawn_relay_on(
        "127.0.0.1:0",
        RelayAccess::for_addresses(InboxAllowlist::from_addresses([
            owner.readable(),
            friend.readable(),
        ])),
    )
    .await;
    let url = format!("http://{addr}");
    let http = Client::builder().timeout(ASK).build().unwrap();

    let on_the_list = fetch_challenge(&http, &url, friend.readable())
        .await
        .unwrap();
    let off_the_list = fetch_challenge(&http, &url, outsider.readable())
        .await
        .unwrap();

    println!("== FINDING 1: the unauthenticated membership test, closed ==");
    println!(
        "host listed        {} and {}",
        owner.readable(),
        friend.readable()
    );
    println!("stranger asks about a LISTED address");
    println!(
        "  GET /whisper/v1/messenger/challenge?to={}",
        friend.readable()
    );
    println!(
        "  nonce = {:?}   ({} chars)",
        on_the_list.nonce,
        on_the_list.nonce.len()
    );
    println!("stranger asks about an UNLISTED address");
    println!(
        "  GET /whisper/v1/messenger/challenge?to={}",
        outsider.readable()
    );
    println!(
        "  nonce = {:?}   ({} chars)",
        off_the_list.nonce,
        off_the_list.nonce.len()
    );

    assert_eq!(
        on_the_list.nonce.len(),
        off_the_list.nonce.len(),
        "listed and unlisted are still distinguishable to an unauthenticated caller"
    );
    assert_eq!(on_the_list.nonce.len(), 32);
    assert_ne!(
        on_the_list.nonce, off_the_list.nonce,
        "two nonces came back identical, so they are not random"
    );

    // And the decoy is a decoy: the outsider signs it perfectly with her own
    // key and it opens nothing.
    let spent = fetch_inbox(&http, &url, &inbox_request(&outsider, &off_the_list.nonce))
        .await
        .unwrap();
    println!("  the outsider spends her nonce: auth_ok={}", spent.auth_ok);
    assert!(!spent.auth_ok, "the decoy nonce actually worked");

    // The listed friend's nonce is real, which is what makes the relay useful.
    let real = fetch_inbox(&http, &url, &inbox_request(&friend, &on_the_list.nonce))
        .await
        .unwrap();
    assert!(
        real.auth_ok,
        "a listed address can no longer collect its own mail"
    );
    relay.abort();
}

/// The same oracle, run the way an attacker would: a list of candidate
/// addresses in, and now nothing out.
#[tokio::test]
async fn the_oracle_no_longer_enumerates_a_hosts_correspondents() {
    let owner = Account::create_by("enum-owner").unwrap();
    let friend = Account::create_by("enum-friend").unwrap();
    let served = [owner.readable().to_string(), friend.readable().to_string()];
    let (addr, relay) = spawn_relay_on(
        "127.0.0.1:0",
        RelayAccess::for_addresses(InboxAllowlist::from_addresses(&served)),
    )
    .await;
    let url = format!("http://{addr}");
    let http = Client::builder().timeout(ASK).build().unwrap();

    // Eight addresses a stranger might already hold: two of them are the
    // host's, six are not. Nothing tells the stranger which in advance.
    let mut candidates: Vec<String> = vec![owner.readable().to_string()];
    for i in 0..6 {
        candidates.push(
            Account::create_by(&format!("enum-candidate-{i}"))
                .unwrap()
                .readable()
                .to_string(),
        );
    }
    candidates.push(friend.readable().to_string());

    // The attacker's exact rule: a non-empty nonce meant "on the list".
    let mut recovered: Vec<String> = Vec::new();
    let mut lengths: Vec<usize> = Vec::new();
    for candidate in &candidates {
        let answer = fetch_challenge(&http, &url, candidate).await.unwrap();
        lengths.push(answer.nonce.len());
        if !answer.nonce.is_empty() {
            recovered.push(candidate.clone());
        }
    }

    println!("== FINDING 1b: the list is no longer readable out of the relay ==");
    println!("candidates tried   {}", candidates.len());
    println!("host's actual list {served:?}");
    println!("answer lengths     {lengths:?}");
    println!(
        "stranger recovered {} of {} - every candidate answered alike",
        recovered.len(),
        candidates.len()
    );
    assert_eq!(
        recovered.len(),
        candidates.len(),
        "the answers still separate into two groups"
    );
    assert!(
        lengths.windows(2).all(|w| w[0] == w[1]),
        "the answer length varied by candidate: {lengths:?}"
    );
    relay.abort();
}

/// FINDING 2, CLOSED: THE KEY DIRECTORY ASKS WHO IS ASKING.
///
/// A key used to come back for any address that was on the list AND had sent
/// through this relay, to any caller at all. That is the "these two people talk
/// to each other" fact, handed to a stranger. It cannot be made symmetric by
/// inventing an answer, because an address is the hash of its own key and a
/// decoy fails that check - so the route stopped answering strangers instead.
#[tokio::test]
async fn the_key_directory_refuses_a_stranger() {
    let owner = Account::create_by("dir-owner").unwrap();
    let friend = Account::create_by("dir-friend").unwrap();
    let outsider = Account::create_by("dir-outsider").unwrap();
    let (addr, relay) = spawn_relay_on(
        "127.0.0.1:0",
        RelayAccess::for_addresses(InboxAllowlist::from_addresses([
            owner.readable(),
            friend.readable(),
        ])),
    )
    .await;
    let url = format!("http://{addr}");
    let http = Client::builder().timeout(ASK).build().unwrap();

    // One ordinary message from the friend to the owner, which is the whole
    // point of the relay existing.
    send_envelope(
        &http,
        &url,
        signed_envelope(owner.readable(), &friend, "dir-1"),
    )
    .await
    .expect("a listed friend may post to a listed owner");

    let listed = fetch_peer_pubkey(&http, &url, friend.readable(), &no_credential(), ASK)
        .await
        .unwrap();
    let unlisted = fetch_peer_pubkey(&http, &url, outsider.readable(), &no_credential(), ASK)
        .await
        .unwrap();

    println!("== FINDING 2: the directory refuses a stranger ==");
    println!(
        "POST /whisper/v1/messenger/pubkey  address={}  (no credential)",
        friend.readable()
    );
    println!("  -> {listed:?}");
    println!(
        "POST /whisper/v1/messenger/pubkey  address={}  (no credential)",
        outsider.readable()
    );
    println!("  -> {unlisted:?}");

    assert_eq!(
        listed, unlisted,
        "the directory still tells a listed address apart for a stranger"
    );
    assert!(listed.is_none());

    // The owner, who the relay is for, still gets the answer - or first contact
    // could never be sealed.
    let nonce = fetch_challenge(&http, &url, owner.readable())
        .await
        .unwrap()
        .nonce;
    let signature = hex::encode(owner.do_sign(&inbox_auth_digest(owner.readable(), &nonce)));
    let pubkey_hex = hex::encode(owner.public_key().serialize_compressed());
    let credential = PubkeyAsker {
        address: owner.readable(),
        pubkey_hex: &pubkey_hex,
        nonce: &nonce,
        signature: &signature,
    };
    let answered = fetch_peer_pubkey(&http, &url, friend.readable(), &credential, ASK)
        .await
        .unwrap();
    println!("the same question from the address the relay is FOR: {answered:?}");
    assert_eq!(
        answered,
        Some(hex::encode(friend.public_key().serialize_compressed())),
        "the relay stopped answering the people it is for"
    );
    relay.abort();
}

/// FINDING 3, CLOSED: THE TRANSACTION DOOR NO LONGER TRUSTS THE LAST HOP.
///
/// The Privacy screen says, of the transaction door: "A machine on your network
/// that tries is refused before its payload is read, whatever the bind is and
/// whoever is on the list."
///
/// The check was `ConnectInfo<SocketAddr>.ip().is_loopback()`, which is the
/// address of whoever opened the TCP connection. Section 4 of
/// docs/RUNNING-A-RELAY.md tells the operator to "Keep it on loopback and let a
/// reverse proxy be the only thing exposed", and ships a Caddy and an nginx
/// config that both `proxy_pass http://127.0.0.1:8787`. Behind either of them
/// every request in the world arrived from 127.0.0.1, and the sentence on the
/// screen was false in the deployment the docs prescribe.
///
/// This test runs both halves against one relay on one machine: a connection
/// opened directly to the relay's own network address, and the identical
/// submission one TCP hop later through a forwarder standing where the
/// documented proxy stands. Both are refused now.
#[tokio::test]
async fn a_reverse_proxy_no_longer_makes_every_submitter_local() {
    let Some(lan) = route_local_address() else {
        println!("no non-loopback local address on this machine; nothing to prove against");
        return;
    };

    // The relay, bound wide, transaction door at its shipped default.
    let (relay_addr, relay) = spawn_relay_on("0.0.0.0:0", RelayAccess::closed()).await;
    let port = relay_addr.port();
    let http = Client::builder().timeout(ASK).build().unwrap();
    let direct = format!("http://{lan}:{port}");

    let info: WhisperInfo = http
        .get(format!("{direct}{INFO_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A. Straight at the relay, from this machine's own network address. The
    //    kernel reports a non-loopback peer, and the door holds.
    let refused: WhisperSubmitResponse = http
        .post(format!("{direct}{SUBMIT_PATH}"))
        .json(&sealed_transaction(&info.pubkey))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refused_err = refused.err.clone().unwrap_or_default();

    // B. The documented deployment: a proxy listening where a friend can reach
    //    it and opening its own connection to 127.0.0.1. Twenty lines is all a
    //    reverse proxy is, for this purpose. It adds no headers, deliberately:
    //    a forwarder that adds none is the hardest case, and sniffing for
    //    `X-Forwarded-For` would not have closed anything.
    let proxy_listener = tokio::net::TcpListener::bind(format!("{lan}:0"))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, from)) = proxy_listener.accept().await else {
                return;
            };
            println!("  proxy accepted a connection from {from}");
            tokio::spawn(async move {
                let Ok(mut outbound) =
                    tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });

    let through_proxy = format!("http://{proxy_addr}");
    let proxied: WhisperSubmitResponse = http
        .post(format!("{through_proxy}{SUBMIT_PATH}"))
        .json(&sealed_transaction(&info.pubkey))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxied_err = proxied.err.clone().unwrap_or_default();

    println!("== FINDING 3: the transaction door and the documented proxy ==");
    println!("relay bound        0.0.0.0:{port}, RelayAccess::closed() (the shipped default)");
    println!("A. straight to the relay at {direct}");
    println!("   ret={} err={refused_err:?}", refused.ret);
    println!("B. the same submission through a proxy at {through_proxy} -> 127.0.0.1:{port}");
    println!("   ret={} err={proxied_err:?}", proxied.ret);

    assert!(
        refused_err.contains("does not accept transactions from other machines"),
        "direct connection from a non-loopback address should be refused: {refused_err}"
    );
    assert!(
        proxied_err.contains("does not accept transactions from other machines"),
        "one TCP hop still launders a stranger into a local submitter: {proxied_err}"
    );
    assert!(
        !proxied_err.contains("node forward"),
        "the proxied submission reached the forward step, so the payload was read: {proxied_err}"
    );

    proxy.abort();
    relay.abort();
}

/// The messenger allowlist is NOT defeated by the same proxy either, because it
/// keys on an address rather than on the connection. Recorded so the finding
/// above is not read wider than it is.
#[tokio::test]
async fn the_same_proxy_does_not_defeat_the_address_list() {
    let Some(lan) = route_local_address() else {
        return;
    };
    let owner = Account::create_by("proxy-owner").unwrap();
    let stranger = Account::create_by("proxy-stranger").unwrap();
    let (relay_addr, relay) = spawn_relay_on(
        "0.0.0.0:0",
        RelayAccess::for_addresses(InboxAllowlist::from_addresses([owner.readable()])),
    )
    .await;
    let port = relay_addr.port();
    let proxy_listener = tokio::net::TcpListener::bind(format!("{lan}:0"))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = proxy_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(mut outbound) =
                    tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    let http = Client::builder().timeout(ASK).build().unwrap();
    let url = format!("http://{proxy_addr}");
    let err = send_envelope(
        &http,
        &url,
        signed_envelope(owner.readable(), &stranger, "proxy-1"),
    )
    .await
    .expect_err("an unlisted sender is refused whatever hop they arrive on");
    println!("== the address list survives the proxy ==");
    println!("unlisted sender through the proxy: {err}");
    assert!(
        err.to_string()
            .contains("carries mail only for the addresses")
    );
    proxy.abort();
    relay.abort();
}

/// FINDING 1c, CLOSED: THE ACK ROUTE ANSWERS IN ONE VOICE.
///
/// `NOT_ON_THE_LIST` is documented as "One sentence, and the same sentence for
/// every refused address on every path". `ack_handler` did not use it: an
/// address the host did not list was told "invalid or expired challenge"; an
/// address the host DID list, presented with the same garbage signature, was
/// told "invalid inbox auth signature". Two different sentences, chosen by
/// whether the address was on the list, to a caller with no credential at all.
///
/// The signature is checked first now, so the wording is decided by what the
/// caller sent.
#[tokio::test]
async fn the_ack_route_answers_listed_and_unlisted_in_the_same_words() {
    let owner = Account::create_by("ack-owner").unwrap();
    let outsider = Account::create_by("ack-outsider").unwrap();
    let (addr, relay) = spawn_relay_on(
        "127.0.0.1:0",
        RelayAccess::for_addresses(InboxAllowlist::from_addresses([owner.readable()])),
    )
    .await;
    let url = format!("http://{addr}");
    let http = Client::builder().timeout(ASK).build().unwrap();

    // The same nonsense claim, twice, differing only in the address it names.
    let junk = |to: &str| {
        serde_json::json!({
            "to": to,
            "claimant_pubkey": "00",
            "nonce": "0123456789abcdef0123456789abcdef",
            "signature": "00",
            "ids": [],
        })
    };
    let ask = async |to: &str| -> String {
        http.post(format!("{url}/whisper/v1/messenger/ack"))
            .json(&junk(to))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };

    let listed = ask(owner.readable()).await;
    let unlisted = ask(outsider.readable()).await;
    println!("== FINDING 1c: one refusal on /ack ==");
    println!("a LISTED address    {listed}");
    println!("an UNLISTED address {unlisted}");
    assert_eq!(
        listed, unlisted,
        "the ack refusals still differ, so the wording still names the list"
    );
    relay.abort();
}
