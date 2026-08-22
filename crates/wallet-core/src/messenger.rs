//! Encrypted wallet-to-wallet chat via DUST Whisper relay + encrypted local history.

use std::fs;

use chrono::Utc;
use dust_whisper::protocol::{MessengerAckRequest, MessengerEnvelope, MessengerInboxRequest};
use serde::{Deserialize, Serialize};
use sys::Account;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::messenger_crypto::{
    MESSENGER_CRYPTO_V1, MESSENGER_CRYPTO_V2, decrypt_body, decrypt_store, encrypt_body_v1,
    encrypt_body_v2, encrypt_store, parse_pubkey_hex, pubkey_hex, sign_inbox_auth,
    storage_key_from_secret, verify_pubkey_address,
};
use crate::paths::{messenger_path, secure_write};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: String,
    pub peer: String,
    pub direction: MessageDirection,
    pub body: String,
    pub timestamp_utc: String,
    pub delivered: bool,
    /// Whether this one message travelled under ECDH to the peer's own key.
    ///
    /// `Some(true)` is v2. `Some(false)` is v1, whose key is derived from the
    /// two addresses the relay stores in clear, so the operator can read it.
    /// `None` is a record written before this field existed, about which
    /// nothing is known. The screen counts anything that is not `Some(true)` as
    /// "not known to be sealed", which is the only claim the data supports.
    #[serde(default)]
    pub sealed: Option<bool>,
}

/// What the screen is allowed to say about one conversation's privacy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessengerPeerSecurity {
    /// This wallet holds a verified key for the peer, so the next send is v2.
    pub sends_sealed: bool,
    /// Messages already in this thread that are not known to have been sealed.
    pub unsealed_messages: u32,
}

/// What one pass over the configured relays actually managed to do.
///
/// A bare "how many messages arrived" cannot carry the difference between an
/// empty inbox, a relay that never answered, and a relay that refused the
/// claim. All three used to arrive at the screen as the number zero, and the
/// screen turned that into "the relay had nothing new".
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessengerPollOutcome {
    /// New messages taken into local history.
    pub added: u32,
    /// Relay URLs configured and attempted.
    pub relays_tried: u32,
    /// Relays that answered the inbox request and accepted the claim.
    pub relays_answered: u32,
    /// Relays that answered but refused the inbox claim.
    pub relays_refused: u32,
    /// Envelopes dropped because their sender could not be verified.
    pub rejected_envelopes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatThread {
    pub peer: String,
    pub last_message: String,
    pub last_timestamp_utc: String,
    pub unread: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MessengerStore {
    messages: Vec<ChatMessage>,
    /// Peer address -> compressed secp256k1 pubkey hex, learned from inbound
    /// envelopes and kept only after the key derives back to that address.
    /// Without it a send has nothing to seal against and falls back to v1,
    /// whose key is the two public addresses and therefore no secret at all.
    #[serde(default)]
    peer_keys: std::collections::BTreeMap<String, String>,
}

struct MessengerCtx<'a> {
    account: &'a Account,
    my_address: &'a str,
    storage_key: Zeroizing<[u8; 32]>,
}

impl MessengerStore {
    fn load(ctx: &MessengerCtx<'_>) -> WalletResult<Self> {
        let path = messenger_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        // The old format could contain plaintext messages. Keep every read in
        // a wiping owner and migrate legacy plaintext before returning it.
        let raw = Zeroizing::new(fs::read(&path).map_err(|e| WalletError::Other(e.to_string()))?);
        if let Ok(text) = std::str::from_utf8(&raw)
            && text.trim_start().starts_with('{')
            && text.contains("\"messages\"")
        {
            let store: Self =
                serde_json::from_str(text).map_err(|e| WalletError::Other(e.to_string()))?;
            let encrypted = encrypt_store(&raw, &ctx.storage_key)?;
            secure_write(&path, &encrypted).map_err(|e| WalletError::Other(e.to_string()))?;
            return Ok(store);
        }
        match decrypt_store(&raw, &ctx.storage_key) {
            Ok(plain) => {
                serde_json::from_slice(&plain).map_err(|e| WalletError::Other(e.to_string()))
            }
            Err(_) => {
                let backup =
                    path.with_extension(format!("bak.{}", Utc::now().format("%Y%m%d%H%M%S")));
                let _ = fs::rename(&path, &backup);
                Ok(Self::default())
            }
        }
    }

    fn save(&self, ctx: &MessengerCtx<'_>) -> WalletResult<()> {
        let path = messenger_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::Other(e.to_string()))?;
        }
        let json = Zeroizing::new(
            serde_json::to_vec(self).map_err(|e| WalletError::Other(e.to_string()))?,
        );
        let enc = encrypt_store(&json, &ctx.storage_key)?;
        secure_write(&path, &enc).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn threads(&self) -> Vec<ChatThread> {
        let mut map: std::collections::HashMap<String, ChatThread> =
            std::collections::HashMap::new();
        for m in &self.messages {
            let entry = map.entry(m.peer.clone()).or_insert_with(|| ChatThread {
                peer: m.peer.clone(),
                last_message: String::new(),
                last_timestamp_utc: String::new(),
                unread: 0,
            });
            if m.timestamp_utc >= entry.last_timestamp_utc {
                entry.last_message = m.body.clone();
                entry.last_timestamp_utc = m.timestamp_utc.clone();
            }
            if m.direction == MessageDirection::In && !m.delivered {
                entry.unread += 1;
            }
        }
        let mut out: Vec<_> = map.into_values().collect();
        out.sort_by(|a, b| b.last_timestamp_utc.cmp(&a.last_timestamp_utc));
        out
    }

    pub fn messages_for(&self, peer: &str) -> Vec<ChatMessage> {
        let mut out: Vec<_> = self
            .messages
            .iter()
            .filter(|m| m.peer == peer)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc));
        out
    }

    fn push(&mut self, msg: ChatMessage) {
        self.messages.push(msg);
    }

    fn mark_read(&mut self, peer: &str) {
        for m in &mut self.messages {
            if m.peer == peer && m.direction == MessageDirection::In {
                m.delivered = true;
            }
        }
    }

    fn has_id(&self, id: &str) -> bool {
        self.messages.iter().any(|m| m.id == id)
    }

    /// Record a peer's public key, but only once it hashes back to the address
    /// it claims. A stranger can supply the right key for someone else's
    /// address; that is harmless, because sealing to it still means only the
    /// holder of the matching secret can open the message. Supplying a *wrong*
    /// key is what this rejects. Returns true when the stored key changed.
    fn learn_peer_key(&mut self, peer: &str, pubkey_hex_str: &str) -> bool {
        let Ok(parsed) = parse_pubkey_hex(pubkey_hex_str) else {
            return false;
        };
        if !verify_pubkey_address(&parsed, peer) {
            return false;
        }
        let normalized = hex::encode(parsed);
        if self.peer_keys.get(peer) == Some(&normalized) {
            return false;
        }
        self.peer_keys.insert(peer.to_string(), normalized);
        true
    }

    fn peer_key(&self, peer: &str) -> Option<[u8; 33]> {
        let stored = self.peer_keys.get(peer)?;
        let parsed = parse_pubkey_hex(stored).ok()?;
        verify_pubkey_address(&parsed, peer).then_some(parsed)
    }
}

fn messenger_ctx<'a>(account: &'a WalletAccount, my_address: &'a str) -> MessengerCtx<'a> {
    let sk = Zeroizing::new(account.inner().secret_key().serialize());
    MessengerCtx {
        account: account.inner(),
        my_address,
        storage_key: Zeroizing::new(storage_key_from_secret(&sk)),
    }
}

fn encrypt_for_send(
    ctx: &MessengerCtx<'_>,
    peer: &str,
    body: &str,
    sent_at: &str,
    peer_pubkey: Option<&[u8; 33]>,
) -> WalletResult<(u8, String, String, Option<String>)> {
    if let Some(peer_pk) = peer_pubkey {
        let (nonce, ciphertext) =
            encrypt_body_v2(ctx.account, ctx.my_address, peer, peer_pk, body, sent_at)?;
        Ok((
            MESSENGER_CRYPTO_V2,
            nonce,
            ciphertext,
            Some(pubkey_hex(ctx.account)),
        ))
    } else {
        let (nonce, ciphertext) = encrypt_body_v1(ctx.my_address, peer, body, sent_at);
        Ok((
            MESSENGER_CRYPTO_V1,
            nonce,
            ciphertext,
            Some(pubkey_hex(ctx.account)),
        ))
    }
}

/// The recipient of a message, checked against what can actually collect one.
///
/// Two things have to be true, and neither was checked before.
///
/// The string has to decode as a Hacash address at all. `Address::from_readable`
/// verifies the base58check payload, so a typo or a truncated paste fails here
/// rather than becoming a conversation.
///
/// And the address has to be one whose inbox can be claimed. Delivery is not
/// "a relay accepted the bytes": the recipient still has to fetch the envelope,
/// and fetching means signing the relay's challenge with the secp256k1 key that
/// derives to the claimed address - `messenger_crypto::verify_pubkey_address`,
/// against `Account::get_address_by_public_key`, which stamps version 0. This
/// wallet's own inbox request is likewise always `Account::readable()`. So a
/// contract, P2SH, PQC or hybrid address has no key anywhere that could claim
/// its inbox, and a message addressed to one is undeliverable by construction
/// no matter how healthy the relay is.
///
/// Returns the trimmed address, which is what gets stored and encrypted to.
fn require_messenger_peer(peer: &str) -> WalletResult<String> {
    let trimmed = peer.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Other("enter a recipient address".into()));
    }
    let decoded = field::Address::from_readable(trimmed).map_err(|_| {
        WalletError::Other("that is not a Hacash address. Check the recipient and try again".into())
    })?;
    if decoded.version() != field::Address::PRIVAKEY {
        return Err(WalletError::Other(
            "messages can only be sent to a standard Hacash account address. This address has no \
             signing key that could ever collect its messages, so nothing sent to it would arrive"
                .into(),
        ));
    }
    Ok(trimmed.to_string())
}

pub async fn messenger_send(
    http: &reqwest::Client,
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
    body: &str,
    relay_urls: &[String],
    peer_pubkey_hex: Option<&str>,
) -> WalletResult<ChatMessage> {
    let peer = require_messenger_peer(peer)?;
    let peer = peer.as_str();
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Other("empty message".into()));
    }
    let ctx = messenger_ctx(account, my_address);
    let sent_at = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    // The store is loaded before the body is sealed, not after it is sent: it
    // is where this wallet keeps the peer keys it has learned, and a key here
    // is the difference between ECDH (v2) and a "key" the relay already has
    // both halves of (v1).
    let mut store = MessengerStore::load(&ctx)?;
    let peer_pk = match peer_pubkey_hex {
        Some(hex_str) => Some(parse_pubkey_hex(hex_str)?),
        None => store.peer_key(peer),
    };
    let (crypto_v, nonce, ciphertext, from_pubkey) =
        encrypt_for_send(&ctx, peer, trimmed, &sent_at, peer_pk.as_ref())?;

    let mut envelope = MessengerEnvelope {
        v: crypto_v,
        id: id.clone(),
        to: peer.to_string(),
        from: my_address.to_string(),
        from_pubkey,
        from_sig: None,
        nonce,
        ciphertext,
        sent_at: sent_at.clone(),
    };
    // Sign the envelope so the recipient can tell this really came from here.
    // Both the relay and the receiving wallet refuse an envelope without it.
    let digest = dust_whisper::messenger_auth::envelope_auth_digest(&envelope);
    envelope.from_sig = Some(hex::encode(ctx.account.do_sign(&digest)));

    let mut relay_ok = false;
    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        if dust_whisper::messenger_client::send_envelope(http, u, envelope.clone())
            .await
            .is_ok()
        {
            relay_ok = true;
            break;
        }
    }

    let msg = ChatMessage {
        id,
        peer: peer.to_string(),
        direction: MessageDirection::Out,
        body: trimmed.to_string(),
        timestamp_utc: sent_at,
        delivered: relay_ok,
        sealed: Some(crypto_v == MESSENGER_CRYPTO_V2),
    };

    store.push(msg.clone());
    store.save(&ctx)?;
    Ok(msg)
}

/// What is true about one conversation's privacy, for the screen to repeat.
///
/// `sends_sealed` is about the future only: it says this wallet holds a
/// verified key for the peer, so the next message is sealed with ECDH to a key
/// only that peer's secret opens. It says nothing about the messages already on
/// screen, which is why `unsealed_messages` is counted separately: a thread can
/// be sealed from here on while every bubble above the banner travelled under
/// v1, whose key is derived from the two addresses the relay holds in clear.
pub fn messenger_peer_security(
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
) -> WalletResult<MessengerPeerSecurity> {
    let trimmed = peer.trim();
    if trimmed.is_empty() {
        return Ok(MessengerPeerSecurity {
            sends_sealed: false,
            unsealed_messages: 0,
        });
    }
    let ctx = messenger_ctx(account, my_address);
    let store = MessengerStore::load(&ctx)?;
    let unsealed = store
        .messages_for(trimmed)
        .iter()
        .filter(|m| m.sealed != Some(true))
        .count();
    Ok(MessengerPeerSecurity {
        sends_sealed: store.peer_key(trimmed).is_some(),
        unsealed_messages: unsealed.min(u32::MAX as usize) as u32,
    })
}

pub async fn messenger_poll_inbox(
    http: &reqwest::Client,
    account: &WalletAccount,
    my_address: &str,
    relay_urls: &[String],
) -> WalletResult<MessengerPollOutcome> {
    let ctx = messenger_ctx(account, my_address);
    let mut store = MessengerStore::load(&ctx)?;
    let mut outcome = MessengerPollOutcome::default();
    let mut learned = false;
    let claimant_pubkey = pubkey_hex(ctx.account);

    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        outcome.relays_tried += 1;
        // Ack ids belong to the relay they were read from, so they start empty
        // for each one.
        let mut ack_ids: Vec<String> = Vec::new();
        let challenge =
            match dust_whisper::messenger_client::fetch_challenge(http, u, my_address).await {
                Ok(c) => c,
                Err(_) => continue,
            };
        let signature = sign_inbox_auth(ctx.account, my_address, &challenge.nonce);
        let request = MessengerInboxRequest {
            to: my_address.to_string(),
            claimant_pubkey: claimant_pubkey.clone(),
            nonce: challenge.nonce.clone(),
            signature: signature.clone(),
        };
        let answer = match dust_whisper::messenger_client::fetch_inbox(http, u, &request).await {
            Ok(a) => a,
            Err(_) => continue,
        };
        if !answer.auth_ok {
            // The relay answered and would not hand the inbox over. That is not
            // an empty inbox, and the person has to be told the difference.
            outcome.relays_refused += 1;
            continue;
        }
        outcome.relays_answered += 1;

        for env in answer.messages {
            // Who wrote this, checked before anything is believed about it.
            // `from` is otherwise a free string on an envelope the relay took
            // from anyone, so an unverified envelope must not become a message
            // in that person's thread, and must not teach this wallet a key.
            if !dust_whisper::messenger_auth::verify_envelope_sender(&env) {
                outcome.rejected_envelopes += 1;
                // Acked so it stops coming back. A malformed or forged envelope
                // left on the relay used to be re-read on every poll; one of
                // them once aborted the whole poll, forever.
                ack_ids.push(env.id);
                continue;
            }
            // The sender pubkey is verified, so keeping it is safe, and it is
            // what lets the reply be sealed with ECDH instead of falling back
            // to a key the relay can derive from the addresses it holds. Done
            // before the duplicate check, so a re-delivered envelope still
            // teaches this wallet a key it may have missed the first time.
            if let Some(claimed) = env.from_pubkey.as_deref() {
                learned |= store.learn_peer_key(&env.from, claimed);
            }
            if store.has_id(&env.id) {
                ack_ids.push(env.id.clone());
                continue;
            }
            let peer_pk = match env.from_pubkey.as_deref().map(parse_pubkey_hex).transpose() {
                Ok(pk) => pk,
                Err(_) => {
                    // Unreachable while the verification above holds, and a
                    // skip either way: one bad envelope may never stop the
                    // poll, which is what a `?` here used to do.
                    outcome.rejected_envelopes += 1;
                    ack_ids.push(env.id);
                    continue;
                }
            };
            let plain = match decrypt_body(
                ctx.account,
                my_address,
                &env.from,
                peer_pk.as_ref(),
                env.v,
                &env.nonce,
                &env.ciphertext,
            ) {
                Ok(p) => p,
                Err(_) => continue,
            };
            store.push(ChatMessage {
                id: env.id.clone(),
                peer: env.from,
                direction: MessageDirection::In,
                body: plain.body,
                timestamp_utc: plain.sent_at,
                delivered: false,
                sealed: Some(env.v == MESSENGER_CRYPTO_V2),
            });
            ack_ids.push(env.id);
            outcome.added += 1;
        }

        if !ack_ids.is_empty()
            && let Ok(challenge) =
                dust_whisper::messenger_client::fetch_challenge(http, u, my_address).await
        {
            let sig = sign_inbox_auth(ctx.account, my_address, &challenge.nonce);
            let _ = dust_whisper::messenger_client::ack_messages(
                http,
                u,
                &MessengerAckRequest {
                    to: my_address.to_string(),
                    claimant_pubkey: claimant_pubkey.clone(),
                    nonce: challenge.nonce,
                    signature: sig,
                    ids: ack_ids.clone(),
                },
            )
            .await;
        }
    }

    if outcome.added > 0 || learned {
        store.save(&ctx)?;
    }
    Ok(outcome)
}

pub fn messenger_threads(
    account: &WalletAccount,
    my_address: &str,
) -> WalletResult<Vec<ChatThread>> {
    let ctx = messenger_ctx(account, my_address);
    Ok(MessengerStore::load(&ctx)?.threads())
}

pub fn messenger_messages(
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
) -> WalletResult<Vec<ChatMessage>> {
    let ctx = messenger_ctx(account, my_address);
    Ok(MessengerStore::load(&ctx)?.messages_for(peer))
}

pub fn messenger_mark_read(
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
) -> WalletResult<()> {
    let ctx = messenger_ctx(account, my_address);
    let mut store = MessengerStore::load(&ctx)?;
    store.mark_read(peer);
    store.save(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    #[test]
    fn store_roundtrip_encrypted() {
        let _iso = IsolatedWalletData::new();
        let acc = WalletAccount::from_secret_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let addr = acc.address();
        let ctx = messenger_ctx(&acc, &addr);
        let mut store = MessengerStore::default();
        store.push(ChatMessage {
            id: "1".into(),
            peer: "peer".into(),
            direction: MessageDirection::Out,
            body: "hi".into(),
            timestamp_utc: "t".into(),
            delivered: true,
            sealed: Some(true),
        });
        store.save(&ctx).unwrap();
        let loaded = MessengerStore::load(&ctx).unwrap();
        assert_eq!(loaded.messages.len(), 1);
    }

    fn account(tail: u8) -> WalletAccount {
        let mut hex = format!("{:0>64}", format!("{tail:x}"));
        hex.truncate(64);
        WalletAccount::from_secret_hex(&hex).unwrap()
    }

    /// One character off is the whole point.
    ///
    /// A person pasting a recipient is one keystroke away from an address that
    /// does not exist. Before this gate the send took it, encrypted to it,
    /// handed it to a relay and wrote it into local history, so the screen
    /// showed a conversation that could never receive an answer.
    #[tokio::test]
    async fn a_mistyped_recipient_is_refused_and_leaves_no_thread_behind() {
        let _iso = IsolatedWalletData::new();
        let me = account(1);
        let my_address = me.address();
        let http = reqwest::Client::new();
        // A configured relay that refuses every connection: nothing below may
        // depend on the network, and the refusal must arrive before it.
        let relays = vec!["http://127.0.0.1:1".to_string()];

        let real_peer = account(2).address();
        let mut typo: Vec<char> = real_peer.chars().collect();
        let last = typo.len() - 1;
        typo[last] = if typo[last] == 'a' { 'b' } else { 'a' };
        let typo: String = typo.into_iter().collect();
        assert_ne!(typo, real_peer);

        let contract = field::Address::create_contract([7u8; 20]).to_readable();

        for bad in [
            "not-a-hacash-address-at-all".to_string(),
            typo,
            "   ".to_string(),
            contract,
        ] {
            let outcome =
                messenger_send(&http, &me, &my_address, &bad, "meet me at 9", &relays, None).await;
            assert!(
                outcome.is_err(),
                "{bad:?} is not an address that can ever collect a message, so the send must refuse it"
            );
        }

        assert!(
            messenger_threads(&me, &my_address).unwrap().is_empty(),
            "a refused recipient must not leave a conversation behind"
        );

        // The gate must not cost the honest case anything: a real address still
        // goes through, is stored, and is honestly marked undelivered because
        // the only relay refused the connection.
        let sent = messenger_send(
            &http,
            &me,
            &my_address,
            &format!("  {real_peer}  "),
            "meet me at 9",
            &relays,
            None,
        )
        .await
        .expect("a well-formed recipient is still accepted");
        assert_eq!(
            sent.peer, real_peer,
            "the stored peer is the trimmed address"
        );
        assert!(!sent.delivered, "no relay took it, and the record says so");
        let threads = messenger_threads(&me, &my_address).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].peer, real_peer);
    }

    /// What the relay operator can read.
    ///
    /// A capture relay stands in for a hostile operator: it hands Bob's wallet
    /// one inbox message and keeps a copy of everything the wallet posts back.
    /// The eavesdrop attempt below uses only what such an operator holds — the
    /// two addresses that travel in clear on every envelope — and must fail.
    #[tokio::test]
    async fn a_reply_is_sealed_to_the_peer_key_the_relay_cannot_derive() {
        use axum::extract::{Query, State};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use dust_whisper::protocol::{
            MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH,
            MESSENGER_SEND_PATH, MessengerAckResponse, MessengerChallengeResponse,
            MessengerInboxResponse, MessengerSendRequest, MessengerSendResponse,
        };
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct CaptureRelay {
            inbox: Arc<Mutex<Vec<MessengerEnvelope>>>,
            posted: Arc<Mutex<Vec<MessengerEnvelope>>>,
        }

        fn keyed(tail: &str) -> WalletAccount {
            let mut hex = "0".repeat(64 - tail.len());
            hex.push_str(tail);
            WalletAccount::from_secret_hex(&hex).unwrap()
        }

        let _iso = IsolatedWalletData::new();
        let alice = keyed("a1");
        let bob = keyed("b0");
        let alice_addr = alice.address();
        let bob_addr = bob.address();

        // Alice opens the conversation the way a first contact has to: no key of
        // Bob's to seal against, and her own pubkey riding along in the envelope.
        let (nonce, ciphertext) =
            encrypt_body_v1(&alice_addr, &bob_addr, "you there?", "2026-08-22T09:00:00Z");
        let opening = signed_envelope(
            MessengerEnvelope {
                v: MESSENGER_CRYPTO_V1,
                id: "alice-opening".into(),
                to: bob_addr.clone(),
                from: alice_addr.clone(),
                from_pubkey: Some(pubkey_hex(alice.inner())),
                from_sig: None,
                nonce,
                ciphertext,
                sent_at: "2026-08-22T09:00:00Z".into(),
            },
            &alice,
        );

        let relay = CaptureRelay {
            inbox: Arc::new(Mutex::new(vec![opening])),
            posted: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route(
                MESSENGER_CHALLENGE_PATH,
                get(|Query(_q): Query<HashMap<String, String>>| async {
                    Json(MessengerChallengeResponse {
                        nonce: "capture-relay-nonce".into(),
                        expires_at: "2099-01-01T00:00:00Z".into(),
                    })
                }),
            )
            .route(
                MESSENGER_INBOX_PATH,
                post(
                    |State(r): State<CaptureRelay>, Json(_): Json<serde_json::Value>| async move {
                        let messages: Vec<MessengerEnvelope> = r.inbox.lock().unwrap().clone();
                        Json(MessengerInboxResponse {
                            messages,
                            auth_ok: true,
                        })
                    },
                ),
            )
            .route(
                MESSENGER_ACK_PATH,
                post(
                    |State(r): State<CaptureRelay>, Json(_): Json<serde_json::Value>| async move {
                        r.inbox.lock().unwrap().clear();
                        Json(MessengerAckResponse {
                            ok: true,
                            removed: 1,
                            err: None,
                        })
                    },
                ),
            )
            .route(
                MESSENGER_SEND_PATH,
                post(
                    |State(r): State<CaptureRelay>, Json(req): Json<MessengerSendRequest>| async move {
                        r.posted.lock().unwrap().push(req.envelope);
                        Json(MessengerSendResponse {
                            ok: true,
                            err: None,
                        })
                    },
                ),
            )
            .with_state(relay.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capture relay");
        let addr = listener.local_addr().expect("capture relay address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve capture relay");
        });
        let url = format!("http://{addr}");
        let http = reqwest::Client::new();

        // What the screen is allowed to say, before and after. The banner reads
        // this and nothing else, so it has to track the envelope below exactly.
        assert!(
            !messenger_peer_security(&bob, &bob_addr, &alice_addr)
                .unwrap()
                .sends_sealed,
            "before a word arrives from Alice this wallet holds no key of hers"
        );

        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("poll the capture relay");
        assert_eq!(
            outcome.added, 1,
            "Bob's wallet must take delivery of Alice's opening"
        );
        assert_eq!(outcome.relays_answered, 1);
        assert_eq!(outcome.rejected_envelopes, 0);
        let security = messenger_peer_security(&bob, &bob_addr, &alice_addr).unwrap();
        assert!(
            security.sends_sealed,
            "her envelope carried her key, so the screen may now say the next send is sealed"
        );
        assert_eq!(
            security.unsealed_messages, 1,
            "Alice's opening was v1, and the screen has to be able to say so"
        );

        messenger_send(
            &http,
            &bob,
            &bob_addr,
            &alice_addr,
            "meet me at 9",
            std::slice::from_ref(&url),
            None,
        )
        .await
        .expect("Bob's reply is accepted");
        server.abort();

        let captured: Vec<MessengerEnvelope> = relay.posted.lock().unwrap().clone();
        assert_eq!(captured.len(), 1, "the reply reached the relay");
        let sealed = &captured[0];

        // Everything the operator has: the ciphertext, and the two clear
        // addresses sitting next to it in the same record.
        let stranger = keyed("ff");
        let leaked = decrypt_body(
            stranger.inner(),
            &sealed.to,
            &sealed.from,
            None,
            MESSENGER_CRYPTO_V1,
            &sealed.nonce,
            &sealed.ciphertext,
        );
        assert!(
            leaked.is_err(),
            "the relay operator read the message from the two public addresses alone: {:?}",
            leaked.map(|p| p.body)
        );
        assert_eq!(
            sealed.v, MESSENGER_CRYPTO_V2,
            "a reply to a peer whose key this wallet already holds must be sealed to that key"
        );

        // And the person it was written for still reads it.
        let bob_pk = parse_pubkey_hex(
            sealed
                .from_pubkey
                .as_deref()
                .expect("the sender pubkey travels with the envelope"),
        )
        .unwrap();
        let plain = decrypt_body(
            alice.inner(),
            &alice_addr,
            &bob_addr,
            Some(&bob_pk),
            sealed.v,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .expect("Alice decrypts the reply");
        assert_eq!(plain.body, "meet me at 9");
    }

    /// Sign an envelope the way `messenger_send` does, so the relay and the
    /// receiving wallet both accept it.
    fn signed_envelope(mut env: MessengerEnvelope, signer: &WalletAccount) -> MessengerEnvelope {
        let digest = dust_whisper::messenger_auth::envelope_auth_digest(&env);
        env.from_sig = Some(hex::encode(signer.inner().do_sign(&digest)));
        env
    }

    fn keyed_account(tail: &str) -> WalletAccount {
        let mut hex = "0".repeat(64 - tail.len());
        hex.push_str(tail);
        WalletAccount::from_secret_hex(&hex).unwrap()
    }

    /// A relay that hands over a fixed inbox and answers `auth_ok` as told.
    async fn spawn_inbox_relay(
        messages: Vec<MessengerEnvelope>,
        auth_ok: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::extract::{Query, State};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use dust_whisper::protocol::{
            MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH,
            MessengerAckResponse, MessengerChallengeResponse, MessengerInboxResponse,
        };
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Fixed {
            inbox: Arc<Mutex<Vec<MessengerEnvelope>>>,
            auth_ok: bool,
        }

        let state = Fixed {
            inbox: Arc::new(Mutex::new(messages)),
            auth_ok,
        };
        let app = Router::new()
            .route(
                MESSENGER_CHALLENGE_PATH,
                get(|Query(_q): Query<HashMap<String, String>>| async {
                    Json(MessengerChallengeResponse {
                        nonce: "fixed-relay-nonce".into(),
                        expires_at: "2099-01-01T00:00:00Z".into(),
                    })
                }),
            )
            .route(
                MESSENGER_INBOX_PATH,
                post(
                    |State(r): State<Fixed>, Json(_): Json<serde_json::Value>| async move {
                        let messages = if r.auth_ok {
                            r.inbox.lock().unwrap().clone()
                        } else {
                            Vec::new()
                        };
                        Json(MessengerInboxResponse {
                            messages,
                            auth_ok: r.auth_ok,
                        })
                    },
                ),
            )
            .route(
                MESSENGER_ACK_PATH,
                post(
                    |State(r): State<Fixed>, Json(_): Json<serde_json::Value>| async move {
                        let removed = {
                            let mut inbox = r.inbox.lock().unwrap();
                            let n = inbox.len() as u32;
                            inbox.clear();
                            n
                        };
                        Json(MessengerAckResponse {
                            ok: true,
                            removed,
                            err: None,
                        })
                    },
                ),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixed relay");
        let addr = listener.local_addr().expect("fixed relay address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle)
    }

    /// Words in a contact's mouth.
    ///
    /// The relay's send endpoint had no authentication, so `from` was a string
    /// anybody could write. A stranger holding nothing but two public addresses
    /// could post a v1 envelope naming a trusted contact as its sender, and the
    /// receiving wallet filed it as an incoming message from that contact under
    /// a banner saying the conversation was sealed to that contact's key. The
    /// wallet refuses such an envelope now, whatever a relay chose to accept.
    #[tokio::test]
    async fn a_forged_message_from_a_contact_never_becomes_a_message() {
        let _iso = IsolatedWalletData::new();
        let alice = keyed_account("a1");
        let bob = keyed_account("b0");
        let mallory = keyed_account("cc");
        let alice_addr = alice.address();
        let bob_addr = bob.address();

        // Everything Mallory has: the two addresses, both of which travel in
        // clear on every envelope. She writes Alice's name on it.
        let (nonce, ciphertext) = encrypt_body_v1(
            &alice_addr,
            &bob_addr,
            "change of plan, send the 500 HAC to my other address",
            "2026-08-22T09:00:00Z",
        );
        let base = MessengerEnvelope {
            v: MESSENGER_CRYPTO_V1,
            id: "forged-1".into(),
            to: bob_addr.clone(),
            from: alice_addr.clone(),
            from_pubkey: Some(pubkey_hex(alice.inner())),
            from_sig: None,
            nonce,
            ciphertext,
            sent_at: "2026-08-22T09:00:00Z".into(),
        };
        // Unsigned, and signed by the wrong key. Neither may land.
        let mut second = base.clone();
        second.id = "forged-2".into();
        let signed_by_mallory = signed_envelope(second, &mallory);
        let (url, relay) = spawn_inbox_relay(vec![base, signed_by_mallory], true).await;
        let http = reqwest::Client::new();

        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the poll completes");
        relay.abort();

        assert_eq!(
            outcome.added, 0,
            "a forged envelope became a message in Bob's history"
        );
        assert_eq!(outcome.rejected_envelopes, 2);
        assert!(
            messenger_threads(&bob, &bob_addr).unwrap().is_empty(),
            "a forged envelope left a conversation behind"
        );
        assert!(
            !messenger_peer_security(&bob, &bob_addr, &alice_addr)
                .unwrap()
                .sends_sealed,
            "a forged envelope taught this wallet a key, which is what flipped the banner"
        );
    }

    /// Nothing reached is not nothing waiting.
    ///
    /// `messenger_poll_inbox` swallowed every transport failure and returned the
    /// number zero, and the screen turned that into "the relay had nothing new"
    /// for a person whose relay had been down for a week.
    #[tokio::test]
    async fn a_poll_that_reached_nobody_is_not_an_empty_inbox() {
        let _iso = IsolatedWalletData::new();
        let bob = keyed_account("b0");
        let bob_addr = bob.address();
        let http = reqwest::Client::new();

        // A relay that refuses the connection.
        let dead = vec!["http://127.0.0.1:1".to_string()];
        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, &dead)
            .await
            .expect("the poll completes");
        assert_eq!(outcome.relays_tried, 1);
        assert_eq!(
            outcome.relays_answered, 0,
            "an unreachable relay must not be counted as answered"
        );
        assert_eq!(outcome.added, 0);

        // A relay that answers and refuses the inbox claim.
        let (url, relay) = spawn_inbox_relay(Vec::new(), false).await;
        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the poll completes");
        relay.abort();
        assert_eq!(outcome.relays_tried, 1);
        assert_eq!(
            outcome.relays_refused, 1,
            "a refused claim must be distinguishable from an empty inbox"
        );
        assert_eq!(outcome.relays_answered, 0);
    }

    /// One junk envelope used to stop the poll for good.
    ///
    /// `from_pubkey` is attacker-controlled free text, and a `?` on parsing it
    /// aborted the whole poll before the save and before the ack, so the junk
    /// stayed on the relay and poisoned every poll after it, forever.
    #[tokio::test]
    async fn one_unreadable_envelope_does_not_block_the_rest_of_the_inbox() {
        let _iso = IsolatedWalletData::new();
        let alice = keyed_account("a1");
        let bob = keyed_account("b0");
        let alice_addr = alice.address();
        let bob_addr = bob.address();

        let junk = MessengerEnvelope {
            v: MESSENGER_CRYPTO_V1,
            id: "junk-1".into(),
            to: bob_addr.clone(),
            from: alice_addr.clone(),
            from_pubkey: Some("zz".into()),
            from_sig: Some("zz".into()),
            nonce: "00".into(),
            ciphertext: "00".into(),
            sent_at: "2026-08-22T08:00:00Z".into(),
        };
        let (nonce, ciphertext) =
            encrypt_body_v1(&alice_addr, &bob_addr, "you there?", "2026-08-22T09:00:00Z");
        let genuine = signed_envelope(
            MessengerEnvelope {
                v: MESSENGER_CRYPTO_V1,
                id: "alice-1".into(),
                to: bob_addr.clone(),
                from: alice_addr.clone(),
                from_pubkey: Some(pubkey_hex(alice.inner())),
                from_sig: None,
                nonce,
                ciphertext,
                sent_at: "2026-08-22T09:00:00Z".into(),
            },
            &alice,
        );

        let (url, relay) = spawn_inbox_relay(vec![junk, genuine], true).await;
        let http = reqwest::Client::new();
        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the poll must complete, not abort on the first bad envelope");
        relay.abort();

        assert_eq!(outcome.rejected_envelopes, 1);
        assert_eq!(
            outcome.added, 1,
            "the genuine message behind the junk one was never delivered"
        );
        let messages = messenger_messages(&bob, &bob_addr, &alice_addr).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, "you there?");
        assert_eq!(
            messages[0].sealed,
            Some(false),
            "a v1 message is not sealed to the peer's key, and the record has to say so"
        );
    }
}
